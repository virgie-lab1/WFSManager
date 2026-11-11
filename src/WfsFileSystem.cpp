#include "WfsFileSystem.h"
#include <cstring>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <ctime>

namespace WfsManager {

WfsFileSystem::WfsFileSystem()
    : isMounted_(false),
      device_(nullptr),
      clusterSize_(WFS_DEFAULT_CLUSTER_SIZE),
      sectorsPerCluster_(8),
      backupSuperblockLba_(0),
      nextInodeNumber_(100)
{
    std::memset(usbKey_, 0, sizeof(usbKey_));
    std::memset(&superblock_, 0, sizeof(superblock_));
}

WfsFileSystem::~WfsFileSystem() {
    Unmount();
}

bool WfsFileSystem::Mount(
    IWfsDevice* device,
    const uint8_t* otpData, size_t otpSize,
    const uint8_t* seepromData, size_t seepromSize
) {
    if (!device || !device->IsOpen()) return false;
    device_ = device;

    // Step 1: Derive USB Storage Key
    if (!WfsCrypto::DeriveUsbStorageKey(otpData, otpSize, seepromData, seepromSize, usbKey_)) {
        std::cerr << "[WfsFileSystem] Failed to derive USB storage key from OTP/SEEPROM" << std::endl;
        return false;
    }

    uint32_t secSize = device_->GetSectorSize();
    clusterSize_ = WFS_DEFAULT_CLUSTER_SIZE;
    sectorsPerCluster_ = clusterSize_ / secSize;

    // Step 2: Read and decrypt Primary Superblock from LBA 0
    std::vector<uint8_t> rawSb(clusterSize_, 0);
    if (!device_->ReadSectors(0, sectorsPerCluster_, rawSb.data())) {
        std::cerr << "[WfsFileSystem] Failed to read primary superblock at LBA 0" << std::endl;
        return false;
    }

    WfsCrypto::CryptCluster(usbKey_, 0, rawSb.data(), clusterSize_, false);
    std::memcpy(&superblock_, rawSb.data(), sizeof(WfsSuperblock));

    bool primaryValid = (superblock_.magic == WFS_SUPERBLOCK_MAGIC || superblock_.magic == WFS_SUPERBLOCK_MAGIC_ALT);

    if (!primaryValid) {
        std::cerr << "[WfsFileSystem] Primary superblock corrupt or unformatted. Checking backup..." << std::endl;
        uint32_t backupLba = 0x7000 * sectorsPerCluster_;
        std::vector<uint8_t> rawBackup(clusterSize_, 0);
        if (device_->ReadSectors(backupLba, sectorsPerCluster_, rawBackup.data())) {
            WfsCrypto::CryptCluster(usbKey_, backupLba, rawBackup.data(), clusterSize_, false);
            WfsSuperblock backupSb;
            std::memcpy(&backupSb, rawBackup.data(), sizeof(WfsSuperblock));
            if (backupSb.magic == WFS_SUPERBLOCK_MAGIC || backupSb.magic == WFS_SUPERBLOCK_MAGIC_ALT) {
                std::cout << "[WfsFileSystem] Recovered valid backup superblock from LBA " << backupLba << std::endl;
                superblock_ = backupSb;
                backupSuperblockLba_ = backupLba;
                primaryValid = true;
            }
        }
    } else {
        backupSuperblockLba_ = superblock_.backup_superblock_lba;
        if (backupSuperblockLba_ == 0) {
            backupSuperblockLba_ = static_cast<uint32_t>(superblock_.total_sectors - sectorsPerCluster_);
        }
    }

    if (!primaryValid) {
        std::cerr << "[WfsFileSystem] Failed to mount: No valid WFS superblock found." << std::endl;
        return false;
    }

    clusterSize_ = superblock_.cluster_size;
    sectorsPerCluster_ = clusterSize_ / secSize;

    // Step 3: Initialize Allocator and load bitmap
    allocator_ = std::make_unique<WfsBlockAllocator>(
        device_,
        clusterSize_,
        superblock_.total_sectors,
        superblock_.allocator_bitmap_cluster
    );

    if (!allocator_->Load()) {
        std::cerr << "[WfsFileSystem] Failed to load block allocation bitmap" << std::endl;
        return false;
    }

    // Step 4: Initialize Transaction Engine
    transaction_ = std::make_unique<WfsTransaction>(device_, allocator_.get(), usbKey_, clusterSize_);

    isMounted_ = true;
    std::cout << "[WfsFileSystem] Successfully mounted WFS Volume. Generation: " 
              << superblock_.generation << ", Free Clusters: " << allocator_->GetFreeClusterCount() 
              << " / " << allocator_->GetTotalClusters() << std::endl;

    return true;
}

bool WfsFileSystem::Format(
    IWfsDevice* device,
    const uint8_t* otpData, size_t otpSize,
    const uint8_t* seepromData, size_t seepromSize,
    uint32_t clusterSize
) {
    if (!device || !device->IsOpen()) return false;
    device_ = device;

    if (!WfsCrypto::DeriveUsbStorageKey(otpData, otpSize, seepromData, seepromSize, usbKey_)) {
        return false;
    }

    clusterSize_ = clusterSize;
    sectorsPerCluster_ = clusterSize_ / device_->GetSectorSize();
    uint64_t totalSectors = device_->GetTotalSectors();

    std::memset(&superblock_, 0, sizeof(WfsSuperblock));
    superblock_.magic = WFS_SUPERBLOCK_MAGIC;
    superblock_.version = 1;
    superblock_.generation = 0; // Increment to 1 upon initial format commit
    superblock_.cluster_size = clusterSize_;
    superblock_.total_sectors = totalSectors;
    superblock_.area_count = 1;
    superblock_.root_inode_cluster = 1; // Cluster 1 = Root Inode
    superblock_.allocator_bitmap_cluster = 2; // Cluster 2..N = Bitmap
    backupSuperblockLba_ = static_cast<uint32_t>(totalSectors - sectorsPerCluster_);
    superblock_.backup_superblock_lba = backupSuperblockLba_;
    superblock_.flags = 0; // Clean

    allocator_ = std::make_unique<WfsBlockAllocator>(
        device_,
        clusterSize_,
        totalSectors,
        superblock_.allocator_bitmap_cluster
    );

    // Reserve system clusters in bitmap (0 = SB, 1 = Root Inode, 2..16 = Bitmap blocks)
    uint32_t bitmapClusters = (allocator_->GetTotalClusters() / 8 + clusterSize_ - 1) / clusterSize_;
    uint32_t reservedEnd = superblock_.allocator_bitmap_cluster + bitmapClusters + 4;
    for (uint32_t i = 0; i < reservedEnd; ++i) {
        allocator_->SetClusterAllocated(i, true);
    }

    transaction_ = std::make_unique<WfsTransaction>(device_, allocator_.get(), usbKey_, clusterSize_);

    // Create Root Inode ('/')
    WfsInodeDisk rootInode;
    std::memset(&rootInode, 0, sizeof(rootInode));
    rootInode.inode_number = 1;
    rootInode.type = WFS_TYPE_DIRECTORY;
    rootInode.ctime = rootInode.mtime = rootInode.atime = static_cast<uint32_t>(std::time(nullptr));

    // Allocate 1 cluster for root directory entries
    std::vector<WfsExtent> rootExtents;
    if (!allocator_->AllocateClusters(1, rootExtents) || rootExtents.empty()) {
        std::cerr << "[WfsFileSystem] Failed to allocate cluster for root directory" << std::endl;
        return false;
    }
    rootInode.direct_extent_count = 1;
    rootInode.direct_extents[0].start_cluster = rootExtents[0].startCluster;
    rootInode.direct_extents[0].count = 1;

    // Initialize root directory block (empty)
    std::vector<uint8_t> emptyDirBlock(clusterSize_, 0);

    transaction_->Begin();
    transaction_->StageWrite(superblock_.root_inode_cluster, reinterpret_cast<const uint8_t*>(&rootInode), sizeof(rootInode), true);
    transaction_->StageWrite(rootExtents[0].startCluster, emptyDirBlock, true);
    transaction_->Commit(superblock_, backupSuperblockLba_);

    isMounted_ = true;
    std::cout << "[WfsFileSystem] Formatted clean WFS partition. Total clusters: " 
              << allocator_->GetTotalClusters() << std::endl;
    return true;
}

void WfsFileSystem::Unmount() {
    if (isMounted_) {
        if (transaction_ && transaction_->IsActive()) {
            transaction_->Rollback(superblock_, backupSuperblockLba_);
        }
        transaction_.reset();
        allocator_.reset();
        isMounted_ = false;
        device_ = nullptr;
    }
}

std::vector<std::string> WfsFileSystem::SplitPath(const std::string& path) {
    std::vector<std::string> parts;
    std::stringstream ss(path);
    std::string item;
    while (std::getline(ss, item, '/')) {
        if (!item.empty() && item != ".") {
            parts.push_back(item);
        }
    }
    return parts;
}

bool WfsFileSystem::ReadInode(uint32_t clusterIndex, WfsInodeDisk& outInode) {
    if (!device_ || !device_->IsOpen()) return false;
    std::vector<uint8_t> buf(clusterSize_, 0);
    uint64_t sector = static_cast<uint64_t>(clusterIndex) * sectorsPerCluster_;

    if (!device_->ReadSectors(sector, sectorsPerCluster_, buf.data())) return false;
    WfsCrypto::CryptCluster(usbKey_, clusterIndex * sectorsPerCluster_, buf.data(), clusterSize_, false);
    std::memcpy(&outInode, buf.data(), sizeof(WfsInodeDisk));
    return true;
}

void WfsFileSystem::StageInodeWrite(uint32_t clusterIndex, const WfsInodeDisk& inode) {
    std::vector<uint8_t> buf(clusterSize_, 0);
    std::memcpy(buf.data(), &inode, sizeof(WfsInodeDisk));
    transaction_->StageWrite(clusterIndex, buf, true);
}

bool WfsFileSystem::ReadDirectoryEntries(const WfsInodeDisk& dirInode, std::vector<WfsDirEntryDisk>& outEntries) {
    outEntries.clear();
    if (dirInode.type != WFS_TYPE_DIRECTORY) return false;

    for (uint32_t e = 0; e < dirInode.direct_extent_count; ++e) {
        uint32_t startCluster = dirInode.direct_extents[e].start_cluster;
        uint32_t count = dirInode.direct_extents[e].count;

        for (uint32_t c = 0; c < count; ++c) {
            uint32_t cluster = startCluster + c;
            std::vector<uint8_t> buf(clusterSize_, 0);
            uint64_t sector = static_cast<uint64_t>(cluster) * sectorsPerCluster_;

            if (!device_->ReadSectors(sector, sectorsPerCluster_, buf.data())) return false;
            WfsCrypto::CryptCluster(usbKey_, cluster * sectorsPerCluster_, buf.data(), clusterSize_, false);

            size_t entryCount = clusterSize_ / sizeof(WfsDirEntryDisk);
            const WfsDirEntryDisk* diskEntries = reinterpret_cast<const WfsDirEntryDisk*>(buf.data());

            for (size_t i = 0; i < entryCount; ++i) {
                if (diskEntries[i].inode_number != 0 && diskEntries[i].name_length > 0) {
                    outEntries.push_back(diskEntries[i]);
                }
            }
        }
    }
    return true;
}

bool WfsFileSystem::WriteDirectoryEntries(
    uint32_t dirInodeCluster,
    WfsInodeDisk& dirInode,
    const std::vector<WfsDirEntryDisk>& entries
) {
    if (dirInode.direct_extent_count == 0) return false;

    size_t entriesPerCluster = clusterSize_ / sizeof(WfsDirEntryDisk);
    size_t clustersNeeded = (entries.size() + entriesPerCluster - 1) / entriesPerCluster;
    if (clustersNeeded == 0) clustersNeeded = 1;

    uint32_t startCluster = dirInode.direct_extents[0].start_cluster;
    for (size_t c = 0; c < dirInode.direct_extents[0].count; ++c) {
        std::vector<uint8_t> blockData(clusterSize_, 0);
        WfsDirEntryDisk* destEntries = reinterpret_cast<WfsDirEntryDisk*>(blockData.data());

        size_t startIdx = c * entriesPerCluster;
        for (size_t i = 0; i < entriesPerCluster && (startIdx + i) < entries.size(); ++i) {
            destEntries[i] = entries[startIdx + i];
        }

        transaction_->StageWrite(startCluster + static_cast<uint32_t>(c), blockData, true);
    }

    dirInode.mtime = static_cast<uint32_t>(std::time(nullptr));
    StageInodeWrite(dirInodeCluster, dirInode);
    return true;
}

bool WfsFileSystem::ResolvePath(const std::string& path, uint32_t& outInodeCluster, WfsInodeDisk& outInode) {
    if (!isMounted_) return false;
    auto parts = SplitPath(path);

    uint32_t currentInodeCluster = superblock_.root_inode_cluster;
    WfsInodeDisk currentInode;
    if (!ReadInode(currentInodeCluster, currentInode)) return false;

    if (parts.empty()) {
        outInodeCluster = currentInodeCluster;
        outInode = currentInode;
        return true;
    }

    for (size_t p = 0; p < parts.size(); ++p) {
        const std::string& targetName = parts[p];
        std::vector<WfsDirEntryDisk> entries;
        if (!ReadDirectoryEntries(currentInode, entries)) return false;

        bool found = false;
        for (const auto& entry : entries) {
            std::string entryName(entry.name, entry.name_length);
            if (entryName == targetName) {
                currentInodeCluster = entry.inode_number;
                if (!ReadInode(currentInodeCluster, currentInode)) return false;
                found = true;
                break;
            }
        }

        if (!found) return false;
    }

    outInodeCluster = currentInodeCluster;
    outInode = currentInode;
    return true;
}

bool WfsFileSystem::ListDirectory(const std::string& dirPath, std::vector<WfsDirEntryDisk>& outEntries) {
    uint32_t inodeCluster;
    WfsInodeDisk inode;
    if (!ResolvePath(dirPath, inodeCluster, inode)) return false;
    if (inode.type != WFS_TYPE_DIRECTORY) return false;
    return ReadDirectoryEntries(inode, outEntries);
}

bool WfsFileSystem::CreateDirectory(const std::string& parentPath, const std::string& dirName) {
    if (!isMounted_) return false;

    uint32_t parentCluster;
    WfsInodeDisk parentInode;
    if (!ResolvePath(parentPath, parentCluster, parentInode)) return false;
    if (parentInode.type != WFS_TYPE_DIRECTORY) return false;

    // Check if entry already exists
    std::vector<WfsDirEntryDisk> entries;
    ReadDirectoryEntries(parentInode, entries);
    for (const auto& e : entries) {
        if (std::string(e.name, e.name_length) == dirName) {
            return false; // Already exists
        }
    }

    // Allocate 1 cluster for new directory Inode, and 1 cluster for its directory entries
    std::vector<WfsExtent> inodeExt, dataExt;
    if (!allocator_->AllocateClusters(1, inodeExt) || !allocator_->AllocateClusters(1, dataExt)) {
        return false;
    }

    WfsInodeDisk newDirInode;
    std::memset(&newDirInode, 0, sizeof(newDirInode));
    newDirInode.inode_number = inodeExt[0].startCluster;
    newDirInode.type = WFS_TYPE_DIRECTORY;
    newDirInode.ctime = newDirInode.mtime = newDirInode.atime = static_cast<uint32_t>(std::time(nullptr));
    newDirInode.direct_extent_count = 1;
    newDirInode.direct_extents[0].start_cluster = dataExt[0].startCluster;
    newDirInode.direct_extents[0].count = 1;

    // Empty directory block
    std::vector<uint8_t> emptyDir(clusterSize_, 0);
    transaction_->StageWrite(dataExt[0].startCluster, emptyDir, true);
    StageInodeWrite(inodeExt[0].startCluster, newDirInode);

    // Add entry to parent directory
    WfsDirEntryDisk newEntry;
    std::memset(&newEntry, 0, sizeof(newEntry));
    newEntry.inode_number = inodeExt[0].startCluster;
    newEntry.type = WFS_TYPE_DIRECTORY;
    newEntry.name_length = static_cast<uint8_t>(dirName.length());
    std::memcpy(newEntry.name, dirName.c_str(), dirName.length());
    entries.push_back(newEntry);

    WriteDirectoryEntries(parentCluster, parentInode, entries);
    return true;
}

bool WfsFileSystem::CreateDirectoryRecursive(const std::string& fullPath) {
    auto parts = SplitPath(fullPath);
    std::string current = "/";
    for (const auto& part : parts) {
        uint32_t dummyCluster;
        WfsInodeDisk dummyInode;
        std::string nextPath = (current == "/") ? ("/" + part) : (current + "/" + part);
        if (!ResolvePath(nextPath, dummyCluster, dummyInode)) {
            if (!CreateDirectory(current, part)) return false;
        }
        current = nextPath;
    }
    return true;
}

bool WfsFileSystem::WriteFile(const std::string& fullPath, const uint8_t* data, size_t size) {
    if (!isMounted_) return false;

    auto parts = SplitPath(fullPath);
    if (parts.empty()) return false;

    std::string filename = parts.back();
    parts.pop_back();

    std::string parentPath = "/";
    for (size_t i = 0; i < parts.size(); ++i) {
        parentPath += parts[i];
        if (i + 1 < parts.size()) parentPath += "/";
    }

    CreateDirectoryRecursive(parentPath);

    uint32_t parentCluster;
    WfsInodeDisk parentInode;
    if (!ResolvePath(parentPath, parentCluster, parentInode)) return false;

    // If file already exists, delete old contents
    DeleteFile(fullPath);

    // Calculate cluster count
    uint32_t clustersNeeded = static_cast<uint32_t>((size + clusterSize_ - 1) / clusterSize_);
    if (clustersNeeded == 0) clustersNeeded = 1;

    std::vector<WfsExtent> dataExtents;
    if (!allocator_->AllocateClusters(clustersNeeded, dataExtents)) {
        return false;
    }

    std::vector<WfsExtent> inodeExtent;
    if (!allocator_->AllocateClusters(1, inodeExtent)) {
        allocator_->FreeClusters(dataExtents);
        return false;
    }

    // Write file payload clusters
    size_t bytesWritten = 0;
    size_t currentExtent = 0;
    uint32_t offsetInExtent = 0;

    for (uint32_t c = 0; c < clustersNeeded; ++c) {
        uint32_t cluster = dataExtents[currentExtent].startCluster + offsetInExtent;
        size_t bytesThisCluster = std::min(size - bytesWritten, static_cast<size_t>(clusterSize_));

        std::vector<uint8_t> block(clusterSize_, 0);
        if (bytesThisCluster > 0) {
            std::memcpy(block.data(), data + bytesWritten, bytesThisCluster);
            bytesWritten += bytesThisCluster;
        }

        transaction_->StageWrite(cluster, block, true);

        offsetInExtent++;
        if (offsetInExtent >= dataExtents[currentExtent].clusterCount) {
            currentExtent++;
            offsetInExtent = 0;
        }
    }

    // Populate File Inode
    WfsInodeDisk fileInode;
    std::memset(&fileInode, 0, sizeof(fileInode));
    fileInode.inode_number = inodeExtent[0].startCluster;
    fileInode.type = WFS_TYPE_FILE;
    fileInode.file_size = size;
    fileInode.ctime = fileInode.mtime = fileInode.atime = static_cast<uint32_t>(std::time(nullptr));
    fileInode.direct_extent_count = static_cast<uint32_t>(std::min(dataExtents.size(), size_t(32)));

    for (size_t i = 0; i < fileInode.direct_extent_count; ++i) {
        fileInode.direct_extents[i].start_cluster = dataExtents[i].startCluster;
        fileInode.direct_extents[i].count = dataExtents[i].clusterCount;
    }

    StageInodeWrite(inodeExtent[0].startCluster, fileInode);

    // Add entry to parent directory
    std::vector<WfsDirEntryDisk> entries;
    ReadDirectoryEntries(parentInode, entries);

    WfsDirEntryDisk newEntry;
    std::memset(&newEntry, 0, sizeof(newEntry));
    newEntry.inode_number = inodeExtent[0].startCluster;
    newEntry.type = WFS_TYPE_FILE;
    newEntry.name_length = static_cast<uint8_t>(filename.length());
    std::memcpy(newEntry.name, filename.c_str(), filename.length());
    entries.push_back(newEntry);

    WriteDirectoryEntries(parentCluster, parentInode, entries);
    return true;
}

bool WfsFileSystem::ReadFile(const std::string& fullPath, std::vector<uint8_t>& outData) {
    outData.clear();
    uint32_t inodeCluster;
    WfsInodeDisk fileInode;
    if (!ResolvePath(fullPath, inodeCluster, fileInode)) return false;
    if (fileInode.type != WFS_TYPE_FILE) return false;

    outData.resize(static_cast<size_t>(fileInode.file_size));
    size_t bytesRead = 0;

    for (uint32_t e = 0; e < fileInode.direct_extent_count; ++e) {
        uint32_t startCluster = fileInode.direct_extents[e].start_cluster;
        uint32_t count = fileInode.direct_extents[e].count;

        for (uint32_t c = 0; c < count; ++c) {
            if (bytesRead >= fileInode.file_size) break;
            uint32_t cluster = startCluster + c;

            std::vector<uint8_t> buf(clusterSize_, 0);
            uint64_t sector = static_cast<uint64_t>(cluster) * sectorsPerCluster_;
            if (!device_->ReadSectors(sector, sectorsPerCluster_, buf.data())) return false;

            WfsCrypto::CryptCluster(usbKey_, cluster * sectorsPerCluster_, buf.data(), clusterSize_, false);

            size_t bytesFromThisCluster = std::min(static_cast<size_t>(fileInode.file_size - bytesRead), static_cast<size_t>(clusterSize_));
            std::memcpy(outData.data() + bytesRead, buf.data(), bytesFromThisCluster);
            bytesRead += bytesFromThisCluster;
        }
    }
    return true;
}

bool WfsFileSystem::DeleteFile(const std::string& fullPath) {
    if (!isMounted_) return false;
    auto parts = SplitPath(fullPath);
    if (parts.empty()) return false;

    std::string filename = parts.back();
    parts.pop_back();

    std::string parentPath = "/";
    for (size_t i = 0; i < parts.size(); ++i) {
        parentPath += parts[i];
        if (i + 1 < parts.size()) parentPath += "/";
    }

    uint32_t parentCluster;
    WfsInodeDisk parentInode;
    if (!ResolvePath(parentPath, parentCluster, parentInode)) return false;

    std::vector<WfsDirEntryDisk> entries;
    if (!ReadDirectoryEntries(parentInode, entries)) return false;

    int targetIdx = -1;
    uint32_t fileInodeCluster = 0;

    for (size_t i = 0; i < entries.size(); ++i) {
        if (std::string(entries[i].name, entries[i].name_length) == filename) {
            targetIdx = static_cast<int>(i);
            fileInodeCluster = entries[i].inode_number;
            break;
        }
    }

    if (targetIdx == -1) return false;

    WfsInodeDisk fileInode;
    if (ReadInode(fileInodeCluster, fileInode)) {
        // Free payload extents
        std::vector<WfsExtent> extents;
        CollectInodeExtents(fileInode, extents);
        allocator_->FreeClusters(extents);

        // Free Inode cluster itself
        allocator_->FreeClusters({ { fileInodeCluster, 1 } });
    }

    // Remove entry from parent directory
    entries.erase(entries.begin() + targetIdx);
    WriteDirectoryEntries(parentCluster, parentInode, entries);
    return true;
}

bool WfsFileSystem::CollectInodeExtents(const WfsInodeDisk& inode, std::vector<WfsExtent>& outExtents) {
    outExtents.clear();
    for (uint32_t i = 0; i < inode.direct_extent_count; ++i) {
        outExtents.push_back({ inode.direct_extents[i].start_cluster, inode.direct_extents[i].count });
    }
    return true;
}

bool WfsFileSystem::RemoveDirectory(const std::string& dirPath, bool recursive) {
    if (!isMounted_ || dirPath == "/" || dirPath.empty()) return false;

    uint32_t dirCluster;
    WfsInodeDisk dirInode;
    if (!ResolvePath(dirPath, dirCluster, dirInode)) return false;
    if (dirInode.type != WFS_TYPE_DIRECTORY) return false;

    std::vector<WfsDirEntryDisk> entries;
    ReadDirectoryEntries(dirInode, entries);

    if (!entries.empty()) {
        if (!recursive) return false;

        for (const auto& entry : entries) {
            std::string childName(entry.name, entry.name_length);
            std::string childPath = (dirPath == "/") ? ("/" + childName) : (dirPath + "/" + childName);

            if (entry.type == WFS_TYPE_DIRECTORY) {
                if (!RemoveDirectory(childPath, true)) return false;
            } else {
                if (!DeleteFile(childPath)) return false;
            }
        }
    }

    // Free directory extents and inode cluster
    std::vector<WfsExtent> dirExtents;
    CollectInodeExtents(dirInode, dirExtents);
    allocator_->FreeClusters(dirExtents);
    allocator_->FreeClusters({ { dirCluster, 1 } });

    // Remove entry from parent
    auto parts = SplitPath(dirPath);
    std::string dirName = parts.back();
    parts.pop_back();

    std::string parentPath = "/";
    for (size_t i = 0; i < parts.size(); ++i) {
        parentPath += parts[i];
        if (i + 1 < parts.size()) parentPath += "/";
    }

    uint32_t parentCluster;
    WfsInodeDisk parentInode;
    if (ResolvePath(parentPath, parentCluster, parentInode)) {
        std::vector<WfsDirEntryDisk> parentEntries;
        ReadDirectoryEntries(parentInode, parentEntries);
        for (auto it = parentEntries.begin(); it != parentEntries.end(); ++it) {
            if (std::string(it->name, it->name_length) == dirName) {
                parentEntries.erase(it);
                break;
            }
        }
        WriteDirectoryEntries(parentCluster, parentInode, parentEntries);
    }

    return true;
}

void WfsFileSystem::CollectReferencedClustersRecursive(uint32_t dirInodeCluster, std::set<uint32_t>& outReferenced) {
    WfsInodeDisk dirInode;
    if (!ReadInode(dirInodeCluster, dirInode)) return;

    outReferenced.insert(dirInodeCluster);
    for (uint32_t i = 0; i < dirInode.direct_extent_count; ++i) {
        for (uint32_t c = 0; c < dirInode.direct_extents[i].count; ++c) {
            outReferenced.insert(dirInode.direct_extents[i].start_cluster + c);
        }
    }

    std::vector<WfsDirEntryDisk> entries;
    ReadDirectoryEntries(dirInode, entries);

    for (const auto& entry : entries) {
        uint32_t childCluster = entry.inode_number;
        outReferenced.insert(childCluster);

        WfsInodeDisk childInode;
        if (ReadInode(childCluster, childInode)) {
            for (uint32_t i = 0; i < childInode.direct_extent_count; ++i) {
                for (uint32_t c = 0; c < childInode.direct_extents[i].count; ++c) {
                    outReferenced.insert(childInode.direct_extents[i].start_cluster + c);
                }
            }

            if (childInode.type == WFS_TYPE_DIRECTORY) {
                CollectReferencedClustersRecursive(childCluster, outReferenced);
            }
        }
    }
}

bool WfsFileSystem::CheckIntegrity(std::vector<std::string>& outIssues) {
    outIssues.clear();
    if (!isMounted_) {
        outIssues.push_back("Filesystem not mounted");
        return false;
    }

    std::set<uint32_t> referencedClusters;
    CollectReferencedClustersRecursive(superblock_.root_inode_cluster, referencedClusters);

    std::vector<uint32_t> orphans;
    std::vector<uint32_t> unallocated;

    bool clean = allocator_->AuditIntegrity(referencedClusters, orphans, unallocated);

    for (uint32_t cluster : orphans) {
        outIssues.push_back("Orphan cluster detected in bitmap (cluster " + std::to_string(cluster) + ")");
    }
    for (uint32_t cluster : unallocated) {
        outIssues.push_back("CRITICAL: Referenced cluster marked free in bitmap (cluster " + std::to_string(cluster) + ")");
    }

    return clean;
}

bool WfsFileSystem::BeginTransaction(const std::string& backupDir) {
    if (!transaction_) return false;
    return transaction_->Begin(backupDir);
}

bool WfsFileSystem::CommitTransaction() {
    if (!transaction_) return false;
    return transaction_->Commit(superblock_, backupSuperblockLba_);
}

bool WfsFileSystem::RollbackTransaction() {
    if (!transaction_) return false;
    return transaction_->Rollback(superblock_, backupSuperblockLba_);
}

} // namespace WfsManager

