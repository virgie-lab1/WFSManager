#pragma once

#include "WfsCommon.h"
#include "WfsStructures.h"
#include "WfsDiskDevice.h"
#include "WfsCrypto.h"
#include "WfsBlockAllocator.h"
#include "WfsTransaction.h"
#include <string>
#include <vector>
#include <set>
#include <memory>

namespace WfsManager {

class WfsFileSystem {
public:
    WfsFileSystem();
    ~WfsFileSystem();

    // Mount using physical device and raw OTP/SEEPROM buffers
    bool Mount(
        IWfsDevice* device,
        const uint8_t* otpData, size_t otpSize,
        const uint8_t* seepromData, size_t seepromSize
    );

    // Format new WFS partition on clean device
    bool Format(
        IWfsDevice* device,
        const uint8_t* otpData, size_t otpSize,
        const uint8_t* seepromData, size_t seepromSize,
        uint32_t clusterSize = WFS_DEFAULT_CLUSTER_SIZE
    );

    void Unmount();
    bool IsMounted() const { return isMounted_; }

    // Path & Inode Operations
    bool ResolvePath(const std::string& path, uint32_t& outInodeCluster, WfsInodeDisk& outInode);
    bool ListDirectory(const std::string& dirPath, std::vector<WfsDirEntryDisk>& outEntries);
    bool CreateDirectory(const std::string& parentPath, const std::string& dirName);
    bool CreateDirectoryRecursive(const std::string& fullPath);

    // File Operations
    bool WriteFile(const std::string& fullPath, const uint8_t* data, size_t size);
    bool ReadFile(const std::string& fullPath, std::vector<uint8_t>& outData);
    bool DeleteFile(const std::string& fullPath);
    bool RemoveDirectory(const std::string& dirPath, bool recursive = false);

    // Inode Extent Reader & Writer
    bool ReadInode(uint32_t clusterIndex, WfsInodeDisk& outInode);
    void StageInodeWrite(uint32_t clusterIndex, const WfsInodeDisk& inode);
    bool CollectInodeExtents(const WfsInodeDisk& inode, std::vector<WfsExtent>& outExtents);

    // Filesystem Integrity & Verification
    bool CheckIntegrity(std::vector<std::string>& outIssues);
    void CollectReferencedClustersRecursive(uint32_t dirInodeCluster, std::set<uint32_t>& outReferenced);

    // Transaction Management
    WfsTransaction* GetTransaction() { return transaction_.get(); }
    WfsBlockAllocator* GetAllocator() { return allocator_.get(); }
    const WfsSuperblock& GetSuperblock() const { return superblock_; }
    uint32_t GetClusterSize() const { return clusterSize_; }
    uint32_t GetSectorsPerCluster() const { return sectorsPerCluster_; }
    const uint8_t* GetUsbKey() const { return usbKey_; }

    bool BeginTransaction(const std::string& backupDir = "");
    bool CommitTransaction();
    bool RollbackTransaction();

private:
    bool isMounted_;
    IWfsDevice* device_;
    uint8_t usbKey_[WfsCrypto::KEY_SIZE];
    uint32_t clusterSize_;
    uint32_t sectorsPerCluster_;

    WfsSuperblock superblock_;
    uint32_t backupSuperblockLba_;

    std::unique_ptr<WfsBlockAllocator> allocator_;
    std::unique_ptr<WfsTransaction> transaction_;

    uint32_t nextInodeNumber_;

    bool ReadDirectoryEntries(const WfsInodeDisk& dirInode, std::vector<WfsDirEntryDisk>& outEntries);
    bool WriteDirectoryEntries(uint32_t dirInodeCluster, WfsInodeDisk& dirInode, const std::vector<WfsDirEntryDisk>& entries);
    std::vector<std::string> SplitPath(const std::string& path);
};

} // namespace WfsManager

