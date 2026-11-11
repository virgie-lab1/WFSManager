#include "WfsTitleManager.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <regex>
#include <cstring>

namespace fs = std::filesystem;

namespace WfsManager {

WfsTitleManager::WfsTitleManager(WfsFileSystem* fileSystem)
    : fs_(fileSystem)
{
}

bool WfsTitleManager::EnumerateInstalledTitles(std::vector<InstalledTitleInfo>& outTitles) {
    outTitles.clear();
    if (!fs_ || !fs_->IsMounted()) return false;

    static const std::vector<std::string> categories = {
        "00050000", // Games
        "00050002", // Demos
        "0005000c", // DLC
        "0005000e", // Updates
        "00050010", // System Titles
        "0005001b", // System Data
        "00050030"  // System Applets
    };

    for (const auto& catStr : categories) {
        std::string catPath = "/usr/title/" + catStr;
        std::vector<WfsDirEntryDisk> lowEntries;
        if (!fs_->ListDirectory(catPath, lowEntries)) continue;

        for (const auto& lowEntry : lowEntries) {
            if (lowEntry.type != WFS_TYPE_DIRECTORY) continue;
            std::string lowIdStr(lowEntry.name, lowEntry.name_length);

            std::string fullHex = catStr + lowIdStr;
            if (fullHex.length() != 16) continue;

            try {
                TitleId id = TitleId::FromString(fullHex);
                InstalledTitleInfo info;
                if (GetTitleInfo(id, info)) {
                    outTitles.push_back(info);
                }
            } catch (...) {
                continue;
            }
        }
    }
    return true;
}

bool WfsTitleManager::GetTitleInfo(TitleId titleId, InstalledTitleInfo& outInfo) {
    if (!fs_ || !fs_->IsMounted()) return false;

    std::string rootPath = titleId.GetHierarchyPath();
    uint32_t cluster;
    WfsInodeDisk inode;
    if (!fs_->ResolvePath(rootPath, cluster, inode)) return false;

    outInfo.id = titleId;
    outInfo.category = titleId.GetCategory();
    outInfo.rootPath = rootPath;
    outInfo.isSystem = titleId.IsSystemOrShared();
    outInfo.totalSizeBytes = CalculateDirectorySize(rootPath);
    outInfo.hasTicket = HasTicket(titleId);

    // Try reading meta.xml
    std::string metaPath = rootPath + "/meta/meta.xml";
    std::vector<uint8_t> metaXmlData;
    outInfo.titleName = "Unknown Title (" + titleId.ToHexString() + ")";
    outInfo.productCode = "N/A";
    outInfo.version = 0;
    outInfo.hasTmd = false;

    if (fs_->ReadFile(metaPath, metaXmlData)) {
        TitleId parsedId;
        ParseMetaXml(metaXmlData, outInfo.titleName, outInfo.productCode, outInfo.version, parsedId);
    }

    // Check if TMD exists
    std::string tmdPath = "/usr/packages/" + titleId.ToContinuousHexString() + "/title.tmd";
    uint32_t tmdCluster;
    WfsInodeDisk tmdInode;
    outInfo.hasTmd = fs_->ResolvePath(tmdPath, tmdCluster, tmdInode);

    return true;
}

uint64_t WfsTitleManager::CalculateDirectorySize(const std::string& wfsDirPath) {
    std::vector<WfsDirEntryDisk> entries;
    if (!fs_->ListDirectory(wfsDirPath, entries)) return 0;

    uint64_t total = 0;
    for (const auto& entry : entries) {
        std::string name(entry.name, entry.name_length);
        std::string childPath = wfsDirPath + "/" + name;
        if (entry.type == WFS_TYPE_DIRECTORY) {
            total += CalculateDirectorySize(childPath);
        } else {
            uint32_t inodeCluster;
            WfsInodeDisk fileInode;
            if (fs_->ResolvePath(childPath, inodeCluster, fileInode)) {
                total += fileInode.file_size;
            }
        }
    }
    return total;
}

bool WfsTitleManager::ParseMetaXml(
    const std::vector<uint8_t>& xmlData,
    std::string& outName,
    std::string& outProductCode,
    uint16_t& outVersion,
    TitleId& outTitleId
) {
    std::string text(reinterpret_cast<const char*>(xmlData.data()), xmlData.size());

    // Simple regex parsing for standard Cafe OS meta.xml fields
    std::smatch m;
    if (std::regex_search(text, m, std::regex("<longname_en[^>]*>(.*?)</longname_en>"))) {
        outName = m[1].str();
        std::replace(outName.begin(), outName.end(), '\n', ' ');
    } else if (std::regex_search(text, m, std::regex("<longname_ja[^>]*>(.*?)</longname_ja>"))) {
        outName = m[1].str();
    }

    if (std::regex_search(text, m, std::regex("<product_code[^>]*>(.*?)</product_code>"))) {
        outProductCode = m[1].str();
    }

    if (std::regex_search(text, m, std::regex("<title_version[^>]*>(.*?)</title_version>"))) {
        try {
            outVersion = static_cast<uint16_t>(std::stoul(m[1].str()));
        } catch (...) {}
    }

    if (std::regex_search(text, m, std::regex("<title_id[^>]*>(.*?)</title_id>"))) {
        try {
            outTitleId = TitleId::FromString(m[1].str());
        } catch (...) {}
    }

    return true;
}

bool WfsTitleManager::HasTicket(TitleId titleId) {
    if (!fs_ || !fs_->IsMounted()) return false;
    std::string pkgTicketPath = "/usr/packages/" + titleId.ToContinuousHexString() + "/title.tik";
    uint32_t cluster;
    WfsInodeDisk inode;
    return fs_->ResolvePath(pkgTicketPath, cluster, inode);
}

bool WfsTitleManager::InjectTicket(TitleId titleId, const uint8_t* ticketData, size_t ticketSize) {
    if (!fs_ || !fs_->IsMounted() || !ticketData || ticketSize < sizeof(WfsTicketHeader)) {
        return false;
    }

    std::string pkgDir = "/usr/packages/" + titleId.ToContinuousHexString();
    fs_->CreateDirectoryRecursive(pkgDir);

    std::string ticketPath = pkgDir + "/title.tik";
    return fs_->WriteFile(ticketPath, ticketData, ticketSize);
}

bool WfsTitleManager::RemoveTicket(TitleId titleId) {
    if (!fs_ || !fs_->IsMounted()) return false;
    std::string ticketPath = "/usr/packages/" + titleId.ToContinuousHexString() + "/title.tik";
    return fs_->DeleteFile(ticketPath);
}

bool WfsTitleManager::UninstallTitle(
    TitleId titleId,
    bool deleteTicket,
    bool forceSystemTitle,
    bool dryRun,
    const std::string& backupDir
) {
    if (!fs_ || !fs_->IsMounted()) return false;

    // Step 1: Guardrail Check - System / Shared Titles Protection
    if (titleId.IsSystemOrShared() && !forceSystemTitle) {
        std::cerr << "[WfsTitleManager] Safety Error: Attempted to delete protected system/shared title "
                  << titleId.ToHexString() << ". Use forceSystemTitle to override." << std::endl;
        throw WfsException(WfsResult::SystemTitleProtected);
    }

    // Step 2: Target Resolution
    std::string titlePath = titleId.GetHierarchyPath();
    uint32_t targetCluster;
    WfsInodeDisk targetInode;
    if (!fs_->ResolvePath(titlePath, targetCluster, targetInode)) {
        std::cerr << "[WfsTitleManager] Target Title ID not found on WFS: " << titlePath << std::endl;
        throw WfsException(WfsResult::TitleNotFound);
    }

    std::cout << "[WfsTitleManager] Starting Safe Uninstallation for Title " 
              << titleId.ToHexString() << " (" << titlePath << ")..." << std::endl;

    if (dryRun) {
        std::cout << "[WfsTitleManager] [DRY RUN] Simulating deletion of " << titlePath << "..." << std::endl;
    }

    // Step 3: Offline Backup of Metadata before write
    if (!backupDir.empty()) {
        fs_->GetTransaction()->CreateOfflineMetadataBackup(
            backupDir + "/wfs_backup_pre_uninstall_" + titleId.ToContinuousHexString() + ".wfsbak",
            fs_->GetSuperblock(),
            fs_->GetSuperblock().backup_superblock_lba
        );
    }

    // Step 4: Begin Atomic Transaction
    fs_->BeginTransaction(backupDir);

    // Step 5: Recursive Block Freeing across the title directory tree
    if (!fs_->RemoveDirectory(titlePath, true)) {
        std::cerr << "[WfsTitleManager] Failed during recursive directory removal of " << titlePath << std::endl;
        fs_->RollbackTransaction();
        return false;
    }

    // Step 6: Database & Package Manifest Cleanup
    std::string pkgPath = "/usr/packages/" + titleId.ToContinuousHexString();
    uint32_t pkgCluster;
    WfsInodeDisk pkgInode;
    if (fs_->ResolvePath(pkgPath, pkgCluster, pkgInode)) {
        fs_->RemoveDirectory(pkgPath, true);
    }

    // Step 7: Ticket Synchronization
    if (deleteTicket && !titleId.IsSystemOrShared()) {
        RemoveTicket(titleId);
    }

    // Step 8: Orphan Prevention & Integrity Verification
    std::vector<std::string> integrityIssues;
    if (!fs_->CheckIntegrity(integrityIssues)) {
        std::cerr << "[WfsTitleManager] Post-uninstallation integrity check failed! Triggering automatic rollback." << std::endl;
        for (const auto& issue : integrityIssues) {
            std::cerr << "  - " << issue << std::endl;
        }
        fs_->RollbackTransaction();
        throw WfsException(WfsResult::IntegrityCheckFailed, "Orphan or unallocated cluster detected during uninstall");
    }

    // Step 9: Atomic Commit
    if (dryRun) {
        fs_->RollbackTransaction();
        std::cout << "[WfsTitleManager] [DRY RUN] Simulation successful. Zero disk sectors modified." << std::endl;
        return true;
    }

    if (!fs_->CommitTransaction()) {
        std::cerr << "[WfsTitleManager] Atomic commit failed during title uninstallation!" << std::endl;
        return false;
    }

    std::cout << "[WfsTitleManager] Title " << titleId.ToHexString() 
              << " safely uninstalled with zero corruption." << std::endl;
    return true;
}

bool WfsTitleManager::ScanHostDirectoryFiles(const std::string& folderPath, std::vector<std::pair<std::string, uint64_t>>& outFiles) {
    outFiles.clear();
    try {
        for (const auto& entry : fs::recursive_directory_iterator(folderPath)) {
            if (entry.is_regular_file()) {
                std::string relPath = fs::relative(entry.path(), folderPath).generic_string();
                uint64_t size = entry.file_size();
                outFiles.push_back({ relPath, size });
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool WfsTitleManager::InstallFromUnpackedFolder(
    const std::string& hostFolderPath,
    TitleId titleIdOverride,
    bool dryRun,
    const std::string& backupDir
) {
    if (!fs_ || !fs_->IsMounted()) return false;

    // Step 1: Scan host files
    std::vector<std::pair<std::string, uint64_t>> hostFiles;
    if (!ScanHostDirectoryFiles(hostFolderPath, hostFiles) || hostFiles.empty()) {
        std::cerr << "[WfsTitleManager] Host folder is empty or inaccessible: " << hostFolderPath << std::endl;
        return false;
    }

    // Step 2: Determine Title ID
    TitleId targetTitleId = titleIdOverride;
    if (targetTitleId.fullId == 0) {
        std::string metaXmlPath = hostFolderPath + "/meta/meta.xml";
        if (fs::exists(metaXmlPath)) {
            std::ifstream in(metaXmlPath, std::ios::binary);
            std::vector<uint8_t> xmlData((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            std::string name, code;
            uint16_t ver;
            ParseMetaXml(xmlData, name, code, ver, targetTitleId);
        }
    }

    if (targetTitleId.fullId == 0) {
        std::cerr << "[WfsTitleManager] Unable to auto-detect Title ID from meta.xml. Title ID must be specified." << std::endl;
        return false;
    }

    // Step 3: Pre-flight Space & Allocation Check
    uint32_t clusterSize = fs_->GetClusterSize();
    uint64_t totalBytes = 0;
    uint32_t totalClustersNeeded = 0;

    for (const auto& f : hostFiles) {
        totalBytes += f.second;
        uint32_t clustersForFile = static_cast<uint32_t>((f.second + clusterSize - 1) / clusterSize);
        if (clustersForFile == 0) clustersForFile = 1;
        totalClustersNeeded += clustersForFile + 1; // +1 cluster for Inode
    }
    totalClustersNeeded += 32;

    uint32_t freeClusters = fs_->GetAllocator()->GetFreeClusterCount();
    std::cout << "[WfsTitleManager] Pre-flight Check: Total required clusters = " << totalClustersNeeded 
              << " (" << (totalClustersNeeded * clusterSize / 1024 / 1024) << " MB), Available free clusters = " 
              << freeClusters << " (" << (freeClusters * clusterSize / 1024 / 1024) << " MB)" << std::endl;

    if (totalClustersNeeded > freeClusters) {
        std::cerr << "[WfsTitleManager] Pre-flight Space Check Failed! Not enough free space on WFS drive." << std::endl;
        throw WfsException(WfsResult::InsufficientFreeSpace);
    }

    std::string targetWfsRoot = targetTitleId.GetHierarchyPath();
    std::cout << "[WfsTitleManager] Target installation path: " << targetWfsRoot << std::endl;

    // Step 4: Pre-transaction offline backup
    if (!backupDir.empty()) {
        fs_->GetTransaction()->CreateOfflineMetadataBackup(
            backupDir + "/wfs_backup_pre_install_" + targetTitleId.ToContinuousHexString() + ".wfsbak",
            fs_->GetSuperblock(),
            fs_->GetSuperblock().backup_superblock_lba
        );
    }

    // Step 5: Begin Transaction
    fs_->BeginTransaction(backupDir);

    // Step 6: Create target directory tree and copy files
    fs_->CreateDirectoryRecursive(targetWfsRoot);

    for (const auto& f : hostFiles) {
        std::string hostFilePath = hostFolderPath + "/" + f.first;
        std::string wfsFilePath = targetWfsRoot + "/" + f.first;

        std::ifstream in(hostFilePath, std::ios::binary);
        if (!in.is_open()) {
            std::cerr << "[WfsTitleManager] Failed to read source file: " << hostFilePath << std::endl;
            fs_->RollbackTransaction();
            return false;
        }

        std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (!fs_->WriteFile(wfsFilePath, fileData.data(), fileData.size())) {
            std::cerr << "[WfsTitleManager] Failed to write file to WFS: " << wfsFilePath << std::endl;
            fs_->RollbackTransaction();
            return false;
        }
    }

    // Step 7: Ticket Injection
    std::string hostTikPath = hostFolderPath + "/title.tik";
    if (fs::exists(hostTikPath)) {
        std::ifstream in(hostTikPath, std::ios::binary);
        std::vector<uint8_t> tikData((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        InjectTicket(targetTitleId, tikData.data(), tikData.size());
        std::cout << "[WfsTitleManager] Injected ticket into /usr/packages/" 
                  << targetTitleId.ToContinuousHexString() << "/title.tik" << std::endl;
    }

    // Step 8: Post-install Integrity Verification
    std::vector<std::string> issues;
    if (!fs_->CheckIntegrity(issues)) {
        std::cerr << "[WfsTitleManager] Post-install integrity check failed! Rolling back." << std::endl;
        for (const auto& issue : issues) std::cerr << "  - " << issue << std::endl;
        fs_->RollbackTransaction();
        return false;
    }

    // Step 9: Commit
    if (dryRun) {
        fs_->RollbackTransaction();
        std::cout << "[WfsTitleManager] [DRY RUN] Installation simulation completed successfully." << std::endl;
        return true;
    }

    if (!fs_->CommitTransaction()) {
        std::cerr << "[WfsTitleManager] Commit failed during installation!" << std::endl;
        return false;
    }

    std::cout << "[WfsTitleManager] Successfully installed Title " 
              << targetTitleId.ToHexString() << " to WFS!" << std::endl;
    return true;
}

bool WfsTitleManager::InstallFromNUSPackage(
    const std::string& hostNusFolderPath,
    bool dryRun,
    const std::string& backupDir
) {
    if (!fs_ || !fs_->IsMounted()) return false;

    std::string tmdPath = hostNusFolderPath + "/title.tmd";
    std::string tikPath = hostNusFolderPath + "/title.tik";

    if (!fs::exists(tmdPath)) {
        std::cerr << "[WfsTitleManager] Missing title.tmd in NUS package folder: " << hostNusFolderPath << std::endl;
        return false;
    }

    std::ifstream tmdFile(tmdPath, std::ios::binary);
    std::vector<uint8_t> tmdData((std::istreambuf_iterator<char>(tmdFile)), std::istreambuf_iterator<char>());
    if (tmdData.size() < sizeof(WfsTmdHeader)) {
        std::cerr << "[WfsTitleManager] Corrupt or truncated title.tmd" << std::endl;
        return false;
    }

    const WfsTmdHeader* tmd = reinterpret_cast<const WfsTmdHeader*>(tmdData.data());
    uint64_t rawTitleId = BigEndian64(tmd->title_id);
    TitleId titleId(rawTitleId);

    std::cout << "[WfsTitleManager] NUS Package detected: Title ID " 
              << titleId.ToHexString() << ", Version " << BigEndian16(tmd->title_version) 
              << ", Contents: " << BigEndian16(tmd->num_contents) << std::endl;

    std::vector<std::pair<std::string, uint64_t>> files;
    ScanHostDirectoryFiles(hostNusFolderPath, files);

    return InstallFromUnpackedFolder(hostNusFolderPath, titleId, dryRun, backupDir);
}

} // namespace WfsManager

