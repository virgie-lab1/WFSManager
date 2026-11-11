#pragma once

#include "WfsCommon.h"
#include "WfsStructures.h"
#include "WfsFileSystem.h"
#include <string>
#include <vector>
#include <memory>

namespace WfsManager {

struct InstalledTitleInfo {
    TitleId id;
    TitleCategory category;
    std::string rootPath;
    std::string titleName;
    std::string productCode;
    uint16_t version;
    uint64_t totalSizeBytes;
    bool hasTicket;
    bool hasTmd;
    bool isSystem;
};

class WfsTitleManager {
public:
    explicit WfsTitleManager(WfsFileSystem* fs);

    // Title Enumeration
    bool EnumerateInstalledTitles(std::vector<InstalledTitleInfo>& outTitles);
    bool GetTitleInfo(TitleId titleId, InstalledTitleInfo& outInfo);

    // Title Deletion / Uninstallation Pipeline
    bool UninstallTitle(
        TitleId titleId,
        bool deleteTicket = true,
        bool forceSystemTitle = false,
        bool dryRun = false,
        const std::string& backupDir = ""
    );

    // Title Installation Pipeline from Unpacked Folder (code, content, meta)
    bool InstallFromUnpackedFolder(
        const std::string& hostFolderPath,
        TitleId titleIdOverride = TitleId(0),
        bool dryRun = false,
        const std::string& backupDir = ""
    );

    // Title Installation Pipeline from Encrypted NUS Package (.app, .h3, .tmd, title.tik)
    bool InstallFromNUSPackage(
        const std::string& hostNusFolderPath,
        bool dryRun = false,
        const std::string& backupDir = ""
    );

    // Ticket & Database Management
    bool InjectTicket(TitleId titleId, const uint8_t* ticketData, size_t ticketSize);
    bool HasTicket(TitleId titleId);
    bool RemoveTicket(TitleId titleId);

private:
    WfsFileSystem* fs_;

    bool ParseMetaXml(const std::vector<uint8_t>& xmlData, std::string& outName, std::string& outProductCode, uint16_t& outVersion, TitleId& outTitleId);
    bool ScanHostDirectoryFiles(const std::string& folderPath, std::vector<std::pair<std::string, uint64_t>>& outFiles);
    uint64_t CalculateDirectorySize(const std::string& wfsDirPath);
};

} // namespace WfsManager

