#include "WfsCommon.h"
#include "WfsDiskDevice.h"
#include "WfsCrypto.h"
#include "WfsFileSystem.h"
#include "WfsTitleManager.h"
#include "WfsSafetyGuard.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <memory>
#include <iomanip>

using namespace WfsManager;

static void PrintUsage(const char* exeName) {
    std::cout << "WFS Manager - Production-Safe Wii U USB Storage Management Tool\n"
              << "Usage: " << exeName << " [device_options] <command> [command_options]\n\n"
              << "Device Options:\n"
              << "  --drive <index>          Physical drive index (e.g. 1 for \\\\.\\PhysicalDrive1)\n"
              << "  --image <path>           Path to raw WFS disk image file (.img/.bin)\n"
              << "  --otp <path>             Path to console otp.bin (1024 bytes)\n"
              << "  --seeprom <path>         Path to console seeprom.bin (512 bytes)\n"
              << "  --dry-run                Simulate writes in-memory without touching physical disk\n"
              << "  --backup-dir <path>      Directory to store automatic pre-transaction metadata backups\n\n"
              << "Commands:\n"
              << "  list                     List all installed applications, updates, and DLCs\n"
              << "  info <title_id>          Display detailed metadata and cluster layout of a title\n"
              << "  uninstall <title_id>     Safely uninstall title, free blocks, and clean tickets\n"
              << "                           [--keep-ticket] Preserve ticket in ticket repository\n"
              << "                           [--force] Force uninstallation even for system titles\n"
              << "  install <path>           Install unpacked title folder or NUS package\n"
              << "                           [--title-id <id>] Explicit Title ID override\n"
              << "  verify                   Perform full filesystem consistency & cluster audit\n"
              << "  backup <out_file>        Snapshot superblock and allocation tables to host PC\n"
              << "  restore <in_file>        Restore filesystem metadata from an offline backup file\n"
              << std::endl;
}

static bool LoadBinaryFile(const std::string& path, std::vector<uint8_t>& outData) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    outData.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    int driveIndex = -1;
    std::string imagePath;
    std::string otpPath = "otp.bin";
    std::string seepromPath = "seeprom.bin";
    std::string backupDir = "./backups";
    bool dryRun = false;
    bool keepTicket = false;
    bool forceSystem = false;
    std::string explicitTitleId;

    std::string command;
    std::vector<std::string> cmdArgs;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--drive" && i + 1 < argc) {
            driveIndex = std::stoi(argv[++i]);
        } else if (arg == "--image" && i + 1 < argc) {
            imagePath = argv[++i];
        } else if (arg == "--otp" && i + 1 < argc) {
            otpPath = argv[++i];
        } else if (arg == "--seeprom" && i + 1 < argc) {
            seepromPath = argv[++i];
        } else if (arg == "--backup-dir" && i + 1 < argc) {
            backupDir = argv[++i];
        } else if (arg == "--dry-run") {
            dryRun = true;
        } else if (arg == "--keep-ticket") {
            keepTicket = true;
        } else if (arg == "--force") {
            forceSystem = true;
        } else if (arg == "--title-id" && i + 1 < argc) {
            explicitTitleId = argv[++i];
        } else if (command.empty() && arg[0] != '-') {
            command = arg;
        } else {
            cmdArgs.push_back(arg);
        }
    }

    if (command.empty()) {
        PrintUsage(argv[0]);
        return 1;
    }

    // Load Cryptographic Keys
    std::vector<uint8_t> otpData, seepromData;
    if (!LoadBinaryFile(otpPath, otpData) || otpData.size() < 1024) {
        std::cerr << "Error: Failed to load valid 1024-byte OTP file from: " << otpPath << std::endl;
        return 1;
    }
    if (!LoadBinaryFile(seepromPath, seepromData) || seepromData.size() < 512) {
        std::cerr << "Error: Failed to load valid 512-byte SEEPROM file from: " << seepromPath << std::endl;
        return 1;
    }

    // Open Storage Device
    std::unique_ptr<IWfsDevice> device;
    if (driveIndex >= 0) {
        std::cout << "Opening Physical Drive \\\\.\\PhysicalDrive" << driveIndex 
                  << (dryRun ? " [DRY-RUN VIRTUAL OVERLAY]" : " [EXCLUSIVE WRITE LOCK]") << "..." << std::endl;
        device = std::make_unique<WfsPhysicalDiskDevice>(driveIndex, false, dryRun);
    } else if (!imagePath.empty()) {
        std::cout << "Opening Image File " << imagePath 
                  << (dryRun ? " [DRY-RUN VIRTUAL OVERLAY]" : " [DIRECT READ/WRITE]") << "..." << std::endl;
        device = std::make_unique<WfsFileImageDevice>(imagePath, false, dryRun);
    } else {
        std::cerr << "Error: Must specify either --drive <index> or --image <path>" << std::endl;
        return 1;
    }

    if (!device->Open()) {
        std::cerr << "Error: Could not open device. Ensure Administrator privileges are granted." << std::endl;
        return 1;
    }

    // Mount Filesystem
    WfsFileSystem fs;
    if (!fs.Mount(device.get(), otpData.data(), otpData.size(), seepromData.data(), seepromData.size())) {
        std::cerr << "Error: Failed to mount WFS volume. Verify drive and cryptographic keys." << std::endl;
        return 1;
    }

    WfsTitleManager titleMgr(&fs);

    // Command Dispatch
    if (command == "list") {
        std::cout << "\nScanning installed applications, updates, and DLC...\n" << std::endl;
        std::vector<InstalledTitleInfo> titles;
        if (!titleMgr.EnumerateInstalledTitles(titles)) {
            std::cerr << "Failed to enumerate titles." << std::endl;
            return 1;
        }

        std::cout << std::left << std::setw(20) << "Title ID"
                  << std::setw(12) << "Category"
                  << std::setw(10) << "Size (MB)"
                  << std::setw(8)  << "Ticket"
                  << "Title Name / Product Code" << std::endl;
        std::cout << std::string(75, '-') << std::endl;

        for (const auto& t : titles) {
            std::string catName = "Other";
            if (t.category == TitleCategory::Game) catName = "Game";
            else if (t.category == TitleCategory::Update) catName = "Update";
            else if (t.category == TitleCategory::DLC) catName = "DLC";
            else if (t.category == TitleCategory::SystemApp) catName = "System";

            std::cout << std::left << std::setw(20) << t.id.ToHexString()
                      << std::setw(12) << catName
                      << std::setw(10) << (t.totalSizeBytes / 1024 / 1024)
                      << std::setw(8)  << (t.hasTicket ? "YES" : "NO")
                      << t.titleName << " [" << t.productCode << "]" << std::endl;
        }
        std::cout << "\nTotal Installed Titles: " << titles.size() << std::endl;

    } else if (command == "info") {
        if (cmdArgs.empty()) {
            std::cerr << "Error: info command requires <title_id>" << std::endl;
            return 1;
        }
        TitleId id = TitleId::FromString(cmdArgs[0]);
        InstalledTitleInfo info;
        if (!titleMgr.GetTitleInfo(id, info)) {
            std::cerr << "Error: Title ID not found: " << id.ToHexString() << std::endl;
            return 1;
        }

        std::cout << "\n--- Title Information ---" << std::endl;
        std::cout << "Title ID:       " << info.id.ToHexString() << std::endl;
        std::cout << "Name:           " << info.titleName << std::endl;
        std::cout << "Product Code:   " << info.productCode << std::endl;
        std::cout << "Version:        v" << info.version << std::endl;
        std::cout << "Storage Size:   " << (info.totalSizeBytes / 1024 / 1024) << " MB (" << info.totalSizeBytes << " bytes)" << std::endl;
        std::cout << "WFS Location:   " << info.rootPath << std::endl;
        std::cout << "Ticket Stored:  " << (info.hasTicket ? "Yes (/usr/packages/...)" : "No") << std::endl;
        std::cout << "TMD Stored:     " << (info.hasTmd ? "Yes" : "No") << std::endl;
        std::cout << "System Title:   " << (info.isSystem ? "YES (PROTECTED)" : "No") << std::endl;

    } else if (command == "uninstall") {
        if (cmdArgs.empty()) {
            std::cerr << "Error: uninstall command requires <title_id>" << std::endl;
            return 1;
        }
        TitleId id = TitleId::FromString(cmdArgs[0]);

        // Pre-flight safety check
        auto report = WfsSafetyGuard::RunPreflightAudit(&fs, device.get());
        WfsSafetyGuard::PrintAuditReport(report);
        if (!report.CanProceedWithWrite()) {
            std::cerr << "Aborting uninstallation due to pre-flight integrity errors." << std::endl;
            return 1;
        }

        bool success = titleMgr.UninstallTitle(
            id,
            !keepTicket,
            forceSystem,
            dryRun,
            backupDir
        );

        if (!success) {
            std::cerr << "Uninstallation failed!" << std::endl;
            return 1;
        }

    } else if (command == "install") {
        if (cmdArgs.empty()) {
            std::cerr << "Error: install command requires <path_to_unpacked_or_nus_folder>" << std::endl;
            return 1;
        }
        std::string sourcePath = cmdArgs[0];

        auto report = WfsSafetyGuard::RunPreflightAudit(&fs, device.get());
        WfsSafetyGuard::PrintAuditReport(report);
        if (!report.CanProceedWithWrite()) {
            std::cerr << "Aborting installation due to pre-flight integrity errors." << std::endl;
            return 1;
        }

        TitleId explicitId(0);
        if (!explicitTitleId.empty()) {
            explicitId = TitleId::FromString(explicitTitleId);
        }

        bool success = false;
        // Detect if NUS package (.tmd present) or unpacked folder (code/content/meta)
        std::string tmdCheck = sourcePath + "/title.tmd";
        std::ifstream tmdFile(tmdCheck);
        if (tmdFile.is_open()) {
            std::cout << "Detected NUS Package format with title.tmd." << std::endl;
            success = titleMgr.InstallFromNUSPackage(sourcePath, dryRun, backupDir);
        } else {
            std::cout << "Detected Unpacked Folder format." << std::endl;
            success = titleMgr.InstallFromUnpackedFolder(sourcePath, explicitId, dryRun, backupDir);
        }

        if (!success) {
            std::cerr << "Installation failed!" << std::endl;
            return 1;
        }

    } else if (command == "verify") {
        std::cout << "Running comprehensive WFS consistency & cluster audit..." << std::endl;
        auto report = WfsSafetyGuard::RunPreflightAudit(&fs, device.get());
        WfsSafetyGuard::PrintAuditReport(report);

    } else if (command == "backup") {
        if (cmdArgs.empty()) {
            std::cerr << "Error: backup command requires <out_file>" << std::endl;
            return 1;
        }
        std::string outFile = cmdArgs[0];
        if (fs.GetTransaction()->CreateOfflineMetadataBackup(outFile, fs.GetSuperblock(), fs.GetSuperblock().backup_superblock_lba)) {
            std::cout << "Metadata snapshot successfully saved to " << outFile << std::endl;
        } else {
            std::cerr << "Backup failed!" << std::endl;
            return 1;
        }

    } else if (command == "restore") {
        if (cmdArgs.empty()) {
            std::cerr << "Error: restore command requires <in_file>" << std::endl;
            return 1;
        }
        std::string inFile = cmdArgs[0];
        WfsSuperblock restoredSb;
        uint32_t backupSbLba;
        if (fs.GetTransaction()->RestoreOfflineMetadataBackup(inFile, restoredSb, backupSbLba)) {
            std::cout << "Filesystem metadata successfully restored from " << inFile << std::endl;
        } else {
            std::cerr << "Restore failed!" << std::endl;
            return 1;
        }

    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        PrintUsage(argv[0]);
        return 1;
    }

    fs.Unmount();
    device->Close();
    return 0;
}

