#pragma once

#include "WfsCommon.h"
#include "WfsDiskDevice.h"
#include "WfsFileSystem.h"
#include "WfsDriveHealth.h"
#include <string>
#include <vector>

namespace WfsManager {

struct SafetyAuditReport {
    bool diskLockVerified;
    bool superblockValid;
    bool backupSuperblockValid;
    bool allocationTableValid;
    bool driveHealthSafe;
    DriveHealthStatus driveHealthStatus;
    uint32_t orphanClusterCount;
    uint32_t unallocatedReferenceCount;
    std::vector<std::string> warnings;
    std::vector<std::string> criticalErrors;

    bool CanProceedWithWrite() const {
        return diskLockVerified && superblockValid && allocationTableValid && driveHealthSafe && criticalErrors.empty();
    }
};

class WfsSafetyGuard {
public:
    // Verify that the drive is exclusively locked against Windows OS background interference
    static bool VerifyExclusiveDiskLock(IWfsDevice* device, std::vector<std::string>& outIssues);

    // Full pre-flight integrity audit of the filesystem
    static SafetyAuditReport RunPreflightAudit(WfsFileSystem* fs, IWfsDevice* device);

    // Validates that an uninstallation will not break system integrity
    static bool ValidateUninstallSafety(
        WfsFileSystem* fs,
        TitleId titleId,
        bool forceSystemTitle,
        std::vector<std::string>& outErrors
    );

    // Validates space and directory parameters before an installation begins
    static bool ValidateInstallSafety(
        WfsFileSystem* fs,
        uint64_t requiredBytes,
        TitleId targetTitleId,
        std::vector<std::string>& outErrors
    );

    // Prints human-readable audit report
    static void PrintAuditReport(const SafetyAuditReport& report);
};

} // namespace WfsManager

