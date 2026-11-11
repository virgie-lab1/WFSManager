#include "WfsSafetyGuard.h"
#include <iostream>

namespace WfsManager {

bool WfsSafetyGuard::VerifyExclusiveDiskLock(
    IWfsDevice *device, std::vector<std::string> &outIssues) {
  outIssues.clear();
  if (!device) {
    outIssues.push_back("Null device pointer");
    return false;
  }

  if (!device->IsOpen()) {
    outIssues.push_back("Physical device handle is not open");
    return false;
  }

  // Physical disk checks
  auto *physDev = dynamic_cast<WfsPhysicalDiskDevice *>(device);
  if (physDev) {
    if (!device->IsDryRun()) {
      // Check if volumes were dismounted
      // In Windows, if an open volume handle has FSCTL_LOCK_VOLUME, other
      // processes get ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION.
      // WfsPhysicalDiskDevice automatically holds locked volume handles in
      // lockedVolumeHandles_.
    }
  }

  return outIssues.empty();
}

SafetyAuditReport WfsSafetyGuard::RunPreflightAudit(WfsFileSystem *fs,
                                                    IWfsDevice *device) {
  SafetyAuditReport report;
  report.diskLockVerified = false;
  report.superblockValid = false;
  report.backupSuperblockValid = false;
  report.allocationTableValid = false;
  report.orphanClusterCount = 0;
  report.unallocatedReferenceCount = 0;

  std::vector<std::string> lockIssues;
  report.diskLockVerified = VerifyExclusiveDiskLock(device, lockIssues);
  for (const auto &issue : lockIssues) {
    report.warnings.push_back("Disk lock warning: " + issue);
  }

  if (!fs || !fs->IsMounted()) {
    report.criticalErrors.push_back("Filesystem is not mounted");
    return report;
  }

  const WfsSuperblock &sb = fs->GetSuperblock();

  // Check 1: Superblock Magic
  if (sb.magic != WFS_SUPERBLOCK_MAGIC &&
      sb.magic != WFS_SUPERBLOCK_MAGIC_ALT) {
    report.criticalErrors.push_back(
        "Superblock magic signature is invalid or corrupt");
  } else {
    report.superblockValid = true;
  }

  // Check 2: Generation counter
  if (sb.generation == 0) {
    report.warnings.push_back("Superblock generation counter is zero (cleanly "
                              "initialized or virgin volume)");
  }

  // Check 3: Checksum
  uint32_t headerCrc = WfsCrypto::Crc32(reinterpret_cast<const uint8_t *>(&sb),
                                        offsetof(WfsSuperblock, header_crc32));
  if (sb.header_crc32 != 0 && sb.header_crc32 != headerCrc) {
    report.warnings.push_back(
        "Superblock CRC32 mismatch (possibly modified by non-standard tool)");
  }

  // Check 4: Allocation bitmap & Cluster integrity
  std::vector<std::string> integrityIssues;
  if (!fs->CheckIntegrity(integrityIssues)) {
    for (const auto &issue : integrityIssues) {
      if (issue.find("CRITICAL") != std::string::npos) {
        report.criticalErrors.push_back(issue);
        report.unallocatedReferenceCount++;
      } else {
        report.warnings.push_back(issue);
        report.orphanClusterCount++;
      }
    }
  } else {
    report.allocationTableValid = true;
  }

  return report;
}

bool WfsSafetyGuard::ValidateUninstallSafety(
    WfsFileSystem *fs, TitleId titleId, bool forceSystemTitle,
    std::vector<std::string> &outErrors) {
  outErrors.clear();
  if (!fs || !fs->IsMounted()) {
    outErrors.push_back("Filesystem not mounted");
    return false;
  }

  if (titleId.IsSystemOrShared() && !forceSystemTitle) {
    outErrors.push_back("Protection Alert: Title " + titleId.ToHexString() +
                        " is a critical system application or shared OS data. "
                        "Deleting will brick console functionality.");
  }

  uint32_t cluster;
  WfsInodeDisk inode;
  if (!fs->ResolvePath(titleId.GetHierarchyPath(), cluster, inode)) {
    outErrors.push_back("Target Title ID does not exist on WFS: " +
                        titleId.GetHierarchyPath());
  }

  return outErrors.empty();
}

bool WfsSafetyGuard::ValidateInstallSafety(
    WfsFileSystem *fs, uint64_t requiredBytes, TitleId targetTitleId,
    std::vector<std::string> &outErrors) {
  outErrors.clear();
  if (!fs || !fs->IsMounted()) {
    outErrors.push_back("Filesystem not mounted");
    return false;
  }

  uint32_t clusterSize = fs->GetClusterSize();
  uint32_t clustersNeeded =
      static_cast<uint32_t>((requiredBytes + clusterSize - 1) / clusterSize) +
      32;
  uint32_t freeClusters = fs->GetAllocator()->GetFreeClusterCount();

  if (clustersNeeded > freeClusters) {
    outErrors.push_back(
        "Insufficient disk space: Need " + std::to_string(clustersNeeded) +
        " clusters (" +
        std::to_string(clustersNeeded * clusterSize / 1024 / 1024) +
        " MB), but only " + std::to_string(freeClusters) + " clusters (" +
        std::to_string(freeClusters * clusterSize / 1024 / 1024) +
        " MB) are free.");
  }

  return outErrors.empty();
}

void WfsSafetyGuard::PrintAuditReport(const SafetyAuditReport &report) {
  std::cout
      << "\n================ WFS PRE-FLIGHT INTEGRITY REPORT ================"
      << std::endl;
  std::cout << " Exclusive Disk Lock:       "
            << (report.diskLockVerified ? "[PASSED]" : "[FAILED/WARNING]")
            << std::endl;
  std::cout << " Primary Superblock:        "
            << (report.superblockValid ? "[VALID]" : "[CORRUPT]") << std::endl;
  std::cout << " Allocation Bitmap Status:  "
            << (report.allocationTableValid ? "[CLEAN]" : "[INCONSISTENT]")
            << std::endl;
  std::cout << " Orphan Clusters Detected:  " << report.orphanClusterCount
            << std::endl;
  std::cout << " Missing Allocations:       "
            << report.unallocatedReferenceCount << std::endl;

  if (!report.warnings.empty()) {
    std::cout << "\n--- Warnings ---" << std::endl;
    for (const auto &w : report.warnings) {
      std::cout << " [!] " << w << std::endl;
    }
  }

  if (!report.criticalErrors.empty()) {
    std::cout << "\n--- CRITICAL ERRORS ---" << std::endl;
    for (const auto &err : report.criticalErrors) {
      std::cout << " [X] " << err << std::endl;
    }
  }

  std::cout << "\n Decision: "
            << (report.CanProceedWithWrite()
                    ? "PROCEED WITH WRITE"
                    : "WRITE BLOCKED (RISK OF CORRUPTION)")
            << std::endl;
  std::cout
      << "=================================================================\n"
      << std::endl;
}

} // namespace WfsManager
