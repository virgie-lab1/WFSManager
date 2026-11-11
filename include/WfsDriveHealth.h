#pragma once

#include "WfsCommon.h"
#include "WfsDiskDevice.h"
#include <string>
#include <vector>
#include <iostream>
#include <chrono>

namespace WfsManager {

enum class DriveHealthStatus {
    Good,       // Healthy, 0 pending/reallocated sectors, all thresholds safe
    Caution,    // Warning signs: reallocated sectors, pending sectors, high temp, SSD wear
    Bad,        // Imminent failure: uncorrectable sectors, threshold tripped, bad surface sectors
    Unknown     // S.M.A.R.T. not supported or blocked by USB enclosure bridge
};

enum class DriveMediaType {
    HDD,        // Rotational mechanical hard drive
    SSD,        // Solid State Drive (SATA/NVMe)
    UsbFlash,   // USB Flash thumb drive
    Virtual,    // Virtual disk / file-backed image
    Unknown
};

enum class AttributeStatus {
    Ok,
    Warning,
    Failing
};

struct SmartAttribute {
    uint8_t id;
    std::string name;
    uint8_t currentValue;
    uint8_t worstValue;
    uint8_t threshold;
    uint64_t rawValue;
    std::string rawFormatted;
    AttributeStatus status;
    bool isCritical;
};

struct DriveHealthReport {
    int driveIndex = -1;
    std::string model;
    std::string serialNumber;
    std::string firmwareRevision;
    std::string busType;
    DriveMediaType mediaType = DriveMediaType::Unknown;
    uint32_t rotationRate = 0;              // RPM (e.g. 5400, 7200, 0 = SSD)
    uint64_t totalCapacityBytes = 0;
    uint32_t sectorSize = 512;
    int temperatureC = -1;                  // Celsius (-1 if unavailable)
    int64_t powerOnHours = -1;              // Operating hours (-1 if unavailable)
    int64_t powerCycleCount = -1;           // Power cycles (-1 if unavailable)
    uint64_t reallocatedSectors = 0;        // S.M.A.R.T. 0x05
    uint64_t pendingSectors = 0;            // S.M.A.R.T. 0xC5 (unstable/pending)
    uint64_t uncorrectableSectors = 0;      // S.M.A.R.T. 0xC6
    uint64_t crcErrors = 0;                 // S.M.A.R.T. 0xC7 (interface/cable issues)
    int ssdRemainingLife = -1;              // 0-100% (-1 if not SSD / not reported)
    
    DriveHealthStatus overallHealth = DriveHealthStatus::Unknown;
    int healthScore = 100;                  // 0-100%
    
    bool smartSupported = false;
    bool smartEnabled = false;
    
    std::vector<SmartAttribute> attributes;
    std::vector<std::string> criticalWarnings;
    std::vector<std::string> cautionWarnings;
    
    // Surface Diagnostics
    bool surfaceScanCompleted = false;
    uint64_t surfaceSectorsScanned = 0;
    uint64_t surfaceBadSectors = 0;
    uint64_t surfaceSlowSectors = 0;       // > 150ms
    uint64_t surfaceVerySlowSectors = 0;   // > 500ms
    double avgReadLatencyMs = 0.0;
    double maxReadLatencyMs = 0.0;
};

class WfsDriveHealth {
public:
    // Run full health diagnosis on a physical drive index (\\.\PhysicalDriveX)
    static DriveHealthReport CheckDrive(int driveIndex, bool runSurfaceScan = false, uint64_t maxScanSectors = 0);

    // Run health diagnosis on an open IWfsDevice
    static DriveHealthReport CheckDevice(IWfsDevice* device, bool runSurfaceScan = false, uint64_t maxScanSectors = 0);

    // Parse raw ATA S.M.A.R.T. 512-byte payload and thresholds into report attributes
    static bool ParseAtaSmartData(
        const uint8_t* smartData512,
        const uint8_t* thresholds512,
        DriveHealthReport& report
    );

    // Helper to evaluate health status and populate warnings/score
    static void EvaluateHealth(DriveHealthReport& report);

    // Formatted terminal printout in the style of CrystalDiskInfo
    static void PrintReport(const DriveHealthReport& report, std::ostream& out = std::cout);

    // Human-readable string helpers
    static std::string HealthStatusToString(DriveHealthStatus status);
    static std::string MediaTypeToString(DriveMediaType type);
    static std::string GetAttributeName(uint8_t id, DriveMediaType mediaType = DriveMediaType::Unknown);
    static bool IsCriticalAttribute(uint8_t id);

private:
#if defined(_WIN32)
    static bool QueryDeviceDescriptor(HANDLE hDevice, DriveHealthReport& report);
    static bool QuerySeekPenalty(HANDLE hDevice, DriveHealthReport& report);
    static bool QuerySatIdentify(HANDLE hDevice, DriveHealthReport& report);
    static bool QuerySatSmart(HANDLE hDevice, DriveHealthReport& report);
    static bool QueryStandardSmart(HANDLE hDevice, DriveHealthReport& report);
    static bool QueryNvmeSmart(HANDLE hDevice, DriveHealthReport& report);
    static bool RunSurfaceScanWin32(HANDLE hDevice, uint64_t totalSectors, uint32_t sectorSize, DriveHealthReport& report, bool deepScan, uint64_t maxSectors);
#endif
    static bool RunGenericSurfaceScan(IWfsDevice* device, DriveHealthReport& report, bool deepScan, uint64_t maxSectors);
};

} // namespace WfsManager
