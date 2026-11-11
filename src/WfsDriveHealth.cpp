#include "WfsDriveHealth.h"
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <map>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

// Self-contained definitions for SCSI and ATA Pass-Through to ensure portability across all SDK versions
#pragma pack(push, 8)
struct WFS_SCSI_PASS_THROUGH {
    USHORT Length;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR CdbLength;
    UCHAR SenseInfoLength;
    UCHAR DataIn;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG_PTR DataBufferOffset;
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
};

struct WFS_SCSI_PASS_THROUGH_WITH_BUFFERS {
    WFS_SCSI_PASS_THROUGH spt;
    ULONG Filler;
    UCHAR ucSenseBuf[32];
    UCHAR ucDataBuf[512];
};
#pragma pack(pop)

#define WFS_IOCTL_SCSI_PASS_THROUGH  0x0004D004
#define WFS_SCSI_IOCTL_DATA_IN       1

// Standard Win32 SMART IOCTLs
#define WFS_SMART_GET_VERSION        0x00074080
#define WFS_SMART_RCV_DRIVE_DATA     0x0007C088

#pragma pack(push, 1)
struct WFS_IDEREGS {
    UCHAR bFeaturesReg;
    UCHAR bSectorCountReg;
    UCHAR bSectorNumberReg;
    UCHAR bCylLowReg;
    UCHAR bCylHighReg;
    UCHAR bDriveHeadReg;
    UCHAR bCommandReg;
    UCHAR bReserved;
};

struct WFS_SENDCMDINPARAMS {
    ULONG cBufferSize;
    WFS_IDEREGS irDriveRegs;
    UCHAR bDriveNumber;
    UCHAR bReserved[3];
    ULONG dwReserved[4];
    UCHAR bBuffer[1];
};

struct WFS_DRIVERSTATUS {
    UCHAR bDriverError;
    UCHAR bIDEError;
    UCHAR bReserved[2];
    ULONG dwReserved[2];
};

struct WFS_SENDCMDOUTPARAMS {
    ULONG cBufferSize;
    WFS_DRIVERSTATUS DriverStatus;
    UCHAR bBuffer[512];
};

struct WFS_GETVERSIONINPARAMS {
    UCHAR bVersion;
    UCHAR bRevision;
    UCHAR bReserved;
    UCHAR bIDEDeviceMap;
    ULONG fCapabilities;
    ULONG dwReserved[4];
};

// NVMe Protocol Specific Query structures
#define WFS_STORAGE_PROTOCOL_NVME    1
#define WFS_NVME_DATA_TYPE_LOG_PAGE  2

struct WFS_STORAGE_PROTOCOL_SPECIFIC_DATA {
    ULONG ProtocolType;
    ULONG DataType;
    ULONG ProtocolDataRequestValue;
    ULONG ProtocolDataRequestSubValue;
    ULONG ProtocolDataOffset;
    ULONG ProtocolDataLength;
    ULONG FixedProtocolReturnData;
    ULONG ProtocolDataRequestSubValue2;
    ULONG ProtocolDataRequestSubValue3;
    ULONG Reserved;
};

struct WFS_STORAGE_PROPERTY_QUERY_PROTOCOL {
    STORAGE_PROPERTY_ID PropertyId;
    STORAGE_QUERY_TYPE QueryType;
    WFS_STORAGE_PROTOCOL_SPECIFIC_DATA ProtocolSpecificData;
};
#pragma pack(pop)

#endif // _WIN32

namespace WfsManager {

std::string WfsDriveHealth::HealthStatusToString(DriveHealthStatus status) {
    switch (status) {
        case DriveHealthStatus::Good:    return "Good";
        case DriveHealthStatus::Caution: return "Caution";
        case DriveHealthStatus::Bad:     return "Bad";
        case DriveHealthStatus::Unknown: default: return "Unknown";
    }
}

std::string WfsDriveHealth::MediaTypeToString(DriveMediaType type) {
    switch (type) {
        case DriveMediaType::HDD:      return "Hard Disk Drive (HDD)";
        case DriveMediaType::SSD:      return "Solid State Drive (SSD)";
        case DriveMediaType::UsbFlash: return "USB Flash Drive";
        case DriveMediaType::Virtual:  return "Virtual Disk Image";
        case DriveMediaType::Unknown: default: return "Unknown Media";
    }
}

bool WfsDriveHealth::IsCriticalAttribute(uint8_t id) {
    switch (id) {
        case 0x05: // Reallocated Sectors Count
        case 0x0A: // Spin Retry Count
        case 0xAA: // Available Reserved Space (SSD)
        case 0xB8: // End-to-End Error
        case 0xBB: // Reported Uncorrectable Errors
        case 0xBC: // Command Timeout
        case 0xC4: // Reallocation Event Count
        case 0xC5: // Current Pending Sector Count
        case 0xC6: // Offline Uncorrectable Sector Count
        case 0xE7: // SSD Remaining Life
            return true;
        default:
            return false;
    }
}

std::string WfsDriveHealth::GetAttributeName(uint8_t id, DriveMediaType mediaType) {
    switch (id) {
        case 0x01: return "Read Error Rate";
        case 0x02: return "Throughput Performance";
        case 0x03: return "Spin-Up Time";
        case 0x04: return "Start/Stop Count";
        case 0x05: return "Reallocated Sectors Count";
        case 0x07: return "Seek Error Rate";
        case 0x08: return "Seek Time Performance";
        case 0x09: return "Power-On Hours";
        case 0x0A: return "Spin Retry Count";
        case 0x0B: return "Calibration Retry Count";
        case 0x0C: return "Power Cycle Count";
        case 0xAA: return (mediaType == DriveMediaType::SSD) ? "Available Reserved Space" : "Unknown";
        case 0xAB: return (mediaType == DriveMediaType::SSD) ? "Program Fail Count" : "Unknown";
        case 0xAC: return (mediaType == DriveMediaType::SSD) ? "Erase Fail Count" : "Unknown";
        case 0xAE: return "Unexpected Power Loss Count";
        case 0xB7: return "SATA Downshift Error Count";
        case 0xB8: return "End-to-End Error";
        case 0xBB: return "Reported Uncorrectable Errors";
        case 0xBC: return "Command Timeout";
        case 0xBD: return "High Fly Writes";
        case 0xBE: return "Airflow Temperature";
        case 0xBF: return "G-Sense Error Rate";
        case 0xC0: return "Power-Off Retract Count";
        case 0xC1: return "Load/Unload Cycle Count";
        case 0xC2: return "Temperature";
        case 0xC3: return "Hardware ECC Recovered";
        case 0xC4: return "Reallocation Event Count";
        case 0xC5: return "Current Pending Sector Count";
        case 0xC6: return "Offline Uncorrectable Sector Count";
        case 0xC7: return "UltraDMA CRC Error Count";
        case 0xC8: return "Multi-Zone / Write Error Rate";
        case 0xE7: return (mediaType == DriveMediaType::SSD) ? "SSD Life Left" : "Unknown";
        case 0xF0: return "Head Flying Hours";
        case 0xF1: return "Total LBAs Written";
        case 0xF2: return "Total LBAs Read";
        default: {
            std::stringstream ss;
            ss << "Vendor Specific (" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)id << ")";
            return ss.str();
        }
    }
}

bool WfsDriveHealth::ParseAtaSmartData(
    const uint8_t* smartData512,
    const uint8_t* thresholds512,
    DriveHealthReport& report
) {
    if (!smartData512) return false;

    // Thresholds map: ID -> threshold
    std::map<uint8_t, uint8_t> thresholdMap;
    if (thresholds512) {
        for (size_t i = 0; i < 30; ++i) {
            size_t offset = 2 + i * 12;
            uint8_t id = thresholds512[offset];
            uint8_t th = thresholds512[offset + 1];
            if (id != 0) {
                thresholdMap[id] = th;
            }
        }
    }

    report.attributes.clear();
    report.smartSupported = true;
    report.smartEnabled = true;

    // 30 entries of 12 bytes each, starting at offset 2
    for (size_t i = 0; i < 30; ++i) {
        size_t offset = 2 + i * 12;
        uint8_t id = smartData512[offset];
        if (id == 0) continue; // Unused attribute slot

        uint8_t current = smartData512[offset + 3];
        uint8_t worst = smartData512[offset + 4];

        // 48-bit raw value
        uint64_t raw = 0;
        for (int b = 0; b < 6; ++b) {
            raw |= (static_cast<uint64_t>(smartData512[offset + 5 + b]) << (b * 8));
        }

        uint8_t threshold = 0;
        auto thIt = thresholdMap.find(id);
        if (thIt != thresholdMap.end()) {
            threshold = thIt->second;
        }

        SmartAttribute attr;
        attr.id = id;
        attr.name = GetAttributeName(id, report.mediaType);
        attr.currentValue = current;
        attr.worstValue = worst;
        attr.threshold = threshold;
        attr.rawValue = raw;
        attr.isCritical = IsCriticalAttribute(id);

        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setw(12) << std::setfill('0') << raw;
        attr.rawFormatted = ss.str();

        // Status evaluation
        if (threshold > 0 && current <= threshold) {
            attr.status = AttributeStatus::Failing;
        } else if (attr.isCritical && raw > 0) {
            if (id == 0xC5 || id == 0xC6 || id == 0x05) {
                attr.status = AttributeStatus::Warning;
            } else {
                attr.status = AttributeStatus::Ok;
            }
        } else {
            attr.status = AttributeStatus::Ok;
        }

        // Special field extractions
        if (id == 0xC2 || id == 0xBE) {
            // Temperature in lower byte
            int temp = static_cast<int>(smartData512[offset + 5]);
            if (temp > 0 && temp < 120) {
                report.temperatureC = temp;
            }
        } else if (id == 0x09) {
            report.powerOnHours = static_cast<int64_t>(raw & 0xFFFFFFFF);
        } else if (id == 0x0C) {
            report.powerCycleCount = static_cast<int64_t>(raw & 0xFFFFFFFF);
        } else if (id == 0x05) {
            report.reallocatedSectors = raw;
        } else if (id == 0xC5) {
            report.pendingSectors = raw;
        } else if (id == 0xC6) {
            report.uncorrectableSectors = raw;
        } else if (id == 0xC7) {
            report.crcErrors = raw;
        } else if (id == 0xE7 && report.mediaType == DriveMediaType::SSD) {
            report.ssdRemainingLife = static_cast<int>(current);
        }

        report.attributes.push_back(attr);
    }

    return !report.attributes.empty();
}

void WfsDriveHealth::EvaluateHealth(DriveHealthReport& report) {
    report.criticalWarnings.clear();
    report.cautionWarnings.clear();
    report.healthScore = 100;

    bool hasFailing = false;
    bool hasCaution = false;

    // Check S.M.A.R.T. attributes
    for (const auto& attr : report.attributes) {
        if (attr.status == AttributeStatus::Failing) {
            hasFailing = true;
            report.criticalWarnings.push_back(
                "SMART threshold breached for " + attr.name + 
                " (Current: " + std::to_string(attr.currentValue) + 
                ", Threshold: " + std::to_string(attr.threshold) + ")"
            );
        }
    }

    // Check Critical Raw Values
    if (report.uncorrectableSectors > 0) {
        hasFailing = true;
        report.criticalWarnings.push_back(
            "Drive reports " + std::to_string(report.uncorrectableSectors) + 
            " Offline Uncorrectable Sectors (0xC6). Unreadable sectors will cause filesystem I/O aborts!"
        );
        report.healthScore -= 50;
    }

    if (report.pendingSectors > 0) {
        hasCaution = true;
        report.cautionWarnings.push_back(
            "Drive reports " + std::to_string(report.pendingSectors) + 
            " Current Pending / Unstable Sectors (0xC5). Sectors may fail upon next write operation!"
        );
        report.healthScore -= std::min(40, static_cast<int>(report.pendingSectors * 10));
    }

    if (report.reallocatedSectors > 0) {
        hasCaution = true;
        report.cautionWarnings.push_back(
            "Drive reports " + std::to_string(report.reallocatedSectors) + 
            " Reallocated Sectors (0x05). Media degradation in progress."
        );
        report.healthScore -= std::min(30, static_cast<int>(report.reallocatedSectors * 5));
    }

    if (report.crcErrors > 0) {
        report.cautionWarnings.push_back(
            "Drive reports " + std::to_string(report.crcErrors) + 
            " UltraDMA CRC Errors (0xC7). Inspect USB cable, port connection, or USB bridge."
        );
        report.healthScore -= 5;
    }

    // Check Temperature
    if (report.temperatureC >= 65) {
        hasFailing = true;
        report.criticalWarnings.push_back(
            "Critical drive temperature detected: " + std::to_string(report.temperatureC) + "°C (Exceeds 65°C safe limit)!"
        );
        report.healthScore -= 30;
    } else if (report.temperatureC >= 55) {
        hasCaution = true;
        report.cautionWarnings.push_back(
            "High drive operating temperature: " + std::to_string(report.temperatureC) + "°C."
        );
        report.healthScore -= 10;
    }

    // Check SSD Health
    if (report.ssdRemainingLife >= 0) {
        if (report.ssdRemainingLife == 0) {
            hasFailing = true;
            report.criticalWarnings.push_back("SSD wear endurance exhausted (0% remaining life)!");
            report.healthScore = 0;
        } else if (report.ssdRemainingLife <= 10) {
            hasCaution = true;
            report.cautionWarnings.push_back("SSD wear near end of life (" + std::to_string(report.ssdRemainingLife) + "% remaining)!");
            report.healthScore = std::min(report.healthScore, report.ssdRemainingLife);
        }
    }

    // Check Surface Scan results
    if (report.surfaceScanCompleted) {
        if (report.surfaceBadSectors > 0) {
            hasFailing = true;
            report.criticalWarnings.push_back(
                "Surface read test detected " + std::to_string(report.surfaceBadSectors) + 
                " unreadable/bad sectors on storage media!"
            );
            report.healthScore -= 40;
        } else if (report.surfaceVerySlowSectors > 0) {
            hasCaution = true;
            report.cautionWarnings.push_back(
                "Surface read test detected " + std::to_string(report.surfaceVerySlowSectors) + 
                " abnormally slow sectors (>500ms latency)."
            );
            report.healthScore -= 15;
        }
    }

    if (report.healthScore < 0) report.healthScore = 0;

    // Overall classification
    if (hasFailing) {
        report.overallHealth = DriveHealthStatus::Bad;
    } else if (hasCaution) {
        report.overallHealth = DriveHealthStatus::Caution;
    } else if (report.smartSupported || report.surfaceScanCompleted) {
        report.overallHealth = DriveHealthStatus::Good;
    } else {
        report.overallHealth = DriveHealthStatus::Unknown;
    }
}

void WfsDriveHealth::PrintReport(const DriveHealthReport& report, std::ostream& out) {
    out << "\n================================================================================\n"
        << "                      WFS MANAGER - DRIVE HEALTH REPORT                         \n"
        << "================================================================================\n";

    if (report.driveIndex >= 0) {
        out << "Physical Device:      \\\\.\\PhysicalDrive" << report.driveIndex << "\n";
    }
    if (!report.model.empty()) {
        out << "Model:                " << report.model << "\n";
    }
    if (!report.serialNumber.empty()) {
        out << "Serial Number:        " << report.serialNumber << "\n";
    }
    if (!report.firmwareRevision.empty()) {
        out << "Firmware Revision:    " << report.firmwareRevision << "\n";
    }
    if (!report.busType.empty()) {
        out << "Interface / Bus:      " << report.busType << "\n";
    }
    out << "Media Type:           " << MediaTypeToString(report.mediaType);
    if (report.rotationRate > 0) {
        out << " (" << report.rotationRate << " RPM)";
    }
    out << "\n";

    if (report.totalCapacityBytes > 0) {
        double gb = static_cast<double>(report.totalCapacityBytes) / (1000.0 * 1000.0 * 1000.0);
        out << "Total Capacity:       " << std::fixed << std::setprecision(2) << gb << " GB (" 
            << report.totalCapacityBytes << " bytes)\n";
    }

    if (report.temperatureC >= 0) {
        int tempF = static_cast<int>(report.temperatureC * 9.0 / 5.0 + 32.0);
        out << "Temperature:          " << report.temperatureC << "°C / " << tempF << "°F\n";
    }

    if (report.powerOnHours >= 0) {
        out << "Power-On Hours:       " << report.powerOnHours << " hours";
        double days = report.powerOnHours / 24.0;
        out << " (" << std::fixed << std::setprecision(1) << days << " days)\n";
    }

    if (report.powerCycleCount >= 0) {
        out << "Power Cycle Count:    " << report.powerCycleCount << " cycles\n";
    }

    if (report.ssdRemainingLife >= 0) {
        out << "SSD Remaining Life:   " << report.ssdRemainingLife << "%\n";
    }

    out << "--------------------------------------------------------------------------------\n";
    out << "OVERALL HEALTH STATUS: [ ";
    switch (report.overallHealth) {
        case DriveHealthStatus::Good:
            out << "GOOD";
            break;
        case DriveHealthStatus::Caution:
            out << "CAUTION / WARNING";
            break;
        case DriveHealthStatus::Bad:
            out << "CRITICAL FAILURE / BAD";
            break;
        case DriveHealthStatus::Unknown: default:
            out << "UNKNOWN";
            break;
    }
    out << " ] (Health Score: " << report.healthScore << "%)\n";
    out << "--------------------------------------------------------------------------------\n";

    if (!report.criticalWarnings.empty()) {
        out << "[!] CRITICAL WARNINGS:\n";
        for (const auto& w : report.criticalWarnings) {
            out << "  * " << w << "\n";
        }
        out << "\n";
    }

    if (!report.cautionWarnings.empty()) {
        out << "[*] CAUTION ADVISORIES:\n";
        for (const auto& w : report.cautionWarnings) {
            out << "  * " << w << "\n";
        }
        out << "\n";
    }

    if (!report.attributes.empty()) {
        out << " S.M.A.R.T. ATTRIBUTES TABLE:\n"
            << " ------------------------------------------------------------------------------\n"
            << " ID  Attribute Name                     Cur  Wst  Thr  Raw Value     Status    \n"
            << " ------------------------------------------------------------------------------\n";

        for (const auto& attr : report.attributes) {
            std::string statusStr = "OK";
            if (attr.status == AttributeStatus::Failing) statusStr = "FAIL";
            else if (attr.status == AttributeStatus::Warning) statusStr = "WARN";

            out << " " << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)attr.id << "  "
                << std::dec << std::left << std::setw(34) << std::setfill(' ') << attr.name.substr(0, 34)
                << std::right << std::setw(4) << (int)attr.currentValue
                << std::setw(5) << (int)attr.worstValue
                << std::setw(5) << (int)attr.threshold << "  "
                << std::left << std::setw(14) << attr.rawFormatted
                << statusStr << "\n";
        }
        out << " ------------------------------------------------------------------------------\n";
    }

    if (report.surfaceScanCompleted) {
        out << "SURFACE SECTOR DIAGNOSTICS:\n"
            << "  Sectors Tested:      " << report.surfaceSectorsScanned << "\n"
            << "  Bad / Unreadable:    " << report.surfaceBadSectors << "\n"
            << "  Slow (>150ms):       " << report.surfaceSlowSectors << "\n"
            << "  Very Slow (>500ms):  " << report.surfaceVerySlowSectors << "\n"
            << "  Average Latency:     " << std::fixed << std::setprecision(2) << report.avgReadLatencyMs << " ms\n"
            << "  Max Latency:         " << std::fixed << std::setprecision(2) << report.maxReadLatencyMs << " ms\n";
    }

    out << "================================================================================\n" << std::endl;
}

#if defined(_WIN32)

static std::string TrimString(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n\0");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n\0");
    return str.substr(first, (last - first + 1));
}

static std::string DecodeAtaString(const uint8_t* buffer, size_t length) {
    std::string s;
    s.resize(length);
    for (size_t i = 0; i < length; i += 2) {
        s[i] = static_cast<char>(buffer[i + 1]);
        s[i + 1] = static_cast<char>(buffer[i]);
    }
    return TrimString(s);
}

bool WfsDriveHealth::QueryDeviceDescriptor(HANDLE hDevice, DriveHealthReport& report) {
    STORAGE_PROPERTY_QUERY query;
    std::memset(&query, 0, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    std::vector<uint8_t> outBuf(1024, 0);
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(
        hDevice,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &query, sizeof(query),
        outBuf.data(), static_cast<DWORD>(outBuf.size()),
        &bytesReturned,
        NULL
    )) {
        return false;
    }

    STORAGE_DEVICE_DESCRIPTOR* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(outBuf.data());

    if (desc->VendorIdOffset > 0 && desc->VendorIdOffset < bytesReturned) {
        std::string vendor = reinterpret_cast<const char*>(outBuf.data() + desc->VendorIdOffset);
        report.model = TrimString(vendor);
    }

    if (desc->ProductIdOffset > 0 && desc->ProductIdOffset < bytesReturned) {
        std::string prod = reinterpret_cast<const char*>(outBuf.data() + desc->ProductIdOffset);
        if (!report.model.empty()) report.model += " ";
        report.model += TrimString(prod);
    }

    if (desc->ProductRevisionOffset > 0 && desc->ProductRevisionOffset < bytesReturned) {
        std::string rev = reinterpret_cast<const char*>(outBuf.data() + desc->ProductRevisionOffset);
        report.firmwareRevision = TrimString(rev);
    }

    if (desc->SerialNumberOffset > 0 && desc->SerialNumberOffset < bytesReturned) {
        std::string serial = reinterpret_cast<const char*>(outBuf.data() + desc->SerialNumberOffset);
        report.serialNumber = TrimString(serial);
    }

    switch (desc->BusType) {
        case BusTypeUsb:            report.busType = "USB"; break;
        case BusTypeSata:           report.busType = "SATA"; break;
        case BusTypeNvme:           report.busType = "NVMe"; break;
        case BusTypeScsi:           report.busType = "SCSI"; break;
        case BusTypeAtapi:          report.busType = "ATAPI"; break;
        case BusTypeAta:            report.busType = "ATA / IDE"; break;
        case BusTypeSd:             report.busType = "SD Card"; break;
        case BusTypeMmc:            report.busType = "MMC"; break;
        case BusTypeVirtual:
        case BusTypeFileBackedVirtual: report.busType = "Virtual Disk"; report.mediaType = DriveMediaType::Virtual; break;
        default:                    report.busType = "Storage Device (" + std::to_string(desc->BusType) + ")"; break;
    }

    return true;
}

bool WfsDriveHealth::QuerySeekPenalty(HANDLE hDevice, DriveHealthReport& report) {
    STORAGE_PROPERTY_QUERY query;
    std::memset(&query, 0, sizeof(query));
    query.PropertyId = StorageDeviceSeekPenaltyProperty;
    query.QueryType = PropertyStandardQuery;

    DEVICE_SEEK_PENALTY_DESCRIPTOR desc;
    std::memset(&desc, 0, sizeof(desc));
    DWORD bytesReturned = 0;

    if (DeviceIoControl(
        hDevice,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &query, sizeof(query),
        &desc, sizeof(desc),
        &bytesReturned,
        NULL
    ) && bytesReturned >= sizeof(desc)) {
        if (desc.IncursSeekPenalty) {
            report.mediaType = DriveMediaType::HDD;
        } else {
            if (report.mediaType != DriveMediaType::Virtual) {
                report.mediaType = (report.busType == "USB") ? DriveMediaType::UsbFlash : DriveMediaType::SSD;
            }
        }
        return true;
    }
    return false;
}

bool WfsDriveHealth::QuerySatIdentify(HANDLE hDevice, DriveHealthReport& report) {
    WFS_SCSI_PASS_THROUGH_WITH_BUFFERS sptwb;
    std::memset(&sptwb, 0, sizeof(sptwb));

    sptwb.spt.Length = sizeof(WFS_SCSI_PASS_THROUGH);
    sptwb.spt.CdbLength = 16;
    sptwb.spt.SenseInfoLength = 32;
    sptwb.spt.DataIn = WFS_SCSI_IOCTL_DATA_IN;
    sptwb.spt.DataTransferLength = 512;
    sptwb.spt.TimeOutValue = 3;
    sptwb.spt.DataBufferOffset = offsetof(WFS_SCSI_PASS_THROUGH_WITH_BUFFERS, ucDataBuf);
    sptwb.spt.SenseInfoOffset = offsetof(WFS_SCSI_PASS_THROUGH_WITH_BUFFERS, ucSenseBuf);

    // SAT-16: ATA PASS-THROUGH (16)
    sptwb.spt.Cdb[0] = 0x85; // ATA PASS-THROUGH 16
    sptwb.spt.Cdb[1] = (4 << 1); // PIO Data In
    sptwb.spt.Cdb[2] = 0x0E; // T_DIR=1, T_LENGTH=2, BYT_BLOK=1
    sptwb.spt.Cdb[6] = 1;    // 1 sector
    sptwb.spt.Cdb[14] = 0xEC; // ATA IDENTIFY DEVICE

    DWORD bytesReturned = 0;
    bool ok = DeviceIoControl(
        hDevice,
        WFS_IOCTL_SCSI_PASS_THROUGH,
        &sptwb, sizeof(sptwb),
        &sptwb, sizeof(sptwb),
        &bytesReturned,
        NULL
    ) != FALSE;

    if (!ok) {
        // Try SAT-12
        std::memset(&sptwb, 0, sizeof(sptwb));
        sptwb.spt.Length = sizeof(WFS_SCSI_PASS_THROUGH);
        sptwb.spt.CdbLength = 12;
        sptwb.spt.SenseInfoLength = 32;
        sptwb.spt.DataIn = WFS_SCSI_IOCTL_DATA_IN;
        sptwb.spt.DataTransferLength = 512;
        sptwb.spt.TimeOutValue = 3;
        sptwb.spt.DataBufferOffset = offsetof(WFS_SCSI_PASS_THROUGH_WITH_BUFFERS, ucDataBuf);
        sptwb.spt.SenseInfoOffset = offsetof(WFS_SCSI_PASS_THROUGH_WITH_BUFFERS, ucSenseBuf);

        sptwb.spt.Cdb[0] = 0xA1; // ATA PASS-THROUGH 12
        sptwb.spt.Cdb[1] = (4 << 1);
        sptwb.spt.Cdb[2] = 0x0E;
        sptwb.spt.Cdb[4] = 1;
        sptwb.spt.Cdb[9] = 0xEC; // ATA IDENTIFY DEVICE

        ok = DeviceIoControl(
            hDevice,
            WFS_IOCTL_SCSI_PASS_THROUGH,
            &sptwb, sizeof(sptwb),
            &sptwb, sizeof(sptwb),
            &bytesReturned,
            NULL
        ) != FALSE;
    }

    if (!ok) return false;

    const uint8_t* data = sptwb.ucDataBuf;

    // Decode Serial (words 10..19)
    std::string serial = DecodeAtaString(data + 20, 20);
    if (!serial.empty()) report.serialNumber = serial;

    // Decode Firmware (words 23..26)
    std::string fw = DecodeAtaString(data + 46, 8);
    if (!fw.empty()) report.firmwareRevision = fw;

    // Decode Model (words 27..46)
    std::string model = DecodeAtaString(data + 54, 40);
    if (!model.empty()) report.model = model;

    // Word 217: Nominal Media Rotation Rate
    uint16_t rotationRate = static_cast<uint16_t>(data[217 * 2] | (data[217 * 2 + 1] << 8));
    if (rotationRate == 0x0001) {
        report.mediaType = DriveMediaType::SSD;
        report.rotationRate = 0;
    } else if (rotationRate >= 3600 && rotationRate <= 15000) {
        report.mediaType = DriveMediaType::HDD;
        report.rotationRate = rotationRate;
    }

    return true;
}

bool WfsDriveHealth::QuerySatSmart(HANDLE hDevice, DriveHealthReport& report) {
    WFS_SCSI_PASS_THROUGH_WITH_BUFFERS sptwbData;
    std::memset(&sptwbData, 0, sizeof(sptwbData));

    sptwbData.spt.Length = sizeof(WFS_SCSI_PASS_THROUGH);
    sptwbData.spt.CdbLength = 16;
    sptwbData.spt.SenseInfoLength = 32;
    sptwbData.spt.DataIn = WFS_SCSI_IOCTL_DATA_IN;
    sptwbData.spt.DataTransferLength = 512;
    sptwbData.spt.TimeOutValue = 3;
    sptwbData.spt.DataBufferOffset = offsetof(WFS_SCSI_PASS_THROUGH_WITH_BUFFERS, ucDataBuf);
    sptwbData.spt.SenseInfoOffset = offsetof(WFS_SCSI_PASS_THROUGH_WITH_BUFFERS, ucSenseBuf);

    // SAT-16: SMART READ DATA
    sptwbData.spt.Cdb[0] = 0x85;
    sptwbData.spt.Cdb[1] = (4 << 1);
    sptwbData.spt.Cdb[2] = 0x0E;
    sptwbData.spt.Cdb[4] = 0xD0; // Feature: SMART READ DATA
    sptwbData.spt.Cdb[6] = 1;
    sptwbData.spt.Cdb[10] = 0x4F; // LBA Mid
    sptwbData.spt.Cdb[12] = 0xC2; // LBA High
    sptwbData.spt.Cdb[14] = 0xB0; // ATA SMART command

    DWORD bytesReturned = 0;
    bool okData = DeviceIoControl(
        hDevice,
        WFS_IOCTL_SCSI_PASS_THROUGH,
        &sptwbData, sizeof(sptwbData),
        &sptwbData, sizeof(sptwbData),
        &bytesReturned,
        NULL
    ) != FALSE;

    if (!okData) {
        // Try SAT-12
        sptwbData.spt.CdbLength = 12;
        sptwbData.spt.Cdb[0] = 0xA1;
        sptwbData.spt.Cdb[1] = (4 << 1);
        sptwbData.spt.Cdb[2] = 0x0E;
        sptwbData.spt.Cdb[3] = 0xD0;
        sptwbData.spt.Cdb[4] = 1;
        sptwbData.spt.Cdb[6] = 0x4F;
        sptwbData.spt.Cdb[7] = 0xC2;
        sptwbData.spt.Cdb[9] = 0xB0;

        okData = DeviceIoControl(
            hDevice,
            WFS_IOCTL_SCSI_PASS_THROUGH,
            &sptwbData, sizeof(sptwbData),
            &sptwbData, sizeof(sptwbData),
            &bytesReturned,
            NULL
        ) != FALSE;
    }

    if (!okData) return false;

    // Read Thresholds
    WFS_SCSI_PASS_THROUGH_WITH_BUFFERS sptwbThresh;
    std::memset(&sptwbThresh, 0, sizeof(sptwbThresh));
    sptwbThresh.spt = sptwbData.spt;
    if (sptwbThresh.spt.CdbLength == 16) {
        sptwbThresh.spt.Cdb[4] = 0xD1; // SMART READ THRESHOLDS
    } else {
        sptwbThresh.spt.Cdb[3] = 0xD1;
    }

    bool okThresh = DeviceIoControl(
        hDevice,
        WFS_IOCTL_SCSI_PASS_THROUGH,
        &sptwbThresh, sizeof(sptwbThresh),
        &sptwbThresh, sizeof(sptwbThresh),
        &bytesReturned,
        NULL
    ) != FALSE;

    return ParseAtaSmartData(
        sptwbData.ucDataBuf,
        okThresh ? sptwbThresh.ucDataBuf : nullptr,
        report
    );
}

bool WfsDriveHealth::QueryStandardSmart(HANDLE hDevice, DriveHealthReport& report) {
    WFS_GETVERSIONINPARAMS versionParams;
    std::memset(&versionParams, 0, sizeof(versionParams));
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(
        hDevice,
        WFS_SMART_GET_VERSION,
        NULL, 0,
        &versionParams, sizeof(versionParams),
        &bytesReturned,
        NULL
    )) {
        return false;
    }

    // Read SMART Data
    WFS_SENDCMDINPARAMS cmdIn;
    std::memset(&cmdIn, 0, sizeof(cmdIn));
    cmdIn.cBufferSize = 512;
    cmdIn.irDriveRegs.bFeaturesReg = 0xD0; // SMART READ DATA
    cmdIn.irDriveRegs.bSectorCountReg = 1;
    cmdIn.irDriveRegs.bSectorNumberReg = 1;
    cmdIn.irDriveRegs.bCylLowReg = 0x4F;
    cmdIn.irDriveRegs.bCylHighReg = 0xC2;
    cmdIn.irDriveRegs.bCommandReg = 0xB0;

    std::vector<uint8_t> outBuffer(sizeof(WFS_SENDCMDOUTPARAMS) + 512, 0);

    if (!DeviceIoControl(
        hDevice,
        WFS_SMART_RCV_DRIVE_DATA,
        &cmdIn, sizeof(cmdIn),
        outBuffer.data(), static_cast<DWORD>(outBuffer.size()),
        &bytesReturned,
        NULL
    )) {
        return false;
    }

    WFS_SENDCMDOUTPARAMS* outParams = reinterpret_cast<WFS_SENDCMDOUTPARAMS*>(outBuffer.data());
    uint8_t smartData[512];
    std::memcpy(smartData, outParams->bBuffer, 512);

    // Read Thresholds
    cmdIn.irDriveRegs.bFeaturesReg = 0xD1; // SMART READ THRESHOLDS
    std::vector<uint8_t> threshBuffer(sizeof(WFS_SENDCMDOUTPARAMS) + 512, 0);
    uint8_t thresholds[512];
    bool okThresh = false;

    if (DeviceIoControl(
        hDevice,
        WFS_SMART_RCV_DRIVE_DATA,
        &cmdIn, sizeof(cmdIn),
        threshBuffer.data(), static_cast<DWORD>(threshBuffer.size()),
        &bytesReturned,
        NULL
    )) {
        WFS_SENDCMDOUTPARAMS* threshParams = reinterpret_cast<WFS_SENDCMDOUTPARAMS*>(threshBuffer.data());
        std::memcpy(thresholds, threshParams->bBuffer, 512);
        okThresh = true;
    }

    return ParseAtaSmartData(smartData, okThresh ? thresholds : nullptr, report);
}

bool WfsDriveHealth::QueryNvmeSmart(HANDLE hDevice, DriveHealthReport& report) {
    size_t querySize = sizeof(WFS_STORAGE_PROPERTY_QUERY_PROTOCOL);
    size_t bufferSize = querySize + 512;
    std::vector<uint8_t> buffer(bufferSize, 0);

    WFS_STORAGE_PROPERTY_QUERY_PROTOCOL* query = reinterpret_cast<WFS_STORAGE_PROPERTY_QUERY_PROTOCOL*>(buffer.data());
    query->PropertyId = static_cast<STORAGE_PROPERTY_ID>(49); // StorageDeviceProtocolSpecificProperty
    query->QueryType = PropertyStandardQuery;
    query->ProtocolSpecificData.ProtocolType = WFS_STORAGE_PROTOCOL_NVME;
    query->ProtocolSpecificData.DataType = WFS_NVME_DATA_TYPE_LOG_PAGE;
    query->ProtocolSpecificData.ProtocolDataRequestValue = 0x02; // SMART / Health Information Log
    query->ProtocolSpecificData.ProtocolDataOffset = static_cast<ULONG>(sizeof(WFS_STORAGE_PROTOCOL_SPECIFIC_DATA));
    query->ProtocolSpecificData.ProtocolDataLength = 512;

    DWORD bytesReturned = 0;
    bool ok = DeviceIoControl(
        hDevice,
        IOCTL_STORAGE_QUERY_PROPERTY,
        buffer.data(), static_cast<DWORD>(bufferSize),
        buffer.data(), static_cast<DWORD>(bufferSize),
        &bytesReturned,
        NULL
    ) != FALSE;

    if (!ok) {
        // Try adapter level (PropertyId 48)
        query->PropertyId = static_cast<STORAGE_PROPERTY_ID>(48);
        ok = DeviceIoControl(
            hDevice,
            IOCTL_STORAGE_QUERY_PROPERTY,
            buffer.data(), static_cast<DWORD>(bufferSize),
            buffer.data(), static_cast<DWORD>(bufferSize),
            &bytesReturned,
            NULL
        ) != FALSE;
    }

    if (!ok) return false;

    const uint8_t* log = buffer.data() + querySize;

    report.smartSupported = true;
    report.smartEnabled = true;
    report.mediaType = DriveMediaType::SSD;

    // NVMe Composite Temperature: Bytes 1-2 (Kelvin)
    uint16_t kelvin = static_cast<uint16_t>(log[1] | (log[2] << 8));
    if (kelvin >= 273) {
        report.temperatureC = kelvin - 273;
    }

    // Available Spare % (Byte 3) and Percentage Used (Byte 5)
    uint8_t availableSpare = log[3];
    uint8_t percentUsed = log[5];
    report.ssdRemainingLife = (percentUsed <= 100) ? (100 - percentUsed) : 0;

    // Power Cycles (Bytes 112..127)
    uint64_t powerCycles = 0;
    std::memcpy(&powerCycles, log + 112, 8);
    report.powerCycleCount = static_cast<int64_t>(powerCycles);

    // Power On Hours (Bytes 128..143)
    uint64_t powerHours = 0;
    std::memcpy(&powerHours, log + 128, 8);
    report.powerOnHours = static_cast<int64_t>(powerHours);

    // Media and Data Integrity Errors (Bytes 160..175)
    uint64_t mediaErrors = 0;
    std::memcpy(&mediaErrors, log + 160, 8);
    report.uncorrectableSectors = mediaErrors;

    // Populate simulated NVMe SMART attributes table for crystal-disk view
    SmartAttribute attrSpare;
    attrSpare.id = 0x01;
    attrSpare.name = "Available Spare Capacity";
    attrSpare.currentValue = availableSpare;
    attrSpare.worstValue = availableSpare;
    attrSpare.threshold = log[4]; // Spare Threshold
    attrSpare.rawValue = availableSpare;
    attrSpare.rawFormatted = std::to_string(availableSpare) + "%";
    attrSpare.status = (availableSpare <= log[4]) ? AttributeStatus::Failing : AttributeStatus::Ok;
    attrSpare.isCritical = true;
    report.attributes.push_back(attrSpare);

    SmartAttribute attrLife;
    attrLife.id = 0x05;
    attrLife.name = "SSD Life Remaining (100 - % Used)";
    attrLife.currentValue = static_cast<uint8_t>(report.ssdRemainingLife);
    attrLife.worstValue = static_cast<uint8_t>(report.ssdRemainingLife);
    attrLife.threshold = 0;
    attrLife.rawValue = percentUsed;
    attrLife.rawFormatted = std::to_string(report.ssdRemainingLife) + "%";
    attrLife.status = (report.ssdRemainingLife <= 10) ? AttributeStatus::Warning : AttributeStatus::Ok;
    attrLife.isCritical = true;
    report.attributes.push_back(attrLife);

    SmartAttribute attrMedia;
    attrMedia.id = 0x0E;
    attrMedia.name = "Media and Data Integrity Errors";
    attrMedia.currentValue = (mediaErrors == 0) ? 100 : 1;
    attrMedia.worstValue = attrMedia.currentValue;
    attrMedia.threshold = 0;
    attrMedia.rawValue = mediaErrors;
    attrMedia.rawFormatted = std::to_string(mediaErrors);
    attrMedia.status = (mediaErrors > 0) ? AttributeStatus::Failing : AttributeStatus::Ok;
    attrMedia.isCritical = true;
    report.attributes.push_back(attrMedia);

    return true;
}

bool WfsDriveHealth::RunSurfaceScanWin32(
    HANDLE hDevice,
    uint64_t totalSectors,
    uint32_t sectorSize,
    DriveHealthReport& report,
    bool deepScan,
    uint64_t maxSectors
) {
    if (hDevice == INVALID_HANDLE_VALUE || totalSectors == 0 || sectorSize == 0) {
        return false;
    }

    report.surfaceScanCompleted = true;
    report.surfaceSectorsScanned = 0;
    report.surfaceBadSectors = 0;
    report.surfaceSlowSectors = 0;
    report.surfaceVerySlowSectors = 0;

    std::vector<uint64_t> targets;

    if (!deepScan) {
        // Fast Sample Scan: test beginning, metadata areas, fractions, and end
        targets.push_back(0); // Superblock / MBR
        targets.push_back(8);
        targets.push_back(16);
        targets.push_back(32);
        targets.push_back(64);
        for (int p = 5; p <= 95; p += 10) {
            targets.push_back((totalSectors * p) / 100);
        }
        if (totalSectors > 16) {
            targets.push_back(totalSectors - 8);
        }
    } else {
        // Deep Sequential / Stride Scan
        uint64_t limit = (maxSectors > 0) ? std::min(totalSectors, maxSectors) : totalSectors;
        uint64_t step = 128; // Test every 64KB
        for (uint64_t s = 0; s < limit; s += step) {
            targets.push_back(s);
        }
    }

    std::vector<uint8_t> blockBuf(sectorSize * 8, 0);
    double totalLatencyMs = 0.0;
    double maxLatencyMs = 0.0;
    size_t samplesCounted = 0;

    for (uint64_t sec : targets) {
        if (sec >= totalSectors) continue;

        LARGE_INTEGER offset;
        offset.QuadPart = static_cast<LONGLONG>(sec) * sectorSize;

        auto tStart = std::chrono::high_resolution_clock::now();

        if (!SetFilePointerEx(hDevice, offset, NULL, FILE_BEGIN)) {
            report.surfaceBadSectors++;
            continue;
        }

        DWORD bytesToRead = static_cast<DWORD>(std::min(static_cast<uint64_t>(blockBuf.size()), (totalSectors - sec) * sectorSize));
        DWORD bytesRead = 0;
        BOOL readOk = ReadFile(hDevice, blockBuf.data(), bytesToRead, &bytesRead, NULL);

        auto tEnd = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(tEnd - tStart).count();

        report.surfaceSectorsScanned += (bytesRead / sectorSize);

        if (!readOk || bytesRead != bytesToRead) {
            report.surfaceBadSectors++;
        } else {
            totalLatencyMs += ms;
            samplesCounted++;
            if (ms > maxLatencyMs) maxLatencyMs = ms;

            if (ms > 500.0) {
                report.surfaceVerySlowSectors++;
            } else if (ms > 150.0) {
                report.surfaceSlowSectors++;
            }
        }
    }

    if (samplesCounted > 0) {
        report.avgReadLatencyMs = totalLatencyMs / static_cast<double>(samplesCounted);
    }
    report.maxReadLatencyMs = maxLatencyMs;

    return true;
}

#endif // _WIN32

bool WfsDriveHealth::RunGenericSurfaceScan(
    IWfsDevice* device,
    DriveHealthReport& report,
    bool deepScan,
    uint64_t maxSectors
) {
    if (!device || !device->IsOpen()) return false;

    uint64_t totalSectors = device->GetTotalSectors();
    uint32_t sectorSize = device->GetSectorSize();

    report.surfaceScanCompleted = true;
    report.surfaceSectorsScanned = 0;
    report.surfaceBadSectors = 0;
    report.surfaceSlowSectors = 0;
    report.surfaceVerySlowSectors = 0;

    std::vector<uint64_t> targets;
    if (!deepScan) {
        targets.push_back(0);
        targets.push_back(8);
        targets.push_back(16);
        for (int p = 10; p <= 90; p += 20) {
            targets.push_back((totalSectors * p) / 100);
        }
    } else {
        uint64_t limit = (maxSectors > 0) ? std::min(totalSectors, maxSectors) : totalSectors;
        uint64_t step = 64;
        for (uint64_t s = 0; s < limit; s += step) {
            targets.push_back(s);
        }
    }

    std::vector<uint8_t> buf(sectorSize * 8, 0);
    double totalLatencyMs = 0.0;
    double maxLatencyMs = 0.0;
    size_t samplesCounted = 0;

    for (uint64_t sec : targets) {
        if (sec >= totalSectors) continue;

        auto tStart = std::chrono::high_resolution_clock::now();
        bool ok = device->ReadSectors(sec, 8, buf.data());
        auto tEnd = std::chrono::high_resolution_clock::now();

        double ms = std::chrono::duration<double, std::milli>(tEnd - tStart).count();
        report.surfaceSectorsScanned += 8;

        if (!ok) {
            report.surfaceBadSectors += 8;
        } else {
            totalLatencyMs += ms;
            samplesCounted++;
            if (ms > maxLatencyMs) maxLatencyMs = ms;
            if (ms > 500.0) report.surfaceVerySlowSectors++;
            else if (ms > 150.0) report.surfaceSlowSectors++;
        }
    }

    if (samplesCounted > 0) {
        report.avgReadLatencyMs = totalLatencyMs / static_cast<double>(samplesCounted);
    }
    report.maxReadLatencyMs = maxLatencyMs;
    return true;
}

DriveHealthReport WfsDriveHealth::CheckDrive(int driveIndex, bool runSurfaceScan, uint64_t maxScanSectors) {
    DriveHealthReport report;
    report.driveIndex = driveIndex;

#if defined(_WIN32)
    std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(driveIndex);

    // Attempt 1: Administrative RW access (for full SAT pass-through)
    HANDLE hDevice = CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    // Attempt 2: Read-Only access
    if (hDevice == INVALID_HANDLE_VALUE) {
        hDevice = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
    }

    // Attempt 3: Query-Only access (works without elevation for standard queries)
    if (hDevice == INVALID_HANDLE_VALUE) {
        hDevice = CreateFileW(
            path.c_str(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
    }

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        report.overallHealth = DriveHealthStatus::Unknown;
        report.criticalWarnings.push_back(
            "Cannot open drive \\\\.\\PhysicalDrive" + std::to_string(driveIndex) + 
            " (Win32 Error " + std::to_string(err) + "). Run as Administrator."
        );
        return report;
    }

    // 1. Query Disk Geometry & Total Capacity
    DISK_GEOMETRY_EX geo;
    std::memset(&geo, 0, sizeof(geo));
    DWORD bytesReturned = 0;
    if (DeviceIoControl(
        hDevice,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        NULL, 0,
        &geo, sizeof(geo),
        &bytesReturned,
        NULL
    )) {
        report.totalCapacityBytes = static_cast<uint64_t>(geo.DiskSize.QuadPart);
        report.sectorSize = geo.Geometry.BytesPerSector;
    }

    // 2. Query Storage Device Properties (Model, Vendor, Serial, BusType)
    QueryDeviceDescriptor(hDevice, report);

    // 3. Query Seek Penalty (HDD vs SSD)
    QuerySeekPenalty(hDevice, report);

    // 4. Query S.M.A.R.T. through hierarchy:
    // First: SAT (SCSI-to-ATA Translation) - Primary for external USB drives
    bool smartFound = false;
    QuerySatIdentify(hDevice, report);
    smartFound = QuerySatSmart(hDevice, report);

    // Second: Standard ATA SMART
    if (!smartFound) {
        smartFound = QueryStandardSmart(hDevice, report);
    }

    // Third: NVMe protocol query
    if (!smartFound && report.busType == "NVMe") {
        smartFound = QueryNvmeSmart(hDevice, report);
    }

    // 5. Run Surface Diagnostics
    RunSurfaceScanWin32(
        hDevice,
        report.totalCapacityBytes / (report.sectorSize ? report.sectorSize : 512),
        report.sectorSize ? report.sectorSize : 512,
        report,
        runSurfaceScan,
        maxScanSectors
    );

    CloseHandle(hDevice);

#else
    report.overallHealth = DriveHealthStatus::Unknown;
    report.cautionWarnings.push_back("Direct S.M.A.R.T. inspection is only supported on Windows host platforms.");
#endif

    EvaluateHealth(report);
    return report;
}

DriveHealthReport WfsDriveHealth::CheckDevice(IWfsDevice* device, bool runSurfaceScan, uint64_t maxScanSectors) {
    if (!device) {
        DriveHealthReport r;
        r.overallHealth = DriveHealthStatus::Unknown;
        return r;
    }

    auto* physDev = dynamic_cast<WfsPhysicalDiskDevice*>(device);
    if (physDev) {
        return CheckDrive(physDev->GetDriveIndex(), runSurfaceScan, maxScanSectors);
    }

    // Virtual Image or In-Memory Device
    DriveHealthReport report;
    report.totalCapacityBytes = device->GetTotalSectors() * device->GetSectorSize();
    report.sectorSize = device->GetSectorSize();
    report.busType = "Virtual Image";
    report.mediaType = DriveMediaType::Virtual;
    report.model = "WFS Virtual Storage Device";
    report.overallHealth = DriveHealthStatus::Good;
    report.healthScore = 100;

    RunGenericSurfaceScan(device, report, runSurfaceScan, maxScanSectors);
    EvaluateHealth(report);
    return report;
}

} // namespace WfsManager
