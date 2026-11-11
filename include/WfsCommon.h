#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <iostream>

#if defined(_MSC_VER)
#include <stdlib.h>
#define WFS_BYTESWAP16(x) _byteswap_ushort(x)
#define WFS_BYTESWAP32(x) _byteswap_ulong(x)
#define WFS_BYTESWAP64(x) _byteswap_uint64(x)
#else
#define WFS_BYTESWAP16(x) __builtin_bswap16(x)
#define WFS_BYTESWAP32(x) __builtin_bswap32(x)
#define WFS_BYTESWAP64(x) __builtin_bswap64(x)
#endif

namespace WfsManager {

// System Endian Conversion for Cafe OS (Big Endian)
// Safe on both MSVC and GCC/Clang
inline uint16_t BigEndian16(uint16_t val) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return val;
#else
    return WFS_BYTESWAP16(val);
#endif
}

inline uint32_t BigEndian32(uint32_t val) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return val;
#else
    return WFS_BYTESWAP32(val);
#endif
}

inline uint64_t BigEndian64(uint64_t val) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return val;
#else
    return WFS_BYTESWAP64(val);
#endif
}

// Result / Status Codes
enum class WfsResult {
    Success = 0,
    InvalidParameter,
    DeviceOpenFailed,
    DeviceLockFailed,
    DeviceIOError,
    InvalidKeys,
    SuperblockCorrupt,
    SuperblockGenerationMismatch,
    AllocationBitmapCorrupt,
    InsufficientFreeSpace,
    TitleNotFound,
    DirectoryNotFound,
    FileNotFound,
    DirectoryNotEmpty,
    AlreadyExists,
    OrphanDetected,
    CrossLinkDetected,
    TicketMissing,
    SystemTitleProtected,
    TransactionAborted,
    DryRunSimulationOnly,
    IntegrityCheckFailed
};

inline const char* WfsResultToString(WfsResult res) {
    switch (res) {
        case WfsResult::Success: return "Success";
        case WfsResult::InvalidParameter: return "Invalid Parameter";
        case WfsResult::DeviceOpenFailed: return "Failed to open physical drive handle";
        case WfsResult::DeviceLockFailed: return "Failed to lock / dismount drive volumes";
        case WfsResult::DeviceIOError: return "Low-level Device I/O Error";
        case WfsResult::InvalidKeys: return "Invalid OTP/SEEPROM keys or key mismatch";
        case WfsResult::SuperblockCorrupt: return "Superblock magic or checksum is corrupt";
        case WfsResult::SuperblockGenerationMismatch: return "Superblock generation sequence desynchronization";
        case WfsResult::AllocationBitmapCorrupt: return "Block allocation bitmap integrity failure";
        case WfsResult::InsufficientFreeSpace: return "Insufficient free clusters for requested write";
        case WfsResult::TitleNotFound: return "Target Title ID not found in /usr/title/";
        case WfsResult::DirectoryNotFound: return "Directory node not found";
        case WfsResult::FileNotFound: return "File not found";
        case WfsResult::DirectoryNotEmpty: return "Directory is not empty";
        case WfsResult::AlreadyExists: return "Target file or directory already exists";
        case WfsResult::OrphanDetected: return "Orphaned cluster detected in allocation table";
        case WfsResult::CrossLinkDetected: return "Cross-linked block detected across multiple inodes";
        case WfsResult::TicketMissing: return "Valid ticket (title.tik) is missing";
        case WfsResult::SystemTitleProtected: return "Attempted unsafe modification of system/shared title";
        case WfsResult::TransactionAborted: return "Transaction aborted and rolled back";
        case WfsResult::DryRunSimulationOnly: return "Operation completed successfully in dry-run simulation mode";
        case WfsResult::IntegrityCheckFailed: return "Post-write integrity verification failed";
        default: return "Unknown WFS Error";
    }
}

class WfsException : public std::runtime_error {
public:
    WfsResult result;
    explicit WfsException(WfsResult res, const std::string& msg = "")
        : std::runtime_error(msg.empty() ? WfsResultToString(res) : (std::string(WfsResultToString(res)) + ": " + msg)),
          result(res) {}
};

// Extent Descriptor (contiguous cluster run)
struct WfsExtent {
    uint32_t startCluster;
    uint32_t clusterCount;

    bool operator==(const WfsExtent& other) const {
        return startCluster == other.startCluster && clusterCount == other.clusterCount;
    }
};

// Title Categories
enum class TitleCategory : uint32_t {
    Game        = 0x00050000,
    Demo        = 0x00050002,
    DLC         = 0x0005000C,
    Update      = 0x0005000E,
    SystemApp   = 0x00050010,
    SystemData  = 0x0005001B,
    SystemApplet= 0x00050030,
    Unknown     = 0xFFFFFFFF
};

struct TitleId {
    uint64_t fullId;

    TitleId() : fullId(0) {}
    explicit TitleId(uint64_t id) : fullId(id) {}
    TitleId(uint32_t high, uint32_t low) : fullId(((uint64_t)high << 32) | low) {}

    uint32_t High() const { return static_cast<uint32_t>(fullId >> 32); }
    uint32_t Low() const { return static_cast<uint32_t>(fullId & 0xFFFFFFFFULL); }

    TitleCategory GetCategory() const {
        uint32_t h = High();
        switch (h) {
            case 0x00050000: return TitleCategory::Game;
            case 0x00050002: return TitleCategory::Demo;
            case 0x0005000C: return TitleCategory::DLC;
            case 0x0005000E: return TitleCategory::Update;
            case 0x00050010: return TitleCategory::SystemApp;
            case 0x0005001B: return TitleCategory::SystemData;
            case 0x00050030: return TitleCategory::SystemApplet;
            default: return TitleCategory::Unknown;
        }
    }

    bool IsSystemOrShared() const {
        TitleCategory cat = GetCategory();
        return cat == TitleCategory::SystemApp || 
               cat == TitleCategory::SystemData || 
               cat == TitleCategory::SystemApplet;
    }

    std::string ToHexString() const {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(8) << High()
           << "-"
           << std::setw(8) << Low();
        return ss.str();
    }

    std::string ToContinuousHexString() const {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(8) << High()
           << std::setw(8) << Low();
        return ss.str();
    }

    std::string GetHierarchyPath() const {
        std::ostringstream ss;
        ss << "/usr/title/"
           << std::hex << std::setfill('0') << std::setw(8) << High()
           << "/"
           << std::setw(8) << Low();
        return ss.str();
    }

    static TitleId FromString(const std::string& str) {
        std::string clean;
        for (char c : str) {
            if (isxdigit(c)) clean += c;
        }
        if (clean.length() != 16) {
            throw WfsException(WfsResult::InvalidParameter, "Title ID string must be 16 hex digits: " + str);
        }
        uint64_t val = std::stoull(clean, nullptr, 16);
        return TitleId(val);
    }
};

} // namespace WfsManager

