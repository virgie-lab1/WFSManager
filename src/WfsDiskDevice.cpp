#include "WfsDiskDevice.h"
#include <iostream>
#include <cstring>

#if defined(_WIN32)
#include <winioctl.h>
#endif

namespace WfsManager {

WfsPhysicalDiskDevice::WfsPhysicalDiskDevice(int driveIndex, bool readOnly, bool dryRun)
    : driveIndex_(driveIndex),
      readOnly_(readOnly),
      dryRun_(dryRun),
      totalSectors_(0),
      sectorSize_(512)
#if defined(_WIN32)
      , hDevice_(INVALID_HANDLE_VALUE)
#else
      , fd_(-1)
#endif
{
}

WfsPhysicalDiskDevice::~WfsPhysicalDiskDevice() {
    Close();
}

bool WfsPhysicalDiskDevice::Open() {
#if defined(_WIN32)
    if (hDevice_ != INVALID_HANDLE_VALUE) {
        return true;
    }

    // Step 1: Pre-lock and dismount all existing logical volumes
    if (!readOnly_ && !dryRun_) {
        LockAndDismountVolumes();
    }

    // Step 2: Open physical drive handle
    std::wstring drivePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(driveIndex_);
    DWORD access = GENERIC_READ;
    if (!readOnly_ && !dryRun_) {
        access |= GENERIC_WRITE;
    }

    DWORD shareMode = FILE_SHARE_READ;
    if (readOnly_) {
        shareMode |= FILE_SHARE_WRITE;
    }

    DWORD flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH;

    hDevice_ = CreateFileW(
        drivePath.c_str(),
        access,
        shareMode,
        NULL,
        OPEN_EXISTING,
        flags,
        NULL
    );

    if (hDevice_ == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::cerr << "[WfsPhysicalDiskDevice] Failed to open \\\\.\\PhysicalDrive" << driveIndex_
                  << " (Error " << err << "). Administrator privileges required." << std::endl;
        UnlockVolumes();
        return false;
    }

    if (!QueryDriveGeometry()) {
        Close();
        return false;
    }

    return true;
#else
    return false;
#endif
}

void WfsPhysicalDiskDevice::Close() {
#if defined(_WIN32)
    if (hDevice_ != INVALID_HANDLE_VALUE) {
        Flush();
        CloseHandle(hDevice_);
        hDevice_ = INVALID_HANDLE_VALUE;
    }
    UnlockVolumes();
#endif
    shadowWrites_.clear();
}

bool WfsPhysicalDiskDevice::IsOpen() const {
#if defined(_WIN32)
    return hDevice_ != INVALID_HANDLE_VALUE;
#else
    return false;
#endif
}

bool WfsPhysicalDiskDevice::QueryDriveGeometry() {
#if defined(_WIN32)
    DISK_GEOMETRY_EX geomEx;
    DWORD bytesReturned = 0;
    if (DeviceIoControl(hDevice_, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &geomEx, sizeof(geomEx), &bytesReturned, NULL)) {
        sectorSize_ = geomEx.Geometry.BytesPerSector;
        if (sectorSize_ == 0) sectorSize_ = 512;
        totalSectors_ = geomEx.DiskSize.QuadPart / sectorSize_;
        return true;
    }

    GET_LENGTH_INFORMATION lengthInfo;
    if (DeviceIoControl(hDevice_, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &lengthInfo, sizeof(lengthInfo), &bytesReturned, NULL)) {
        sectorSize_ = 512;
        totalSectors_ = lengthInfo.Length.QuadPart / sectorSize_;
        return true;
    }

    // Fallback standard geometry
    DISK_GEOMETRY geom;
    if (DeviceIoControl(hDevice_, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geom, sizeof(geom), &bytesReturned, NULL)) {
        sectorSize_ = geom.BytesPerSector;
        if (sectorSize_ == 0) sectorSize_ = 512;
        totalSectors_ = (geom.Cylinders.QuadPart * geom.TracksPerCylinder * geom.SectorsPerTrack);
        return true;
    }

    std::cerr << "[WfsPhysicalDiskDevice] Failed to query drive geometry (Error " << GetLastError() << ")" << std::endl;
    return false;
#else
    return false;
#endif
}

bool WfsPhysicalDiskDevice::LockAndDismountVolumes() {
#if defined(_WIN32)
    wchar_t driveStrings[512];
    DWORD len = GetLogicalDriveStringsW(511, driveStrings);
    if (len == 0) return false;

    wchar_t* current = driveStrings;
    while (*current) {
        std::wstring root(current); // e.g. L"E:\\"
        if (root.length() >= 2 && root[1] == L':') {
            std::wstring volPath = L"\\\\.\\" + root.substr(0, 2);
            HANDLE hVol = CreateFileW(
                volPath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );

            if (hVol != INVALID_HANDLE_VALUE) {
                STORAGE_DEVICE_NUMBER devNum;
                DWORD bytesReturned = 0;
                if (DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &devNum, sizeof(devNum), &bytesReturned, NULL)) {
                    if (static_cast<int>(devNum.DeviceNumber) == driveIndex_) {
                        DWORD dummy;
                        if (DeviceIoControl(hVol, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dummy, NULL)) {
                            DeviceIoControl(hVol, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dummy, NULL);
                            lockedVolumeHandles_.push_back(hVol);
                            std::wcout << L"[WfsPhysicalDiskDevice] Locked & dismounted volume: " << volPath << std::endl;
                            current += wcslen(current) + 1;
                            continue;
                        }
                    }
                }
                CloseHandle(hVol);
            }
        }
        current += wcslen(current) + 1;
    }
    return true;
#else
    return false;
#endif
}

void WfsPhysicalDiskDevice::UnlockVolumes() {
#if defined(_WIN32)
    for (HANDLE h : lockedVolumeHandles_) {
        DWORD dummy;
        DeviceIoControl(h, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &dummy, NULL);
        CloseHandle(h);
    }
    lockedVolumeHandles_.clear();
#endif
}

bool WfsPhysicalDiskDevice::ReadSectors(uint64_t sectorOffset, size_t sectorCount, uint8_t* outBuffer) {
    if (!IsOpen() || !outBuffer) return false;

    for (size_t i = 0; i < sectorCount; ++i) {
        uint64_t currentSector = sectorOffset + i;
        uint8_t* targetPtr = outBuffer + i * sectorSize_;

        if (dryRun_) {
            auto it = shadowWrites_.find(currentSector);
            if (it != shadowWrites_.end()) {
                std::memcpy(targetPtr, it->second.data(), sectorSize_);
                continue;
            }
        }

#if defined(_WIN32)
        LARGE_INTEGER offset;
        offset.QuadPart = static_cast<LONGLONG>(currentSector) * sectorSize_;
        if (!SetFilePointerEx(hDevice_, offset, NULL, FILE_BEGIN)) {
            return false;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(hDevice_, targetPtr, static_cast<DWORD>(sectorSize_), &bytesRead, NULL) || bytesRead != sectorSize_) {
            return false;
        }
#endif
    }
    return true;
}

bool WfsPhysicalDiskDevice::WriteSectors(uint64_t sectorOffset, size_t sectorCount, const uint8_t* inBuffer) {
    if (!IsOpen() || !inBuffer) return false;
    if (readOnly_) return false;

    if (dryRun_) {
        for (size_t i = 0; i < sectorCount; ++i) {
            uint64_t currentSector = sectorOffset + i;
            std::vector<uint8_t> secData(inBuffer + i * sectorSize_, inBuffer + (i + 1) * sectorSize_);
            shadowWrites_[currentSector] = std::move(secData);
        }
        return true;
    }

#if defined(_WIN32)
    LARGE_INTEGER offset;
    offset.QuadPart = static_cast<LONGLONG>(sectorOffset) * sectorSize_;
    if (!SetFilePointerEx(hDevice_, offset, NULL, FILE_BEGIN)) {
        return false;
    }

    DWORD totalBytes = static_cast<DWORD>(sectorCount * sectorSize_);
    DWORD bytesWritten = 0;
    if (!WriteFile(hDevice_, inBuffer, totalBytes, &bytesWritten, NULL) || bytesWritten != totalBytes) {
        std::cerr << "[WfsPhysicalDiskDevice] Write failed at LBA " << sectorOffset 
                  << " (Error " << GetLastError() << ")" << std::endl;
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool WfsPhysicalDiskDevice::Flush() {
#if defined(_WIN32)
    if (hDevice_ != INVALID_HANDLE_VALUE && !readOnly_ && !dryRun_) {
        return FlushFileBuffers(hDevice_) != FALSE;
    }
#endif
    return true;
}

// --- WfsFileImageDevice Implementation ---

WfsFileImageDevice::WfsFileImageDevice(const std::string& filePath, bool readOnly, bool dryRun)
    : filePath_(filePath),
      readOnly_(readOnly),
      dryRun_(dryRun),
      totalSectors_(0),
      sectorSize_(512)
#if defined(_WIN32)
      , hFile_(INVALID_HANDLE_VALUE)
#else
      , fd_(-1)
#endif
{
}

WfsFileImageDevice::~WfsFileImageDevice() {
    Close();
}

bool WfsFileImageDevice::Open() {
#if defined(_WIN32)
    if (hFile_ != INVALID_HANDLE_VALUE) return true;

    DWORD access = GENERIC_READ;
    if (!readOnly_ && !dryRun_) access |= GENERIC_WRITE;

    hFile_ = CreateFileA(
        filePath_.c_str(),
        access,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile_ == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER size;
    if (!GetFileSizeEx(hFile_, &size)) {
        Close();
        return false;
    }

    totalSectors_ = size.QuadPart / sectorSize_;
    return true;
#else
    return false;
#endif
}

void WfsFileImageDevice::Close() {
#if defined(_WIN32)
    if (hFile_ != INVALID_HANDLE_VALUE) {
        Flush();
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
    }
#endif
    shadowWrites_.clear();
}

bool WfsFileImageDevice::IsOpen() const {
#if defined(_WIN32)
    return hFile_ != INVALID_HANDLE_VALUE;
#else
    return false;
#endif
}

bool WfsFileImageDevice::ReadSectors(uint64_t sectorOffset, size_t sectorCount, uint8_t* outBuffer) {
    if (!IsOpen() || !outBuffer) return false;

    for (size_t i = 0; i < sectorCount; ++i) {
        uint64_t curSec = sectorOffset + i;
        uint8_t* targetPtr = outBuffer + i * sectorSize_;

        if (dryRun_) {
            auto it = shadowWrites_.find(curSec);
            if (it != shadowWrites_.end()) {
                std::memcpy(targetPtr, it->second.data(), sectorSize_);
                continue;
            }
        }

#if defined(_WIN32)
        LARGE_INTEGER offset;
        offset.QuadPart = static_cast<LONGLONG>(curSec) * sectorSize_;
        if (!SetFilePointerEx(hFile_, offset, NULL, FILE_BEGIN)) return false;

        DWORD bytesRead = 0;
        if (!ReadFile(hFile_, targetPtr, static_cast<DWORD>(sectorSize_), &bytesRead, NULL) || bytesRead != sectorSize_) {
            return false;
        }
#endif
    }
    return true;
}

bool WfsFileImageDevice::WriteSectors(uint64_t sectorOffset, size_t sectorCount, const uint8_t* inBuffer) {
    if (!IsOpen() || !inBuffer) return false;
    if (readOnly_) return false;

    if (dryRun_) {
        for (size_t i = 0; i < sectorCount; ++i) {
            uint64_t curSec = sectorOffset + i;
            std::vector<uint8_t> secData(inBuffer + i * sectorSize_, inBuffer + (i + 1) * sectorSize_);
            shadowWrites_[curSec] = std::move(secData);
        }
        return true;
    }

#if defined(_WIN32)
    LARGE_INTEGER offset;
    offset.QuadPart = static_cast<LONGLONG>(sectorOffset) * sectorSize_;
    if (!SetFilePointerEx(hFile_, offset, NULL, FILE_BEGIN)) return false;

    DWORD totalBytes = static_cast<DWORD>(sectorCount * sectorSize_);
    DWORD bytesWritten = 0;
    if (!WriteFile(hFile_, inBuffer, totalBytes, &bytesWritten, NULL) || bytesWritten != totalBytes) {
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool WfsFileImageDevice::Flush() {
#if defined(_WIN32)
    if (hFile_ != INVALID_HANDLE_VALUE && !readOnly_ && !dryRun_) {
        return FlushFileBuffers(hFile_) != FALSE;
    }
#endif
    return true;
}

// --- WfsMemoryDevice Implementation ---

WfsMemoryDevice::WfsMemoryDevice(uint64_t totalSectors, uint32_t sectorSize)
    : isOpen_(false), totalSectors_(totalSectors), sectorSize_(sectorSize) {
    buffer_.resize(totalSectors * sectorSize, 0);
}

bool WfsMemoryDevice::ReadSectors(uint64_t sectorOffset, size_t sectorCount, uint8_t* outBuffer) {
    if (!isOpen_ || !outBuffer) return false;
    uint64_t startByte = sectorOffset * sectorSize_;
    uint64_t totalBytes = sectorCount * sectorSize_;
    if (startByte + totalBytes > buffer_.size()) return false;

    std::memcpy(outBuffer, buffer_.data() + startByte, totalBytes);
    return true;
}

bool WfsMemoryDevice::WriteSectors(uint64_t sectorOffset, size_t sectorCount, const uint8_t* inBuffer) {
    if (!isOpen_ || !inBuffer) return false;
    uint64_t startByte = sectorOffset * sectorSize_;
    uint64_t totalBytes = sectorCount * sectorSize_;
    if (startByte + totalBytes > buffer_.size()) return false;

    std::memcpy(buffer_.data() + startByte, inBuffer, totalBytes);
    return true;
}

} // namespace WfsManager

