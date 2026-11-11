#pragma once

#include "WfsCommon.h"
#include <memory>
#include <map>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace WfsManager {

class IWfsDevice {
public:
    virtual ~IWfsDevice() = default;

    virtual bool Open() = 0;
    virtual void Close() = 0;
    virtual bool IsOpen() const = 0;

    virtual uint64_t GetTotalSectors() const = 0;
    virtual uint32_t GetSectorSize() const = 0;

    virtual bool ReadSectors(uint64_t sectorOffset, size_t sectorCount, uint8_t* outBuffer) = 0;
    virtual bool WriteSectors(uint64_t sectorOffset, size_t sectorCount, const uint8_t* inBuffer) = 0;

    virtual bool Flush() = 0;
    virtual bool IsDryRun() const = 0;
};

// Physical Raw Win32 Drive Device (\\\\.\\PhysicalDriveX)
class WfsPhysicalDiskDevice : public IWfsDevice {
public:
    WfsPhysicalDiskDevice(int driveIndex, bool readOnly, bool dryRun = false);
    ~WfsPhysicalDiskDevice() override;

    bool Open() override;
    void Close() override;
    bool IsOpen() const override;

    uint64_t GetTotalSectors() const override { return totalSectors_; }
    uint32_t GetSectorSize() const override { return sectorSize_; }

    bool ReadSectors(uint64_t sectorOffset, size_t sectorCount, uint8_t* outBuffer) override;
    virtual bool WriteSectors(uint64_t sectorOffset, size_t sectorCount, const uint8_t* inBuffer) override;

    bool Flush() override;
    bool IsDryRun() const override { return dryRun_; }

    // Lock and dismount all Windows logical volumes mapped to this physical drive
    bool LockAndDismountVolumes();
    void UnlockVolumes();

    size_t GetShadowWriteCount() const { return shadowWrites_.size(); }

private:
    int driveIndex_;
    bool readOnly_;
    bool dryRun_;
    uint64_t totalSectors_;
    uint32_t sectorSize_;

#if defined(_WIN32)
    HANDLE hDevice_;
    std::vector<HANDLE> lockedVolumeHandles_;
#else
    int fd_;
#endif

    // Dry-run virtual write overlay (Sector LBA -> 512/4096-byte sector data)
    std::map<uint64_t, std::vector<uint8_t>> shadowWrites_;

    bool QueryDriveGeometry();
};

// Image File Device (for .img/.bin WFS files)
class WfsFileImageDevice : public IWfsDevice {
public:
    WfsFileImageDevice(const std::string& filePath, bool readOnly, bool dryRun = false);
    ~WfsFileImageDevice() override;

    bool Open() override;
    void Close() override;
    bool IsOpen() const override;

    uint64_t GetTotalSectors() const override { return totalSectors_; }
    uint32_t GetSectorSize() const override { return sectorSize_; }

    bool ReadSectors(uint64_t sectorOffset, size_t sectorCount, uint8_t* outBuffer) override;
    bool WriteSectors(uint64_t sectorOffset, size_t sectorCount, const uint8_t* inBuffer) override;

    bool Flush() override;
    bool IsDryRun() const override { return dryRun_; }

private:
    std::string filePath_;
    bool readOnly_;
    bool dryRun_;
    uint64_t totalSectors_;
    uint32_t sectorSize_;

#if defined(_WIN32)
    HANDLE hFile_;
#else
    int fd_;
#endif

    std::map<uint64_t, std::vector<uint8_t>> shadowWrites_;
};

// Memory-Backed Virtual Device (useful for unit tests and sandboxed simulations)
class WfsMemoryDevice : public IWfsDevice {
public:
    WfsMemoryDevice(uint64_t totalSectors, uint32_t sectorSize = 512);

    bool Open() override { isOpen_ = true; return true; }
    void Close() override { isOpen_ = false; }
    bool IsOpen() const override { return isOpen_; }

    uint64_t GetTotalSectors() const override { return totalSectors_; }
    uint32_t GetSectorSize() const override { return sectorSize_; }

    bool ReadSectors(uint64_t sectorOffset, size_t sectorCount, uint8_t* outBuffer) override;
    bool WriteSectors(uint64_t sectorOffset, size_t sectorCount, const uint8_t* inBuffer) override;

    bool Flush() override { return true; }
    bool IsDryRun() const override { return false; }

    uint8_t* GetRawBuffer() { return buffer_.data(); }
    const uint8_t* GetRawBuffer() const { return buffer_.data(); }

private:
    bool isOpen_;
    uint64_t totalSectors_;
    uint32_t sectorSize_;
    std::vector<uint8_t> buffer_;
};

} // namespace WfsManager

