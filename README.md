# WFS Manager: Production-Safe Wii U USB Storage Management Engine

## Overview & System Objectives
`WFS Manager` is a low-level filesystem management and write engine designed specifically for the proprietary **Wii File System (WFS)** used on Nintendo Wii U external USB storage devices and internal MLC dumps.

The Wii U operating system (Cafe OS / IOSU) enforces extreme consistency validation across storage structures. Any desynchronization between directory inode trees, block allocation maps, superblock transaction sequence counters, or cryptographic sector Initialization Vectors (IVs) causes the console to display a disk read error (`160-0103`) and prompt a mandatory destructive reformat.

This engine implements **safe, atomic write operations** for:
1. **Safe Application Deletion & Uninstallation:** Target resolution under `/usr/title/`, recursive block freeing, ticket/TMD synchronization, and orphan cluster prevention.
2. **Safe Application Installation:** Pre-flight space reservation, contiguous/fragmented cluster allocation, directory hierarchy generation, package manifest injection, and ticket registration.
3. **Zero Filesystem Corruption Engine:** Win32 exclusive volume locking/dismounting, pre-transaction offline metadata snapshotting, staged write-ahead logging (WAL), LBA-based AES-128-CBC encryption, and automated instantaneous rollback.

---

## Architecture Blueprint

### 1. Data Flow & Transaction Lifecycle

```
[Host PC Application]
        │
        ├── 1. Win32 Exclusive Drive Locking (FSCTL_LOCK_VOLUME / FSCTL_DISMOUNT_VOLUME)
        │
        ├── 2. Pre-Flight Safety Audit (Superblock CRC32, Generation Parity, Space Check)
        │
        ├── 3. Offline Metadata Snapshot (<DriveId>_WFS_BACKUP_<Timestamp>.wfsbak)
        │
        ├── 4. Transaction Begin (Shadow Allocator Snapshot + Staging Buffer)
        │
        ├── 5. Phase 1: Payload Cluster Writes (AES-128-CBC with LBA IV -> Read-back Verify)
        │
        ├── 6. Phase 2: Inode & Directory Block Updates (Flush to Disk)
        │
        ├── 7. Phase 3: Block Allocation Bitmap Commit (Dirty Blocks Written & Flushed)
        │
        ├── 8. Phase 4: Atomic Superblock Generation Flip (Increment Generation, CRC32, SHA-1)
        │       ├── Primary Superblock (LBA 0) -> Flush
        │       └── Backup Superblock (backup_lba) -> Flush
        │
        └── 9. Final Integrity Audit (Orphan Prevention / Cross-Link Check)
```

---

## Directory Hierarchy & File Layout

```
c:\Users\Virg\WFSManager\
├── include\
│   ├── WfsCommon.h           // Endian utilities, TitleId structures, WfsResult enum
│   ├── WfsCrypto.h           // AES-128-ECB/CBC, LBA IV derivation, OTP/SEEPROM key derivation
│   ├── WfsStructures.h       // Superblock, AreaHeader, Inode, DirectoryEntry, TMD, Ticket structs
│   ├── WfsDiskDevice.h       // Win32 raw drive wrapper (\\\\.\\PhysicalDriveX), FileImage, MemoryDevice
│   ├── WfsBlockAllocator.h   // Cluster allocation bitmap management, free-space search, orphan audit
│   ├── WfsTransaction.h      // Atomic commit engine, WAL/journaling, pre-write snapshot & rollback
│   ├── WfsFileSystem.h       // Main WFS driver: mount, read, write, traverse, delete, insert
│   ├── WfsTitleManager.h     // Title uninstallation, recursive block freeing, NUS/unpacked installer
│   ├── WfsDriveHealth.h      // CrystalDiskInfo-grade S.M.A.R.T. monitor, SAT/NVMe pass-through & surface scan
│   └── WfsSafetyGuard.h      // Windows disk lock verification, hardware health check, integrity audit
├── src\
│   ├── WfsCrypto.cpp
│   ├── WfsDiskDevice.cpp
│   ├── WfsBlockAllocator.cpp
│   ├── WfsTransaction.cpp
│   ├── WfsFileSystem.cpp
│   ├── WfsTitleManager.cpp
│   ├── WfsSafetyGuard.cpp
│   ├── WfsDriveHealth.cpp
│   └── main.cpp              // Production CLI / management engine
├── tests\
│   ├── test_wfs.cpp          // C++ automated unit & integrity test suite
│   ├── verify_wfs_suite.py   // Python verification test harness
│   └── sim_wfs_engine.py     // Python end-to-end WFS pipeline simulator
└── CMakeLists.txt            // CMake build configuration
```

---

## CLI Usage

### Build
```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

### Drive Health & S.M.A.R.T. Inspection (CrystalDiskInfo-Style)
```bash
# Fast S.M.A.R.T. health check, temperature, and wear status (no keys required)
wfsmanager --drive 1 health

# Deep surface sector scan with high-resolution read latency & bad block detection
wfsmanager --drive 1 health --surface-scan
```

### List Installed Titles
```bash
wfsmanager --drive 1 --otp otp.bin --seeprom seeprom.bin list
```

### Safe Uninstallation
```bash
# Dry run simulation (no physical sectors modified)
wfsmanager --drive 1 --otp otp.bin --seeprom seeprom.bin --dry-run uninstall 00050000-10144F00

# Production safe uninstallation with automatic pre-transaction backup
wfsmanager --drive 1 --otp otp.bin --seeprom seeprom.bin --backup-dir ./backups uninstall 00050000-10144F00
```

### Safe Installation
```bash
# Install from unpacked folder (containing code/, content/, meta/)
wfsmanager --drive 1 --otp otp.bin --seeprom seeprom.bin --backup-dir ./backups install "C:/Titles/MyGame"

# Install from NUS package (containing .app, .h3, title.tmd, title.tik)
wfsmanager --drive 1 --otp otp.bin --seeprom seeprom.bin install "C:/NUS/GamePackage"
```

### Offline Metadata Backup & Recovery
```bash
# Manual offline backup
wfsmanager --drive 1 --otp otp.bin --seeprom seeprom.bin backup "./backups/drive1_backup.wfsbak"

# Emergency recovery from backup
wfsmanager --drive 1 --otp otp.bin --seeprom seeprom.bin restore "./backups/drive1_backup.wfsbak"
```

