#include "WfsTransaction.h"
#include <fstream>
#include <chrono>
#include <ctime>
#include <iostream>
#include <cstring>

namespace WfsManager {

#pragma pack(push, 1)
struct WfsBackupHeader {
    char     magic[8];          // "WFSBAK01"
    uint64_t timestamp;         // Epoch timestamp
    uint32_t cluster_size;
    uint32_t backup_sb_lba;
    uint32_t bitmap_byte_size;
    uint32_t crc32;
};
#pragma pack(pop)

WfsTransaction::WfsTransaction(
    IWfsDevice* device,
    WfsBlockAllocator* allocator,
    const uint8_t usbKey[WfsCrypto::KEY_SIZE],
    uint32_t clusterSize
) : device_(device),
    allocator_(allocator),
    clusterSize_(clusterSize),
    sectorsPerCluster_(clusterSize / (device ? device->GetSectorSize() : 512)),
    inTransaction_(false)
{
    if (sectorsPerCluster_ == 0) sectorsPerCluster_ = 8;
    std::memcpy(usbKey_, usbKey, WfsCrypto::KEY_SIZE);
}

bool WfsTransaction::CreateOfflineMetadataBackup(
    const std::string& backupFilePath,
    const WfsSuperblock& primarySb,
    uint32_t backupSbLba
) {
    (void)primarySb;
    if (!device_ || !device_->IsOpen() || !allocator_) return false;

    std::ofstream out(backupFilePath, std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "[WfsTransaction] Failed to open backup file: " << backupFilePath << std::endl;
        return false;
    }

    const auto& bitmapData = allocator_->GetBitmapData();

    WfsBackupHeader header;
    std::memcpy(header.magic, "WFSBAK01", 8);
    header.timestamp = static_cast<uint64_t>(std::time(nullptr));
    header.cluster_size = clusterSize_;
    header.backup_sb_lba = backupSbLba;
    header.bitmap_byte_size = static_cast<uint32_t>(bitmapData.size());
    header.crc32 = 0; // calculated later

    // Read raw Primary Superblock from LBA 0
    std::vector<uint8_t> rawPrimarySb(clusterSize_, 0);
    device_->ReadSectors(0, sectorsPerCluster_, rawPrimarySb.data());

    // Read raw Backup Superblock from backupSbLba
    std::vector<uint8_t> rawBackupSb(clusterSize_, 0);
    device_->ReadSectors(backupSbLba, sectorsPerCluster_, rawBackupSb.data());

    header.crc32 = WfsCrypto::Crc32(bitmapData.data(), bitmapData.size());

    out.write(reinterpret_cast<const char*>(&header), sizeof(header));
    out.write(reinterpret_cast<const char*>(rawPrimarySb.data()), rawPrimarySb.size());
    out.write(reinterpret_cast<const char*>(rawBackupSb.data()), rawBackupSb.size());
    out.write(reinterpret_cast<const char*>(bitmapData.data()), bitmapData.size());

    out.flush();
    lastBackupPath_ = backupFilePath;
    std::cout << "[WfsTransaction] Offline metadata snapshot saved to: " << backupFilePath << std::endl;
    return true;
}

bool WfsTransaction::RestoreOfflineMetadataBackup(
    const std::string& backupFilePath,
    WfsSuperblock& outRestoredSb,
    uint32_t& outBackupSbLba
) {
    if (!device_ || !device_->IsOpen() || !allocator_) return false;

    std::ifstream in(backupFilePath, std::ios::binary);
    if (!in.is_open()) return false;

    WfsBackupHeader header;
    in.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (std::memcmp(header.magic, "WFSBAK01", 8) != 0) {
        std::cerr << "[WfsTransaction] Corrupt backup file magic" << std::endl;
        return false;
    }

    std::vector<uint8_t> rawPrimarySb(header.cluster_size);
    std::vector<uint8_t> rawBackupSb(header.cluster_size);
    std::vector<uint8_t> bitmapData(header.bitmap_byte_size);

    in.read(reinterpret_cast<char*>(rawPrimarySb.data()), rawPrimarySb.size());
    in.read(reinterpret_cast<char*>(rawBackupSb.data()), rawBackupSb.size());
    in.read(reinterpret_cast<char*>(bitmapData.data()), bitmapData.size());

    // Verify CRC
    uint32_t crc = WfsCrypto::Crc32(bitmapData.data(), bitmapData.size());
    if (crc != header.crc32) {
        std::cerr << "[WfsTransaction] Backup bitmap CRC mismatch!" << std::endl;
        return false;
    }

    // Restore to physical drive
    device_->WriteSectors(0, sectorsPerCluster_, rawPrimarySb.data());
    device_->WriteSectors(header.backup_sb_lba, sectorsPerCluster_, rawBackupSb.data());

    // Restore bitmap
    uint32_t bitmapStart = allocator_->GetBitmapStartCluster();
    uint64_t bitmapSec = static_cast<uint64_t>(bitmapStart) * sectorsPerCluster_;
    size_t totalSecs = (bitmapData.size() + 511) / 512;
    device_->WriteSectors(bitmapSec, totalSecs, bitmapData.data());

    device_->Flush();

    // Parse restored superblock (decrypting with key)
    std::vector<uint8_t> decryptedSb = rawPrimarySb;
    WfsCrypto::CryptCluster(usbKey_, 0, decryptedSb.data(), clusterSize_, false);
    std::memcpy(&outRestoredSb, decryptedSb.data(), sizeof(WfsSuperblock));
    outBackupSbLba = header.backup_sb_lba;

    std::cout << "[WfsTransaction] Filesystem metadata successfully restored from backup!" << std::endl;
    return true;
}

bool WfsTransaction::Begin(const std::string& offlineBackupDir) {
    if (inTransaction_) {
        std::cerr << "[WfsTransaction] Transaction already active!" << std::endl;
        return false;
    }

    stagedWrites_.clear();
    allocator_->SnapshotState();

    if (!offlineBackupDir.empty()) {
        auto now = std::chrono::system_clock::now();
        auto timeT = std::chrono::system_clock::to_time_t(now);
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", std::localtime(&timeT));
        std::string bakFile = offlineBackupDir + "/wfs_metadata_pre_tx_" + buf + ".wfsbak";
        lastBackupPath_ = bakFile;
    }

    inTransaction_ = true;
    return true;
}

void WfsTransaction::StageWrite(uint32_t clusterIndex, const std::vector<uint8_t>& data, bool encrypt) {
    StageWrite(clusterIndex, data.data(), data.size(), encrypt);
}

void WfsTransaction::StageWrite(uint32_t clusterIndex, const uint8_t* data, size_t length, bool encrypt) {
    StagedClusterWrite staged;
    staged.clusterIndex = clusterIndex;
    staged.plaintextData.resize(clusterSize_, 0);
    size_t copyBytes = std::min(length, static_cast<size_t>(clusterSize_));
    std::memcpy(staged.plaintextData.data(), data, copyBytes);
    staged.requiresEncryption = encrypt;
    staged.checksum = WfsCrypto::Crc32(staged.plaintextData.data(), staged.plaintextData.size());

    stagedWrites_[clusterIndex] = std::move(staged);
}

bool WfsTransaction::WriteAndVerifyCluster(const StagedClusterWrite& write) {
    uint32_t clusterLba = write.clusterIndex * sectorsPerCluster_;
    std::vector<uint8_t> writeBuffer = write.plaintextData;

    // Encrypt cluster using LBA-based IV and USB master key
    if (write.requiresEncryption) {
        WfsCrypto::CryptCluster(usbKey_, clusterLba, writeBuffer.data(), clusterSize_, true);
    }

    // Write to physical storage
    if (!device_->WriteSectors(clusterLba, sectorsPerCluster_, writeBuffer.data())) {
        std::cerr << "[WfsTransaction] Failed to write cluster " << write.clusterIndex 
                  << " at LBA " << clusterLba << std::endl;
        return false;
    }

    // Read back and verify if not in dry-run mode
    if (!device_->IsDryRun()) {
        std::vector<uint8_t> readBack(clusterSize_, 0);
        if (!device_->ReadSectors(clusterLba, sectorsPerCluster_, readBack.data())) {
            std::cerr << "[WfsTransaction] Read-back verification failed for cluster " 
                      << write.clusterIndex << std::endl;
            return false;
        }

        if (write.requiresEncryption) {
            WfsCrypto::CryptCluster(usbKey_, clusterLba, readBack.data(), clusterSize_, false);
        }

        uint32_t readChecksum = WfsCrypto::Crc32(readBack.data(), readBack.size());
        if (readChecksum != write.checksum) {
            std::cerr << "[WfsTransaction] Integrity mismatch on cluster " << write.clusterIndex 
                      << " (Expected CRC " << std::hex << write.checksum 
                      << ", Read " << readChecksum << std::dec << ")" << std::endl;
            return false;
        }
    }

    return true;
}

bool WfsTransaction::Commit(WfsSuperblock& activeSuperblock, uint32_t backupSuperblockLba) {
    if (!inTransaction_) return false;

    // Phase 1: Write all staged data clusters and directory nodes
    for (const auto& pair : stagedWrites_) {
        if (!WriteAndVerifyCluster(pair.second)) {
            std::cerr << "[WfsTransaction] Error in Phase 1 (Payload Write). Aborting transaction." << std::endl;
            Rollback(activeSuperblock, backupSuperblockLba);
            return false;
        }
    }
    device_->Flush();

    // Phase 2: Write modified allocation bitmap blocks
    if (!allocator_->FlushDirtyBlocks()) {
        std::cerr << "[WfsTransaction] Error in Phase 2 (Bitmap Flush). Aborting transaction." << std::endl;
        Rollback(activeSuperblock, backupSuperblockLba);
        return false;
    }
    device_->Flush();

    // Phase 3: Increment Superblock Generation, recalculate checksums, and atomically commit
    activeSuperblock.generation++;
    activeSuperblock.flags &= ~0x01; // Mark clean

    // Calculate CRC32 of Superblock header fields (excluding CRC and SHA1)
    activeSuperblock.header_crc32 = WfsCrypto::Crc32(
        reinterpret_cast<const uint8_t*>(&activeSuperblock),
        offsetof(WfsSuperblock, header_crc32)
    );

    // Calculate SHA-1 of entire 4096-byte superblock payload
    auto sha = WfsCrypto::Sha1(
        reinterpret_cast<const uint8_t*>(&activeSuperblock),
        sizeof(WfsSuperblock) - sizeof(activeSuperblock.sha1_hash)
    );
    std::memcpy(activeSuperblock.sha1_hash, sha.data(), 20);

    // Encrypt Superblock with LBA 0 IV
    std::vector<uint8_t> encryptedSb(clusterSize_, 0);
    std::memcpy(encryptedSb.data(), &activeSuperblock, sizeof(WfsSuperblock));
    WfsCrypto::CryptCluster(usbKey_, 0, encryptedSb.data(), clusterSize_, true);

    // Write Primary Superblock to LBA 0
    if (!device_->WriteSectors(0, sectorsPerCluster_, encryptedSb.data())) {
        std::cerr << "[WfsTransaction] Critical Error: Failed to write Primary Superblock!" << std::endl;
        return false;
    }
    device_->Flush();

    // Encrypt and write Backup Superblock to backupSuperblockLba
    std::vector<uint8_t> encryptedBackupSb(clusterSize_, 0);
    std::memcpy(encryptedBackupSb.data(), &activeSuperblock, sizeof(WfsSuperblock));
    WfsCrypto::CryptCluster(usbKey_, backupSuperblockLba, encryptedBackupSb.data(), clusterSize_, true);

    if (!device_->WriteSectors(backupSuperblockLba, sectorsPerCluster_, encryptedBackupSb.data())) {
        std::cerr << "[WfsTransaction] Warning: Failed to write Backup Superblock at LBA " 
                  << backupSuperblockLba << std::endl;
    }
    device_->Flush();

    // Phase 4: Commit in-memory allocator state
    allocator_->CommitSnapshot();
    inTransaction_ = false;
    stagedWrites_.clear();

    std::cout << "[WfsTransaction] Transaction committed successfully. New Generation: " 
              << activeSuperblock.generation << std::endl;
    return true;
}

bool WfsTransaction::Rollback(const WfsSuperblock& originalSuperblock, uint32_t backupSuperblockLba) {
    std::cerr << "[WfsTransaction] Rolling back transaction to Generation " 
              << originalSuperblock.generation << "..." << std::endl;

    allocator_->RevertToSnapshot();
    stagedWrites_.clear();

    if (!device_->IsDryRun()) {
        // Restore original primary superblock
        std::vector<uint8_t> encryptedSb(clusterSize_, 0);
        std::memcpy(encryptedSb.data(), &originalSuperblock, sizeof(WfsSuperblock));
        WfsCrypto::CryptCluster(usbKey_, 0, encryptedSb.data(), clusterSize_, true);
        device_->WriteSectors(0, sectorsPerCluster_, encryptedSb.data());

        // Restore backup superblock
        std::vector<uint8_t> encryptedBackupSb(clusterSize_, 0);
        std::memcpy(encryptedBackupSb.data(), &originalSuperblock, sizeof(WfsSuperblock));
        WfsCrypto::CryptCluster(usbKey_, backupSuperblockLba, encryptedBackupSb.data(), clusterSize_, true);
        device_->WriteSectors(backupSuperblockLba, sectorsPerCluster_, encryptedBackupSb.data());

        allocator_->FlushDirtyBlocks();
        device_->Flush();
    }

    inTransaction_ = false;
    std::cout << "[WfsTransaction] Rollback complete." << std::endl;
    return true;
}

} // namespace WfsManager

