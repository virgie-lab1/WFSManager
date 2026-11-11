#pragma once

#include "WfsCommon.h"
#include "WfsStructures.h"
#include "WfsDiskDevice.h"
#include "WfsCrypto.h"
#include "WfsBlockAllocator.h"
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace WfsManager {

struct StagedClusterWrite {
    uint32_t clusterIndex;
    std::vector<uint8_t> plaintextData;
    bool requiresEncryption;
    uint32_t checksum;
};

class WfsTransaction {
public:
    WfsTransaction(
        IWfsDevice* device,
        WfsBlockAllocator* allocator,
        const uint8_t usbKey[WfsCrypto::KEY_SIZE],
        uint32_t clusterSize
    );

    // Creates an offline snapshot of critical metadata before touching physical storage
    bool CreateOfflineMetadataBackup(
        const std::string& backupFilePath,
        const WfsSuperblock& primarySb,
        uint32_t backupSbLba
    );

    // Restores offline snapshot in emergency / recovery scenarios
    bool RestoreOfflineMetadataBackup(
        const std::string& backupFilePath,
        WfsSuperblock& outRestoredSb,
        uint32_t& outBackupSbLba
    );

    // Begin atomic transaction
    bool Begin(const std::string& offlineBackupDir = "");

    // Stage a cluster write in write-ahead log
    void StageWrite(uint32_t clusterIndex, const std::vector<uint8_t>& data, bool encrypt = true);
    void StageWrite(uint32_t clusterIndex, const uint8_t* data, size_t length, bool encrypt = true);

    // Execute staged writes, flush, and atomically update Superblock
    bool Commit(WfsSuperblock& activeSuperblock, uint32_t backupSuperblockLba);

    // Rollback changes to pre-transaction state
    bool Rollback(const WfsSuperblock& originalSuperblock, uint32_t backupSuperblockLba);

    bool IsActive() const { return inTransaction_; }
    size_t GetStagedCount() const { return stagedWrites_.size(); }
    const std::string& GetLastBackupPath() const { return lastBackupPath_; }

private:
    IWfsDevice* device_;
    WfsBlockAllocator* allocator_;
    uint8_t usbKey_[WfsCrypto::KEY_SIZE];
    uint32_t clusterSize_;
    uint32_t sectorsPerCluster_;

    bool inTransaction_;
    std::string lastBackupPath_;

    // Staged cluster writes: Cluster Index -> StagedClusterWrite
    std::map<uint32_t, StagedClusterWrite> stagedWrites_;

    WfsSuperblock preTxSuperblock_;

    bool WriteAndVerifyCluster(const StagedClusterWrite& write);
};

} // namespace WfsManager

