#pragma once

#include "WfsCommon.h"
#include "WfsDiskDevice.h"
#include <vector>
#include <set>
#include <memory>

namespace WfsManager {

class WfsBlockAllocator {
public:
    WfsBlockAllocator(IWfsDevice* device, uint32_t clusterSize, uint64_t totalSectors, uint32_t bitmapStartCluster);

    bool Load();
    bool FlushDirtyBlocks();

    // Allocation methods
    bool AllocateClusters(uint32_t count, std::vector<WfsExtent>& outExtents, bool requireContiguous = false);
    bool FreeClusters(const std::vector<WfsExtent>& extents);

    // Queries
    uint32_t GetTotalClusters() const { return totalClusters_; }
    uint32_t GetFreeClusterCount() const { return freeClusterCount_; }
    uint32_t GetAllocatedClusterCount() const { return totalClusters_ - freeClusterCount_; }
    uint32_t GetClusterSize() const { return clusterSize_; }
    uint32_t GetBitmapStartCluster() const { return bitmapStartCluster_; }
    double GetFragmentationRatio() const;

    // Direct bit testing
    bool IsClusterAllocated(uint32_t clusterIndex) const;
    void SetClusterAllocated(uint32_t clusterIndex, bool allocated);

    // Transaction state management
    void SnapshotState();
    void RevertToSnapshot();
    void CommitSnapshot();

    // Consistency and integrity audit
    bool AuditIntegrity(
        const std::set<uint32_t>& referencedClusters,
        std::vector<uint32_t>& outOrphanClusters,
        std::vector<uint32_t>& outUnallocatedReferences
    ) const;

    const std::vector<uint8_t>& GetBitmapData() const { return activeBitmap_; }

private:
    IWfsDevice* device_;
    uint32_t clusterSize_;
    uint64_t totalSectors_;
    uint32_t sectorsPerCluster_;
    uint32_t bitmapStartCluster_;
    uint32_t totalClusters_;
    uint32_t freeClusterCount_;
    uint32_t bitmapBlockCount_;

    std::vector<uint8_t> committedBitmap_;
    std::vector<uint8_t> activeBitmap_;
    std::vector<uint8_t> snapshotBitmap_;
    std::set<uint32_t> dirtyBitmapBlocks_; // Blocks that require disk write on commit

    uint32_t FindContiguousFree(uint32_t count, uint32_t startSearch = 0) const;
    void MarkBitmapBlockDirty(uint32_t clusterIndex);
};

} // namespace WfsManager

