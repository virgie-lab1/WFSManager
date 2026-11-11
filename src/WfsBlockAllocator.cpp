#include "WfsBlockAllocator.h"
#include <cstring>
#include <algorithm>
#include <iostream>

namespace WfsManager {

WfsBlockAllocator::WfsBlockAllocator(IWfsDevice* device, uint32_t clusterSize, uint64_t totalSectors, uint32_t bitmapStartCluster)
    : device_(device),
      clusterSize_(clusterSize),
      totalSectors_(totalSectors),
      sectorsPerCluster_(clusterSize / (device ? device->GetSectorSize() : 512)),
      bitmapStartCluster_(bitmapStartCluster),
      totalClusters_(0),
      freeClusterCount_(0),
      bitmapBlockCount_(0)
{
    if (sectorsPerCluster_ == 0) sectorsPerCluster_ = 8;
    totalClusters_ = static_cast<uint32_t>(totalSectors_ / sectorsPerCluster_);

    size_t bitmapBytes = (totalClusters_ + 7) / 8;
    bitmapBlockCount_ = static_cast<uint32_t>((bitmapBytes + clusterSize_ - 1) / clusterSize_);

    activeBitmap_.resize(bitmapBytes, 0);
    committedBitmap_.resize(bitmapBytes, 0);
    snapshotBitmap_.resize(bitmapBytes, 0);
    freeClusterCount_ = totalClusters_;
}

bool WfsBlockAllocator::Load() {
    if (!device_ || !device_->IsOpen()) return false;

    size_t totalBytesToRead = bitmapBlockCount_ * clusterSize_;
    std::vector<uint8_t> tempBuffer(totalBytesToRead);

    uint64_t startSector = static_cast<uint64_t>(bitmapStartCluster_) * sectorsPerCluster_;
    size_t totalSectorsToRead = bitmapBlockCount_ * sectorsPerCluster_;

    if (!device_->ReadSectors(startSector, totalSectorsToRead, tempBuffer.data())) {
        std::cerr << "[WfsBlockAllocator] Failed to read allocation bitmap at cluster " 
                  << bitmapStartCluster_ << std::endl;
        return false;
    }

    size_t actualBitmapBytes = (totalClusters_ + 7) / 8;
    std::memcpy(activeBitmap_.data(), tempBuffer.data(), actualBitmapBytes);
    committedBitmap_ = activeBitmap_;
    snapshotBitmap_ = activeBitmap_;

    // Calculate initial free cluster count
    freeClusterCount_ = 0;
    for (uint32_t i = 0; i < totalClusters_; ++i) {
        if (!IsClusterAllocated(i)) {
            freeClusterCount_++;
        }
    }

    dirtyBitmapBlocks_.clear();
    return true;
}

bool WfsBlockAllocator::FlushDirtyBlocks() {
    if (!device_ || !device_->IsOpen() || dirtyBitmapBlocks_.empty()) {
        return true;
    }

    for (uint32_t blockIdx : dirtyBitmapBlocks_) {
        uint32_t clusterIndex = bitmapStartCluster_ + blockIdx;
        uint64_t sectorOffset = static_cast<uint64_t>(clusterIndex) * sectorsPerCluster_;

        size_t byteOffset = blockIdx * clusterSize_;
        std::vector<uint8_t> blockData(clusterSize_, 0);

        size_t bytesToCopy = std::min(static_cast<size_t>(clusterSize_), activeBitmap_.size() - byteOffset);
        std::memcpy(blockData.data(), activeBitmap_.data() + byteOffset, bytesToCopy);

        if (!device_->WriteSectors(sectorOffset, sectorsPerCluster_, blockData.data())) {
            std::cerr << "[WfsBlockAllocator] Failed to write bitmap block " << blockIdx << std::endl;
            return false;
        }
    }

    device_->Flush();
    committedBitmap_ = activeBitmap_;
    dirtyBitmapBlocks_.clear();
    return true;
}

bool WfsBlockAllocator::IsClusterAllocated(uint32_t clusterIndex) const {
    if (clusterIndex >= totalClusters_) return true;
    uint32_t byteIdx = clusterIndex / 8;
    uint8_t bitIdx = clusterIndex % 8;
    return (activeBitmap_[byteIdx] & (1 << bitIdx)) != 0;
}

void WfsBlockAllocator::SetClusterAllocated(uint32_t clusterIndex, bool allocated) {
    if (clusterIndex >= totalClusters_) return;
    uint32_t byteIdx = clusterIndex / 8;
    uint8_t bitIdx = clusterIndex % 8;

    bool current = (activeBitmap_[byteIdx] & (1 << bitIdx)) != 0;
    if (current == allocated) return;

    if (allocated) {
        activeBitmap_[byteIdx] |= (1 << bitIdx);
        if (freeClusterCount_ > 0) freeClusterCount_--;
    } else {
        activeBitmap_[byteIdx] &= ~(1 << bitIdx);
        freeClusterCount_++;
    }

    MarkBitmapBlockDirty(clusterIndex);
}

void WfsBlockAllocator::MarkBitmapBlockDirty(uint32_t clusterIndex) {
    uint32_t byteIdx = clusterIndex / 8;
    uint32_t blockIdx = byteIdx / clusterSize_;
    dirtyBitmapBlocks_.insert(blockIdx);
}

uint32_t WfsBlockAllocator::FindContiguousFree(uint32_t count, uint32_t startSearch) const {
    if (count == 0 || count > freeClusterCount_) return 0xFFFFFFFF;

    uint32_t currentRun = 0;
    uint32_t runStart = 0;

    for (uint32_t i = startSearch; i < totalClusters_; ++i) {
        if (!IsClusterAllocated(i)) {
            if (currentRun == 0) runStart = i;
            currentRun++;
            if (currentRun == count) return runStart;
        } else {
            currentRun = 0;
        }
    }
    return 0xFFFFFFFF;
}

bool WfsBlockAllocator::AllocateClusters(uint32_t count, std::vector<WfsExtent>& outExtents, bool requireContiguous) {
    if (count == 0) return true;
    if (count > freeClusterCount_) {
        std::cerr << "[WfsBlockAllocator] Out of space: Requested " << count 
                  << " clusters, but only " << freeClusterCount_ << " free." << std::endl;
        return false;
    }

    outExtents.clear();

    // Strategy 1: Attempt contiguous allocation first to minimize fragmentation
    uint32_t searchStart = bitmapStartCluster_ + bitmapBlockCount_ + 4;
    uint32_t contiguousStart = FindContiguousFree(count, searchStart);

    if (contiguousStart != 0xFFFFFFFF) {
        for (uint32_t i = 0; i < count; ++i) {
            SetClusterAllocated(contiguousStart + i, true);
        }
        outExtents.push_back({ contiguousStart, count });
        return true;
    }

    if (requireContiguous) {
        return false;
    }

    // Strategy 2: Gather extent runs across available free space
    uint32_t remaining = count;
    uint32_t cur = searchStart;

    while (remaining > 0 && cur < totalClusters_) {
        while (cur < totalClusters_ && IsClusterAllocated(cur)) {
            cur++;
        }
        if (cur >= totalClusters_) break;

        uint32_t runStart = cur;
        uint32_t runLen = 0;
        while (cur < totalClusters_ && !IsClusterAllocated(cur) && runLen < remaining) {
            SetClusterAllocated(cur, true);
            cur++;
            runLen++;
        }

        outExtents.push_back({ runStart, runLen });
        remaining -= runLen;
    }

    if (remaining > 0) {
        FreeClusters(outExtents);
        outExtents.clear();
        return false;
    }

    return true;
}

bool WfsBlockAllocator::FreeClusters(const std::vector<WfsExtent>& extents) {
    for (const auto& ext : extents) {
        for (uint32_t i = 0; i < ext.clusterCount; ++i) {
            uint32_t cluster = ext.startCluster + i;
            if (cluster < totalClusters_) {
                SetClusterAllocated(cluster, false);
            }
        }
    }
    return true;
}

void WfsBlockAllocator::SnapshotState() {
    snapshotBitmap_ = activeBitmap_;
}

void WfsBlockAllocator::RevertToSnapshot() {
    activeBitmap_ = snapshotBitmap_;
    dirtyBitmapBlocks_.clear();

    freeClusterCount_ = 0;
    for (uint32_t i = 0; i < totalClusters_; ++i) {
        if (!IsClusterAllocated(i)) freeClusterCount_++;
    }
}

void WfsBlockAllocator::CommitSnapshot() {
    snapshotBitmap_ = activeBitmap_;
}

double WfsBlockAllocator::GetFragmentationRatio() const {
    if (totalClusters_ == 0) return 0.0;
    uint32_t freeFragments = 0;
    bool inFreeRun = false;

    for (uint32_t i = 0; i < totalClusters_; ++i) {
        bool free = !IsClusterAllocated(i);
        if (free && !inFreeRun) {
            freeFragments++;
            inFreeRun = true;
        } else if (!free) {
            inFreeRun = false;
        }
    }

    if (freeClusterCount_ == 0) return 0.0;
    return static_cast<double>(freeFragments) / static_cast<double>(freeClusterCount_);
}

bool WfsBlockAllocator::AuditIntegrity(
    const std::set<uint32_t>& referencedClusters,
    std::vector<uint32_t>& outOrphanClusters,
    std::vector<uint32_t>& outUnallocatedReferences
) const {
    outOrphanClusters.clear();
    outUnallocatedReferences.clear();

    // Check for referenced clusters marked free
    for (uint32_t cluster : referencedClusters) {
        if (cluster >= totalClusters_) {
            outUnallocatedReferences.push_back(cluster);
        } else if (!IsClusterAllocated(cluster)) {
            outUnallocatedReferences.push_back(cluster);
        }
    }

    // Check for allocated clusters not referenced anywhere
    uint32_t reservedEnd = bitmapStartCluster_ + bitmapBlockCount_ + 4;

    for (uint32_t i = reservedEnd; i < totalClusters_; ++i) {
        if (IsClusterAllocated(i)) {
            if (referencedClusters.find(i) == referencedClusters.end()) {
                outOrphanClusters.push_back(i);
            }
        }
    }

    return outOrphanClusters.empty() && outUnallocatedReferences.empty();
}

} // namespace WfsManager

