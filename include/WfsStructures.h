#pragma once

#include "WfsCommon.h"

#pragma pack(push, 1)

namespace WfsManager {

constexpr uint32_t WFS_SUPERBLOCK_MAGIC     = 0x53465321; // "SFS!" (Big-Endian)
constexpr uint32_t WFS_SUPERBLOCK_MAGIC_ALT = 0x57465300; // "WFS\0"
constexpr uint32_t WFS_DEFAULT_SECTOR_SIZE  = 0x0200;     // 512 bytes
constexpr uint32_t WFS_DEFAULT_CLUSTER_SIZE = 0x1000;     // 4096 bytes (8 sectors)
constexpr uint32_t WFS_METADATA_BLOCK_SIZE  = 0x1000;     // 4096 bytes

constexpr uint16_t WFS_TYPE_FILE            = 0x0001;
constexpr uint16_t WFS_TYPE_DIRECTORY       = 0x0002;
constexpr uint16_t WFS_FLAG_SYSTEM          = 0x0004;
constexpr uint16_t WFS_FLAG_HIDDEN          = 0x0008;

// Primary and Backup Superblock Layout (stored at LBA 0 and backup LBA)
struct WfsSuperblock {
    uint32_t magic;                     // 0x00: WFS_SUPERBLOCK_MAGIC
    uint32_t version;                   // 0x04: Filesystem format version (e.g. 0x00000001)
    uint32_t generation;                // 0x08: Monotonic transaction commit counter
    uint32_t cluster_size;              // 0x0C: Bytes per cluster (typically 0x1000 or 0x2000)
    uint64_t total_sectors;             // 0x10: Total addressable drive sectors
    uint32_t area_count;                // 0x18: Number of allocation areas
    uint32_t root_inode_cluster;        // 0x1C: Cluster index of root directory ('/')
    uint32_t allocator_bitmap_cluster;  // 0x20: Cluster index of primary allocation bitmap
    uint32_t backup_superblock_lba;     // 0x24: LBA of redundant backup superblock
    uint32_t flags;                     // 0x28: State flags (0x01 = dirty/journal active)
    uint32_t header_crc32;              // 0x2C: CRC32 of preceding header fields
    uint8_t  sha1_hash[20];             // 0x30: SHA-1 hash of the active metadata payload
    uint8_t  reserved[4028];            // 0x44: Padding to 4096 bytes (metadata block size)
};
static_assert(sizeof(WfsSuperblock) == 4096, "WfsSuperblock size must be exactly 4096 bytes");

// Allocation Area Descriptor
struct WfsAreaHeader {
    uint32_t area_index;                // 0x00: 0-indexed area identifier
    uint32_t start_cluster;             // 0x04: First cluster of this area
    uint32_t cluster_count;             // 0x08: Number of clusters in this area
    uint32_t subblock_allocator_offset; // 0x0C: Cluster offset of subblock allocator (metadata)
    uint32_t data_allocator_offset;     // 0x10: Cluster offset of data cluster bitmap
    uint32_t flags;                     // 0x14: Area flags
    uint8_t  reserved[40];              // 0x18: Reserved area padding
};

// Inode Structure (4096 bytes or subblock descriptor)
struct WfsInodeDisk {
    uint32_t inode_number;              // 0x00: Unique Inode ID
    uint16_t type;                      // 0x04: WFS_TYPE_FILE or WFS_TYPE_DIRECTORY
    uint16_t flags;                     // 0x06: Permission / system flags
    uint64_t file_size;                 // 0x08: File size in bytes (0 for directory)
    uint32_t ctime;                     // 0x10: Creation timestamp (POSIX seconds)
    uint32_t mtime;                     // 0x14: Modification timestamp
    uint32_t atime;                     // 0x18: Access timestamp
    uint32_t direct_extent_count;       // 0x1C: Number of direct extents populated
    struct {
        uint32_t start_cluster;         // Starting cluster index
        uint32_t count;                 // Number of contiguous clusters
    } direct_extents[32];               // 0x20: Direct extent table (32 * 8 = 256 bytes)
    uint32_t indirect_cluster;          // 0x120: Cluster pointing to indirect extents
    uint32_t double_indirect_cluster;   // 0x124: Double indirect pointer
    uint8_t  reserved[3800];            // Padding to 4096 bytes
};
static_assert(sizeof(WfsInodeDisk) == 4096, "WfsInodeDisk size must be exactly 4096 bytes");

// Directory Entry (Variable or aligned within directory block)
struct WfsDirEntryDisk {
    uint32_t inode_number;              // Inode referenced by this entry
    uint8_t  type;                      // 0x01 = File, 0x02 = Directory
    uint8_t  name_length;               // Length of filename (excluding null terminator)
    char     name[250];                 // UTF-8 filename (null-terminated)
};
static_assert(sizeof(WfsDirEntryDisk) == 256, "WfsDirEntryDisk size must be 256 bytes");

// Title Metadata (TMD) Header Structure (Cafe OS)
struct WfsTmdHeader {
    uint32_t signature_type;            // 0x00: RSA type (e.g. 0x00010004 for RSA-2048)
    uint8_t  signature[256];            // 0x04: RSA-2048 Signature
    uint8_t  padding_sig[60];           // 0x104: Padding after signature
    char     issuer[64];                // 0x140: Issuer string
    uint8_t  version;                   // 0x180: TMD Version
    uint8_t  ca_crl_version;            // 0x181
    uint8_t  signer_crl_version;        // 0x182
    uint8_t  reserved1;                 // 0x183
    uint64_t system_version;            // 0x184: Minimum OS Version
    uint64_t title_id;                  // 0x18C: 8-byte Title ID
    uint32_t title_type;                // 0x194: Title Type
    uint16_t group_id;                  // 0x198: Publisher Group ID
    uint8_t  reserved2[62];             // 0x19A: Reserved
    uint32_t access_rights;             // 0x1D8: Access rights bitmask
    uint16_t title_version;             // 0x1DC: Title Version
    uint16_t num_contents;              // 0x1DE: Number of contents
    uint16_t boot_index;                // 0x1E0: Index of boot content (.app)
    uint16_t reserved3;                 // 0x1E2: Reserved
};

// TMD Content Chunk Entry
struct WfsTmdContentChunk {
    uint32_t content_id;                // ID of content file (e.g. 00000000 for 00000000.app)
    uint16_t index;                     // Content index
    uint16_t type;                      // Content type (0x0001 = Normal, 0x2001 = Shared)
    uint64_t size;                      // Size of content file in bytes
    uint8_t  sha1_hash[20];             // SHA-1 hash of this content
};

// Title Ticket (title.tik) Header Structure (Cafe OS)
struct WfsTicketHeader {
    uint32_t signature_type;            // 0x00: Signature Type
    uint8_t  signature[256];            // 0x04: Signature
    uint8_t  padding_sig[60];           // 0x104: Padding
    char     issuer[64];                // 0x140: Issuer string
    uint8_t  ecdh_data[60];             // 0x180: ECDH data
    uint8_t  ticket_version;            // 0x1BC: Ticket Version
    uint8_t  reserved1[2];              // 0x1BD
    uint8_t  title_key_enc[16];         // 0x1BF: Encrypted Title Key (AES-128 with Common Key)
    uint8_t  unknown;                   // 0x1CF
    uint64_t ticket_id;                 // 0x1D0: Unique Ticket ID
    uint32_t console_id;                // 0x1D8: Target Console ID (or 0 for universal/common ticket)
    uint64_t title_id;                  // 0x1DC: Target Title ID
    uint16_t sys_access_mask;           // 0x1E4
    uint16_t ticket_version_internal;   // 0x1E6
    uint32_t permitted_titles_mask;     // 0x1E8
    uint32_t permit_mask;               // 0x1EC
    uint8_t  title_export_allowed;      // 0x1F0
    uint8_t  common_key_index;          // 0x1F1: 0 = Common Key
    uint8_t  reserved2[48];             // 0x1F2
    uint8_t  content_access_permissions[64]; // 0x222
    uint16_t padding_end;               // 0x262
};

} // namespace WfsManager

#pragma pack(pop)

