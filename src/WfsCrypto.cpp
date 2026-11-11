#include "WfsCrypto.h"
#include <cstring>
#include <algorithm>

namespace WfsManager {

// --- Rijndael AES-128 Core Implementation ---

static const uint8_t s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rs_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static void AesKeyExpansion(const uint8_t* key, uint8_t* roundKeys) {
    std::memcpy(roundKeys, key, 16);
    uint32_t bytesGenerated = 16;
    uint32_t rconIteration = 1;
    uint8_t temp[4];

    while (bytesGenerated < 176) {
        for (int i = 0; i < 4; ++i) {
            temp[i] = roundKeys[bytesGenerated - 4 + i];
        }
        if (bytesGenerated % 16 == 0) {
            // RotWord
            uint8_t k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            // SubWord
            temp[0] = s_box[temp[0]];
            temp[1] = s_box[temp[1]];
            temp[2] = s_box[temp[2]];
            temp[3] = s_box[temp[3]];
            // Rcon
            temp[0] ^= rcon[rconIteration++];
        }
        for (int i = 0; i < 4; ++i) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }
}

static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

static uint8_t MultiplyGF(uint8_t x, uint8_t y) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (y & 1) p ^= x;
        uint8_t hi_bit = (x & 0x80);
        x <<= 1;
        if (hi_bit) x ^= 0x1b;
        y >>= 1;
    }
    return p;
}

static void AddRoundKey(uint8_t state[4][4], const uint8_t* roundKey) {
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            state[r][c] ^= roundKey[c * 4 + r];
        }
    }
}

static void SubBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = s_box[state[r][c]];
        }
    }
}

static void InvSubBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = rs_box[state[r][c]];
        }
    }
}

static void ShiftRows(uint8_t state[4][4]) {
    uint8_t t;
    // Row 1
    t = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t;
    // Row 2
    t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
    t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
    // Row 3
    t = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t;
}

static void InvShiftRows(uint8_t state[4][4]) {
    uint8_t t;
    // Row 1
    t = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = t;
    // Row 2
    t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
    t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
    // Row 3
    t = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = t;
}

static void MixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t a[4];
        for (int r = 0; r < 4; ++r) a[r] = state[r][c];
        uint8_t t = a[0] ^ a[1] ^ a[2] ^ a[3];
        uint8_t u = a[0];
        state[0][c] ^= t ^ xtime(a[0] ^ a[1]);
        state[1][c] ^= t ^ xtime(a[1] ^ a[2]);
        state[2][c] ^= t ^ xtime(a[2] ^ a[3]);
        state[3][c] ^= t ^ xtime(a[3] ^ u);
    }
}

static void InvMixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t a = state[0][c], b = state[1][c], d = state[2][c], e = state[3][c];
        state[0][c] = MultiplyGF(a, 0x0e) ^ MultiplyGF(b, 0x0b) ^ MultiplyGF(d, 0x0d) ^ MultiplyGF(e, 0x09);
        state[1][c] = MultiplyGF(a, 0x09) ^ MultiplyGF(b, 0x0e) ^ MultiplyGF(d, 0x0b) ^ MultiplyGF(e, 0x0d);
        state[2][c] = MultiplyGF(a, 0x0d) ^ MultiplyGF(b, 0x09) ^ MultiplyGF(d, 0x0e) ^ MultiplyGF(e, 0x0b);
        state[3][c] = MultiplyGF(a, 0x0b) ^ MultiplyGF(b, 0x0d) ^ MultiplyGF(d, 0x09) ^ MultiplyGF(e, 0x0e);
    }
}

void WfsCrypto::Aes128EcbEncrypt(const uint8_t key[KEY_SIZE], const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE]) {
    uint8_t roundKeys[176];
    AesKeyExpansion(key, roundKeys);

    uint8_t state[4][4];
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            state[r][c] = in[c * 4 + r];
        }
    }

    AddRoundKey(state, roundKeys);

    for (int round = 1; round < 10; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 160);

    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            out[c * 4 + r] = state[r][c];
        }
    }
}

void WfsCrypto::Aes128EcbDecrypt(const uint8_t key[KEY_SIZE], const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE]) {
    uint8_t roundKeys[176];
    AesKeyExpansion(key, roundKeys);

    uint8_t state[4][4];
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            state[r][c] = in[c * 4 + r];
        }
    }

    AddRoundKey(state, roundKeys + 160);

    for (int round = 9; round >= 1; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            out[c * 4 + r] = state[r][c];
        }
    }
}

void WfsCrypto::Aes128CbcEncrypt(
    const uint8_t key[KEY_SIZE],
    const uint8_t iv[BLOCK_SIZE],
    const uint8_t* in,
    uint8_t* out,
    size_t length
) {
    if (length % BLOCK_SIZE != 0) return;
    uint8_t currentIv[BLOCK_SIZE];
    std::memcpy(currentIv, iv, BLOCK_SIZE);

    for (size_t offset = 0; offset < length; offset += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE];
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            block[i] = in[offset + i] ^ currentIv[i];
        }
        Aes128EcbEncrypt(key, block, out + offset);
        std::memcpy(currentIv, out + offset, BLOCK_SIZE);
    }
}

void WfsCrypto::Aes128CbcDecrypt(
    const uint8_t key[KEY_SIZE],
    const uint8_t iv[BLOCK_SIZE],
    const uint8_t* in,
    uint8_t* out,
    size_t length
) {
    if (length % BLOCK_SIZE != 0) return;
    uint8_t currentIv[BLOCK_SIZE];
    std::memcpy(currentIv, iv, BLOCK_SIZE);

    for (size_t offset = 0; offset < length; offset += BLOCK_SIZE) {
        uint8_t nextIv[BLOCK_SIZE];
        std::memcpy(nextIv, in + offset, BLOCK_SIZE);

        uint8_t block[BLOCK_SIZE];
        Aes128EcbDecrypt(key, in + offset, block);

        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            out[offset + i] = block[i] ^ currentIv[i];
        }
        std::memcpy(currentIv, nextIv, BLOCK_SIZE);
    }
}

bool WfsCrypto::DeriveUsbStorageKey(
    const uint8_t* otpData, size_t otpSize,
    const uint8_t* seepromData, size_t seepromSize,
    uint8_t outKey[KEY_SIZE]
) {
    if (!otpData || otpSize < OTP_SIZE || !seepromData || seepromSize < SEEPROM_SIZE || !outKey) {
        return false;
    }

    // OTP contains IVS Key at offset 0x130 (16 bytes)
    const uint8_t* ivsKey = otpData + OTP_IVS_KEY_OFFSET;

    // SEEPROM contains IVS Seed at offset 0x0B0 (16 bytes)
    const uint8_t* ivsSeed = seepromData + SEEPROM_IVS_SEED_OFFSET;

    // Check device ID match (first 4 bytes of IVS Seed usually match SEEPROM offset 0x000)
    // Both are present on the hardware.
    // Derive USB Storage Master Key via AES-128-ECB(key = IVS_KEY, data = IVS_SEED)
    Aes128EcbEncrypt(ivsKey, ivsSeed, outKey);
    return true;
}

void WfsCrypto::CalculateSectorIV(uint32_t lba, uint8_t outIv[BLOCK_SIZE]) {
    std::memset(outIv, 0, BLOCK_SIZE);
    uint32_t beLba = BigEndian32(lba);
    std::memcpy(outIv, &beLba, sizeof(uint32_t));
}

void WfsCrypto::CryptCluster(
    const uint8_t key[KEY_SIZE],
    uint32_t clusterLba,
    uint8_t* data,
    size_t clusterSize,
    bool encrypt
) {
    uint8_t iv[BLOCK_SIZE];
    CalculateSectorIV(clusterLba, iv);

    if (encrypt) {
        Aes128CbcEncrypt(key, iv, data, data, clusterSize);
    } else {
        Aes128CbcDecrypt(key, iv, data, data, clusterSize);
    }
}

bool WfsCrypto::DecryptTitleKey(
    const uint8_t commonKey[16],
    const uint8_t encryptedTitleKey[16],
    uint64_t titleId,
    uint8_t outDecryptedTitleKey[16]
) {
    if (!commonKey || !encryptedTitleKey || !outDecryptedTitleKey) return false;

    // Ticket IV is (TitleID || 0x00 * 8) in Big Endian
    uint8_t iv[16];
    std::memset(iv, 0, 16);
    uint64_t beTitleId = BigEndian64(titleId);
    std::memcpy(iv, &beTitleId, sizeof(uint64_t));

    Aes128CbcDecrypt(commonKey, iv, encryptedTitleKey, outDecryptedTitleKey, 16);
    return true;
}

// --- SHA-1 Hash Implementation (FIPS 180-1) ---

#define SHA1_ROL(val, bits) (((val) << (bits)) | ((val) >> (32 - (bits))))

std::array<uint8_t, 20> WfsCrypto::Sha1(const uint8_t* data, size_t length) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    std::vector<uint8_t> msg(data, data + length);
    uint64_t bitLength = static_cast<uint64_t>(length) * 8;

    msg.push_back(0x80);
    while ((msg.size() % 64) != 56) {
        msg.push_back(0x00);
    }

    uint64_t beBitLength = BigEndian64(bitLength);
    const uint8_t* bitLenBytes = reinterpret_cast<const uint8_t*>(&beBitLength);
    msg.insert(msg.end(), bitLenBytes, bitLenBytes + 8);

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            uint32_t val;
            std::memcpy(&val, &msg[chunk + i * 4], 4);
            w[i] = BigEndian32(val);
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = SHA1_ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = SHA1_ROL(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = SHA1_ROL(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    std::array<uint8_t, 20> digest;
    uint32_t h[5] = { BigEndian32(h0), BigEndian32(h1), BigEndian32(h2), BigEndian32(h3), BigEndian32(h4) };
    std::memcpy(digest.data(), h, 20);
    return digest;
}

// --- CRC-32 (IEEE 802.3) ---

uint32_t WfsCrypto::Crc32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = data[i];
        crc ^= byte;
        for (int j = 0; j < 8; ++j) {
            uint32_t mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return ~crc;
}

} // namespace WfsManager
