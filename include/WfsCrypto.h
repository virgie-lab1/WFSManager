#pragma once

#include "WfsCommon.h"
#include <array>
#include <vector>

namespace WfsManager {

class WfsCrypto {
public:
    static constexpr size_t KEY_SIZE   = 16; // 128-bit AES
    static constexpr size_t BLOCK_SIZE = 16; // 128-bit block
    static constexpr size_t OTP_SIZE   = 1024;
    static constexpr size_t SEEPROM_SIZE = 512;

    static constexpr size_t OTP_IVS_KEY_OFFSET    = 0x130;
    static constexpr size_t SEEPROM_IVS_SEED_OFFSET = 0x0B0;
    static constexpr size_t SEEPROM_DEVICE_ID_OFFSET = 0x000;

    // Derive console-specific USB storage master key from OTP and SEEPROM dumps
    static bool DeriveUsbStorageKey(
        const uint8_t* otpData, size_t otpSize,
        const uint8_t* seepromData, size_t seepromSize,
        uint8_t outKey[KEY_SIZE]
    );

    // Compute 16-byte IV for a specific LBA or cluster index
    static void CalculateSectorIV(uint32_t lba, uint8_t outIv[BLOCK_SIZE]);

    // Raw AES-128-ECB
    static void Aes128EcbEncrypt(const uint8_t key[KEY_SIZE], const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE]);
    static void Aes128EcbDecrypt(const uint8_t key[KEY_SIZE], const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE]);

    // AES-128-CBC for data clusters (size must be a multiple of 16 bytes)
    static void Aes128CbcEncrypt(
        const uint8_t key[KEY_SIZE],
        const uint8_t iv[BLOCK_SIZE],
        const uint8_t* in,
        uint8_t* out,
        size_t length
    );

    static void Aes128CbcDecrypt(
        const uint8_t key[KEY_SIZE],
        const uint8_t iv[BLOCK_SIZE],
        const uint8_t* in,
        uint8_t* out,
        size_t length
    );

    // Crypt a WFS cluster in-place using its physical LBA
    static void CryptCluster(
        const uint8_t key[KEY_SIZE],
        uint32_t clusterLba,
        uint8_t* data,
        size_t clusterSize,
        bool encrypt
    );

    // Decrypt Title Key from Ticket using common key provided by user/environment
    static bool DecryptTitleKey(
        const uint8_t commonKey[16],
        const uint8_t encryptedTitleKey[16],
        uint64_t titleId,
        uint8_t outDecryptedTitleKey[16]
    );

    // SHA-1 Hash (20 bytes)
    static std::array<uint8_t, 20> Sha1(const uint8_t* data, size_t length);

    // CRC32 Checksum
    static uint32_t Crc32(const uint8_t* data, size_t length);
};

} // namespace WfsManager

