#include "WfsBlockAllocator.h"
#include "WfsCommon.h"
#include "WfsCrypto.h"
#include "WfsDiskDevice.h"
#include "WfsFileSystem.h"
#include "WfsSafetyGuard.h"
#include "WfsTitleManager.h"
#include "WfsTransaction.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#define WFS_ASSERT(cond)                                                                \
  do {                                                                                  \
    if (!(cond)) {                                                                      \
      std::cerr << "[TEST FAILURE] Assertion failed: " #cond " in " << __FUNCTION__     \
                << " (" << __FILE__ << ":" << __LINE__ << ")" << std::endl;            \
      std::exit(1);                                                                     \
    }                                                                                   \
  } while (0)

using namespace WfsManager;

static void TestCrypto() {
  std::cout << "[TEST] Running WfsCrypto verification..." << std::endl;

  // Test 1: AES-128 ECB Test Vector (NIST SP 800-38A)
  // Key: 2b7e151628aed2a6abf7158809cf4f3c
  // Plaintext: 6bc1bee22e409f96e93d7e117393172a
  // Ciphertext: 3ad77bb40d7a3660a89ecaf32466ef97
  const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                           0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  const uint8_t plain[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                             0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
  const uint8_t expectedCipher[16] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a,
                                      0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3,
                                      0x24, 0x66, 0xef, 0x97};

  uint8_t cipher[16];
  WfsCrypto::Aes128EcbEncrypt(key, plain, cipher);
  WFS_ASSERT(std::memcmp(cipher, expectedCipher, 16) == 0 &&
             "AES-128-ECB Encrypt failed NIST test vector");

  uint8_t decrypted[16];
  WfsCrypto::Aes128EcbDecrypt(key, cipher, decrypted);
  WFS_ASSERT(std::memcmp(decrypted, plain, 16) == 0 &&
             "AES-128-ECB Decrypt failed NIST test vector");

  // Test 2: SHA-1
  std::string testMsg = "hello";
  auto sha = WfsCrypto::Sha1(reinterpret_cast<const uint8_t *>(testMsg.data()),
                             testMsg.length());
  // aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
  const uint8_t expectedSha[20] = {0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8,
                                   0xa2, 0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48,
                                   0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d};
  WFS_ASSERT(std::memcmp(sha.data(), expectedSha, 20) == 0 &&
             "SHA-1 failed known test vector");

  // Test 3: CRC32
  uint32_t crc =
      WfsCrypto::Crc32(reinterpret_cast<const uint8_t *>("123456789"), 9);
  WFS_ASSERT(crc == 0xCBF43926 && "CRC32 failed standard test vector");

  // Test 4: USB Key Derivation
  std::vector<uint8_t> otp(1024, 0xAA);
  std::vector<uint8_t> seeprom(512, 0xBB);
  // Put test IVS key at OTP 0x130
  std::memcpy(otp.data() + 0x130, key, 16);
  // Put test IVS seed at SEEPROM 0x0B0
  std::memcpy(seeprom.data() + 0x0B0, plain, 16);

  uint8_t derivedUsbKey[16];
  bool ok = WfsCrypto::DeriveUsbStorageKey(
      otp.data(), otp.size(), seeprom.data(), seeprom.size(), derivedUsbKey);
  WFS_ASSERT(ok && "DeriveUsbStorageKey failed");
  WFS_ASSERT(std::memcmp(derivedUsbKey, expectedCipher, 16) == 0 &&
             "DeriveUsbStorageKey result mismatch");

  std::cout << "  -> All cryptographic routines verified successfully!"
            << std::endl;
}

static void TestFormatAndMount() {
  std::cout << "[TEST] Running WFS Format, Mount, and Inode traversal..."
            << std::endl;

  // Create 64 MB virtual in-memory storage device (131072 sectors of 512 bytes)
  uint64_t totalSectors = 131072;
  WfsMemoryDevice memDev(totalSectors, 512);
  memDev.Open();

  std::vector<uint8_t> otp(1024, 0x11);
  std::vector<uint8_t> seeprom(512, 0x22);

  WfsFileSystem fs;
  bool formatted = fs.Format(&memDev, otp.data(), otp.size(), seeprom.data(),
                             seeprom.size(), 4096);
  WFS_ASSERT(formatted && "Format failed");
  WFS_ASSERT(fs.IsMounted() && "Filesystem not mounted after format");
  WFS_ASSERT(fs.GetSuperblock().generation == 1 && "Initial generation mismatch");

  // Test writing and reading back file
  std::string testPath = "/usr/title/00050000/10144f00/code/cos.xml";
  std::string xmlContent =
      "<app type=\"game\" title_id=\"0005000010144F00\" />";

  fs.BeginTransaction();
  bool writeOk = fs.WriteFile(
      testPath, reinterpret_cast<const uint8_t *>(xmlContent.data()),
      xmlContent.size());
  WFS_ASSERT(writeOk && "WriteFile failed");
  fs.CommitTransaction();

  std::vector<uint8_t> readBack;
  bool readOk = fs.ReadFile(testPath, readBack);
  WFS_ASSERT(readOk && "ReadFile failed");
  WFS_ASSERT(readBack.size() == xmlContent.size());
  WFS_ASSERT(std::memcmp(readBack.data(), xmlContent.data(), xmlContent.size()) == 0);

  // Verify filesystem consistency
  std::vector<std::string> issues;
  bool clean = fs.CheckIntegrity(issues);
  WFS_ASSERT(clean && "Filesystem integrity check failed after file write");

  std::cout << "  -> Format, Mount, File Write/Read, and Integrity passed!"
            << std::endl;
}

static void TestTitleInstallationAndUninstallation() {
  std::cout << "[TEST] Running Title Installation, Database Sync, and Safe "
               "Uninstallation..."
            << std::endl;

  uint64_t totalSectors = 131072;
  WfsMemoryDevice memDev(totalSectors, 512);
  memDev.Open();

  std::vector<uint8_t> otp(1024, 0x33);
  std::vector<uint8_t> seeprom(512, 0x44);

  WfsFileSystem fs;
  fs.Format(&memDev, otp.data(), otp.size(), seeprom.data(), seeprom.size(),
            4096);

  WfsTitleManager titleMgr(&fs);
  TitleId titleId(0x00050000, 0x10144F00); // Game Title

  // Setup simulated title files
  std::string titleRoot = titleId.GetHierarchyPath();
  std::string metaXml =
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
      "<menu>\n"
      "  <longname_en>Homebrew Test Application</longname_en>\n"
      "  <product_code>WUP-P-TEST</product_code>\n"
      "  <title_version>0</title_version>\n"
      "  <title_id>0005000010144F00</title_id>\n"
      "</menu>";

  fs.BeginTransaction();
  fs.CreateDirectoryRecursive(titleRoot + "/code");
  fs.CreateDirectoryRecursive(titleRoot + "/content");
  fs.CreateDirectoryRecursive(titleRoot + "/meta");

  fs.WriteFile(titleRoot + "/meta/meta.xml",
               reinterpret_cast<const uint8_t *>(metaXml.data()),
               metaXml.size());

  std::vector<uint8_t> dummyRpx(16384, 0x90); // 16 KB code
  fs.WriteFile(titleRoot + "/code/game.rpx", dummyRpx.data(), dummyRpx.size());

  std::vector<uint8_t> dummyData(32768, 0x55); // 32 KB content
  fs.WriteFile(titleRoot + "/content/archive.dat", dummyData.data(),
               dummyData.size());

  // Inject ticket
  WfsTicketHeader ticket;
  std::memset(&ticket, 0, sizeof(ticket));
  ticket.title_id = BigEndian64(titleId.fullId);
  titleMgr.InjectTicket(titleId, reinterpret_cast<const uint8_t *>(&ticket),
                        sizeof(ticket));

  fs.CommitTransaction();

  // 1. Verify Title Enumeration
  std::vector<InstalledTitleInfo> titles;
  titleMgr.EnumerateInstalledTitles(titles);
  WFS_ASSERT(titles.size() == 1 &&
             "Title enumeration should find exactly 1 installed title");
  WFS_ASSERT(titles[0].id.fullId == titleId.fullId);
  WFS_ASSERT(titles[0].titleName.find("Homebrew") != std::string::npos);
  WFS_ASSERT(titles[0].productCode == "WUP-P-TEST");
  WFS_ASSERT(titles[0].hasTicket == true);

  std::cout << "  -> Found installed title: " << titles[0].titleName << " ("
            << titles[0].id.ToHexString() << ")" << std::endl;

  // 2. Test Dry-Run Uninstallation
  uint32_t freeBefore = fs.GetAllocator()->GetFreeClusterCount();
  titleMgr.UninstallTitle(titleId, true, false, true); // dryRun = true
  uint32_t freeAfterDryRun = fs.GetAllocator()->GetFreeClusterCount();
  WFS_ASSERT(freeBefore == freeAfterDryRun &&
             "Dry-run uninstallation must not alter cluster allocation count!");

  // Verify title still exists after dry-run
  titles.clear();
  titleMgr.EnumerateInstalledTitles(titles);
  WFS_ASSERT(titles.size() == 1 && "Title must still exist after dry-run!");

  // 3. Real Uninstallation
  std::cout << "  -> Performing real uninstallation..." << std::endl;
  bool uninstalled = titleMgr.UninstallTitle(titleId, true, false, false);
  WFS_ASSERT(uninstalled && "Uninstallation failed");

  // Verify title is gone
  titles.clear();
  titleMgr.EnumerateInstalledTitles(titles);
  WFS_ASSERT(titles.empty() && "Title list must be empty after uninstallation");

  // Verify ticket is gone
  WFS_ASSERT(!titleMgr.HasTicket(titleId) &&
             "Ticket must be removed from /usr/packages/");

  // 4. Critical Verification: ZERO ORPHAN CLUSTERS
  std::vector<std::string> auditIssues;
  bool integrityClean = fs.CheckIntegrity(auditIssues);
  if (!integrityClean) {
    for (const auto &iss : auditIssues)
      std::cerr << "  ISSUE: " << iss << std::endl;
  }
  WFS_ASSERT(integrityClean && "Post-uninstall integrity check failed: Orphan or unallocated clusters detected!");

  uint32_t freeAfterReal = fs.GetAllocator()->GetFreeClusterCount();
  WFS_ASSERT(freeAfterReal > freeBefore &&
             "Free clusters must increase after uninstallation");

  std::cout << "  -> Title safely uninstalled. Zero orphans detected. Free "
               "clusters restored: "
            << freeAfterReal << " (was " << freeBefore << ")" << std::endl;
}

static void TestAtomicRollbackOnFailure() {
  std::cout << "[TEST] Running Atomic Transaction Rollback test..."
            << std::endl;

  uint64_t totalSectors = 131072;
  WfsMemoryDevice memDev(totalSectors, 512);
  memDev.Open();

  std::vector<uint8_t> otp(1024, 0x55);
  std::vector<uint8_t> seeprom(512, 0x66);

  WfsFileSystem fs;
  fs.Format(&memDev, otp.data(), otp.size(), seeprom.data(), seeprom.size(),
            4096);

  uint32_t initialFree = fs.GetAllocator()->GetFreeClusterCount();
  uint32_t initialGen = fs.GetSuperblock().generation;

  // Start transaction and stage writes
  fs.BeginTransaction();
  std::vector<uint8_t> bigData(65536, 0xAA);
  fs.WriteFile("/usr/title/00050000/12345678/content/large.bin", bigData.data(),
               bigData.size());

  // Abort transaction and rollback
  fs.RollbackTransaction();

  // Verify state was completely restored
  uint32_t rolledBackFree = fs.GetAllocator()->GetFreeClusterCount();
  uint32_t rolledBackGen = fs.GetSuperblock().generation;

  WFS_ASSERT(rolledBackFree == initialFree &&
             "Cluster count not restored on rollback");
  WFS_ASSERT(rolledBackGen == initialGen &&
             "Superblock generation altered on rollback");

  uint32_t cluster;
  WfsInodeDisk inode;
  bool exists = fs.ResolvePath("/usr/title/00050000/12345678/content/large.bin",
                               cluster, inode);
  WFS_ASSERT(!exists && "Rolled-back file must not exist on filesystem");

  std::cout << "  -> Atomic rollback verified successfully. Pre-transaction "
               "state 100% restored!"
            << std::endl;
}

int main() {
  std::cout << "========================================================\n"
            << "       WFS MANAGER - AUTOMATED TEST SUITE               \n"
            << "========================================================\n"
            << std::endl;

  TestCrypto();
  TestFormatAndMount();
  TestTitleInstallationAndUninstallation();
  TestAtomicRollbackOnFailure();

  std::cout << "\n>>> ALL UNIT & INTEGRITY TESTS PASSED SUCCESSFULLY! <<<\n"
            << std::endl;
  return 0;
}
