// Identity store implementation with OS-keystore protected encryption. Spec: core/identity/README.md.
#include "identity/IdentityStore.h"

#include <array>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#if defined(__APPLE__)
#include <Security/Security.h>
#endif

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#endif

#if defined(_WIN32)
#include <Windows.h>
#include <wincrypt.h>
#endif

#if defined(__linux__)
#include <libsecret/secret.h>
#endif

namespace identity {

namespace {

constexpr uint8_t kMagic[8] = {'P', '2', 'P', 'C', 'H', 'A', 'T', '1'};
constexpr uint32_t kHeaderVersion = 1;
constexpr uint32_t kPayloadVersion = 1;
constexpr size_t kSaltSize = 16;
constexpr size_t kNonceSize = 12;
constexpr size_t kTagSize = 16;
constexpr size_t kSeedSize = 32;
constexpr size_t kKeySize = 32;
constexpr char kHkdfInfo[] = "p2pchat.identity.v1";

uint64_t nowMillis() {
  using namespace std::chrono;
  return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

void secureZero(void* data, size_t size) {
  if (data != nullptr && size > 0) {
    OPENSSL_cleanse(data, size);
  }
}

bool lockMemory(void* data, size_t size) {
#if defined(_WIN32)
  return VirtualLock(data, size) != 0;
#elif defined(__unix__) || defined(__APPLE__)
  return mlock(data, size) == 0;
#else
  (void)data;
  (void)size;
  return false;
#endif
}

void unlockMemory(void* data, size_t size) {
#if defined(_WIN32)
  VirtualUnlock(data, size);
#elif defined(__unix__) || defined(__APPLE__)
  munlock(data, size);
#else
  (void)data;
  (void)size;
#endif
}

class BinaryWriter {
 public:
  void writeU8(uint8_t value) { data_.push_back(value); }

  void writeU32(uint32_t value) {
    for (int i = 0; i < 4; ++i) {
      data_.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
  }

  void writeU64(uint64_t value) {
    for (int i = 0; i < 8; ++i) {
      data_.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
  }

  void writeBytes(const uint8_t* bytes, size_t len) {
    data_.insert(data_.end(), bytes, bytes + len);
  }

  void writeBytes(const std::array<uint8_t, 32>& bytes) {
    writeBytes(bytes.data(), bytes.size());
  }

  const std::vector<uint8_t>& data() const { return data_; }

 private:
  std::vector<uint8_t> data_;
};

class BinaryReader {
 public:
  explicit BinaryReader(const std::vector<uint8_t>& data) : data_(data), offset_(0) {}

  uint8_t readU8() {
    ensureAvailable(1);
    return data_[offset_++];
  }

  uint32_t readU32() {
    ensureAvailable(4);
    uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      value |= static_cast<uint32_t>(data_[offset_++]) << (i * 8);
    }
    return value;
  }

  uint64_t readU64() {
    ensureAvailable(8);
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
      value |= static_cast<uint64_t>(data_[offset_++]) << (i * 8);
    }
    return value;
  }

  std::array<uint8_t, 32> readBytes32() {
    ensureAvailable(32);
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), data_.data() + offset_, out.size());
    offset_ += out.size();
    return out;
  }

 private:
  void ensureAvailable(size_t count) {
    if (offset_ + count > data_.size()) {
      throw std::runtime_error("identity store parse out of bounds");
    }
  }

  const std::vector<uint8_t>& data_;
  size_t offset_;
};

class MemoryLock {
 public:
  MemoryLock(void* data, size_t size) : data_(data), size_(size), locked_(lockMemory(data, size)) {}
  ~MemoryLock() { if (locked_) { unlockMemory(data_, size_); } }

 private:
  void* data_;
  size_t size_;
  bool locked_;
};

uint32_t readU32LE(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24);
}

std::vector<uint8_t> readFile(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open identity store for reading");
  }
  input.seekg(0, std::ios::end);
  std::streamoff size = input.tellg();
  if (size < 0) {
    throw std::runtime_error("failed to read identity store size");
  }
  input.seekg(0, std::ios::beg);
  std::vector<uint8_t> data(static_cast<size_t>(size));
  if (size > 0) {
    input.read(reinterpret_cast<char*>(data.data()), size);
    if (!input) {
      throw std::runtime_error("failed to read identity store bytes");
    }
  }
  return data;
}

void writeFileAtomic(const std::string& path, const std::vector<uint8_t>& data) {
  std::filesystem::path target(path);
  std::filesystem::path tmp = target;
  tmp += ".tmp";
  {
    std::ofstream output(tmp, std::ios::binary | std::ios::trunc);
    if (!output) {
      throw std::runtime_error("failed to open identity store for writing");
    }
    if (!data.empty()) {
      output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
      if (!output) {
        throw std::runtime_error("failed to write identity store bytes");
      }
    }
    output.flush();
    if (!output) {
      throw std::runtime_error("failed to flush identity store bytes");
    }
  }
  std::filesystem::permissions(tmp,
                               std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                               std::filesystem::perm_options::replace);
  std::filesystem::rename(tmp, target);
}

std::array<uint8_t, 32> randomBytes32() {
  std::array<uint8_t, 32> out{};
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  return out;
}

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
  std::array<uint8_t, 32> out{};
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_MD_CTX_new failed");
  }
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP_DigestInit_ex failed");
  }
  if (EVP_DigestUpdate(ctx, data, len) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP_DigestUpdate failed");
  }
  unsigned int out_len = 0;
  if (EVP_DigestFinal_ex(ctx, out.data(), &out_len) != 1 || out_len != out.size()) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP_DigestFinal_ex failed");
  }
  EVP_MD_CTX_free(ctx);
  return out;
}

std::array<uint8_t, 32> ed25519PublicFromSeed(const std::array<uint8_t, 32>& seed) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
  if (!pkey) {
    throw std::runtime_error("EVP_PKEY_new_raw_private_key failed for Ed25519");
  }
  std::array<uint8_t, 32> pub{};
  size_t len = pub.size();
  if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) != 1 || len != pub.size()) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_PKEY_get_raw_public_key failed for Ed25519");
  }
  EVP_PKEY_free(pkey);
  return pub;
}

std::array<uint8_t, 32> x25519PublicFromPrivate(const std::array<uint8_t, 32>& priv) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
  if (!pkey) {
    throw std::runtime_error("EVP_PKEY_new_raw_private_key failed for X25519");
  }
  std::array<uint8_t, 32> pub{};
  size_t len = pub.size();
  if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) != 1 || len != pub.size()) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_PKEY_get_raw_public_key failed for X25519");
  }
  EVP_PKEY_free(pkey);
  return pub;
}

IdentityKeyPair generateIdentityKey() {
  IdentityKeyPair key;
  key.seed = randomBytes32();
  key.public_key = ed25519PublicFromSeed(key.seed);
  return key;
}

DeviceKeyPair generateDeviceKey() {
  DeviceKeyPair key;
  key.ed25519_seed = randomBytes32();
  key.ed25519_public = ed25519PublicFromSeed(key.ed25519_seed);
  key.x25519_private = randomBytes32();
  key.x25519_public = x25519PublicFromPrivate(key.x25519_private);
  key.device_id = sha256(key.ed25519_public.data(), key.ed25519_public.size());
  return key;
}

std::array<uint8_t, 32> hkdfSha256(const std::array<uint8_t, 32>& key,
                                  const uint8_t* salt,
                                  size_t salt_len,
                                  size_t out_len,
                                  const std::string& info) {
  if (out_len != 32) {
    throw std::runtime_error("HKDF output length unsupported");
  }
  std::array<uint8_t, 32> out{};
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!ctx) {
    throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
  }
  if (EVP_PKEY_derive_init(ctx) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_derive_init failed");
  }
  if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed");
  }
  if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, static_cast<int>(salt_len)) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_salt failed");
  }
  if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key.data(), static_cast<int>(key.size())) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed");
  }
  if (!info.empty()) {
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
                                   reinterpret_cast<const unsigned char*>(info.data()),
                                   static_cast<int>(info.size())) != 1) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("EVP_PKEY_CTX_add1_hkdf_info failed");
    }
  }
  size_t len = out.size();
  if (EVP_PKEY_derive(ctx, out.data(), &len) != 1 || len != out.size()) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_derive failed");
  }
  EVP_PKEY_CTX_free(ctx);
  return out;
}

std::vector<uint8_t> aesGcmEncrypt(const std::array<uint8_t, 32>& key,
                                  const std::array<uint8_t, kNonceSize>& nonce,
                                  const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& aad,
                                  std::array<uint8_t, kTagSize>& tag_out) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex failed");
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
  }
  if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex key failed");
  }
  int out_len = 0;
  if (!aad.empty()) {
    if (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("EVP_EncryptUpdate aad failed");
    }
  }
  std::vector<uint8_t> ciphertext(plaintext.size());
  if (!plaintext.empty()) {
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("EVP_EncryptUpdate failed");
    }
  } else {
    out_len = 0;
  }
  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptFinal_ex failed");
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_out.size()), tag_out.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
  }
  EVP_CIPHER_CTX_free(ctx);
  ciphertext.resize(static_cast<size_t>(out_len + final_len));
  return ciphertext;
}

std::vector<uint8_t> aesGcmDecrypt(const std::array<uint8_t, 32>& key,
                                  const std::array<uint8_t, kNonceSize>& nonce,
                                  const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& aad,
                                  const std::array<uint8_t, kTagSize>& tag) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
  }
  if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex key failed");
  }
  int out_len = 0;
  if (!aad.empty()) {
    if (EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("EVP_DecryptUpdate aad failed");
    }
  }
  std::vector<uint8_t> plaintext(ciphertext.size());
  if (!ciphertext.empty()) {
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                          ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("EVP_DecryptUpdate failed");
    }
  } else {
    out_len = 0;
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                          const_cast<uint8_t*>(tag.data())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
  }
  int final_len = 0;
  int final_ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);
  EVP_CIPHER_CTX_free(ctx);
  if (final_ok != 1) {
    throw std::runtime_error("identity store authentication failed");
  }
  plaintext.resize(static_cast<size_t>(out_len + final_len));
  return plaintext;
}

std::vector<uint8_t> buildHeader(const std::array<uint8_t, kSaltSize>& salt,
                                 const std::array<uint8_t, kNonceSize>& nonce,
                                 uint32_t ciphertext_len) {
  BinaryWriter writer;
  writer.writeBytes(kMagic, sizeof(kMagic));
  writer.writeU32(kHeaderVersion);
  writer.writeBytes(salt.data(), salt.size());
  writer.writeBytes(nonce.data(), nonce.size());
  writer.writeU32(ciphertext_len);
  return writer.data();
}

IdentityRecord parsePayload(const std::vector<uint8_t>& payload) {
  BinaryReader reader(payload);
  uint32_t payload_version = reader.readU32();
  if (payload_version != kPayloadVersion) {
    throw std::runtime_error("identity payload version mismatch");
  }
  IdentityRecord record;
  record.version = reader.readU32();
  record.created_at_ms = reader.readU64();
  record.rotated_at_ms = reader.readU64();
  record.active.seed = reader.readBytes32();
  record.active.public_key = ed25519PublicFromSeed(record.active.seed);
  record.has_previous = reader.readU8() != 0;
  if (record.has_previous) {
    record.previous.seed = reader.readBytes32();
    record.previous.public_key = ed25519PublicFromSeed(record.previous.seed);
  }
  uint32_t device_count = reader.readU32();
  if (device_count == 0 || device_count > 1024) {
    throw std::runtime_error("invalid device count in identity store");
  }
  record.active_device_id = reader.readBytes32();
  record.devices.reserve(device_count);
  for (uint32_t i = 0; i < device_count; ++i) {
    DeviceKeyPair device;
    device.device_id = reader.readBytes32();
    device.ed25519_seed = reader.readBytes32();
    device.x25519_private = reader.readBytes32();
    device.ed25519_public = ed25519PublicFromSeed(device.ed25519_seed);
    device.x25519_public = x25519PublicFromPrivate(device.x25519_private);
    record.devices.push_back(device);
  }
  bool active_found = false;
  for (const auto& device : record.devices) {
    if (device.device_id == record.active_device_id) {
      active_found = true;
      break;
    }
  }
  if (!active_found) {
    throw std::runtime_error("active device id not found in identity store");
  }
  return record;
}

std::vector<uint8_t> serializePayload(const IdentityRecord& record) {
  BinaryWriter writer;
  writer.writeU32(kPayloadVersion);
  writer.writeU32(record.version);
  writer.writeU64(record.created_at_ms);
  writer.writeU64(record.rotated_at_ms);
  writer.writeBytes(record.active.seed);
  writer.writeU8(record.has_previous ? 1 : 0);
  if (record.has_previous) {
    writer.writeBytes(record.previous.seed);
  }
  if (record.devices.empty()) {
    throw std::runtime_error("cannot serialize identity without devices");
  }
  writer.writeU32(static_cast<uint32_t>(record.devices.size()));
  writer.writeBytes(record.active_device_id);
  for (const auto& device : record.devices) {
    writer.writeBytes(device.device_id);
    writer.writeBytes(device.ed25519_seed);
    writer.writeBytes(device.x25519_private);
  }
  return writer.data();
}

std::string defaultKeychainAccount() {
  return "identity-master-key";
}

#if defined(__APPLE__)
std::array<uint8_t, 32> loadOrCreateKeychainKey(const std::string& service_name) {
  std::array<uint8_t, 32> key{};
  CFStringRef service = CFStringCreateWithCString(kCFAllocatorDefault, service_name.c_str(), kCFStringEncodingUTF8);
  CFStringRef account = CFStringCreateWithCString(kCFAllocatorDefault, defaultKeychainAccount().c_str(), kCFStringEncodingUTF8);
  const void* query_keys[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit};
  const void* query_vals[] = {kSecClassGenericPassword, service, account, kCFBooleanTrue, kSecMatchLimitOne};
  CFDictionaryRef query = CFDictionaryCreate(nullptr, query_keys, query_vals, 5,
                                             &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFTypeRef result = nullptr;
  OSStatus status = SecItemCopyMatching(query, &result);
  CFRelease(query);
  if (status == errSecSuccess && result != nullptr) {
    CFDataRef data = static_cast<CFDataRef>(result);
    if (CFDataGetLength(data) != static_cast<CFIndex>(key.size())) {
      CFRelease(data);
      CFRelease(service);
      CFRelease(account);
      throw std::runtime_error("keychain master key length mismatch");
    }
    std::memcpy(key.data(), CFDataGetBytePtr(data), key.size());
    CFRelease(data);
    CFRelease(service);
    CFRelease(account);
    return key;
  }
  if (status != errSecItemNotFound) {
    CFRelease(service);
    CFRelease(account);
    throw std::runtime_error("keychain lookup failed");
  }
  key = randomBytes32();
  CFDataRef data = CFDataCreate(nullptr, key.data(), static_cast<CFIndex>(key.size()));
  const void* add_keys[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData, kSecAttrAccessible};
  const void* add_vals[] = {kSecClassGenericPassword, service, account, data,
                            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly};
  CFDictionaryRef add_query = CFDictionaryCreate(nullptr, add_keys, add_vals, 5,
                                                 &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  status = SecItemAdd(add_query, nullptr);
  CFRelease(add_query);
  CFRelease(data);
  CFRelease(service);
  CFRelease(account);
  if (status != errSecSuccess) {
    throw std::runtime_error("keychain add failed");
  }
  return key;
}
#endif

#if defined(_WIN32)
std::filesystem::path windowsKeyPath(const std::string& service_name) {
  const char* appdata = std::getenv("APPDATA");
  std::filesystem::path base = appdata ? appdata : ".";
  std::filesystem::path dir = base / "p2pchat";
  std::filesystem::create_directories(dir);
  std::string filename = "master_" + service_name + ".bin";
  return dir / filename;
}

std::array<uint8_t, 32> loadOrCreateDpapiKey(const std::string& service_name) {
  std::array<uint8_t, 32> key{};
  std::filesystem::path path = windowsKeyPath(service_name);
  if (std::filesystem::exists(path)) {
    std::vector<uint8_t> blob = readFile(path.string());
    if (blob.empty()) {
      throw std::runtime_error("dpapi blob empty");
    }
    DATA_BLOB in_blob{};
    in_blob.pbData = blob.data();
    in_blob.cbData = static_cast<DWORD>(blob.size());
    DATA_BLOB out_blob{};
    if (!CryptUnprotectData(&in_blob, nullptr, nullptr, nullptr, nullptr, 0, &out_blob)) {
      throw std::runtime_error("CryptUnprotectData failed");
    }
    if (out_blob.cbData != key.size()) {
      LocalFree(out_blob.pbData);
      throw std::runtime_error("dpapi key length mismatch");
    }
    std::memcpy(key.data(), out_blob.pbData, key.size());
    LocalFree(out_blob.pbData);
    return key;
  }
  key = randomBytes32();
  DATA_BLOB in_blob{};
  in_blob.pbData = key.data();
  in_blob.cbData = static_cast<DWORD>(key.size());
  DATA_BLOB out_blob{};
  if (!CryptProtectData(&in_blob, nullptr, nullptr, nullptr, nullptr, 0, &out_blob)) {
    throw std::runtime_error("CryptProtectData failed");
  }
  std::vector<uint8_t> blob(out_blob.pbData, out_blob.pbData + out_blob.cbData);
  LocalFree(out_blob.pbData);
  writeFileAtomic(path.string(), blob);
  return key;
}
#endif

#if defined(__linux__)
const SecretSchema* linuxSchema() {
  static const SecretSchema schema = {
      "com.p2pchat.identity",
      SECRET_SCHEMA_NONE,
      {{"service", SECRET_SCHEMA_ATTRIBUTE_STRING}, {nullptr, 0}},
  };
  return &schema;
}

std::array<uint8_t, 32> loadOrCreateSecretKey(const std::string& service_name) {
  std::array<uint8_t, 32> key{};
  GError* error = nullptr;
  gchar* stored = secret_password_lookup_sync(linuxSchema(), nullptr, &error,
                                              "service", service_name.c_str(), nullptr);
  if (error != nullptr) {
    g_error_free(error);
    throw std::runtime_error("libsecret lookup failed");
  }
  if (stored != nullptr) {
    std::string stored_str(stored);
    secret_password_free(stored);
    std::vector<uint8_t> decoded((stored_str.size() * 3) / 4 + 4);
    int out_len = EVP_DecodeBlock(decoded.data(),
                                  reinterpret_cast<const unsigned char*>(stored_str.data()),
                                  static_cast<int>(stored_str.size()));
    if (out_len < 0) {
      throw std::runtime_error("libsecret base64 decode failed");
    }
    size_t padding = 0;
    if (!stored_str.empty() && stored_str.back() == '=') {
      padding++;
      if (stored_str.size() > 1 && stored_str[stored_str.size() - 2] == '=') {
        padding++;
      }
    }
    size_t actual_len = static_cast<size_t>(out_len) - padding;
    decoded.resize(actual_len);
    if (decoded.size() != key.size()) {
      throw std::runtime_error("libsecret key length mismatch");
    }
    std::memcpy(key.data(), decoded.data(), key.size());
    return key;
  }
  key = randomBytes32();
  std::array<uint8_t, 64> encoded{};
  int encoded_len = EVP_EncodeBlock(encoded.data(), key.data(), static_cast<int>(key.size()));
  std::string encoded_str(reinterpret_cast<char*>(encoded.data()), static_cast<size_t>(encoded_len));
  gboolean ok = secret_password_store_sync(linuxSchema(), SECRET_COLLECTION_DEFAULT,
                                           "p2pchat identity master key", encoded_str.c_str(), nullptr, &error,
                                           "service", service_name.c_str(), nullptr);
  if (error != nullptr) {
    g_error_free(error);
    throw std::runtime_error("libsecret store failed");
  }
  if (!ok) {
    throw std::runtime_error("libsecret store returned false");
  }
  return key;
}
#endif

std::array<uint8_t, 32> loadOrCreateMasterKey(const std::string& service_name) {
#if defined(__APPLE__)
  return loadOrCreateKeychainKey(service_name);
#elif defined(_WIN32)
  return loadOrCreateDpapiKey(service_name);
#elif defined(__linux__)
  return loadOrCreateSecretKey(service_name);
#else
  throw std::runtime_error("unsupported platform for master key storage");
#endif
}

}  // namespace

OsKeyStore::OsKeyStore(std::string service_name) : service_name_(std::move(service_name)) {}

std::array<uint8_t, 32> OsKeyStore::loadOrCreate() {
  return loadOrCreateMasterKey(service_name_);
}

InMemoryKeyStore::InMemoryKeyStore(std::array<uint8_t, 32> key) : key_(key) {}

std::array<uint8_t, 32> InMemoryKeyStore::loadOrCreate() {
  return key_;
}

IdentityStore::IdentityStore(Options options) : options_(std::move(options)) {
  if (!options_.master_key) {
    throw std::runtime_error("master key provider is required");
  }
  if (options_.path.empty()) {
    throw std::runtime_error("identity store path is required");
  }
}

bool IdentityStore::exists() const {
  return std::filesystem::exists(options_.path);
}

IdentityRecord IdentityStore::createNew() {
  if (exists()) {
    throw std::runtime_error("identity store already exists");
  }
  IdentityRecord record;
  record.version = 1;
  record.created_at_ms = nowMillis();
  record.rotated_at_ms = 0;
  record.active = generateIdentityKey();
  record.has_previous = false;
  record.devices.clear();
  record.devices.push_back(generateDeviceKey());
  record.active_device_id = record.devices.front().device_id;
  save(record);
  return record;
}

IdentityRecord IdentityStore::load() const {
  std::vector<uint8_t> file_bytes = readFile(options_.path);
  if (file_bytes.size() < sizeof(kMagic) + 4 + kSaltSize + kNonceSize + 4 + kTagSize) {
    throw std::runtime_error("identity store file too small");
  }
  size_t offset = 0;
  if (std::memcmp(file_bytes.data(), kMagic, sizeof(kMagic)) != 0) {
    throw std::runtime_error("identity store magic mismatch");
  }
  offset += sizeof(kMagic);
  if (offset + 4 > file_bytes.size()) {
    throw std::runtime_error("identity store header truncated");
  }
  uint32_t header_version = readU32LE(file_bytes.data() + offset);
  offset += 4;
  if (header_version != kHeaderVersion) {
    throw std::runtime_error("identity store header version mismatch");
  }
  if (offset + kSaltSize + kNonceSize + 4 > file_bytes.size()) {
    throw std::runtime_error("identity store header truncated");
  }
  std::array<uint8_t, kSaltSize> salt{};
  std::memcpy(salt.data(), file_bytes.data() + offset, salt.size());
  offset += salt.size();
  std::array<uint8_t, kNonceSize> nonce{};
  std::memcpy(nonce.data(), file_bytes.data() + offset, nonce.size());
  offset += nonce.size();
  uint32_t ciphertext_len = readU32LE(file_bytes.data() + offset);
  offset += 4;
  size_t expected_size = offset + ciphertext_len + kTagSize;
  if (expected_size != file_bytes.size()) {
    throw std::runtime_error("identity store size mismatch");
  }
  std::vector<uint8_t> header = buildHeader(salt, nonce, ciphertext_len);
  std::array<uint8_t, 32> master_key = options_.master_key->loadOrCreate();
  MemoryLock master_lock(master_key.data(), master_key.size());
  std::array<uint8_t, 32> file_key = hkdfSha256(master_key, salt.data(), salt.size(), 32, kHkdfInfo);
  MemoryLock file_lock(file_key.data(), file_key.size());
  std::vector<uint8_t> ciphertext(file_bytes.begin() + static_cast<long>(offset),
                                  file_bytes.begin() + static_cast<long>(offset + ciphertext_len));
  std::array<uint8_t, kTagSize> tag{};
  std::memcpy(tag.data(), file_bytes.data() + offset + ciphertext_len, tag.size());
  std::vector<uint8_t> plaintext = aesGcmDecrypt(file_key, nonce, ciphertext, header, tag);
  IdentityRecord record = parsePayload(plaintext);
  secureZero(plaintext.data(), plaintext.size());
  secureZero(file_key.data(), file_key.size());
  secureZero(master_key.data(), master_key.size());
  return record;
}

IdentityRecord IdentityStore::rotateIdentity() {
  IdentityRecord record = load();
  record.previous = record.active;
  record.has_previous = true;
  record.active = generateIdentityKey();
  record.rotated_at_ms = nowMillis();
  if (record.version == std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("identity version overflow");
  }
  record.version += 1;
  save(record);
  return record;
}

void IdentityStore::save(const IdentityRecord& record) const {
  std::vector<uint8_t> payload = serializePayload(record);
  std::array<uint8_t, kSaltSize> salt{};
  std::array<uint8_t, kNonceSize> nonce{};
  if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed for salt");
  }
  if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed for nonce");
  }
  std::array<uint8_t, 32> master_key = options_.master_key->loadOrCreate();
  MemoryLock master_lock(master_key.data(), master_key.size());
  std::array<uint8_t, 32> file_key = hkdfSha256(master_key, salt.data(), salt.size(), 32, kHkdfInfo);
  MemoryLock file_lock(file_key.data(), file_key.size());
  std::vector<uint8_t> header = buildHeader(salt, nonce, static_cast<uint32_t>(payload.size()));
  std::array<uint8_t, kTagSize> tag{};
  std::vector<uint8_t> ciphertext = aesGcmEncrypt(file_key, nonce, payload, header, tag);
  BinaryWriter writer;
  writer.writeBytes(kMagic, sizeof(kMagic));
  writer.writeU32(kHeaderVersion);
  writer.writeBytes(salt.data(), salt.size());
  writer.writeBytes(nonce.data(), nonce.size());
  writer.writeU32(static_cast<uint32_t>(ciphertext.size()));
  writer.writeBytes(ciphertext.data(), ciphertext.size());
  writer.writeBytes(tag.data(), tag.size());
  writeFileAtomic(options_.path, writer.data());
  secureZero(payload.data(), payload.size());
  secureZero(ciphertext.data(), ciphertext.size());
  secureZero(file_key.data(), file_key.size());
  secureZero(master_key.data(), master_key.size());
}

std::array<uint8_t, 32> IdentityStore::userIdFromPublicKey(const std::array<uint8_t, 32>& public_key) {
  return sha256(public_key.data(), public_key.size());
}

std::string IdentityStore::toHex(const std::array<uint8_t, 32>& bytes) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

}  // namespace identity
