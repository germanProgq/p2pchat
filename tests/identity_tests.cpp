// Identity module unit tests and deterministic vectors. Spec: core/identity/README.md.
#include "identity/IdentityStore.h"

#include <array>
#include <chrono>
#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>

namespace {

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

std::array<uint8_t, 32> fixedKey() {
  std::array<uint8_t, 32> key{};
  for (size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<uint8_t>(i + 1);
  }
  return key;
}

std::filesystem::path uniqueTempPath() {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  std::filesystem::path base = std::filesystem::temp_directory_path();
  return base / ("p2pchat_identity_test_" + std::to_string(now));
}

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

void testDeterministicVector() {
  const std::array<uint8_t, 32> seed = {
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
      0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
      0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
      0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
  const std::array<uint8_t, 32> expected = {
      0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
      0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
      0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
      0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
  auto pub = ed25519PublicFromSeed(seed);
  require(pub == expected, "Ed25519 test vector mismatch");

  std::filesystem::path dir = uniqueTempPath();
  std::filesystem::create_directories(dir);
  std::filesystem::path path = dir / "identity.store";
  auto key_store = std::make_shared<identity::InMemoryKeyStore>(fixedKey());
  identity::IdentityStore store({path.string(), key_store});

  identity::IdentityRecord record;
  record.version = 1;
  record.created_at_ms = 0;
  record.rotated_at_ms = 0;
  record.active.seed = seed;
  record.has_previous = false;
  identity::DeviceKeyPair device;
  for (size_t i = 0; i < device.ed25519_seed.size(); ++i) {
    device.ed25519_seed[i] = static_cast<uint8_t>(0x11 + i);
    device.x25519_private[i] = static_cast<uint8_t>(0x22 + i);
  }
  device.ed25519_public = ed25519PublicFromSeed(device.ed25519_seed);
  device.x25519_public = x25519PublicFromPrivate(device.x25519_private);
  device.device_id = identity::IdentityStore::userIdFromPublicKey(device.ed25519_public);
  record.devices.push_back(device);
  record.active_device_id = device.device_id;
  store.save(record);

  identity::IdentityRecord loaded = store.load();
  require(loaded.active.public_key == expected, "Loaded identity public key mismatch");
  require(loaded.devices.size() == 1, "Loaded device count mismatch");
  require(loaded.devices[0].ed25519_public == device.ed25519_public, "Loaded device ed25519 mismatch");
  require(loaded.devices[0].x25519_public == device.x25519_public, "Loaded device x25519 mismatch");
}

void testSerialization() {
  std::filesystem::path dir = uniqueTempPath();
  std::filesystem::create_directories(dir);
  std::filesystem::path path = dir / "identity.store";
  auto key_store = std::make_shared<identity::InMemoryKeyStore>(fixedKey());
  identity::IdentityStore store({path.string(), key_store});
  identity::IdentityRecord created = store.createNew();
  identity::IdentityRecord loaded = store.load();
  require(created.active.public_key == loaded.active.public_key, "Public key mismatch after reload");
  require(created.active_device_id == loaded.active_device_id, "Active device mismatch after reload");
}

void testRotation() {
  std::filesystem::path dir = uniqueTempPath();
  std::filesystem::create_directories(dir);
  std::filesystem::path path = dir / "identity.store";
  auto key_store = std::make_shared<identity::InMemoryKeyStore>(fixedKey());
  identity::IdentityStore store({path.string(), key_store});
  identity::IdentityRecord created = store.createNew();
  identity::IdentityRecord rotated = store.rotateIdentity();
  require(rotated.has_previous, "Rotation did not keep previous identity");
  require(rotated.previous.public_key == created.active.public_key, "Previous identity mismatch");
  require(rotated.active.public_key != created.active.public_key, "Active identity did not rotate");
}

}  // namespace

int main() {
  const std::vector<std::pair<std::string, std::function<void()>>> tests = {
      {"deterministic_vector", testDeterministicVector},
      {"serialization", testSerialization},
      {"rotation", testRotation},
  };

  int failures = 0;
  for (const auto& test : tests) {
    try {
      test.second();
      std::cout << "[PASS] " << test.first << std::endl;
    } catch (const std::exception& ex) {
      std::cout << "[FAIL] " << test.first << ": " << ex.what() << std::endl;
      failures++;
    }
  }

  return failures == 0 ? 0 : 1;
}
