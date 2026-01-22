// Core identity data types and key material definitions. Spec: core/identity/README.md.
#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace identity {

struct IdentityKeyPair {
  std::array<uint8_t, 32> seed{};
  std::array<uint8_t, 32> public_key{};
};

struct DeviceKeyPair {
  std::array<uint8_t, 32> device_id{};
  std::array<uint8_t, 32> ed25519_seed{};
  std::array<uint8_t, 32> ed25519_public{};
  std::array<uint8_t, 32> x25519_private{};
  std::array<uint8_t, 32> x25519_public{};
};

struct IdentityRecord {
  uint32_t version = 0;
  uint64_t created_at_ms = 0;
  uint64_t rotated_at_ms = 0;
  IdentityKeyPair active{};
  bool has_previous = false;
  IdentityKeyPair previous{};
  std::vector<DeviceKeyPair> devices;
  std::array<uint8_t, 32> active_device_id{};
};

}  // namespace identity
