// X3DH handshake and prekey bundle definitions. Spec: core/crypto/ratchet_spec.md.
#pragma once

#include "crypto/Primitives.h"
#include "identity/IdentityTypes.h"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace crypto {

constexpr uint32_t kCapabilityPqHybrid = 1u << 0;

struct SignedPreKeyPublic {
  uint32_t id = 0;
  std::array<uint8_t, 32> public_key{};
  std::array<uint8_t, 64> signature{};
};

struct SignedPreKeyPair {
  uint32_t id = 0;
  KeyPair key_pair{};
  std::array<uint8_t, 64> signature{};
};

struct OneTimePreKeyPublic {
  uint32_t id = 0;
  std::array<uint8_t, 32> public_key{};
};

struct OneTimePreKeyPair {
  uint32_t id = 0;
  KeyPair key_pair{};
};

struct PreKeyBundle {
  uint32_t version = 1;
  std::array<uint8_t, 32> identity_ed25519{};
  std::array<uint8_t, 32> identity_x25519{};
  SignedPreKeyPublic signed_prekey{};
  bool has_one_time = false;
  OneTimePreKeyPublic one_time_prekey{};
  uint32_t capabilities = 0;
};

struct PreKeyMessage {
  uint8_t version = 1;
  uint8_t flags = 0;
  uint32_t signed_prekey_id = 0;
  uint32_t one_time_prekey_id = 0;
  uint32_t capabilities = 0;
  std::array<uint8_t, 32> initiator_identity_ed25519{};
  std::array<uint8_t, 32> initiator_identity_x25519{};
  std::array<uint8_t, 32> initiator_ephemeral{};
};

struct InitiatorKeys {
  std::array<uint8_t, 32> identity_ed25519{};
  std::array<uint8_t, 32> identity_x25519_public{};
  std::array<uint8_t, 32> identity_x25519_private{};
};

struct InitiatorResult {
  PreKeyMessage message;
  std::array<uint8_t, 32> root_key{};
  KeyPair ratchet_key;
  std::array<uint8_t, 32> remote_ratchet_pub{};
  uint32_t one_time_prekey_id = 0;
};

struct ResponderResult {
  std::array<uint8_t, 32> root_key{};
  std::array<uint8_t, 32> remote_ratchet_pub{};
  bool used_one_time = false;
  uint32_t one_time_prekey_id = 0;
};

SignedPreKeyPair createSignedPreKey(const identity::DeviceKeyPair& device_keys, uint32_t id);
OneTimePreKeyPair createOneTimePreKey(uint32_t id);
PreKeyBundle createPreKeyBundle(const identity::DeviceKeyPair& device_keys,
                                const SignedPreKeyPair& signed_prekey,
                                const std::optional<OneTimePreKeyPublic>& one_time_prekey,
                                uint32_t capabilities);

std::array<uint8_t, 64> signSignedPreKey(const std::array<uint8_t, 32>& identity_seed,
                                         uint32_t id,
                                         const std::array<uint8_t, 32>& public_key);

bool verifySignedPreKey(const PreKeyBundle& bundle);

std::vector<uint8_t> serializePreKeyMessage(const PreKeyMessage& message);
PreKeyMessage parsePreKeyMessage(const std::vector<uint8_t>& data);

InitiatorResult initiateX3DH(const InitiatorKeys& initiator,
                             const PreKeyBundle& responder_bundle,
                             const std::optional<KeyPair>& ephemeral_override,
                             const std::vector<uint8_t>& extra_shared = {});

ResponderResult respondX3DH(const PreKeyMessage& message,
                            const identity::DeviceKeyPair& responder_identity,
                            const SignedPreKeyPair& signed_prekey,
                            const std::optional<OneTimePreKeyPair>& one_time_prekey,
                            const std::vector<uint8_t>& extra_shared = {});

}
