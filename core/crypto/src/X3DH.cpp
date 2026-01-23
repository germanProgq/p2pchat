// X3DH handshake and prekey logic. Spec: core/crypto/ratchet_spec.md.
#include "crypto/X3DH.h"

#include <cstring>
#include <stdexcept>

namespace crypto {

namespace {

constexpr uint8_t kFlagHasOneTime = 0x01;
const std::vector<uint8_t> kSignedPreKeyContext = {'p','2','p','c','h','a','t','.','s','p','k','.','v','1'};
const std::vector<uint8_t> kX3dhInfo = {'p','2','p','c','h','a','t','.','x','3','d','h','.','r','o','o','t','.','v','1'};

void writeU32LE(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

uint32_t readU32LE(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24);
}

std::array<uint8_t, 32> deriveRootKey(const std::vector<uint8_t>& concat) {
  std::vector<uint8_t> salt(32, 0);
  std::vector<uint8_t> okm = hkdfSha256(concat, salt, kX3dhInfo, 32);
  if (okm.size() != 32) {
    throw std::runtime_error("X3DH root key length mismatch");
  }
  std::array<uint8_t, 32> out{};
  std::memcpy(out.data(), okm.data(), out.size());
  secureZero(okm.data(), okm.size());
  return out;
}

std::vector<uint8_t> signedPreKeyMessage(uint32_t id, const std::array<uint8_t, 32>& public_key) {
  std::vector<uint8_t> msg;
  msg.reserve(kSignedPreKeyContext.size() + 4 + public_key.size());
  msg.insert(msg.end(), kSignedPreKeyContext.begin(), kSignedPreKeyContext.end());
  writeU32LE(msg, id);
  msg.insert(msg.end(), public_key.begin(), public_key.end());
  return msg;
}

void ensurePqSupported(uint32_t capabilities, const std::vector<uint8_t>& extra_shared) {
  bool pq_flag = (capabilities & kCapabilityPqHybrid) != 0;
  if (pq_flag && extra_shared.empty()) {
    throw std::runtime_error("PQ capability requires extra shared secret");
  }
  if (!pq_flag && !extra_shared.empty()) {
    throw std::runtime_error("extra shared secret provided without PQ capability");
  }
}

}

SignedPreKeyPair createSignedPreKey(const identity::IdentityKeyPair& identity_keys, uint32_t id) {
  SignedPreKeyPair signed_prekey;
  signed_prekey.id = id;
  signed_prekey.key_pair = generateX25519KeyPair();
  signed_prekey.signature = signSignedPreKey(identity_keys.seed, id, signed_prekey.key_pair.public_key);
  return signed_prekey;
}

OneTimePreKeyPair createOneTimePreKey(uint32_t id) {
  OneTimePreKeyPair prekey;
  prekey.id = id;
  prekey.key_pair = generateX25519KeyPair();
  return prekey;
}

std::array<uint8_t, 64> signSignedPreKey(const std::array<uint8_t, 32>& identity_seed,
                                         uint32_t id,
                                         const std::array<uint8_t, 32>& public_key) {
  std::vector<uint8_t> message = signedPreKeyMessage(id, public_key);
  return ed25519Sign(identity_seed, message.data(), message.size());
}

PreKeyBundle createPreKeyBundle(const identity::IdentityKeyPair& identity_keys,
                                const identity::DeviceKeyPair& device_keys,
                                const SignedPreKeyPair& signed_prekey,
                                const std::optional<OneTimePreKeyPublic>& one_time_prekey,
                                uint32_t capabilities) {
  PreKeyBundle bundle;
  bundle.version = 2;
  bundle.identity_ed25519 = identity_keys.public_key;
  bundle.device_ed25519 = device_keys.ed25519_public;
  bundle.identity_x25519 = device_keys.x25519_public;
  bundle.signed_prekey.id = signed_prekey.id;
  bundle.signed_prekey.public_key = signed_prekey.key_pair.public_key;
  bundle.signed_prekey.signature = signed_prekey.signature;
  bundle.capabilities = capabilities;
  if (one_time_prekey.has_value()) {
    bundle.has_one_time = true;
    bundle.one_time_prekey = *one_time_prekey;
  } else {
    bundle.has_one_time = false;
  }
  return bundle;
}

std::vector<uint8_t> serializePreKeyBundle(const PreKeyBundle& bundle) {
  std::vector<uint8_t> out;
  out.reserve(bundle.has_one_time ? 238 : 202);
  out.push_back(static_cast<uint8_t>(bundle.version));
  out.push_back(static_cast<uint8_t>(bundle.has_one_time ? 1 : 0));
  writeU32LE(out, bundle.capabilities);
  out.insert(out.end(), bundle.identity_ed25519.begin(), bundle.identity_ed25519.end());
  if (bundle.version >= 2) {
    out.insert(out.end(), bundle.device_ed25519.begin(), bundle.device_ed25519.end());
  }
  out.insert(out.end(), bundle.identity_x25519.begin(), bundle.identity_x25519.end());
  writeU32LE(out, bundle.signed_prekey.id);
  out.insert(out.end(), bundle.signed_prekey.public_key.begin(), bundle.signed_prekey.public_key.end());
  out.insert(out.end(), bundle.signed_prekey.signature.begin(), bundle.signed_prekey.signature.end());
  if (bundle.has_one_time) {
    writeU32LE(out, bundle.one_time_prekey.id);
    out.insert(out.end(), bundle.one_time_prekey.public_key.begin(), bundle.one_time_prekey.public_key.end());
  }
  return out;
}

PreKeyBundle parsePreKeyBundle(const std::vector<uint8_t>& data) {
  size_t offset = 0;
  if (data.size() < 1 + 1 + 4 + 32 + 32 + 4 + 32 + 64) {
    throw std::runtime_error("prekey bundle truncated");
  }
  PreKeyBundle bundle;
  bundle.version = data[offset++];
  bundle.has_one_time = data[offset++] != 0;
  bundle.capabilities = readU32LE(data.data() + offset);
  offset += 4;
  std::memcpy(bundle.identity_ed25519.data(), data.data() + offset, 32);
  offset += 32;
  if (bundle.version >= 2) {
    if (offset + 32 > data.size()) {
      throw std::runtime_error("prekey bundle device key truncated");
    }
    std::memcpy(bundle.device_ed25519.data(), data.data() + offset, 32);
    offset += 32;
  } else {
    bundle.device_ed25519 = bundle.identity_ed25519;
  }
  if (offset + 32 + 4 + 32 + 64 > data.size()) {
    throw std::runtime_error("prekey bundle truncated");
  }
  std::memcpy(bundle.identity_x25519.data(), data.data() + offset, 32);
  offset += 32;
  bundle.signed_prekey.id = readU32LE(data.data() + offset);
  offset += 4;
  std::memcpy(bundle.signed_prekey.public_key.data(), data.data() + offset, 32);
  offset += 32;
  std::memcpy(bundle.signed_prekey.signature.data(), data.data() + offset, 64);
  offset += 64;
  if (bundle.has_one_time) {
    if (offset + 4 + 32 > data.size()) {
      throw std::runtime_error("prekey bundle one-time truncated");
    }
    bundle.one_time_prekey.id = readU32LE(data.data() + offset);
    offset += 4;
    std::memcpy(bundle.one_time_prekey.public_key.data(), data.data() + offset, 32);
  }
  return bundle;
}

bool verifySignedPreKey(const PreKeyBundle& bundle) {
  std::vector<uint8_t> message = signedPreKeyMessage(bundle.signed_prekey.id,
                                                     bundle.signed_prekey.public_key);
  return ed25519Verify(bundle.identity_ed25519, message.data(), message.size(),
                       bundle.signed_prekey.signature);
}

std::vector<uint8_t> serializePreKeyMessage(const PreKeyMessage& message) {
  std::vector<uint8_t> out;
  out.reserve(142);
  out.push_back(message.version);
  out.push_back(message.flags);
  writeU32LE(out, message.signed_prekey_id);
  writeU32LE(out, message.one_time_prekey_id);
  writeU32LE(out, message.capabilities);
  out.insert(out.end(), message.initiator_identity_ed25519.begin(), message.initiator_identity_ed25519.end());
  if (message.version >= 2) {
    out.insert(out.end(), message.initiator_device_ed25519.begin(), message.initiator_device_ed25519.end());
  }
  out.insert(out.end(), message.initiator_identity_x25519.begin(), message.initiator_identity_x25519.end());
  out.insert(out.end(), message.initiator_ephemeral.begin(), message.initiator_ephemeral.end());
  return out;
}

PreKeyMessage parsePreKeyMessage(const std::vector<uint8_t>& data) {
  PreKeyMessage message;
  size_t offset = 0;
  if (data.size() < 1 + 1 + 4 + 4 + 4 + 32 + 32 + 32) {
    throw std::runtime_error("prekey message truncated");
  }
  message.version = data[offset++];
  if (message.version != 1 && message.version != 2) {
    throw std::runtime_error("unsupported prekey message version");
  }
  size_t expected = message.version == 1 ? 110 : 142;
  if (data.size() != expected) {
    throw std::runtime_error("prekey message length mismatch");
  }
  message.flags = data[offset++];
  message.signed_prekey_id = readU32LE(data.data() + offset);
  offset += 4;
  message.one_time_prekey_id = readU32LE(data.data() + offset);
  offset += 4;
  message.capabilities = readU32LE(data.data() + offset);
  offset += 4;
  std::memcpy(message.initiator_identity_ed25519.data(), data.data() + offset, 32);
  offset += 32;
  if (message.version >= 2) {
    std::memcpy(message.initiator_device_ed25519.data(), data.data() + offset, 32);
    offset += 32;
  } else {
    message.initiator_device_ed25519 = message.initiator_identity_ed25519;
  }
  std::memcpy(message.initiator_identity_x25519.data(), data.data() + offset, 32);
  offset += 32;
  std::memcpy(message.initiator_ephemeral.data(), data.data() + offset, 32);
  return message;
}

InitiatorResult initiateX3DH(const InitiatorKeys& initiator,
                             const PreKeyBundle& responder_bundle,
                             const std::optional<KeyPair>& ephemeral_override,
                             const std::vector<uint8_t>& extra_shared) {
  if (responder_bundle.version != 1 && responder_bundle.version != 2) {
    throw std::runtime_error("unsupported prekey bundle version");
  }
  if (!verifySignedPreKey(responder_bundle)) {
    throw std::runtime_error("signed prekey signature invalid");
  }
  if (responder_bundle.capabilities & kCapabilityPqHybrid) {
    ensurePqSupported(kCapabilityPqHybrid, extra_shared);
  }
  if (!extra_shared.empty() && (responder_bundle.capabilities & kCapabilityPqHybrid) == 0) {
    throw std::runtime_error("responder does not advertise PQ capability");
  }

  KeyPair ephemeral = ephemeral_override.has_value() ? *ephemeral_override : generateX25519KeyPair();

  std::array<uint8_t, 32> dh1 = x25519SharedSecret(initiator.identity_x25519_private,
                                                   responder_bundle.signed_prekey.public_key);
  std::array<uint8_t, 32> dh2 = x25519SharedSecret(ephemeral.private_key,
                                                   responder_bundle.identity_x25519);
  std::array<uint8_t, 32> dh3 = x25519SharedSecret(ephemeral.private_key,
                                                   responder_bundle.signed_prekey.public_key);
  std::array<uint8_t, 32> dh4{};
  bool has_dh4 = false;

  std::vector<uint8_t> concat;
  concat.insert(concat.end(), dh1.begin(), dh1.end());
  concat.insert(concat.end(), dh2.begin(), dh2.end());
  concat.insert(concat.end(), dh3.begin(), dh3.end());

  if (responder_bundle.has_one_time) {
    dh4 = x25519SharedSecret(ephemeral.private_key,
                             responder_bundle.one_time_prekey.public_key);
    concat.insert(concat.end(), dh4.begin(), dh4.end());
    has_dh4 = true;
  }
  concat.insert(concat.end(), extra_shared.begin(), extra_shared.end());

  InitiatorResult result;
  result.root_key = deriveRootKey(concat);
  result.ratchet_key = ephemeral;
  result.remote_ratchet_pub = responder_bundle.signed_prekey.public_key;
  result.one_time_prekey_id = responder_bundle.has_one_time ? responder_bundle.one_time_prekey.id : 0;

  result.message.version = 2;
  result.message.flags = responder_bundle.has_one_time ? kFlagHasOneTime : 0;
  result.message.signed_prekey_id = responder_bundle.signed_prekey.id;
  result.message.one_time_prekey_id = responder_bundle.has_one_time ? responder_bundle.one_time_prekey.id : 0;
  result.message.capabilities = (!extra_shared.empty() ? kCapabilityPqHybrid : 0);
  result.message.initiator_identity_ed25519 = initiator.identity_ed25519;
  result.message.initiator_device_ed25519 = initiator.device_ed25519;
  result.message.initiator_identity_x25519 = initiator.identity_x25519_public;
  result.message.initiator_ephemeral = ephemeral.public_key;

  secureZero(concat.data(), concat.size());
  secureZero(dh1.data(), dh1.size());
  secureZero(dh2.data(), dh2.size());
  secureZero(dh3.data(), dh3.size());
  if (has_dh4) {
    secureZero(dh4.data(), dh4.size());
  }
  secureZero(ephemeral.private_key.data(), ephemeral.private_key.size());
  return result;
}

ResponderResult respondX3DH(const PreKeyMessage& message,
                            const identity::DeviceKeyPair& responder_identity,
                            const SignedPreKeyPair& signed_prekey,
                            const std::optional<OneTimePreKeyPair>& one_time_prekey,
                            const std::vector<uint8_t>& extra_shared) {
  if (message.version != 1 && message.version != 2) {
    throw std::runtime_error("unsupported prekey message version");
  }
  if (message.signed_prekey_id != signed_prekey.id) {
    throw std::runtime_error("signed prekey id mismatch");
  }
  bool has_one_time = (message.flags & kFlagHasOneTime) != 0;
  if (has_one_time) {
    if (!one_time_prekey.has_value()) {
      throw std::runtime_error("one-time prekey missing");
    }
    if (message.one_time_prekey_id != one_time_prekey->id) {
      throw std::runtime_error("one-time prekey id mismatch");
    }
  }
  ensurePqSupported(message.capabilities, extra_shared);

  std::array<uint8_t, 32> dh1 = x25519SharedSecret(signed_prekey.key_pair.private_key,
                                                   message.initiator_identity_x25519);
  std::array<uint8_t, 32> dh2 = x25519SharedSecret(responder_identity.x25519_private,
                                                   message.initiator_ephemeral);
  std::array<uint8_t, 32> dh3 = x25519SharedSecret(signed_prekey.key_pair.private_key,
                                                   message.initiator_ephemeral);
  std::array<uint8_t, 32> dh4{};
  bool has_dh4 = false;

  std::vector<uint8_t> concat;
  concat.insert(concat.end(), dh1.begin(), dh1.end());
  concat.insert(concat.end(), dh2.begin(), dh2.end());
  concat.insert(concat.end(), dh3.begin(), dh3.end());

  if (has_one_time) {
    dh4 = x25519SharedSecret(one_time_prekey->key_pair.private_key,
                             message.initiator_ephemeral);
    concat.insert(concat.end(), dh4.begin(), dh4.end());
    has_dh4 = true;
  }
  concat.insert(concat.end(), extra_shared.begin(), extra_shared.end());

  ResponderResult result;
  result.root_key = deriveRootKey(concat);
  result.remote_ratchet_pub = message.initiator_ephemeral;
  result.used_one_time = has_one_time;
  result.one_time_prekey_id = has_one_time ? message.one_time_prekey_id : 0;
  secureZero(concat.data(), concat.size());
  secureZero(dh1.data(), dh1.size());
  secureZero(dh2.data(), dh2.size());
  secureZero(dh3.data(), dh3.size());
  if (has_dh4) {
    secureZero(dh4.data(), dh4.size());
  }
  return result;
}

}
