// Crypto module unit tests and vectors. Spec: core/crypto/ratchet_spec.md.
#include "crypto/Primitives.h"
#include "crypto/Ratchet.h"
#include "crypto/X3DH.h"

#include <array>
#include <cctype>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

uint8_t hexNibble(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<uint8_t>(c - '0');
  }
  char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (lower >= 'a' && lower <= 'f') {
    return static_cast<uint8_t>(10 + (lower - 'a'));
  }
  throw std::runtime_error("invalid hex character");
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    throw std::runtime_error("hex string length must be even");
  }
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    uint8_t hi = hexNibble(hex[i]);
    uint8_t lo = hexNibble(hex[i + 1]);
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

template <size_t N>
std::array<uint8_t, N> hexToArray(const std::string& hex) {
  std::vector<uint8_t> bytes = hexToBytes(hex);
  if (bytes.size() != N) {
    throw std::runtime_error("hex length mismatch");
  }
  std::array<uint8_t, N> out{};
  std::copy(bytes.begin(), bytes.end(), out.begin());
  return out;
}

std::vector<uint8_t> toBytes(const std::string& text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

std::array<uint8_t, 32> messageKeyFromChain(const std::array<uint8_t, 32>& chain_key) {
  const uint8_t kMessageKey = 0x01;
  return crypto::hmacSha256(chain_key, &kMessageKey, 1);
}

void deriveAeadKeyNonce(const std::array<uint8_t, 32>& message_key,
                        std::array<uint8_t, 32>& aead_key,
                        std::array<uint8_t, 12>& nonce) {
  const std::vector<uint8_t> info = {'p','2','p','c','h','a','t','.','r','a','t','c','h','e','t','.','m','s','g','.','v','1'};
  std::vector<uint8_t> okm = crypto::hkdfSha256(std::vector<uint8_t>(message_key.begin(), message_key.end()),
                                                {}, info, 44);
  require(okm.size() == 44, "message key expansion length mismatch");
  std::copy(okm.begin(), okm.begin() + 32, aead_key.begin());
  std::copy(okm.begin() + 32, okm.end(), nonce.begin());
}

std::vector<uint8_t> buildAad(const std::vector<uint8_t>& aad, const crypto::RatchetHeader& header) {
  std::vector<uint8_t> header_bytes = crypto::Ratchet::serializeHeader(header);
  std::vector<uint8_t> out;
  out.reserve(aad.size() + header_bytes.size());
  out.insert(out.end(), aad.begin(), aad.end());
  out.insert(out.end(), header_bytes.begin(), header_bytes.end());
  return out;
}

void testX25519Vector() {
  const std::array<uint8_t, 32> alice_private = hexToArray<32>(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  const std::array<uint8_t, 32> alice_public_expected = hexToArray<32>(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  const std::array<uint8_t, 32> bob_private = hexToArray<32>(
      "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  const std::array<uint8_t, 32> bob_public_expected = hexToArray<32>(
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  const std::array<uint8_t, 32> shared_expected = hexToArray<32>(
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

  auto alice_public = crypto::x25519PublicFromPrivate(alice_private);
  auto bob_public = crypto::x25519PublicFromPrivate(bob_private);
  require(alice_public == alice_public_expected, "X25519 alice public vector mismatch");
  require(bob_public == bob_public_expected, "X25519 bob public vector mismatch");

  auto shared_ab = crypto::x25519SharedSecret(alice_private, bob_public);
  auto shared_ba = crypto::x25519SharedSecret(bob_private, alice_public);
  require(shared_ab == shared_expected, "X25519 shared secret vector mismatch");
  require(shared_ba == shared_expected, "X25519 shared secret symmetry mismatch");
}

void testHkdfVector() {
  std::vector<uint8_t> ikm(22, 0x0b);
  std::vector<uint8_t> salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
  std::vector<uint8_t> info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
  std::vector<uint8_t> okm = crypto::hkdfSha256(ikm, salt, info, 42);
  std::vector<uint8_t> expected = {
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
      0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
      0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
  require(okm == expected, "HKDF test vector mismatch");
}

std::pair<crypto::Ratchet, crypto::Ratchet> setupHandshake() {
  identity::IdentityKeyPair responder_identity{};
  responder_identity.seed = hexToArray<32>(
      "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
  responder_identity.public_key = crypto::ed25519PublicFromSeed(responder_identity.seed);

  identity::DeviceKeyPair responder{};
  responder.ed25519_seed = hexToArray<32>(
      "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
  responder.ed25519_public = crypto::ed25519PublicFromSeed(responder.ed25519_seed);
  responder.x25519_private = hexToArray<32>(
      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
  responder.x25519_public = crypto::x25519PublicFromPrivate(responder.x25519_private);

  crypto::SignedPreKeyPair signed_prekey{};
  signed_prekey.id = 7;
  signed_prekey.key_pair.private_key = hexToArray<32>(
      "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
  signed_prekey.key_pair.public_key = crypto::x25519PublicFromPrivate(signed_prekey.key_pair.private_key);
  signed_prekey.signature = crypto::signSignedPreKey(responder_identity.seed,
                                                     signed_prekey.id,
                                                     signed_prekey.key_pair.public_key);

  crypto::OneTimePreKeyPair one_time{};
  one_time.id = 42;
  one_time.key_pair.private_key = hexToArray<32>(
      "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
  one_time.key_pair.public_key = crypto::x25519PublicFromPrivate(one_time.key_pair.private_key);

  crypto::OneTimePreKeyPublic one_time_pub{};
  one_time_pub.id = one_time.id;
  one_time_pub.public_key = one_time.key_pair.public_key;

  crypto::PreKeyBundle bundle = crypto::createPreKeyBundle(responder_identity,
                                                           responder,
                                                           signed_prekey,
                                                           one_time_pub,
                                                           0);

  identity::IdentityKeyPair initiator_identity{};
  initiator_identity.seed = hexToArray<32>(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  initiator_identity.public_key = crypto::ed25519PublicFromSeed(initiator_identity.seed);

  identity::DeviceKeyPair initiator_device{};
  initiator_device.ed25519_seed = hexToArray<32>(
      "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  initiator_device.ed25519_public = crypto::ed25519PublicFromSeed(initiator_device.ed25519_seed);
  initiator_device.x25519_private = hexToArray<32>(
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
  initiator_device.x25519_public = crypto::x25519PublicFromPrivate(initiator_device.x25519_private);

  crypto::InitiatorKeys initiator{};
  initiator.identity_ed25519 = initiator_identity.public_key;
  initiator.device_ed25519 = initiator_device.ed25519_public;
  initiator.identity_x25519_private = initiator_device.x25519_private;
  initiator.identity_x25519_public = initiator_device.x25519_public;

  crypto::KeyPair ephemeral{};
  ephemeral.private_key = hexToArray<32>(
      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
  ephemeral.public_key = crypto::x25519PublicFromPrivate(ephemeral.private_key);

  crypto::InitiatorResult init = crypto::initiateX3DH(initiator, bundle, ephemeral);
  std::vector<uint8_t> message_bytes = crypto::serializePreKeyMessage(init.message);
  crypto::PreKeyMessage parsed = crypto::parsePreKeyMessage(message_bytes);
  require(parsed.initiator_ephemeral == init.message.initiator_ephemeral, "PreKeyMessage parse mismatch");

  crypto::ResponderResult resp = crypto::respondX3DH(parsed, responder, signed_prekey, one_time);
  require(init.root_key == resp.root_key, "X3DH root key mismatch");
  const std::array<uint8_t, 32> expected_root = hexToArray<32>(
      "61e27fe4468078c75b335f58b6773d9278db001bbdf1a74b987921039c3ed9a1");
  require(init.root_key == expected_root, "X3DH root key vector mismatch");

  crypto::Ratchet initiator_ratchet = crypto::Ratchet::initInitiator(init.root_key,
                                                                     init.ratchet_key,
                                                                     init.remote_ratchet_pub);
  crypto::Ratchet responder_ratchet = crypto::Ratchet::initResponder(resp.root_key,
                                                                     signed_prekey.key_pair,
                                                                     resp.remote_ratchet_pub);
  return {initiator_ratchet, responder_ratchet};
}

void testX3dhAndRatchet() {
  auto ratchets = setupHandshake();
  crypto::Ratchet initiator = ratchets.first;
  crypto::Ratchet responder = ratchets.second;

  std::vector<uint8_t> aad = {0x01, 0x02, 0x03};
  std::vector<uint8_t> hello = toBytes("hello");
  std::vector<uint8_t> reply = toBytes("world");

  crypto::RatchetMessage msg1 = initiator.encrypt(hello, aad);
  std::vector<uint8_t> out1 = responder.decrypt(msg1, aad);
  require(out1 == hello, "decrypt mismatch for initiator message");

  crypto::RatchetMessage msg2 = responder.encrypt(reply, aad);
  std::vector<uint8_t> out2 = initiator.decrypt(msg2, aad);
  require(out2 == reply, "decrypt mismatch for responder message");

  std::vector<uint8_t> text1 = toBytes("first");
  std::vector<uint8_t> text2 = toBytes("second");
  crypto::RatchetMessage m1 = initiator.encrypt(text1, aad);
  crypto::RatchetMessage m2 = initiator.encrypt(text2, aad);
  std::vector<uint8_t> o2 = responder.decrypt(m2, aad);
  require(o2 == text2, "out-of-order decrypt failed");
  std::vector<uint8_t> o1 = responder.decrypt(m1, aad);
  require(o1 == text1, "skipped key decrypt failed");
}

void testForwardSecrecyProperty() {
  auto ratchets = setupHandshake();
  crypto::Ratchet initiator = ratchets.first;
  crypto::Ratchet responder = ratchets.second;

  std::vector<uint8_t> aad = {0x11, 0x22};
  std::vector<uint8_t> hello = toBytes("start");
  std::array<uint8_t, 32> old_chain = initiator.sendingChainKey();

  crypto::RatchetMessage msg1 = initiator.encrypt(hello, aad);
  std::vector<uint8_t> out1 = responder.decrypt(msg1, aad);
  require(out1 == hello, "initial decrypt mismatch");

  std::vector<uint8_t> responder_text = toBytes("ratchet");
  crypto::RatchetMessage msg2 = responder.encrypt(responder_text, aad);

  std::array<uint8_t, 32> old_message_key = messageKeyFromChain(old_chain);
  std::array<uint8_t, 32> aead_key{};
  std::array<uint8_t, 12> nonce{};
  deriveAeadKeyNonce(old_message_key, aead_key, nonce);
  std::vector<uint8_t> aad_full = buildAad(aad, msg2.header);
  bool failed = false;
  try {
    std::vector<uint8_t> wrong = crypto::aeadDecrypt(crypto::AeadAlgorithm::ChaCha20Poly1305,
                                                     aead_key,
                                                     nonce,
                                                     msg2.ciphertext,
                                                     aad_full,
                                                     msg2.tag);
    (void)wrong;
  } catch (const std::exception&) {
    failed = true;
  }
  require(failed, "forward secrecy check failed");

  std::vector<uint8_t> out2 = initiator.decrypt(msg2, aad);
  require(out2 == responder_text, "ratchet decrypt mismatch");
}

}

int main() {
  const std::vector<std::pair<std::string, std::function<void()>>> tests = {
      {"x25519_vector", testX25519Vector},
      {"hkdf_vector", testHkdfVector},
      {"x3dh_ratchet", testX3dhAndRatchet},
      {"forward_secrecy", testForwardSecrecyProperty},
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
