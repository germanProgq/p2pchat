// Session manager integration tests. Spec: app.txt.
#include "session/SessionManager.h"

#include <array>
#include <chrono>
#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto/X3DH.h"
#include "identity/IdentityStore.h"
#include "transport/LoopbackTransport.h"

namespace {

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

std::array<uint8_t, 32> fixedKey() {
  std::array<uint8_t, 32> key{};
  for (size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<uint8_t>(0x11 + i);
  }
  return key;
}

std::filesystem::path uniqueTempPath() {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  return std::filesystem::temp_directory_path() / ("p2pchat_session_test_" + std::to_string(now));
}

template <size_t N>
std::array<uint8_t, N> hexToArray(const std::string& hex) {
  std::array<uint8_t, N> out{};
  for (size_t i = 0; i < N; ++i) {
    char hi = hex[i * 2];
    char lo = hex[i * 2 + 1];
    auto nibble = [](char c) -> uint8_t {
      if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
      }
      if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(10 + (c - 'a'));
      }
      if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(10 + (c - 'A'));
      }
      throw std::runtime_error("invalid hex");
    };
    out[i] = static_cast<uint8_t>((nibble(hi) << 4) | nibble(lo));
  }
  return out;
}

std::pair<crypto::Ratchet, crypto::Ratchet> setupRatchets() {
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
  crypto::ResponderResult resp = crypto::respondX3DH(init.message, responder, signed_prekey, one_time);

  crypto::Ratchet initiator_ratchet = crypto::Ratchet::initInitiator(init.root_key,
                                                                     init.ratchet_key,
                                                                     init.remote_ratchet_pub);
  crypto::Ratchet responder_ratchet = crypto::Ratchet::initResponder(resp.root_key,
                                                                     signed_prekey.key_pair,
                                                                     resp.remote_ratchet_pub);
  return {initiator_ratchet, responder_ratchet};
}

std::vector<uint8_t> sessionId() {
  std::vector<uint8_t> id(16, 0);
  for (size_t i = 0; i < id.size(); ++i) {
    id[i] = static_cast<uint8_t>(0xA0 + i);
  }
  return id;
}

void testSendReceive() {
  auto ratchets = setupRatchets();
  std::filesystem::path dirA = uniqueTempPath();
  std::filesystem::path dirB = uniqueTempPath();
  std::filesystem::create_directories(dirA);
  std::filesystem::create_directories(dirB);

  storage::StorageOptions optA;
  optA.path = (dirA / "store.db").string();
  optA.schema_path = (std::filesystem::path(P2PCHAT_SOURCE_DIR) / "core/storage/schema.sql").string();
  optA.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedKey());
  storage::Storage storeA(optA);
  storeA.open();

  storage::StorageOptions optB;
  optB.path = (dirB / "store.db").string();
  optB.schema_path = optA.schema_path;
  optB.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedKey());
  storage::Storage storeB(optB);
  storeB.open();

  transport::LoopbackNetwork network;
  transport::LoopbackTransport transportA("A", network);
  transport::LoopbackTransport transportB("B", network);

  session::SessionManager managerA({&storeA, &transportA});
  session::SessionManager managerB({&storeB, &transportB});
  managerA.bindTransportCallbacks();
  managerB.bindTransportCallbacks();
  managerA.start();
  managerB.start();

  managerA.addSession("B", sessionId(), ratchets.first);
  managerB.addSession("A", sessionId(), ratchets.second);

  bool received = false;
  managerB.onMessage = [&](const session::IncomingMessage& msg) {
    received = (msg.body == std::vector<uint8_t>{'h','i'});
  };

  require(transportA.connect(transport::PeerInfo{"B", "", 0}), "connect failed");

  managerA.sendMessage("B", "chat1", std::vector<uint8_t>{'h','i'});

  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  for (int i = 0; i < 5; ++i) {
    managerA.tick(now + i * 10);
    managerB.tick(now + i * 10);
  }

  require(received, "message not received");
  auto history = managerA.getHistory("chat1", 1, 10);
  require(history.size() == 1, "history size mismatch");
  require(history[0].acked, "ack not recorded");
}

void testSyncHello() {
  auto ratchets = setupRatchets();
  std::filesystem::path dirA = uniqueTempPath();
  std::filesystem::path dirB = uniqueTempPath();
  std::filesystem::create_directories(dirA);
  std::filesystem::create_directories(dirB);

  storage::StorageOptions optA;
  optA.path = (dirA / "store.db").string();
  optA.schema_path = (std::filesystem::path(P2PCHAT_SOURCE_DIR) / "core/storage/schema.sql").string();
  optA.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedKey());
  storage::Storage storeA(optA);
  storeA.open();

  storage::StorageOptions optB;
  optB.path = (dirB / "store.db").string();
  optB.schema_path = optA.schema_path;
  optB.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedKey());
  storage::Storage storeB(optB);
  storeB.open();

  transport::LoopbackNetwork network;
  transport::LoopbackTransport transportA("A", network);
  transport::LoopbackTransport transportB("B", network);

  session::SessionManager managerA({&storeA, &transportA});
  session::SessionManager managerB({&storeB, &transportB});
  managerA.bindTransportCallbacks();
  managerB.bindTransportCallbacks();
  managerA.start();
  managerB.start();

  managerA.addSession("B", sessionId(), ratchets.first);
  managerB.addSession("A", sessionId(), ratchets.second);

  managerA.sendMessage("B", "chat_sync", std::vector<uint8_t>{'o','f','f'});

  auto due = storeA.loadDueOutbox(std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count(), 10);
  for (const auto& item : due) {
    storeA.removeOutbox(item.id);
  }

  require(transportA.connect(transport::PeerInfo{"B", "", 0}), "connect failed");
  managerB.syncWithPeer("A", std::vector<std::string>{"chat_sync"});

  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  for (int i = 0; i < 10; ++i) {
    managerA.tick(now + i * 10);
    managerB.tick(now + i * 10);
  }

  auto history = managerB.getHistory("chat_sync", 1, 10);
  require(history.size() == 1, "sync history missing");
  require(history[0].body == std::vector<uint8_t>{'o','f','f'}, "sync payload mismatch");
}

}

int main() {
  const std::vector<std::pair<std::string, std::function<void()>>> tests = {
      {"send_receive", testSendReceive},
      {"sync_hello", testSyncHello},
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
