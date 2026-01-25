// Core facade integration tests. Spec: app.txt.
#include "core/Core.h"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

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
    key[i] = static_cast<uint8_t>(0x21 + i);
  }
  return key;
}

std::filesystem::path uniqueTempPath() {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  return std::filesystem::temp_directory_path() / ("p2pchat_core_test_" + std::to_string(now));
}

int64_t nowMs() {
  using namespace std::chrono;
  return static_cast<int64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

void testHandshakeAndSend() {
  transport::LoopbackNetwork network;

  std::filesystem::path dirA = uniqueTempPath();
  std::filesystem::path dirB = uniqueTempPath();
  std::filesystem::create_directories(dirA);
  std::filesystem::create_directories(dirB);

  core::NodeConfig configA;
  configA.identity_path = (dirA / "identity.bin").string();
  configA.storage_path = (dirA / "store.db").string();
  configA.schema_path = (std::filesystem::path(P2PCHAT_SOURCE_DIR) / "core/storage/schema.sql").string();
  configA.username = "core-a";
  configA.password = "password123";
  configA.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedKey());
  configA.transport_kind = core::TransportKind::Loopback;
  configA.loopback_network = &network;
  configA.handshake_base_delay_ms = 10;
  configA.handshake_max_delay_ms = 40;
  configA.handshake_max_attempts = 3;

  core::NodeConfig configB = configA;
  configB.identity_path = (dirB / "identity.bin").string();
  configB.storage_path = (dirB / "store.db").string();

  core::Core coreA;
  core::Core coreB;

  coreA.start(configA);
  coreB.start(configB);

  bool received = false;
  coreB.onMessage = [&](const session::IncomingMessage& msg) {
    received = (msg.body == std::vector<uint8_t>{'o','k'});
  };

  std::string peer_id = coreA.addContact(coreB.localPreKeyBundle());
  transport::PeerInfo peer;
  peer.id = peer_id;
  coreA.connectPeer(peer);

  coreA.send(peer_id, std::vector<uint8_t>{'o','k'});

  int64_t start = nowMs();
  for (int i = 0; i < 5; ++i) {
    coreA.tick(start + i * 10);
    coreB.tick(start + i * 10);
  }

  require(received, "message not received");
  auto history = coreA.getHistory(peer_id, 1, 10);
  require(history.size() == 1, "history size mismatch");
  require(history[0].acked, "ack missing in history");
}

}  // namespace

int main() {
  const std::vector<std::pair<std::string, void (*)()>> tests = {
      {"core_handshake_and_send", testHandshakeAndSend},
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
