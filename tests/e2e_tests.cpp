// End-to-end P2P flow tests. Spec: docs/e2e_flow.md.
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
    key[i] = static_cast<uint8_t>(0x31 + i);
  }
  return key;
}

std::filesystem::path uniqueTempPath(const std::string& suffix) {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  return std::filesystem::temp_directory_path() / ("p2pchat_e2e_" + suffix + "_" + std::to_string(now));
}

int64_t nowMs() {
  using namespace std::chrono;
  return static_cast<int64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

void tickPair(core::Core& a, core::Core& b, int rounds, int64_t start_ms, int64_t step_ms) {
  for (int i = 0; i < rounds; ++i) {
    int64_t t = start_ms + static_cast<int64_t>(i) * step_ms;
    a.tick(t);
    b.tick(t);
  }
}

void testEndToEndReconnectResync() {
  transport::LoopbackNetwork network;

  std::filesystem::path dirA = uniqueTempPath("a");
  std::filesystem::path dirB = uniqueTempPath("b");
  std::filesystem::create_directories(dirA);
  std::filesystem::create_directories(dirB);

  core::NodeConfig configA;
  configA.identity_path = (dirA / "identity.bin").string();
  configA.storage_path = (dirA / "store.db").string();
  configA.schema_path = (std::filesystem::path(P2PCHAT_SOURCE_DIR) / "core/storage/schema.sql").string();
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

  std::vector<std::vector<uint8_t>> received;
  auto onMessage = [&received](const session::IncomingMessage& msg) {
    received.push_back(msg.body);
  };
  coreB.onMessage = onMessage;

  std::string peer_id = coreA.addContact(coreB.localPreKeyBundle());
  transport::PeerInfo peer;
  peer.id = peer_id;
  coreA.connectPeer(peer);

  coreA.send(peer_id, std::vector<uint8_t>{'h', 'i'});
  int64_t start = nowMs();
  tickPair(coreA, coreB, 10, start, 10);

  require(received.size() == 1, "initial message not received");

  coreB.stop();

  coreA.send(peer_id, std::vector<uint8_t>{'o', 'f', 'f', '1'});
  coreA.send(peer_id, std::vector<uint8_t>{'o', 'f', 'f', '2'});
  coreA.send(peer_id, std::vector<uint8_t>{'o', 'f', 'f', '3'});

  coreB.start(configB);
  coreB.onMessage = onMessage;
  coreA.connectPeer(peer);

  int64_t restart_start = nowMs();
  tickPair(coreA, coreB, 20, restart_start, 15);

  require(received.size() == 4, "offline messages not delivered after reconnect");

  auto historyB = coreB.getHistory(peer_id, 1, 10);
  require(historyB.size() == 4, "history size mismatch after resync");
  require(historyB[0].body == std::vector<uint8_t>{'h', 'i'}, "history content mismatch");
  require(historyB[1].body == std::vector<uint8_t>{'o', 'f', 'f', '1'}, "offline message 1 missing");
  require(historyB[2].body == std::vector<uint8_t>{'o', 'f', 'f', '2'}, "offline message 2 missing");
  require(historyB[3].body == std::vector<uint8_t>{'o', 'f', 'f', '3'}, "offline message 3 missing");

  auto historyA = coreA.getHistory(peer_id, 1, 10);
  require(historyA.size() == 4, "sender history size mismatch");
  require(historyA[0].acked, "initial message not acked");
}

}

int main() {
  const std::vector<std::pair<std::string, void (*)()>> tests = {
      {"e2e_reconnect_resync", testEndToEndReconnectResync},
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
