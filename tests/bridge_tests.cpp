// Bridge contract and payload tests. Spec: app/bridge/BridgeSpec.md.
#include "bridge/Bridge.h"
#include "bridge/BridgeJson.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/Core.h"
#include "identity/IdentityStore.h"
#include "transport/LoopbackTransport.h"

namespace {

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

crypto::PreKeyBundle makeBundle() {
  crypto::PreKeyBundle bundle;
  bundle.version = 1;
  bundle.has_one_time = true;
  bundle.capabilities = 0xA5A5A5A5u;
  for (size_t i = 0; i < bundle.identity_ed25519.size(); ++i) {
    bundle.identity_ed25519[i] = static_cast<uint8_t>(i);
    bundle.identity_x25519[i] = static_cast<uint8_t>(0x20 + i);
    bundle.signed_prekey.public_key[i] = static_cast<uint8_t>(0x40 + i);
    bundle.one_time_prekey.public_key[i] = static_cast<uint8_t>(0x90 + i);
  }
  bundle.signed_prekey.id = 7;
  for (size_t i = 0; i < bundle.signed_prekey.signature.size(); ++i) {
    bundle.signed_prekey.signature[i] = static_cast<uint8_t>(0x60 + i);
  }
  bundle.one_time_prekey.id = 9;
  return bundle;
}

std::array<uint8_t, 32> makeMasterKey() {
  std::array<uint8_t, 32> key{};
  for (size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<uint8_t>(0x10 + i);
  }
  return key;
}

bool bytesEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

std::filesystem::path uniqueTempPath() {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  return std::filesystem::temp_directory_path() / ("p2pchat_bridge_test_" + std::to_string(now));
}

int64_t nowMs() {
  using namespace std::chrono;
  return static_cast<int64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

bridge::NodeConfig makeBridgeConfig(const std::filesystem::path& dir,
                                    transport::LoopbackNetwork& network,
                                    const std::array<uint8_t, 32>& master_key) {
  bridge::NodeConfig config;
  config.identity_path = (dir / "identity.bin").string();
  config.storage_path = (dir / "store.db").string();
  config.schema_path = (std::filesystem::path(P2PCHAT_SOURCE_DIR) / "core/storage/schema.sql").string();
  config.master_key.assign(master_key.begin(), master_key.end());
  config.transport_kind = bridge::TransportKind::Loopback;
  config.loopback_network = &network;
  return config;
}

core::NodeConfig makeCoreConfig(const std::filesystem::path& dir,
                                transport::LoopbackNetwork& network,
                                const std::array<uint8_t, 32>& master_key) {
  core::NodeConfig config;
  config.identity_path = (dir / "identity.bin").string();
  config.storage_path = (dir / "store.db").string();
  config.schema_path = (std::filesystem::path(P2PCHAT_SOURCE_DIR) / "core/storage/schema.sql").string();
  config.master_key = std::make_shared<identity::InMemoryKeyStore>(master_key);
  config.transport_kind = core::TransportKind::Loopback;
  config.loopback_network = &network;
  return config;
}

class FakeCore final : public bridge::CoreBackend {
 public:
  void start(const core::NodeConfig& config) override {
    start_calls++;
    last_config = config;
  }

  void stop() override {
    stop_calls++;
  }

  std::string addContact(const crypto::PreKeyBundle& bundle) override {
    last_bundle = bundle;
    has_bundle = true;
    return peer_id;
  }

  void send(const std::string& chat_id,
            const std::vector<uint8_t>& plaintext,
            uint8_t content_type) override {
    last_send_chat = chat_id;
    last_send_bytes = plaintext;
    last_send_type = content_type;
    send_calls++;
  }

  std::vector<session::HistoryMessage> getHistory(const std::string&,
                                                  int64_t,
                                                  size_t) const override {
    return history;
  }

  void linkDevice(const std::string& link_code) override {
    last_link_code = link_code;
  }

  void emitMessage(const session::IncomingMessage& msg) {
    if (onMessage) {
      onMessage(msg);
    }
  }

  void emitConnectionChange(const transport::PeerId& peer, transport::ConnectionState state) {
    if (onConnectionChange) {
      onConnectionChange(peer, state);
    }
  }

  void emitPeerStatus(const transport::PeerId& peer, core::PeerStatus status) {
    if (onPeerStatus) {
      onPeerStatus(peer, status);
    }
  }

  void emitError(const transport::PeerId& peer, const std::string& message) {
    if (onError) {
      onError(peer, message);
    }
  }

  int start_calls = 0;
  int stop_calls = 0;
  int send_calls = 0;
  std::string peer_id = "peer-1";
  core::NodeConfig last_config{};
  crypto::PreKeyBundle last_bundle{};
  bool has_bundle = false;
  std::string last_send_chat;
  std::vector<uint8_t> last_send_bytes;
  uint8_t last_send_type = 0;
  std::vector<session::HistoryMessage> history;
  std::string last_link_code;
};

void testStartConfig() {
  auto backend = std::make_shared<FakeCore>();
  bridge::Bridge bridge(backend);

  bridge::NodeConfig config;
  config.identity_path = "id.bin";
  config.storage_path = "store.db";
  config.schema_path = "schema.sql";
  config.transport_kind = bridge::TransportKind::WebRtc;
  config.transport.max_in_flight = 9;
  config.transport.max_queue_bytes = 4096;
  config.transport.retry.base_delay_ms = 123;
  config.transport.retry.max_delay_ms = 456;
  config.transport.retry.max_attempts = 7;
  config.transport.retry.jitter_ratio = 0.1;
  config.webrtc.bind_address = "0.0.0.0";
  config.webrtc.bind_port = 4242;
  config.webrtc.max_datagram_size = 1400;
  config.one_time_prekeys = 33;
  config.signed_prekey_id = 2;
  config.one_time_start_id = 2000;
  config.handshake_base_delay_ms = 11;
  config.handshake_max_delay_ms = 22;
  config.handshake_max_attempts = 3;

  std::array<uint8_t, 32> master = makeMasterKey();
  config.master_key.assign(master.begin(), master.end());

  bridge.start(config);

  require(backend->start_calls == 1, "start not invoked");
  require(backend->last_config.identity_path == config.identity_path, "identity path mismatch");
  require(backend->last_config.storage_path == config.storage_path, "storage path mismatch");
  require(backend->last_config.schema_path == config.schema_path, "schema path mismatch");
  require(backend->last_config.transport_kind == core::TransportKind::WebRtc, "transport kind mismatch");
  require(backend->last_config.transport.max_in_flight == config.transport.max_in_flight, "max_in_flight mismatch");
  require(backend->last_config.transport.max_queue_bytes == config.transport.max_queue_bytes, "max_queue_bytes mismatch");
  require(backend->last_config.transport.retry.base_delay_ms == config.transport.retry.base_delay_ms, "retry base delay mismatch");
  require(backend->last_config.transport.retry.max_delay_ms == config.transport.retry.max_delay_ms, "retry max delay mismatch");
  require(backend->last_config.transport.retry.max_attempts == config.transport.retry.max_attempts, "retry attempts mismatch");
  require(backend->last_config.transport.retry.jitter_ratio == config.transport.retry.jitter_ratio, "retry jitter mismatch");
  require(backend->last_config.webrtc.bind_address == config.webrtc.bind_address, "webrtc bind address mismatch");
  require(backend->last_config.webrtc.bind_port == config.webrtc.bind_port, "webrtc bind port mismatch");
  require(backend->last_config.webrtc.max_datagram_size == config.webrtc.max_datagram_size, "webrtc datagram mismatch");
  require(backend->last_config.one_time_prekeys == config.one_time_prekeys, "one_time_prekeys mismatch");
  require(backend->last_config.signed_prekey_id == config.signed_prekey_id, "signed_prekey_id mismatch");
  require(backend->last_config.one_time_start_id == config.one_time_start_id, "one_time_start_id mismatch");
  require(backend->last_config.handshake_base_delay_ms == config.handshake_base_delay_ms, "handshake base delay mismatch");
  require(backend->last_config.handshake_max_delay_ms == config.handshake_max_delay_ms, "handshake max delay mismatch");
  require(backend->last_config.handshake_max_attempts == config.handshake_max_attempts, "handshake attempts mismatch");
  require(backend->last_config.master_key != nullptr, "master key not set");

  std::array<uint8_t, 32> loaded = backend->last_config.master_key->loadOrCreate();
  require(std::equal(loaded.begin(), loaded.end(), master.begin()), "master key value mismatch");
}

void testAddContactAndSend() {
  auto backend = std::make_shared<FakeCore>();
  bridge::Bridge bridge(backend);

  crypto::PreKeyBundle bundle = makeBundle();
  std::vector<uint8_t> encoded = crypto::serializePreKeyBundle(bundle);
  std::string peer_id = bridge.addContact(encoded);

  require(peer_id == backend->peer_id, "peer id mismatch");
  require(backend->has_bundle, "bundle not captured");
  require(bytesEqual(crypto::serializePreKeyBundle(backend->last_bundle), encoded), "bundle decode mismatch");

  bridge.send(peer_id, std::string("hi"));
  require(backend->send_calls == 1, "send not called");
  require(backend->last_send_chat == peer_id, "send chat mismatch");
  require(backend->last_send_type == static_cast<uint8_t>(session::ContentType::Text), "text content type mismatch");
  require(bytesEqual(backend->last_send_bytes, std::vector<uint8_t>{'h','i'}), "text bytes mismatch");

  bridge.send(peer_id, std::vector<uint8_t>{0x01, 0x02});
  require(backend->send_calls == 2, "binary send not called");
  require(backend->last_send_type == static_cast<uint8_t>(session::ContentType::Binary), "binary content type mismatch");
  require(bytesEqual(backend->last_send_bytes, std::vector<uint8_t>{0x01, 0x02}), "binary bytes mismatch");
}

void testHistoryMapping() {
  auto backend = std::make_shared<FakeCore>();
  bridge::Bridge bridge(backend);

  session::HistoryMessage msg;
  msg.chat_id = "peer-1";
  msg.msg_id = "m1";
  msg.sender_device = "dev-1";
  msg.ts_ms = 1000;
  msg.content_type = static_cast<uint8_t>(session::ContentType::Text);
  msg.body = std::vector<uint8_t>{'o','k'};
  msg.delivered = true;
  msg.acked = true;
  msg.index = 42;
  backend->history = {msg};

  std::vector<bridge::HistoryMessage> history = bridge.getHistory("peer-1", 0, 10);
  require(history.size() == 1, "history size mismatch");
  require(history[0].chat_id == msg.chat_id, "history chat mismatch");
  require(history[0].msg_id == msg.msg_id, "history msg id mismatch");
  require(history[0].sender_device == msg.sender_device, "history sender mismatch");
  require(history[0].ts_ms == msg.ts_ms, "history timestamp mismatch");
  require(history[0].content_type == bridge::ContentType::Text, "history content type mismatch");
  require(bytesEqual(history[0].body, msg.body), "history body mismatch");
  require(history[0].delivered == msg.delivered, "history delivered mismatch");
  require(history[0].acked == msg.acked, "history acked mismatch");
  require(history[0].index == msg.index, "history index mismatch");
}

void testEventSnapshots() {
  auto backend = std::make_shared<FakeCore>();
  bridge::Bridge bridge(backend);

  std::vector<std::string> snapshots;
  bridge.onMessage = [&](const bridge::IncomingMessage& message) {
    snapshots.push_back(bridge::toJsonPayload(message));
  };
  bridge.onConnectionChange = [&](const bridge::ConnectionEvent& event) {
    snapshots.push_back(bridge::toJsonPayload(event));
  };
  bridge.onPeerStatus = [&](const bridge::PeerStatusEvent& event) {
    snapshots.push_back(bridge::toJsonPayload(event));
  };
  bridge.onError = [&](const bridge::ErrorEvent& event) {
    snapshots.push_back(bridge::toJsonPayload(event));
  };

  session::IncomingMessage incoming;
  incoming.chat_id = "peer-1";
  incoming.msg_id = "m-1";
  incoming.sender_device = "dev-1";
  incoming.ts_ms = 1234;
  incoming.content_type = static_cast<uint8_t>(session::ContentType::Text);
  incoming.body = std::vector<uint8_t>{'o','k'};

  backend->emitMessage(incoming);
  backend->emitConnectionChange("peer-1", transport::ConnectionState::Connected);
  backend->emitPeerStatus("peer-1", core::PeerStatus::Ready);
  backend->emitError("peer-1", "boom");

  require(snapshots.size() == 4, "snapshot count mismatch");
  require(snapshots[0] == "{\"chatId\":\"peer-1\",\"msgId\":\"m-1\",\"senderDevice\":\"dev-1\",\"tsMs\":1234,\"contentType\":\"text\",\"body\":[111,107]}", "message snapshot mismatch");
  require(snapshots[1] == "{\"peerId\":\"peer-1\",\"state\":\"connected\"}", "connection snapshot mismatch");
  require(snapshots[2] == "{\"peerId\":\"peer-1\",\"status\":\"ready\"}", "peer status snapshot mismatch");
  require(snapshots[3] == "{\"peerId\":\"peer-1\",\"message\":\"boom\"}", "error snapshot mismatch");
}

void testInvalidBundleHandling() {
  auto backend = std::make_shared<FakeCore>();
  bridge::Bridge bridge(backend);

  bool threw = false;
  try {
    bridge.addContact(std::vector<uint8_t>{0x01, 0x02});
  } catch (const std::exception&) {
    threw = true;
  }
  require(threw, "invalid bundle did not throw");
}

void testHandshakeFailureStatus() {
  transport::LoopbackNetwork network;

  std::filesystem::path dirA = uniqueTempPath();
  std::filesystem::path dirB = uniqueTempPath();
  std::filesystem::create_directories(dirA);
  std::filesystem::create_directories(dirB);

  std::array<uint8_t, 32> master_key = makeMasterKey();
  bridge::NodeConfig configA = makeBridgeConfig(dirA, network, master_key);
  configA.handshake_base_delay_ms = 1;
  configA.handshake_max_delay_ms = 1;
  configA.handshake_max_attempts = 2;

  core::NodeConfig configB = makeCoreConfig(dirB, network, master_key);

  core::Core peer_core;
  peer_core.start(configB);
  std::vector<uint8_t> bundle = crypto::serializePreKeyBundle(peer_core.localPreKeyBundle());

  auto backend = std::make_shared<bridge::CoreAdapter>();
  bridge::Bridge bridge(backend);
  bridge.start(configA);

  std::vector<bridge::PeerStatus> statuses;
  std::string peer_id;
  bridge.onPeerStatus = [&](const bridge::PeerStatusEvent& event) {
    if (peer_id.empty()) {
      peer_id = event.peer_id;
    }
    statuses.push_back(event.status);
  };

  std::string returned_peer = bridge.addContact(bundle);
  if (peer_id.empty()) {
    peer_id = returned_peer;
  }

  int64_t start = nowMs();
  for (int i = 0; i < 4; ++i) {
    backend->tick(start + i * 1000);
  }

  require(!statuses.empty(), "peer status missing");
  require(statuses.front() == bridge::PeerStatus::Pending, "pending status missing");
  require(statuses.back() == bridge::PeerStatus::Failed, "failed status missing");
}

}

int main() {
  const std::vector<std::pair<std::string, void (*)()>> tests = {
      {"bridge_start_config", testStartConfig},
      {"bridge_add_contact_send", testAddContactAndSend},
      {"bridge_history_mapping", testHistoryMapping},
      {"bridge_event_snapshots", testEventSnapshots},
      {"bridge_invalid_bundle", testInvalidBundleHandling},
      {"bridge_handshake_failure_status", testHandshakeFailureStatus},
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
