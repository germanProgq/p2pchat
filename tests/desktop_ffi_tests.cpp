// Desktop FFI contract tests. Spec: docs/desktop_app.md.
#include "p2pchat_ffi.h"

#include <array>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "transport/LoopbackTransport.h"

namespace {

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

std::array<uint8_t, 32> masterKey() {
  std::array<uint8_t, 32> key{};
  for (size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<uint8_t>(0x55 + i);
  }
  return key;
}

std::filesystem::path uniqueTempPath(const std::string& suffix) {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  return std::filesystem::temp_directory_path() / ("p2pchat_ffi_" + suffix + "_" + std::to_string(now));
}

int64_t nowMs() {
  using namespace std::chrono;
  return static_cast<int64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
  if (hex.size() % 2 != 0) {
    return false;
  }
  out.clear();
  out.reserve(hex.size() / 2);
  auto nibble = [](char c, uint8_t& v) {
    if (c >= '0' && c <= '9') {
      v = static_cast<uint8_t>(c - '0');
      return true;
    }
    if (c >= 'a' && c <= 'f') {
      v = static_cast<uint8_t>(10 + (c - 'a'));
      return true;
    }
    if (c >= 'A' && c <= 'F') {
      v = static_cast<uint8_t>(10 + (c - 'A'));
      return true;
    }
    return false;
  };
  for (size_t i = 0; i < hex.size(); i += 2) {
    uint8_t hi = 0;
    uint8_t lo = 0;
    if (!nibble(hex[i], hi) || !nibble(hex[i + 1], lo)) {
      return false;
    }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

struct CallbackState {
  bool received = false;
  std::string payload;
};

void onEvent(void* user_data, p2pchat_event_type type, const char* payload_json) {
  if (!user_data || !payload_json) {
    return;
  }
  if (type != P2PCHAT_EVENT_MESSAGE) {
    return;
  }
  auto* state = static_cast<CallbackState*>(user_data);
  state->received = true;
  state->payload = payload_json;
}

struct ConfigHolder {
  std::string identity_path;
  std::string storage_path;
  std::string schema_path;
  std::string username;
  std::string password;
  p2pchat_node_config config{};
};

ConfigHolder makeConfig(const std::filesystem::path& dir,
                        transport::LoopbackNetwork& network,
                        const std::array<uint8_t, 32>& key) {
  ConfigHolder holder;
  std::filesystem::create_directories(dir);
  holder.identity_path = (dir / "identity.bin").string();
  holder.storage_path = (dir / "store.db").string();
  holder.schema_path = (std::filesystem::path(P2PCHAT_SOURCE_DIR) / "core/storage/schema.sql").string();
  holder.username = "ffi-user";
  holder.password = "password123";
  holder.config.identity_path = holder.identity_path.c_str();
  holder.config.storage_path = holder.storage_path.c_str();
  holder.config.schema_path = holder.schema_path.c_str();
  holder.config.username = holder.username.c_str();
  holder.config.password = holder.password.c_str();
  holder.config.master_key = key.data();
  holder.config.master_key_len = key.size();
  holder.config.transport_kind = P2PCHAT_TRANSPORT_LOOPBACK;
  holder.config.loopback_network = &network;
  holder.config.handshake_base_delay_ms = 5;
  holder.config.handshake_max_delay_ms = 20;
  holder.config.handshake_max_attempts = 3;
  return holder;
}

void testFfiLoopback() {
  transport::LoopbackNetwork network;
  auto dirA = uniqueTempPath("a");
  auto dirB = uniqueTempPath("b");
  std::array<uint8_t, 32> key = masterKey();

  p2pchat_handle* a = p2pchat_create();
  p2pchat_handle* b = p2pchat_create();
  require(a && b, "handles not created");

  ConfigHolder configA = makeConfig(dirA, network, key);
  ConfigHolder configB = makeConfig(dirB, network, key);

  require(p2pchat_start(a, &configA.config), "start A failed");
  require(p2pchat_start(b, &configB.config), "start B failed");

  CallbackState state;
  p2pchat_set_event_callback(b, onEvent, &state);

  char* bundle_hex = p2pchat_local_bundle_hex(b);
  require(bundle_hex != nullptr, "bundle hex missing");
  std::vector<uint8_t> bundle_bytes;
  require(hexToBytes(bundle_hex, bundle_bytes), "bundle hex invalid");
  p2pchat_string_free(bundle_hex);

  char* peer_id = p2pchat_add_contact(a, bundle_bytes.data(), bundle_bytes.size());
  require(peer_id != nullptr, "addContact failed");

  p2pchat_peer_info peer{};
  peer.peer_id = peer_id;
  require(p2pchat_connect_peer(a, &peer), "connect failed");

  const std::string message = "ffi hello";
  require(p2pchat_send(a, peer_id,
                       reinterpret_cast<const uint8_t*>(message.data()),
                       message.size(),
                       1),
          "send failed");

  int64_t start = nowMs();
  for (int i = 0; i < 20; ++i) {
    int64_t t = start + i * 10;
    p2pchat_tick(a, t);
    p2pchat_tick(b, t);
    if (state.received) {
      break;
    }
  }

  require(state.received, "message not received");
  require(state.payload.find("\"chatId\"") != std::string::npos, "payload missing chatId");

  char* history = p2pchat_get_history_json(b, peer_id, 1, 10);
  require(history != nullptr, "history missing");
  require(std::string(history).find("ffi hello") == std::string::npos,
          "plaintext should not appear in history json");
  p2pchat_string_free(history);

  p2pchat_string_free(peer_id);
  p2pchat_stop(a);
  p2pchat_stop(b);
  p2pchat_destroy(a);
  p2pchat_destroy(b);
}

}

int main() {
  const std::vector<std::pair<std::string, void (*)()>> tests = {
      {"ffi_loopback", testFfiLoopback},
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
