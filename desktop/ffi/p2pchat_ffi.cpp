// C FFI implementation for desktop UI bindings. Spec: docs/desktop_app.md.
#include "p2pchat_ffi.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <vector>

#include "bridge/BridgeJson.h"
#include "core/Core.h"
#include "crypto/X3DH.h"
#include "identity/IdentityStore.h"
#include "session/SessionManager.h"
#include "transport/Ice.h"
#include "transport/LoopbackTransport.h"

namespace {

thread_local std::string g_last_error;

void setError(const std::string& message) {
  g_last_error = message;
}

char* allocString(const std::string& value) {
  char* out = static_cast<char*>(std::malloc(value.size() + 1));
  if (!out) {
    setError("allocation failed");
    return nullptr;
  }
  if (!value.empty()) {
    std::memcpy(out, value.data(), value.size());
  }
  out[value.size()] = '\0';
  return out;
}

bridge::ContentType toBridgeContentType(uint8_t value) {
  if (value == static_cast<uint8_t>(session::ContentType::Text)) {
    return bridge::ContentType::Text;
  }
  return bridge::ContentType::Binary;
}

bridge::IncomingMessage toBridgeMessage(const session::IncomingMessage& msg) {
  bridge::IncomingMessage out;
  out.chat_id = msg.chat_id;
  out.msg_id = msg.msg_id;
  out.sender_device = msg.sender_device;
  out.ts_ms = msg.ts_ms;
  out.content_type = toBridgeContentType(msg.content_type);
  out.body = msg.body;
  return out;
}

bridge::HistoryMessage toBridgeHistory(const session::HistoryMessage& msg) {
  bridge::HistoryMessage out;
  out.chat_id = msg.chat_id;
  out.msg_id = msg.msg_id;
  out.sender_device = msg.sender_device;
  out.ts_ms = msg.ts_ms;
  out.content_type = toBridgeContentType(msg.content_type);
  out.body = msg.body;
  out.delivered = msg.delivered;
  out.acked = msg.acked;
  out.index = msg.index;
  return out;
}

bridge::ConnectionEvent toBridgeConnection(const transport::PeerId& peer, transport::ConnectionState state) {
  bridge::ConnectionEvent event;
  event.peer_id = peer;
  switch (state) {
    case transport::ConnectionState::Disconnected:
      event.state = bridge::ConnectionState::Disconnected;
      break;
    case transport::ConnectionState::Connecting:
      event.state = bridge::ConnectionState::Connecting;
      break;
    case transport::ConnectionState::Connected:
      event.state = bridge::ConnectionState::Connected;
      break;
  }
  return event;
}

bridge::PeerStatusEvent toBridgePeerStatus(const transport::PeerId& peer, core::PeerStatus status) {
  bridge::PeerStatusEvent event;
  event.peer_id = peer;
  switch (status) {
    case core::PeerStatus::Pending:
      event.status = bridge::PeerStatus::Pending;
      break;
    case core::PeerStatus::Ready:
      event.status = bridge::PeerStatus::Ready;
      break;
    case core::PeerStatus::Failed:
      event.status = bridge::PeerStatus::Failed;
      break;
  }
  return event;
}

bridge::ErrorEvent toBridgeError(const transport::PeerId& peer, const std::string& message) {
  bridge::ErrorEvent event;
  event.peer_id = peer;
  event.message = message;
  return event;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

std::string historyJson(const std::vector<session::HistoryMessage>& history, const std::string& peer_username) {
  std::string out;
  out.push_back('[');
  bool first = true;
  for (const auto& msg : history) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    bridge::HistoryMessage bridge_msg = toBridgeHistory(msg);
    bridge_msg.peer_username = peer_username;
    out += bridge::toJsonPayload(bridge_msg);
  }
  out.push_back(']');
  return out;
}

struct CallbackState {
  p2pchat_event_cb callback = nullptr;
  void* user_data = nullptr;
  std::mutex mutex;
};

}  // namespace

struct p2pchat_handle {
  core::Core core;
  std::mutex core_mutex;
  CallbackState callbacks;
};

extern "C" {

p2pchat_handle* p2pchat_create() {
  try {
    auto* handle = new p2pchat_handle();
    return handle;
  } catch (const std::exception& ex) {
    setError(ex.what());
    return nullptr;
  } catch (...) {
    setError("unknown error");
    return nullptr;
  }
}

void p2pchat_destroy(p2pchat_handle* handle) {
  if (!handle) {
    return;
  }
  try {
    {
      std::lock_guard<std::mutex> lock(handle->core_mutex);
      handle->core.stop();
    }
  } catch (...) {
  }
  delete handle;
}

void p2pchat_set_event_callback(p2pchat_handle* handle,
                                p2pchat_event_cb callback,
                                void* user_data) {
  if (!handle) {
    return;
  }
  std::lock_guard<std::mutex> lock(handle->callbacks.mutex);
  handle->callbacks.callback = callback;
  handle->callbacks.user_data = user_data;
}

bool p2pchat_start(p2pchat_handle* handle, const p2pchat_node_config* config) {
  if (!handle || !config) {
    setError("invalid handle or config");
    return false;
  }
  try {
    core::NodeConfig node;
    if (!config->identity_path || !config->storage_path || !config->schema_path) {
      setError("identity_path, storage_path, and schema_path are required");
      return false;
    }
    node.identity_path = config->identity_path;
    node.storage_path = config->storage_path;
    node.schema_path = config->schema_path;
    if (config->username) {
      node.username = config->username;
    }
    if (config->password) {
      node.password = config->password;
    }
    if (config->master_key && config->master_key_len == 32) {
      std::array<uint8_t, 32> key{};
      std::copy(config->master_key, config->master_key + 32, key.begin());
      node.master_key = std::make_shared<identity::InMemoryKeyStore>(key);
    } else {
      std::string service = config->keystore_service ? config->keystore_service : "p2pchat";
      node.master_key = std::make_shared<identity::OsKeyStore>(service);
    }

    node.transport_kind = static_cast<core::TransportKind>(config->transport_kind == 0
                                                               ? P2PCHAT_TRANSPORT_QUIC
                                                               : config->transport_kind);
    node.transport.max_in_flight = config->max_in_flight > 0 ? config->max_in_flight : node.transport.max_in_flight;
    node.transport.max_queue_bytes = config->max_queue_bytes > 0 ? config->max_queue_bytes
                                                                  : node.transport.max_queue_bytes;
    if (config->retry_base_delay_ms > 0) {
      node.transport.retry.base_delay_ms = config->retry_base_delay_ms;
    }
    if (config->retry_max_delay_ms > 0) {
      node.transport.retry.max_delay_ms = config->retry_max_delay_ms;
    }
    if (config->retry_max_attempts > 0) {
      node.transport.retry.max_attempts = config->retry_max_attempts;
    }
    if (config->retry_jitter_ratio >= 0.0) {
      node.transport.retry.jitter_ratio = config->retry_jitter_ratio;
    }

    if (config->bind_address && config->bind_address[0] != '\0') {
      node.quic.bind_address = config->bind_address;
      node.webrtc.bind_address = config->bind_address;
    }
    if (config->bind_port != 0) {
      node.quic.bind_port = config->bind_port;
      node.webrtc.bind_port = config->bind_port;
    }
    if (config->max_datagram_size != 0) {
      node.quic.max_datagram_size = config->max_datagram_size;
      node.webrtc.max_datagram_size = config->max_datagram_size;
    }

    if (config->stun_servers && config->stun_server_count > 0) {
      node.quic.ice.stun_servers.clear();
      node.webrtc.ice.stun_servers.clear();
      for (size_t i = 0; i < config->stun_server_count; ++i) {
        if (!config->stun_servers[i]) {
          continue;
        }
        node.quic.ice.stun_servers.emplace_back(config->stun_servers[i]);
        node.webrtc.ice.stun_servers.emplace_back(config->stun_servers[i]);
      }
    }

    if (config->relay_candidates && config->relay_candidate_count > 0) {
      node.quic.ice.relay_candidates.clear();
      node.webrtc.ice.relay_candidates.clear();
      for (size_t i = 0; i < config->relay_candidate_count; ++i) {
        const auto& entry = config->relay_candidates[i];
        if (!entry.address) {
          continue;
        }
        transport::IceCandidate candidate;
        candidate.type = static_cast<transport::IceCandidateType>(entry.type);
        candidate.address = entry.address;
        candidate.port = entry.port;
        candidate.priority = entry.priority;
        node.quic.ice.relay_candidates.push_back(candidate);
        node.webrtc.ice.relay_candidates.push_back(candidate);
      }
    }

    if (config->one_time_prekeys > 0) {
      node.one_time_prekeys = config->one_time_prekeys;
    }
    if (config->signed_prekey_id != 0) {
      node.signed_prekey_id = config->signed_prekey_id;
    }
    if (config->one_time_start_id != 0) {
      node.one_time_start_id = config->one_time_start_id;
    }
    if (config->handshake_base_delay_ms > 0) {
      node.handshake_base_delay_ms = config->handshake_base_delay_ms;
    }
    if (config->handshake_max_delay_ms > 0) {
      node.handshake_max_delay_ms = config->handshake_max_delay_ms;
    }
    if (config->handshake_max_attempts > 0) {
      node.handshake_max_attempts = config->handshake_max_attempts;
    }

    if (config->loopback_network) {
      node.loopback_network = static_cast<transport::LoopbackNetwork*>(config->loopback_network);
      node.transport_kind = core::TransportKind::Loopback;
    }

    handle->core.onMessage = [handle](const session::IncomingMessage& msg) {
      bridge::IncomingMessage bridge_msg = toBridgeMessage(msg);
      if (auto username = handle->core.contactUsername(msg.chat_id)) {
        bridge_msg.peer_username = *username;
      }
      std::string payload = bridge::toJsonPayload(bridge_msg);
      p2pchat_event_cb cb = nullptr;
      void* user_data = nullptr;
      {
        std::lock_guard<std::mutex> lock(handle->callbacks.mutex);
        cb = handle->callbacks.callback;
        user_data = handle->callbacks.user_data;
      }
      if (cb) {
        cb(user_data, P2PCHAT_EVENT_MESSAGE, payload.c_str());
      }
    };
    handle->core.onConnectionChange = [handle](const transport::PeerId& peer, transport::ConnectionState state) {
      bridge::ConnectionEvent event = toBridgeConnection(peer, state);
      if (auto username = handle->core.contactUsername(peer)) {
        event.peer_username = *username;
      }
      std::string payload = bridge::toJsonPayload(event);
      p2pchat_event_cb cb = nullptr;
      void* user_data = nullptr;
      {
        std::lock_guard<std::mutex> lock(handle->callbacks.mutex);
        cb = handle->callbacks.callback;
        user_data = handle->callbacks.user_data;
      }
      if (cb) {
        cb(user_data, P2PCHAT_EVENT_CONNECTION, payload.c_str());
      }
    };
    handle->core.onPeerStatus = [handle](const transport::PeerId& peer, core::PeerStatus status) {
      bridge::PeerStatusEvent event = toBridgePeerStatus(peer, status);
      if (auto username = handle->core.contactUsername(peer)) {
        event.peer_username = *username;
      }
      std::string payload = bridge::toJsonPayload(event);
      p2pchat_event_cb cb = nullptr;
      void* user_data = nullptr;
      {
        std::lock_guard<std::mutex> lock(handle->callbacks.mutex);
        cb = handle->callbacks.callback;
        user_data = handle->callbacks.user_data;
      }
      if (cb) {
        cb(user_data, P2PCHAT_EVENT_PEER_STATUS, payload.c_str());
      }
    };
    handle->core.onError = [handle](const transport::PeerId& peer, const std::string& message) {
      bridge::ErrorEvent event = toBridgeError(peer, message);
      if (auto username = handle->core.contactUsername(peer)) {
        event.peer_username = *username;
      }
      std::string payload = bridge::toJsonPayload(event);
      p2pchat_event_cb cb = nullptr;
      void* user_data = nullptr;
      {
        std::lock_guard<std::mutex> lock(handle->callbacks.mutex);
        cb = handle->callbacks.callback;
        user_data = handle->callbacks.user_data;
      }
      if (cb) {
        cb(user_data, P2PCHAT_EVENT_ERROR, payload.c_str());
      }
    };

    {
      std::lock_guard<std::mutex> lock(handle->core_mutex);
      handle->core.start(node);
    }
    return true;
  } catch (const std::exception& ex) {
    setError(ex.what());
    return false;
  } catch (...) {
    setError("unknown error");
    return false;
  }
}

void p2pchat_stop(p2pchat_handle* handle) {
  if (!handle) {
    return;
  }
  try {
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    handle->core.stop();
  } catch (...) {
  }
}

void p2pchat_tick(p2pchat_handle* handle, int64_t now_ms) {
  if (!handle) {
    return;
  }
  std::lock_guard<std::mutex> lock(handle->core_mutex);
  handle->core.tick(now_ms);
}

char* p2pchat_local_bundle_hex(p2pchat_handle* handle) {
  if (!handle) {
    setError("invalid handle");
    return nullptr;
  }
  try {
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    std::vector<uint8_t> bundle = crypto::serializePreKeyBundle(handle->core.localPreKeyBundle());
    return allocString(bytesToHex(bundle));
  } catch (const std::exception& ex) {
    setError(ex.what());
    return nullptr;
  }
}

char* p2pchat_local_ice(p2pchat_handle* handle) {
  if (!handle) {
    setError("invalid handle");
    return nullptr;
  }
  try {
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    std::string ice = handle->core.localIceDescription();
    return allocString(ice);
  } catch (const std::exception& ex) {
    setError(ex.what());
    return nullptr;
  }
}

char* p2pchat_begin_link(p2pchat_handle* handle) {
  if (!handle) {
    setError("invalid handle");
    return nullptr;
  }
  try {
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    std::string code = handle->core.beginLink();
    return allocString(code);
  } catch (const std::exception& ex) {
    setError(ex.what());
    return nullptr;
  }
}

char* p2pchat_add_contact(p2pchat_handle* handle,
                          const uint8_t* bundle_bytes,
                          size_t bundle_len) {
  if (!handle || !bundle_bytes || bundle_len == 0) {
    setError("invalid bundle");
    return nullptr;
  }
  try {
    std::vector<uint8_t> bytes(bundle_bytes, bundle_bytes + bundle_len);
    crypto::PreKeyBundle bundle = crypto::parsePreKeyBundle(bytes);
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    std::string peer_id = handle->core.addContact(bundle);
    return allocString(peer_id);
  } catch (const std::exception& ex) {
    setError(ex.what());
    return nullptr;
  }
}

char* p2pchat_add_contact_with_username(p2pchat_handle* handle,
                                        const uint8_t* bundle_bytes,
                                        size_t bundle_len,
                                        const char* username) {
  if (!handle || !bundle_bytes || bundle_len == 0) {
    setError("invalid bundle");
    return nullptr;
  }
  if (!username) {
    setError("invalid username");
    return nullptr;
  }
  try {
    std::vector<uint8_t> bytes(bundle_bytes, bundle_bytes + bundle_len);
    crypto::PreKeyBundle bundle = crypto::parsePreKeyBundle(bytes);
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    std::string peer_id = handle->core.addContact(bundle, username);
    return allocString(peer_id);
  } catch (const std::exception& ex) {
    setError(ex.what());
    return nullptr;
  }
}

bool p2pchat_connect_peer(p2pchat_handle* handle, const p2pchat_peer_info* peer) {
  if (!handle || !peer || !peer->peer_id) {
    setError("invalid peer");
    return false;
  }
  try {
    transport::PeerInfo info;
    info.id = peer->peer_id;
    if (peer->address) {
      info.address = peer->address;
      info.port = peer->port;
    }
    if (peer->ice_blob) {
      info.ice_blob = peer->ice_blob;
    }
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    handle->core.connectPeer(info);
    return true;
  } catch (const std::exception& ex) {
    setError(ex.what());
    return false;
  }
}

bool p2pchat_send(p2pchat_handle* handle,
                  const char* chat_id,
                  const uint8_t* payload,
                  size_t payload_len,
                  uint8_t content_type) {
  if (!handle || !chat_id || !payload || payload_len == 0) {
    setError("invalid send payload");
    return false;
  }
  try {
    std::vector<uint8_t> bytes(payload, payload + payload_len);
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    handle->core.send(chat_id, bytes, content_type);
    return true;
  } catch (const std::exception& ex) {
    setError(ex.what());
    return false;
  }
}

char* p2pchat_get_history_json(p2pchat_handle* handle,
                               const char* chat_id,
                               int64_t cursor,
                               size_t limit) {
  if (!handle || !chat_id) {
    setError("invalid history request");
    return nullptr;
  }
  try {
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    auto history = handle->core.getHistory(chat_id, cursor, limit);
    std::string peer_username;
    if (auto username = handle->core.contactUsername(chat_id)) {
      peer_username = *username;
    }
    return allocString(historyJson(history, peer_username));
  } catch (const std::exception& ex) {
    setError(ex.what());
    return nullptr;
  }
}

bool p2pchat_link_device(p2pchat_handle* handle, const char* link_code) {
  if (!handle || !link_code) {
    setError("invalid link code");
    return false;
  }
  try {
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    handle->core.linkDevice(link_code);
    return true;
  } catch (const std::exception& ex) {
    setError(ex.what());
    return false;
  }
}

char* p2pchat_local_username(p2pchat_handle* handle) {
  if (!handle) {
    setError("invalid handle");
    return nullptr;
  }
  try {
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    std::string username = handle->core.localUsername();
    return allocString(username);
  } catch (const std::exception& ex) {
    setError(ex.what());
    return nullptr;
  }
}

char* p2pchat_identity_public_key_hex(p2pchat_handle* handle) {
  if (!handle) {
    setError("invalid handle");
    return nullptr;
  }
  try {
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    std::array<uint8_t, 32> key = handle->core.localIdentityPublicKey();
    std::vector<uint8_t> bytes(key.begin(), key.end());
    return allocString(bytesToHex(bytes));
  } catch (const std::exception& ex) {
    setError(ex.what());
    return nullptr;
  }
}

char* p2pchat_sign_identity_hex(p2pchat_handle* handle,
                                const uint8_t* message_bytes,
                                size_t message_len) {
  if (!handle || !message_bytes || message_len == 0) {
    setError("invalid message");
    return nullptr;
  }
  try {
    std::vector<uint8_t> message(message_bytes, message_bytes + message_len);
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    std::vector<uint8_t> sig = handle->core.signIdentity(message);
    return allocString(bytesToHex(sig));
  } catch (const std::exception& ex) {
    setError(ex.what());
    return nullptr;
  }
}

bool p2pchat_update_profile(p2pchat_handle* handle, const char* username, const char* password) {
  if (!handle) {
    setError("invalid handle");
    return false;
  }
  try {
    std::lock_guard<std::mutex> lock(handle->core_mutex);
    std::string name = username ? username : "";
    std::string pass = password ? password : "";
    handle->core.updateProfile(name, pass);
    return true;
  } catch (const std::exception& ex) {
    setError(ex.what());
    return false;
  }
}

const char* p2pchat_last_error() {
  return g_last_error.empty() ? nullptr : g_last_error.c_str();
}

void p2pchat_clear_error() {
  g_last_error.clear();
}

void p2pchat_string_free(char* value) {
  std::free(value);
}

}  // extern "C"
