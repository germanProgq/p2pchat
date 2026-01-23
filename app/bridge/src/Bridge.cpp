// RN bridge implementation and core adapter. Spec: app/bridge/BridgeSpec.md.
#include "bridge/Bridge.h"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

namespace bridge {

CoreAdapter::CoreAdapter() : core_(std::make_unique<core::Core>()) {
  bindCallbacks();
}

CoreAdapter::CoreAdapter(std::unique_ptr<core::Core> core) : core_(std::move(core)) {
  if (!core_) {
    throw std::runtime_error("core adapter missing core instance");
  }
  bindCallbacks();
}

CoreAdapter::~CoreAdapter() {
  stop();
}

void CoreAdapter::start(const core::NodeConfig& config) {
  core_->start(config);
}

void CoreAdapter::stop() {
  core_->stop();
}

void CoreAdapter::tick(int64_t now_ms) {
  core_->tick(now_ms);
}

std::string CoreAdapter::addContact(const crypto::PreKeyBundle& bundle) {
  return core_->addContact(bundle);
}

void CoreAdapter::send(const std::string& chat_id,
                       const std::vector<uint8_t>& plaintext,
                       uint8_t content_type) {
  core_->send(chat_id, plaintext, content_type);
}

std::vector<session::HistoryMessage> CoreAdapter::getHistory(const std::string& chat_id,
                                                             int64_t start_index,
                                                             size_t limit) const {
  return core_->getHistory(chat_id, start_index, limit);
}

void CoreAdapter::linkDevice(const std::string& link_code) {
  core_->linkDevice(link_code);
}

void CoreAdapter::bindCallbacks() {
  core_->onMessage = [this](const session::IncomingMessage& msg) {
    if (onMessage) {
      onMessage(msg);
    }
  };
  core_->onConnectionChange = [this](const transport::PeerId& peer, transport::ConnectionState state) {
    if (onConnectionChange) {
      onConnectionChange(peer, state);
    }
  };
  core_->onPeerStatus = [this](const transport::PeerId& peer, core::PeerStatus status) {
    if (onPeerStatus) {
      onPeerStatus(peer, status);
    }
  };
  core_->onError = [this](const transport::PeerId& peer, const std::string& message) {
    if (onError) {
      onError(peer, message);
    }
  };
}

Bridge::Bridge(std::shared_ptr<CoreBackend> backend) : backend_(std::move(backend)) {
  if (!backend_) {
    throw std::runtime_error("bridge backend missing");
  }
  bindBackend();
}

void Bridge::start(const NodeConfig& config) {
  backend_->start(toCoreConfig(config));
}

std::string Bridge::addContact(const std::vector<uint8_t>& prekey_bundle) {
  crypto::PreKeyBundle bundle = crypto::parsePreKeyBundle(prekey_bundle);
  return backend_->addContact(bundle);
}

void Bridge::send(const std::string& chat_id, const std::string& text) {
  std::vector<uint8_t> bytes(text.begin(), text.end());
  backend_->send(chat_id, bytes, static_cast<uint8_t>(session::ContentType::Text));
}

void Bridge::send(const std::string& chat_id, const std::vector<uint8_t>& bytes) {
  backend_->send(chat_id, bytes, static_cast<uint8_t>(session::ContentType::Binary));
}

std::vector<HistoryMessage> Bridge::getHistory(const std::string& chat_id,
                                               int64_t start_index,
                                               size_t limit) const {
  std::vector<session::HistoryMessage> history = backend_->getHistory(chat_id, start_index, limit);
  std::vector<HistoryMessage> out;
  out.reserve(history.size());
  for (const auto& msg : history) {
    HistoryMessage converted;
    converted.chat_id = msg.chat_id;
    converted.msg_id = msg.msg_id;
    converted.sender_device = msg.sender_device;
    converted.ts_ms = msg.ts_ms;
    converted.content_type = toBridgeContentType(msg.content_type);
    converted.body = msg.body;
    converted.delivered = msg.delivered;
    converted.acked = msg.acked;
    converted.index = msg.index;
    out.push_back(std::move(converted));
  }
  return out;
}

void Bridge::linkDevice(const std::string& link_code) {
  backend_->linkDevice(link_code);
}

void Bridge::bindBackend() {
  backend_->onMessage = [this](const session::IncomingMessage& msg) {
    if (!onMessage) {
      return;
    }
    IncomingMessage out;
    out.chat_id = msg.chat_id;
    out.msg_id = msg.msg_id;
    out.sender_device = msg.sender_device;
    out.ts_ms = msg.ts_ms;
    out.content_type = toBridgeContentType(msg.content_type);
    out.body = msg.body;
    onMessage(out);
  };
  backend_->onConnectionChange = [this](const transport::PeerId& peer, transport::ConnectionState state) {
    if (!onConnectionChange) {
      return;
    }
    ConnectionEvent event;
    event.peer_id = peer;
    event.state = toBridgeState(state);
    onConnectionChange(event);
  };
  backend_->onPeerStatus = [this](const transport::PeerId& peer, core::PeerStatus status) {
    if (!onPeerStatus) {
      return;
    }
    PeerStatusEvent event;
    event.peer_id = peer;
    event.status = toBridgeStatus(status);
    onPeerStatus(event);
  };
  backend_->onError = [this](const transport::PeerId& peer, const std::string& message) {
    if (!onError) {
      return;
    }
    ErrorEvent event;
    event.peer_id = peer;
    event.message = message;
    onError(event);
  };
}

core::NodeConfig Bridge::toCoreConfig(const NodeConfig& config) const {
  core::NodeConfig out;
  out.identity_path = config.identity_path;
  out.storage_path = config.storage_path;
  out.schema_path = config.schema_path;
  if (!config.master_key.empty()) {
    if (config.master_key.size() != 32) {
      throw std::runtime_error("master key length must be 32 bytes");
    }
    std::array<uint8_t, 32> key{};
    std::copy(config.master_key.begin(), config.master_key.end(), key.begin());
    out.master_key = std::make_shared<identity::InMemoryKeyStore>(key);
  }
  switch (config.transport_kind) {
    case TransportKind::Loopback:
      out.transport_kind = core::TransportKind::Loopback;
      break;
    case TransportKind::Quic:
      out.transport_kind = core::TransportKind::Quic;
      break;
    case TransportKind::WebRtc:
      out.transport_kind = core::TransportKind::WebRtc;
      break;
  }
  out.transport = config.transport;
  out.quic = config.quic;
  out.webrtc = config.webrtc;
  out.loopback_network = config.loopback_network;
  out.one_time_prekeys = config.one_time_prekeys;
  out.signed_prekey_id = config.signed_prekey_id;
  out.one_time_start_id = config.one_time_start_id;
  out.handshake_base_delay_ms = config.handshake_base_delay_ms;
  out.handshake_max_delay_ms = config.handshake_max_delay_ms;
  out.handshake_max_attempts = config.handshake_max_attempts;
  return out;
}

ConnectionState Bridge::toBridgeState(transport::ConnectionState state) {
  switch (state) {
    case transport::ConnectionState::Disconnected:
      return ConnectionState::Disconnected;
    case transport::ConnectionState::Connecting:
      return ConnectionState::Connecting;
    case transport::ConnectionState::Connected:
      return ConnectionState::Connected;
  }
  return ConnectionState::Disconnected;
}

PeerStatus Bridge::toBridgeStatus(core::PeerStatus status) {
  switch (status) {
    case core::PeerStatus::Pending:
      return PeerStatus::Pending;
    case core::PeerStatus::Ready:
      return PeerStatus::Ready;
    case core::PeerStatus::Failed:
      return PeerStatus::Failed;
  }
  return PeerStatus::Failed;
}

ContentType Bridge::toBridgeContentType(uint8_t value) {
  if (value == static_cast<uint8_t>(session::ContentType::Text)) {
    return ContentType::Text;
  }
  return ContentType::Binary;
}

}
