// RN bridge implementation and core adapter. Spec: app/bridge/BridgeSpec.md.
#include "bridge/Bridge.h"

#include <algorithm>
#include <array>
#include <optional>
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

std::vector<uint8_t> CoreAdapter::localBundle() const {
  return crypto::serializePreKeyBundle(core_->localPreKeyBundle());
}

std::string CoreAdapter::localIce() const {
  return core_->localIceDescription();
}

std::string CoreAdapter::beginLink() const {
  return core_->beginLink();
}

void CoreAdapter::tick(int64_t now_ms) {
  core_->tick(now_ms);
}

std::string CoreAdapter::addContact(const crypto::PreKeyBundle& bundle) {
  return core_->addContact(bundle);
}

std::string CoreAdapter::addContactWithUsername(const crypto::PreKeyBundle& bundle, const std::string& username) {
  return core_->addContact(bundle, username);
}

void CoreAdapter::connectPeer(const transport::PeerInfo& info) {
  core_->connectPeer(info);
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

std::optional<std::string> CoreAdapter::lookupUsername(const std::string& peer_id) const {
  return core_->contactUsername(peer_id);
}

std::string CoreAdapter::localUsername() const {
  return core_->localUsername();
}

std::vector<uint8_t> CoreAdapter::localIdentityPublicKey() const {
  std::array<uint8_t, 32> key = core_->localIdentityPublicKey();
  return std::vector<uint8_t>(key.begin(), key.end());
}

std::vector<uint8_t> CoreAdapter::signIdentity(const std::vector<uint8_t>& message) const {
  return core_->signIdentity(message);
}

void CoreAdapter::updateProfile(const std::string& username, const std::string& password) {
  core_->updateProfile(username, password);
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

std::vector<uint8_t> Bridge::localBundle() const {
  return backend_->localBundle();
}

std::string Bridge::localIce() const {
  return backend_->localIce();
}

std::string Bridge::beginLink() const {
  return backend_->beginLink();
}

std::string Bridge::addContact(const std::vector<uint8_t>& prekey_bundle) {
  crypto::PreKeyBundle bundle = crypto::parsePreKeyBundle(prekey_bundle);
  return backend_->addContact(bundle);
}

std::string Bridge::addContactWithUsername(const std::vector<uint8_t>& prekey_bundle, const std::string& username) {
  crypto::PreKeyBundle bundle = crypto::parsePreKeyBundle(prekey_bundle);
  return backend_->addContactWithUsername(bundle, username);
}

void Bridge::connectPeer(const PeerInfo& info) {
  transport::PeerInfo peer;
  peer.id = info.peer_id;
  peer.address = info.address;
  peer.port = info.port;
  peer.ice_blob = info.ice_blob;
  backend_->connectPeer(peer);
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
  std::optional<std::string> peer_username = backend_->lookupUsername(chat_id);
  for (const auto& msg : history) {
    HistoryMessage converted;
    converted.chat_id = msg.chat_id;
    converted.msg_id = msg.msg_id;
    converted.sender_device = msg.sender_device;
    converted.peer_username = peer_username.value_or("");
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

std::string Bridge::localUsername() const {
  return backend_->localUsername();
}

std::vector<uint8_t> Bridge::localIdentityPublicKey() const {
  return backend_->localIdentityPublicKey();
}

std::vector<uint8_t> Bridge::signIdentity(const std::vector<uint8_t>& message) const {
  return backend_->signIdentity(message);
}

void Bridge::updateProfile(const std::string& username, const std::string& password) {
  backend_->updateProfile(username, password);
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
    out.peer_username = backend_->lookupUsername(msg.chat_id).value_or("");
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
    event.peer_username = backend_->lookupUsername(peer).value_or("");
    event.state = toBridgeState(state);
    onConnectionChange(event);
  };
  backend_->onPeerStatus = [this](const transport::PeerId& peer, core::PeerStatus status) {
    if (!onPeerStatus) {
      return;
    }
    PeerStatusEvent event;
    event.peer_id = peer;
    event.peer_username = backend_->lookupUsername(peer).value_or("");
    event.status = toBridgeStatus(status);
    onPeerStatus(event);
  };
  backend_->onError = [this](const transport::PeerId& peer, const std::string& message) {
    if (!onError) {
      return;
    }
    ErrorEvent event;
    event.peer_id = peer;
    event.peer_username = backend_->lookupUsername(peer).value_or("");
    event.message = message;
    onError(event);
  };
}

core::NodeConfig Bridge::toCoreConfig(const NodeConfig& config) const {
  core::NodeConfig out;
  out.identity_path = config.identity_path;
  out.storage_path = config.storage_path;
  out.schema_path = config.schema_path;
  out.username = config.username;
  out.password = config.password;
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
