// Core facade implementation coordinating identity, storage, transport, and sessions.
#include "core/Core.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <utility>

#include "crypto/Primitives.h"
#include "transport/Ice.h"

namespace core {

namespace {

constexpr char kHandshakeMagic[4] = {'P', '2', 'P', 'H'};
constexpr uint8_t kHandshakeVersion = 1;
constexpr size_t kSessionIdSize = 16;

enum class HandshakeType : uint8_t {
  Init = 1,
  Ack = 2
};

struct HandshakeFrame {
  HandshakeType type = HandshakeType::Init;
  std::vector<uint8_t> payload;
};

void writeU32(std::vector<uint8_t>& out, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
  }
}

uint32_t readU32(const std::vector<uint8_t>& data, size_t& offset) {
  if (offset + 4 > data.size()) {
    throw std::runtime_error("handshake parse overflow");
  }
  uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<uint32_t>(data[offset + i]) << (8 * i);
  }
  offset += 4;
  return value;
}

std::vector<uint8_t> encodeHandshake(HandshakeType type, const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> out;
  out.reserve(4 + 1 + 1 + 4 + payload.size());
  out.insert(out.end(), kHandshakeMagic, kHandshakeMagic + 4);
  out.push_back(kHandshakeVersion);
  out.push_back(static_cast<uint8_t>(type));
  writeU32(out, static_cast<uint32_t>(payload.size()));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

bool isHandshakeFrame(const std::vector<uint8_t>& bytes) {
  if (bytes.size() < 6) {
    return false;
  }
  return std::memcmp(bytes.data(), kHandshakeMagic, sizeof(kHandshakeMagic)) == 0;
}

HandshakeFrame decodeHandshake(const std::vector<uint8_t>& bytes) {
  if (!isHandshakeFrame(bytes)) {
    throw std::runtime_error("handshake magic mismatch");
  }
  size_t offset = 4;
  uint8_t version = bytes[offset++];
  if (version != kHandshakeVersion) {
    throw std::runtime_error("handshake version mismatch");
  }
  HandshakeFrame frame;
  frame.type = static_cast<HandshakeType>(bytes[offset++]);
  uint32_t length = readU32(bytes, offset);
  if (offset + length > bytes.size()) {
    throw std::runtime_error("handshake length mismatch");
  }
  frame.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                       bytes.begin() + static_cast<std::ptrdiff_t>(offset + length));
  return frame;
}

std::vector<uint8_t> encodeHandshakeInit(const std::vector<uint8_t>& session_id,
                                         const std::vector<uint8_t>& prekey_message) {
  if (session_id.size() != kSessionIdSize) {
    throw std::runtime_error("session id length mismatch");
  }
  std::vector<uint8_t> out;
  out.reserve(kSessionIdSize + 4 + prekey_message.size());
  out.insert(out.end(), session_id.begin(), session_id.end());
  writeU32(out, static_cast<uint32_t>(prekey_message.size()));
  out.insert(out.end(), prekey_message.begin(), prekey_message.end());
  return out;
}

void decodeHandshakeInit(const std::vector<uint8_t>& payload,
                         std::vector<uint8_t>& session_id,
                         std::vector<uint8_t>& prekey_message) {
  if (payload.size() < kSessionIdSize + 4) {
    throw std::runtime_error("handshake init truncated");
  }
  session_id.assign(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(kSessionIdSize));
  size_t offset = kSessionIdSize;
  uint32_t length = readU32(payload, offset);
  if (offset + length > payload.size()) {
    throw std::runtime_error("handshake init length mismatch");
  }
  prekey_message.assign(payload.begin() + static_cast<std::ptrdiff_t>(offset),
                        payload.begin() + static_cast<std::ptrdiff_t>(offset + length));
}

std::vector<uint8_t> encodeHandshakeAck(const std::vector<uint8_t>& session_id, uint8_t status) {
  if (session_id.size() != kSessionIdSize) {
    throw std::runtime_error("session id length mismatch");
  }
  std::vector<uint8_t> out;
  out.reserve(kSessionIdSize + 1);
  out.insert(out.end(), session_id.begin(), session_id.end());
  out.push_back(status);
  return out;
}

void decodeHandshakeAck(const std::vector<uint8_t>& payload,
                        std::vector<uint8_t>& session_id,
                        uint8_t& status) {
  if (payload.size() != kSessionIdSize + 1) {
    throw std::runtime_error("handshake ack length mismatch");
  }
  session_id.assign(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(kSessionIdSize));
  status = payload.back();
}

int64_t nowMs() {
  using namespace std::chrono;
  return static_cast<int64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::vector<uint8_t> u32ToBytes(uint32_t value) {
  std::vector<uint8_t> out;
  writeU32(out, value);
  return out;
}

uint32_t u32FromBytes(const std::vector<uint8_t>& data, uint32_t fallback) {
  if (data.size() != 4) {
    return fallback;
  }
  size_t offset = 0;
  return readU32(data, offset);
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

std::vector<uint8_t> hexToBytes(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    throw std::runtime_error("hex length mismatch");
  }
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
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
    throw std::runtime_error("invalid hex character");
  };
  for (size_t i = 0; i < hex.size(); i += 2) {
    uint8_t hi = nibble(hex[i]);
    uint8_t lo = nibble(hex[i + 1]);
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

std::string userIdFromDevice(const std::array<uint8_t, 32>& ed25519_public) {
  std::array<uint8_t, 32> user_id = identity::IdentityStore::userIdFromPublicKey(ed25519_public);
  return identity::IdentityStore::toHex(user_id);
}

crypto::SignedPreKeyPair decodeSignedPrekey(const storage::PrekeyRecord& record) {
  if (record.public_key.size() != 96 || record.secret.size() != 32) {
    throw std::runtime_error("signed prekey record invalid");
  }
  crypto::SignedPreKeyPair prekey;
  prekey.id = static_cast<uint32_t>(record.id);
  std::copy(record.secret.begin(), record.secret.end(), prekey.key_pair.private_key.begin());
  std::copy(record.public_key.begin(), record.public_key.begin() + 32, prekey.key_pair.public_key.begin());
  std::copy(record.public_key.begin() + 32, record.public_key.end(), prekey.signature.begin());
  return prekey;
}

crypto::OneTimePreKeyPair decodeOneTimePrekey(const storage::PrekeyRecord& record) {
  if (record.public_key.size() != 32 || record.secret.size() != 32) {
    throw std::runtime_error("one-time prekey record invalid");
  }
  crypto::OneTimePreKeyPair prekey;
  prekey.id = static_cast<uint32_t>(record.id);
  std::copy(record.secret.begin(), record.secret.end(), prekey.key_pair.private_key.begin());
  std::copy(record.public_key.begin(), record.public_key.end(), prekey.key_pair.public_key.begin());
  return prekey;
}

storage::PrekeyRecord encodeSignedPrekey(const crypto::SignedPreKeyPair& prekey) {
  storage::PrekeyRecord record;
  record.id = prekey.id;
  record.public_key.insert(record.public_key.end(), prekey.key_pair.public_key.begin(), prekey.key_pair.public_key.end());
  record.public_key.insert(record.public_key.end(), prekey.signature.begin(), prekey.signature.end());
  record.secret.assign(prekey.key_pair.private_key.begin(), prekey.key_pair.private_key.end());
  record.used = false;
  return record;
}

storage::PrekeyRecord encodeOneTimePrekey(const crypto::OneTimePreKeyPair& prekey) {
  storage::PrekeyRecord record;
  record.id = prekey.id;
  record.public_key.assign(prekey.key_pair.public_key.begin(), prekey.key_pair.public_key.end());
  record.secret.assign(prekey.key_pair.private_key.begin(), prekey.key_pair.private_key.end());
  record.used = false;
  return record;
}

int64_t nextDelay(int64_t base_delay, int64_t max_delay, uint32_t attempts) {
  int64_t delay = base_delay;
  for (uint32_t i = 0; i < attempts; ++i) {
    if (delay >= max_delay) {
      return max_delay;
    }
    delay = std::min(max_delay, delay * 2);
  }
  return std::min(delay, max_delay);
}

}

Core::Core() = default;

Core::~Core() {
  stop();
}

void Core::start(const NodeConfig& config) {
  if (running_) {
    return;
  }
  config_ = config;
  if (config_.identity_path.empty() || config_.storage_path.empty() || config_.schema_path.empty()) {
    throw std::runtime_error("core paths missing");
  }
  if (!config_.master_key) {
    config_.master_key = std::make_shared<identity::OsKeyStore>("p2pchat.master");
  }
  identity_store_ = std::make_unique<identity::IdentityStore>(identity::IdentityStore::Options{config_.identity_path, config_.master_key});
  if (identity_store_->exists()) {
    identity_ = identity_store_->load();
  } else {
    identity_ = identity_store_->createNew();
  }
  storage::StorageOptions options;
  options.path = config_.storage_path;
  options.schema_path = config_.schema_path;
  options.master_key = config_.master_key;
  storage_ = std::make_unique<storage::Storage>(options);
  storage_->open();

  ensurePreKeys();

  std::string local_peer = userIdFromDevice(activeDevice().ed25519_public);
  switch (config_.transport_kind) {
    case TransportKind::Loopback: {
      if (!config_.loopback_network) {
        throw std::runtime_error("loopback network missing");
      }
      transport_ = std::make_unique<transport::LoopbackTransport>(local_peer, *config_.loopback_network, config_.transport);
      break;
    }
    case TransportKind::Quic: {
      transport_ = std::make_unique<transport::QuicTransport>(local_peer, config_.quic, config_.transport);
      break;
    }
    case TransportKind::WebRtc: {
      transport_ = std::make_unique<transport::WebRtcTransport>(local_peer, config_.webrtc, config_.transport);
      break;
    }
  }

  session_manager_ = std::make_unique<session::SessionManager>(session::SessionManagerConfig{storage_.get(), transport_.get()});
  session_manager_->onMessage = [this](const session::IncomingMessage& msg) {
    if (onMessage) {
      onMessage(msg);
    }
  };
  session_manager_->onError = [this](const transport::PeerId& peer, const std::string& err) {
    if (onError) {
      onError(peer, err);
    }
  };
  session_manager_->start();
  for (const auto& peer_id : storage_->listSessionPeers()) {
    session_manager_->loadSession(peer_id);
  }

  transport_->onReceive = [this](const transport::PeerId& peer, transport::Frame&& frame) {
    handleTransportReceive(peer, std::move(frame));
  };
  transport_->onAck = [this](const transport::PeerId& peer, transport::FrameId id) {
    handleTransportAck(peer, id);
  };
  transport_->onSendFailed = [this](const transport::PeerId& peer,
                                    transport::FrameId id,
                                    transport::SendFailure reason) {
    handleTransportSendFailed(peer, id, reason);
  };
  transport_->onConnectionState = [this](const transport::PeerId& peer, transport::ConnectionState state) {
    handleTransportConnection(peer, state);
  };
  transport_->onWritable = [this](const transport::PeerId& peer, bool writable) {
    handleTransportWritable(peer, writable);
  };

  running_ = true;
}

void Core::stop() {
  running_ = false;
  pending_handshakes_.clear();
  peer_info_.clear();
  session_manager_.reset();
  transport_.reset();
  if (storage_) {
    storage_->close();
  }
  storage_.reset();
  identity_store_.reset();
}

void Core::tick(int64_t now_ms) {
  if (!running_) {
    return;
  }
  session_manager_->tick(now_ms);
  for (auto& entry : pending_handshakes_) {
    if (entry.second.attempts >= config_.handshake_max_attempts) {
      if (!entry.second.failed_notified) {
        if (onPeerStatus) {
          onPeerStatus(entry.first, PeerStatus::Failed);
        }
        entry.second.failed_notified = true;
      }
      continue;
    }
    if (now_ms >= entry.second.next_retry_ms) {
      sendHandshakeInit(entry.first);
    }
  }
}

std::string Core::localUserId() const {
  return userIdFromDevice(activeDevice().ed25519_public);
}

crypto::PreKeyBundle Core::localPreKeyBundle() const {
  auto signed_prekey_record = storage_->loadPrekey(config_.signed_prekey_id);
  if (!signed_prekey_record) {
    throw std::runtime_error("signed prekey missing");
  }
  crypto::SignedPreKeyPair signed_prekey = decodeSignedPrekey(*signed_prekey_record);
  std::optional<storage::PrekeyRecord> one_time = storage_->loadUnusedPrekey(config_.one_time_start_id);
  std::optional<crypto::OneTimePreKeyPublic> one_time_public;
  if (one_time.has_value()) {
    if (one_time->public_key.size() != 32) {
      throw std::runtime_error("one-time prekey public invalid");
    }
    crypto::OneTimePreKeyPublic pub;
    pub.id = static_cast<uint32_t>(one_time->id);
    std::copy(one_time->public_key.begin(), one_time->public_key.end(), pub.public_key.begin());
    one_time_public = pub;
  }
  identity::DeviceKeyPair device = activeDevice();
  return crypto::createPreKeyBundle(device, signed_prekey, one_time_public, 0);
}

std::string Core::localIceDescription() const {
  if (!transport_) {
    return {};
  }
  if (auto* quic = dynamic_cast<transport::QuicTransport*>(transport_.get())) {
    return quic->localIceDescription();
  }
  if (auto* rtc = dynamic_cast<transport::WebRtcTransport*>(transport_.get())) {
    return rtc->localIceDescription();
  }
  return {};
}

std::string Core::beginLink() const {
  return encodeLinkBundle(localPreKeyBundle());
}

std::string Core::addContact(const crypto::PreKeyBundle& bundle) {
  identity::DeviceKeyPair device = activeDevice();
  crypto::InitiatorKeys initiator;
  initiator.identity_ed25519 = device.ed25519_public;
  initiator.identity_x25519_public = device.x25519_public;
  initiator.identity_x25519_private = device.x25519_private;

  crypto::InitiatorResult init = crypto::initiateX3DH(initiator, bundle, std::nullopt);
  std::vector<uint8_t> prekey_bytes = crypto::serializePreKeyMessage(init.message);
  std::vector<uint8_t> session_id = crypto::randomBytes(kSessionIdSize);

  crypto::Ratchet ratchet = crypto::Ratchet::initInitiator(init.root_key,
                                                           init.ratchet_key,
                                                           init.remote_ratchet_pub);
  std::string peer_id = userIdFromDevice(bundle.identity_ed25519);
  session_manager_->addSession(peer_id, session_id, ratchet);

  PendingHandshake pending;
  pending.session_id = session_id;
  pending.prekey_message = prekey_bytes;
  pending.attempts = 0;
  pending.next_retry_ms = 0;
  pending_handshakes_[peer_id] = std::move(pending);
  if (onPeerStatus) {
    onPeerStatus(peer_id, PeerStatus::Pending);
  }

  if (transport_->state(peer_id) == transport::ConnectionState::Connected) {
    sendHandshakeInit(peer_id);
  }
  return peer_id;
}

void Core::connectPeer(const transport::PeerInfo& info) {
  peer_info_[info.id] = info;
  transport_->connect(info);
  if (pending_handshakes_.find(info.id) != pending_handshakes_.end()) {
    sendHandshakeInit(info.id);
  }
}

void Core::send(const std::string& chat_id,
                const std::vector<uint8_t>& plaintext,
                uint8_t content_type) {
  session_manager_->sendMessage(chat_id, chat_id, plaintext, content_type);
}

std::vector<session::HistoryMessage> Core::getHistory(const std::string& chat_id,
                                                      int64_t start_index,
                                                      size_t limit) const {
  return session_manager_->getHistory(chat_id, start_index, limit);
}

void Core::linkDevice(const std::string& link_code) {
  crypto::PreKeyBundle bundle = decodeLinkBundle(link_code);
  addContact(bundle);
}

void Core::ensurePreKeys() {
  auto signed_meta = storage_->getMeta("signed_prekey_id");
  if (!signed_meta) {
    storage_->setMeta("signed_prekey_id", u32ToBytes(config_.signed_prekey_id));
  }
  auto signed_record = storage_->loadPrekey(config_.signed_prekey_id);
  if (!signed_record || signed_record->public_key.size() != 96) {
    identity::DeviceKeyPair device = activeDevice();
    crypto::SignedPreKeyPair signed_prekey = crypto::createSignedPreKey(device, config_.signed_prekey_id);
    storage_->storePrekey(encodeSignedPrekey(signed_prekey));
  }

  auto next_id_blob = storage_->getMeta("one_time_next_id");
  uint32_t next_id = next_id_blob ? u32FromBytes(*next_id_blob, config_.one_time_start_id) : config_.one_time_start_id;
  if (!next_id_blob) {
    storage_->setMeta("one_time_next_id", u32ToBytes(next_id));
  }

  int64_t available = storage_->countUnusedPrekeys(config_.one_time_start_id);
  while (available < static_cast<int64_t>(config_.one_time_prekeys)) {
    crypto::OneTimePreKeyPair prekey = crypto::createOneTimePreKey(next_id);
    storage_->storePrekey(encodeOneTimePrekey(prekey));
    next_id += 1;
    available += 1;
  }
  storage_->setMeta("one_time_next_id", u32ToBytes(next_id));
}

identity::DeviceKeyPair Core::activeDevice() const {
  for (const auto& device : identity_.devices) {
    if (device.device_id == identity_.active_device_id) {
      return device;
    }
  }
  if (!identity_.devices.empty()) {
    return identity_.devices.front();
  }
  throw std::runtime_error("identity has no devices");
}

void Core::handleTransportReceive(const transport::PeerId& peer, transport::Frame&& frame) {
  if (!running_) {
    return;
  }
  try {
    if (isHandshakeFrame(frame.bytes)) {
      HandshakeFrame handshake = decodeHandshake(frame.bytes);
      if (handshake.type == HandshakeType::Init) {
        handleHandshakeInit(peer, handshake.payload);
      } else if (handshake.type == HandshakeType::Ack) {
        handleHandshakeAck(peer, handshake.payload);
      }
      return;
    }
    if (session_manager_->hasSession(peer)) {
      session_manager_->onTransportReceive(peer, std::move(frame));
    }
  } catch (const std::exception& ex) {
    if (onError) {
      onError(peer, ex.what());
    }
  }
}

void Core::handleTransportAck(const transport::PeerId& peer, transport::FrameId id) {
  if (session_manager_) {
    session_manager_->onTransportAck(peer, id);
  }
}

void Core::handleTransportSendFailed(const transport::PeerId& peer,
                                     transport::FrameId id,
                                     transport::SendFailure reason) {
  if (session_manager_) {
    session_manager_->onTransportSendFailed(peer, id, reason);
  }
}

void Core::handleTransportConnection(const transport::PeerId& peer, transport::ConnectionState state) {
  if (session_manager_) {
    session_manager_->onTransportConnection(peer, state);
  }
  if (onConnectionChange) {
    onConnectionChange(peer, state);
  }
  if (state == transport::ConnectionState::Connected) {
    auto pending = pending_handshakes_.find(peer);
    if (pending != pending_handshakes_.end()) {
      sendHandshakeInit(peer);
    }
  }
}

void Core::handleTransportWritable(const transport::PeerId& peer, bool writable) {
  if (session_manager_) {
    session_manager_->onTransportWritable(peer, writable);
  }
  if (writable) {
    auto pending = pending_handshakes_.find(peer);
    if (pending != pending_handshakes_.end()) {
      sendHandshakeInit(peer);
    }
  }
}

void Core::handleHandshakeInit(const transport::PeerId& peer, const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> session_id;
  std::vector<uint8_t> prekey_message;
  decodeHandshakeInit(payload, session_id, prekey_message);

  crypto::PreKeyMessage message = crypto::parsePreKeyMessage(prekey_message);
  auto signed_record = storage_->loadPrekey(message.signed_prekey_id);
  if (!signed_record) {
    throw std::runtime_error("signed prekey not found");
  }
  crypto::SignedPreKeyPair signed_prekey = decodeSignedPrekey(*signed_record);

  std::optional<crypto::OneTimePreKeyPair> one_time;
  if (message.flags & 0x01) {
    auto one_time_record = storage_->loadPrekey(message.one_time_prekey_id);
    if (!one_time_record) {
      throw std::runtime_error("one-time prekey not found");
    }
    one_time = decodeOneTimePrekey(*one_time_record);
    storage_->markPrekeyUsed(message.one_time_prekey_id);
  }

  identity::DeviceKeyPair device = activeDevice();
  crypto::ResponderResult responder = crypto::respondX3DH(message, device, signed_prekey, one_time);
  crypto::Ratchet ratchet = crypto::Ratchet::initResponder(responder.root_key,
                                                           signed_prekey.key_pair,
                                                           responder.remote_ratchet_pub);
  session_manager_->addSession(peer, session_id, ratchet);
  if (onPeerStatus) {
    onPeerStatus(peer, PeerStatus::Ready);
  }

  std::vector<uint8_t> ack_payload = encodeHandshakeAck(session_id, 0);
  std::vector<uint8_t> ack_frame = encodeHandshake(HandshakeType::Ack, ack_payload);
  transport_->send(peer, transport::Frame{ack_frame});
}

void Core::handleHandshakeAck(const transport::PeerId& peer, const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> session_id;
  uint8_t status = 0;
  decodeHandshakeAck(payload, session_id, status);
  if (status != 0) {
    if (onPeerStatus) {
      onPeerStatus(peer, PeerStatus::Failed);
    }
    throw std::runtime_error("handshake rejected");
  }
  pending_handshakes_.erase(peer);
  if (onPeerStatus) {
    onPeerStatus(peer, PeerStatus::Ready);
  }
}

void Core::sendHandshakeInit(const transport::PeerId& peer) {
  auto it = pending_handshakes_.find(peer);
  if (it == pending_handshakes_.end()) {
    return;
  }
  PendingHandshake& pending = it->second;
  std::vector<uint8_t> init_payload = encodeHandshakeInit(pending.session_id, pending.prekey_message);
  std::vector<uint8_t> frame_bytes = encodeHandshake(HandshakeType::Init, init_payload);
  transport_->send(peer, transport::Frame{frame_bytes});
  pending.attempts += 1;
  int64_t delay = nextDelay(config_.handshake_base_delay_ms, config_.handshake_max_delay_ms, pending.attempts - 1);
  pending.next_retry_ms = nowMs() + delay;
}

std::string Core::encodeLinkBundle(const crypto::PreKeyBundle& bundle) const {
  return bytesToHex(crypto::serializePreKeyBundle(bundle));
}

crypto::PreKeyBundle Core::decodeLinkBundle(const std::string& link_code) const {
  return crypto::parsePreKeyBundle(hexToBytes(link_code));
}

}
