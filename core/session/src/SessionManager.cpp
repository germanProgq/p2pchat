// Session and sync manager implementation.
#include "session/SessionManager.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <utility>

#include "crypto/Primitives.h"

namespace session {

namespace {

constexpr uint8_t kProtoVersion = 1;
constexpr size_t kSessionIdSize = 16;
constexpr size_t kNonceSize = 12;
constexpr size_t kTagSize = 16;
constexpr size_t kHeaderSize = 1 + 1 + 1 + 1 + kSessionIdSize + 8 + kNonceSize + 4;
constexpr uint8_t kStoredPayloadVersion = 1;

enum class FrameType : uint8_t {
  AppMsg = 1,
  Ack = 2,
  SyncHello = 3,
  SyncChunk = 4,
  SyncAck = 5,
  KeyUpdate = 6,
  Pong = 7
};

struct FrameHeader {
  uint8_t version = 0;
  FrameType type = FrameType::AppMsg;
  uint8_t flags = 0;
  uint8_t reserved = 0;
  std::array<uint8_t, kSessionIdSize> session_id{};
  uint64_t counter = 0;
  std::array<uint8_t, kNonceSize> nonce{};
  uint32_t payload_len = 0;
};

int64_t nowMs() {
  using namespace std::chrono;
  return static_cast<int64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

void writeU8(std::vector<uint8_t>& out, uint8_t value) {
  out.push_back(value);
}

void writeU32(std::vector<uint8_t>& out, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
  }
}

void writeU64(std::vector<uint8_t>& out, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
  }
}

void writeI64(std::vector<uint8_t>& out, int64_t value) {
  writeU64(out, static_cast<uint64_t>(value));
}

uint8_t readU8(const std::vector<uint8_t>& data, size_t& offset) {
  if (offset + 1 > data.size()) {
    throw std::runtime_error("parse out of bounds");
  }
  return data[offset++];
}

uint32_t readU32(const std::vector<uint8_t>& data, size_t& offset) {
  if (offset + 4 > data.size()) {
    throw std::runtime_error("parse out of bounds");
  }
  uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<uint32_t>(data[offset + i]) << (8 * i);
  }
  offset += 4;
  return value;
}

uint64_t readU64(const std::vector<uint8_t>& data, size_t& offset) {
  if (offset + 8 > data.size()) {
    throw std::runtime_error("parse out of bounds");
  }
  uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(data[offset + i]) << (8 * i);
  }
  offset += 8;
  return value;
}

int64_t readI64(const std::vector<uint8_t>& data, size_t& offset) {
  return static_cast<int64_t>(readU64(data, offset));
}

void writeBytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& bytes) {
  writeU32(out, static_cast<uint32_t>(bytes.size()));
  out.insert(out.end(), bytes.begin(), bytes.end());
}

std::vector<uint8_t> readBytes(const std::vector<uint8_t>& data, size_t& offset) {
  uint32_t len = readU32(data, offset);
  if (offset + len > data.size()) {
    throw std::runtime_error("parse out of bounds");
  }
  std::vector<uint8_t> out(data.begin() + static_cast<std::ptrdiff_t>(offset),
                           data.begin() + static_cast<std::ptrdiff_t>(offset + len));
  offset += len;
  return out;
}

void writeString(std::vector<uint8_t>& out, const std::string& value) {
  writeU32(out, static_cast<uint32_t>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
}

std::string readString(const std::vector<uint8_t>& data, size_t& offset) {
  uint32_t len = readU32(data, offset);
  if (offset + len > data.size()) {
    throw std::runtime_error("parse out of bounds");
  }
  std::string out(data.begin() + static_cast<std::ptrdiff_t>(offset),
                  data.begin() + static_cast<std::ptrdiff_t>(offset + len));
  offset += len;
  return out;
}

std::vector<uint8_t> encodeHeader(const FrameHeader& header) {
  std::vector<uint8_t> out;
  out.reserve(kHeaderSize);
  out.push_back(header.version);
  out.push_back(static_cast<uint8_t>(header.type));
  out.push_back(header.flags);
  out.push_back(header.reserved);
  out.insert(out.end(), header.session_id.begin(), header.session_id.end());
  writeU64(out, header.counter);
  out.insert(out.end(), header.nonce.begin(), header.nonce.end());
  writeU32(out, header.payload_len);
  return out;
}

FrameHeader decodeHeader(const std::vector<uint8_t>& data) {
  if (data.size() < kHeaderSize) {
    throw std::runtime_error("frame header truncated");
  }
  size_t offset = 0;
  FrameHeader header;
  header.version = readU8(data, offset);
  header.type = static_cast<FrameType>(readU8(data, offset));
  header.flags = readU8(data, offset);
  header.reserved = readU8(data, offset);
  std::memcpy(header.session_id.data(), data.data() + offset, header.session_id.size());
  offset += header.session_id.size();
  header.counter = readU64(data, offset);
  std::memcpy(header.nonce.data(), data.data() + offset, header.nonce.size());
  offset += header.nonce.size();
  header.payload_len = readU32(data, offset);
  return header;
}

std::array<uint8_t, 32> deriveFrameKey(const storage::SessionState& state) {
  std::vector<uint8_t> info = {'p','2','p','c','h','a','t','.','f','r','a','m','e','.','v','1'};
  std::vector<uint8_t> salt(state.session_id.begin(), state.session_id.end());
  std::vector<uint8_t> ikm(state.root_key.begin(), state.root_key.end());
  std::vector<uint8_t> okm = crypto::hkdfSha256(ikm, salt, info, 32);
  if (okm.size() != 32) {
    throw std::runtime_error("frame key length mismatch");
  }
  std::array<uint8_t, 32> key{};
  std::copy(okm.begin(), okm.end(), key.begin());
  return key;
}

std::array<uint8_t, kSessionIdSize> sessionIdToArray(const std::vector<uint8_t>& session_id) {
  if (session_id.size() != kSessionIdSize) {
    throw std::runtime_error("session id length mismatch");
  }
  std::array<uint8_t, kSessionIdSize> out{};
  std::copy(session_id.begin(), session_id.end(), out.begin());
  return out;
}

std::vector<uint8_t> randomPadding(size_t max_len) {
  if (max_len == 0) {
    return {};
  }
  size_t pad_len = crypto::randomBytes(1)[0] % (max_len + 1);
  if (pad_len == 0) {
    return {};
  }
  return crypto::randomBytes(pad_len);
}

std::string randomIdHex(size_t bytes) {
  std::vector<uint8_t> raw = crypto::randomBytes(bytes);
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(raw.size() * 2);
  for (uint8_t b : raw) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

std::vector<uint8_t> encodeRatchetMessage(const crypto::RatchetMessage& msg) {
  std::vector<uint8_t> out;
  std::vector<uint8_t> header = crypto::Ratchet::serializeHeader(msg.header);
  out.insert(out.end(), header.begin(), header.end());
  writeU32(out, static_cast<uint32_t>(msg.ciphertext.size()));
  out.insert(out.end(), msg.ciphertext.begin(), msg.ciphertext.end());
  out.insert(out.end(), msg.tag.begin(), msg.tag.end());
  return out;
}

crypto::RatchetMessage decodeRatchetMessage(const std::vector<uint8_t>& data) {
  if (data.size() < 40 + 4 + kTagSize) {
    throw std::runtime_error("ratchet message truncated");
  }
  crypto::RatchetMessage msg;
  std::vector<uint8_t> header_bytes(data.begin(), data.begin() + 40);
  msg.header = crypto::Ratchet::parseHeader(header_bytes);
  size_t offset = 40;
  uint32_t cipher_len = readU32(data, offset);
  if (offset + cipher_len + kTagSize > data.size()) {
    throw std::runtime_error("ratchet message length mismatch");
  }
  msg.ciphertext.assign(data.begin() + static_cast<std::ptrdiff_t>(offset),
                        data.begin() + static_cast<std::ptrdiff_t>(offset + cipher_len));
  offset += cipher_len;
  std::memcpy(msg.tag.data(), data.data() + offset, msg.tag.size());
  return msg;
}

std::vector<uint8_t> encodeStoredPayload(uint8_t content_type,
                                         const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& ratchet_bytes) {
  std::vector<uint8_t> out;
  out.push_back(kStoredPayloadVersion);
  out.push_back(content_type);
  writeBytes(out, plaintext);
  writeBytes(out, ratchet_bytes);
  return out;
}

struct StoredPayload {
  uint8_t content_type = 0;
  std::vector<uint8_t> plaintext;
  std::vector<uint8_t> ratchet_bytes;
};

StoredPayload decodeStoredPayload(const std::vector<uint8_t>& data) {
  if (data.size() < 2) {
    throw std::runtime_error("stored payload truncated");
  }
  size_t offset = 0;
  uint8_t version = readU8(data, offset);
  if (version != kStoredPayloadVersion) {
    throw std::runtime_error("stored payload version mismatch");
  }
  StoredPayload payload;
  payload.content_type = readU8(data, offset);
  payload.plaintext = readBytes(data, offset);
  payload.ratchet_bytes = readBytes(data, offset);
  return payload;
}

std::vector<uint8_t> encodeAppPayload(const IncomingMessage& message,
                                      const std::vector<uint8_t>& ratchet_bytes) {
  std::vector<uint8_t> out;
  writeString(out, message.chat_id);
  writeString(out, message.msg_id);
  writeI64(out, message.ts_ms);
  writeU8(out, message.content_type);
  writeBytes(out, ratchet_bytes);
  return out;
}

IncomingMessage decodeAppPayload(const std::vector<uint8_t>& data,
                                 std::vector<uint8_t>& ratchet_bytes) {
  size_t offset = 0;
  IncomingMessage msg;
  msg.chat_id = readString(data, offset);
  msg.msg_id = readString(data, offset);
  msg.ts_ms = readI64(data, offset);
  msg.content_type = readU8(data, offset);
  ratchet_bytes = readBytes(data, offset);
  return msg;
}

std::vector<uint8_t> encodeAckPayload(const std::string& chat_id, const std::string& msg_id) {
  std::vector<uint8_t> out;
  writeString(out, chat_id);
  writeString(out, msg_id);
  return out;
}

void decodeAckPayload(const std::vector<uint8_t>& data, std::string& chat_id, std::string& msg_id) {
  size_t offset = 0;
  chat_id = readString(data, offset);
  msg_id = readString(data, offset);
}

std::vector<uint8_t> encodeSyncHelloPayload(const std::string& chat_id,
                                            int64_t last_index,
                                            const storage::BloomFilter& bloom) {
  std::vector<uint8_t> out;
  writeString(out, chat_id);
  writeI64(out, last_index);
  writeU32(out, bloom.bitCount());
  writeU32(out, bloom.hashCount());
  writeU64(out, bloom.seed());
  writeBytes(out, bloom.bytes());
  return out;
}

struct SyncHelloPayload {
  std::string chat_id;
  int64_t last_index = 0;
  uint32_t bloom_bits = 0;
  uint32_t bloom_hashes = 0;
  uint64_t bloom_seed = 0;
  std::vector<uint8_t> bloom_bytes;
};

SyncHelloPayload decodeSyncHelloPayload(const std::vector<uint8_t>& data) {
  size_t offset = 0;
  SyncHelloPayload payload;
  payload.chat_id = readString(data, offset);
  payload.last_index = readI64(data, offset);
  payload.bloom_bits = readU32(data, offset);
  payload.bloom_hashes = readU32(data, offset);
  payload.bloom_seed = readU64(data, offset);
  payload.bloom_bytes = readBytes(data, offset);
  return payload;
}

struct SyncChunkItem {
  int64_t index = 0;
  std::string msg_id;
  std::string sender_device;
  int64_t ts_ms = 0;
  uint8_t content_type = 0;
  std::vector<uint8_t> ratchet_bytes;
};

std::vector<uint8_t> encodeSyncChunkPayload(const std::string& chat_id,
                                            uint64_t chunk_id,
                                            const std::vector<SyncChunkItem>& items) {
  std::vector<uint8_t> out;
  writeString(out, chat_id);
  writeU64(out, chunk_id);
  writeU32(out, static_cast<uint32_t>(items.size()));
  for (const auto& item : items) {
    writeI64(out, item.index);
    writeString(out, item.msg_id);
    writeString(out, item.sender_device);
    writeI64(out, item.ts_ms);
    writeU8(out, item.content_type);
    writeBytes(out, item.ratchet_bytes);
  }
  return out;
}

struct SyncChunkPayload {
  std::string chat_id;
  uint64_t chunk_id = 0;
  std::vector<SyncChunkItem> items;
};

SyncChunkPayload decodeSyncChunkPayload(const std::vector<uint8_t>& data) {
  size_t offset = 0;
  SyncChunkPayload payload;
  payload.chat_id = readString(data, offset);
  payload.chunk_id = readU64(data, offset);
  uint32_t count = readU32(data, offset);
  payload.items.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    SyncChunkItem item;
    item.index = readI64(data, offset);
    item.msg_id = readString(data, offset);
    item.sender_device = readString(data, offset);
    item.ts_ms = readI64(data, offset);
    item.content_type = readU8(data, offset);
    item.ratchet_bytes = readBytes(data, offset);
    payload.items.push_back(std::move(item));
  }
  return payload;
}

std::vector<uint8_t> encodeSyncAckPayload(const std::string& chat_id, uint64_t chunk_id) {
  std::vector<uint8_t> out;
  writeString(out, chat_id);
  writeU64(out, chunk_id);
  return out;
}

void decodeSyncAckPayload(const std::vector<uint8_t>& data, std::string& chat_id, uint64_t& chunk_id) {
  size_t offset = 0;
  chat_id = readString(data, offset);
  chunk_id = readU64(data, offset);
}

std::vector<uint8_t> buildFrame(const storage::SessionState& state,
                                const std::array<uint8_t, 32>& frame_key,
                                FrameType type,
                                uint64_t counter,
                                const std::vector<uint8_t>& payload,
                                crypto::AeadAlgorithm algorithm,
                                size_t max_padding) {
  FrameHeader header;
  header.version = kProtoVersion;
  header.type = type;
  header.session_id = sessionIdToArray(state.session_id);
  header.counter = counter;
  std::vector<uint8_t> nonce = crypto::randomBytes(kNonceSize);
  if (nonce.size() != kNonceSize) {
    throw std::runtime_error("nonce length mismatch");
  }
  std::copy(nonce.begin(), nonce.end(), header.nonce.begin());
  header.payload_len = static_cast<uint32_t>(payload.size());
  std::vector<uint8_t> header_bytes = encodeHeader(header);
  crypto::AeadResult sealed = crypto::aeadEncrypt(algorithm, frame_key, header.nonce, payload, header_bytes);
  std::vector<uint8_t> frame;
  frame.reserve(header_bytes.size() + sealed.ciphertext.size() + sealed.tag.size() + max_padding);
  frame.insert(frame.end(), header_bytes.begin(), header_bytes.end());
  frame.insert(frame.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
  frame.insert(frame.end(), sealed.tag.begin(), sealed.tag.end());
  std::vector<uint8_t> padding = randomPadding(max_padding);
  frame.insert(frame.end(), padding.begin(), padding.end());
  return frame;
}

std::pair<FrameHeader, std::vector<uint8_t>> decodeFrame(const std::array<uint8_t, 32>& frame_key,
                                                         crypto::AeadAlgorithm algorithm,
                                                         const std::vector<uint8_t>& bytes) {
  FrameHeader header = decodeHeader(bytes);
  if (header.version != kProtoVersion) {
    throw std::runtime_error("frame version mismatch");
  }
  size_t payload_offset = kHeaderSize;
  size_t required = payload_offset + header.payload_len + kTagSize;
  if (bytes.size() < required) {
    throw std::runtime_error("frame payload truncated");
  }
  std::vector<uint8_t> ciphertext(bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset),
                                  bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset + header.payload_len));
  std::array<uint8_t, kTagSize> tag{};
  std::memcpy(tag.data(), bytes.data() + payload_offset + header.payload_len, tag.size());
  std::vector<uint8_t> header_bytes(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(kHeaderSize));
  std::vector<uint8_t> payload = crypto::aeadDecrypt(algorithm, frame_key, header.nonce,
                                                     ciphertext, header_bytes, tag);
  return {header, std::move(payload)};
}

std::vector<uint8_t> ratchetAad(const std::vector<uint8_t>& session_id,
                                const std::string& chat_id,
                                const std::string& msg_id) {
  std::vector<uint8_t> aad;
  aad.reserve(session_id.size() + chat_id.size() + msg_id.size());
  aad.insert(aad.end(), session_id.begin(), session_id.end());
  aad.insert(aad.end(), chat_id.begin(), chat_id.end());
  aad.insert(aad.end(), msg_id.begin(), msg_id.end());
  return aad;
}

storage::SessionState buildSessionState(const std::vector<uint8_t>& session_id,
                                        const crypto::RatchetState& ratchet_state) {
  storage::SessionState state;
  state.session_id = session_id;
  state.root_key = ratchet_state.root_key;
  state.chain_snd = ratchet_state.sending_chain_key;
  state.chain_rcv = ratchet_state.receiving_chain_key;
  state.local_ratchet_key = ratchet_state.local_ratchet_key;
  state.remote_ratchet_pub = ratchet_state.remote_ratchet_pub;
  state.has_sending_chain = ratchet_state.has_sending_chain;
  state.has_receiving_chain = ratchet_state.has_receiving_chain;
  state.counter_snd = ratchet_state.sending_count;
  state.counter_rcv = ratchet_state.receiving_count;
  state.previous_counter = ratchet_state.previous_sending_count;
  state.frame_counter_snd = 1;
  state.frame_counter_rcv = 0;
  return state;
}

crypto::RatchetState ratchetStateFromSession(const storage::SessionState& state) {
  crypto::RatchetState ratchet_state;
  ratchet_state.root_key = state.root_key;
  ratchet_state.sending_chain_key = state.chain_snd;
  ratchet_state.receiving_chain_key = state.chain_rcv;
  ratchet_state.local_ratchet_key = state.local_ratchet_key;
  ratchet_state.remote_ratchet_pub = state.remote_ratchet_pub;
  ratchet_state.has_sending_chain = state.has_sending_chain;
  ratchet_state.has_receiving_chain = state.has_receiving_chain;
  ratchet_state.sending_count = state.counter_snd;
  ratchet_state.receiving_count = state.counter_rcv;
  ratchet_state.previous_sending_count = state.previous_counter;
  return ratchet_state;
}

}

SessionManager::SessionManager(SessionManagerConfig config) : config_(std::move(config)) {
  if (!config_.storage || !config_.transport) {
    throw std::runtime_error("SessionManager missing dependencies");
  }
}

void SessionManager::start() {
  if (running_) {
    return;
  }
  running_ = true;
}

void SessionManager::stop() {
  running_ = false;
}

void SessionManager::tick(int64_t now_ms) {
  if (!running_) {
    return;
  }
  flushOutbox(now_ms);
}

void SessionManager::bindTransportCallbacks() {
  config_.transport->onReceive = [this](const transport::PeerId& peer, transport::Frame&& frame) {
    onTransportReceive(peer, std::move(frame));
  };
  config_.transport->onAck = [this](const transport::PeerId& peer, transport::FrameId id) {
    onTransportAck(peer, id);
  };
  config_.transport->onSendFailed = [this](const transport::PeerId& peer,
                                           transport::FrameId id,
                                           transport::SendFailure reason) {
    onTransportSendFailed(peer, id, reason);
  };
  config_.transport->onConnectionState = [this](const transport::PeerId& peer, transport::ConnectionState state) {
    onTransportConnection(peer, state);
  };
  config_.transport->onWritable = [this](const transport::PeerId& peer, bool writable) {
    onTransportWritable(peer, writable);
  };
}

void SessionManager::onTransportReceive(const transport::PeerId& peer, transport::Frame&& frame) {
  handleReceive(peer, std::move(frame));
}

void SessionManager::onTransportAck(const transport::PeerId& peer, transport::FrameId id) {
  handleAck(peer, id);
}

void SessionManager::onTransportSendFailed(const transport::PeerId& peer,
                                           transport::FrameId id,
                                           transport::SendFailure) {
  handleSendFailed(peer, id);
}

void SessionManager::onTransportConnection(const transport::PeerId& peer, transport::ConnectionState state) {
  handleConnection(peer, state);
}

void SessionManager::onTransportWritable(const transport::PeerId& peer, bool writable) {
  handleWritable(peer, writable);
}

void SessionManager::addSession(const transport::PeerId& peer,
                                const std::vector<uint8_t>& session_id,
                                const crypto::Ratchet& ratchet) {
  if (session_id.size() != kSessionIdSize) {
    throw std::runtime_error("session id length mismatch");
  }
  crypto::RatchetState ratchet_state = ratchet.exportState();
  storage::SessionState state = buildSessionState(session_id, ratchet_state);
  Session session;
  session.state = state;
  session.ratchet = std::make_unique<crypto::Ratchet>(crypto::Ratchet::fromState(ratchet_state));
  session.frame_key = deriveFrameKey(session.state);
  sessions_[peer] = std::move(session);
  persistSession(peer, sessions_[peer], nowMs());
}

bool SessionManager::loadSession(const transport::PeerId& peer) {
  auto stored = config_.storage->loadSession(peer);
  if (!stored) {
    return false;
  }
  crypto::RatchetState ratchet_state = ratchetStateFromSession(*stored);
  Session session;
  session.state = *stored;
  session.ratchet = std::make_unique<crypto::Ratchet>(crypto::Ratchet::fromState(ratchet_state));
  session.frame_key = deriveFrameKey(session.state);
  sessions_[peer] = std::move(session);
  return true;
}

bool SessionManager::hasSession(const transport::PeerId& peer) const {
  return sessions_.find(peer) != sessions_.end();
}

void SessionManager::sendMessage(const transport::PeerId& peer,
                                 const std::string& chat_id,
                                 const std::vector<uint8_t>& plaintext,
                                 uint8_t content_type) {
  auto it = sessions_.find(peer);
  if (it == sessions_.end()) {
    throw std::runtime_error("session missing for peer");
  }
  Session& session = it->second;
  IncomingMessage message;
  message.chat_id = chat_id;
  message.msg_id = randomIdHex(16);
  message.sender_device = config_.transport->localId();
  message.ts_ms = nowMs();
  message.content_type = content_type;

  std::vector<uint8_t> aad = ratchetAad(session.state.session_id, message.chat_id, message.msg_id);
  crypto::RatchetMessage ratchet_msg = session.ratchet->encrypt(plaintext, aad);
  std::vector<uint8_t> ratchet_bytes = encodeRatchetMessage(ratchet_msg);
  std::vector<uint8_t> stored_payload = encodeStoredPayload(content_type, plaintext, ratchet_bytes);
  std::vector<uint8_t> payload = encodeAppPayload(message, ratchet_bytes);

  std::vector<uint8_t> frame_bytes = buildFrame(session.state,
                                                session.frame_key,
                                                FrameType::AppMsg,
                                                session.state.frame_counter_snd++,
                                                payload,
                                                config_.frame_aead,
                                                config_.max_padding);

  config_.storage->appendMessage(chat_id,
                                 message.msg_id,
                                 message.sender_device,
                                 message.ts_ms,
                                 stored_payload);

  int64_t outbox_id = config_.storage->enqueueOutbox(peer, session.state.session_id, frame_bytes, message.ts_ms);
  transport::SendResult result = config_.transport->send(peer, transport::Frame{frame_bytes});
  if (result.status == transport::SendStatus::Accepted) {
    config_.storage->markOutboxAttempt(outbox_id, message.ts_ms);
    in_flight_[result.id] = outbox_id;
    outbox_to_frames_[outbox_id].push_back(result.id);
  }
  persistSession(peer, session, message.ts_ms);
}

std::vector<HistoryMessage> SessionManager::getHistory(const std::string& chat_id,
                                                       int64_t start_index,
                                                       size_t limit) const {
  std::vector<storage::StoredMessage> stored = config_.storage->listMessages(chat_id, start_index, limit);
  std::vector<HistoryMessage> out;
  out.reserve(stored.size());
  for (const auto& msg : stored) {
    HistoryMessage history;
    history.chat_id = msg.chat_id;
    history.msg_id = msg.msg_id;
    history.sender_device = msg.sender_device;
    history.ts_ms = msg.ts_ms;
    history.delivered = msg.delivered;
    history.acked = msg.acked;
    history.index = msg.index;
    StoredPayload payload = decodeStoredPayload(msg.payload);
    history.content_type = payload.content_type;
    history.body = std::move(payload.plaintext);
    out.push_back(std::move(history));
  }
  return out;
}

void SessionManager::syncWithPeer(const transport::PeerId& peer) {
  std::vector<std::string> chat_ids;
  auto chats = config_.storage->listChats();
  chat_ids.reserve(chats.size());
  for (const auto& chat : chats) {
    chat_ids.push_back(chat.chat_id);
  }
  syncWithPeer(peer, chat_ids);
}

void SessionManager::syncWithPeer(const transport::PeerId& peer, const std::vector<std::string>& chat_ids) {
  auto it = sessions_.find(peer);
  if (it == sessions_.end()) {
    return;
  }
  for (const auto& chat_id : chat_ids) {
    int64_t last_index = config_.storage->lastIndex(chat_id);
    storage::BloomFilter bloom = config_.storage->buildRecentBloom(chat_id,
                                                                   config_.sync_recent_window,
                                                                   config_.bloom_bits,
                                                                   config_.bloom_hashes,
                                                                   config_.bloom_seed);
    std::vector<uint8_t> payload = encodeSyncHelloPayload(chat_id, last_index, bloom);
    std::vector<uint8_t> frame_bytes = buildFrame(it->second.state,
                                                  it->second.frame_key,
                                                  FrameType::SyncHello,
                                                  it->second.state.frame_counter_snd++,
                                                  payload,
                                                  config_.frame_aead,
                                                  config_.max_padding);
    int64_t outbox_id = config_.storage->enqueueOutbox(peer, it->second.state.session_id, frame_bytes, nowMs());
    transport::SendResult result = config_.transport->send(peer, transport::Frame{frame_bytes});
    if (result.status == transport::SendStatus::Accepted) {
      config_.storage->markOutboxAttempt(outbox_id, nowMs());
      in_flight_[result.id] = outbox_id;
      outbox_to_frames_[outbox_id].push_back(result.id);
    }
  }
}

void SessionManager::handleReceive(const transport::PeerId& peer, transport::Frame&& frame) {
  if (!running_) {
    return;
  }
  auto it = sessions_.find(peer);
  if (it == sessions_.end()) {
    return;
  }
  Session& session = it->second;
  try {
    auto decoded = decodeFrame(session.frame_key, config_.frame_aead, frame.bytes);
    FrameHeader header = decoded.first;
    std::vector<uint8_t> payload = std::move(decoded.second);

    if (header.session_id != sessionIdToArray(session.state.session_id)) {
      return;
    }
    if (header.counter <= session.state.frame_counter_rcv) {
      return;
    }
    session.state.frame_counter_rcv = header.counter;

    switch (header.type) {
      case FrameType::AppMsg: {
        std::vector<uint8_t> ratchet_bytes;
        IncomingMessage incoming = decodeAppPayload(payload, ratchet_bytes);
        if (config_.storage->messageExists(incoming.chat_id, incoming.msg_id)) {
          std::vector<uint8_t> ack_payload = encodeAckPayload(incoming.chat_id, incoming.msg_id);
          std::vector<uint8_t> ack_frame = buildFrame(session.state,
                                                      session.frame_key,
                                                      FrameType::Ack,
                                                      session.state.frame_counter_snd++,
                                                      ack_payload,
                                                      config_.frame_aead,
                                                      config_.max_padding);
          int64_t outbox_id = config_.storage->enqueueOutbox(peer, session.state.session_id, ack_frame, nowMs());
          transport::SendResult result = config_.transport->send(peer, transport::Frame{ack_frame});
          if (result.status == transport::SendStatus::Accepted) {
            config_.storage->markOutboxAttempt(outbox_id, nowMs());
            in_flight_[result.id] = outbox_id;
            outbox_to_frames_[outbox_id].push_back(result.id);
          }
          break;
        }
        crypto::RatchetMessage ratchet_msg = decodeRatchetMessage(ratchet_bytes);
        std::vector<uint8_t> aad = ratchetAad(session.state.session_id, incoming.chat_id, incoming.msg_id);
        std::vector<uint8_t> plaintext = session.ratchet->decrypt(ratchet_msg, aad);
        std::vector<uint8_t> stored_payload = encodeStoredPayload(incoming.content_type, plaintext, ratchet_bytes);
        config_.storage->appendMessage(incoming.chat_id, incoming.msg_id, peer, incoming.ts_ms, stored_payload);
        IncomingMessage notify = incoming;
        notify.sender_device = peer;
        notify.body = std::move(plaintext);
        if (onMessage) {
          onMessage(notify);
        }
        std::vector<uint8_t> ack_payload = encodeAckPayload(incoming.chat_id, incoming.msg_id);
        std::vector<uint8_t> ack_frame = buildFrame(session.state,
                                                    session.frame_key,
                                                    FrameType::Ack,
                                                    session.state.frame_counter_snd++,
                                                    ack_payload,
                                                    config_.frame_aead,
                                                    config_.max_padding);
        int64_t outbox_id = config_.storage->enqueueOutbox(peer, session.state.session_id, ack_frame, nowMs());
        transport::SendResult result = config_.transport->send(peer, transport::Frame{ack_frame});
        if (result.status == transport::SendStatus::Accepted) {
          config_.storage->markOutboxAttempt(outbox_id, nowMs());
          in_flight_[result.id] = outbox_id;
          outbox_to_frames_[outbox_id].push_back(result.id);
        }
        break;
      }
      case FrameType::Ack: {
        std::string chat_id;
        std::string msg_id;
        decodeAckPayload(payload, chat_id, msg_id);
        config_.storage->markMessageAcked(chat_id, msg_id);
        break;
      }
      case FrameType::SyncHello: {
        SyncHelloPayload hello = decodeSyncHelloPayload(payload);
        storage::BloomFilter remote = storage::BloomFilter::fromBytes(hello.bloom_bytes,
                                                                      hello.bloom_hashes,
                                                                      hello.bloom_seed);
        std::vector<storage::SyncRange> ranges = config_.storage->planSync(hello.chat_id,
                                                                           hello.last_index,
                                                                           remote,
                                                                           config_.sync_recent_window);
        uint64_t chunk_id = 1;
        for (const auto& range : ranges) {
          int64_t start = range.start_index;
          while (start <= range.end_index) {
            int64_t end = std::min<int64_t>(range.end_index,
                                            start + static_cast<int64_t>(config_.sync_batch) - 1);
            auto messages = config_.storage->listMessagesRange(hello.chat_id, start, end);
            std::vector<SyncChunkItem> items;
            items.reserve(messages.size());
            for (const auto& msg : messages) {
              StoredPayload stored = decodeStoredPayload(msg.payload);
              SyncChunkItem item;
              item.index = msg.index;
              item.msg_id = msg.msg_id;
              item.sender_device = msg.sender_device;
              item.ts_ms = msg.ts_ms;
              item.content_type = stored.content_type;
              item.ratchet_bytes = stored.ratchet_bytes;
              items.push_back(std::move(item));
            }
            std::vector<uint8_t> chunk_payload = encodeSyncChunkPayload(hello.chat_id, chunk_id++, items);
            std::vector<uint8_t> chunk_frame = buildFrame(session.state,
                                                          session.frame_key,
                                                          FrameType::SyncChunk,
                                                          session.state.frame_counter_snd++,
                                                          chunk_payload,
                                                          config_.frame_aead,
                                                          config_.max_padding);
            int64_t outbox_id = config_.storage->enqueueOutbox(peer, session.state.session_id, chunk_frame, nowMs());
            transport::SendResult result = config_.transport->send(peer, transport::Frame{chunk_frame});
            if (result.status == transport::SendStatus::Accepted) {
              config_.storage->markOutboxAttempt(outbox_id, nowMs());
              in_flight_[result.id] = outbox_id;
              outbox_to_frames_[outbox_id].push_back(result.id);
            }
            start = end + 1;
          }
        }
        break;
      }
      case FrameType::SyncChunk: {
        SyncChunkPayload chunk = decodeSyncChunkPayload(payload);
        for (const auto& item : chunk.items) {
          if (config_.storage->messageExists(chunk.chat_id, item.msg_id)) {
            continue;
          }
          crypto::RatchetMessage ratchet_msg = decodeRatchetMessage(item.ratchet_bytes);
          std::vector<uint8_t> aad = ratchetAad(session.state.session_id, chunk.chat_id, item.msg_id);
          std::vector<uint8_t> plaintext = session.ratchet->decrypt(ratchet_msg, aad);
          std::vector<uint8_t> stored_payload = encodeStoredPayload(item.content_type, plaintext, item.ratchet_bytes);
          storage::StoredMessage stored;
          stored.chat_id = chunk.chat_id;
          stored.msg_id = item.msg_id;
          stored.sender_device = item.sender_device;
          stored.ts_ms = item.ts_ms;
          stored.payload = stored_payload;
          config_.storage->upsertMessageAtIndex(stored, item.index);
          if (onMessage) {
            IncomingMessage notify;
            notify.chat_id = chunk.chat_id;
            notify.msg_id = item.msg_id;
            notify.sender_device = item.sender_device;
            notify.ts_ms = item.ts_ms;
            notify.content_type = item.content_type;
            notify.body = plaintext;
            onMessage(notify);
          }
        }
        std::vector<uint8_t> ack_payload = encodeSyncAckPayload(chunk.chat_id, chunk.chunk_id);
        std::vector<uint8_t> ack_frame = buildFrame(session.state,
                                                    session.frame_key,
                                                    FrameType::SyncAck,
                                                    session.state.frame_counter_snd++,
                                                    ack_payload,
                                                    config_.frame_aead,
                                                    config_.max_padding);
        int64_t outbox_id = config_.storage->enqueueOutbox(peer, session.state.session_id, ack_frame, nowMs());
        transport::SendResult result = config_.transport->send(peer, transport::Frame{ack_frame});
        if (result.status == transport::SendStatus::Accepted) {
          config_.storage->markOutboxAttempt(outbox_id, nowMs());
          in_flight_[result.id] = outbox_id;
          outbox_to_frames_[outbox_id].push_back(result.id);
        }
        break;
      }
      case FrameType::SyncAck: {
        std::string chat_id;
        uint64_t chunk_id = 0;
        decodeSyncAckPayload(payload, chat_id, chunk_id);
        (void)chat_id;
        (void)chunk_id;
        break;
      }
      case FrameType::KeyUpdate:
      case FrameType::Pong:
        break;
    }
    persistSession(peer, session, nowMs());
  } catch (const std::exception& ex) {
    if (onError) {
      onError(peer, ex.what());
    }
  }
}

void SessionManager::handleAck(const transport::PeerId&, transport::FrameId id) {
  auto it = in_flight_.find(id);
  if (it == in_flight_.end()) {
    return;
  }
  int64_t outbox_id = it->second;
  in_flight_.erase(it);
  auto frames_it = outbox_to_frames_.find(outbox_id);
  if (frames_it != outbox_to_frames_.end()) {
    for (transport::FrameId frame_id : frames_it->second) {
      in_flight_.erase(frame_id);
    }
    outbox_to_frames_.erase(frames_it);
  }
  config_.storage->removeOutbox(outbox_id);
}

void SessionManager::handleSendFailed(const transport::PeerId&, transport::FrameId id) {
  in_flight_.erase(id);
}

void SessionManager::handleConnection(const transport::PeerId& peer, transport::ConnectionState state) {
  if (state == transport::ConnectionState::Connected) {
    syncWithPeer(peer);
    flushOutbox(nowMs());
  }
}

void SessionManager::handleWritable(const transport::PeerId&, bool writable) {
  if (writable) {
    flushOutbox(nowMs());
  }
}

void SessionManager::flushOutbox(int64_t now_ms) {
  auto due = config_.storage->loadDueOutbox(now_ms, config_.outbox_batch);
  for (const auto& item : due) {
    auto it = sessions_.find(item.peer_device);
    if (it == sessions_.end()) {
      continue;
    }
    if (config_.transport->state(item.peer_device) != transport::ConnectionState::Connected) {
      continue;
    }
    transport::SendResult result = config_.transport->send(item.peer_device, transport::Frame{item.frame});
    if (result.status == transport::SendStatus::Accepted) {
      config_.storage->markOutboxAttempt(item.id, now_ms);
      in_flight_[result.id] = item.id;
      outbox_to_frames_[item.id].push_back(result.id);
    }
  }
}

void SessionManager::persistSession(const transport::PeerId& peer, Session& session, int64_t now_ms) {
  crypto::RatchetState ratchet_state = session.ratchet->exportState();
  session.state.root_key = ratchet_state.root_key;
  session.state.chain_snd = ratchet_state.sending_chain_key;
  session.state.chain_rcv = ratchet_state.receiving_chain_key;
  session.state.local_ratchet_key = ratchet_state.local_ratchet_key;
  session.state.remote_ratchet_pub = ratchet_state.remote_ratchet_pub;
  session.state.has_sending_chain = ratchet_state.has_sending_chain;
  session.state.has_receiving_chain = ratchet_state.has_receiving_chain;
  session.state.counter_snd = ratchet_state.sending_count;
  session.state.counter_rcv = ratchet_state.receiving_count;
  session.state.previous_counter = ratchet_state.previous_sending_count;
  config_.storage->saveSession(peer, session.state, now_ms);
}

}
