// UDP transport core implementation.
#include "DatagramTransport.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <stdexcept>
#include <utility>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace transport {

int64_t nowMs();
std::string addrKey(const sockaddr_in& addr);
bool parseAddress(const std::string& address, uint16_t port, sockaddr_in& out);
uint64_t readU64(const uint8_t* data);
uint32_t readU32(const uint8_t* data);
void writeU64(uint8_t* data, uint64_t value);
void writeU32(uint8_t* data, uint32_t value);

namespace {

constexpr uint8_t kPacketData = 0;
constexpr uint8_t kPacketAck = 1;
constexpr size_t kWireHeaderSize = 1 + 8 + 4;

#if defined(_WIN32)
constexpr SocketType kInvalidSocket = INVALID_SOCKET;
using SockLenType = int;

struct WsaInit {
  WsaInit() {
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
      throw std::runtime_error("WSAStartup failed");
    }
  }
  ~WsaInit() { WSACleanup(); }
};

int closeSocket(SocketType sock) {
  return closesocket(sock);
}

bool setNonBlocking(SocketType sock) {
  u_long mode = 1;
  return ioctlsocket(sock, FIONBIO, &mode) == 0;
}
#else
constexpr SocketType kInvalidSocket = -1;
using SockLenType = socklen_t;

int closeSocket(SocketType sock) {
  return close(sock);
}

bool setNonBlocking(SocketType sock) {
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }
  return fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
}
#endif

}

DatagramTransport::DatagramTransport(const PeerId& local_id,
                                     const DatagramConfig& config,
                                     const TransportConfig& transport_config,
                                     bool auto_start)
    : config_(config), transport_config_(transport_config), local_id_(local_id) {
  if (config_.max_datagram_size <= kWireHeaderSize) {
    throw std::runtime_error("udp datagram size too small");
  }
#if defined(_WIN32)
  static WsaInit wsa_init;
#endif
  socket_fd_ = static_cast<SocketType>(socket(AF_INET, SOCK_DGRAM, 0));
  if (socket_fd_ == kInvalidSocket) {
    throw std::runtime_error("udp socket create failed");
  }

  sockaddr_in bind_addr{};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(config_.bind_port);
  if (!parseAddress(config_.bind_address, config_.bind_port, bind_addr)) {
    closeSocket(socket_fd_);
    throw std::runtime_error("udp bind address invalid");
  }
  if (bind(socket_fd_, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
    closeSocket(socket_fd_);
    throw std::runtime_error("udp bind failed");
  }
  if (!setNonBlocking(socket_fd_)) {
    closeSocket(socket_fd_);
    throw std::runtime_error("udp nonblocking failed");
  }
  sockaddr_in actual{};
  SockLenType len = sizeof(actual);
  if (getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&actual), &len) == 0) {
    bound_port_ = ntohs(actual.sin_port);
  }
  if (auto_start) {
    start();
  }
}

DatagramTransport::~DatagramTransport() {
  stop();
  if (socket_fd_ != kInvalidSocket) {
    closeSocket(socket_fd_);
    socket_fd_ = kInvalidSocket;
  }
}

PeerId DatagramTransport::localId() const {
  return local_id_;
}

ConnectionState DatagramTransport::state(const PeerId& peer) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return ConnectionState::Disconnected;
  }
  return it->second.state;
}

bool DatagramTransport::connect(const PeerInfo& peer) {
  if (peer.id.empty() || peer.id == local_id_) {
    return false;
  }
  if (peer.address.empty() || peer.port == 0) {
    return false;
  }
  sockaddr_in addr{};
  if (!parseAddress(peer.address, peer.port, addr)) {
    return false;
  }
  std::string key = addrKey(addr);
  bool notify = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    PeerState& state = peers_[peer.id];
    notify = state.state != ConnectionState::Connected;
    state.state = ConnectionState::Connected;
    peer_addr_key_[peer.id] = key;
    addr_to_peer_[key] = peer.id;
  }
  if (notify) {
    if (onConnectionState) {
      onConnectionState(peer.id, ConnectionState::Connected);
    }
  }
  return true;
}

void DatagramTransport::disconnect(const PeerId& peer) {
  std::vector<std::function<void()>> callbacks;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peers_.find(peer);
    if (it == peers_.end()) {
      return;
    }
    PeerState& state = it->second;
    if (state.state != ConnectionState::Disconnected) {
      callbacks.push_back([this, peer]() {
        if (onConnectionState) {
          onConnectionState(peer, ConnectionState::Disconnected);
        }
      });
    }
    for (const auto& entry : state.pending) {
      FrameId id = entry.first;
      callbacks.push_back([this, peer, id]() {
        if (onSendFailed) {
          onSendFailed(peer, id, SendFailure::Disconnected);
        }
      });
    }
    state.pending.clear();
    state.send_order.clear();
    state.queued_bytes = 0;
    state.in_flight = 0;
    state.writable = true;
    state.state = ConnectionState::Disconnected;
    auto key_it = peer_addr_key_.find(peer);
    if (key_it != peer_addr_key_.end()) {
      addr_to_peer_.erase(key_it->second);
      peer_addr_key_.erase(key_it);
    }
  }
  for (const auto& cb : callbacks) {
    cb();
  }
}

SendResult DatagramTransport::send(const PeerId& peer, const Frame& frame) {
  if (frame.bytes.size() + kWireHeaderSize > config_.max_datagram_size) {
    return {SendStatus::TooLarge, 0};
  }
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = peers_.find(peer);
  if (it == peers_.end() || it->second.state != ConnectionState::Connected) {
    return {SendStatus::Disconnected, 0};
  }
  PeerState& state = it->second;
  if (state.queued_bytes + frame.bytes.size() > transport_config_.max_queue_bytes) {
    if (state.writable) {
      state.writable = false;
      if (onWritable) {
        onWritable(peer, false);
      }
    }
    return {SendStatus::Backpressure, 0};
  }
  FrameId id = next_frame_id_++;
  PendingFrame pending;
  pending.id = id;
  pending.bytes = frame.bytes;
  pending.next_send_at_ms = nowMs();
  state.pending[id] = std::move(pending);
  state.send_order.push_back(id);
  state.queued_bytes += frame.bytes.size();
  cv_.notify_all();
  return {SendStatus::Accepted, id};
}

size_t DatagramTransport::queuedBytes(const PeerId& peer) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return 0;
  }
  return it->second.queued_bytes;
}

void DatagramTransport::start() {
  bool expected = false;
  if (!running_.compare_exchange_strong(expected, true)) {
    return;
  }
  io_thread_ = std::thread([this]() { ioLoop(); });
}

void DatagramTransport::stop() {
  running_ = false;
  cv_.notify_all();
  if (io_thread_.joinable()) {
    io_thread_.join();
  }
}

uint16_t DatagramTransport::boundPort() const {
  return bound_port_;
}

SocketType DatagramTransport::socketHandle() const {
  return socket_fd_;
}

void DatagramTransport::ioLoop() {
  while (running_) {
    int64_t now_ms = nowMs();
    std::vector<std::function<void()>> callbacks;
    receivePackets(callbacks);
    processTimers(now_ms, callbacks);
    for (const auto& cb : callbacks) {
      cb();
    }
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait_for(lock, std::chrono::milliseconds(10));
  }
}

void DatagramTransport::processTimers(int64_t now_ms, std::vector<std::function<void()>>& callbacks) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& entry : peers_) {
    PeerState& state = entry.second;
    if (state.state != ConnectionState::Connected) {
      continue;
    }

    std::vector<FrameId> to_fail;
    for (FrameId id : state.send_order) {
      auto it = state.pending.find(id);
      if (it == state.pending.end()) {
        continue;
      }
      PendingFrame& frame = it->second;
      if (frame.awaiting_ack && now_ms >= frame.ack_deadline_ms) {
        if (state.in_flight > 0) {
          state.in_flight--;
        }
        if (frame.attempts >= transport_config_.retry.max_attempts) {
          to_fail.push_back(id);
          continue;
        }
        frame.awaiting_ack = false;
        frame.next_send_at_ms = now_ms;
      }
    }

    for (FrameId id : to_fail) {
      auto it = state.pending.find(id);
      if (it == state.pending.end()) {
        continue;
      }
      size_t size = it->second.bytes.size();
      state.pending.erase(it);
      state.send_order.erase(std::remove(state.send_order.begin(), state.send_order.end(), id),
                             state.send_order.end());
      if (state.queued_bytes >= size) {
        state.queued_bytes -= size;
      } else {
        state.queued_bytes = 0;
      }
      if (!state.writable && state.queued_bytes < transport_config_.max_queue_bytes) {
        state.writable = true;
        callbacks.push_back([this, peer = entry.first]() {
          if (onWritable) {
            onWritable(peer, true);
          }
        });
      }
      callbacks.push_back([this, peer = entry.first, id]() {
        if (onSendFailed) {
          onSendFailed(peer, id, SendFailure::Timeout);
        }
      });
    }

    if (state.in_flight >= transport_config_.max_in_flight) {
      continue;
    }

    auto key_it = peer_addr_key_.find(entry.first);
    if (key_it == peer_addr_key_.end()) {
      continue;
    }
    const std::string& addr_key = key_it->second;

    for (FrameId id : state.send_order) {
      if (state.in_flight >= transport_config_.max_in_flight) {
        break;
      }
      auto it = state.pending.find(id);
      if (it == state.pending.end()) {
        continue;
      }
      PendingFrame& frame = it->second;
      if (!frame.awaiting_ack && frame.next_send_at_ms <= now_ms) {
        frame.attempts += 1;
        frame.awaiting_ack = true;
        frame.ack_deadline_ms = now_ms + transport_config_.retry.nextDelayMs(frame.attempts - 1);
        if (frame.ack_deadline_ms < now_ms) {
          frame.ack_deadline_ms = now_ms;
        }
        state.in_flight += 1;
        sendPacket(addr_key, kPacketData, frame.id, frame.bytes);
      }
    }
  }
}

void DatagramTransport::receivePackets(std::vector<std::function<void()>>& callbacks) {
  std::vector<uint8_t> buffer(config_.max_datagram_size);
  while (true) {
    sockaddr_in from{};
    SockLenType from_len = sizeof(from);
#if defined(_WIN32)
    int received = recvfrom(socket_fd_, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
                             reinterpret_cast<sockaddr*>(&from), &from_len);
    if (received == SOCKET_ERROR) {
      int err = WSAGetLastError();
      if (err == WSAEWOULDBLOCK) {
        break;
      }
      break;
    }
#else
    ssize_t received = recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                reinterpret_cast<sockaddr*>(&from), &from_len);
    if (received < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        break;
      }
      break;
    }
#endif
    if (received < static_cast<int>(kWireHeaderSize)) {
      continue;
    }
    uint8_t type = buffer[0];
    uint64_t frame_id = readU64(buffer.data() + 1);
    uint32_t length = readU32(buffer.data() + 1 + 8);
    if (kWireHeaderSize + length > static_cast<size_t>(received)) {
      continue;
    }
    std::string key = addrKey(from);
    PeerId peer;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = addr_to_peer_.find(key);
      if (it == addr_to_peer_.end()) {
        continue;
      }
      peer = it->second;
    }
    if (type == kPacketData) {
      std::vector<uint8_t> payload(buffer.begin() + static_cast<std::ptrdiff_t>(kWireHeaderSize),
                                   buffer.begin() + static_cast<std::ptrdiff_t>(kWireHeaderSize + length));
      sendPacket(key, kPacketAck, frame_id, {});
      handleData(peer, frame_id, std::move(payload), callbacks);
    } else if (type == kPacketAck) {
      handleAck(peer, frame_id, callbacks);
    }
  }
}

void DatagramTransport::handleData(const PeerId& peer, FrameId id, std::vector<uint8_t> payload,
                                   std::vector<std::function<void()>>& callbacks) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = peers_.find(peer);
  if (it == peers_.end() || it->second.state != ConnectionState::Connected) {
    return;
  }
  ReceiveState& recv = it->second.receive;
  if (!recv.initialized) {
    recv.initialized = true;
    recv.next_expected = id;
  }
  if (id < recv.next_expected) {
    return;
  }
  recv.buffer.emplace(id, std::move(payload));
  while (true) {
    auto buf_it = recv.buffer.find(recv.next_expected);
    if (buf_it == recv.buffer.end()) {
      break;
    }
    std::vector<uint8_t> data = std::move(buf_it->second);
    recv.buffer.erase(buf_it);
    Frame frame{std::move(data)};
    callbacks.push_back([this, peer, frame = std::move(frame)]() mutable {
      if (onReceive) {
        onReceive(peer, std::move(frame));
      }
    });
    recv.next_expected += 1;
  }
}

void DatagramTransport::handleAck(const PeerId& peer, FrameId id, std::vector<std::function<void()>>& callbacks) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return;
  }
  PeerState& state = it->second;
  auto pending_it = state.pending.find(id);
  if (pending_it == state.pending.end()) {
    return;
  }
  if (pending_it->second.awaiting_ack && state.in_flight > 0) {
    state.in_flight -= 1;
  }
  size_t size = pending_it->second.bytes.size();
  state.pending.erase(pending_it);
  state.send_order.erase(std::remove(state.send_order.begin(), state.send_order.end(), id),
                         state.send_order.end());
  if (state.queued_bytes >= size) {
    state.queued_bytes -= size;
  } else {
    state.queued_bytes = 0;
  }
  if (!state.writable && state.queued_bytes < transport_config_.max_queue_bytes) {
    state.writable = true;
    callbacks.push_back([this, peer]() {
      if (onWritable) {
        onWritable(peer, true);
      }
    });
  }
  callbacks.push_back([this, peer, id]() {
    if (onAck) {
      onAck(peer, id);
    }
  });
}

void DatagramTransport::sendPacket(const std::string& addr_key, uint8_t type, FrameId id,
                                   const std::vector<uint8_t>& payload) {
  auto sep = addr_key.find(':');
  if (sep == std::string::npos) {
    return;
  }
  std::string host = addr_key.substr(0, sep);
  uint16_t port = static_cast<uint16_t>(std::stoi(addr_key.substr(sep + 1)));
  sockaddr_in addr{};
  if (!parseAddress(host, port, addr)) {
    return;
  }
  std::vector<uint8_t> buffer;
  buffer.resize(kWireHeaderSize + payload.size());
  buffer[0] = type;
  writeU64(buffer.data() + 1, id);
  writeU32(buffer.data() + 1 + 8, static_cast<uint32_t>(payload.size()));
  if (!payload.empty()) {
    std::memcpy(buffer.data() + kWireHeaderSize, payload.data(), payload.size());
  }
#if defined(_WIN32)
  sendto(socket_fd_, reinterpret_cast<const char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
         reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#else
  sendto(socket_fd_, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#endif
}

int64_t nowMs() {
  using namespace std::chrono;
  return static_cast<int64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string addrKey(const sockaddr_in& addr) {
  char buf[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, const_cast<in_addr*>(&addr.sin_addr), buf, sizeof(buf));
  uint16_t port = ntohs(addr.sin_port);
  return std::string(buf) + ":" + std::to_string(port);
}

bool parseAddress(const std::string& address, uint16_t port, sockaddr_in& out) {
  std::string host = address.empty() ? "0.0.0.0" : address;
  out.sin_family = AF_INET;
  out.sin_port = htons(port);
  return inet_pton(AF_INET, host.c_str(), &out.sin_addr) == 1;
}

uint64_t readU64(const uint8_t* data) {
  uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(data[i]) << (8 * i);
  }
  return value;
}

uint32_t readU32(const uint8_t* data) {
  uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<uint32_t>(data[i]) << (8 * i);
  }
  return value;
}

void writeU64(uint8_t* data, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    data[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
  }
}

void writeU32(uint8_t* data, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    data[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
  }
}

}
