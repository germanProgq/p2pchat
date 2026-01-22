// UDP transport core for QUIC/WebRTC adapters.
#pragma once

#include "transport/ITransport.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#endif

namespace transport {

#if defined(_WIN32)
using SocketType = SOCKET;
#else
using SocketType = int;
#endif

struct DatagramConfig {
  std::string bind_address = "0.0.0.0";
  uint16_t bind_port = 0;
  size_t max_datagram_size = 1200;
};

class DatagramTransport final : public ITransport {
 public:
  DatagramTransport(const PeerId& local_id,
                    const DatagramConfig& config,
                    const TransportConfig& transport_config,
                    bool auto_start = true);
  ~DatagramTransport() override;

  PeerId localId() const override;
  ConnectionState state(const PeerId& peer) const override;
  bool connect(const PeerInfo& peer) override;
  void disconnect(const PeerId& peer) override;
  SendResult send(const PeerId& peer, const Frame& frame) override;
  size_t queuedBytes(const PeerId& peer) const override;

  void start();
  void stop();

  uint16_t boundPort() const;
  SocketType socketHandle() const;

 private:
  struct PendingFrame {
    FrameId id = 0;
    std::vector<uint8_t> bytes;
    uint32_t attempts = 0;
    bool awaiting_ack = false;
    int64_t ack_deadline_ms = 0;
    int64_t next_send_at_ms = 0;
  };

  struct ReceiveState {
    bool initialized = false;
    FrameId next_expected = 1;
    std::map<FrameId, std::vector<uint8_t>> buffer;
  };

  struct PeerState {
    ConnectionState state = ConnectionState::Disconnected;
    bool writable = true;
    size_t queued_bytes = 0;
    uint64_t in_flight = 0;
    std::deque<FrameId> send_order;
    std::unordered_map<FrameId, PendingFrame> pending;
    ReceiveState receive;
  };

  DatagramConfig config_;
  TransportConfig transport_config_;
  PeerId local_id_;

  mutable std::mutex mutex_;
  std::condition_variable cv_;
  std::unordered_map<PeerId, PeerState> peers_;
  std::unordered_map<PeerId, std::string> peer_addr_key_;
  std::unordered_map<std::string, PeerId> addr_to_peer_;
  std::atomic<bool> running_{false};
  std::thread io_thread_;
  FrameId next_frame_id_ = 1;

  SocketType socket_fd_ = static_cast<SocketType>(-1);
  uint16_t bound_port_ = 0;

  void ioLoop();
  void processIo(int64_t now_ms);
  void processTimers(int64_t now_ms, std::vector<std::function<void()>>& callbacks);
  void receivePackets(std::vector<std::function<void()>>& callbacks);
  void handleData(const PeerId& peer, FrameId id, std::vector<uint8_t> payload,
                  std::vector<std::function<void()>>& callbacks);
  void handleAck(const PeerId& peer, FrameId id, std::vector<std::function<void()>>& callbacks);
  void sendPacket(const std::string& addr_key, uint8_t type, FrameId id,
                  const std::vector<uint8_t>& payload);
};

}
