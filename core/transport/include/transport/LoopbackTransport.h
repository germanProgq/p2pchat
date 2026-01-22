// In-memory transport for loopback and deterministic testing.
#pragma once

#include "transport/ITransport.h"

#include <deque>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace transport {

class LoopbackNetwork;

class LoopbackTransport : public ITransport {
 public:
  LoopbackTransport(const PeerId& local_id, LoopbackNetwork& network, TransportConfig config = {});
  ~LoopbackTransport() override;

  PeerId localId() const override;
  ConnectionState state(const PeerId& peer) const override;
  bool connect(const PeerInfo& peer) override;
  void disconnect(const PeerId& peer) override;
  SendResult send(const PeerId& peer, const Frame& frame) override;
  size_t queuedBytes(const PeerId& peer) const override;

 private:
  struct OutboundFrame {
    FrameId id = 0;
    std::vector<uint8_t> bytes;
  };

  struct PeerState {
    LoopbackTransport* remote = nullptr;
    ConnectionState state = ConnectionState::Disconnected;
    std::deque<OutboundFrame> queue;
    size_t queued_bytes = 0;
    bool writable = true;
  };

  LoopbackNetwork& network_;
  PeerId local_id_;
  TransportConfig config_;
  mutable std::mutex mutex_;
  std::unordered_map<PeerId, PeerState> peers_;
  FrameId next_frame_id_ = 1;

  void notifyConnection(const PeerId& peer, ConnectionState state);
  void notifyWritable(const PeerId& peer, bool writable);
  void notifyAck(const PeerId& peer, FrameId id);
  void notifySendFailed(const PeerId& peer, FrameId id, SendFailure reason);

  void flush(const PeerId& peer);
  void receiveFrom(const PeerId& sender,
                   FrameId id,
                   std::vector<uint8_t> bytes,
                   LoopbackTransport* sender_transport);

  friend class LoopbackNetwork;
};

class LoopbackNetwork {
 public:
  bool registerPeer(const PeerId& id, LoopbackTransport* transport);
  void unregisterPeer(const PeerId& id);
  LoopbackTransport* findPeer(const PeerId& id) const;

 private:
  mutable std::mutex mutex_;
  std::unordered_map<PeerId, LoopbackTransport*> peers_;
};

}
