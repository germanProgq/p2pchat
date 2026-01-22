// Transport abstraction and invariants. Spec: core/transport/ITransport.h.
// - Accepted frames are delivered at most once and in send order per peer.
// - Each accepted frame yields either onAck or onSendFailed.
// - Backpressure is signaled by SendStatus::Backpressure and onWritable(false).
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace transport {

using PeerId = std::string;
using FrameId = uint64_t;

struct PeerInfo {
  PeerId id;
};

struct Frame {
  std::vector<uint8_t> bytes;
};

enum class ConnectionState {
  Disconnected,
  Connecting,
  Connected
};

enum class SendStatus {
  Accepted,
  Backpressure,
  Disconnected,
  TooLarge
};

enum class SendFailure {
  Disconnected,
  Timeout,
  Dropped,
  TooLarge
};

struct SendResult {
  SendStatus status = SendStatus::Disconnected;
  FrameId id = 0;
};

struct RetryPolicy {
  int64_t base_delay_ms = 100;
  int64_t max_delay_ms = 2000;
  uint32_t max_attempts = 5;
  double jitter_ratio = 0.2;

  int64_t nextDelayMs(uint32_t attempts) const;
};

struct TransportConfig {
  size_t max_in_flight = 32;
  size_t max_queue_bytes = static_cast<size_t>(1) << 20;
  RetryPolicy retry{};
};

class ITransport {
 public:
  virtual ~ITransport() = default;

  virtual PeerId localId() const = 0;
  virtual ConnectionState state(const PeerId& peer) const = 0;
  virtual bool connect(const PeerInfo& peer) = 0;
  virtual void disconnect(const PeerId& peer) = 0;
  virtual SendResult send(const PeerId& peer, const Frame& frame) = 0;
  virtual size_t queuedBytes(const PeerId& peer) const = 0;

  std::function<void(const PeerId&, Frame&&)> onReceive;
  std::function<void(const PeerId&, FrameId)> onAck;
  std::function<void(const PeerId&, FrameId, SendFailure)> onSendFailed;
  std::function<void(const PeerId&, ConnectionState)> onConnectionState;
  std::function<void(const PeerId&, bool)> onWritable;
};

}
