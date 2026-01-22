// Loopback transport implementation with ordered delivery and ACK callbacks.
#include "transport/LoopbackTransport.h"

#include <algorithm>
#include <random>
#include <stdexcept>
#include <utility>

namespace transport {

namespace {

template <typename Fn, typename... Args>
void safeInvoke(const Fn& fn, Args&&... args) {
  if (!fn) {
    return;
  }
  try {
    fn(std::forward<Args>(args)...);
  } catch (...) {
  }
}

}

int64_t RetryPolicy::nextDelayMs(uint32_t attempts) const {
  if (base_delay_ms <= 0 || max_delay_ms <= 0) {
    return 0;
  }
  int64_t delay = base_delay_ms;
  uint32_t steps = attempts;
  while (steps-- > 0 && delay < max_delay_ms) {
    if (delay > max_delay_ms / 2) {
      delay = max_delay_ms;
      break;
    }
    delay *= 2;
  }
  delay = std::min(delay, max_delay_ms);
  if (jitter_ratio <= 0.0) {
    return delay;
  }
  thread_local std::mt19937_64 rng([]() {
    std::random_device rd;
    return std::mt19937_64(rd());
  }());
  std::uniform_real_distribution<double> dist(-jitter_ratio, jitter_ratio);
  double factor = 1.0 + dist(rng);
  double jittered = static_cast<double>(delay) * factor;
  if (jittered < 0.0) {
    jittered = 0.0;
  }
  int64_t clamped = static_cast<int64_t>(jittered);
  if (clamped > max_delay_ms) {
    clamped = max_delay_ms;
  }
  return clamped;
}

LoopbackTransport::LoopbackTransport(const PeerId& local_id,
                                     LoopbackNetwork& network,
                                     TransportConfig config)
    : network_(network), local_id_(local_id), config_(config) {
  if (!network_.registerPeer(local_id_, this)) {
    throw std::runtime_error("loopback peer already registered");
  }
}

LoopbackTransport::~LoopbackTransport() {
  std::vector<PeerId> peers;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    peers.reserve(peers_.size());
    for (const auto& entry : peers_) {
      if (entry.second.state == ConnectionState::Connected) {
        peers.push_back(entry.first);
      }
    }
  }
  for (const auto& peer : peers) {
    disconnect(peer);
  }
  network_.unregisterPeer(local_id_);
}

PeerId LoopbackTransport::localId() const {
  return local_id_;
}

ConnectionState LoopbackTransport::state(const PeerId& peer) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return ConnectionState::Disconnected;
  }
  return it->second.state;
}

bool LoopbackTransport::connect(const PeerInfo& peer) {
  if (peer.id.empty() || peer.id == local_id_) {
    return false;
  }
  LoopbackTransport* remote = network_.findPeer(peer.id);
  if (!remote) {
    return false;
  }

  bool notify_local = false;
  bool notify_remote = false;
  {
    LoopbackTransport* first = this < remote ? this : remote;
    LoopbackTransport* second = this < remote ? remote : this;
    std::scoped_lock<std::mutex, std::mutex> lock(first->mutex_, second->mutex_);

    auto& local_state = peers_[peer.id];
    notify_local = local_state.state != ConnectionState::Connected;
    local_state.state = ConnectionState::Connected;
    local_state.remote = remote;

    auto& remote_state = remote->peers_[local_id_];
    notify_remote = remote_state.state != ConnectionState::Connected;
    remote_state.state = ConnectionState::Connected;
    remote_state.remote = this;
  }

  if (notify_local) {
    notifyConnection(peer.id, ConnectionState::Connected);
  }
  if (notify_remote) {
    remote->notifyConnection(local_id_, ConnectionState::Connected);
  }
  return true;
}

void LoopbackTransport::disconnect(const PeerId& peer) {
  LoopbackTransport* remote = nullptr;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peers_.find(peer);
    if (it == peers_.end()) {
      return;
    }
    remote = it->second.remote;
  }

  std::vector<OutboundFrame> local_dropped;
  std::vector<OutboundFrame> remote_dropped;
  bool notify_local = false;
  bool notify_remote = false;
  bool notify_writable_local = false;
  bool notify_writable_remote = false;

  if (remote && remote != this) {
    LoopbackTransport* first = this < remote ? this : remote;
    LoopbackTransport* second = this < remote ? remote : this;
    std::scoped_lock<std::mutex, std::mutex> lock(first->mutex_, second->mutex_);

    auto it_local = peers_.find(peer);
    if (it_local != peers_.end()) {
      notify_local = it_local->second.state != ConnectionState::Disconnected;
      notify_writable_local = !it_local->second.writable;
      local_dropped.reserve(it_local->second.queue.size());
      for (auto& frame : it_local->second.queue) {
        local_dropped.push_back(std::move(frame));
      }
      it_local->second.queue.clear();
      it_local->second.queued_bytes = 0;
      it_local->second.writable = true;
      it_local->second.state = ConnectionState::Disconnected;
      it_local->second.remote = nullptr;
    }

    auto it_remote = remote->peers_.find(local_id_);
    if (it_remote != remote->peers_.end()) {
      notify_remote = it_remote->second.state != ConnectionState::Disconnected;
      notify_writable_remote = !it_remote->second.writable;
      remote_dropped.reserve(it_remote->second.queue.size());
      for (auto& frame : it_remote->second.queue) {
        remote_dropped.push_back(std::move(frame));
      }
      it_remote->second.queue.clear();
      it_remote->second.queued_bytes = 0;
      it_remote->second.writable = true;
      it_remote->second.state = ConnectionState::Disconnected;
      it_remote->second.remote = nullptr;
    }
  } else {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it_local = peers_.find(peer);
    if (it_local != peers_.end()) {
      notify_local = it_local->second.state != ConnectionState::Disconnected;
      notify_writable_local = !it_local->second.writable;
      local_dropped.reserve(it_local->second.queue.size());
      for (auto& frame : it_local->second.queue) {
        local_dropped.push_back(std::move(frame));
      }
      it_local->second.queue.clear();
      it_local->second.queued_bytes = 0;
      it_local->second.writable = true;
      it_local->second.state = ConnectionState::Disconnected;
      it_local->second.remote = nullptr;
    }
  }

  if (notify_writable_local) {
    notifyWritable(peer, true);
  }
  if (notify_writable_remote && remote) {
    remote->notifyWritable(local_id_, true);
  }

  for (const auto& frame : local_dropped) {
    notifySendFailed(peer, frame.id, SendFailure::Disconnected);
  }
  for (const auto& frame : remote_dropped) {
    if (remote) {
      remote->notifySendFailed(local_id_, frame.id, SendFailure::Disconnected);
    }
  }

  if (notify_local) {
    notifyConnection(peer, ConnectionState::Disconnected);
  }
  if (notify_remote && remote) {
    remote->notifyConnection(local_id_, ConnectionState::Disconnected);
  }
}

SendResult LoopbackTransport::send(const PeerId& peer, const Frame& frame) {
  if (frame.bytes.size() > config_.max_queue_bytes) {
    return {SendStatus::TooLarge, 0};
  }

  LoopbackTransport* remote = nullptr;
  FrameId id = 0;
  bool notify_backpressure = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peers_.find(peer);
    if (it == peers_.end() || it->second.state != ConnectionState::Connected || !it->second.remote) {
      return {SendStatus::Disconnected, 0};
    }

    auto& state = it->second;
    if (state.queued_bytes + frame.bytes.size() > config_.max_queue_bytes) {
      if (state.writable) {
        state.writable = false;
        notify_backpressure = true;
      }
      return {SendStatus::Backpressure, 0};
    }

    id = next_frame_id_++;
    state.queue.push_back({id, frame.bytes});
    state.queued_bytes += frame.bytes.size();
    remote = state.remote;
  }

  if (notify_backpressure) {
    notifyWritable(peer, false);
  }

  if (remote) {
    flush(peer);
  }

  return {SendStatus::Accepted, id};
}

size_t LoopbackTransport::queuedBytes(const PeerId& peer) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return 0;
  }
  return it->second.queued_bytes;
}

void LoopbackTransport::notifyConnection(const PeerId& peer, ConnectionState state) {
  safeInvoke(onConnectionState, peer, state);
}

void LoopbackTransport::notifyWritable(const PeerId& peer, bool writable) {
  safeInvoke(onWritable, peer, writable);
}

void LoopbackTransport::notifyAck(const PeerId& peer, FrameId id) {
  safeInvoke(onAck, peer, id);
}

void LoopbackTransport::notifySendFailed(const PeerId& peer, FrameId id, SendFailure reason) {
  safeInvoke(onSendFailed, peer, id, reason);
}

void LoopbackTransport::flush(const PeerId& peer) {
  while (true) {
    OutboundFrame frame;
    LoopbackTransport* remote = nullptr;
    bool notify_writable = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = peers_.find(peer);
      if (it == peers_.end() || it->second.state != ConnectionState::Connected || !it->second.remote) {
        return;
      }
      if (it->second.queue.empty()) {
        return;
      }

      frame = std::move(it->second.queue.front());
      it->second.queue.pop_front();
      if (frame.bytes.size() <= it->second.queued_bytes) {
        it->second.queued_bytes -= frame.bytes.size();
      } else {
        it->second.queued_bytes = 0;
      }
      remote = it->second.remote;

      if (!it->second.writable && it->second.queued_bytes < config_.max_queue_bytes) {
        it->second.writable = true;
        notify_writable = true;
      }
    }

    if (notify_writable) {
      notifyWritable(peer, true);
    }

    if (remote) {
      remote->receiveFrom(local_id_, frame.id, std::move(frame.bytes), this);
    }
  }
}

void LoopbackTransport::receiveFrom(const PeerId& sender,
                                   FrameId id,
                                   std::vector<uint8_t> bytes,
                                   LoopbackTransport* sender_transport) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peers_.find(sender);
    if (it == peers_.end() || it->second.state != ConnectionState::Connected) {
      return;
    }
  }

  bool delivered = true;
  if (onReceive) {
    try {
      onReceive(sender, Frame{std::move(bytes)});
    } catch (...) {
      delivered = false;
    }
  }

  if (!delivered) {
    if (sender_transport) {
      sender_transport->notifySendFailed(local_id_, id, SendFailure::Dropped);
    }
    return;
  }

  if (sender_transport) {
    sender_transport->notifyAck(local_id_, id);
  }
}

bool LoopbackNetwork::registerPeer(const PeerId& id, LoopbackTransport* transport) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (peers_.find(id) != peers_.end()) {
    return false;
  }
  peers_[id] = transport;
  return true;
}

void LoopbackNetwork::unregisterPeer(const PeerId& id) {
  std::lock_guard<std::mutex> lock(mutex_);
  peers_.erase(id);
}

LoopbackTransport* LoopbackNetwork::findPeer(const PeerId& id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = peers_.find(id);
  if (it == peers_.end()) {
    return nullptr;
  }
  return it->second;
}

}
