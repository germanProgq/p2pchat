// Transport abstraction tests. Spec: core/transport/ITransport.h.
#include "transport/ITransport.h"
#include "transport/LoopbackTransport.h"

#include <algorithm>
#include <deque>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using transport::ConnectionState;
using transport::Frame;
using transport::FrameId;
using transport::ITransport;
using transport::PeerId;
using transport::PeerInfo;
using transport::SendFailure;
using transport::SendResult;
using transport::SendStatus;
using transport::TransportConfig;

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

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

class SimulatedNetwork;

class SimulatedTransport : public ITransport {
 public:
  SimulatedTransport(const PeerId& local_id, SimulatedNetwork& network, TransportConfig config = {});
  ~SimulatedTransport() override;

  PeerId localId() const override;
  ConnectionState state(const PeerId& peer) const override;
  bool connect(const PeerInfo& peer) override;
  void disconnect(const PeerId& peer) override;
  SendResult send(const PeerId& peer, const Frame& frame) override;
  size_t queuedBytes(const PeerId& peer) const override;

  void process(int64_t now_ms);
  uint32_t attemptsFor(const PeerId& peer, FrameId id) const;

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
    SimulatedTransport* remote = nullptr;
    ConnectionState state = ConnectionState::Disconnected;
    size_t queued_bytes = 0;
    bool writable = true;
    uint64_t in_flight = 0;
    std::deque<FrameId> send_order;
    std::unordered_map<FrameId, PendingFrame> pending;
    std::unordered_map<FrameId, uint32_t> completed_attempts;
    ReceiveState receive;
  };

  SimulatedNetwork& network_;
  PeerId local_id_;
  TransportConfig config_;
  FrameId next_frame_id_ = 1;
  std::unordered_map<PeerId, PeerState> peers_;

  void notifyWritable(const PeerId& peer, bool writable);
  void notifyConnection(const PeerId& peer, ConnectionState state);
  void notifyAck(const PeerId& peer, FrameId id);
  void notifySendFailed(const PeerId& peer, FrameId id, SendFailure reason);

  void scheduleSend(const PeerId& peer, PendingFrame& frame, int64_t now_ms);
  void handleAckFrom(const PeerId& peer, FrameId id);
  void receiveFrom(const PeerId& sender,
                   FrameId id,
                   std::vector<uint8_t> bytes,
                   SimulatedTransport* sender_transport);

  friend class SimulatedNetwork;
};

class SimulatedNetwork {
 public:
  bool registerPeer(const PeerId& id, SimulatedTransport* transport);
  void unregisterPeer(const PeerId& id);
  SimulatedTransport* findPeer(const PeerId& id) const;

  void setLatency(const PeerId& from, const PeerId& to, int64_t ms);
  void dropNextAck(const PeerId& from, const PeerId& to);
  bool shouldDropAck(const PeerId& from, const PeerId& to);

  void scheduleDelivery(const PeerId& from,
                        const PeerId& to,
                        FrameId id,
                        std::vector<uint8_t> bytes,
                        SimulatedTransport* sender);
  void advanceTime(int64_t delta_ms);
  int64_t nowMs() const { return now_ms_; }

 private:
  struct LinkBehavior {
    int64_t latency_ms = 0;
    bool drop_next_ack = false;
    bool drop_acks = false;
  };

  struct DeliveryEvent {
    int64_t deliver_at = 0;
    PeerId from;
    PeerId to;
    FrameId id = 0;
    std::vector<uint8_t> bytes;
    SimulatedTransport* sender = nullptr;
  };

  bool deliverDue();

  int64_t now_ms_ = 0;
  std::map<PeerId, SimulatedTransport*> peers_;
  std::map<std::pair<PeerId, PeerId>, LinkBehavior> links_;
  std::vector<DeliveryEvent> events_;
};

SimulatedTransport::SimulatedTransport(const PeerId& local_id,
                                       SimulatedNetwork& network,
                                       TransportConfig config)
    : network_(network), local_id_(local_id), config_(config) {
  if (!network_.registerPeer(local_id_, this)) {
    throw std::runtime_error("simulated peer already registered");
  }
}

SimulatedTransport::~SimulatedTransport() {
  std::vector<PeerId> peers;
  peers.reserve(peers_.size());
  for (const auto& entry : peers_) {
    if (entry.second.state == ConnectionState::Connected) {
      peers.push_back(entry.first);
    }
  }
  for (const auto& peer : peers) {
    disconnect(peer);
  }
  network_.unregisterPeer(local_id_);
}

PeerId SimulatedTransport::localId() const {
  return local_id_;
}

ConnectionState SimulatedTransport::state(const PeerId& peer) const {
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return ConnectionState::Disconnected;
  }
  return it->second.state;
}

bool SimulatedTransport::connect(const PeerInfo& peer) {
  if (peer.id.empty() || peer.id == local_id_) {
    return false;
  }
  SimulatedTransport* remote = network_.findPeer(peer.id);
  if (!remote) {
    return false;
  }

  auto& local_state = peers_[peer.id];
  bool notify_local = local_state.state != ConnectionState::Connected;
  local_state.state = ConnectionState::Connected;
  local_state.remote = remote;

  auto& remote_state = remote->peers_[local_id_];
  bool notify_remote = remote_state.state != ConnectionState::Connected;
  remote_state.state = ConnectionState::Connected;
  remote_state.remote = this;

  if (notify_local) {
    notifyConnection(peer.id, ConnectionState::Connected);
  }
  if (notify_remote) {
    remote->notifyConnection(local_id_, ConnectionState::Connected);
  }
  return true;
}

void SimulatedTransport::disconnect(const PeerId& peer) {
  SimulatedTransport* remote = network_.findPeer(peer);

  std::vector<FrameId> local_dropped;
  std::vector<FrameId> remote_dropped;
  bool notify_local = false;
  bool notify_remote = false;
  bool notify_writable_local = false;
  bool notify_writable_remote = false;

  auto it_local = peers_.find(peer);
  if (it_local != peers_.end()) {
    notify_local = it_local->second.state != ConnectionState::Disconnected;
    notify_writable_local = !it_local->second.writable;
    for (const auto& entry : it_local->second.pending) {
      local_dropped.push_back(entry.first);
      it_local->second.completed_attempts[entry.first] = entry.second.attempts;
    }
    it_local->second.pending.clear();
    it_local->second.send_order.clear();
    it_local->second.queued_bytes = 0;
    it_local->second.in_flight = 0;
    it_local->second.writable = true;
    it_local->second.state = ConnectionState::Disconnected;
    it_local->second.remote = nullptr;
  }

  if (remote) {
    auto it_remote = remote->peers_.find(local_id_);
    if (it_remote != remote->peers_.end()) {
      notify_remote = it_remote->second.state != ConnectionState::Disconnected;
      notify_writable_remote = !it_remote->second.writable;
      for (const auto& entry : it_remote->second.pending) {
        remote_dropped.push_back(entry.first);
        it_remote->second.completed_attempts[entry.first] = entry.second.attempts;
      }
      it_remote->second.pending.clear();
      it_remote->second.send_order.clear();
      it_remote->second.queued_bytes = 0;
      it_remote->second.in_flight = 0;
      it_remote->second.writable = true;
      it_remote->second.state = ConnectionState::Disconnected;
      it_remote->second.remote = nullptr;
    }
  }

  if (notify_writable_local) {
    notifyWritable(peer, true);
  }
  if (notify_writable_remote && remote) {
    remote->notifyWritable(local_id_, true);
  }

  for (FrameId id : local_dropped) {
    notifySendFailed(peer, id, SendFailure::Disconnected);
  }
  for (FrameId id : remote_dropped) {
    if (remote) {
      remote->notifySendFailed(local_id_, id, SendFailure::Disconnected);
    }
  }

  if (notify_local) {
    notifyConnection(peer, ConnectionState::Disconnected);
  }
  if (notify_remote && remote) {
    remote->notifyConnection(local_id_, ConnectionState::Disconnected);
  }
}

SendResult SimulatedTransport::send(const PeerId& peer, const Frame& frame) {
  if (frame.bytes.size() > config_.max_queue_bytes) {
    return {SendStatus::TooLarge, 0};
  }

  auto it = peers_.find(peer);
  if (it == peers_.end() || it->second.state != ConnectionState::Connected || !it->second.remote) {
    return {SendStatus::Disconnected, 0};
  }

  auto& state = it->second;
  if (state.queued_bytes + frame.bytes.size() > config_.max_queue_bytes) {
    if (state.writable) {
      state.writable = false;
      notifyWritable(peer, false);
    }
    return {SendStatus::Backpressure, 0};
  }

  FrameId id = next_frame_id_++;
  PendingFrame pending;
  pending.id = id;
  pending.bytes = frame.bytes;
  pending.next_send_at_ms = network_.nowMs();

  state.pending[id] = std::move(pending);
  state.send_order.push_back(id);
  state.queued_bytes += frame.bytes.size();

  process(network_.nowMs());

  return {SendStatus::Accepted, id};
}

size_t SimulatedTransport::queuedBytes(const PeerId& peer) const {
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return 0;
  }
  return it->second.queued_bytes;
}

void SimulatedTransport::process(int64_t now_ms) {
  for (auto& entry : peers_) {
    auto& state = entry.second;
    if (state.state != ConnectionState::Connected) {
      continue;
    }

    std::vector<FrameId> to_fail;
    for (const auto& id : state.send_order) {
      auto it = state.pending.find(id);
      if (it == state.pending.end()) {
        continue;
      }
      auto& frame = it->second;
      if (frame.awaiting_ack && now_ms >= frame.ack_deadline_ms) {
        if (state.in_flight > 0) {
          state.in_flight--;
        }
        if (frame.attempts >= config_.retry.max_attempts) {
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
      state.completed_attempts[id] = it->second.attempts;
      size_t size = it->second.bytes.size();
      state.pending.erase(it);
      state.send_order.erase(std::remove(state.send_order.begin(), state.send_order.end(), id),
                             state.send_order.end());
      if (state.queued_bytes >= size) {
        state.queued_bytes -= size;
      } else {
        state.queued_bytes = 0;
      }
      if (!state.writable && state.queued_bytes < config_.max_queue_bytes) {
        state.writable = true;
        notifyWritable(entry.first, true);
      }
      notifySendFailed(entry.first, id, SendFailure::Timeout);
    }

    for (const auto& id : state.send_order) {
      if (state.in_flight >= config_.max_in_flight) {
        break;
      }
      auto it = state.pending.find(id);
      if (it == state.pending.end()) {
        continue;
      }
      auto& frame = it->second;
      if (!frame.awaiting_ack && frame.next_send_at_ms <= now_ms) {
        scheduleSend(entry.first, frame, now_ms);
      }
    }
  }
}

uint32_t SimulatedTransport::attemptsFor(const PeerId& peer, FrameId id) const {
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return 0;
  }
  auto pending_it = it->second.pending.find(id);
  if (pending_it != it->second.pending.end()) {
    return pending_it->second.attempts;
  }
  auto completed_it = it->second.completed_attempts.find(id);
  if (completed_it == it->second.completed_attempts.end()) {
    return 0;
  }
  return completed_it->second;
}

void SimulatedTransport::notifyWritable(const PeerId& peer, bool writable) {
  safeInvoke(onWritable, peer, writable);
}

void SimulatedTransport::notifyConnection(const PeerId& peer, ConnectionState state) {
  safeInvoke(onConnectionState, peer, state);
}

void SimulatedTransport::notifyAck(const PeerId& peer, FrameId id) {
  safeInvoke(onAck, peer, id);
}

void SimulatedTransport::notifySendFailed(const PeerId& peer, FrameId id, SendFailure reason) {
  safeInvoke(onSendFailed, peer, id, reason);
}

void SimulatedTransport::scheduleSend(const PeerId& peer, PendingFrame& frame, int64_t now_ms) {
  if (frame.awaiting_ack) {
    return;
  }
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return;
  }
  auto& state = it->second;
  frame.attempts += 1;
  frame.awaiting_ack = true;
  frame.ack_deadline_ms = now_ms + config_.retry.nextDelayMs(frame.attempts - 1);
  if (frame.ack_deadline_ms < now_ms) {
    frame.ack_deadline_ms = now_ms;
  }
  state.in_flight += 1;
  network_.scheduleDelivery(local_id_, peer, frame.id, frame.bytes, this);
}

void SimulatedTransport::handleAckFrom(const PeerId& peer, FrameId id) {
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return;
  }
  auto& state = it->second;
  auto pending_it = state.pending.find(id);
  if (pending_it == state.pending.end()) {
    return;
  }
  state.completed_attempts[id] = pending_it->second.attempts;
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
  if (!state.writable && state.queued_bytes < config_.max_queue_bytes) {
    state.writable = true;
    notifyWritable(peer, true);
  }
  notifyAck(peer, id);
}

void SimulatedTransport::receiveFrom(const PeerId& sender,
                                     FrameId id,
                                     std::vector<uint8_t> bytes,
                                     SimulatedTransport* sender_transport) {
  auto it = peers_.find(sender);
  if (it == peers_.end() || it->second.state != ConnectionState::Connected) {
    return;
  }
  auto& recv = it->second.receive;
  if (!recv.initialized) {
    recv.initialized = true;
    recv.next_expected = id;
  }

  if (id >= recv.next_expected && recv.buffer.find(id) == recv.buffer.end()) {
    recv.buffer.emplace(id, std::move(bytes));
  }

  if (sender_transport && !network_.shouldDropAck(local_id_, sender)) {
    sender_transport->handleAckFrom(local_id_, id);
  }

  while (true) {
    auto buf_it = recv.buffer.find(recv.next_expected);
    if (buf_it == recv.buffer.end()) {
      break;
    }
    auto payload = std::move(buf_it->second);
    recv.buffer.erase(buf_it);
    safeInvoke(onReceive, sender, Frame{std::move(payload)});
    recv.next_expected += 1;
  }
}

bool SimulatedNetwork::registerPeer(const PeerId& id, SimulatedTransport* transport) {
  if (peers_.find(id) != peers_.end()) {
    return false;
  }
  peers_[id] = transport;
  return true;
}

void SimulatedNetwork::unregisterPeer(const PeerId& id) {
  peers_.erase(id);
}

SimulatedTransport* SimulatedNetwork::findPeer(const PeerId& id) const {
  auto it = peers_.find(id);
  if (it == peers_.end()) {
    return nullptr;
  }
  return it->second;
}

void SimulatedNetwork::setLatency(const PeerId& from, const PeerId& to, int64_t ms) {
  links_[{from, to}].latency_ms = ms;
}

void SimulatedNetwork::dropNextAck(const PeerId& from, const PeerId& to) {
  links_[{from, to}].drop_next_ack = true;
}

bool SimulatedNetwork::shouldDropAck(const PeerId& from, const PeerId& to) {
  auto it = links_.find({from, to});
  if (it == links_.end()) {
    return false;
  }
  if (it->second.drop_acks) {
    return true;
  }
  if (it->second.drop_next_ack) {
    it->second.drop_next_ack = false;
    return true;
  }
  return false;
}

void SimulatedNetwork::scheduleDelivery(const PeerId& from,
                                        const PeerId& to,
                                        FrameId id,
                                        std::vector<uint8_t> bytes,
                                        SimulatedTransport* sender) {
  int64_t latency = 0;
  auto it = links_.find({from, to});
  if (it != links_.end()) {
    latency = it->second.latency_ms;
  }
  DeliveryEvent event;
  event.deliver_at = now_ms_ + latency;
  event.from = from;
  event.to = to;
  event.id = id;
  event.bytes = std::move(bytes);
  event.sender = sender;
  events_.push_back(std::move(event));
}

bool SimulatedNetwork::deliverDue() {
  bool delivered = false;
  auto it = events_.begin();
  while (it != events_.end()) {
    if (it->deliver_at <= now_ms_) {
      DeliveryEvent event = std::move(*it);
      it = events_.erase(it);
      auto* receiver = findPeer(event.to);
      if (receiver) {
        receiver->receiveFrom(event.from, event.id, std::move(event.bytes), event.sender);
      }
      delivered = true;
    } else {
      ++it;
    }
  }
  return delivered;
}

void SimulatedNetwork::advanceTime(int64_t delta_ms) {
  if (delta_ms < 0) {
    return;
  }
  now_ms_ += delta_ms;
  bool progress = true;
  while (progress) {
    progress = deliverDue();
    for (auto& entry : peers_) {
      entry.second->process(now_ms_);
    }
    progress = deliverDue() || progress;
  }
}

void testLoopbackOrderingAndAck() {
  transport::LoopbackNetwork network;
  transport::TransportConfig config;
  transport::LoopbackTransport a("A", network, config);
  transport::LoopbackTransport b("B", network, config);

  std::vector<int> received;
  std::vector<FrameId> acks;
  bool a_connected = false;
  bool b_connected = false;

  a.onAck = [&](const PeerId&, FrameId id) { acks.push_back(id); };
  a.onConnectionState = [&](const PeerId&, ConnectionState state) {
    if (state == ConnectionState::Connected) {
      a_connected = true;
    }
  };
  b.onConnectionState = [&](const PeerId&, ConnectionState state) {
    if (state == ConnectionState::Connected) {
      b_connected = true;
    }
  };
  b.onReceive = [&](const PeerId&, Frame&& frame) {
    if (!frame.bytes.empty()) {
      received.push_back(frame.bytes[0]);
    }
  };

  require(a.connect(PeerInfo{"B"}), "loopback connect failed");
  require(a_connected && b_connected, "connection callbacks missing");

  auto r1 = a.send("B", Frame{{1}});
  auto r2 = a.send("B", Frame{{2}});
  auto r3 = a.send("B", Frame{{3}});

  require(r1.status == SendStatus::Accepted, "send 1 rejected");
  require(r2.status == SendStatus::Accepted, "send 2 rejected");
  require(r3.status == SendStatus::Accepted, "send 3 rejected");

  require(received.size() == 3, "unexpected receive count");
  require(received[0] == 1 && received[1] == 2 && received[2] == 3, "receive order mismatch");
  require(acks.size() == 3, "ack count mismatch");
  require(acks[0] == r1.id && acks[1] == r2.id && acks[2] == r3.id, "ack order mismatch");
}

void testSimulatedRetry() {
  SimulatedNetwork network;
  TransportConfig config;
  config.retry.base_delay_ms = 10;
  config.retry.max_delay_ms = 40;
  config.retry.max_attempts = 3;
  config.retry.jitter_ratio = 0.0;

  SimulatedTransport a("A", network, config);
  SimulatedTransport b("B", network, config);

  int receive_count = 0;
  bool acked = false;

  b.onReceive = [&](const PeerId&, Frame&&) { receive_count++; };
  a.onAck = [&](const PeerId&, FrameId) { acked = true; };

  require(a.connect(PeerInfo{"B"}), "simulated connect failed");
  network.dropNextAck("B", "A");

  auto result = a.send("B", Frame{{9}});
  require(result.status == SendStatus::Accepted, "send not accepted");

  network.advanceTime(1);
  require(receive_count == 1, "initial receive missing");
  require(!acked, "ack should be dropped");

  network.advanceTime(15);
  require(acked, "ack missing after retry");
  require(receive_count == 1, "duplicate delivery detected");
  require(a.attemptsFor("B", result.id) >= 2, "retry did not occur");
}

void testBackpressure() {
  SimulatedNetwork network;
  TransportConfig config;
  config.max_queue_bytes = 4;
  config.retry.base_delay_ms = 5;
  config.retry.max_delay_ms = 10;
  config.retry.max_attempts = 2;
  config.retry.jitter_ratio = 0.0;

  SimulatedTransport a("A", network, config);
  SimulatedTransport b("B", network, config);

  bool writable_false = false;
  bool writable_true = false;
  a.onWritable = [&](const PeerId&, bool writable) {
    if (!writable) {
      writable_false = true;
    } else {
      writable_true = true;
    }
  };

  require(a.connect(PeerInfo{"B"}), "simulated connect failed");

  auto r1 = a.send("B", Frame{{1, 2, 3}});
  require(r1.status == SendStatus::Accepted, "first send rejected");
  auto r2 = a.send("B", Frame{{4, 5, 6}});
  require(r2.status == SendStatus::Backpressure, "backpressure not signaled");
  require(writable_false, "writable=false not signaled");

  network.advanceTime(5);
  require(writable_true, "writable=true not signaled");
}

void testReconnection() {
  SimulatedNetwork network;
  TransportConfig config;
  SimulatedTransport a("A", network, config);
  SimulatedTransport b("B", network, config);

  bool saw_disconnect = false;
  bool saw_reconnect = false;
  int received = 0;

  a.onConnectionState = [&](const PeerId&, ConnectionState state) {
    if (state == ConnectionState::Disconnected) {
      saw_disconnect = true;
    }
    if (state == ConnectionState::Connected) {
      saw_reconnect = true;
    }
  };
  b.onReceive = [&](const PeerId&, Frame&&) { received++; };

  require(a.connect(PeerInfo{"B"}), "connect failed");
  a.disconnect("B");
  require(saw_disconnect, "disconnect callback missing");

  auto rejected = a.send("B", Frame{{7}});
  require(rejected.status == SendStatus::Disconnected, "send should be rejected when disconnected");

  saw_reconnect = false;
  require(a.connect(PeerInfo{"B"}), "reconnect failed");
  require(saw_reconnect, "reconnect callback missing");

  auto accepted = a.send("B", Frame{{8}});
  require(accepted.status == SendStatus::Accepted, "send after reconnect rejected");
  network.advanceTime(1);
  require(received == 1, "message not delivered after reconnect");
}

}

int main() {
  const std::vector<std::pair<std::string, void (*)()>> tests = {
      {"loopback_ordering_and_ack", testLoopbackOrderingAndAck},
      {"simulated_retry", testSimulatedRetry},
      {"backpressure", testBackpressure},
      {"reconnection", testReconnection},
  };

  int failures = 0;
  for (const auto& test : tests) {
    try {
      test.second();
      std::cout << "[PASS] " << test.first << std::endl;
    } catch (const std::exception& ex) {
      std::cout << "[FAIL] " << test.first << ": " << ex.what() << std::endl;
      failures++;
    }
  }

  return failures == 0 ? 0 : 1;
}
