// Session and sync manager over transport and storage.
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto/Ratchet.h"
#include "storage/Storage.h"
#include "transport/ITransport.h"

namespace session {

enum class ContentType : uint8_t {
  Text = 1,
  Binary = 2,
  DeviceRevocation = 3
};

struct HistoryMessage {
  std::string chat_id;
  std::string msg_id;
  std::string sender_device;
  int64_t ts_ms = 0;
  uint8_t content_type = 0;
  std::vector<uint8_t> body;
  bool delivered = false;
  bool acked = false;
  int64_t index = 0;
};

struct IncomingMessage {
  std::string chat_id;
  std::string msg_id;
  std::string sender_device;
  int64_t ts_ms = 0;
  uint8_t content_type = 0;
  std::vector<uint8_t> body;
};

struct SessionManagerConfig {
  storage::Storage* storage = nullptr;
  transport::ITransport* transport = nullptr;
  crypto::AeadAlgorithm frame_aead = crypto::AeadAlgorithm::ChaCha20Poly1305;
  size_t max_padding = 16;
  size_t outbox_batch = 32;
  size_t sync_recent_window = 50;
  uint32_t bloom_bits = 512;
  uint32_t bloom_hashes = 3;
  uint64_t bloom_seed = 0xBEEF;
  size_t sync_batch = 20;
};

class SessionManager {
 public:
  explicit SessionManager(SessionManagerConfig config);

  void start();
  void stop();
  void tick(int64_t now_ms);
  void bindTransportCallbacks();

  void onTransportReceive(const transport::PeerId& peer, transport::Frame&& frame);
  void onTransportAck(const transport::PeerId& peer, transport::FrameId id);
  void onTransportSendFailed(const transport::PeerId& peer,
                             transport::FrameId id,
                             transport::SendFailure reason);
  void onTransportConnection(const transport::PeerId& peer, transport::ConnectionState state);
  void onTransportWritable(const transport::PeerId& peer, bool writable);

  void addSession(const transport::PeerId& peer,
                  const std::vector<uint8_t>& session_id,
                  const crypto::Ratchet& ratchet);

  bool loadSession(const transport::PeerId& peer);
  bool hasSession(const transport::PeerId& peer) const;
  void dropSession(const transport::PeerId& peer);

  void sendMessage(const transport::PeerId& peer,
                   const std::string& chat_id,
                   const std::vector<uint8_t>& plaintext,
                   uint8_t content_type = static_cast<uint8_t>(ContentType::Text));

  std::vector<HistoryMessage> getHistory(const std::string& chat_id,
                                         int64_t start_index,
                                         size_t limit) const;

  void syncWithPeer(const transport::PeerId& peer);
  void syncWithPeer(const transport::PeerId& peer, const std::vector<std::string>& chat_ids);

  std::function<void(const IncomingMessage&)> onMessage;
  std::function<void(const transport::PeerId&, const std::string&)> onError;
  std::function<void(const std::string&)> onDeviceRevoked;

 private:
  struct Session {
    storage::SessionState state;
    std::unique_ptr<crypto::Ratchet> ratchet;
    std::array<uint8_t, 32> frame_key{};
  };

  SessionManagerConfig config_;
  std::unordered_map<transport::PeerId, Session> sessions_;
  std::unordered_map<transport::FrameId, int64_t> in_flight_;
  std::unordered_map<int64_t, std::vector<transport::FrameId>> outbox_to_frames_;
  bool running_ = false;

  void handleReceive(const transport::PeerId& peer, transport::Frame&& frame);
  void handleAck(const transport::PeerId& peer, transport::FrameId id);
  void handleSendFailed(const transport::PeerId& peer, transport::FrameId id);
  void handleConnection(const transport::PeerId& peer, transport::ConnectionState state);
  void handleWritable(const transport::PeerId& peer, bool writable);

  void flushOutbox(int64_t now_ms);
  void persistSession(const transport::PeerId& peer, Session& session, int64_t now_ms);
};

}
