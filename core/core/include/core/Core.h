// Core facade for session, storage, identity, and transport.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto/X3DH.h"
#include "identity/IdentityStore.h"
#include "session/SessionManager.h"
#include "transport/LoopbackTransport.h"
#include "transport/QuicTransport.h"
#include "transport/WebRtcTransport.h"

namespace core {

enum class TransportKind : uint8_t {
  Loopback = 1,
  Quic = 2,
  WebRtc = 3
};

enum class PeerStatus : uint8_t {
  Pending = 1,
  Ready = 2,
  Failed = 3
};

struct NodeConfig {
  std::string identity_path;
  std::string storage_path;
  std::string schema_path;
  std::shared_ptr<identity::MasterKeyProvider> master_key;
  TransportKind transport_kind = TransportKind::Quic;
  transport::TransportConfig transport{};
  transport::QuicConfig quic{};
  transport::WebRtcConfig webrtc{};
  transport::LoopbackNetwork* loopback_network = nullptr;
  size_t one_time_prekeys = 50;
  uint32_t signed_prekey_id = 1;
  uint32_t one_time_start_id = 1000;
  int64_t handshake_base_delay_ms = 200;
  int64_t handshake_max_delay_ms = 2000;
  uint32_t handshake_max_attempts = 5;
};

class Core {
 public:
  Core();
  ~Core();

  void start(const NodeConfig& config);
  void stop();
  void tick(int64_t now_ms);

  std::string localUserId() const;
  crypto::PreKeyBundle localPreKeyBundle() const;
  std::string localIceDescription() const;
  std::string beginLink() const;

  std::string addContact(const crypto::PreKeyBundle& bundle);
  void connectPeer(const transport::PeerInfo& info);
  void send(const std::string& chat_id,
            const std::vector<uint8_t>& plaintext,
            uint8_t content_type = static_cast<uint8_t>(session::ContentType::Text));
  std::vector<session::HistoryMessage> getHistory(const std::string& chat_id,
                                                  int64_t start_index,
                                                  size_t limit) const;
  void linkDevice(const std::string& link_code);

  std::function<void(const session::IncomingMessage&)> onMessage;
  std::function<void(const transport::PeerId&, transport::ConnectionState)> onConnectionChange;
  std::function<void(const transport::PeerId&, PeerStatus)> onPeerStatus;
  std::function<void(const transport::PeerId&, const std::string&)> onError;

 private:
  struct PendingHandshake {
    std::vector<uint8_t> session_id;
    std::vector<uint8_t> prekey_message;
    int64_t next_retry_ms = 0;
    uint32_t attempts = 0;
    bool failed_notified = false;
  };

  NodeConfig config_{};
  std::unique_ptr<identity::IdentityStore> identity_store_;
  identity::IdentityRecord identity_{};
  std::unique_ptr<storage::Storage> storage_;
  std::unique_ptr<transport::ITransport> transport_;
  std::unique_ptr<session::SessionManager> session_manager_;
  std::unordered_map<transport::PeerId, PendingHandshake> pending_handshakes_;
  std::unordered_map<transport::PeerId, transport::PeerInfo> peer_info_;
  bool running_ = false;

  void ensurePreKeys();
  identity::DeviceKeyPair activeDevice() const;

  void handleTransportReceive(const transport::PeerId& peer, transport::Frame&& frame);
  void handleTransportAck(const transport::PeerId& peer, transport::FrameId id);
  void handleTransportSendFailed(const transport::PeerId& peer,
                                 transport::FrameId id,
                                 transport::SendFailure reason);
  void handleTransportConnection(const transport::PeerId& peer, transport::ConnectionState state);
  void handleTransportWritable(const transport::PeerId& peer, bool writable);

  void handleHandshakeInit(const transport::PeerId& peer, const std::vector<uint8_t>& payload);
  void handleHandshakeAck(const transport::PeerId& peer, const std::vector<uint8_t>& payload);
  void sendHandshakeInit(const transport::PeerId& peer);

  std::string encodeLinkBundle(const crypto::PreKeyBundle& bundle) const;
  crypto::PreKeyBundle decodeLinkBundle(const std::string& link_code) const;
};

}
