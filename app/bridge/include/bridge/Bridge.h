// RN bridge surface and payload mapping. Spec: app/bridge/BridgeSpec.md.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "core/Core.h"
#include "crypto/X3DH.h"
#include "identity/IdentityStore.h"
#include "session/SessionManager.h"
#include "transport/ITransport.h"
#include "transport/QuicTransport.h"
#include "transport/WebRtcTransport.h"

namespace transport {
class LoopbackNetwork;
}

namespace bridge {

enum class TransportKind : uint8_t {
  Loopback = 1,
  Quic = 2,
  WebRtc = 3
};

enum class ConnectionState : uint8_t {
  Disconnected = 0,
  Connecting = 1,
  Connected = 2
};

enum class PeerStatus : uint8_t {
  Pending = 1,
  Ready = 2,
  Failed = 3
};

enum class ContentType : uint8_t {
  Text = 1,
  Binary = 2
};

struct NodeConfig {
  std::string identity_path;
  std::string storage_path;
  std::string schema_path;
  std::string username;
  std::string password;
  std::vector<uint8_t> master_key;
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

struct IncomingMessage {
  std::string chat_id;
  std::string msg_id;
  std::string sender_device;
  std::string peer_username;
  int64_t ts_ms = 0;
  ContentType content_type = ContentType::Binary;
  std::vector<uint8_t> body;
};

struct HistoryMessage {
  std::string chat_id;
  std::string msg_id;
  std::string sender_device;
  std::string peer_username;
  int64_t ts_ms = 0;
  ContentType content_type = ContentType::Binary;
  std::vector<uint8_t> body;
  bool delivered = false;
  bool acked = false;
  int64_t index = 0;
};

struct ConnectionEvent {
  std::string peer_id;
  std::string peer_username;
  ConnectionState state = ConnectionState::Disconnected;
};

struct PeerStatusEvent {
  std::string peer_id;
  std::string peer_username;
  PeerStatus status = PeerStatus::Pending;
};

struct ErrorEvent {
  std::string peer_id;
  std::string peer_username;
  std::string message;
};

struct PeerInfo {
  std::string peer_id;
  std::string address;
  uint16_t port = 0;
  std::string ice_blob;
};

class CoreBackend {
 public:
  virtual ~CoreBackend() = default;

  virtual void start(const core::NodeConfig& config) = 0;
  virtual void stop() = 0;
  virtual std::vector<uint8_t> localBundle() const = 0;
  virtual std::string localIce() const = 0;
  virtual std::string beginLink() const = 0;
  virtual std::string addContact(const crypto::PreKeyBundle& bundle) = 0;
  virtual std::string addContactWithUsername(const crypto::PreKeyBundle& bundle, const std::string& username) = 0;
  virtual void connectPeer(const transport::PeerInfo& info) = 0;
  virtual void send(const std::string& chat_id,
                    const std::vector<uint8_t>& plaintext,
                    uint8_t content_type) = 0;
  virtual std::vector<session::HistoryMessage> getHistory(const std::string& chat_id,
                                                          int64_t start_index,
                                                          size_t limit) const = 0;
  virtual void linkDevice(const std::string& link_code) = 0;
  virtual std::optional<std::string> lookupUsername(const std::string& peer_id) const = 0;
  virtual std::string localUsername() const = 0;
  virtual std::vector<uint8_t> localIdentityPublicKey() const = 0;
  virtual std::vector<uint8_t> signIdentity(const std::vector<uint8_t>& message) const = 0;
  virtual void updateProfile(const std::string& username, const std::string& password) = 0;

  std::function<void(const session::IncomingMessage&)> onMessage;
  std::function<void(const transport::PeerId&, transport::ConnectionState)> onConnectionChange;
  std::function<void(const transport::PeerId&, core::PeerStatus)> onPeerStatus;
  std::function<void(const transport::PeerId&, const std::string&)> onError;
};

class CoreAdapter final : public CoreBackend {
 public:
  CoreAdapter();
  explicit CoreAdapter(std::unique_ptr<core::Core> core);
  ~CoreAdapter() override;

  void start(const core::NodeConfig& config) override;
  void stop() override;
  std::vector<uint8_t> localBundle() const override;
  std::string localIce() const override;
  std::string beginLink() const override;
  void tick(int64_t now_ms);
  std::string addContact(const crypto::PreKeyBundle& bundle) override;
  std::string addContactWithUsername(const crypto::PreKeyBundle& bundle, const std::string& username) override;
  void connectPeer(const transport::PeerInfo& info) override;
  void send(const std::string& chat_id,
            const std::vector<uint8_t>& plaintext,
            uint8_t content_type) override;
  std::vector<session::HistoryMessage> getHistory(const std::string& chat_id,
                                                  int64_t start_index,
                                                  size_t limit) const override;
  void linkDevice(const std::string& link_code) override;
  std::optional<std::string> lookupUsername(const std::string& peer_id) const override;
  std::string localUsername() const override;
  std::vector<uint8_t> localIdentityPublicKey() const override;
  std::vector<uint8_t> signIdentity(const std::vector<uint8_t>& message) const override;
  void updateProfile(const std::string& username, const std::string& password) override;

 private:
  std::unique_ptr<core::Core> core_;
  void bindCallbacks();
};

class Bridge {
 public:
  explicit Bridge(std::shared_ptr<CoreBackend> backend);

  void start(const NodeConfig& config);
  std::vector<uint8_t> localBundle() const;
  std::string localIce() const;
  std::string beginLink() const;
  std::string addContact(const std::vector<uint8_t>& prekey_bundle);
  std::string addContactWithUsername(const std::vector<uint8_t>& prekey_bundle, const std::string& username);
  void connectPeer(const PeerInfo& info);
  void send(const std::string& chat_id, const std::string& text);
  void send(const std::string& chat_id, const std::vector<uint8_t>& bytes);
  std::vector<HistoryMessage> getHistory(const std::string& chat_id,
                                         int64_t start_index,
                                         size_t limit) const;
  void linkDevice(const std::string& link_code);
  std::string localUsername() const;
  std::vector<uint8_t> localIdentityPublicKey() const;
  std::vector<uint8_t> signIdentity(const std::vector<uint8_t>& message) const;
  void updateProfile(const std::string& username, const std::string& password);

  std::function<void(const IncomingMessage&)> onMessage;
  std::function<void(const ConnectionEvent&)> onConnectionChange;
  std::function<void(const PeerStatusEvent&)> onPeerStatus;
  std::function<void(const ErrorEvent&)> onError;

 private:
  std::shared_ptr<CoreBackend> backend_;

  void bindBackend();
  core::NodeConfig toCoreConfig(const NodeConfig& config) const;
  static ConnectionState toBridgeState(transport::ConnectionState state);
  static PeerStatus toBridgeStatus(core::PeerStatus status);
  static ContentType toBridgeContentType(uint8_t value);
};

}
