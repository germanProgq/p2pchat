// RN bridge surface and payload mapping. Spec: app/bridge/BridgeSpec.md.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
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
  int64_t ts_ms = 0;
  ContentType content_type = ContentType::Binary;
  std::vector<uint8_t> body;
};

struct HistoryMessage {
  std::string chat_id;
  std::string msg_id;
  std::string sender_device;
  int64_t ts_ms = 0;
  ContentType content_type = ContentType::Binary;
  std::vector<uint8_t> body;
  bool delivered = false;
  bool acked = false;
  int64_t index = 0;
};

struct ConnectionEvent {
  std::string peer_id;
  ConnectionState state = ConnectionState::Disconnected;
};

struct PeerStatusEvent {
  std::string peer_id;
  PeerStatus status = PeerStatus::Pending;
};

struct ErrorEvent {
  std::string peer_id;
  std::string message;
};

class CoreBackend {
 public:
  virtual ~CoreBackend() = default;

  virtual void start(const core::NodeConfig& config) = 0;
  virtual void stop() = 0;
  virtual std::string addContact(const crypto::PreKeyBundle& bundle) = 0;
  virtual void send(const std::string& chat_id,
                    const std::vector<uint8_t>& plaintext,
                    uint8_t content_type) = 0;
  virtual std::vector<session::HistoryMessage> getHistory(const std::string& chat_id,
                                                          int64_t start_index,
                                                          size_t limit) const = 0;
  virtual void linkDevice(const std::string& link_code) = 0;

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
  std::string addContact(const crypto::PreKeyBundle& bundle) override;
  void send(const std::string& chat_id,
            const std::vector<uint8_t>& plaintext,
            uint8_t content_type) override;
  std::vector<session::HistoryMessage> getHistory(const std::string& chat_id,
                                                  int64_t start_index,
                                                  size_t limit) const override;
  void linkDevice(const std::string& link_code) override;

 private:
  std::unique_ptr<core::Core> core_;
  void bindCallbacks();
};

class Bridge {
 public:
  explicit Bridge(std::shared_ptr<CoreBackend> backend);

  void start(const NodeConfig& config);
  std::string addContact(const std::vector<uint8_t>& prekey_bundle);
  void send(const std::string& chat_id, const std::string& text);
  void send(const std::string& chat_id, const std::vector<uint8_t>& bytes);
  std::vector<HistoryMessage> getHistory(const std::string& chat_id,
                                         int64_t start_index,
                                         size_t limit) const;
  void linkDevice(const std::string& link_code);

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
