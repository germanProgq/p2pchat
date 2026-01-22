// QUIC-style UDP transport adapter.
#pragma once

#include "transport/ITransport.h"
#include "transport/Ice.h"

#include <memory>
#include <string>

namespace transport {

struct QuicConfig {
  std::string bind_address = "0.0.0.0";
  uint16_t bind_port = 0;
  size_t max_datagram_size = 1200;
  IceConfig ice{};
};

class QuicTransport final : public ITransport {
 public:
  QuicTransport(const PeerId& local_id, const QuicConfig& config, const TransportConfig& transport_config = {});
  ~QuicTransport() override;

  PeerId localId() const override;
  ConnectionState state(const PeerId& peer) const override;
  bool connect(const PeerInfo& peer) override;
  void disconnect(const PeerId& peer) override;
  SendResult send(const PeerId& peer, const Frame& frame) override;
  size_t queuedBytes(const PeerId& peer) const override;

  uint16_t boundPort() const;
  std::string localIceDescription() const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}
