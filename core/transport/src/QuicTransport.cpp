// QUIC transport adapter implementation.
#include "transport/QuicTransport.h"

#include "DatagramTransport.h"
#include "transport/Ice.h"

namespace transport {

class QuicTransport::Impl {
 public:
  Impl(const PeerId& local_id, const QuicConfig& config, const TransportConfig& transport_config)
      : transport(local_id,
                  DatagramConfig{config.bind_address, config.bind_port, config.max_datagram_size},
                  transport_config,
                  false) {
    ice_description = gatherIceDescription(config.ice,
                                           config.bind_address,
                                           config.bind_port,
                                           static_cast<IceSocket>(transport.socketHandle()));
    ice_blob = encodeIceDescription(ice_description);
    transport.start();
  }

  DatagramTransport transport;
  IceDescription ice_description;
  std::string ice_blob;
};

QuicTransport::QuicTransport(const PeerId& local_id, const QuicConfig& config, const TransportConfig& transport_config) {
  impl_ = std::make_unique<Impl>(local_id, config, transport_config);
  impl_->transport.onReceive = [this](const PeerId& peer, Frame&& frame) {
    if (onReceive) {
      onReceive(peer, std::move(frame));
    }
  };
  impl_->transport.onAck = [this](const PeerId& peer, FrameId id) {
    if (onAck) {
      onAck(peer, id);
    }
  };
  impl_->transport.onSendFailed = [this](const PeerId& peer, FrameId id, SendFailure failure) {
    if (onSendFailed) {
      onSendFailed(peer, id, failure);
    }
  };
  impl_->transport.onConnectionState = [this](const PeerId& peer, ConnectionState state) {
    if (onConnectionState) {
      onConnectionState(peer, state);
    }
  };
  impl_->transport.onWritable = [this](const PeerId& peer, bool writable) {
    if (onWritable) {
      onWritable(peer, writable);
    }
  };
}

QuicTransport::~QuicTransport() = default;

PeerId QuicTransport::localId() const {
  return impl_->transport.localId();
}

ConnectionState QuicTransport::state(const PeerId& peer) const {
  return impl_->transport.state(peer);
}

bool QuicTransport::connect(const PeerInfo& peer) {
  if (!peer.ice_blob.empty()) {
    try {
      IceDescription remote = decodeIceDescription(peer.ice_blob);
      auto candidate = selectIceCandidate(remote);
      if (candidate.address.empty() || candidate.port == 0) {
        return false;
      }
      PeerInfo direct = peer;
      direct.address = candidate.address;
      direct.port = candidate.port;
      direct.ice_blob.clear();
      return impl_->transport.connect(direct);
    } catch (const std::exception&) {
      return false;
    }
  }
  return impl_->transport.connect(peer);
}

void QuicTransport::disconnect(const PeerId& peer) {
  impl_->transport.disconnect(peer);
}

SendResult QuicTransport::send(const PeerId& peer, const Frame& frame) {
  return impl_->transport.send(peer, frame);
}

size_t QuicTransport::queuedBytes(const PeerId& peer) const {
  return impl_->transport.queuedBytes(peer);
}

uint16_t QuicTransport::boundPort() const {
  return impl_->transport.boundPort();
}

std::string QuicTransport::localIceDescription() const {
  return impl_->ice_blob;
}

}
