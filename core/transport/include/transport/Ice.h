// ICE candidate gathering and signaling utilities.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace transport {

enum class IceCandidateType : uint8_t {
  Host = 1,
  Srflx = 2,
  Relay = 3
};

struct IceCandidate {
  IceCandidateType type = IceCandidateType::Host;
  std::string address;
  uint16_t port = 0;
  uint32_t priority = 0;
};

struct IceDescription {
  std::string ufrag;
  std::string pwd;
  std::vector<IceCandidate> candidates;
};

struct IceConfig {
  std::vector<std::string> stun_servers;
  std::string bind_address = "0.0.0.0";
  uint16_t bind_port = 0;
  int timeout_ms = 1500;
  std::vector<IceCandidate> relay_candidates;
};

using IceSocket = std::intptr_t;

IceDescription gatherIceDescription(const IceConfig& config,
                                    const std::string& bind_address,
                                    uint16_t bind_port,
                                    IceSocket socket_handle = static_cast<IceSocket>(-1));

std::string encodeIceDescription(const IceDescription& description);
IceDescription decodeIceDescription(const std::string& blob);
IceCandidate selectIceCandidate(const IceDescription& description);

}
