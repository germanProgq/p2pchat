// JSON payload snapshots for bridge events. Spec: app/bridge/BridgeSpec.md.
#pragma once

#include <string>

#include "bridge/Bridge.h"

namespace bridge {

std::string toJsonPayload(const IncomingMessage& message);
std::string toJsonPayload(const ConnectionEvent& event);
std::string toJsonPayload(const PeerStatusEvent& event);
std::string toJsonPayload(const ErrorEvent& event);
std::string toJsonPayload(const HistoryMessage& message);

}
