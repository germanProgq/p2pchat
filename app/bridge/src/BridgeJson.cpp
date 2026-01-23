// Bridge event JSON payload encoder. Spec: app/bridge/BridgeSpec.md.
#include "bridge/BridgeJson.h"

#include <cstdio>
#include <string>

namespace bridge {

namespace {

std::string escapeJson(const std::string& input) {
  std::string out;
  out.reserve(input.size() + 8);
  for (unsigned char c : input) {
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[7];
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(c));
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
}

std::string bytesToJson(const std::vector<uint8_t>& bytes) {
  std::string out;
  out.push_back('[');
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      out.push_back(',');
    }
    out += std::to_string(bytes[i]);
  }
  out.push_back(']');
  return out;
}

const char* contentTypeToString(ContentType type) {
  switch (type) {
    case ContentType::Text:
      return "text";
    case ContentType::Binary:
      return "binary";
  }
  return "binary";
}

const char* connectionStateToString(ConnectionState state) {
  switch (state) {
    case ConnectionState::Disconnected:
      return "disconnected";
    case ConnectionState::Connecting:
      return "connecting";
    case ConnectionState::Connected:
      return "connected";
  }
  return "disconnected";
}

const char* peerStatusToString(PeerStatus status) {
  switch (status) {
    case PeerStatus::Pending:
      return "pending";
    case PeerStatus::Ready:
      return "ready";
    case PeerStatus::Failed:
      return "failed";
  }
  return "failed";
}

}

std::string toJsonPayload(const IncomingMessage& message) {
  std::string out;
  out.reserve(256 + message.body.size() * 4);
  out += "{\"chatId\":\"";
  out += escapeJson(message.chat_id);
  out += "\",\"msgId\":\"";
  out += escapeJson(message.msg_id);
  out += "\",\"senderDevice\":\"";
  out += escapeJson(message.sender_device);
  out += "\",\"tsMs\":";
  out += std::to_string(message.ts_ms);
  out += ",\"contentType\":\"";
  out += contentTypeToString(message.content_type);
  out += "\",\"body\":";
  out += bytesToJson(message.body);
  out += "}";
  return out;
}

std::string toJsonPayload(const ConnectionEvent& event) {
  std::string out;
  out.reserve(96);
  out += "{\"peerId\":\"";
  out += escapeJson(event.peer_id);
  out += "\",\"state\":\"";
  out += connectionStateToString(event.state);
  out += "\"}";
  return out;
}

std::string toJsonPayload(const PeerStatusEvent& event) {
  std::string out;
  out.reserve(96);
  out += "{\"peerId\":\"";
  out += escapeJson(event.peer_id);
  out += "\",\"status\":\"";
  out += peerStatusToString(event.status);
  out += "\"}";
  return out;
}

std::string toJsonPayload(const ErrorEvent& event) {
  std::string out;
  out.reserve(128);
  out += "{\"peerId\":\"";
  out += escapeJson(event.peer_id);
  out += "\",\"message\":\"";
  out += escapeJson(event.message);
  out += "\"}";
  return out;
}

std::string toJsonPayload(const HistoryMessage& message) {
  std::string out;
  out.reserve(256 + message.body.size() * 4);
  out += "{\"chatId\":\"";
  out += escapeJson(message.chat_id);
  out += "\",\"msgId\":\"";
  out += escapeJson(message.msg_id);
  out += "\",\"senderDevice\":\"";
  out += escapeJson(message.sender_device);
  out += "\",\"tsMs\":";
  out += std::to_string(message.ts_ms);
  out += ",\"contentType\":\"";
  out += contentTypeToString(message.content_type);
  out += "\",\"body\":";
  out += bytesToJson(message.body);
  out += ",\"delivered\":";
  out += message.delivered ? "true" : "false";
  out += ",\"acked\":";
  out += message.acked ? "true" : "false";
  out += ",\"index\":";
  out += std::to_string(message.index);
  out += "}";
  return out;
}

}
