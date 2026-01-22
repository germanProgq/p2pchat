// ICE candidate gathering and signaling implementation.
#include "transport/Ice.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <openssl/rand.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace transport {

namespace {

constexpr uint32_t kStunMagic = 0x2112A442;
constexpr uint16_t kStunBindingRequest = 0x0001;
constexpr uint16_t kStunBindingSuccess = 0x0101;
constexpr uint16_t kStunAttrMappedAddress = 0x0001;
constexpr uint16_t kStunAttrXorMappedAddress = 0x0020;
constexpr size_t kStunHeaderSize = 20;

#if defined(_WIN32)
using SocketType = SOCKET;
constexpr SocketType kInvalidSocket = INVALID_SOCKET;
using SockLenType = int;

struct WsaInit {
  WsaInit() {
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
      throw std::runtime_error("WSAStartup failed");
    }
  }
  ~WsaInit() { WSACleanup(); }
};

int closeSocket(SocketType sock) {
  return closesocket(sock);
}
#else
using SocketType = int;
constexpr SocketType kInvalidSocket = -1;
using SockLenType = socklen_t;

int closeSocket(SocketType sock) {
  return close(sock);
}
#endif

struct SocketGuard {
  SocketType sock = kInvalidSocket;
  bool owned = false;
  ~SocketGuard() {
    if (owned && sock != kInvalidSocket) {
      closeSocket(sock);
    }
  }
};

uint16_t readU16BE(const uint8_t* data) {
  return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

uint32_t readU32BE(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) |
         static_cast<uint32_t>(data[3]);
}

void writeU16BE(uint8_t* out, uint16_t value) {
  out[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
  out[1] = static_cast<uint8_t>(value & 0xFF);
}

void writeU32BE(uint8_t* out, uint32_t value) {
  out[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
  out[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
  out[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
  out[3] = static_cast<uint8_t>(value & 0xFF);
}

std::string randomHex(size_t bytes) {
  std::vector<uint8_t> raw(bytes);
  if (bytes > 0 && RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(raw.size() * 2);
  for (uint8_t b : raw) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

bool parsePort(const std::string& text, uint16_t& port) {
  if (text.empty()) {
    return false;
  }
  uint32_t value = 0;
  for (char c : text) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      return false;
    }
    value = value * 10 + static_cast<uint32_t>(c - '0');
    if (value > 65535) {
      return false;
    }
  }
  port = static_cast<uint16_t>(value);
  return true;
}

bool parseHostPort(const std::string& input, std::string& host, uint16_t& port) {
  port = 3478;
  if (input.empty()) {
    return false;
  }
  if (input.front() == '[') {
    auto end = input.find(']');
    if (end == std::string::npos) {
      return false;
    }
    host = input.substr(1, end - 1);
    if (end + 1 < input.size() && input[end + 1] == ':') {
      uint16_t parsed = 0;
      if (!parsePort(input.substr(end + 2), parsed)) {
        return false;
      }
      port = parsed;
    }
    return true;
  }
  auto pos = input.rfind(':');
  if (pos != std::string::npos && input.find(':') == pos) {
    uint16_t parsed = 0;
    if (parsePort(input.substr(pos + 1), parsed)) {
      host = input.substr(0, pos);
      port = parsed;
      return true;
    }
  }
  host = input;
  return true;
}

bool resolveAddress(const std::string& host, uint16_t port, sockaddr_storage& out, SockLenType& out_len) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  addrinfo* res = nullptr;
  std::string port_str = std::to_string(port);
  if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
    return false;
  }
  bool found = false;
  for (addrinfo* cur = res; cur != nullptr; cur = cur->ai_next) {
    if (cur->ai_family != AF_INET && cur->ai_family != AF_INET6) {
      continue;
    }
    if (cur->ai_addrlen > sizeof(out)) {
      continue;
    }
    std::memset(&out, 0, sizeof(out));
    std::memcpy(&out, cur->ai_addr, cur->ai_addrlen);
    out_len = static_cast<SockLenType>(cur->ai_addrlen);
    found = true;
    break;
  }
  freeaddrinfo(res);
  return found;
}

std::string sockaddrToString(const sockaddr_storage& addr) {
  char buf[INET6_ADDRSTRLEN] = {0};
  if (addr.ss_family == AF_INET) {
    auto* in = reinterpret_cast<const sockaddr_in*>(&addr);
    if (inet_ntop(AF_INET, const_cast<in_addr*>(&in->sin_addr), buf, sizeof(buf))) {
      return std::string(buf);
    }
  } else if (addr.ss_family == AF_INET6) {
    auto* in6 = reinterpret_cast<const sockaddr_in6*>(&addr);
    if (inet_ntop(AF_INET6, const_cast<in6_addr*>(&in6->sin6_addr), buf, sizeof(buf))) {
      return std::string(buf);
    }
  }
  return {};
}

uint16_t sockaddrPort(const sockaddr_storage& addr) {
  if (addr.ss_family == AF_INET) {
    auto* in = reinterpret_cast<const sockaddr_in*>(&addr);
    return ntohs(in->sin_port);
  }
  if (addr.ss_family == AF_INET6) {
    auto* in6 = reinterpret_cast<const sockaddr_in6*>(&addr);
    return ntohs(in6->sin6_port);
  }
  return 0;
}

std::string determineLocalAddress(const std::string& remote_host, uint16_t remote_port) {
  sockaddr_storage remote{};
  SockLenType remote_len = 0;
  if (!resolveAddress(remote_host, remote_port, remote, remote_len)) {
    return {};
  }
  SocketType sock = socket(remote.ss_family, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == kInvalidSocket) {
    return {};
  }
  SocketGuard guard{sock, true};
  if (connect(sock, reinterpret_cast<sockaddr*>(&remote), remote_len) != 0) {
    return {};
  }
  sockaddr_storage local{};
  SockLenType local_len = sizeof(local);
  if (getsockname(sock, reinterpret_cast<sockaddr*>(&local), &local_len) != 0) {
    return {};
  }
  return sockaddrToString(local);
}

std::vector<uint8_t> buildStunRequest(std::array<uint8_t, 12>& transaction_id) {
  if (RAND_bytes(transaction_id.data(), static_cast<int>(transaction_id.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  std::vector<uint8_t> out(kStunHeaderSize, 0);
  writeU16BE(out.data(), kStunBindingRequest);
  writeU16BE(out.data() + 2, 0);
  writeU32BE(out.data() + 4, kStunMagic);
  std::memcpy(out.data() + 8, transaction_id.data(), transaction_id.size());
  return out;
}

bool waitForReadable(SocketType sock, int timeout_ms) {
  if (timeout_ms < 0) {
    timeout_ms = 0;
  }
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(sock, &readfds);
  timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  int nfds = 0;
#if !defined(_WIN32)
  nfds = static_cast<int>(sock + 1);
#endif
  int result = select(nfds, &readfds, nullptr, nullptr, &tv);
  return result > 0 && FD_ISSET(sock, &readfds);
}

bool parseMappedAddress(const uint8_t* value,
                        size_t len,
                        bool xor_addr,
                        const std::array<uint8_t, 12>& transaction_id,
                        std::string& out_addr,
                        uint16_t& out_port) {
  if (len < 4) {
    return false;
  }
  uint8_t family = value[1];
  uint16_t port = readU16BE(value + 2);
  if (xor_addr) {
    port ^= static_cast<uint16_t>(kStunMagic >> 16);
  }
  if (family == 0x01) {
    if (len < 8) {
      return false;
    }
    uint32_t addr = readU32BE(value + 4);
    if (xor_addr) {
      addr ^= kStunMagic;
    }
    in_addr ipv4{};
    ipv4.s_addr = htonl(addr);
    char buf[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &ipv4, buf, sizeof(buf))) {
      return false;
    }
    out_addr = buf;
    out_port = port;
    return true;
  }
  if (family == 0x02) {
    if (len < 20) {
      return false;
    }
    std::array<uint8_t, 16> addr{};
    std::memcpy(addr.data(), value + 4, addr.size());
    if (xor_addr) {
      std::array<uint8_t, 16> mask{};
      writeU32BE(mask.data(), kStunMagic);
      std::memcpy(mask.data() + 4, transaction_id.data(), transaction_id.size());
      for (size_t i = 0; i < addr.size(); ++i) {
        addr[i] ^= mask[i];
      }
    }
    in6_addr ipv6{};
    std::memcpy(ipv6.s6_addr, addr.data(), addr.size());
    char buf[INET6_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET6, &ipv6, buf, sizeof(buf))) {
      return false;
    }
    out_addr = buf;
    out_port = port;
    return true;
  }
  return false;
}

bool parseStunResponse(const uint8_t* data,
                       size_t len,
                       const std::array<uint8_t, 12>& transaction_id,
                       std::string& out_addr,
                       uint16_t& out_port) {
  if (len < kStunHeaderSize) {
    return false;
  }
  uint16_t type = readU16BE(data);
  uint16_t msg_len = readU16BE(data + 2);
  uint32_t cookie = readU32BE(data + 4);
  if (type != kStunBindingSuccess || cookie != kStunMagic) {
    return false;
  }
  if (msg_len + kStunHeaderSize > len) {
    return false;
  }
  if (std::memcmp(data + 8, transaction_id.data(), transaction_id.size()) != 0) {
    return false;
  }
  bool mapped_found = false;
  std::string mapped_addr;
  uint16_t mapped_port = 0;
  size_t offset = kStunHeaderSize;
  size_t limit = kStunHeaderSize + msg_len;
  while (offset + 4 <= limit) {
    uint16_t attr_type = readU16BE(data + offset);
    uint16_t attr_len = readU16BE(data + offset + 2);
    size_t value_offset = offset + 4;
    size_t value_end = value_offset + attr_len;
    if (value_end > limit) {
      break;
    }
    if (attr_type == kStunAttrXorMappedAddress) {
      if (parseMappedAddress(data + value_offset, attr_len, true, transaction_id, out_addr, out_port)) {
        return true;
      }
    } else if (attr_type == kStunAttrMappedAddress) {
      std::string addr;
      uint16_t port = 0;
      if (parseMappedAddress(data + value_offset, attr_len, false, transaction_id, addr, port)) {
        mapped_found = true;
        mapped_addr = addr;
        mapped_port = port;
      }
    }
    size_t padded = (attr_len + 3) & ~static_cast<size_t>(3);
    offset = value_offset + padded;
  }
  if (mapped_found) {
    out_addr = mapped_addr;
    out_port = mapped_port;
    return true;
  }
  return false;
}

bool stunBinding(SocketType sock,
                 const std::string& server,
                 int timeout_ms,
                 std::string& out_addr,
                 uint16_t& out_port) {
  std::string host;
  uint16_t port = 0;
  if (!parseHostPort(server, host, port)) {
    return false;
  }
  sockaddr_storage dst{};
  SockLenType dst_len = 0;
  if (!resolveAddress(host, port, dst, dst_len)) {
    return false;
  }
  std::array<uint8_t, 12> transaction_id{};
  std::vector<uint8_t> request = buildStunRequest(transaction_id);
  int sent = sendto(sock,
                    reinterpret_cast<const char*>(request.data()),
                    static_cast<int>(request.size()),
                    0,
                    reinterpret_cast<sockaddr*>(&dst),
                    dst_len);
  if (sent <= 0) {
    return false;
  }
  auto start = std::chrono::steady_clock::now();
  std::vector<uint8_t> buffer(512);
  while (true) {
    auto now = std::chrono::steady_clock::now();
    int elapsed = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count());
    int remaining = timeout_ms - elapsed;
    if (remaining <= 0) {
      return false;
    }
    if (!waitForReadable(sock, remaining)) {
      return false;
    }
    sockaddr_storage from{};
    SockLenType from_len = sizeof(from);
#if defined(_WIN32)
    int received = recvfrom(sock,
                            reinterpret_cast<char*>(buffer.data()),
                            static_cast<int>(buffer.size()),
                            0,
                            reinterpret_cast<sockaddr*>(&from),
                            &from_len);
    if (received <= 0) {
      int err = WSAGetLastError();
      if (err == WSAEWOULDBLOCK) {
        continue;
      }
      return false;
    }
#else
    ssize_t received = recvfrom(sock,
                                buffer.data(),
                                buffer.size(),
                                0,
                                reinterpret_cast<sockaddr*>(&from),
                                &from_len);
    if (received < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        continue;
      }
      return false;
    }
#endif
    if (parseStunResponse(buffer.data(),
                          static_cast<size_t>(received),
                          transaction_id,
                          out_addr,
                          out_port)) {
      return true;
    }
  }
}

uint32_t typePreference(IceCandidateType type) {
  switch (type) {
    case IceCandidateType::Host:
      return 126;
    case IceCandidateType::Srflx:
      return 100;
    case IceCandidateType::Relay:
      return 0;
  }
  return 0;
}

uint32_t candidatePriority(IceCandidateType type, uint16_t component) {
  uint32_t type_pref = typePreference(type);
  uint32_t local_pref = 65535;
  uint32_t comp = component == 0 ? 1 : component;
  return (type_pref << 24) | (local_pref << 8) | (256 - comp);
}

std::vector<std::string> split(const std::string& input, char delim) {
  std::vector<std::string> parts;
  std::string current;
  for (char c : input) {
    if (c == delim) {
      parts.push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  parts.push_back(current);
  return parts;
}

}  // namespace

IceDescription gatherIceDescription(const IceConfig& config,
                                    const std::string& bind_address,
                                    uint16_t bind_port,
                                    IceSocket socket_handle) {
  IceDescription description;
  description.ufrag = randomHex(8);
  description.pwd = randomHex(16);

#if defined(_WIN32)
  static WsaInit wsa_init;
#endif

  SocketType sock = kInvalidSocket;
  SocketGuard guard;
  if (socket_handle != static_cast<IceSocket>(-1)) {
    sock = static_cast<SocketType>(socket_handle);
  } else {
    std::string bind_host = config.bind_address.empty() ? bind_address : config.bind_address;
    uint16_t port = config.bind_port != 0 ? config.bind_port : bind_port;
    sockaddr_storage addr{};
    SockLenType addr_len = 0;
    if (!resolveAddress(bind_host.empty() ? "0.0.0.0" : bind_host, port, addr, addr_len)) {
      throw std::runtime_error("ICE bind address invalid");
    }
    sock = socket(addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == kInvalidSocket) {
      throw std::runtime_error("ICE socket create failed");
    }
    guard.sock = sock;
    guard.owned = true;
    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), addr_len) != 0) {
      throw std::runtime_error("ICE bind failed");
    }
  }

  sockaddr_storage local_addr{};
  SockLenType local_len = sizeof(local_addr);
  if (getsockname(sock, reinterpret_cast<sockaddr*>(&local_addr), &local_len) != 0) {
    throw std::runtime_error("ICE getsockname failed");
  }
  uint16_t local_port = sockaddrPort(local_addr);

  std::string host_addr;
  std::string bind_host = config.bind_address.empty() ? bind_address : config.bind_address;
  if (!bind_host.empty() && bind_host != "0.0.0.0" && bind_host != "::") {
    host_addr = bind_host;
  } else {
    host_addr = sockaddrToString(local_addr);
  }
  if (host_addr == "0.0.0.0" || host_addr == "::" || host_addr.empty()) {
    if (!config.stun_servers.empty()) {
      std::string host;
      uint16_t port = 0;
      if (parseHostPort(config.stun_servers.front(), host, port)) {
        host_addr = determineLocalAddress(host, port);
      }
    }
    if (host_addr.empty()) {
      host_addr = determineLocalAddress("1.1.1.1", 53);
    }
  }

  if (!host_addr.empty() && local_port != 0) {
    IceCandidate host;
    host.type = IceCandidateType::Host;
    host.address = host_addr;
    host.port = local_port;
    host.priority = candidatePriority(host.type, 1);
    description.candidates.push_back(host);
  }

  for (const auto& relay : config.relay_candidates) {
    if (relay.address.empty() || relay.port == 0) {
      continue;
    }
    IceCandidate candidate = relay;
    if (candidate.priority == 0) {
      candidate.priority = candidatePriority(candidate.type, 1);
    }
    description.candidates.push_back(candidate);
  }

  if (!config.stun_servers.empty()) {
    for (const auto& server : config.stun_servers) {
      std::string mapped_addr;
      uint16_t mapped_port = 0;
      if (stunBinding(sock, server, config.timeout_ms, mapped_addr, mapped_port)) {
        IceCandidate srflx;
        srflx.type = IceCandidateType::Srflx;
        srflx.address = mapped_addr;
        srflx.port = mapped_port;
        srflx.priority = candidatePriority(srflx.type, 1);
        description.candidates.push_back(srflx);
        break;
      }
    }
  }

  return description;
}

std::string encodeIceDescription(const IceDescription& description) {
  std::string out = "1|";
  out += description.ufrag;
  out += "|";
  out += description.pwd;
  out += "|";
  bool first = true;
  for (const auto& candidate : description.candidates) {
    if (!first) {
      out += ";";
    }
    first = false;
    out += std::to_string(static_cast<uint8_t>(candidate.type));
    out += ",";
    out += std::to_string(candidate.priority);
    out += ",";
    out += candidate.address;
    out += ",";
    out += std::to_string(candidate.port);
  }
  return out;
}

IceDescription decodeIceDescription(const std::string& blob) {
  auto parts = split(blob, '|');
  if (parts.size() < 3) {
    throw std::runtime_error("ICE description parse failed");
  }
  if (parts[0] != "1") {
    throw std::runtime_error("ICE description version mismatch");
  }
  IceDescription description;
  description.ufrag = parts[1];
  description.pwd = parts[2];
  if (parts.size() > 3 && !parts[3].empty()) {
    auto candidates = split(parts[3], ';');
    for (const auto& entry : candidates) {
      if (entry.empty()) {
        continue;
      }
      auto fields = split(entry, ',');
      if (fields.size() != 4) {
        throw std::runtime_error("ICE candidate parse failed");
      }
      IceCandidate candidate;
      candidate.type = static_cast<IceCandidateType>(static_cast<uint8_t>(std::stoi(fields[0])));
      candidate.priority = static_cast<uint32_t>(std::stoul(fields[1]));
      candidate.address = fields[2];
      candidate.port = static_cast<uint16_t>(std::stoul(fields[3]));
      description.candidates.push_back(candidate);
    }
  }
  return description;
}

IceCandidate selectIceCandidate(const IceDescription& description) {
  if (description.candidates.empty()) {
    throw std::runtime_error("ICE has no candidates");
  }
  auto best = std::max_element(description.candidates.begin(),
                               description.candidates.end(),
                               [](const IceCandidate& a, const IceCandidate& b) {
                                 uint32_t a_pri = a.priority == 0 ? candidatePriority(a.type, 1) : a.priority;
                                 uint32_t b_pri = b.priority == 0 ? candidatePriority(b.type, 1) : b.priority;
                                 if (a_pri != b_pri) {
                                   return a_pri < b_pri;
                                 }
                                 return static_cast<uint8_t>(a.type) < static_cast<uint8_t>(b.type);
                               });
  return *best;
}

}  // namespace transport
