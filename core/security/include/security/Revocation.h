// Revocation payload encoding helpers. Spec: core/security/SECURITY.md.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace security {

constexpr uint8_t kRevocationVersion = 1;

struct RevocationPayload {
  uint8_t version = kRevocationVersion;
  std::array<uint8_t, 32> device_id{};
  int64_t revoked_at_ms = 0;
  std::array<uint8_t, 64> signature{};
};

inline void writeU64(std::vector<uint8_t>& out, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
  }
}

inline uint64_t readU64(const std::vector<uint8_t>& data, size_t& offset) {
  if (offset + 8 > data.size()) {
    throw std::runtime_error("revocation payload truncated");
  }
  uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
  }
  offset += 8;
  return value;
}

inline std::vector<uint8_t> revocationSignBytes(uint8_t version,
                                                 const std::array<uint8_t, 32>& device_id,
                                                 int64_t revoked_at_ms) {
  static constexpr char kContext[] = "p2pchat.revocation.v1";
  std::vector<uint8_t> out;
  out.reserve(sizeof(kContext) - 1 + 1 + device_id.size() + 8);
  out.insert(out.end(), kContext, kContext + sizeof(kContext) - 1);
  out.push_back(version);
  out.insert(out.end(), device_id.begin(), device_id.end());
  writeU64(out, static_cast<uint64_t>(revoked_at_ms));
  return out;
}

inline std::vector<uint8_t> encodeRevocationPayload(const RevocationPayload& payload) {
  std::vector<uint8_t> out;
  out.reserve(1 + payload.device_id.size() + 8 + payload.signature.size());
  out.push_back(payload.version);
  out.insert(out.end(), payload.device_id.begin(), payload.device_id.end());
  writeU64(out, static_cast<uint64_t>(payload.revoked_at_ms));
  out.insert(out.end(), payload.signature.begin(), payload.signature.end());
  return out;
}

inline RevocationPayload decodeRevocationPayload(const std::vector<uint8_t>& data) {
  if (data.size() != 1 + 32 + 8 + 64) {
    throw std::runtime_error("revocation payload size mismatch");
  }
  size_t offset = 0;
  RevocationPayload payload;
  payload.version = data[offset++];
  if (payload.version != kRevocationVersion) {
    throw std::runtime_error("revocation payload version mismatch");
  }
  std::memcpy(payload.device_id.data(), data.data() + offset, payload.device_id.size());
  offset += payload.device_id.size();
  payload.revoked_at_ms = static_cast<int64_t>(readU64(data, offset));
  std::memcpy(payload.signature.data(), data.data() + offset, payload.signature.size());
  return payload;
}

inline std::string toHex(const std::array<uint8_t, 32>& bytes) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

inline std::array<uint8_t, 32> fromHex32(const std::string& hex) {
  if (hex.size() != 64) {
    throw std::runtime_error("hex length mismatch");
  }
  auto nibble = [](char c) -> uint8_t {
    if (c >= '0' && c <= '9') {
      return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
      return static_cast<uint8_t>(10 + (c - 'a'));
    }
    if (c >= 'A' && c <= 'F') {
      return static_cast<uint8_t>(10 + (c - 'A'));
    }
    throw std::runtime_error("invalid hex character");
  };
  std::array<uint8_t, 32> out{};
  for (size_t i = 0; i < out.size(); ++i) {
    uint8_t hi = nibble(hex[i * 2]);
    uint8_t lo = nibble(hex[i * 2 + 1]);
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return out;
}

}
