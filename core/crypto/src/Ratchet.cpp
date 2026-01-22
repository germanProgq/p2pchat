// Double ratchet implementation. Spec: core/crypto/ratchet_spec.md.
#include "crypto/Ratchet.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace crypto {

namespace {

constexpr uint8_t kChainMessageKey = 0x01;
constexpr uint8_t kChainNextKey = 0x02;

const std::vector<uint8_t> kRootInfo = {'p','2','p','c','h','a','t','.','r','a','t','c','h','e','t','.','r','k','.','v','1'};
const std::vector<uint8_t> kMessageInfo = {'p','2','p','c','h','a','t','.','r','a','t','c','h','e','t','.','m','s','g','.','v','1'};

struct RootKdfResult {
  std::array<uint8_t, 32> root{};
  std::array<uint8_t, 32> chain{};
};

RootKdfResult kdfRoot(const std::array<uint8_t, 32>& root_key,
                      const std::array<uint8_t, 32>& dh_out) {
  std::vector<uint8_t> salt(root_key.begin(), root_key.end());
  std::vector<uint8_t> ikm(dh_out.begin(), dh_out.end());
  std::vector<uint8_t> okm = hkdfSha256(ikm, salt, kRootInfo, 64);
  if (okm.size() != 64) {
    throw std::runtime_error("KDF_RK output length mismatch");
  }
  RootKdfResult out;
  std::memcpy(out.root.data(), okm.data(), 32);
  std::memcpy(out.chain.data(), okm.data() + 32, 32);
  return out;
}

std::array<uint8_t, 32> kdfChainMessage(const std::array<uint8_t, 32>& chain_key) {
  return hmacSha256(chain_key, &kChainMessageKey, 1);
}

std::array<uint8_t, 32> kdfChainNext(const std::array<uint8_t, 32>& chain_key) {
  return hmacSha256(chain_key, &kChainNextKey, 1);
}

std::vector<uint8_t> concatAad(const std::vector<uint8_t>& aad,
                               const std::vector<uint8_t>& header) {
  std::vector<uint8_t> out;
  out.reserve(aad.size() + header.size());
  out.insert(out.end(), aad.begin(), aad.end());
  out.insert(out.end(), header.begin(), header.end());
  return out;
}

void writeU32LE(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

uint32_t readU32LE(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24);
}

}

Ratchet::Ratchet(const RatchetConfig& config,
                 const std::array<uint8_t, 32>& root_key,
                 const KeyPair& local_ratchet_key,
                 const std::array<uint8_t, 32>& remote_ratchet_pub)
    : root_key_(root_key),
      local_ratchet_key_(local_ratchet_key),
      remote_ratchet_pub_(remote_ratchet_pub),
      config_(config) {}

Ratchet::~Ratchet() {
  secureZero(root_key_.data(), root_key_.size());
  secureZero(sending_chain_key_.data(), sending_chain_key_.size());
  secureZero(receiving_chain_key_.data(), receiving_chain_key_.size());
  secureZero(local_ratchet_key_.private_key.data(), local_ratchet_key_.private_key.size());
  for (auto& entry : skipped_keys_) {
    secureZero(entry.second.data(), entry.second.size());
  }
}

Ratchet Ratchet::initInitiator(const std::array<uint8_t, 32>& root_key,
                               const KeyPair& local_ratchet_key,
                               const std::array<uint8_t, 32>& remote_ratchet_pub,
                               const RatchetConfig& config) {
  Ratchet ratchet(config, root_key, local_ratchet_key, remote_ratchet_pub);
  ratchet.known_remote_keys_.insert(remote_ratchet_pub);
  std::array<uint8_t, 32> dh_out = x25519SharedSecret(local_ratchet_key.private_key, remote_ratchet_pub);
  RootKdfResult derived = kdfRoot(ratchet.root_key_, dh_out);
  ratchet.root_key_ = derived.root;
  ratchet.sending_chain_key_ = derived.chain;
  ratchet.has_sending_chain_ = true;
  ratchet.has_receiving_chain_ = false;
  ratchet.ns_ = 0;
  ratchet.nr_ = 0;
  ratchet.pn_ = 0;
  return ratchet;
}

Ratchet Ratchet::initResponder(const std::array<uint8_t, 32>& root_key,
                               const KeyPair& local_ratchet_key,
                               const std::array<uint8_t, 32>& remote_ratchet_pub,
                               const RatchetConfig& config) {
  Ratchet ratchet(config, root_key, local_ratchet_key, remote_ratchet_pub);
  ratchet.known_remote_keys_.insert(remote_ratchet_pub);
  std::array<uint8_t, 32> dh_out = x25519SharedSecret(local_ratchet_key.private_key, remote_ratchet_pub);
  RootKdfResult derived = kdfRoot(ratchet.root_key_, dh_out);
  ratchet.root_key_ = derived.root;
  ratchet.receiving_chain_key_ = derived.chain;
  ratchet.has_receiving_chain_ = true;
  ratchet.has_sending_chain_ = false;
  ratchet.ns_ = 0;
  ratchet.nr_ = 0;
  ratchet.pn_ = 0;
  return ratchet;
}

RatchetMessage Ratchet::encrypt(const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& aad) {
  ensureSendingChain();
  uint32_t message_index = ns_;
  std::array<uint8_t, 32> message_key = kdfChainMessage(sending_chain_key_);
  std::array<uint8_t, 32> next_chain = kdfChainNext(sending_chain_key_);
  secureZero(sending_chain_key_.data(), sending_chain_key_.size());
  sending_chain_key_ = next_chain;
  ns_ += 1;

  RatchetHeader header;
  header.dh_pub = local_ratchet_key_.public_key;
  header.pn = pn_;
  header.n = message_index;

  std::vector<uint8_t> header_bytes = serializeHeader(header);
  std::vector<uint8_t> aad_full = concatAad(aad, header_bytes);
  std::vector<uint8_t> okm = hkdfSha256(std::vector<uint8_t>(message_key.begin(), message_key.end()),
                                        {}, kMessageInfo, 44);
  if (okm.size() != 44) {
    throw std::runtime_error("message key expansion length mismatch");
  }
  std::array<uint8_t, 32> aead_key{};
  std::array<uint8_t, 12> nonce{};
  std::memcpy(aead_key.data(), okm.data(), aead_key.size());
  std::memcpy(nonce.data(), okm.data() + aead_key.size(), nonce.size());
  AeadResult result = aeadEncrypt(config_.aead, aead_key, nonce, plaintext, aad_full);
  secureZero(message_key.data(), message_key.size());
  secureZero(aead_key.data(), aead_key.size());
  secureZero(nonce.data(), nonce.size());

  RatchetMessage message;
  message.header = header;
  message.ciphertext = std::move(result.ciphertext);
  message.tag = result.tag;
  return message;
}

std::vector<uint8_t> Ratchet::decrypt(const RatchetMessage& message,
                                      const std::vector<uint8_t>& aad) {
  SkippedKeyId lookup{message.header.dh_pub, message.header.n};
  auto skipped = skipped_keys_.find(lookup);
  if (skipped != skipped_keys_.end()) {
    std::vector<uint8_t> header_bytes = serializeHeader(message.header);
    std::vector<uint8_t> aad_full = concatAad(aad, header_bytes);
    std::array<uint8_t, 32> stored_key = skipped->second;
    std::vector<uint8_t> okm = hkdfSha256(std::vector<uint8_t>(stored_key.begin(), stored_key.end()),
                                          {}, kMessageInfo, 44);
    if (okm.size() != 44) {
      throw std::runtime_error("message key expansion length mismatch");
    }
    std::array<uint8_t, 32> aead_key{};
    std::array<uint8_t, 12> nonce{};
    std::memcpy(aead_key.data(), okm.data(), aead_key.size());
    std::memcpy(nonce.data(), okm.data() + aead_key.size(), nonce.size());
    std::vector<uint8_t> plaintext = aeadDecrypt(config_.aead, aead_key, nonce,
                                                 message.ciphertext, aad_full, message.tag);
    secureZero(aead_key.data(), aead_key.size());
    secureZero(nonce.data(), nonce.size());
    secureZero(skipped->second.data(), skipped->second.size());
    skipped_keys_.erase(skipped);
    secureZero(stored_key.data(), stored_key.size());
    return plaintext;
  }

  if (message.header.dh_pub != remote_ratchet_pub_) {
    if (known_remote_keys_.find(message.header.dh_pub) != known_remote_keys_.end()) {
      throw std::runtime_error("message for retired ratchet key");
    }
    skipMessageKeys(message.header.pn);
    dhRatchet(message.header.dh_pub);
  }

  if (!has_receiving_chain_) {
    throw std::runtime_error("receiving chain not initialized");
  }
  if (message.header.n < nr_) {
    throw std::runtime_error("message number already processed");
  }
  skipMessageKeys(message.header.n);

  std::array<uint8_t, 32> message_key = kdfChainMessage(receiving_chain_key_);
  std::array<uint8_t, 32> next_chain = kdfChainNext(receiving_chain_key_);
  secureZero(receiving_chain_key_.data(), receiving_chain_key_.size());
  receiving_chain_key_ = next_chain;
  nr_ += 1;

  std::vector<uint8_t> header_bytes = serializeHeader(message.header);
  std::vector<uint8_t> aad_full = concatAad(aad, header_bytes);
  std::vector<uint8_t> okm = hkdfSha256(std::vector<uint8_t>(message_key.begin(), message_key.end()),
                                        {}, kMessageInfo, 44);
  if (okm.size() != 44) {
    throw std::runtime_error("message key expansion length mismatch");
  }
  std::array<uint8_t, 32> aead_key{};
  std::array<uint8_t, 12> nonce{};
  std::memcpy(aead_key.data(), okm.data(), aead_key.size());
  std::memcpy(nonce.data(), okm.data() + aead_key.size(), nonce.size());
  std::vector<uint8_t> plaintext = aeadDecrypt(config_.aead, aead_key, nonce,
                                               message.ciphertext, aad_full, message.tag);
  secureZero(message_key.data(), message_key.size());
  secureZero(aead_key.data(), aead_key.size());
  secureZero(nonce.data(), nonce.size());
  return plaintext;
}

std::vector<uint8_t> Ratchet::serializeHeader(const RatchetHeader& header) {
  std::vector<uint8_t> out;
  out.reserve(40);
  out.insert(out.end(), header.dh_pub.begin(), header.dh_pub.end());
  writeU32LE(out, header.pn);
  writeU32LE(out, header.n);
  return out;
}

RatchetHeader Ratchet::parseHeader(const std::vector<uint8_t>& data) {
  if (data.size() != 40) {
    throw std::runtime_error("ratchet header length mismatch");
  }
  RatchetHeader header;
  std::memcpy(header.dh_pub.data(), data.data(), header.dh_pub.size());
  header.pn = readU32LE(data.data() + 32);
  header.n = readU32LE(data.data() + 36);
  return header;
}

Ratchet Ratchet::fromState(const RatchetState& state, const RatchetConfig& config) {
  Ratchet ratchet(config, state.root_key, state.local_ratchet_key, state.remote_ratchet_pub);
  ratchet.root_key_ = state.root_key;
  ratchet.local_ratchet_key_ = state.local_ratchet_key;
  ratchet.remote_ratchet_pub_ = state.remote_ratchet_pub;
  ratchet.sending_chain_key_ = state.sending_chain_key;
  ratchet.receiving_chain_key_ = state.receiving_chain_key;
  ratchet.has_sending_chain_ = state.has_sending_chain;
  ratchet.has_receiving_chain_ = state.has_receiving_chain;
  ratchet.ns_ = state.sending_count;
  ratchet.nr_ = state.receiving_count;
  ratchet.pn_ = state.previous_sending_count;
  if (state.remote_ratchet_pub != std::array<uint8_t, 32>{}) {
    ratchet.known_remote_keys_.insert(state.remote_ratchet_pub);
  }
  return ratchet;
}

RatchetState Ratchet::exportState() const {
  RatchetState state;
  state.root_key = root_key_;
  state.local_ratchet_key = local_ratchet_key_;
  state.remote_ratchet_pub = remote_ratchet_pub_;
  state.sending_chain_key = sending_chain_key_;
  state.receiving_chain_key = receiving_chain_key_;
  state.has_sending_chain = has_sending_chain_;
  state.has_receiving_chain = has_receiving_chain_;
  state.sending_count = ns_;
  state.receiving_count = nr_;
  state.previous_sending_count = pn_;
  return state;
}

const std::array<uint8_t, 32>& Ratchet::rootKey() const {
  return root_key_;
}

const std::array<uint8_t, 32>& Ratchet::sendingChainKey() const {
  return sending_chain_key_;
}

const std::array<uint8_t, 32>& Ratchet::receivingChainKey() const {
  return receiving_chain_key_;
}

const std::array<uint8_t, 32>& Ratchet::localRatchetPublic() const {
  return local_ratchet_key_.public_key;
}

const std::array<uint8_t, 32>& Ratchet::remoteRatchetPublic() const {
  return remote_ratchet_pub_;
}

uint32_t Ratchet::sendingCount() const {
  return ns_;
}

uint32_t Ratchet::receivingCount() const {
  return nr_;
}

uint32_t Ratchet::previousSendingCount() const {
  return pn_;
}

bool Ratchet::SkippedKeyLess::operator()(const SkippedKeyId& lhs, const SkippedKeyId& rhs) const {
  int cmp = std::memcmp(lhs.dh_pub.data(), rhs.dh_pub.data(), lhs.dh_pub.size());
  if (cmp != 0) {
    return cmp < 0;
  }
  return lhs.n < rhs.n;
}

bool Ratchet::ArrayLess::operator()(const std::array<uint8_t, 32>& lhs,
                                    const std::array<uint8_t, 32>& rhs) const {
  int cmp = std::memcmp(lhs.data(), rhs.data(), lhs.size());
  return cmp < 0;
}

void Ratchet::skipMessageKeys(uint32_t until) {
  if (!has_receiving_chain_) {
    return;
  }
  if (until < nr_) {
    return;
  }
  uint64_t limit = static_cast<uint64_t>(nr_) + static_cast<uint64_t>(config_.max_skip);
  if (static_cast<uint64_t>(until) > limit) {
    throw std::runtime_error("skip limit exceeded");
  }
  while (nr_ < until) {
    std::array<uint8_t, 32> message_key = kdfChainMessage(receiving_chain_key_);
    std::array<uint8_t, 32> next_chain = kdfChainNext(receiving_chain_key_);
    secureZero(receiving_chain_key_.data(), receiving_chain_key_.size());
    receiving_chain_key_ = next_chain;
    SkippedKeyId id{remote_ratchet_pub_, nr_};
    skipped_keys_.emplace(id, message_key);
    nr_ += 1;
  }
}

void Ratchet::dhRatchet(const std::array<uint8_t, 32>& new_remote) {
  pn_ = ns_;
  ns_ = 0;
  nr_ = 0;

  std::array<uint8_t, 32> dh_recv = x25519SharedSecret(local_ratchet_key_.private_key, new_remote);
  RootKdfResult recv = kdfRoot(root_key_, dh_recv);
  root_key_ = recv.root;
  secureZero(receiving_chain_key_.data(), receiving_chain_key_.size());
  receiving_chain_key_ = recv.chain;
  has_receiving_chain_ = true;

  secureZero(local_ratchet_key_.private_key.data(), local_ratchet_key_.private_key.size());
  local_ratchet_key_ = generateX25519KeyPair();
  std::array<uint8_t, 32> dh_send = x25519SharedSecret(local_ratchet_key_.private_key, new_remote);
  RootKdfResult send = kdfRoot(root_key_, dh_send);
  root_key_ = send.root;
  secureZero(sending_chain_key_.data(), sending_chain_key_.size());
  sending_chain_key_ = send.chain;
  has_sending_chain_ = true;

  known_remote_keys_.insert(remote_ratchet_pub_);
  known_remote_keys_.insert(new_remote);
  remote_ratchet_pub_ = new_remote;
}

void Ratchet::ensureSendingChain() {
  if (has_sending_chain_) {
    return;
  }
  secureZero(local_ratchet_key_.private_key.data(), local_ratchet_key_.private_key.size());
  local_ratchet_key_ = generateX25519KeyPair();
  std::array<uint8_t, 32> dh_send = x25519SharedSecret(local_ratchet_key_.private_key, remote_ratchet_pub_);
  RootKdfResult send = kdfRoot(root_key_, dh_send);
  root_key_ = send.root;
  secureZero(sending_chain_key_.data(), sending_chain_key_.size());
  sending_chain_key_ = send.chain;
  has_sending_chain_ = true;
  ns_ = 0;
}

}
