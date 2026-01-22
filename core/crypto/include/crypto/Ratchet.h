// Double ratchet interface and message structures. Spec: core/crypto/ratchet_spec.md.
#pragma once

#include "crypto/Primitives.h"

#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <vector>

namespace crypto {

struct RatchetHeader {
  std::array<uint8_t, 32> dh_pub{};
  uint32_t pn = 0;
  uint32_t n = 0;
};

struct RatchetMessage {
  RatchetHeader header;
  std::vector<uint8_t> ciphertext;
  std::array<uint8_t, 16> tag{};
};

struct RatchetConfig {
  AeadAlgorithm aead = AeadAlgorithm::ChaCha20Poly1305;
  uint32_t max_skip = 2000;
};

struct RatchetState {
  std::array<uint8_t, 32> root_key{};
  KeyPair local_ratchet_key{};
  std::array<uint8_t, 32> remote_ratchet_pub{};
  std::array<uint8_t, 32> sending_chain_key{};
  std::array<uint8_t, 32> receiving_chain_key{};
  bool has_sending_chain = false;
  bool has_receiving_chain = false;
  uint32_t sending_count = 0;
  uint32_t receiving_count = 0;
  uint32_t previous_sending_count = 0;
};

class Ratchet {
 public:
  ~Ratchet();

  static Ratchet initInitiator(const std::array<uint8_t, 32>& root_key,
                               const KeyPair& local_ratchet_key,
                               const std::array<uint8_t, 32>& remote_ratchet_pub,
                               const RatchetConfig& config = {});

  static Ratchet initResponder(const std::array<uint8_t, 32>& root_key,
                               const KeyPair& local_ratchet_key,
                               const std::array<uint8_t, 32>& remote_ratchet_pub,
                               const RatchetConfig& config = {});

  RatchetMessage encrypt(const std::vector<uint8_t>& plaintext,
                         const std::vector<uint8_t>& aad);

  std::vector<uint8_t> decrypt(const RatchetMessage& message,
                               const std::vector<uint8_t>& aad);

  static std::vector<uint8_t> serializeHeader(const RatchetHeader& header);
  static RatchetHeader parseHeader(const std::vector<uint8_t>& data);
  static Ratchet fromState(const RatchetState& state, const RatchetConfig& config = {});
  RatchetState exportState() const;

  const std::array<uint8_t, 32>& rootKey() const;
  const std::array<uint8_t, 32>& sendingChainKey() const;
  const std::array<uint8_t, 32>& receivingChainKey() const;
  const std::array<uint8_t, 32>& localRatchetPublic() const;
  const std::array<uint8_t, 32>& remoteRatchetPublic() const;

  uint32_t sendingCount() const;
  uint32_t receivingCount() const;
  uint32_t previousSendingCount() const;

 private:
  struct SkippedKeyId {
    std::array<uint8_t, 32> dh_pub{};
    uint32_t n = 0;
  };

  struct SkippedKeyLess {
    bool operator()(const SkippedKeyId& lhs, const SkippedKeyId& rhs) const;
  };

  struct ArrayLess {
    bool operator()(const std::array<uint8_t, 32>& lhs,
                    const std::array<uint8_t, 32>& rhs) const;
  };

  Ratchet(const RatchetConfig& config,
          const std::array<uint8_t, 32>& root_key,
          const KeyPair& local_ratchet_key,
          const std::array<uint8_t, 32>& remote_ratchet_pub);

  void skipMessageKeys(uint32_t until);
  void dhRatchet(const std::array<uint8_t, 32>& new_remote);
  void ensureSendingChain();

  std::array<uint8_t, 32> root_key_{};
  KeyPair local_ratchet_key_{};
  std::array<uint8_t, 32> remote_ratchet_pub_{};

  std::array<uint8_t, 32> sending_chain_key_{};
  std::array<uint8_t, 32> receiving_chain_key_{};

  bool has_sending_chain_ = false;
  bool has_receiving_chain_ = false;

  uint32_t ns_ = 0;
  uint32_t nr_ = 0;
  uint32_t pn_ = 0;

  RatchetConfig config_{};
  std::map<SkippedKeyId, std::array<uint8_t, 32>, SkippedKeyLess> skipped_keys_;
  std::set<std::array<uint8_t, 32>, ArrayLess> known_remote_keys_;
};

}
