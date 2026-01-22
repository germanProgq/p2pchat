// Crypto primitives and key utilities. Spec: core/crypto/ratchet_spec.md.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace crypto {

enum class AeadAlgorithm : uint32_t {
  ChaCha20Poly1305 = 1,
  Aes256Gcm = 2,
};

struct KeyPair {
  std::array<uint8_t, 32> private_key{};
  std::array<uint8_t, 32> public_key{};
};

struct AeadResult {
  std::vector<uint8_t> ciphertext;
  std::array<uint8_t, 16> tag{};
};

std::array<uint8_t, 32> randomBytes32();
std::vector<uint8_t> randomBytes(size_t len);

KeyPair generateX25519KeyPair();
std::array<uint8_t, 32> x25519PublicFromPrivate(const std::array<uint8_t, 32>& private_key);
std::array<uint8_t, 32> x25519SharedSecret(const std::array<uint8_t, 32>& private_key,
                                            const std::array<uint8_t, 32>& public_key);

std::array<uint8_t, 32> ed25519PublicFromSeed(const std::array<uint8_t, 32>& seed);
std::array<uint8_t, 64> ed25519Sign(const std::array<uint8_t, 32>& seed,
                                    const uint8_t* data,
                                    size_t len);
bool ed25519Verify(const std::array<uint8_t, 32>& public_key,
                   const uint8_t* data,
                   size_t len,
                   const std::array<uint8_t, 64>& signature);

std::vector<uint8_t> hkdfSha256(const std::vector<uint8_t>& ikm,
                                const std::vector<uint8_t>& salt,
                                const std::vector<uint8_t>& info,
                                size_t out_len);

std::array<uint8_t, 32> hmacSha256(const std::array<uint8_t, 32>& key,
                                   const uint8_t* data,
                                   size_t len);

AeadResult aeadEncrypt(AeadAlgorithm algorithm,
                       const std::array<uint8_t, 32>& key,
                       const std::array<uint8_t, 12>& nonce,
                       const std::vector<uint8_t>& plaintext,
                       const std::vector<uint8_t>& aad);

std::vector<uint8_t> aeadDecrypt(AeadAlgorithm algorithm,
                                 const std::array<uint8_t, 32>& key,
                                 const std::array<uint8_t, 12>& nonce,
                                 const std::vector<uint8_t>& ciphertext,
                                 const std::vector<uint8_t>& aad,
                                 const std::array<uint8_t, 16>& tag);

void secureZero(void* data, size_t size);

}
