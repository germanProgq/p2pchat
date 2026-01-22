// Crypto primitives implementation. Spec: core/crypto/ratchet_spec.md.
#include "crypto/Primitives.h"

#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

namespace crypto {

namespace {

const EVP_CIPHER* cipherFor(AeadAlgorithm algorithm) {
  switch (algorithm) {
    case AeadAlgorithm::ChaCha20Poly1305:
      return EVP_chacha20_poly1305();
    case AeadAlgorithm::Aes256Gcm:
      return EVP_aes_256_gcm();
    default:
      throw std::runtime_error("unsupported AEAD algorithm");
  }
}

int getTagCtrl(AeadAlgorithm algorithm) {
  switch (algorithm) {
    case AeadAlgorithm::ChaCha20Poly1305:
      return EVP_CTRL_AEAD_GET_TAG;
    case AeadAlgorithm::Aes256Gcm:
      return EVP_CTRL_GCM_GET_TAG;
    default:
      return 0;
  }
}

int setTagCtrl(AeadAlgorithm algorithm) {
  switch (algorithm) {
    case AeadAlgorithm::ChaCha20Poly1305:
      return EVP_CTRL_AEAD_SET_TAG;
    case AeadAlgorithm::Aes256Gcm:
      return EVP_CTRL_GCM_SET_TAG;
    default:
      return 0;
  }
}

int setIvLenCtrl(AeadAlgorithm algorithm) {
  switch (algorithm) {
    case AeadAlgorithm::ChaCha20Poly1305:
      return EVP_CTRL_AEAD_SET_IVLEN;
    case AeadAlgorithm::Aes256Gcm:
      return EVP_CTRL_GCM_SET_IVLEN;
    default:
      return 0;
  }
}

}

std::array<uint8_t, 32> randomBytes32() {
  std::array<uint8_t, 32> out{};
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  return out;
}

std::vector<uint8_t> randomBytes(size_t len) {
  std::vector<uint8_t> out(len);
  if (len == 0) {
    return out;
  }
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  return out;
}

KeyPair generateX25519KeyPair() {
  KeyPair key_pair;
  key_pair.private_key = randomBytes32();
  key_pair.public_key = x25519PublicFromPrivate(key_pair.private_key);
  return key_pair;
}

std::array<uint8_t, 32> x25519PublicFromPrivate(const std::array<uint8_t, 32>& private_key) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                private_key.data(), private_key.size());
  if (!pkey) {
    throw std::runtime_error("EVP_PKEY_new_raw_private_key failed for X25519");
  }
  std::array<uint8_t, 32> public_key{};
  size_t len = public_key.size();
  if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &len) != 1 || len != public_key.size()) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_PKEY_get_raw_public_key failed for X25519");
  }
  EVP_PKEY_free(pkey);
  return public_key;
}

std::array<uint8_t, 32> x25519SharedSecret(const std::array<uint8_t, 32>& private_key,
                                            const std::array<uint8_t, 32>& public_key) {
  EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                private_key.data(), private_key.size());
  if (!priv) {
    throw std::runtime_error("EVP_PKEY_new_raw_private_key failed for X25519");
  }
  EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                              public_key.data(), public_key.size());
  if (!pub) {
    EVP_PKEY_free(priv);
    throw std::runtime_error("EVP_PKEY_new_raw_public_key failed for X25519");
  }
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
  if (!ctx) {
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    throw std::runtime_error("EVP_PKEY_CTX_new failed for X25519");
  }
  if (EVP_PKEY_derive_init(ctx) != 1) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    throw std::runtime_error("EVP_PKEY_derive_init failed for X25519");
  }
  if (EVP_PKEY_derive_set_peer(ctx, pub) != 1) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    throw std::runtime_error("EVP_PKEY_derive_set_peer failed for X25519");
  }
  std::array<uint8_t, 32> secret{};
  size_t len = secret.size();
  if (EVP_PKEY_derive(ctx, secret.data(), &len) != 1 || len != secret.size()) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    throw std::runtime_error("EVP_PKEY_derive failed for X25519");
  }
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(priv);
  EVP_PKEY_free(pub);
  return secret;
}

std::array<uint8_t, 32> ed25519PublicFromSeed(const std::array<uint8_t, 32>& seed) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
  if (!pkey) {
    throw std::runtime_error("EVP_PKEY_new_raw_private_key failed for Ed25519");
  }
  std::array<uint8_t, 32> pub{};
  size_t len = pub.size();
  if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) != 1 || len != pub.size()) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_PKEY_get_raw_public_key failed for Ed25519");
  }
  EVP_PKEY_free(pkey);
  return pub;
}

std::array<uint8_t, 64> ed25519Sign(const std::array<uint8_t, 32>& seed,
                                    const uint8_t* data,
                                    size_t len) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
  if (!pkey) {
    throw std::runtime_error("EVP_PKEY_new_raw_private_key failed for Ed25519");
  }
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_MD_CTX_new failed for Ed25519 sign");
  }
  if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_DigestSignInit failed for Ed25519 sign");
  }
  std::array<uint8_t, 64> signature{};
  size_t sig_len = signature.size();
  if (EVP_DigestSign(ctx, signature.data(), &sig_len, data, len) != 1 || sig_len != signature.size()) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_DigestSign failed for Ed25519 sign");
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return signature;
}

bool ed25519Verify(const std::array<uint8_t, 32>& public_key,
                   const uint8_t* data,
                   size_t len,
                   const std::array<uint8_t, 64>& signature) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                               public_key.data(), public_key.size());
  if (!pkey) {
    throw std::runtime_error("EVP_PKEY_new_raw_public_key failed for Ed25519");
  }
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_MD_CTX_new failed for Ed25519 verify");
  }
  if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_DigestVerifyInit failed for Ed25519 verify");
  }
  int ok = EVP_DigestVerify(ctx, signature.data(), signature.size(), data, len);
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok == 1;
}

std::vector<uint8_t> hkdfSha256(const std::vector<uint8_t>& ikm,
                                const std::vector<uint8_t>& salt,
                                const std::vector<uint8_t>& info,
                                size_t out_len) {
  if (out_len == 0) {
    return {};
  }
  std::vector<uint8_t> out(out_len);
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!ctx) {
    throw std::runtime_error("EVP_PKEY_CTX_new_id failed for HKDF");
  }
  if (EVP_PKEY_derive_init(ctx) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_derive_init failed for HKDF");
  }
  if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed for HKDF");
  }
  if (!salt.empty()) {
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), static_cast<int>(salt.size())) != 1) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_salt failed for HKDF");
    }
  }
  if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(), static_cast<int>(ikm.size())) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed for HKDF");
  }
  if (!info.empty()) {
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), static_cast<int>(info.size())) != 1) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("EVP_PKEY_CTX_add1_hkdf_info failed for HKDF");
    }
  }
  size_t len = out.size();
  if (EVP_PKEY_derive(ctx, out.data(), &len) != 1 || len != out.size()) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_derive failed for HKDF");
  }
  EVP_PKEY_CTX_free(ctx);
  return out;
}

std::array<uint8_t, 32> hmacSha256(const std::array<uint8_t, 32>& key,
                                   const uint8_t* data,
                                   size_t len) {
  std::array<uint8_t, 32> out{};
  unsigned int out_len = 0;
  unsigned char* result = HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                               data, len, out.data(), &out_len);
  if (!result || out_len != out.size()) {
    throw std::runtime_error("HMAC-SHA256 failed");
  }
  return out;
}

AeadResult aeadEncrypt(AeadAlgorithm algorithm,
                       const std::array<uint8_t, 32>& key,
                       const std::array<uint8_t, 12>& nonce,
                       const std::vector<uint8_t>& plaintext,
                       const std::vector<uint8_t>& aad) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }
  const EVP_CIPHER* cipher = cipherFor(algorithm);
  if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex failed");
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, setIvLenCtrl(algorithm), static_cast<int>(nonce.size()), nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CTRL_SET_IVLEN failed");
  }
  if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex key failed");
  }
  int out_len = 0;
  if (!aad.empty()) {
    if (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("EVP_EncryptUpdate aad failed");
    }
  }
  std::vector<uint8_t> ciphertext(plaintext.size());
  if (!plaintext.empty()) {
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("EVP_EncryptUpdate failed");
    }
  } else {
    out_len = 0;
  }
  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptFinal_ex failed");
  }
  AeadResult result;
  result.ciphertext = std::move(ciphertext);
  if (EVP_CIPHER_CTX_ctrl(ctx, getTagCtrl(algorithm), static_cast<int>(result.tag.size()), result.tag.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CTRL_GET_TAG failed");
  }
  EVP_CIPHER_CTX_free(ctx);
  result.ciphertext.resize(static_cast<size_t>(out_len + final_len));
  return result;
}

std::vector<uint8_t> aeadDecrypt(AeadAlgorithm algorithm,
                                 const std::array<uint8_t, 32>& key,
                                 const std::array<uint8_t, 12>& nonce,
                                 const std::vector<uint8_t>& ciphertext,
                                 const std::vector<uint8_t>& aad,
                                 const std::array<uint8_t, 16>& tag) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }
  const EVP_CIPHER* cipher = cipherFor(algorithm);
  if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, setIvLenCtrl(algorithm), static_cast<int>(nonce.size()), nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CTRL_SET_IVLEN failed");
  }
  if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex key failed");
  }
  int out_len = 0;
  if (!aad.empty()) {
    if (EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("EVP_DecryptUpdate aad failed");
    }
  }
  std::vector<uint8_t> plaintext(ciphertext.size());
  if (!ciphertext.empty()) {
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                          ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("EVP_DecryptUpdate failed");
    }
  } else {
    out_len = 0;
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, setTagCtrl(algorithm), static_cast<int>(tag.size()),
                          const_cast<uint8_t*>(tag.data())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CTRL_SET_TAG failed");
  }
  int final_len = 0;
  int ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);
  EVP_CIPHER_CTX_free(ctx);
  if (ok != 1) {
    throw std::runtime_error("AEAD authentication failed");
  }
  plaintext.resize(static_cast<size_t>(out_len + final_len));
  return plaintext;
}

void secureZero(void* data, size_t size) {
  if (data != nullptr && size > 0) {
    OPENSSL_cleanse(data, size);
  }
}

}
