// Identity store interface and key management operations. Spec: core/identity/README.md.
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include "identity/IdentityTypes.h"

namespace identity {

class MasterKeyProvider {
 public:
  virtual ~MasterKeyProvider() = default;
  virtual std::array<uint8_t, 32> loadOrCreate() = 0;
};

class OsKeyStore final : public MasterKeyProvider {
 public:
  explicit OsKeyStore(std::string service_name);
  std::array<uint8_t, 32> loadOrCreate() override;

 private:
  std::string service_name_;
};

class InMemoryKeyStore final : public MasterKeyProvider {
 public:
  explicit InMemoryKeyStore(std::array<uint8_t, 32> key);
  std::array<uint8_t, 32> loadOrCreate() override;

 private:
  std::array<uint8_t, 32> key_{};
};

class IdentityStore {
 public:
  struct Options {
    std::string path;
    std::shared_ptr<MasterKeyProvider> master_key;
  };

  explicit IdentityStore(Options options);

  bool exists() const;
  IdentityRecord createNew();
  IdentityRecord load() const;
  IdentityRecord rotateIdentity();
  void save(const IdentityRecord& record) const;

  static std::array<uint8_t, 32> userIdFromPublicKey(const std::array<uint8_t, 32>& public_key);
  static std::string toHex(const std::array<uint8_t, 32>& bytes);

 private:
  Options options_;
};

}  // namespace identity
