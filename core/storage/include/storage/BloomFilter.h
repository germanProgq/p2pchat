// Bloom filter utility for sync reconciliation. Spec: core/storage/schema.sql.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace storage {

class BloomFilter {
 public:
  BloomFilter(uint32_t bits, uint32_t hash_count, uint64_t seed);

  static BloomFilter fromBytes(const std::vector<uint8_t>& bytes,
                               uint32_t hash_count,
                               uint64_t seed);

  void add(const std::string& value);
  bool possiblyContains(const std::string& value) const;

  const std::vector<uint8_t>& bytes() const;
  uint32_t bitCount() const;
  uint32_t hashCount() const;
  uint64_t seed() const;

 private:
  uint32_t bits_;
  uint32_t hash_count_;
  uint64_t seed_;
  std::vector<uint8_t> bytes_;

  void setBit(uint32_t index);
  bool testBit(uint32_t index) const;
};

}
