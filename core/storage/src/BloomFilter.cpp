// Bloom filter implementation for sync reconciliation. Spec: core/storage/schema.sql.
#include "storage/BloomFilter.h"

#include <stdexcept>

namespace storage {

namespace {

constexpr uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

uint64_t fnv1a(const uint8_t* data, size_t len, uint64_t seed) {
  uint64_t hash = kFnvOffset ^ seed;
  for (size_t i = 0; i < len; ++i) {
    hash ^= static_cast<uint64_t>(data[i]);
    hash *= kFnvPrime;
  }
  return hash;
}

std::pair<uint64_t, uint64_t> hashPair(const std::string& value, uint64_t seed) {
  const auto* data = reinterpret_cast<const uint8_t*>(value.data());
  size_t len = value.size();
  uint64_t h1 = fnv1a(data, len, seed);
  uint64_t h2 = fnv1a(data, len, seed ^ 0x9e3779b97f4a7c15ULL);
  if (h2 == 0) {
    h2 = 0x27d4eb2d;
  }
  return {h1, h2};
}

}

BloomFilter::BloomFilter(uint32_t bits, uint32_t hash_count, uint64_t seed)
    : bits_(bits), hash_count_(hash_count), seed_(seed), bytes_((bits + 7) / 8, 0) {
  if (bits_ == 0 || hash_count_ == 0) {
    throw std::runtime_error("BloomFilter parameters must be non-zero");
  }
}

BloomFilter BloomFilter::fromBytes(const std::vector<uint8_t>& bytes,
                                   uint32_t hash_count,
                                   uint64_t seed) {
  if (bytes.empty() || hash_count == 0) {
    throw std::runtime_error("BloomFilter bytes must be non-empty");
  }
  BloomFilter filter(static_cast<uint32_t>(bytes.size() * 8), hash_count, seed);
  filter.bytes_ = bytes;
  return filter;
}

void BloomFilter::add(const std::string& value) {
  auto hashes = hashPair(value, seed_);
  for (uint32_t i = 0; i < hash_count_; ++i) {
    uint64_t combined = hashes.first + (static_cast<uint64_t>(i) * hashes.second);
    uint32_t index = static_cast<uint32_t>(combined % bits_);
    setBit(index);
  }
}

bool BloomFilter::possiblyContains(const std::string& value) const {
  auto hashes = hashPair(value, seed_);
  for (uint32_t i = 0; i < hash_count_; ++i) {
    uint64_t combined = hashes.first + (static_cast<uint64_t>(i) * hashes.second);
    uint32_t index = static_cast<uint32_t>(combined % bits_);
    if (!testBit(index)) {
      return false;
    }
  }
  return true;
}

const std::vector<uint8_t>& BloomFilter::bytes() const {
  return bytes_;
}

uint32_t BloomFilter::bitCount() const {
  return bits_;
}

uint32_t BloomFilter::hashCount() const {
  return hash_count_;
}

uint64_t BloomFilter::seed() const {
  return seed_;
}

void BloomFilter::setBit(uint32_t index) {
  uint32_t byte_index = index / 8;
  uint32_t bit_index = index % 8;
  bytes_[byte_index] |= static_cast<uint8_t>(1u << bit_index);
}

bool BloomFilter::testBit(uint32_t index) const {
  uint32_t byte_index = index / 8;
  uint32_t bit_index = index % 8;
  return (bytes_[byte_index] & static_cast<uint8_t>(1u << bit_index)) != 0;
}

}
