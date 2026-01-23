// Storage and sync interfaces. Spec: core/storage/schema.sql.
#pragma once

#include "storage/BloomFilter.h"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "crypto/Primitives.h"
#include "identity/IdentityStore.h"

namespace storage {

struct OutboxPolicy {
  int64_t base_delay_ms = 500;
  int64_t max_delay_ms = 60000;
  double jitter_ratio = 0.2;

  int64_t nextDelayMs(uint32_t attempts) const;
};

struct StorageOptions {
  std::string path;
  std::string schema_path;
  std::shared_ptr<identity::MasterKeyProvider> master_key;
  OutboxPolicy outbox_policy{};
};

struct StoredMessage {
  std::string chat_id;
  std::string msg_id;
  std::string sender_device;
  int64_t ts_ms = 0;
  std::vector<uint8_t> payload;
  bool delivered = false;
  bool acked = false;
  int64_t index = 0;
};

struct OutboxItem {
  int64_t id = 0;
  std::string peer_device;
  std::vector<uint8_t> session_id;
  std::vector<uint8_t> frame;
  int64_t next_retry_at_ms = 0;
  uint32_t attempts = 0;
};

struct SyncRange {
  int64_t start_index = 0;
  int64_t end_index = 0;
};

struct SessionState {
  std::vector<uint8_t> session_id;
  std::array<uint8_t, 32> root_key{};
  std::array<uint8_t, 32> chain_snd{};
  std::array<uint8_t, 32> chain_rcv{};
  crypto::KeyPair local_ratchet_key{};
  std::array<uint8_t, 32> remote_ratchet_pub{};
  bool has_sending_chain = false;
  bool has_receiving_chain = false;
  uint32_t counter_snd = 0;
  uint32_t counter_rcv = 0;
  uint32_t previous_counter = 0;
  uint64_t frame_counter_snd = 0;
  uint64_t frame_counter_rcv = 0;
};

struct PrekeyRecord {
  int64_t id = 0;
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> secret;
  bool used = false;
};

struct ChatSummary {
  std::string chat_id;
  int64_t last_index = 0;
  int64_t updated_at_ms = 0;
};

class Storage {
 public:
  explicit Storage(StorageOptions options);
  ~Storage();

  void open();
  void close();
  bool isOpen() const;

  int64_t appendMessage(const std::string& chat_id,
                        const std::string& msg_id,
                        const std::string& sender_device,
                        int64_t ts_ms,
                        const std::vector<uint8_t>& payload);

  std::vector<StoredMessage> listMessages(const std::string& chat_id,
                                          int64_t start_index,
                                          size_t limit) const;

  std::vector<StoredMessage> listMessagesRange(const std::string& chat_id,
                                               int64_t start_index,
                                               int64_t end_index) const;

  int64_t lastIndex(const std::string& chat_id) const;
  std::vector<ChatSummary> listChats() const;
  bool messageExists(const std::string& chat_id, const std::string& msg_id) const;
  void markMessageDelivered(const std::string& chat_id, const std::string& msg_id);
  void markMessageAcked(const std::string& chat_id, const std::string& msg_id);

  int64_t enqueueOutbox(const std::string& peer_device,
                        const std::vector<uint8_t>& session_id,
                        const std::vector<uint8_t>& frame,
                        int64_t now_ms);

  std::vector<OutboxItem> loadDueOutbox(int64_t now_ms, size_t limit) const;
  void markOutboxAttempt(int64_t id, int64_t now_ms);
  void removeOutbox(int64_t id);

  BloomFilter buildRecentBloom(const std::string& chat_id,
                               size_t window,
                               uint32_t bloom_bits,
                               uint32_t hash_count,
                               uint64_t seed) const;

  std::vector<SyncRange> planSync(const std::string& chat_id,
                                  int64_t remote_last_index,
                                  const BloomFilter& remote_bloom,
                                  size_t recent_window) const;

  void saveSession(const std::string& peer_device,
                   const SessionState& state,
                   int64_t updated_at_ms);

  std::optional<SessionState> loadSession(const std::string& peer_device) const;
  std::vector<std::string> listSessionPeers() const;
  void deleteSession(const std::string& peer_device);

  void storePrekey(const PrekeyRecord& record);
  std::optional<PrekeyRecord> loadPrekey(int64_t id) const;
  void markPrekeyUsed(int64_t id);
  std::optional<PrekeyRecord> loadUnusedPrekey(int64_t min_id) const;
  int64_t countUnusedPrekeys(int64_t min_id) const;

  void setMeta(const std::string& key, const std::vector<uint8_t>& value);
  std::optional<std::vector<uint8_t>> getMeta(const std::string& key) const;

  void upsertMessageAtIndex(const StoredMessage& message, int64_t index);

 private:
  StorageOptions options_;
  std::array<uint8_t, 32> master_key_{};
  struct SqliteDb;
  std::unique_ptr<SqliteDb> db_;

  void ensureSchema();
  std::vector<std::pair<int64_t, std::string>> recentMessageIds(const std::string& chat_id,
                                                                size_t window) const;
};

}
