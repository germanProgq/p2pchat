// Storage and sync tests. Spec: core/storage/schema.sql.
#include "storage/Storage.h"

#include <array>
#include <chrono>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <sqlite3.h>

namespace {

std::array<uint8_t, 32> fixedKey() {
  std::array<uint8_t, 32> key{};
  for (size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<uint8_t>(0xA0 + i);
  }
  return key;
}

std::filesystem::path uniqueTempPath() {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  std::filesystem::path base = std::filesystem::temp_directory_path();
  return base / ("p2pchat_storage_test_" + std::to_string(now));
}

std::filesystem::path schemaPath() {
  return std::filesystem::path(P2PCHAT_SOURCE_DIR) / "core/storage/schema.sql";
}

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

bool tableExists(sqlite3* db, const std::string& name) {
  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db,
                         "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?;",
                         -1,
                         &stmt,
                         nullptr) != SQLITE_OK) {
    throw std::runtime_error("sqlite prepare failed");
  }
  sqlite3_bind_text(stmt, 1, name.c_str(), static_cast<int>(name.size()), SQLITE_TRANSIENT);
  bool found = sqlite3_step(stmt) == SQLITE_ROW;
  sqlite3_finalize(stmt);
  return found;
}

int userVersion(sqlite3* db) {
  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &stmt, nullptr) != SQLITE_OK) {
    throw std::runtime_error("sqlite prepare failed");
  }
  int version = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    version = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt);
  return version;
}

void testMigrationAppliesSchema() {
  std::filesystem::path dir = uniqueTempPath();
  std::filesystem::create_directories(dir);
  std::filesystem::path db_path = dir / "store.db";

  storage::StorageOptions options;
  options.path = db_path.string();
  options.schema_path = schemaPath().string();
  options.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedKey());
  options.outbox_policy.jitter_ratio = 0.0;

  storage::Storage store(options);
  store.open();
  store.close();

  sqlite3* db = nullptr;
  require(sqlite3_open_v2(db_path.string().c_str(), &db, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
          "sqlite open failed");
  int version = userVersion(db);
  require(version == 1, "schema version mismatch");
  require(tableExists(db, "messages"), "messages table missing");
  require(tableExists(db, "outbox"), "outbox table missing");
  sqlite3_close(db);
}

void testMigrationRejectsNewerVersion() {
  std::filesystem::path dir = uniqueTempPath();
  std::filesystem::create_directories(dir);
  std::filesystem::path db_path = dir / "store.db";

  sqlite3* db = nullptr;
  require(sqlite3_open_v2(db_path.string().c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK,
          "sqlite open failed");
  require(sqlite3_exec(db, "PRAGMA user_version = 2;", nullptr, nullptr, nullptr) == SQLITE_OK,
          "sqlite set user_version failed");
  sqlite3_close(db);

  storage::StorageOptions options;
  options.path = db_path.string();
  options.schema_path = schemaPath().string();
  options.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedKey());

  bool threw = false;
  try {
    storage::Storage store(options);
    store.open();
  } catch (const std::exception&) {
    threw = true;
  }
  require(threw, "expected schema version rejection");
}

void testOutboxRetryTiming() {
  std::filesystem::path dir = uniqueTempPath();
  std::filesystem::create_directories(dir);
  std::filesystem::path db_path = dir / "store.db";

  storage::StorageOptions options;
  options.path = db_path.string();
  options.schema_path = schemaPath().string();
  options.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedKey());
  options.outbox_policy.base_delay_ms = 1000;
  options.outbox_policy.max_delay_ms = 8000;
  options.outbox_policy.jitter_ratio = 0.0;

  storage::Storage store(options);
  store.open();

  int64_t now = 100000;
  std::vector<uint8_t> session_id = {0x01, 0x02, 0x03};
  std::vector<uint8_t> frame = {0x10, 0x11, 0x12};
  int64_t id = store.enqueueOutbox("peerA", session_id, frame, now);

  auto due = store.loadDueOutbox(now, 10);
  require(due.size() == 1, "expected one due outbox");
  require(due[0].attempts == 0, "unexpected attempts count");
  require(due[0].frame == frame, "frame mismatch");

  store.markOutboxAttempt(id, now);
  auto before_retry = store.loadDueOutbox(now + 999, 10);
  require(before_retry.empty(), "outbox retry triggered early");
  auto on_retry = store.loadDueOutbox(now + 1000, 10);
  require(on_retry.size() == 1, "outbox retry missing");
  require(on_retry[0].attempts == 1, "attempts not incremented");

  store.markOutboxAttempt(id, now + 1000);
  auto second_retry = store.loadDueOutbox(now + 3000, 10);
  require(second_retry.size() == 1, "second retry missing");
  require(second_retry[0].attempts == 2, "attempts not incremented twice");
}

void testSyncGapRepair() {
  std::filesystem::path dir = uniqueTempPath();
  std::filesystem::create_directories(dir);
  std::filesystem::path db_path = dir / "store.db";

  storage::StorageOptions options;
  options.path = db_path.string();
  options.schema_path = schemaPath().string();
  options.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedKey());

  storage::Storage store(options);
  store.open();

  const std::string chat_id = "chatA";
  for (int i = 1; i <= 6; ++i) {
    std::string msg_id = "m" + std::to_string(i);
    std::vector<uint8_t> payload = {static_cast<uint8_t>(i)};
    store.appendMessage(chat_id, msg_id, "deviceA", 1000 + i, payload);
  }

  storage::BloomFilter remote_bloom(256, 3, 0xBEEF);
  remote_bloom.add("m1");
  remote_bloom.add("m2");
  remote_bloom.add("m3");
  remote_bloom.add("m5");
  remote_bloom.add("m6");

  auto ranges = store.planSync(chat_id, 6, remote_bloom, 10);
  require(ranges.size() == 1, "expected one gap range");
  require(ranges[0].start_index == 4 && ranges[0].end_index == 4, "gap range mismatch");

  storage::BloomFilter remote_bloom2(256, 3, 0xBEEF);
  remote_bloom2.add("m1");
  remote_bloom2.add("m2");
  remote_bloom2.add("m3");
  auto ranges2 = store.planSync(chat_id, 3, remote_bloom2, 10);
  require(ranges2.size() == 1, "expected contiguous sync range");
  require(ranges2[0].start_index == 4 && ranges2[0].end_index == 6, "sync range mismatch");

  auto messages = store.listMessagesRange(chat_id, 2, 3);
  require(messages.size() == 2, "unexpected message range size");
  require(messages[0].payload[0] == 2, "payload mismatch");
  require(messages[1].payload[0] == 3, "payload mismatch");
}

}

int main() {
  const std::vector<std::pair<std::string, std::function<void()>>> tests = {
      {"migration_applies_schema", testMigrationAppliesSchema},
      {"migration_rejects_newer_version", testMigrationRejectsNewerVersion},
      {"outbox_retry_timing", testOutboxRetryTiming},
      {"sync_gap_repair", testSyncGapRepair},
  };

  int failures = 0;
  for (const auto& test : tests) {
    try {
      test.second();
      std::cout << "[PASS] " << test.first << std::endl;
    } catch (const std::exception& ex) {
      std::cout << "[FAIL] " << test.first << ": " << ex.what() << std::endl;
      failures++;
    }
  }

  return failures == 0 ? 0 : 1;
}
