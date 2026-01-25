// Storage and sync implementation. Spec: core/storage/schema.sql.
#include "storage/Storage.h"

#include "crypto/Primitives.h"

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>

#include <sqlite3.h>

namespace storage {

namespace {

constexpr int kSchemaVersion = 3;
constexpr uint32_t kSessionStateMagic = 0x324E5353;
constexpr uint32_t kSessionStateVersion = 2;

struct SealedBlob {
  crypto::AeadAlgorithm algorithm = crypto::AeadAlgorithm::ChaCha20Poly1305;
  std::array<uint8_t, 12> nonce{};
  std::vector<uint8_t> blob;
  std::array<uint8_t, 16> tag{};
};

std::string readFile(const std::string& path) {
  std::ifstream file(path, std::ios::in | std::ios::binary);
  if (!file) {
    throw std::runtime_error("failed to open schema file");
  }
  std::string contents;
  file.seekg(0, std::ios::end);
  contents.resize(static_cast<size_t>(file.tellg()));
  file.seekg(0, std::ios::beg);
  if (!contents.empty()) {
    file.read(&contents[0], static_cast<std::streamsize>(contents.size()));
  }
  return contents;
}

std::vector<uint8_t> toBytes(const std::string& text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

std::string toHex(const std::vector<uint8_t>& data) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (uint8_t byte : data) {
    out.push_back(kHex[(byte >> 4) & 0x0F]);
    out.push_back(kHex[byte & 0x0F]);
  }
  return out;
}

std::array<uint8_t, 12> randomNonce() {
  std::vector<uint8_t> bytes = crypto::randomBytes(12);
  if (bytes.size() != 12) {
    throw std::runtime_error("randomBytes length mismatch");
  }
  std::array<uint8_t, 12> nonce{};
  std::copy(bytes.begin(), bytes.end(), nonce.begin());
  return nonce;
}

SealedBlob sealBlob(const std::array<uint8_t, 32>& key,
                    const std::vector<uint8_t>& plaintext,
                    const std::string& aad_text) {
  SealedBlob sealed;
  sealed.nonce = randomNonce();
  std::vector<uint8_t> aad = toBytes(aad_text);
  crypto::AeadResult result = crypto::aeadEncrypt(sealed.algorithm, key, sealed.nonce, plaintext, aad);
  sealed.blob = std::move(result.ciphertext);
  sealed.tag = result.tag;
  return sealed;
}

std::vector<uint8_t> openBlob(const std::array<uint8_t, 32>& key,
                              const SealedBlob& sealed,
                              const std::string& aad_text) {
  std::vector<uint8_t> aad = toBytes(aad_text);
  return crypto::aeadDecrypt(sealed.algorithm, key, sealed.nonce, sealed.blob, aad, sealed.tag);
}

void writeU32(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

void writeU64(std::vector<uint8_t>& out, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
  }
}

uint32_t readU32(const std::vector<uint8_t>& data, size_t& offset) {
  if (offset + 4 > data.size()) {
    throw std::runtime_error("session state parse overflow");
  }
  uint32_t value = static_cast<uint32_t>(data[offset]) |
                   (static_cast<uint32_t>(data[offset + 1]) << 8) |
                   (static_cast<uint32_t>(data[offset + 2]) << 16) |
                   (static_cast<uint32_t>(data[offset + 3]) << 24);
  offset += 4;
  return value;
}

uint64_t readU64(const std::vector<uint8_t>& data, size_t& offset) {
  if (offset + 8 > data.size()) {
    throw std::runtime_error("session state parse overflow");
  }
  uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(data[offset + i]) << (8 * i);
  }
  offset += 8;
  return value;
}

std::vector<uint8_t> encodeSession(const SessionState& state) {
  std::vector<uint8_t> out;
  writeU32(out, kSessionStateMagic);
  writeU32(out, kSessionStateVersion);
  writeU32(out, static_cast<uint32_t>(state.session_id.size()));
  out.insert(out.end(), state.session_id.begin(), state.session_id.end());
  out.insert(out.end(), state.root_key.begin(), state.root_key.end());
  out.insert(out.end(), state.chain_snd.begin(), state.chain_snd.end());
  out.insert(out.end(), state.chain_rcv.begin(), state.chain_rcv.end());
  out.insert(out.end(), state.local_ratchet_key.private_key.begin(), state.local_ratchet_key.private_key.end());
  out.insert(out.end(), state.local_ratchet_key.public_key.begin(), state.local_ratchet_key.public_key.end());
  out.insert(out.end(), state.remote_ratchet_pub.begin(), state.remote_ratchet_pub.end());
  out.push_back(static_cast<uint8_t>(state.has_sending_chain ? 1 : 0));
  out.push_back(static_cast<uint8_t>(state.has_receiving_chain ? 1 : 0));
  writeU32(out, state.counter_snd);
  writeU32(out, state.counter_rcv);
  writeU32(out, state.previous_counter);
  writeU64(out, state.frame_counter_snd);
  writeU64(out, state.frame_counter_rcv);
  return out;
}

SessionState decodeSession(const std::vector<uint8_t>& data) {
  SessionState state;
  size_t offset = 0;
  bool has_header = data.size() >= 8;
  if (has_header) {
    uint32_t magic = readU32(data, offset);
    if (magic == kSessionStateMagic) {
      uint32_t version = readU32(data, offset);
      if (version != kSessionStateVersion) {
        throw std::runtime_error("session state version mismatch");
      }
    } else {
      offset = 0;
    }
  }

  uint32_t session_len = readU32(data, offset);
  if (offset + session_len > data.size()) {
    throw std::runtime_error("session state length invalid");
  }
  auto begin = data.begin() + static_cast<std::ptrdiff_t>(offset);
  auto end = data.begin() + static_cast<std::ptrdiff_t>(offset + session_len);
  state.session_id.assign(begin, end);
  offset += session_len;
  if (offset + state.root_key.size() * 3 > data.size()) {
    throw std::runtime_error("session state key overflow");
  }
  std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
            data.begin() + static_cast<std::ptrdiff_t>(offset + state.root_key.size()),
            state.root_key.begin());
  offset += state.root_key.size();
  std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
            data.begin() + static_cast<std::ptrdiff_t>(offset + state.chain_snd.size()),
            state.chain_snd.begin());
  offset += state.chain_snd.size();
  std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
            data.begin() + static_cast<std::ptrdiff_t>(offset + state.chain_rcv.size()),
            state.chain_rcv.begin());
  offset += state.chain_rcv.size();
  if (offset + state.local_ratchet_key.private_key.size() +
          state.local_ratchet_key.public_key.size() +
          state.remote_ratchet_pub.size() + 2 <= data.size()) {
    std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
              data.begin() + static_cast<std::ptrdiff_t>(offset + state.local_ratchet_key.private_key.size()),
              state.local_ratchet_key.private_key.begin());
    offset += state.local_ratchet_key.private_key.size();
    std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
              data.begin() + static_cast<std::ptrdiff_t>(offset + state.local_ratchet_key.public_key.size()),
              state.local_ratchet_key.public_key.begin());
    offset += state.local_ratchet_key.public_key.size();
    std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
              data.begin() + static_cast<std::ptrdiff_t>(offset + state.remote_ratchet_pub.size()),
              state.remote_ratchet_pub.begin());
    offset += state.remote_ratchet_pub.size();
    state.has_sending_chain = data[offset++] != 0;
    state.has_receiving_chain = data[offset++] != 0;
  }
  state.counter_snd = readU32(data, offset);
  state.counter_rcv = readU32(data, offset);
  state.previous_counter = readU32(data, offset);
  if (offset + 16 <= data.size()) {
    state.frame_counter_snd = readU64(data, offset);
    state.frame_counter_rcv = readU64(data, offset);
  }
  return state;
}

uint64_t randomU64() {
  std::vector<uint8_t> bytes = crypto::randomBytes(8);
  if (bytes.size() != 8) {
    throw std::runtime_error("randomBytes length mismatch");
  }
  uint64_t value = 0;
  for (size_t i = 0; i < bytes.size(); ++i) {
    value |= static_cast<uint64_t>(bytes[i]) << (8 * i);
  }
  return value;
}

int64_t clampDelay(int64_t delay, int64_t max_delay) {
  if (delay < 0) {
    return 0;
  }
  if (delay > max_delay) {
    return max_delay;
  }
  return delay;
}

int64_t withJitter(int64_t delay, double jitter_ratio) {
  if (jitter_ratio <= 0.0) {
    return delay;
  }
  double jitter = static_cast<double>(delay) * jitter_ratio;
  int64_t jitter_ms = static_cast<int64_t>(jitter);
  if (jitter_ms <= 0) {
    return delay;
  }
  uint64_t span = static_cast<uint64_t>(jitter_ms) * 2ULL + 1ULL;
  int64_t delta = static_cast<int64_t>(randomU64() % span) - jitter_ms;
  return std::max<int64_t>(0, delay + delta);
}

class Statement {
 public:
  Statement(sqlite3* db, const std::string& sql) {
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt_, nullptr) != SQLITE_OK) {
      throw std::runtime_error("sqlite prepare failed");
    }
  }

  ~Statement() {
    if (stmt_) {
      sqlite3_finalize(stmt_);
    }
  }

  sqlite3_stmt* get() const {
    return stmt_;
  }

 private:
  sqlite3_stmt* stmt_ = nullptr;
};

void bindText(sqlite3_stmt* stmt, int index, const std::string& value) {
  if (sqlite3_bind_text(stmt, index, value.c_str(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
    throw std::runtime_error("sqlite bind text failed");
  }
}

void bindOptionalText(sqlite3_stmt* stmt, int index, const std::string& value) {
  if (value.empty()) {
    if (sqlite3_bind_null(stmt, index) != SQLITE_OK) {
      throw std::runtime_error("sqlite bind null failed");
    }
    return;
  }
  bindText(stmt, index, value);
}

void bindInt64(sqlite3_stmt* stmt, int index, int64_t value) {
  if (sqlite3_bind_int64(stmt, index, value) != SQLITE_OK) {
    throw std::runtime_error("sqlite bind int64 failed");
  }
}

void bindInt(sqlite3_stmt* stmt, int index, int value) {
  if (sqlite3_bind_int(stmt, index, value) != SQLITE_OK) {
    throw std::runtime_error("sqlite bind int failed");
  }
}

void bindBlob(sqlite3_stmt* stmt, int index, const std::vector<uint8_t>& value) {
  const void* data = value.empty() ? nullptr : value.data();
  int size = static_cast<int>(value.size());
  if (sqlite3_bind_blob(stmt, index, data, size, SQLITE_TRANSIENT) != SQLITE_OK) {
    throw std::runtime_error("sqlite bind blob failed");
  }
}

template <size_t N>
void bindBlob(sqlite3_stmt* stmt, int index, const std::array<uint8_t, N>& value) {
  const void* data = value.data();
  int size = static_cast<int>(value.size());
  if (sqlite3_bind_blob(stmt, index, data, size, SQLITE_TRANSIENT) != SQLITE_OK) {
    throw std::runtime_error("sqlite bind blob failed");
  }
}

std::vector<uint8_t> columnBlob(sqlite3_stmt* stmt, int index) {
  const auto* data = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, index));
  int size = sqlite3_column_bytes(stmt, index);
  if (!data || size <= 0) {
    return {};
  }
  return std::vector<uint8_t>(data, data + size);
}

std::string columnText(sqlite3_stmt* stmt, int index) {
  const unsigned char* text = sqlite3_column_text(stmt, index);
  if (!text) {
    return {};
  }
  return std::string(reinterpret_cast<const char*>(text));
}

int64_t columnInt64(sqlite3_stmt* stmt, int index) {
  return sqlite3_column_int64(stmt, index);
}

int columnInt(sqlite3_stmt* stmt, int index) {
  return sqlite3_column_int(stmt, index);
}

}

struct Storage::SqliteDb {
  sqlite3* db = nullptr;

  explicit SqliteDb(const std::string& path) {
    if (sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
      std::string err = sqlite3_errmsg(db);
      sqlite3_close(db);
      db = nullptr;
      throw std::runtime_error("sqlite open failed: " + err);
    }
    sqlite3_busy_timeout(db, 5000);
  }

  ~SqliteDb() {
    if (db) {
      sqlite3_close(db);
    }
  }

  void exec(const std::string& sql) const {
    char* err = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
      std::string msg = err ? err : "sqlite exec failed";
      sqlite3_free(err);
      throw std::runtime_error(msg);
    }
  }

  int userVersion() const {
    Statement stmt(db, "PRAGMA user_version;");
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
      throw std::runtime_error("sqlite user_version query failed");
    }
    return sqlite3_column_int(stmt.get(), 0);
  }
};

int64_t OutboxPolicy::nextDelayMs(uint32_t attempts) const {
  if (attempts == 0) {
    return withJitter(clampDelay(base_delay_ms, max_delay_ms), jitter_ratio);
  }
  uint32_t shift = std::min<uint32_t>(attempts - 1, 30);
  int64_t delay = base_delay_ms * static_cast<int64_t>(1ULL << shift);
  delay = clampDelay(delay, max_delay_ms);
  return withJitter(delay, jitter_ratio);
}

Storage::Storage(StorageOptions options)
    : options_(std::move(options)) {
  if (!options_.master_key) {
    throw std::runtime_error("master key provider required");
  }
  master_key_ = options_.master_key->loadOrCreate();
}

Storage::~Storage() {
  close();
  crypto::secureZero(master_key_.data(), master_key_.size());
}

void Storage::open() {
  if (db_) {
    return;
  }
  if (options_.path.empty()) {
    throw std::runtime_error("storage path required");
  }
  if (options_.schema_path.empty()) {
    throw std::runtime_error("schema path required");
  }
  db_ = std::make_unique<SqliteDb>(options_.path);
  ensureSchema();
}

void Storage::close() {
  db_.reset();
}

bool Storage::isOpen() const {
  return static_cast<bool>(db_);
}

void Storage::ensureSchema() {
  int version = db_->userVersion();
  if (version == 0) {
    std::string schema = readFile(options_.schema_path);
    if (schema.empty()) {
      throw std::runtime_error("schema file empty");
    }
    db_->exec(schema);
    version = db_->userVersion();
  }
  if (version == 2) {
    db_->exec("ALTER TABLE contacts ADD COLUMN username TEXT;");
    db_->exec("CREATE INDEX IF NOT EXISTS idx_contacts_username ON contacts(username);");
    db_->exec("PRAGMA user_version = 3;");
    version = 3;
  }
  if (version != kSchemaVersion) {
    throw std::runtime_error("unsupported schema version");
  }
}

int64_t Storage::appendMessage(const std::string& chat_id,
                               const std::string& msg_id,
                               const std::string& sender_device,
                               int64_t ts_ms,
                               const std::vector<uint8_t>& payload) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  db_->exec("BEGIN IMMEDIATE;");
  try {
    int64_t last_index = 0;
    {
      Statement stmt(db_->db, "SELECT last_index FROM chats WHERE chat_id = ?;");
      bindText(stmt.get(), 1, chat_id);
      int rc = sqlite3_step(stmt.get());
      if (rc == SQLITE_ROW) {
        last_index = columnInt64(stmt.get(), 0);
      } else if (rc != SQLITE_DONE) {
        throw std::runtime_error("sqlite select chat failed");
      }
    }
    int64_t next_index = last_index + 1;
    SealedBlob sealed = sealBlob(master_key_, payload, "messages:" + chat_id + ":" + msg_id);
    {
      Statement stmt(db_->db,
                     "INSERT INTO messages(chat_id, msg_id, sender_device, ts_ms, aead_algo, aead_nonce, aead_blob, aead_tag, delivered, acked, idx)"
                     " VALUES(?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?);");
      bindText(stmt.get(), 1, chat_id);
      bindText(stmt.get(), 2, msg_id);
      bindText(stmt.get(), 3, sender_device);
      bindInt64(stmt.get(), 4, ts_ms);
      bindInt(stmt.get(), 5, static_cast<int>(sealed.algorithm));
      bindBlob(stmt.get(), 6, sealed.nonce);
      bindBlob(stmt.get(), 7, sealed.blob);
      bindBlob(stmt.get(), 8, sealed.tag);
      bindInt64(stmt.get(), 9, next_index);
      if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("sqlite insert message failed");
      }
    }
    {
      Statement stmt(db_->db,
                     "INSERT INTO chats(chat_id, last_index, updated_at_ms) VALUES(?, ?, ?)"
                     " ON CONFLICT(chat_id) DO UPDATE SET last_index = excluded.last_index, updated_at_ms = excluded.updated_at_ms;");
      bindText(stmt.get(), 1, chat_id);
      bindInt64(stmt.get(), 2, next_index);
      bindInt64(stmt.get(), 3, ts_ms);
      if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("sqlite upsert chat failed");
      }
    }
    db_->exec("COMMIT;");
    return next_index;
  } catch (...) {
    db_->exec("ROLLBACK;");
    throw;
  }
}

std::vector<StoredMessage> Storage::listMessages(const std::string& chat_id,
                                                 int64_t start_index,
                                                 size_t limit) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  std::vector<StoredMessage> out;
  Statement stmt(db_->db,
                 "SELECT msg_id, sender_device, ts_ms, aead_algo, aead_nonce, aead_blob, aead_tag, delivered, acked, idx"
                 " FROM messages WHERE chat_id = ? AND idx >= ? ORDER BY idx ASC LIMIT ?;");
  bindText(stmt.get(), 1, chat_id);
  bindInt64(stmt.get(), 2, start_index);
  bindInt64(stmt.get(), 3, static_cast<int64_t>(limit));
  while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
    StoredMessage msg;
    msg.chat_id = chat_id;
    msg.msg_id = columnText(stmt.get(), 0);
    msg.sender_device = columnText(stmt.get(), 1);
    msg.ts_ms = columnInt64(stmt.get(), 2);
    SealedBlob sealed;
    sealed.algorithm = static_cast<crypto::AeadAlgorithm>(columnInt(stmt.get(), 3));
    auto nonce = columnBlob(stmt.get(), 4);
    auto blob = columnBlob(stmt.get(), 5);
    auto tag = columnBlob(stmt.get(), 6);
    if (nonce.size() != sealed.nonce.size() || tag.size() != sealed.tag.size()) {
      throw std::runtime_error("message nonce/tag size mismatch");
    }
    std::copy(nonce.begin(), nonce.end(), sealed.nonce.begin());
    std::copy(tag.begin(), tag.end(), sealed.tag.begin());
    sealed.blob = std::move(blob);
    msg.payload = openBlob(master_key_, sealed, "messages:" + chat_id + ":" + msg.msg_id);
    msg.delivered = columnInt(stmt.get(), 7) != 0;
    msg.acked = columnInt(stmt.get(), 8) != 0;
    msg.index = columnInt64(stmt.get(), 9);
    out.push_back(std::move(msg));
  }
  return out;
}

std::vector<StoredMessage> Storage::listMessagesRange(const std::string& chat_id,
                                                      int64_t start_index,
                                                      int64_t end_index) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  std::vector<StoredMessage> out;
  Statement stmt(db_->db,
                 "SELECT msg_id, sender_device, ts_ms, aead_algo, aead_nonce, aead_blob, aead_tag, delivered, acked, idx"
                 " FROM messages WHERE chat_id = ? AND idx BETWEEN ? AND ? ORDER BY idx ASC;");
  bindText(stmt.get(), 1, chat_id);
  bindInt64(stmt.get(), 2, start_index);
  bindInt64(stmt.get(), 3, end_index);
  while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
    StoredMessage msg;
    msg.chat_id = chat_id;
    msg.msg_id = columnText(stmt.get(), 0);
    msg.sender_device = columnText(stmt.get(), 1);
    msg.ts_ms = columnInt64(stmt.get(), 2);
    SealedBlob sealed;
    sealed.algorithm = static_cast<crypto::AeadAlgorithm>(columnInt(stmt.get(), 3));
    auto nonce = columnBlob(stmt.get(), 4);
    auto blob = columnBlob(stmt.get(), 5);
    auto tag = columnBlob(stmt.get(), 6);
    if (nonce.size() != sealed.nonce.size() || tag.size() != sealed.tag.size()) {
      throw std::runtime_error("message nonce/tag size mismatch");
    }
    std::copy(nonce.begin(), nonce.end(), sealed.nonce.begin());
    std::copy(tag.begin(), tag.end(), sealed.tag.begin());
    sealed.blob = std::move(blob);
    msg.payload = openBlob(master_key_, sealed, "messages:" + chat_id + ":" + msg.msg_id);
    msg.delivered = columnInt(stmt.get(), 7) != 0;
    msg.acked = columnInt(stmt.get(), 8) != 0;
    msg.index = columnInt64(stmt.get(), 9);
    out.push_back(std::move(msg));
  }
  return out;
}

int64_t Storage::lastIndex(const std::string& chat_id) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db, "SELECT last_index FROM chats WHERE chat_id = ?;");
  bindText(stmt.get(), 1, chat_id);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_ROW) {
    return columnInt64(stmt.get(), 0);
  }
  if (rc != SQLITE_DONE) {
    throw std::runtime_error("sqlite select last_index failed");
  }
  return 0;
}

std::vector<ChatSummary> Storage::listChats() const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  std::vector<ChatSummary> chats;
  Statement stmt(db_->db, "SELECT chat_id, last_index, updated_at_ms FROM chats ORDER BY updated_at_ms DESC;");
  while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
    ChatSummary summary;
    summary.chat_id = columnText(stmt.get(), 0);
    summary.last_index = columnInt64(stmt.get(), 1);
    summary.updated_at_ms = columnInt64(stmt.get(), 2);
    chats.push_back(std::move(summary));
  }
  return chats;
}

void Storage::upsertContact(const ContactRecord& contact) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db,
                 "INSERT INTO contacts(peer_id, username, identity_ed25519, device_ed25519, created_at_ms, updated_at_ms)"
                 " VALUES(?, ?, ?, ?, ?, ?)"
                 " ON CONFLICT(peer_id) DO UPDATE SET username = excluded.username,"
                 " identity_ed25519 = excluded.identity_ed25519, device_ed25519 = excluded.device_ed25519,"
                 " updated_at_ms = excluded.updated_at_ms;");
  bindText(stmt.get(), 1, contact.peer_id);
  bindOptionalText(stmt.get(), 2, contact.username);
  bindBlob(stmt.get(), 3, contact.identity_ed25519);
  bindBlob(stmt.get(), 4, contact.device_ed25519);
  bindInt64(stmt.get(), 5, contact.created_at_ms);
  bindInt64(stmt.get(), 6, contact.updated_at_ms);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite upsert contact failed");
  }
}

std::optional<ContactRecord> Storage::loadContact(const std::string& peer_id) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db,
                 "SELECT username, identity_ed25519, device_ed25519, created_at_ms, updated_at_ms"
                 " FROM contacts WHERE peer_id = ?;");
  bindText(stmt.get(), 1, peer_id);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_DONE) {
    return std::nullopt;
  }
  if (rc != SQLITE_ROW) {
    throw std::runtime_error("sqlite load contact failed");
  }
  ContactRecord record;
  record.peer_id = peer_id;
  record.username = columnText(stmt.get(), 0);
  auto identity_blob = columnBlob(stmt.get(), 1);
  auto device_blob = columnBlob(stmt.get(), 2);
  if (identity_blob.size() != record.identity_ed25519.size() ||
      device_blob.size() != record.device_ed25519.size()) {
    throw std::runtime_error("contact key size mismatch");
  }
  std::copy(identity_blob.begin(), identity_blob.end(), record.identity_ed25519.begin());
  std::copy(device_blob.begin(), device_blob.end(), record.device_ed25519.begin());
  record.created_at_ms = columnInt64(stmt.get(), 3);
  record.updated_at_ms = columnInt64(stmt.get(), 4);
  return record;
}

std::vector<ContactRecord> Storage::listContacts() const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  std::vector<ContactRecord> contacts;
  Statement stmt(db_->db,
                 "SELECT peer_id, username, identity_ed25519, device_ed25519, created_at_ms, updated_at_ms"
                 " FROM contacts ORDER BY updated_at_ms DESC;");
  while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
    ContactRecord record;
    record.peer_id = columnText(stmt.get(), 0);
    record.username = columnText(stmt.get(), 1);
    auto identity_blob = columnBlob(stmt.get(), 2);
    auto device_blob = columnBlob(stmt.get(), 3);
    if (identity_blob.size() != record.identity_ed25519.size() ||
        device_blob.size() != record.device_ed25519.size()) {
      throw std::runtime_error("contact key size mismatch");
    }
    std::copy(identity_blob.begin(), identity_blob.end(), record.identity_ed25519.begin());
    std::copy(device_blob.begin(), device_blob.end(), record.device_ed25519.begin());
    record.created_at_ms = columnInt64(stmt.get(), 4);
    record.updated_at_ms = columnInt64(stmt.get(), 5);
    contacts.push_back(std::move(record));
  }
  return contacts;
}

bool Storage::messageExists(const std::string& chat_id, const std::string& msg_id) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db, "SELECT 1 FROM messages WHERE chat_id = ? AND msg_id = ? LIMIT 1;");
  bindText(stmt.get(), 1, chat_id);
  bindText(stmt.get(), 2, msg_id);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_ROW) {
    return true;
  }
  if (rc != SQLITE_DONE) {
    throw std::runtime_error("sqlite select message failed");
  }
  return false;
}

void Storage::markMessageDelivered(const std::string& chat_id, const std::string& msg_id) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db,
                 "UPDATE messages SET delivered = 1 WHERE chat_id = ? AND msg_id = ?;");
  bindText(stmt.get(), 1, chat_id);
  bindText(stmt.get(), 2, msg_id);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite update delivered failed");
  }
}

void Storage::markMessageAcked(const std::string& chat_id, const std::string& msg_id) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db,
                 "UPDATE messages SET acked = 1 WHERE chat_id = ? AND msg_id = ?;");
  bindText(stmt.get(), 1, chat_id);
  bindText(stmt.get(), 2, msg_id);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite update acked failed");
  }
}

void Storage::storeRevocation(const RevocationRecord& record) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db,
                 "INSERT INTO revocations(device_id, identity_ed25519, revoked_at_ms, signature)"
                 " VALUES(?, ?, ?, ?)"
                 " ON CONFLICT(device_id) DO UPDATE SET identity_ed25519 = excluded.identity_ed25519,"
                 " revoked_at_ms = excluded.revoked_at_ms, signature = excluded.signature;");
  bindText(stmt.get(), 1, record.device_id);
  bindBlob(stmt.get(), 2, record.identity_ed25519);
  bindInt64(stmt.get(), 3, record.revoked_at_ms);
  bindBlob(stmt.get(), 4, record.signature);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite upsert revocation failed");
  }
}

std::optional<RevocationRecord> Storage::loadRevocation(const std::string& device_id) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db,
                 "SELECT identity_ed25519, revoked_at_ms, signature FROM revocations WHERE device_id = ?;");
  bindText(stmt.get(), 1, device_id);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_DONE) {
    return std::nullopt;
  }
  if (rc != SQLITE_ROW) {
    throw std::runtime_error("sqlite load revocation failed");
  }
  RevocationRecord record;
  record.device_id = device_id;
  auto identity_blob = columnBlob(stmt.get(), 0);
  auto signature_blob = columnBlob(stmt.get(), 2);
  if (identity_blob.size() != record.identity_ed25519.size() ||
      signature_blob.size() != record.signature.size()) {
    throw std::runtime_error("revocation key size mismatch");
  }
  std::copy(identity_blob.begin(), identity_blob.end(), record.identity_ed25519.begin());
  std::copy(signature_blob.begin(), signature_blob.end(), record.signature.begin());
  record.revoked_at_ms = columnInt64(stmt.get(), 1);
  return record;
}

bool Storage::isDeviceRevoked(const std::string& device_id) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db, "SELECT 1 FROM revocations WHERE device_id = ? LIMIT 1;");
  bindText(stmt.get(), 1, device_id);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_ROW) {
    return true;
  }
  if (rc != SQLITE_DONE) {
    throw std::runtime_error("sqlite select revocation failed");
  }
  return false;
}

int64_t Storage::enqueueOutbox(const std::string& peer_device,
                               const std::vector<uint8_t>& session_id,
                               const std::vector<uint8_t>& frame,
                               int64_t now_ms) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  SealedBlob sealed = sealBlob(master_key_, frame, "outbox:" + peer_device + ":" + toHex(session_id));
  Statement stmt(db_->db,
                 "INSERT INTO outbox(peer_device, session_id, frame_algo, frame_nonce, frame_blob, frame_tag, next_retry_at_ms, attempts)"
                 " VALUES(?, ?, ?, ?, ?, ?, ?, 0);");
  bindText(stmt.get(), 1, peer_device);
  bindBlob(stmt.get(), 2, session_id);
  bindInt(stmt.get(), 3, static_cast<int>(sealed.algorithm));
  bindBlob(stmt.get(), 4, sealed.nonce);
  bindBlob(stmt.get(), 5, sealed.blob);
  bindBlob(stmt.get(), 6, sealed.tag);
  bindInt64(stmt.get(), 7, now_ms);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite insert outbox failed");
  }
  return sqlite3_last_insert_rowid(db_->db);
}

std::vector<OutboxItem> Storage::loadDueOutbox(int64_t now_ms, size_t limit) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  std::vector<OutboxItem> out;
  Statement stmt(db_->db,
                 "SELECT id, peer_device, session_id, frame_algo, frame_nonce, frame_blob, frame_tag, next_retry_at_ms, attempts"
                 " FROM outbox WHERE next_retry_at_ms <= ? ORDER BY next_retry_at_ms ASC, id ASC LIMIT ?;");
  bindInt64(stmt.get(), 1, now_ms);
  bindInt64(stmt.get(), 2, static_cast<int64_t>(limit));
  while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
    OutboxItem item;
    item.id = columnInt64(stmt.get(), 0);
    item.peer_device = columnText(stmt.get(), 1);
    item.session_id = columnBlob(stmt.get(), 2);
    SealedBlob sealed;
    sealed.algorithm = static_cast<crypto::AeadAlgorithm>(columnInt(stmt.get(), 3));
    auto nonce = columnBlob(stmt.get(), 4);
    auto blob = columnBlob(stmt.get(), 5);
    auto tag = columnBlob(stmt.get(), 6);
    if (nonce.size() != sealed.nonce.size() || tag.size() != sealed.tag.size()) {
      throw std::runtime_error("outbox nonce/tag size mismatch");
    }
    std::copy(nonce.begin(), nonce.end(), sealed.nonce.begin());
    std::copy(tag.begin(), tag.end(), sealed.tag.begin());
    sealed.blob = std::move(blob);
    item.frame = openBlob(master_key_, sealed, "outbox:" + item.peer_device + ":" + toHex(item.session_id));
    item.next_retry_at_ms = columnInt64(stmt.get(), 7);
    item.attempts = static_cast<uint32_t>(columnInt64(stmt.get(), 8));
    out.push_back(std::move(item));
  }
  return out;
}

void Storage::markOutboxAttempt(int64_t id, int64_t now_ms) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  uint32_t attempts = 0;
  {
    Statement stmt(db_->db, "SELECT attempts FROM outbox WHERE id = ?;");
    bindInt64(stmt.get(), 1, id);
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
      attempts = static_cast<uint32_t>(columnInt64(stmt.get(), 0));
    } else {
      throw std::runtime_error("outbox entry not found");
    }
  }
  attempts += 1;
  int64_t delay = options_.outbox_policy.nextDelayMs(attempts);
  int64_t next_retry = now_ms + delay;
  Statement update(db_->db,
                   "UPDATE outbox SET attempts = ?, next_retry_at_ms = ? WHERE id = ?;");
  bindInt64(update.get(), 1, attempts);
  bindInt64(update.get(), 2, next_retry);
  bindInt64(update.get(), 3, id);
  if (sqlite3_step(update.get()) != SQLITE_DONE) {
    throw std::runtime_error("outbox retry update failed");
  }
}

void Storage::removeOutbox(int64_t id) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db, "DELETE FROM outbox WHERE id = ?;");
  bindInt64(stmt.get(), 1, id);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite delete outbox failed");
  }
}

void Storage::clearOutboxForPeer(const std::string& peer_device) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db, "DELETE FROM outbox WHERE peer_device = ?;");
  bindText(stmt.get(), 1, peer_device);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite clear outbox failed");
  }
}

BloomFilter Storage::buildRecentBloom(const std::string& chat_id,
                                      size_t window,
                                      uint32_t bloom_bits,
                                      uint32_t hash_count,
                                      uint64_t seed) const {
  BloomFilter filter(bloom_bits, hash_count, seed);
  auto recent = recentMessageIds(chat_id, window);
  for (const auto& entry : recent) {
    filter.add(entry.second);
  }
  return filter;
}

std::vector<SyncRange> Storage::planSync(const std::string& chat_id,
                                         int64_t remote_last_index,
                                         const BloomFilter& remote_bloom,
                                         size_t recent_window) const {
  std::vector<SyncRange> ranges;
  int64_t local_last = lastIndex(chat_id);
  if (remote_last_index < 0) {
    remote_last_index = 0;
  }
  if (local_last == 0) {
    return ranges;
  }
  if (remote_last_index < local_last) {
    SyncRange range;
    range.start_index = remote_last_index + 1;
    range.end_index = local_last;
    ranges.push_back(range);
  }
  auto recent = recentMessageIds(chat_id, recent_window);
  std::vector<int64_t> missing;
  for (const auto& entry : recent) {
    if (entry.first <= remote_last_index && !remote_bloom.possiblyContains(entry.second)) {
      missing.push_back(entry.first);
    }
  }
  if (!missing.empty()) {
    std::sort(missing.begin(), missing.end());
    int64_t start = missing.front();
    int64_t end = missing.front();
    for (size_t i = 1; i < missing.size(); ++i) {
      if (missing[i] == end + 1) {
        end = missing[i];
      } else {
        ranges.push_back({start, end});
        start = missing[i];
        end = missing[i];
      }
    }
    ranges.push_back({start, end});
  }
  if (ranges.empty()) {
    return ranges;
  }
  std::sort(ranges.begin(), ranges.end(), [](const SyncRange& a, const SyncRange& b) {
    if (a.start_index == b.start_index) {
      return a.end_index < b.end_index;
    }
    return a.start_index < b.start_index;
  });
  std::vector<SyncRange> merged;
  SyncRange current = ranges.front();
  for (size_t i = 1; i < ranges.size(); ++i) {
    if (ranges[i].start_index <= current.end_index + 1) {
      current.end_index = std::max(current.end_index, ranges[i].end_index);
    } else {
      merged.push_back(current);
      current = ranges[i];
    }
  }
  merged.push_back(current);
  return merged;
}

void Storage::saveSession(const std::string& peer_device,
                          const SessionState& state,
                          int64_t updated_at_ms) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  std::vector<uint8_t> encoded = encodeSession(state);
  SealedBlob sealed = sealBlob(master_key_, encoded, "session:" + peer_device);
  Statement stmt(db_->db,
                 "INSERT INTO sessions(peer_device, state_algo, state_nonce, state_blob, state_tag, updated_at_ms)"
                 " VALUES(?, ?, ?, ?, ?, ?)"
                 " ON CONFLICT(peer_device) DO UPDATE SET state_algo = excluded.state_algo, state_nonce = excluded.state_nonce,"
                 " state_blob = excluded.state_blob, state_tag = excluded.state_tag, updated_at_ms = excluded.updated_at_ms;");
  bindText(stmt.get(), 1, peer_device);
  bindInt(stmt.get(), 2, static_cast<int>(sealed.algorithm));
  bindBlob(stmt.get(), 3, sealed.nonce);
  bindBlob(stmt.get(), 4, sealed.blob);
  bindBlob(stmt.get(), 5, sealed.tag);
  bindInt64(stmt.get(), 6, updated_at_ms);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite upsert session failed");
  }
}

std::optional<SessionState> Storage::loadSession(const std::string& peer_device) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db,
                 "SELECT state_algo, state_nonce, state_blob, state_tag FROM sessions WHERE peer_device = ?;");
  bindText(stmt.get(), 1, peer_device);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_DONE) {
    return std::nullopt;
  }
  if (rc != SQLITE_ROW) {
    throw std::runtime_error("sqlite load session failed");
  }
  SealedBlob sealed;
  sealed.algorithm = static_cast<crypto::AeadAlgorithm>(columnInt(stmt.get(), 0));
  auto nonce = columnBlob(stmt.get(), 1);
  auto blob = columnBlob(stmt.get(), 2);
  auto tag = columnBlob(stmt.get(), 3);
  if (nonce.size() != sealed.nonce.size() || tag.size() != sealed.tag.size()) {
    throw std::runtime_error("session nonce/tag size mismatch");
  }
  std::copy(nonce.begin(), nonce.end(), sealed.nonce.begin());
  std::copy(tag.begin(), tag.end(), sealed.tag.begin());
  sealed.blob = std::move(blob);
  std::vector<uint8_t> decoded = openBlob(master_key_, sealed, "session:" + peer_device);
  return decodeSession(decoded);
}

std::vector<std::string> Storage::listSessionPeers() const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  std::vector<std::string> out;
  Statement stmt(db_->db, "SELECT peer_device FROM sessions ORDER BY peer_device ASC;");
  while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
    out.push_back(columnText(stmt.get(), 0));
  }
  return out;
}

void Storage::deleteSession(const std::string& peer_device) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db, "DELETE FROM sessions WHERE peer_device = ?;");
  bindText(stmt.get(), 1, peer_device);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite delete session failed");
  }
}

void Storage::storePrekey(const PrekeyRecord& record) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  SealedBlob sealed = sealBlob(master_key_, record.secret, "prekey:" + std::to_string(record.id));
  Statement stmt(db_->db,
                 "INSERT INTO prekeys(id, public, secret_algo, secret_nonce, secret_blob, secret_tag, used)"
                 " VALUES(?, ?, ?, ?, ?, ?, ?)"
                 " ON CONFLICT(id) DO UPDATE SET public = excluded.public, secret_algo = excluded.secret_algo,"
                 " secret_nonce = excluded.secret_nonce, secret_blob = excluded.secret_blob, secret_tag = excluded.secret_tag, used = excluded.used;");
  bindInt64(stmt.get(), 1, record.id);
  bindBlob(stmt.get(), 2, record.public_key);
  bindInt(stmt.get(), 3, static_cast<int>(sealed.algorithm));
  bindBlob(stmt.get(), 4, sealed.nonce);
  bindBlob(stmt.get(), 5, sealed.blob);
  bindBlob(stmt.get(), 6, sealed.tag);
  bindInt(stmt.get(), 7, record.used ? 1 : 0);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite upsert prekey failed");
  }
}

std::optional<PrekeyRecord> Storage::loadPrekey(int64_t id) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db,
                 "SELECT public, secret_algo, secret_nonce, secret_blob, secret_tag, used FROM prekeys WHERE id = ?;");
  bindInt64(stmt.get(), 1, id);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_DONE) {
    return std::nullopt;
  }
  if (rc != SQLITE_ROW) {
    throw std::runtime_error("sqlite load prekey failed");
  }
  PrekeyRecord record;
  record.id = id;
  record.public_key = columnBlob(stmt.get(), 0);
  SealedBlob sealed;
  sealed.algorithm = static_cast<crypto::AeadAlgorithm>(columnInt(stmt.get(), 1));
  auto nonce = columnBlob(stmt.get(), 2);
  auto blob = columnBlob(stmt.get(), 3);
  auto tag = columnBlob(stmt.get(), 4);
  if (nonce.size() != sealed.nonce.size() || tag.size() != sealed.tag.size()) {
    throw std::runtime_error("prekey nonce/tag size mismatch");
  }
  std::copy(nonce.begin(), nonce.end(), sealed.nonce.begin());
  std::copy(tag.begin(), tag.end(), sealed.tag.begin());
  sealed.blob = std::move(blob);
  record.secret = openBlob(master_key_, sealed, "prekey:" + std::to_string(id));
  record.used = columnInt(stmt.get(), 5) != 0;
  return record;
}

void Storage::markPrekeyUsed(int64_t id) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db, "UPDATE prekeys SET used = 1 WHERE id = ?;");
  bindInt64(stmt.get(), 1, id);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite update prekey failed");
  }
}

std::optional<PrekeyRecord> Storage::loadUnusedPrekey(int64_t min_id) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db,
                 "SELECT id, public, secret_algo, secret_nonce, secret_blob, secret_tag, used"
                 " FROM prekeys WHERE used = 0 AND id >= ? ORDER BY id ASC LIMIT 1;");
  bindInt64(stmt.get(), 1, min_id);
  if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
    return std::nullopt;
  }
  PrekeyRecord record;
  record.id = columnInt64(stmt.get(), 0);
  record.public_key = columnBlob(stmt.get(), 1);
  SealedBlob sealed;
  sealed.algorithm = static_cast<crypto::AeadAlgorithm>(columnInt(stmt.get(), 2));
  auto nonce = columnBlob(stmt.get(), 3);
  auto blob = columnBlob(stmt.get(), 4);
  auto tag = columnBlob(stmt.get(), 5);
  if (nonce.size() != sealed.nonce.size() || tag.size() != sealed.tag.size()) {
    throw std::runtime_error("prekey nonce/tag size mismatch");
  }
  std::copy(nonce.begin(), nonce.end(), sealed.nonce.begin());
  std::copy(tag.begin(), tag.end(), sealed.tag.begin());
  sealed.blob = std::move(blob);
  record.secret = openBlob(master_key_, sealed, "prekey:" + std::to_string(record.id));
  record.used = columnInt(stmt.get(), 6) != 0;
  return record;
}

int64_t Storage::countUnusedPrekeys(int64_t min_id) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db, "SELECT COUNT(1) FROM prekeys WHERE used = 0 AND id >= ?;");
  bindInt64(stmt.get(), 1, min_id);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_ROW) {
    return columnInt64(stmt.get(), 0);
  }
  if (rc != SQLITE_DONE) {
    throw std::runtime_error("sqlite count prekeys failed");
  }
  return 0;
}

void Storage::setMeta(const std::string& key, const std::vector<uint8_t>& value) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db, "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;");
  bindText(stmt.get(), 1, key);
  bindBlob(stmt.get(), 2, value);
  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw std::runtime_error("sqlite meta upsert failed");
  }
}

std::optional<std::vector<uint8_t>> Storage::getMeta(const std::string& key) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  Statement stmt(db_->db, "SELECT value FROM meta WHERE key = ?;");
  bindText(stmt.get(), 1, key);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_ROW) {
    return columnBlob(stmt.get(), 0);
  }
  if (rc != SQLITE_DONE) {
    throw std::runtime_error("sqlite meta select failed");
  }
  return std::nullopt;
}

void Storage::upsertMessageAtIndex(const StoredMessage& message, int64_t index) {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  db_->exec("BEGIN IMMEDIATE;");
  try {
    if (messageExists(message.chat_id, message.msg_id)) {
      db_->exec("COMMIT;");
      return;
    }
    SealedBlob sealed = sealBlob(master_key_, message.payload, "messages:" + message.chat_id + ":" + message.msg_id);
    {
      Statement stmt(db_->db,
                     "INSERT INTO messages(chat_id, msg_id, sender_device, ts_ms, aead_algo, aead_nonce, aead_blob, aead_tag, delivered, acked, idx)"
                     " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
      bindText(stmt.get(), 1, message.chat_id);
      bindText(stmt.get(), 2, message.msg_id);
      bindText(stmt.get(), 3, message.sender_device);
      bindInt64(stmt.get(), 4, message.ts_ms);
      bindInt(stmt.get(), 5, static_cast<int>(sealed.algorithm));
      bindBlob(stmt.get(), 6, sealed.nonce);
      bindBlob(stmt.get(), 7, sealed.blob);
      bindBlob(stmt.get(), 8, sealed.tag);
      bindInt(stmt.get(), 9, message.delivered ? 1 : 0);
      bindInt(stmt.get(), 10, message.acked ? 1 : 0);
      bindInt64(stmt.get(), 11, index);
      if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("sqlite insert message failed");
      }
    }
    {
      Statement stmt(db_->db,
                     "INSERT INTO chats(chat_id, last_index, updated_at_ms) VALUES(?, ?, ?)"
                     " ON CONFLICT(chat_id) DO UPDATE SET last_index = MAX(last_index, excluded.last_index), updated_at_ms = excluded.updated_at_ms;");
      bindText(stmt.get(), 1, message.chat_id);
      bindInt64(stmt.get(), 2, index);
      bindInt64(stmt.get(), 3, message.ts_ms);
      if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error("sqlite upsert chat failed");
      }
    }
    db_->exec("COMMIT;");
  } catch (...) {
    db_->exec("ROLLBACK;");
    throw;
  }
}

std::vector<std::pair<int64_t, std::string>> Storage::recentMessageIds(const std::string& chat_id,
                                                                       size_t window) const {
  if (!db_) {
    throw std::runtime_error("storage not open");
  }
  std::vector<std::pair<int64_t, std::string>> out;
  Statement stmt(db_->db,
                 "SELECT idx, msg_id FROM messages WHERE chat_id = ? ORDER BY idx DESC LIMIT ?;");
  bindText(stmt.get(), 1, chat_id);
  bindInt64(stmt.get(), 2, static_cast<int64_t>(window));
  while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
    int64_t idx = columnInt64(stmt.get(), 0);
    std::string msg_id = columnText(stmt.get(), 1);
    out.emplace_back(idx, msg_id);
  }
  std::reverse(out.begin(), out.end());
  return out;
}

}
