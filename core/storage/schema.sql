-- Storage schema for messages, sessions, prekeys, and outbox. SSOT: core/storage/schema.sql.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS chats (
  chat_id TEXT PRIMARY KEY,
  last_index INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
  peer_id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  identity_ed25519 BLOB NOT NULL,
  device_ed25519 BLOB NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_contacts_updated ON contacts(updated_at_ms);
CREATE INDEX IF NOT EXISTS idx_contacts_username ON contacts(username);

CREATE TABLE IF NOT EXISTS messages (
  chat_id TEXT NOT NULL,
  msg_id TEXT NOT NULL,
  sender_device TEXT NOT NULL,
  ts_ms INTEGER NOT NULL,
  aead_algo INTEGER NOT NULL,
  aead_nonce BLOB NOT NULL,
  aead_blob BLOB NOT NULL,
  aead_tag BLOB NOT NULL,
  delivered INTEGER NOT NULL DEFAULT 0,
  acked INTEGER NOT NULL DEFAULT 0,
  idx INTEGER NOT NULL,
  PRIMARY KEY(chat_id, msg_id),
  UNIQUE(chat_id, idx)
);

CREATE INDEX IF NOT EXISTS idx_messages_chat_idx ON messages(chat_id, idx);
CREATE INDEX IF NOT EXISTS idx_messages_chat_ts ON messages(chat_id, ts_ms);

CREATE TABLE IF NOT EXISTS sessions (
  peer_device TEXT PRIMARY KEY,
  state_algo INTEGER NOT NULL,
  state_nonce BLOB NOT NULL,
  state_blob BLOB NOT NULL,
  state_tag BLOB NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS prekeys (
  id INTEGER PRIMARY KEY,
  public BLOB NOT NULL,
  secret_algo INTEGER NOT NULL,
  secret_nonce BLOB NOT NULL,
  secret_blob BLOB NOT NULL,
  secret_tag BLOB NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  peer_device TEXT NOT NULL,
  session_id BLOB NOT NULL,
  frame_algo INTEGER NOT NULL,
  frame_nonce BLOB NOT NULL,
  frame_blob BLOB NOT NULL,
  frame_tag BLOB NOT NULL,
  next_retry_at_ms INTEGER NOT NULL,
  attempts INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_outbox_retry ON outbox(next_retry_at_ms);

CREATE TABLE IF NOT EXISTS revocations (
  device_id TEXT PRIMARY KEY,
  identity_ed25519 BLOB NOT NULL,
  revoked_at_ms INTEGER NOT NULL,
  signature BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revocations_revoked_at ON revocations(revoked_at_ms);

PRAGMA user_version = 3;
