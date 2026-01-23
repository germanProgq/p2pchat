End-to-End P2P Flow (Phase 6 SSOT)

Scope
- Two devices establish a secure session, exchange messages, handle disconnects, and resync history.
- Transport is abstracted; LoopbackTransport is acceptable for headless tests.

Roles
- Device A: initiator that adds Device B using a prekey bundle.
- Device B: responder that accepts the handshake and decrypts messages.

Flow
1) Identity and storage initialization
   - Each device opens its identity store and storage database with a master key.
   - Prekeys exist or are generated and stored before any handshake.

2) Link and handshake
   - Device B exposes a PreKeyBundle (beginLink or direct bundle retrieval).
   - Device A calls addContact(bundle) to create a pending session and handshake payload.
   - A transport connection is established between A and B.
   - Device A sends a handshake init frame containing session_id and prekey message.
   - Device B validates the prekey message, creates the responder ratchet, stores the session, and replies with an ack frame.
   - Device A marks the peer Ready on successful ack.

3) Message exchange
   - Device A sends an APP_MSG frame; payload includes chat_id, msg_id, timestamp, content_type, and ratchet header bytes.
   - Device B decrypts the ratchet message, stores plaintext in its encrypted message store, and emits onMessage.
   - Device B returns an ACK frame; Device A marks the message as acked.

4) Disconnect and offline send
   - Transport reports Disconnected; sessions remain persisted.
   - While offline, Device A can send messages; frames are enqueued in outbox with retry scheduling.
   - The outbox is flushed on reconnect or on explicit ticks.

5) Reconnect and history resync
   - Transport reconnects and notifies both peers.
   - Each side sends SYNC_HELLO for known chats with last_index and Bloom filter.
   - The peer computes missing ranges and sends SYNC_CHUNK batches with stored ratchet bytes.
   - Receivers decrypt, upsert messages at their original indices, and emit onMessage.
   - SYNC_ACK is sent per chunk.
   - Any queued outbox frames are flushed after reconnect.

6) Verification expectations
   - Both devices end with identical chat history for the shared chat_id.
   - Messages sent while offline are present after reconnect with correct ordering and ack state.
   - No duplicate messages are stored or emitted.
