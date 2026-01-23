# RN Bridge Spec

This document is the single source of truth for the React Native bridge surface.

## Methods

### start(nodeConfig)
Boots the core and opens storage. Required fields:
- identityPath (string): filesystem path to identity blob.
- storagePath (string): filesystem path to SQLite storage.
- schemaPath (string): filesystem path to schema.sql.

Optional fields:
- masterKey (Uint8Array, 32 bytes): overrides OS keystore for tests.
- transportKind (string): "quic" | "webrtc" | "loopback".
- transport (object): { maxInFlight, maxQueueBytes, retry }.
- retry (object): { baseDelayMs, maxDelayMs, maxAttempts, jitterRatio }.
- quic (object): { bindAddress, bindPort, maxDatagramSize, ice }.
- webrtc (object): { bindAddress, bindPort, maxDatagramSize, ice }.
- ice (object): { stunServers, bindAddress, bindPort, timeoutMs, relayCandidates }.
- relayCandidates (array): entries of { type, address, port, priority }.
- oneTimePrekeys (number).
- signedPrekeyId (number).
- oneTimeStartId (number).
- handshakeBaseDelayMs (number).
- handshakeMaxDelayMs (number).
- handshakeMaxAttempts (number).

### addContact(prekeyBundle)
Adds a contact and starts the handshake.
- prekeyBundle (Uint8Array): serialized prekey bundle.
- Returns: peerId (string).

Prekey bundle encoding (little-endian integers):
- version (u8, current = 2)
- hasOneTime (u8)
- capabilities (u32)
- identityEd25519 (32 bytes)
- deviceEd25519 (32 bytes)
- identityX25519 (32 bytes)
- signedPrekeyId (u32)
- signedPrekeyPublic (32 bytes)
- signedPrekeySignature (64 bytes)
- if hasOneTime == 1:
  - oneTimePrekeyId (u32)
  - oneTimePrekeyPublic (32 bytes)

### send(chatId, payload)
Sends a message to a chat.
- chatId (string).
- payload (string | Uint8Array): string implies UTF-8 text; Uint8Array implies binary.

### getHistory(chatId, cursor, limit)
Returns message history.
- chatId (string).
- cursor (number): start index (inclusive).
- limit (number).
- Returns: array of history messages.

### linkDevice(linkCode)
Links a device using a link code string.

## Events

### onMessage
Payload:
- chatId (string)
- msgId (string)
- senderDevice (string)
- tsMs (number)
- contentType (string): "text" | "binary"
- body (Uint8Array)

### onConnectionChange
Payload:
- peerId (string)
- state (string): "disconnected" | "connecting" | "connected"

### onPeerStatus
Payload:
- peerId (string)
- status (string): "pending" | "ready" | "failed"

### onError
Payload:
- peerId (string)
- message (string)
