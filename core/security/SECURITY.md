# Security & Hardening (Phase 7)

## Scope
This document is the single source of truth for core security hardening, threat model assumptions, revocation flow, and automated security checks.

## Threat Model
- Adversary can observe network traffic and attempt replay or injection.
- Malicious peers may send malformed frames or protocol violations.
- Local disk may be captured; at-rest data must remain encrypted.
- Devices can be compromised and must be revocable by trusted peers.

Non-goals:
- A fully compromised OS or kernel.
- Side-channel attacks beyond constant-time cryptographic primitives.

## Key Handling Requirements
- RNG: OS CSPRNG only (RAND_bytes, platform CSPRNG). No custom RNG.
- Zeroization: secrets are cleared after use or when no longer needed.
- At-rest keys are wrapped by OS keystore; database payloads are AEAD sealed.
- Key material should be mlocked where supported.

## Device Revocation Format
Payload (binary, little-endian):
- version (u8) = 1
- device_id (32 bytes, SHA-256 of device Ed25519 public key)
- revoked_at_ms (i64, Unix epoch millis)
- signature (64 bytes, Ed25519)

Signature input:
- context string: "p2pchat.revocation.v1"
- version (u8)
- device_id (32 bytes)
- revoked_at_ms (u64, little-endian)

Validation rules:
- Signature must verify against the sender’s identity Ed25519 public key.
- If the target device is known, the signer identity must match the target identity.
- On success, store revocation and drop sessions/outbox for the revoked device.

## Hardening Checklist
- AEAD with header AAD for all frames.
- Replay protection via session counter checks.
- Strict size checks for parsing.
- Encrypted-at-rest storage for messages, sessions, and prekeys.
- No telemetry, no plaintext metadata storage beyond required indices.

## Automated Security Tests
- Static analysis for banned calls in core/crypto and core/identity:
  - rand(), srand(), random_device, drand48, lrand48, RAND_pseudo_bytes
  - MD5, SHA1, or other deprecated hashes
- Frame parsing fuzz test must exercise decode paths with random data and never crash.

## Manual Verification
- Confirm zeroization paths in X3DH and ratchet teardown.
- Validate revoke-device flow: publish revocation, verify signature, drop sessions, block new handshakes.
