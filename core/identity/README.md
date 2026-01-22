<!-- SSOT for identity keys, storage, and rotation rules. -->
# Identity and Key Lifecycle (Phase 1)

## Scope
This document is the single source of truth for identity keys, device keys, storage format, and rotation rules in the core identity module.

## Key Types
- Identity key: Ed25519. Long-term user identity. UserID is SHA-256 of the identity public key.
- Device keys: per device Ed25519 (signing) and X25519 (key agreement). DeviceID is SHA-256 of the device Ed25519 public key.

## Storage Location
The identity store is a single encrypted file at a caller-provided path. The CLI defaults to a user data directory.

## Encrypted-at-Rest Policy
- The file is encrypted with AES-256-GCM.
- The file key is derived from a 32-byte master key using HKDF-SHA256.
- The master key is stored in the OS keystore:
  - macOS: Keychain generic password item.
  - Windows: DPAPI-protected blob on disk.
  - Linux: libsecret item.

## File Format (Identity Store)
Binary, little-endian. Header is authenticated as AEAD AAD.

Header:
- magic[8] = "P2PCHAT1"
- version (u32) = 1
- salt[16]
- nonce[12]
- ciphertext_len (u32)

Body (ciphertext, AES-256-GCM):
- payload_version (u32) = 1
- record_version (u32) = 1 (increments on rotation)
- created_at_ms (u64)
- rotated_at_ms (u64)
- active_identity_seed[32]
- has_previous (u8)
- previous_identity_seed[32] (present if has_previous = 1)
- device_count (u32)
- active_device_id[32]
- for each device:
  - device_id[32]
  - device_ed25519_seed[32]
  - device_x25519_private[32]

The public keys are derived from seeds on load; no plaintext public keys are stored.

## Rotation Rules
- Rotation replaces the active identity key with a newly generated Ed25519 key.
- The previous identity key is retained in the store for short-term verification and revocation signing.
- rotated_at_ms is set at rotation time.
- The store version increments on each rotation.

## CLI Manual Test
- Generate a new identity: `identity_cli init --store /path/to/identity.store`
- Export public key: `identity_cli public-key --store /path/to/identity.store`
- Reload and verify: `identity_cli self-test`

## Deterministic Test Vector
Ed25519 test vector uses the RFC 8032 seed:
- seed: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
- public: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
