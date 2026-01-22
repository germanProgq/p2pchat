Crypto + Ratchet Spec (SOT)

Version
- ProtocolVersion: 1
- Ciphersuite: X25519, Ed25519, HKDF-SHA256, HMAC-SHA256, AEAD (ChaCha20-Poly1305 or AES-256-GCM)

Key Types
- Identity signing key: Ed25519 (seed + public)
- Identity DH key: X25519 (private + public)
- Signed prekey: X25519 keypair signed by Ed25519 identity
- One-time prekey: X25519 keypair
- Ratchet key: X25519 keypair

PreKeyBundle (public)
Fields:
- version (u32)
- identity_ed25519_pub (32 bytes)
- identity_x25519_pub (32 bytes)
- signed_prekey_id (u32)
- signed_prekey_pub (32 bytes)
- signed_prekey_signature (64 bytes)
- has_one_time (u8, 0 or 1)
- one_time_prekey_id (u32, 0 if none)
- one_time_prekey_pub (32 bytes, zero if none)
- capabilities (u32 bitset)

Signed PreKey Signature
- signature = Ed25519.Sign(identity_seed, "p2pchat.spk.v1" || signed_prekey_id_le || signed_prekey_pub)
- verify with identity_ed25519_pub

PreKeyMessage (initiator -> responder)
Fields (binary, little-endian for integers):
- version (u8)
- flags (u8) bit0 = has_one_time
- signed_prekey_id (u32)
- one_time_prekey_id (u32, 0 if none)
- capabilities (u32)
- initiator_identity_ed25519_pub (32 bytes)
- initiator_identity_x25519_pub (32 bytes)
- initiator_ephemeral_pub (32 bytes)  [also the initial ratchet public key]

X3DH Shared Secret
Initiator computes:
- DH1 = X25519(initiator_identity_x25519_priv, responder_signed_prekey_pub)
- DH2 = X25519(initiator_ephemeral_priv, responder_identity_x25519_pub)
- DH3 = X25519(initiator_ephemeral_priv, responder_signed_prekey_pub)
- DH4 = X25519(initiator_ephemeral_priv, responder_one_time_prekey_pub) if present
- concat = DH1 || DH2 || DH3 || DH4
- root_key = HKDF-SHA256(salt=0^32, ikm=concat, info="p2pchat.x3dh.root.v1", L=32)
Responder derives the same root_key using its private keys and the initiator PreKeyMessage.

Initial Ratchet State
- Initiator uses:
  - local ratchet key = initiator_ephemeral
  - remote ratchet pub = responder_signed_prekey_pub
  - (root_key, CKs) = KDF_RK(root_key, X25519(local_ratchet_priv, remote_ratchet_pub))
  - CKr is empty until first reply
- Responder uses:
  - local ratchet key = responder_signed_prekey (private key)
  - remote ratchet pub = initiator_ephemeral_pub
  - (root_key, CKr) = KDF_RK(root_key, X25519(local_ratchet_priv, remote_ratchet_pub))
  - CKs is empty until responder sends (it generates a new ratchet key and derives CKs)

Root KDF (KDF_RK)
- input: root_key (32), dh_out (32)
- okm = HKDF-SHA256(salt=root_key, ikm=dh_out, info="p2pchat.ratchet.rk.v1", L=64)
- new_root_key = okm[0..31]
- chain_key = okm[32..63]

Chain KDF (KDF_CK)
- message_key = HMAC-SHA256(chain_key, 0x01)
- next_chain_key = HMAC-SHA256(chain_key, 0x02)

Message Key Expansion
- okm = HKDF-SHA256(salt=empty, ikm=message_key, info="p2pchat.ratchet.msg.v1", L=44)
- aead_key = okm[0..31]
- nonce = okm[32..43] (12 bytes)

Ratchet Header
Binary format (40 bytes):
- dh_pub (32 bytes)
- pn (u32) previous sending chain length
- n (u32) message number in current sending chain

AEAD
- ciphertext = AEAD-Encrypt(aead_key, nonce, plaintext, aad)
- aad = app-provided associated data concatenated with Ratchet Header bytes
- tag size is 16 bytes

Ratchet Step (on new dh_pub)
When a message header dh_pub differs from the stored remote ratchet key:
1) Skip message keys in the current receiving chain up to header.pn
2) PN = Ns; Ns = 0; Nr = 0
3) (root_key, CKr) = KDF_RK(root_key, X25519(current_local_priv, new_remote_pub))
4) Generate new local ratchet key
5) (root_key, CKs) = KDF_RK(root_key, X25519(new_local_priv, new_remote_pub))
6) Set remote ratchet pub = new_remote_pub

Skipped Message Keys
- Store skipped message keys by (dh_pub, n)
- MaxSkip default: 2000; exceeding it is a protocol error
- If a skipped key exists for an incoming header, decrypt with it and delete it
- If a header uses a previously seen dh_pub and no skipped key is present, reject as out-of-window

Security
- All randomness uses OS CSPRNG via OpenSSL RAND_bytes
- Secrets are zeroized on release where feasible (OPENSSL_cleanse)
- No branch-on-secret in application code; rely on vetted primitives
