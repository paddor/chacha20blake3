# Changelog

## 0.3.0 — 2026-06-09

### Changed

- **Breaking:** `Stream` class replaced by `Session` class. `Session`
  wraps the upstream chacha20-blake3 v0.10.0 `Session20` type: pre-derived
  encryption and authentication keys with a continuous ChaCha20 block
  counter, eliminating the per-message BLAKE3 KDF cost.
  - `Session.new(enc_key, auth_key, nonce)` (3 args: 32-byte encryption
    key, 32-byte authentication key, 8-byte nonce) replaces
    `Stream.new(key, nonce)` (2 args: 32-byte key, 24-byte nonce).
  - `#block_counter` replaces `#message_index`.
- Upstream dependency changed from git rev to `chacha20-blake3 = "0.10.0"`
  (crates.io).

### Added

- `SESSION_NONCE_SIZE` constant (8).

## 0.2.0 — 2026-04-07

### Added

- `ChaCha20Blake3.derive_key(context, material, length:)` — BLAKE3 KDF with
  configurable output length (default 32, max 65535).

## 0.1.0

Initial release.

- ChaCha20-BLAKE3 AEAD encryption via Rust native extension (rb_sys/magnus)
- `Cipher` class with `#encrypt`, `#decrypt`, `#encrypt_detached`, `#decrypt_detached`
- `Stream` class with automatic nonce management, thread-safe (Mutex-protected counter)
- Counter exhaustion check (raises after 2^64 messages to prevent nonce reuse)
- AAD (associated data) support on all encrypt/decrypt methods
- Generated keys and nonces are frozen to prevent accidental mutation
- No output allocation on failed MAC verification (DoS resistance)
- 2-copy FFI path using `encrypt_in_place_detached` and pre-allocated Ruby strings
- SIMD-accelerated on x86-64 (AVX2/AVX-512) and ARM (NEON/SVE)
- Compiled with `-C target-cpu=native` as workaround for upstream missing `#[target_feature]` annotations (see [upstream PR #12](https://github.com/skerkour/chacha20-blake3/pull/12))
