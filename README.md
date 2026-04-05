# ChaCha20Blake3

[![CI](https://github.com/paddor/chacha20blake3/actions/workflows/ci.yml/badge.svg)](https://github.com/paddor/chacha20blake3/actions/workflows/ci.yml)
[![Gem Version](https://img.shields.io/gem/v/chacha20blake3?color=e9573f)](https://rubygems.org/gems/chacha20blake3)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Warning:** This gem is not maintained by cryptographers. The author is not a
> cryptographer. It has not been independently audited. For production use where
> proven, audited libraries matter, consider [RbNaCl](https://github.com/RubyCrypto/rbnacl)
> (XChaCha20-Poly1305) or another gem from [RubyCrypto](https://github.com/RubyCrypto).
>
> This gem exists because no Ruby binding for ChaCha20-BLAKE3 existed yet. If
> RbNaCl adds ChaCha20-BLAKE3 support, or this gem is transferred to
> [RubyCrypto](https://github.com/RubyCrypto), this warning will be removed.

Fast, paranoia-grade authenticated encryption for Ruby -- no NIST primitives, no hardware AES requirement.

This gem wraps the [`chacha20-blake3`](https://github.com/skerkour/chacha20-blake3) Rust crate via a native Rust extension ([magnus](https://github.com/matsadler/magnus)). The underlying cipher combines:

- **ChaCha20** stream cipher (DJB, RFC 8439)
- **BLAKE3** as the authentication MAC

SIMD-accelerated on every major architecture:
| Platform | Acceleration |
|----------|-------------|
| x86-64   | AVX2, AVX-512 |
| ARM64    | NEON, SVE |
| Generic  | Pure Rust fallback |

No AES-NI, no hardware crypto instructions, no NIST curves. Pure DJB crypto all the way down.

## Why ChaCha20 + BLAKE3?

- **No NIST influence** - avoids AES (backdoor concerns), P-256/P-384 (nothing-up-my-sleeve suspicion), SHA-2 (NSA design)
- **Hardware-agnostic** - fast on any CPU, not just ones with AES-NI
- **Embedded-friendly** - small code size, no hardware requirements
- **Modern MAC** - BLAKE3 is faster than Poly1305 on larger payloads and provides 256-bit tags vs 128-bit

## Installation

Add to your Gemfile:

```ruby
gem "chacha20blake3"
```

Or install directly:

```sh
gem install chacha20blake3
```

Building from source requires a Rust toolchain (`rustup.rs`).

## Quick Start

```ruby
require "chacha20blake3"

# Generate a random key and nonce
key   = ChaCha20Blake3.generate_key    # 32 bytes, CSPRNG
nonce = ChaCha20Blake3.generate_nonce  # 24 bytes, CSPRNG

cipher = ChaCha20Blake3::Cipher.new(key)

# Encrypt - returns ciphertext with tag appended (last 32 bytes)
ciphertext = cipher.encrypt(nonce, "Hello, world!")

# Decrypt - raises ChaCha20Blake3::DecryptionError on authentication failure
plaintext = cipher.decrypt(nonce, ciphertext)
# => "Hello, world!" (Encoding::BINARY)
```

### With Associated Data (AAD)

AAD is authenticated but not encrypted. Use it to bind ciphertext to context
(e.g., a session ID, record ID, version header):

```ruby
aad = "user_id=42,version=1"

ct = cipher.encrypt(nonce, plaintext, aad: aad)
pt = cipher.decrypt(nonce, ct, aad: aad)

# Wrong AAD raises DecryptionError
cipher.decrypt(nonce, ct, aad: "tampered")  # => raises!
```

### Detached Tag

Store the 32-byte authentication tag separately from the ciphertext:

```ruby
ct, tag = cipher.encrypt_detached(nonce, plaintext, aad: aad)

# ct and tag can be stored/transmitted separately
pt = cipher.decrypt_detached(nonce, ct, tag, aad: aad)
```

## API Reference

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ChaCha20Blake3::KEY_SIZE`   | `32` | Key length in bytes |
| `ChaCha20Blake3::NONCE_SIZE` | `24` | Nonce length in bytes |
| `ChaCha20Blake3::TAG_SIZE`   | `32` | Authentication tag length in bytes |

### Module Methods

#### `ChaCha20Blake3.generate_key -> String`
Returns 32 cryptographically random bytes (BINARY encoding). Uses the OS CSPRNG (`getrandom(2)` on Linux, `BCryptGenRandom` on Windows).

#### `ChaCha20Blake3.generate_nonce -> String`
Returns 24 cryptographically random bytes (BINARY encoding).

#### `ChaCha20Blake3.generate_key_and_nonce -> [key, nonce]`
Convenience wrapper returning `[generate_key, generate_nonce]`.

### `ChaCha20Blake3::Cipher`

#### `.new(key) -> Cipher`
Creates a cipher with the given 32-byte key (BINARY String). Raises `ArgumentError` if the key is not exactly 32 bytes.

#### `#encrypt(nonce, plaintext, aad: "") -> String`
Encrypts `plaintext` and returns a BINARY String containing the ciphertext followed by the 32-byte authentication tag. `nonce` must be exactly 24 bytes.

Output length: `plaintext.bytesize + 32`

#### `#decrypt(nonce, ciphertext, aad: "") -> String`
Decrypts and authenticates `ciphertext` (which must include the 32-byte tag). Returns the plaintext as a BINARY String, or raises `ChaCha20Blake3::DecryptionError` if authentication fails.

#### `#encrypt_detached(nonce, plaintext, aad: "") -> [ciphertext, tag]`
Encrypts `plaintext`, returning ciphertext and the 32-byte tag as separate BINARY Strings.

#### `#decrypt_detached(nonce, ciphertext, tag, aad: "") -> String`
Decrypts and authenticates using a separately-provided 32-byte tag. Raises `ChaCha20Blake3::DecryptionError` on failure.

### Thread Safety

Both `Cipher` and `Stream` instances are safe to share across threads (and
Ractors).

`Cipher` is stateless (it only holds the key), so concurrent calls are safe
by nature. The caller is responsible for never reusing a nonce.

`Stream` holds an internal counter that determines the next nonce. All
operations hold a mutex for the duration of encrypt/decrypt, ensuring that no
two threads can encrypt with the same nonce. This is a security invariant,
not just a correctness one: nonce reuse in a stream cipher is catastrophic
(see below).

### `ChaCha20Blake3::DecryptionError < StandardError`
Raised when authentication verification fails during decryption. **Never** use this as a timing oracle - the verification is constant-time.

## Security Notes

### ⚠️ Don't Roll Your Own Protocol

This gem is a raw AEAD cipher, not a secure protocol. If you need encrypted
messaging, file encryption, or transport security, use a proven protocol
library (libsodium's secretstream, Noise Framework, TLS) instead of
combining primitives yourself.

### Nonce Reuse Is Catastrophic

**A (key, nonce) pair must NEVER be used to encrypt two different messages.**

Nonce reuse in a stream cipher destroys confidentiality: an attacker who sees two ciphertexts encrypted with the same (key, nonce) can XOR them together, cancelling the keystream and recovering the XOR of the two plaintexts. If either plaintext has known structure (and it usually does), both are recoverable.

Safe nonce strategies:
- Use `generate_nonce` for each message (24-byte nonces make accidental collision astronomically unlikely)
- Use a counter-based nonce with a single long-lived key
- Derive a fresh key per session with a KDF

### Key Management

Keys must be treated as secrets. Use `SecureRandom.bytes(32)` or `ChaCha20Blake3.generate_key` for key generation. Never derive keys from passwords without a proper KDF (Argon2, scrypt, PBKDF2).

### Tag Size

The 32-byte (256-bit) tag provides 128-bit security against forgery (birthday bound). This is double the tag size of AES-GCM (128-bit tag, 64-bit forgery security) and XChaCha20-Poly1305 (128-bit tag, 64-bit forgery security).

### What This Is Not

- Not a key agreement protocol - use X25519 or Noise for key exchange
- Not a password hashing function - use Argon2 for password storage
- Not a digital signature scheme - use Ed25519 for signatures

## Performance

This gem peaks at ~1.27 GB/s encrypt on a 2019 MacBook Pro (i7-9750H, Linux
VM, AVX2). The upstream Rust crate achieves 3+ GB/s on modern hardware (AMD
EPYC 9R45) without the Ruby FFI overhead.

Compared to ChaCha20-Poly1305 and AES-256-GCM via Ruby's OpenSSL bindings
(same machine):

```
Size         CC20-B3 enc  CC20-P1305 enc     AES-GCM enc
---------------------------------------------------------
64 B           62.5 MB/s       25.8 MB/s       29.5 MB/s
1 KB          392.1 MB/s      295.5 MB/s      323.1 MB/s
64 KB          1.15 GB/s       1.40 GB/s       1.90 GB/s
1 MB           1.20 GB/s       1.39 GB/s       1.97 GB/s
```

ChaCha20-BLAKE3 is ~2x faster on small messages (lower per-call overhead).
AES-256-GCM pulls ahead on large messages on CPUs with AES-NI. On CPUs
without AES-NI, ChaCha20-BLAKE3 wins across the board. The tradeoff for
slightly lower bulk throughput is a 256-bit authentication tag (128-bit
forgery security) vs 128-bit tags in Poly1305 and GCM (64-bit forgery
security).

See [benchmarks/README.md](benchmarks/README.md) for the full 64 B - 64 MiB
results.

### Ruby binding overhead

The Ruby bindings use 2 memory copies per operation (down from 3 in a naive
implementation) due to unavoidable data copies across the FFI boundary:

1. **Ruby string -> Rust Vec** - Ruby's GC can relocate string buffers at any
   time, so the plaintext must be copied into Rust-owned memory before
   encryption begins. This copy cannot be eliminated safely.
2. **Encrypt/decrypt in place** - the bindings call `encrypt_in_place_detached`
   directly on the Rust Vec, avoiding the extra allocation that the upstream
   convenience `encrypt()` function would make internally.
3. **Rust Vec -> Ruby string** - after encryption (or successful MAC
   verification on decrypt), the output Ruby string is allocated at the exact
   final size (`str_buf_new`), then filled with a single `cat()` call.

The remaining bottleneck at large sizes (>2 MiB) is L3 cache eviction, not
the FFI overhead.

Run the included benchmarks:

```sh
bundle exec rake bench
```

## Building from Source

```sh
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install gem dependencies
bundle install

# Compile the native extension
bundle exec rake compile

# Run tests
bundle exec rake test

# Run Rust unit tests
bundle exec rake cargo_test

# Lint
bundle exec rake clippy
```

## License

MIT
