# frozen_string_literal: true

$stdout.sync = true

require "chacha20blake3"
require "openssl"

SIZES = {
  "64 B"   =>         64,
  "256 B"  =>        256,
  "1 KB"   =>      1_024,
  "4 KB"   =>      4_096,
  "64 KB"  =>     65_536,
  "256 KB" =>    262_144,
  "1 MB"   =>  1_048_576,
}.freeze

MIN_SECONDS = 1.0

def measure(bytes, &block)
  n = [1, (200_000 / [bytes, 1].max)].max
  n = [n, 5_000_000].min

  block.call

  loop do
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    n.times(&block)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0

    return [elapsed / n, n, elapsed] if elapsed >= MIN_SECONDS

    n = [(n * MIN_SECONDS / [elapsed, 0.001].max * 1.1).ceil, n * 8].min
  end
end

def throughput_str(bytes, seconds)
  mbps = bytes.to_f / seconds / 1_000_000
  if mbps >= 1000
    format("%.2f GB/s", mbps / 1000)
  elsif mbps >= 1
    format("%.1f MB/s", mbps)
  else
    format("%.1f KB/s", mbps * 1000)
  end
end

# -- ChaCha20-BLAKE3 setup --
cc_key    = ChaCha20Blake3.generate_key
cc_nonce  = ChaCha20Blake3.generate_nonce
cc_cipher = ChaCha20Blake3::Cipher.new(cc_key)

# -- OpenSSL helper --
def ossl_encrypt(cipher_name, key, iv, plaintext)
  c = OpenSSL::Cipher.new(cipher_name)
  c.encrypt
  c.key = key
  c.iv = iv
  ct = c.update(plaintext) + c.final
  tag = c.auth_tag
  [ct, tag]
end

def ossl_decrypt(cipher_name, key, iv, ciphertext, tag)
  c = OpenSSL::Cipher.new(cipher_name)
  c.decrypt
  c.key = key
  c.iv = iv
  c.auth_tag = tag
  c.update(ciphertext) + c.final
end

# -- AES-256-GCM setup --
aes_key = OpenSSL::Random.random_bytes(32)
aes_iv  = OpenSSL::Random.random_bytes(12)

# -- ChaCha20-Poly1305 setup --
cp_key = OpenSSL::Random.random_bytes(32)
cp_iv  = OpenSSL::Random.random_bytes(12)

puts "ChaCha20-BLAKE3 vs ChaCha20-Poly1305 (OpenSSL) vs AES-256-GCM (OpenSSL)"
puts "Ruby #{RUBY_VERSION} / #{RUBY_PLATFORM}"
puts

header = format("%-8s %15s %15s %15s %15s %15s %15s", "Size",
  "CC20-B3 enc", "CC20-P1305 enc", "AES-GCM enc",
  "CC20-B3 dec", "CC20-P1305 dec", "AES-GCM dec")
puts header
puts "-" * header.size

SIZES.each do |label, size|
  $stderr.print "#{label}... "

  plaintext = Random.bytes(size)

  cc_ct = cc_cipher.encrypt(cc_nonce, plaintext)
  cp_ct, cp_tag = ossl_encrypt("chacha20-poly1305", cp_key, cp_iv, plaintext)
  aes_ct, aes_tag = ossl_encrypt("aes-256-gcm", aes_key, aes_iv, plaintext)

  cc_enc, = measure(size) { cc_cipher.encrypt(cc_nonce, plaintext) }
  cp_enc, = measure(size) { ossl_encrypt("chacha20-poly1305", cp_key, cp_iv, plaintext) }
  aes_enc, = measure(size) { ossl_encrypt("aes-256-gcm", aes_key, aes_iv, plaintext) }

  cc_dec, = measure(size) { cc_cipher.decrypt(cc_nonce, cc_ct) }
  cp_dec, = measure(size) { ossl_decrypt("chacha20-poly1305", cp_key, cp_iv, cp_ct, cp_tag) }
  aes_dec, = measure(size) { ossl_decrypt("aes-256-gcm", aes_key, aes_iv, aes_ct, aes_tag) }

  puts format("%-8s %15s %15s %15s %15s %15s %15s",
    label,
    throughput_str(size, cc_enc),
    throughput_str(size, cp_enc),
    throughput_str(size, aes_enc),
    throughput_str(size, cc_dec),
    throughput_str(size, cp_dec),
    throughput_str(size, aes_dec))

  $stderr.puts "done"
end
