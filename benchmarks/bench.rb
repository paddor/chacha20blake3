# frozen_string_literal: true

$stdout.sync = true

require "chacha20blake3"

key    = ChaCha20Blake3.generate_key
nonce  = ChaCha20Blake3.generate_nonce
cipher = ChaCha20Blake3::Cipher.new(key)

SIZES = (6..26).map { |n|
  bytes = 1 << n
  label = case bytes
          when 0...1024       then "#{bytes} B"
          when 1024...1024**2 then "#{bytes / 1024} KiB"
          else                     "#{bytes / 1024**2} MiB"
          end
  [label, bytes]
}.to_h.freeze

def human_size(bytes)
  case bytes
  when 0...1024                then "#{bytes} B"
  when 1024...1024**2          then "#{bytes / 1024} KiB"
  when 1024**2...1024**3       then "#{bytes / 1024**2} MiB"
  else                              "#{bytes / 1024**3} GiB"
  end
end

def throughput_str(bytes, seconds)
  mbps = bytes.to_f / seconds / 1_000_000
  if mbps >= 1000
    format("%.2f GB/s", mbps / 1000)
  elsif mbps >= 1
    format("%.1f MB/s", mbps)
  elsif mbps >= 0.001
    format("%.1f KB/s", mbps * 1000)
  else
    format("%.1f B/s", mbps * 1_000_000)
  end
end

MIN_SECONDS = 1.0

def measure(bytes, &block)
  if bytes >= 128 * 1024 * 1024
    block.call
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    block.call
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
    return [elapsed, 1, elapsed]
  end

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

def format_time(seconds)
  case seconds
  when 0...0.000_001     then format("%.1f ns", seconds * 1_000_000_000)
  when 0...0.001         then format("%.1f \u00b5s", seconds * 1_000_000)
  when 0...1             then format("%.2f ms", seconds * 1_000)
  else                        format("%.2f s", seconds)
  end
end

puts "chacha20blake3 #{ChaCha20Blake3::VERSION} benchmarks"
puts "Ruby #{RUBY_VERSION} / #{RUBY_PLATFORM}"
puts
puts format("%-10s %12s %12s %15s %15s", "Size", "Encrypt", "Decrypt", "Enc throughput", "Dec throughput")
puts "-" * 68

SIZES.each do |label, size|
  $stderr.print "#{label}... "

  plaintext  = Random.bytes(size)
  ciphertext = cipher.encrypt(nonce, plaintext)

  enc_time, = measure(size) { cipher.encrypt(nonce, plaintext) }
  dec_time, = measure(size) { cipher.decrypt(nonce, ciphertext) }

  puts format("%-10s %12s %12s %15s %15s",
              label,
              format_time(enc_time),
              format_time(dec_time),
              throughput_str(size, enc_time),
              throughput_str(size, dec_time))

  $stderr.puts "done"
end
