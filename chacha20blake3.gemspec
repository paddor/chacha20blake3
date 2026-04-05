# frozen_string_literal: true

require_relative "lib/chacha20blake3/version"

Gem::Specification.new do |spec|
  spec.name          = "chacha20blake3"
  spec.version       = ChaCha20Blake3::VERSION
  spec.authors       = [""]
  spec.email         = [""]

  spec.summary       = "Fast DJB-family authenticated encryption: ChaCha20 + BLAKE3 MAC"
  spec.description   = <<~DESC
    Ruby bindings (via Rust/magnus) for the chacha20-blake3 AEAD cipher.
    256-bit key, 192-bit nonce, 256-bit authentication tag. No NIST primitives.
    SIMD-accelerated on x86-64 (AVX2/AVX-512) and ARM (NEON/SVE).
    Ideal for paranoid security users and embedded systems.
  DESC
  spec.homepage      = "https://github.com/paddor/chacha20blake3"
  spec.license       = "MIT"

  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"]    = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files = Dir[
    "lib/**/*.rb",
    "ext/**/*.{rs,rb}",
    "**/Cargo.toml",
    "Cargo.lock",
    "LICENSE",
    "README.md"
  ]

  spec.require_paths = ["lib"]
  spec.extensions    = ["ext/chacha20blake3/extconf.rb"]

  spec.add_dependency "rb_sys", "~> 0.9"

  spec.add_development_dependency "rake",          "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "minitest",      "~> 5.0"
end
