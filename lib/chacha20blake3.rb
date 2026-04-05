# frozen_string_literal: true

require_relative "chacha20blake3/chacha20blake3"
require_relative "chacha20blake3/version"

module ChaCha20Blake3
  def self.generate_key_and_nonce
    [generate_key, generate_nonce]
  end
end
