# frozen_string_literal: true

require "minitest/autorun"
require "objspace"
require "chacha20blake3"

describe ChaCha20Blake3 do
  describe "constants" do
    it "KEY_SIZE is 32" do
      assert_equal 32, ChaCha20Blake3::KEY_SIZE
    end

    it "NONCE_SIZE is 24" do
      assert_equal 24, ChaCha20Blake3::NONCE_SIZE
    end

    it "TAG_SIZE is 32" do
      assert_equal 32, ChaCha20Blake3::TAG_SIZE
    end
  end

  describe ".generate_key" do
    it "returns 32 bytes" do
      assert_equal 32, ChaCha20Blake3.generate_key.bytesize
    end

    it "returns random bytes each time" do
      refute_equal ChaCha20Blake3.generate_key, ChaCha20Blake3.generate_key
    end

    it "returns BINARY encoding" do
      assert_equal Encoding::BINARY, ChaCha20Blake3.generate_key.encoding
    end

    it "returns a frozen string" do
      assert_predicate ChaCha20Blake3.generate_key, :frozen?
    end
  end

  describe ".generate_nonce" do
    it "returns 24 bytes" do
      assert_equal 24, ChaCha20Blake3.generate_nonce.bytesize
    end

    it "returns random bytes each time" do
      refute_equal ChaCha20Blake3.generate_nonce, ChaCha20Blake3.generate_nonce
    end

    it "returns a frozen string" do
      assert_predicate ChaCha20Blake3.generate_nonce, :frozen?
    end
  end

  describe ".generate_key_and_nonce" do
    it "returns [key, nonce] with correct sizes" do
      key, nonce = ChaCha20Blake3.generate_key_and_nonce
      assert_equal 32, key.bytesize
      assert_equal 24, nonce.bytesize
    end

    it "returns frozen strings" do
      key, nonce = ChaCha20Blake3.generate_key_and_nonce
      assert_predicate key, :frozen?
      assert_predicate nonce, :frozen?
    end
  end

  describe "DecryptionError" do
    it "is a StandardError" do
      assert_operator ChaCha20Blake3::DecryptionError, :<, StandardError
    end
  end
end

describe ChaCha20Blake3::Cipher do
  before do
    @key    = ChaCha20Blake3.generate_key
    @nonce  = ChaCha20Blake3.generate_nonce
    @cipher = ChaCha20Blake3::Cipher.new(@key)
  end

  describe "#encrypt / #decrypt round-trip" do
    it "decrypts back to the original plaintext" do
      pt = "Hello, ChaCha20-BLAKE3!"
      ct = @cipher.encrypt(@nonce, pt)
      assert_equal pt.b, @cipher.decrypt(@nonce, ct)
    end

    it "returns BINARY encoding from encrypt" do
      assert_equal Encoding::BINARY, @cipher.encrypt(@nonce, "test").encoding
    end

    it "returns BINARY encoding from decrypt" do
      ct = @cipher.encrypt(@nonce, "test")
      assert_equal Encoding::BINARY, @cipher.decrypt(@nonce, ct).encoding
    end

    it "returns mutable ciphertext from encrypt" do
      refute_predicate @cipher.encrypt(@nonce, "test"), :frozen?
    end

    it "returns mutable plaintext from decrypt" do
      ct = @cipher.encrypt(@nonce, "test")
      refute_predicate @cipher.decrypt(@nonce, ct), :frozen?
    end

    it "produces ciphertext of plaintext_len + TAG_SIZE" do
      pt = "hello"
      ct = @cipher.encrypt(@nonce, pt)
      assert_equal pt.bytesize + ChaCha20Blake3::TAG_SIZE, ct.bytesize
    end

    it "handles empty plaintext" do
      ct = @cipher.encrypt(@nonce, "")
      assert_equal "".b, @cipher.decrypt(@nonce, ct)
    end

    it "handles 1 MB plaintext" do
      pt = Random.bytes(1_048_576)
      ct = @cipher.encrypt(@nonce, pt)
      assert_equal pt, @cipher.decrypt(@nonce, ct)
    end

    it "handles all 256 byte values" do
      pt = (0..255).map(&:chr).join.b
      ct = @cipher.encrypt(@nonce, pt)
      assert_equal pt, @cipher.decrypt(@nonce, ct)
    end
  end

  describe "AAD (associated data)" do
    it "round-trips with matching AAD" do
      pt = "sensitive payload"
      ct = @cipher.encrypt(@nonce, pt, aad: "context binding")
      assert_equal pt.b, @cipher.decrypt(@nonce, ct, aad: "context binding")
    end

    it "raises DecryptionError on wrong AAD" do
      ct = @cipher.encrypt(@nonce, "payload", aad: "correct aad")
      assert_raises(ChaCha20Blake3::DecryptionError) do
        @cipher.decrypt(@nonce, ct, aad: "wrong aad")
      end
    end

    it "raises DecryptionError when AAD is missing but was used" do
      ct = @cipher.encrypt(@nonce, "payload", aad: "some aad")
      assert_raises(ChaCha20Blake3::DecryptionError) do
        @cipher.decrypt(@nonce, ct)
      end
    end

    it "raises DecryptionError when AAD is added but was not used" do
      ct = @cipher.encrypt(@nonce, "payload")
      assert_raises(ChaCha20Blake3::DecryptionError) do
        @cipher.decrypt(@nonce, ct, aad: "unexpected aad")
      end
    end
  end

  describe "decryption failures" do
    it "raises DecryptionError with wrong key" do
      other_cipher = ChaCha20Blake3::Cipher.new(ChaCha20Blake3.generate_key)
      ct = @cipher.encrypt(@nonce, "secret")
      assert_raises(ChaCha20Blake3::DecryptionError) do
        other_cipher.decrypt(@nonce, ct)
      end
    end

    it "raises DecryptionError with wrong nonce" do
      ct = @cipher.encrypt(@nonce, "secret")
      assert_raises(ChaCha20Blake3::DecryptionError) do
        @cipher.decrypt(ChaCha20Blake3.generate_nonce, ct)
      end
    end

    it "raises DecryptionError on truncated ciphertext" do
      ct = @cipher.encrypt(@nonce, "secret")
      assert_raises(ChaCha20Blake3::DecryptionError) do
        @cipher.decrypt(@nonce, ct[0, ct.bytesize / 2])
      end
    end

    it "raises DecryptionError on bit flip in ciphertext" do
      ct = @cipher.encrypt(@nonce, "secret").dup
      ct.setbyte(0, ct.getbyte(0) ^ 0xFF)
      assert_raises(ChaCha20Blake3::DecryptionError) do
        @cipher.decrypt(@nonce, ct)
      end
    end

    it "raises DecryptionError on bit flip in tag" do
      ct = @cipher.encrypt(@nonce, "secret").dup
      ct.setbyte(-1, ct.getbyte(-1) ^ 0xFF)
      assert_raises(ChaCha20Blake3::DecryptionError) do
        @cipher.decrypt(@nonce, ct)
      end
    end

    it "does not allocate output string on failed MAC (DoS resistance)" do
      size = 1_048_576
      ct = @cipher.encrypt(@nonce, Random.bytes(size))
      tampered = ct.dup
      tampered.setbyte(0, tampered.getbyte(0) ^ 0xFF)

      GC.start
      large_before = ObjectSpace.each_object(String).count { |s| s.bytesize >= size }

      assert_raises(ChaCha20Blake3::DecryptionError) do
        @cipher.decrypt(@nonce, tampered)
      end

      large_after = ObjectSpace.each_object(String).count { |s| s.bytesize >= size }
      assert_equal large_before, large_after,
        "failed MAC verification should not allocate a large output string"
    end
  end

  describe "#encrypt_detached / #decrypt_detached" do
    it "returns [ciphertext, tag]" do
      result = @cipher.encrypt_detached(@nonce, "payload")
      assert_instance_of Array, result
      assert_equal 2, result.length
    end

    it "produces a TAG_SIZE-byte tag" do
      _, tag = @cipher.encrypt_detached(@nonce, "payload")
      assert_equal ChaCha20Blake3::TAG_SIZE, tag.bytesize
    end

    it "round-trips" do
      pt = "detached round-trip test"
      ct, tag = @cipher.encrypt_detached(@nonce, pt)
      assert_equal pt.b, @cipher.decrypt_detached(@nonce, ct, tag)
    end

    it "round-trips with AAD" do
      ct, tag = @cipher.encrypt_detached(@nonce, "payload", aad: "context")
      assert_equal "payload".b, @cipher.decrypt_detached(@nonce, ct, tag, aad: "context")
    end

    it "returns mutable ciphertext, tag, and plaintext" do
      ct, tag = @cipher.encrypt_detached(@nonce, "payload")
      pt = @cipher.decrypt_detached(@nonce, ct, tag)
      refute_predicate ct, :frozen?
      refute_predicate tag, :frozen?
      refute_predicate pt, :frozen?
    end

    it "raises DecryptionError on wrong tag" do
      ct, tag = @cipher.encrypt_detached(@nonce, "payload")
      bad_tag = tag.dup
      bad_tag.setbyte(0, bad_tag.getbyte(0) ^ 0xFF)
      assert_raises(ChaCha20Blake3::DecryptionError) do
        @cipher.decrypt_detached(@nonce, ct, bad_tag)
      end
    end

    it "raises DecryptionError on wrong AAD" do
      ct, tag = @cipher.encrypt_detached(@nonce, "payload", aad: "right")
      assert_raises(ChaCha20Blake3::DecryptionError) do
        @cipher.decrypt_detached(@nonce, ct, tag, aad: "wrong")
      end
    end
  end

  describe "input validation" do
    it "raises ArgumentError when key is too short" do
      assert_raises(ArgumentError) { ChaCha20Blake3::Cipher.new("\x00" * 31) }
    end

    it "raises ArgumentError when key is too long" do
      assert_raises(ArgumentError) { ChaCha20Blake3::Cipher.new("\x00" * 33) }
    end

    it "raises ArgumentError when nonce is too short" do
      ct = @cipher.encrypt(@nonce, "hi")
      assert_raises(ArgumentError) { @cipher.decrypt("\x00" * 23, ct) }
    end

    it "raises ArgumentError when nonce is too long" do
      ct = @cipher.encrypt(@nonce, "hi")
      assert_raises(ArgumentError) { @cipher.decrypt("\x00" * 25, ct) }
    end

    it "raises ArgumentError when detached tag is too short" do
      ct, _tag = @cipher.encrypt_detached(@nonce, "hi")
      assert_raises(ArgumentError) do
        @cipher.decrypt_detached(@nonce, ct, "\x00" * 31)
      end
    end

    it "raises ArgumentError when detached tag is too long" do
      ct, _tag = @cipher.encrypt_detached(@nonce, "hi")
      assert_raises(ArgumentError) do
        @cipher.decrypt_detached(@nonce, ct, "\x00" * 33)
      end
    end
  end
end

describe ChaCha20Blake3::Stream do
  before do
    @key   = ChaCha20Blake3.generate_key
    @nonce = ChaCha20Blake3.generate_nonce
  end

  describe ".new" do
    it "returns a Stream" do
      assert_instance_of ChaCha20Blake3::Stream,
                         ChaCha20Blake3::Stream.new(@key, @nonce)
    end

    it "raises ArgumentError when key is too short" do
      assert_raises(ArgumentError) { ChaCha20Blake3::Stream.new("\x00" * 31, @nonce) }
    end

    it "raises ArgumentError when key is too long" do
      assert_raises(ArgumentError) { ChaCha20Blake3::Stream.new("\x00" * 33, @nonce) }
    end

    it "raises ArgumentError when nonce is too short" do
      assert_raises(ArgumentError) { ChaCha20Blake3::Stream.new(@key, "\x00" * 23) }
    end

    it "raises ArgumentError when nonce is too long" do
      assert_raises(ArgumentError) { ChaCha20Blake3::Stream.new(@key, "\x00" * 25) }
    end
  end

  describe "#message_index" do
    it "starts at zero" do
      s = ChaCha20Blake3::Stream.new(@key, @nonce)
      assert_equal 0, s.message_index
    end

    it "increments on encrypt" do
      s = ChaCha20Blake3::Stream.new(@key, @nonce)
      s.encrypt("a")
      assert_equal 1, s.message_index
      s.encrypt("b")
      assert_equal 2, s.message_index
    end

    it "increments on successful decrypt" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      ct = enc.encrypt("hello")
      assert_equal 0, dec.message_index
      dec.decrypt(ct)
      assert_equal 1, dec.message_index
    end

    it "does not increment on failed decrypt" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      ct = enc.encrypt("hello", aad: "right")
      assert_raises(ChaCha20Blake3::DecryptionError) { dec.decrypt(ct, aad: "wrong") }
      assert_equal 0, dec.message_index
    end
  end

  describe "#encrypt / #decrypt round-trip" do
    it "decrypts a single message" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      pt  = "Hello, Stream!"
      assert_equal pt.b, dec.decrypt(enc.encrypt(pt))
    end

    it "decrypts multiple messages in order" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      messages    = ["first", "second", "third", "fourth", "fifth"]
      ciphertexts = messages.map { |m| enc.encrypt(m) }
      decrypted   = ciphertexts.map { |ct| dec.decrypt(ct) }
      assert_equal messages.map(&:b), decrypted
    end

    it "returns BINARY encoding" do
      s = ChaCha20Blake3::Stream.new(@key, @nonce)
      assert_equal Encoding::BINARY, s.encrypt("test").encoding
    end

    it "returns mutable ciphertext and plaintext" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      ct = enc.encrypt("test")
      pt = dec.decrypt(ct)
      refute_predicate ct, :frozen?
      refute_predicate pt, :frozen?
    end

    it "produces ciphertext of plaintext_len + TAG_SIZE" do
      s  = ChaCha20Blake3::Stream.new(@key, @nonce)
      pt = "hello"
      assert_equal pt.bytesize + ChaCha20Blake3::TAG_SIZE, s.encrypt(pt).bytesize
    end

    it "handles empty message" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      assert_equal "".b, dec.decrypt(enc.encrypt(""))
    end
  end

  describe "AAD per message" do
    it "round-trips with per-message AAD" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      ct1 = enc.encrypt("msg1", aad: "ctx1")
      ct2 = enc.encrypt("msg2", aad: "ctx2")
      assert_equal "msg1".b, dec.decrypt(ct1, aad: "ctx1")
      assert_equal "msg2".b, dec.decrypt(ct2, aad: "ctx2")
    end

    it "raises DecryptionError on wrong AAD" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      ct  = enc.encrypt("payload", aad: "correct")
      assert_raises(ChaCha20Blake3::DecryptionError) { dec.decrypt(ct, aad: "wrong") }
    end
  end

  describe "nonce isolation" do
    it "produces different ciphertexts for the same plaintext" do
      s   = ChaCha20Blake3::Stream.new(@key, @nonce)
      ct1 = s.encrypt("repeat")
      ct2 = s.encrypt("repeat")
      refute_equal ct1, ct2
    end
  end

  describe "order enforcement" do
    it "raises DecryptionError when messages are out of order" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      _ct1 = enc.encrypt("first")
      ct2  = enc.encrypt("second")
      assert_raises(ChaCha20Blake3::DecryptionError) { dec.decrypt(ct2) }
    end

    it "does not advance counter on failed decrypt" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      ct1 = enc.encrypt("first")
      ct2 = enc.encrypt("second")
      assert_raises(ChaCha20Blake3::DecryptionError) { dec.decrypt(ct2) }
      assert_equal "first".b, dec.decrypt(ct1)
    end
  end

  describe "large message" do
    it "round-trips 64 MB" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      pt  = Random.bytes(64 * 1024 * 1024)
      assert_equal pt, dec.decrypt(enc.encrypt(pt))
    end
  end

  describe "integrity" do
    it "raises DecryptionError on bit flip" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      ct  = enc.encrypt("secret").dup
      ct.setbyte(0, ct.getbyte(0) ^ 0xFF)
      assert_raises(ChaCha20Blake3::DecryptionError) { dec.decrypt(ct) }
    end

    it "raises DecryptionError on truncated ciphertext" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      ct  = enc.encrypt("secret")
      assert_raises(ChaCha20Blake3::DecryptionError) { dec.decrypt(ct[0, ct.bytesize / 2]) }
    end

    it "does not allocate output string on failed MAC (DoS resistance)" do
      enc = ChaCha20Blake3::Stream.new(@key, @nonce)
      dec = ChaCha20Blake3::Stream.new(@key, @nonce)
      size = 1_048_576
      ct = enc.encrypt(Random.bytes(size))
      tampered = ct.dup
      tampered.setbyte(0, tampered.getbyte(0) ^ 0xFF)

      GC.start
      large_before = ObjectSpace.each_object(String).count { |s| s.bytesize >= size }

      assert_raises(ChaCha20Blake3::DecryptionError) { dec.decrypt(tampered) }

      large_after = ObjectSpace.each_object(String).count { |s| s.bytesize >= size }
      assert_equal large_before, large_after,
        "failed MAC verification should not allocate a large output string"
    end
  end
end
