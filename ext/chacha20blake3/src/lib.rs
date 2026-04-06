use magnus::{
    exception::ExceptionClass,
    function, method,
    prelude::*,
    r_array::RArray,
    r_hash::RHash,
    r_string::RString,
    scan_args::{get_kwargs, scan_args},
    value::{Opaque, Value},
    Error, Ruby,
};
use std::sync::{Mutex, OnceLock};

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 32;

// Opaque<T> is Send+Sync and is designed for storing Ruby values in statics.
static DECRYPTION_ERROR: OnceLock<Opaque<ExceptionClass>> = OnceLock::new();

fn decryption_error(ruby: &Ruby) -> ExceptionClass {
    ruby.get_inner(*DECRYPTION_ERROR.get().expect("DecryptionError not initialized"))
}

#[magnus::wrap(class = "ChaCha20Blake3::Cipher", free_immediately, size)]
struct Cipher(chacha20_blake3::ChaCha20Blake3);

// Safety: ChaCha20Blake3 holds only a [u8; 32] key with no interior mutability.
unsafe impl Send for Cipher {}
unsafe impl Sync for Cipher {}

// No #reset or #rewind method by design: allowing the counter to go backwards
// would silently reuse (key, nonce) pairs, which is catastrophic for a stream cipher.
#[magnus::wrap(class = "ChaCha20Blake3::Stream", free_immediately, size)]
struct Stream {
    cipher:       chacha20_blake3::ChaCha20Blake3,
    nonce_prefix: [u8; 16],
    counter_base: u64,
    counter:      Mutex<u64>,
}

// Safety: all fields are Send. The Mutex<u64> provides interior mutability with
// synchronization, making Stream both Send and Sync (safe for Ractors).
unsafe impl Send for Stream {}
unsafe impl Sync for Stream {}

fn nonce_for_counter(s: &Stream, counter: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(&s.nonce_prefix);
    nonce[16..].copy_from_slice(&s.counter_base.wrapping_add(counter).to_le_bytes());
    nonce
}

fn validate_key(ruby: &Ruby, key: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    if key.len() != KEY_SIZE {
        return Err(Error::new(
            ruby.exception_arg_error(),
            format!("key must be exactly {KEY_SIZE} bytes, got {}", key.len()),
        ));
    }
    Ok(key.try_into().unwrap())
}

fn validate_nonce(ruby: &Ruby, nonce: &[u8]) -> Result<[u8; NONCE_SIZE], Error> {
    if nonce.len() != NONCE_SIZE {
        return Err(Error::new(
            ruby.exception_arg_error(),
            format!("nonce must be exactly {NONCE_SIZE} bytes, got {}", nonce.len()),
        ));
    }
    Ok(nonce.try_into().unwrap())
}

fn validate_tag(ruby: &Ruby, tag: &[u8]) -> Result<[u8; TAG_SIZE], Error> {
    if tag.len() != TAG_SIZE {
        return Err(Error::new(
            ruby.exception_arg_error(),
            format!("tag must be exactly {TAG_SIZE} bytes, got {}", tag.len()),
        ));
    }
    Ok(tag.try_into().unwrap())
}

fn cipher_initialize(ruby: &Ruby, rb_key: RString) -> Result<Cipher, Error> {
    // SAFETY: key bytes are copied into a fixed array before any GC can run.
    let key_arr = unsafe { validate_key(ruby, rb_key.as_slice())? };
    rb_key.freeze();
    Ok(Cipher(chacha20_blake3::ChaCha20Blake3::new(key_arr)))
}

fn cipher_encrypt(ruby: &Ruby, rb_self: &Cipher, args: &[Value]) -> Result<RString, Error> {
    let parsed =
        scan_args::<(RString, RString), (), (), (), RHash, ()>(args)?;
    let (rb_nonce, rb_plaintext) = parsed.required;
    let kw = get_kwargs::<_, (), (Option<RString>,), ()>(
        parsed.keywords,
        &[],
        &["aad"],
    )?;
    let (opt_aad,) = kw.optional;

    // SAFETY: Copy all borrowed bytes before any Ruby allocation.
    let (buf, tag) = unsafe {
        let nonce_arr = validate_nonce(ruby, rb_nonce.as_slice())?;
        let mut buf = rb_plaintext.as_slice().to_vec();
        let aad = opt_aad
            .as_ref()
            .map_or_else(Vec::new, |s| s.as_slice().to_vec());
        let tag = rb_self.0.encrypt_in_place_detached(&nonce_arr, &mut buf, &aad);
        (buf, tag)
    };

    let output = ruby.str_buf_new(buf.len() + TAG_SIZE);
    output.cat(&buf);
    output.cat(&tag);
    Ok(output)
}

fn cipher_decrypt(ruby: &Ruby, rb_self: &Cipher, args: &[Value]) -> Result<RString, Error> {
    let parsed =
        scan_args::<(RString, RString), (), (), (), RHash, ()>(args)?;
    let (rb_nonce, rb_ciphertext) = parsed.required;
    let kw = get_kwargs::<_, (), (Option<RString>,), ()>(
        parsed.keywords,
        &[],
        &["aad"],
    )?;
    let (opt_aad,) = kw.optional;

    // SAFETY: Copy all borrowed bytes before any Ruby allocation.
    let buf = unsafe {
        let nonce_arr = validate_nonce(ruby, rb_nonce.as_slice())?;
        let mut buf = rb_ciphertext.as_slice().to_vec();
        let aad = opt_aad
            .as_ref()
            .map_or_else(Vec::new, |s| s.as_slice().to_vec());
        if buf.len() < TAG_SIZE {
            return Err(Error::new(decryption_error(ruby), "decryption failed"));
        }
        let tag_start = buf.len() - TAG_SIZE;
        let tag: [u8; TAG_SIZE] = buf[tag_start..].try_into().unwrap();
        buf.truncate(tag_start);
        rb_self
            .0
            .decrypt_in_place_detached(&nonce_arr, &mut buf, &tag, &aad)
            .map_err(|_| Error::new(decryption_error(ruby), "decryption failed"))?;
        buf
    };

    let output = ruby.str_buf_new(buf.len());
    output.cat(&buf);
    Ok(output)
}

fn cipher_encrypt_detached(ruby: &Ruby, rb_self: &Cipher, args: &[Value]) -> Result<RArray, Error> {
    let parsed =
        scan_args::<(RString, RString), (), (), (), RHash, ()>(args)?;
    let (rb_nonce, rb_plaintext) = parsed.required;
    let kw = get_kwargs::<_, (), (Option<RString>,), ()>(
        parsed.keywords,
        &[],
        &["aad"],
    )?;
    let (opt_aad,) = kw.optional;

    // SAFETY: Copy all borrowed bytes before any Ruby allocation.
    let (ciphertext, tag) = unsafe {
        let nonce_arr = validate_nonce(ruby, rb_nonce.as_slice())?;
        // Must copy: encrypt_in_place_detached mutates the buffer in place.
        let mut in_out = rb_plaintext.as_slice().to_vec();
        let aad = opt_aad
            .as_ref()
            .map_or_else(Vec::new, |s| s.as_slice().to_vec());
        let tag = rb_self
            .0
            .encrypt_in_place_detached(&nonce_arr, &mut in_out, &aad);
        (in_out, tag)
    };

    let result = ruby.ary_new();
    let ct_str = ruby.str_buf_new(ciphertext.len());
    ct_str.cat(&ciphertext);
    let tag_str = ruby.str_buf_new(TAG_SIZE);
    tag_str.cat(&tag);
    result.push(ct_str)?;
    result.push(tag_str)?;
    Ok(result)
}

fn cipher_decrypt_detached(
    ruby: &Ruby,
    rb_self: &Cipher,
    args: &[Value],
) -> Result<RString, Error> {
    let parsed =
        scan_args::<(RString, RString, RString), (), (), (), RHash, ()>(args)?;
    let (rb_nonce, rb_ciphertext, rb_tag) = parsed.required;
    let kw = get_kwargs::<_, (), (Option<RString>,), ()>(
        parsed.keywords,
        &[],
        &["aad"],
    )?;
    let (opt_aad,) = kw.optional;

    // SAFETY: Copy all borrowed bytes before any Ruby allocation.
    let plaintext = unsafe {
        let nonce_arr = validate_nonce(ruby, rb_nonce.as_slice())?;
        let tag_arr = validate_tag(ruby, rb_tag.as_slice())?;
        let mut in_out = rb_ciphertext.as_slice().to_vec();
        let aad = opt_aad
            .as_ref()
            .map_or_else(Vec::new, |s| s.as_slice().to_vec());
        rb_self
            .0
            .decrypt_in_place_detached(&nonce_arr, &mut in_out, &tag_arr, &aad)
            .map_err(|_| Error::new(decryption_error(ruby), "decryption failed"))?;
        in_out
    };

    let output = ruby.str_buf_new(plaintext.len());
    output.cat(&plaintext);
    Ok(output)
}

fn stream_initialize(ruby: &Ruby, rb_key: RString, rb_nonce: RString) -> Result<Stream, Error> {
    let (key_arr, nonce_arr) = unsafe {
        (validate_key(ruby, rb_key.as_slice())?,
         validate_nonce(ruby, rb_nonce.as_slice())?)
    };
    rb_key.freeze();
    rb_nonce.freeze();
    Ok(Stream {
        cipher:       chacha20_blake3::ChaCha20Blake3::new(key_arr),
        nonce_prefix: nonce_arr[..16].try_into().unwrap(),
        counter_base: u64::from_le_bytes(nonce_arr[16..].try_into().unwrap()),
        counter:      Mutex::new(0),
    })
}

fn stream_encrypt(ruby: &Ruby, rb_self: &Stream, args: &[Value]) -> Result<RString, Error> {
    let parsed = scan_args::<(RString,), (), (), (), RHash, ()>(args)?;
    let (rb_plaintext,) = parsed.required;
    let kw = get_kwargs::<_, (), (Option<RString>,), ()>(parsed.keywords, &[], &["aad"])?;
    let (opt_aad,) = kw.optional;

    // Hold the lock for the entire operation so no two threads can encrypt
    // with the same nonce.
    let mut counter = rb_self.counter.lock().unwrap();

    let (buf, tag) = unsafe {
        let nonce = nonce_for_counter(rb_self, *counter);
        let mut buf = rb_plaintext.as_slice().to_vec();
        let aad = opt_aad.as_ref().map_or_else(Vec::new, |s| s.as_slice().to_vec());
        let tag = rb_self.cipher.encrypt_in_place_detached(&nonce, &mut buf, &aad);
        (buf, tag)
    };
    // Advance counter. Overflow would reuse the initial nonce, which is
    // catastrophic for a stream cipher.
    *counter = counter.checked_add(1).ok_or_else(|| {
        Error::new(
            ruby.exception_runtime_error(),
            "stream counter exhausted (2^64 messages); create a new Stream to continue",
        )
    })?;

    let output = ruby.str_buf_new(buf.len() + TAG_SIZE);
    output.cat(&buf);
    output.cat(&tag);
    Ok(output)
}

fn stream_decrypt(ruby: &Ruby, rb_self: &Stream, args: &[Value]) -> Result<RString, Error> {
    let parsed = scan_args::<(RString,), (), (), (), RHash, ()>(args)?;
    let (rb_ciphertext,) = parsed.required;
    let kw = get_kwargs::<_, (), (Option<RString>,), ()>(parsed.keywords, &[], &["aad"])?;
    let (opt_aad,) = kw.optional;

    // Hold the lock for the entire operation so the counter only advances
    // after successful authentication.
    let mut counter = rb_self.counter.lock().unwrap();

    let buf = unsafe {
        let nonce = nonce_for_counter(rb_self, *counter);
        let mut buf = rb_ciphertext.as_slice().to_vec();
        let aad = opt_aad.as_ref().map_or_else(Vec::new, |s| s.as_slice().to_vec());
        if buf.len() < TAG_SIZE {
            return Err(Error::new(decryption_error(ruby), "decryption failed"));
        }
        let tag_start = buf.len() - TAG_SIZE;
        let tag: [u8; TAG_SIZE] = buf[tag_start..].try_into().unwrap();
        buf.truncate(tag_start);
        rb_self.cipher.decrypt_in_place_detached(&nonce, &mut buf, &tag, &aad)
            .map_err(|_| Error::new(decryption_error(ruby), "decryption failed"))?;
        buf
    };
    // Advance counter only after successful MAC verification.
    *counter = counter.checked_add(1).ok_or_else(|| {
        Error::new(
            ruby.exception_runtime_error(),
            "stream counter exhausted (2^64 messages); create a new Stream to continue",
        )
    })?;

    let output = ruby.str_buf_new(buf.len());
    output.cat(&buf);
    Ok(output)
}

fn stream_message_index(rb_self: &Stream) -> u64 {
    *rb_self.counter.lock().unwrap()
}

fn blake3_derive_key(ruby: &Ruby, args: &[Value]) -> Result<RString, Error> {
    let parsed = scan_args::<(RString, RString), (), (), (), RHash, ()>(args)?;
    let (rb_context, rb_material) = parsed.required;
    let kw = get_kwargs::<_, (), (Option<usize>,), ()>(parsed.keywords, &[], &["length"])?;
    let (opt_length,) = kw.optional;
    let length = opt_length.unwrap_or(32);

    if length == 0 || length > 65535 {
        return Err(Error::new(
            ruby.exception_arg_error(),
            format!("length must be 1..65535, got {length}"),
        ));
    }

    // SAFETY: copy context string before any allocation
    let context = unsafe { std::str::from_utf8(rb_context.as_slice()) }
        .map_err(|_| Error::new(ruby.exception_arg_error(), "context must be valid UTF-8"))?
        .to_owned();

    let mut output_buf = vec![0u8; length];
    unsafe {
        let mut deriver = blake3::Hasher::new_derive_key(&context);
        deriver.update(rb_material.as_slice());
        let mut reader = deriver.finalize_xof();
        reader.fill(&mut output_buf);
    }

    let output = ruby.str_from_slice(&output_buf);
    output.freeze();
    Ok(output)
}


fn generate_key(ruby: &Ruby) -> Result<RString, Error> {
    let mut key = [0u8; KEY_SIZE];
    getrandom::getrandom(&mut key).map_err(|e| {
        Error::new(
            ruby.exception_runtime_error(),
            format!("RNG failure: {e}"),
        )
    })?;
    let s = ruby.str_from_slice(&key);
    s.freeze();
    Ok(s)
}

fn generate_nonce(ruby: &Ruby) -> Result<RString, Error> {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce).map_err(|e| {
        Error::new(
            ruby.exception_runtime_error(),
            format!("RNG failure: {e}"),
        )
    })?;
    let s = ruby.str_from_slice(&nonce);
    s.freeze();
    Ok(s)
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("ChaCha20Blake3")?;

    module.const_set("KEY_SIZE", KEY_SIZE as u64)?;
    module.const_set("NONCE_SIZE", NONCE_SIZE as u64)?;
    module.const_set("TAG_SIZE", TAG_SIZE as u64)?;

    let decryption_error_class =
        module.define_error("DecryptionError", ruby.exception_standard_error())?;
    DECRYPTION_ERROR
        .set(Opaque::from(decryption_error_class))
        .unwrap_or_else(|_| panic!("init called more than once"));

    let cipher_class = module.define_class("Cipher", ruby.class_object())?;
    cipher_class.define_singleton_method("new", function!(cipher_initialize, 1))?;
    cipher_class.define_method("encrypt", method!(cipher_encrypt, -1))?;
    cipher_class.define_method("decrypt", method!(cipher_decrypt, -1))?;
    cipher_class.define_method("encrypt_detached", method!(cipher_encrypt_detached, -1))?;
    cipher_class.define_method("decrypt_detached", method!(cipher_decrypt_detached, -1))?;

    let stream_class = module.define_class("Stream", ruby.class_object())?;
    stream_class.define_singleton_method("new", function!(stream_initialize, 2))?;
    stream_class.define_method("encrypt",       method!(stream_encrypt, -1))?;
    stream_class.define_method("decrypt",       method!(stream_decrypt, -1))?;
    stream_class.define_method("message_index", method!(stream_message_index, 0))?;

    module.define_module_function("generate_key", function!(generate_key, 0))?;
    module.define_module_function("generate_nonce", function!(generate_nonce, 0))?;
    module.define_module_function("derive_key", function!(blake3_derive_key, -1))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{nonce_for_counter, Mutex, Stream};
    use chacha20_blake3::ChaCha20Blake3;

    fn make_stream(key: [u8; 32], nonce: [u8; 24]) -> Stream {
        Stream {
            cipher:       ChaCha20Blake3::new(key),
            nonce_prefix: nonce[..16].try_into().unwrap(),
            counter_base: u64::from_le_bytes(nonce[16..].try_into().unwrap()),
            counter:      Mutex::new(0),
        }
    }

    #[test]
    fn stream_multi_message_roundtrip() {
        let key   = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let enc = make_stream(key, nonce);
        let dec = make_stream(key, nonce);

        let messages: &[&[u8]] = &[b"alpha", b"beta", b"gamma"];
        let ciphertexts: Vec<Vec<u8>> = messages.iter().map(|m| {
            let mut counter = enc.counter.lock().unwrap();
            let n  = nonce_for_counter(&enc, *counter);
            let ct = enc.cipher.encrypt(&n, m, b"");
            *counter += 1;
            ct
        }).collect();

        for (ct, expected) in ciphertexts.iter().zip(messages.iter()) {
            let mut counter = dec.counter.lock().unwrap();
            let n  = nonce_for_counter(&dec, *counter);
            let pt = dec.cipher.decrypt(&n, ct, b"").expect("decrypt failed");
            *counter += 1;
            assert_eq!(pt.as_slice(), *expected);
        }
    }

    #[test]
    fn stream_same_message_different_ciphertext() {
        let key   = [0x33u8; 32];
        let nonce = [0x44u8; 24];
        let s = make_stream(key, nonce);

        let mut counter = s.counter.lock().unwrap();
        let n1 = nonce_for_counter(&s, *counter);
        let ct1 = s.cipher.encrypt(&n1, b"repeat", b"");
        *counter += 1;

        let n2 = nonce_for_counter(&s, *counter);
        let ct2 = s.cipher.encrypt(&n2, b"repeat", b"");

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn stream_nonce_suffix_wraps() {
        // When counter_base is near u64::MAX, the nonce suffix (counter_base + counter)
        // wraps around. This is fine - it's the counter *index* that must never wrap.
        let key   = [0x55u8; 32];
        let mut nonce = [0u8; 24];
        nonce[16..].copy_from_slice(&u64::MAX.to_le_bytes());

        let s = make_stream(key, nonce);
        *s.counter.lock().unwrap() = 1; // counter_base(MAX) + 1 wraps nonce suffix to 0

        let n = nonce_for_counter(&s, *s.counter.lock().unwrap());
        assert_eq!(&n[16..], &0u64.to_le_bytes());
    }

    #[test]
    fn stream_failed_decrypt_does_not_advance_counter() {
        let key   = [0x66u8; 32];
        let nonce = [0x77u8; 24];
        let enc = make_stream(key, nonce);
        let dec = make_stream(key, nonce);

        // Encrypt a message
        let mut enc_counter = enc.counter.lock().unwrap();
        let n = nonce_for_counter(&enc, *enc_counter);
        let ct = enc.cipher.encrypt(&n, b"hello", b"");
        *enc_counter = enc_counter.wrapping_add(1);
        drop(enc_counter);

        // Tamper with ciphertext
        let mut tampered = ct.clone();
        tampered[0] ^= 0xFF;

        // Decrypt should fail
        let mut dec_counter = dec.counter.lock().unwrap();
        let n = nonce_for_counter(&dec, *dec_counter);
        let result = dec.cipher.decrypt(&n, &tampered, b"");
        assert!(result.is_err());
        // Counter must NOT have advanced
        assert_eq!(*dec_counter, 0);

        // Original ciphertext should still decrypt at counter 0
        let n = nonce_for_counter(&dec, *dec_counter);
        let pt = dec.cipher.decrypt(&n, &ct, b"").expect("decrypt failed");
        *dec_counter = dec_counter.wrapping_add(1);
        assert_eq!(pt.as_slice(), b"hello");
    }

    #[test]
    fn round_trip_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let nonce = [0x1bu8; 24];
        let plaintext = b"hello from pure Rust tests";
        let aad = b"binding test";

        let cipher = ChaCha20Blake3::new(key);
        let ct = cipher.encrypt(&nonce, plaintext, aad);
        let pt = cipher.decrypt(&nonce, &ct, aad).expect("decrypt failed");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn round_trip_detached() {
        let key = [0x13u8; 32];
        let nonce = [0x37u8; 24];
        let plaintext = b"detached tag round trip";

        let cipher = ChaCha20Blake3::new(key);
        let mut buf = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(&nonce, &mut buf, b"");
        cipher
            .decrypt_in_place_detached(&nonce, &mut buf, &tag, b"")
            .expect("detached decrypt failed");
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [0xAAu8; 32];
        let key2 = [0xBBu8; 32];
        let nonce = [0x00u8; 24];
        let pt = b"secret";

        let ct = ChaCha20Blake3::new(key1).encrypt(&nonce, pt, b"");
        assert!(ChaCha20Blake3::new(key2).decrypt(&nonce, &ct, b"").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [0xCCu8; 32];
        let nonce = [0x01u8; 24];
        let pt = b"secret";

        let ct = ChaCha20Blake3::new(key).encrypt(&nonce, pt, b"correct aad");
        assert!(ChaCha20Blake3::new(key)
            .decrypt(&nonce, &ct, b"wrong aad")
            .is_err());
    }

    #[test]
    fn empty_plaintext() {
        let key = [0x77u8; 32];
        let nonce = [0x88u8; 24];
        let cipher = ChaCha20Blake3::new(key);
        let ct = cipher.encrypt(&nonce, b"", b"");
        let pt = cipher.decrypt(&nonce, &ct, b"").expect("empty decrypt failed");
        assert!(pt.is_empty());
    }

    #[test]
    fn large_plaintext() {
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 24];
        let plaintext = vec![0xFFu8; 1_048_576];
        let cipher = ChaCha20Blake3::new(key);
        let ct = cipher.encrypt(&nonce, &plaintext, b"");
        let pt = cipher.decrypt(&nonce, &ct, b"").expect("large decrypt failed");
        assert_eq!(pt, plaintext);
    }
}
