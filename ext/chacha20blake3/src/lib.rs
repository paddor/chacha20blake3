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
const SESSION_NONCE_SIZE: usize = 8;
const TAG_SIZE: usize = 32;

static DECRYPTION_ERROR: OnceLock<Opaque<ExceptionClass>> = OnceLock::new();

fn decryption_error(ruby: &Ruby) -> ExceptionClass {
    ruby.get_inner(*DECRYPTION_ERROR.get().expect("DecryptionError not initialized"))
}

#[magnus::wrap(class = "ChaCha20Blake3::Cipher", free_immediately, size)]
struct Cipher(chacha20_blake3::ChaCha20Blake3);

// Safety: ChaCha20Blake3 holds only a [u8; 32] key with no interior mutability.
unsafe impl Send for Cipher {}
unsafe impl Sync for Cipher {}

#[magnus::wrap(class = "ChaCha20Blake3::Session", free_immediately, size)]
struct Session {
    inner: Mutex<chacha20_blake3::Session20>,
}

// Safety: Mutex<Session20> provides Send+Sync via interior synchronization.
unsafe impl Send for Session {}
unsafe impl Sync for Session {}

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

fn validate_session_nonce(ruby: &Ruby, nonce: &[u8]) -> Result<[u8; SESSION_NONCE_SIZE], Error> {
    if nonce.len() != SESSION_NONCE_SIZE {
        return Err(Error::new(
            ruby.exception_arg_error(),
            format!(
                "session nonce must be exactly {SESSION_NONCE_SIZE} bytes, got {}",
                nonce.len()
            ),
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

fn session_initialize(
    ruby: &Ruby,
    rb_enc_key: RString,
    rb_auth_key: RString,
    rb_nonce: RString,
) -> Result<Session, Error> {
    let (enc_key, auth_key, nonce) = unsafe {
        (
            validate_key(ruby, rb_enc_key.as_slice())?,
            validate_key(ruby, rb_auth_key.as_slice())?,
            validate_session_nonce(ruby, rb_nonce.as_slice())?,
        )
    };
    rb_enc_key.freeze();
    rb_auth_key.freeze();
    rb_nonce.freeze();
    Ok(Session {
        inner: Mutex::new(chacha20_blake3::Session20::new(enc_key, auth_key, nonce)),
    })
}

fn session_encrypt(ruby: &Ruby, rb_self: &Session, args: &[Value]) -> Result<RString, Error> {
    let parsed = scan_args::<(RString,), (), (), (), RHash, ()>(args)?;
    let (rb_plaintext,) = parsed.required;
    let kw = get_kwargs::<_, (), (Option<RString>,), ()>(parsed.keywords, &[], &["aad"])?;
    let (opt_aad,) = kw.optional;

    let mut session = rb_self.inner.lock().unwrap();

    let (buf, tag) = unsafe {
        let mut buf = rb_plaintext.as_slice().to_vec();
        let aad = opt_aad.as_ref().map_or_else(Vec::new, |s| s.as_slice().to_vec());
        let tag = session.encrypt_in_place_detached(&mut buf, &aad);
        (buf, tag)
    };

    let output = ruby.str_buf_new(buf.len() + TAG_SIZE);
    output.cat(&buf);
    output.cat(&tag);
    Ok(output)
}

fn session_decrypt(ruby: &Ruby, rb_self: &Session, args: &[Value]) -> Result<RString, Error> {
    let parsed = scan_args::<(RString,), (), (), (), RHash, ()>(args)?;
    let (rb_ciphertext,) = parsed.required;
    let kw = get_kwargs::<_, (), (Option<RString>,), ()>(parsed.keywords, &[], &["aad"])?;
    let (opt_aad,) = kw.optional;

    let mut session = rb_self.inner.lock().unwrap();

    let buf = unsafe {
        let mut buf = rb_ciphertext.as_slice().to_vec();
        let aad = opt_aad.as_ref().map_or_else(Vec::new, |s| s.as_slice().to_vec());
        if buf.len() < TAG_SIZE {
            return Err(Error::new(decryption_error(ruby), "decryption failed"));
        }
        let tag_start = buf.len() - TAG_SIZE;
        let tag: [u8; TAG_SIZE] = buf[tag_start..].try_into().unwrap();
        buf.truncate(tag_start);
        session
            .decrypt_in_place_detached(&mut buf, &tag, &aad)
            .map_err(|_| Error::new(decryption_error(ruby), "decryption failed"))?;
        buf
    };

    let output = ruby.str_buf_new(buf.len());
    output.cat(&buf);
    Ok(output)
}

fn session_block_counter(rb_self: &Session) -> u64 {
    rb_self.inner.lock().unwrap().block_counter()
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
    module.const_set("SESSION_NONCE_SIZE", SESSION_NONCE_SIZE as u64)?;
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

    let session_class = module.define_class("Session", ruby.class_object())?;
    session_class.define_singleton_method("new", function!(session_initialize, 3))?;
    session_class.define_method("encrypt",       method!(session_encrypt, -1))?;
    session_class.define_method("decrypt",       method!(session_decrypt, -1))?;
    session_class.define_method("block_counter", method!(session_block_counter, 0))?;

    module.define_module_function("generate_key", function!(generate_key, 0))?;
    module.define_module_function("generate_nonce", function!(generate_nonce, 0))?;
    module.define_module_function("derive_key", function!(blake3_derive_key, -1))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use chacha20_blake3::{ChaCha20Blake3, Session20};

    #[test]
    fn session_multi_message_roundtrip() {
        let enc_key = [0x11u8; 32];
        let auth_key = [0x22u8; 32];
        let nonce = [0x33u8; 8];
        let mut enc = Session20::new(enc_key, auth_key, nonce);
        let mut dec = Session20::new(enc_key, auth_key, nonce);

        let messages: &[&[u8]] = &[b"alpha", b"beta", b"gamma"];
        let ciphertexts: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| enc.encrypt(m, b""))
            .collect();

        for (ct, expected) in ciphertexts.iter().zip(messages.iter()) {
            let pt = dec.decrypt(ct, b"").expect("decrypt failed");
            assert_eq!(pt.as_slice(), *expected);
        }
    }

    #[test]
    fn session_same_message_different_ciphertext() {
        let enc_key = [0x44u8; 32];
        let auth_key = [0x55u8; 32];
        let nonce = [0x66u8; 8];
        let mut session = Session20::new(enc_key, auth_key, nonce);

        let ct1 = session.encrypt(b"repeat", b"");
        let ct2 = session.encrypt(b"repeat", b"");

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn session_block_counter_advances_by_blocks() {
        let enc_key = [0x77u8; 32];
        let auth_key = [0x88u8; 32];
        let nonce = [0x99u8; 8];
        let mut session = Session20::new(enc_key, auth_key, nonce);

        assert_eq!(session.block_counter(), 0);

        // 100 bytes = ceil(100/64) = 2 blocks
        session.encrypt(&[0u8; 100], b"");
        assert_eq!(session.block_counter(), 2);

        // 64 bytes = exactly 1 block
        session.encrypt(&[0u8; 64], b"");
        assert_eq!(session.block_counter(), 3);

        // 0 bytes = 0 blocks
        session.encrypt(b"", b"");
        assert_eq!(session.block_counter(), 3);
    }

    #[test]
    fn session_failed_decrypt_does_not_advance_counter() {
        let enc_key = [0xAAu8; 32];
        let auth_key = [0xBBu8; 32];
        let nonce = [0xCCu8; 8];
        let mut enc = Session20::new(enc_key, auth_key, nonce);
        let mut dec = Session20::new(enc_key, auth_key, nonce);

        let ct = enc.encrypt(b"hello", b"");

        // Tamper with ciphertext
        let mut tampered = ct.clone();
        tampered[0] ^= 0xFF;

        assert!(dec.decrypt(&tampered, b"").is_err());
        assert_eq!(dec.block_counter(), 0);

        // Original still decrypts
        let pt = dec.decrypt(&ct, b"").expect("decrypt failed");
        assert_eq!(pt.as_slice(), b"hello");
    }

    #[test]
    fn session_with_aad() {
        let enc_key = [0xDDu8; 32];
        let auth_key = [0xEEu8; 32];
        let nonce = [0xFFu8; 8];
        let mut enc = Session20::new(enc_key, auth_key, nonce);
        let mut dec = Session20::new(enc_key, auth_key, nonce);

        let ct = enc.encrypt(b"payload", b"header");
        let pt = dec.decrypt(&ct, b"header").expect("decrypt with aad failed");
        assert_eq!(pt.as_slice(), b"payload");
    }

    #[test]
    fn session_wrong_aad_fails() {
        let enc_key = [0x01u8; 32];
        let auth_key = [0x02u8; 32];
        let nonce = [0x03u8; 8];
        let mut enc = Session20::new(enc_key, auth_key, nonce);
        let mut dec = Session20::new(enc_key, auth_key, nonce);

        let ct = enc.encrypt(b"payload", b"correct");
        assert!(dec.decrypt(&ct, b"wrong").is_err());
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
