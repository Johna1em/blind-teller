//! Sealing: how a browser hands secrets to the enclave.
//!
//! X25519 + HKDF-SHA256 + ChaCha20-Poly1305, with associated data that ties a
//! ciphertext to one purpose. Wire format, base64:
//!   `0x01 | ephemeral_public(32) | nonce(12) | ciphertext+tag`
//!
//! `web/src/lib/seal.ts` implements the same format, and
//! `fixtures/seal-vector.json` holds them together.

use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const VERSION: u8 = 1;
const INFO: &[u8] = b"blind-teller/v1/seal";
const HEADER: usize = 1 + 32 + 12;

fn derive(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> [u8; 32] {
    // Both public keys go in the salt, so a key is bound to this exact exchange.
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared).expand(INFO, &mut key).expect("32 bytes is a valid length");
    key
}

pub fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Seal `plain` to `recipient`. `entropy` supplies the ephemeral key and nonce.
pub fn seal(recipient: &[u8; 32], plain: &[u8], aad: &[u8], entropy: &[u8; 44]) -> Result<String, &'static str> {
    let ephemeral = StaticSecret::from(<[u8; 32]>::try_from(&entropy[..32]).unwrap());
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient));
    if !shared.was_contributory() {
        return Err("seal_bad_recipient");
    }
    let key = derive(shared.as_bytes(), &ephemeral_public, recipient);
    let nonce = &entropy[32..];
    let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| "seal_failed")?;
    let mut out = Vec::with_capacity(HEADER + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(STANDARD.encode(out))
}

/// Open a sealed blob. Any failure is the same failure: an attacker learns
/// nothing from which step refused.
pub fn open(secret: &[u8; 32], sealed: &str, aad: &[u8]) -> Result<Vec<u8>, &'static str> {
    let raw = STANDARD.decode(sealed.trim()).map_err(|_| "bad_ciphertext")?;
    if raw.len() < HEADER + 16 || raw[0] != VERSION {
        return Err("bad_ciphertext");
    }
    let ephemeral: [u8; 32] = raw[1..33].try_into().unwrap();
    let secret = StaticSecret::from(*secret);
    let recipient = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
    if !shared.was_contributory() {
        return Err("bad_ciphertext");
    }
    let key = derive(shared.as_bytes(), &ephemeral, &recipient);
    ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(Nonce::from_slice(&raw[33..45]), Payload { msg: &raw[45..], aad })
        .map_err(|_| "bad_ciphertext")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [5u8; 32];
    const ENTROPY: [u8; 44] = [9u8; 44];

    #[test]
    fn a_sealed_message_opens() {
        let s = seal(&public_of(&SECRET), b"hello", b"order:1", &ENTROPY).unwrap();
        assert_eq!(open(&SECRET, &s, b"order:1").unwrap(), b"hello");
    }

    #[test]
    fn a_ciphertext_cannot_move_to_another_order() {
        let s = seal(&public_of(&SECRET), b"hello", b"order:1", &ENTROPY).unwrap();
        assert_eq!(open(&SECRET, &s, b"order:2").unwrap_err(), "bad_ciphertext");
    }

    #[test]
    fn the_wrong_key_cannot_open() {
        let s = seal(&public_of(&SECRET), b"hello", b"a", &ENTROPY).unwrap();
        assert!(open(&[6u8; 32], &s, b"a").is_err());
    }

    #[test]
    fn a_flipped_bit_is_refused() {
        let s = seal(&public_of(&SECRET), b"hello", b"a", &ENTROPY).unwrap();
        let mut raw = STANDARD.decode(&s).unwrap();
        *raw.last_mut().unwrap() ^= 1;
        assert!(open(&SECRET, &STANDARD.encode(raw), b"a").is_err());
    }

    #[test]
    fn garbage_is_refused() {
        assert!(open(&SECRET, "not base64!", b"a").is_err());
        assert!(open(&SECRET, "AAAA", b"a").is_err());
    }

    #[test]
    fn low_order_keys_are_refused() {
        assert_eq!(seal(&[0u8; 32], b"x", b"a", &ENTROPY).unwrap_err(), "seal_bad_recipient");
    }

    /// Regenerates the vector the browser's sealing code is tested against.
    #[test]
    fn seal_vector_matches_the_committed_file() {
        let recipient = public_of(&SECRET);
        let s = seal(&recipient, b"blind teller seal vector", b"aad", &ENTROPY).unwrap();
        let v = serde_json::json!({
            "recipient_secret": hex::encode(SECRET), "recipient_public": hex::encode(recipient),
            "entropy": hex::encode(ENTROPY), "plaintext": "blind teller seal vector", "aad": "aad", "sealed": s,
        });
        let text = serde_json::to_string_pretty(&v).unwrap() + "\n";
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/seal-vector.json");
        match std::fs::read_to_string(path) {
            Ok(existing) => assert_eq!(existing.replace("\r\n", "\n"), text),
            Err(_) => std::fs::write(path, text).unwrap(),
        }
    }
}
