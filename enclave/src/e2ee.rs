//! NEAR AI Cloud end-to-end encryption, protocol v3, in pure Rust.
//!
//! Every field is encrypted to the attested model key, so NEAR AI's gateway
//! routes ciphertext it can't read. Nothing else on `wasm32-wasip2` speaks this,
//! and that's why almost no project uses it.
//!
//! Scheme: X25519 (from the model's ed25519 key), HKDF-SHA256 with info
//! `ed25519_encryption`, XChaCha20-Poly1305. v3 binds the reply key and the
//! field name as associated data. Envelope, hex: `eph(32) | nonce(24) | ct+tag`.
//!
//! Tested against NEAR's published vectors (`test-fixtures/e2ee-v3.json` in
//! nearai/inference-sdk), generated with libsodium.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const INFO: &[u8] = b"ed25519_encryption";
const REQUEST_AAD: &[u8] = b"nearai-e2ee-request-v3";
const SUITE_ED25519: u8 = 2;
const PREFIX: usize = 32 + 24;
const TAG: usize = 16;

pub const FIELD_CONTENT: &str = "messages[].content";

fn derive(shared: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared).expand(INFO, &mut key).expect("32 bytes is a valid length");
    key
}

/// The model's X25519 key, converted from its attested ed25519 key.
pub fn model_x25519(ed25519_public: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    let key = VerifyingKey::from_bytes(ed25519_public).map_err(|_| "model_key_invalid")?;
    Ok(key.to_montgomery().to_bytes())
}

/// The per-request reply key. A fresh one for every call, so a captured
/// response can't be opened with a key that lives on.
pub struct ReplyKey {
    public: [u8; 32],
    x25519: StaticSecret,
}

impl ReplyKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        Self { public: signing.verifying_key().to_bytes(), x25519: StaticSecret::from(signing.to_scalar_bytes()) }
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public)
    }

    pub fn request_aad(&self) -> Vec<u8> {
        let mut aad = REQUEST_AAD.to_vec();
        aad.push(SUITE_ED25519);
        aad.extend_from_slice(&self.public);
        aad
    }

    /// Open a response field. Responses carry no associated data.
    pub fn decrypt(&self, ciphertext_hex: &str) -> Result<String, &'static str> {
        if ciphertext_hex.is_empty() {
            return Ok(String::new());
        }
        open_with(&self.x25519, ciphertext_hex, &[])
    }
}

pub fn field_aad(request_aad: &[u8], field: &str) -> Vec<u8> {
    [request_aad, &[0], field.as_bytes()].concat()
}

/// Encrypt one field to the model. `entropy` is the ephemeral secret and nonce.
pub fn encrypt(model_x25519: &[u8; 32], plain: &str, aad: &[u8], entropy: &[u8; 56]) -> Result<String, &'static str> {
    let ephemeral = StaticSecret::from(<[u8; 32]>::try_from(&entropy[..32]).unwrap());
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*model_x25519));
    if !shared.was_contributory() {
        return Err("model_key_invalid");
    }
    let key = derive(shared.as_bytes());
    let nonce = &entropy[32..];
    let ct = XChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plain.as_bytes(), aad })
        .map_err(|_| "e2ee_encrypt_failed")?;
    let mut out = Vec::with_capacity(PREFIX + ct.len());
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(hex::encode(out))
}

fn open_with(secret: &StaticSecret, ciphertext_hex: &str, aad: &[u8]) -> Result<String, &'static str> {
    let raw = hex::decode(ciphertext_hex).map_err(|_| "e2ee_bad_envelope")?;
    if raw.len() < PREFIX + TAG {
        return Err("e2ee_bad_envelope");
    }
    let ephemeral: [u8; 32] = raw[..32].try_into().unwrap();
    let key = derive(secret.diffie_hellman(&PublicKey::from(ephemeral)).as_bytes());
    let plain = XChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(XNonce::from_slice(&raw[32..PREFIX]), Payload { msg: &raw[PREFIX..], aad })
        .map_err(|_| "e2ee_decrypt_failed")?;
    String::from_utf8(plain).map_err(|_| "e2ee_decrypt_failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pasted from nearai/inference-sdk `test-fixtures/e2ee-v3.json`, the suite
    // "Generated independently with cryptography AESGCM and libsodium".
    const MODEL_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const MODEL_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const REPLY_SECRET: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    const REPLY_PUBLIC: &str = "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a";
    const EPHEMERAL: &str = "0303030303030303030303030303030303030303030303030303030303030303";
    const NONCE: &str = "000102030405060708090a0b0c0d0e0f1011121314151617";
    const AAD: &str = "6e65617261692d653265652d726571756573742d76330266be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a006d657373616765735b5d2e636f6e74656e74";
    const PLAINTEXT: &str = "E2EE v3: private prompt";
    const CIPHERTEXT: &str = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22000102030405060708090a0b0c0d0e0f1011121314151617952f1029d9facf0669005cd32fc9f3682f65e17b55d57abc02aeccf35eaabf4b8efe9979121175";

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn the_reply_key_matches_near_ai_vectors() {
        let reply = ReplyKey::from_seed(&h32(REPLY_SECRET));
        assert_eq!(reply.public_hex(), REPLY_PUBLIC);
        assert_eq!(hex::encode(field_aad(&reply.request_aad(), FIELD_CONTENT)), AAD);
    }

    #[test]
    fn encryption_matches_near_ai_vectors_byte_for_byte() {
        let reply = ReplyKey::from_seed(&h32(REPLY_SECRET));
        let aad = field_aad(&reply.request_aad(), FIELD_CONTENT);
        let mut entropy = [0u8; 56];
        entropy[..32].copy_from_slice(&h32(EPHEMERAL));
        entropy[32..].copy_from_slice(&hex::decode(NONCE).unwrap());
        let model = model_x25519(&h32(MODEL_PUBLIC)).unwrap();
        assert_eq!(encrypt(&model, PLAINTEXT, &aad, &entropy).unwrap(), CIPHERTEXT);
    }

    #[test]
    fn the_model_side_can_open_it() {
        // The model holds the ed25519 seed; converting it gives the X25519 key.
        let reply = ReplyKey::from_seed(&h32(REPLY_SECRET));
        let aad = field_aad(&reply.request_aad(), FIELD_CONTENT);
        let model = StaticSecret::from(SigningKey::from_bytes(&h32(MODEL_SECRET)).to_scalar_bytes());
        assert_eq!(open_with(&model, CIPHERTEXT, &aad).unwrap(), PLAINTEXT);
    }

    #[test]
    fn a_response_round_trips_to_the_reply_key() {
        let reply = ReplyKey::from_seed(&h32(REPLY_SECRET));
        let reply_x = PublicKey::from(&reply.x25519).to_bytes();
        let ct = encrypt(&reply_x, "{\"status\":\"success\"}", &[], &[7u8; 56]).unwrap();
        assert_eq!(reply.decrypt(&ct).unwrap(), "{\"status\":\"success\"}");
    }

    #[test]
    fn a_tampered_envelope_is_refused() {
        let reply = ReplyKey::from_seed(&h32(REPLY_SECRET));
        let reply_x = PublicKey::from(&reply.x25519).to_bytes();
        let mut ct = encrypt(&reply_x, "x", &[], &[7u8; 56]).unwrap();
        ct.replace_range(ct.len() - 2.., "00");
        assert!(reply.decrypt(&ct).is_err());
    }

    #[test]
    fn an_empty_field_stays_empty() {
        assert_eq!(ReplyKey::from_seed(&[1u8; 32]).decrypt("").unwrap(), "");
    }

    #[test]
    fn short_envelopes_are_refused() {
        assert_eq!(ReplyKey::from_seed(&[1u8; 32]).decrypt("abcd").unwrap_err(), "e2ee_bad_envelope");
    }
}
