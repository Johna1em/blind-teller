//! One end-to-end encrypted call to a TEE-hosted model on NEAR AI Cloud.
//!
//! The email leaves the enclave only as ciphertext to the model's attested key,
//! so the gateway can't read it. The reply is checked against the model's own
//! signature, which also pins the exact request bytes: a gateway can't quietly
//! answer a different question.
//!
//! Which key is genuine isn't decided here. The verdict names the keys, and the
//! contract accepts them only if the on-chain registry has proven them through
//! NEAR's tee-verifier.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::checks::Extraction;
use crate::e2ee::{self, ReplyKey};
use crate::host::{Host, HttpRequest};
use crate::policy::{model_options, MAX_TOKENS, NEAR_AI_BASE, SYSTEM_PROMPT};

/// Time for one model call. Two calls and overhead must fit a 180 s run.
const CHAT_TIMEOUT_SECS: u64 = 75;
const SIGNATURE_TIMEOUT_SECS: u64 = 10;
/// A signature lands a moment after the reply, and a lookup can reach a node that
/// doesn't hold it yet. NEAR's verification example uses the same schedule.
const SIGNATURE_ATTEMPTS: usize = 5;
const SIGNATURE_WAIT_MS: u64 = 1_000;

#[derive(Debug, Clone, Deserialize)]
pub struct ModelRef {
    pub id: String,
    /// The model's ed25519 key, lowercase hex.
    pub key: String,
}

#[derive(Deserialize)]
struct SignatureBody {
    text: String,
    signature: String,
    signing_address: String,
    signing_algo: String,
    #[serde(default)]
    signature_kind: Option<String>,
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn key_bytes(hex_key: &str) -> Result<[u8; 32], &'static str> {
    hex::decode(hex_key).ok().and_then(|b| b.try_into().ok()).ok_or("model_key_invalid")
}

/// The request body, with every message encrypted to the model.
pub fn build_body(model: &ModelRef, reply: &ReplyKey, user: &str, entropy: &[[u8; 56]; 2]) -> Result<Vec<u8>, &'static str> {
    let x25519 = e2ee::model_x25519(&key_bytes(&model.key)?)?;
    let aad = e2ee::field_aad(&reply.request_aad(), e2ee::FIELD_CONTENT);
    let system = e2ee::encrypt(&x25519, SYSTEM_PROMPT, &aad, &entropy[0])?;
    let user = e2ee::encrypt(&x25519, user, &aad, &entropy[1])?;
    let Value::Object(mut body) = json!({
        "model": model.id,
        "messages": [{ "role": "system", "content": system }, { "role": "user", "content": user }],
        "temperature": 0,
        "max_tokens": MAX_TOKENS,
        "stream": false,
    }) else {
        return Err("model_request_failed");
    };
    if let Value::Object(options) = model_options(&model.id) {
        body.extend(options);
    }
    serde_json::to_vec(&body).map_err(|_| "model_request_failed")
}

/// The email, wrapped so a closing marker inside it can't end the data block.
pub fn user_message(email_text: &str, marker: &str) -> String {
    format!("<{marker}>\n{email_text}\n</{marker}>")
}

pub fn headers(model: &ModelRef, reply: &ReplyKey, api_key: &str) -> Vec<(String, String)> {
    [
        ("authorization", format!("Bearer {api_key}")),
        ("content-type", "application/json".to_string()),
        ("accept-encoding", "identity".to_string()),
        ("x-signing-algo", "ed25519".to_string()),
        ("x-client-pub-key", reply.public_hex()),
        ("x-model-pub-key", model.key.clone()),
        ("x-encryption-version", "3".to_string()),
        ("x-encrypt-all-fields", "true".to_string()),
        ("x-no-aliasing", "true".to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

/// Check the model's signature over this exact exchange.
pub fn verify_signature(model: &ModelRef, signature_json: &[u8], request: &[u8], response: &[u8]) -> Result<(), &'static str> {
    let s: SignatureBody = serde_json::from_slice(signature_json).map_err(|_| "model_signature_invalid")?;
    if s.signing_algo != "ed25519" || !s.signing_address.eq_ignore_ascii_case(&model.key) {
        return Err("model_signature_invalid");
    }
    // `gateway` means the gateway signed, which proves nothing about the model.
    // A missing kind proves nothing either: NEAR's docs say not to infer it.
    if s.signature_kind.as_deref() != Some("provider_tee") {
        return Err("model_signature_not_tee");
    }
    let expected = format!("{}:{}:{}", model.id, sha256_hex(request), sha256_hex(response));
    if s.text != expected {
        return Err("model_signature_mismatch");
    }
    let key = VerifyingKey::from_bytes(&key_bytes(&model.key)?).map_err(|_| "model_key_invalid")?;
    let sig_bytes: [u8; 64] = hex::decode(s.signature.trim_start_matches("0x")).ok().and_then(|b| b.try_into().ok()).ok_or("model_signature_invalid")?;
    key.verify_strict(s.text.as_bytes(), &Signature::from_bytes(&sig_bytes)).map_err(|_| "model_signature_invalid")
}

/// Pull the JSON object out of a model reply, which may arrive in a code fence.
pub fn parse_reply(content: &str) -> Result<Extraction, &'static str> {
    let start = content.find('{').ok_or("model_reply_invalid")?;
    let end = content.rfind('}').ok_or("model_reply_invalid")?;
    if end < start {
        return Err("model_reply_invalid");
    }
    serde_json::from_str(&content[start..=end]).map_err(|_| "model_reply_invalid")
}

/// Ask one model to read one email.
pub fn read_email(host: &dyn Host, model: &ModelRef, api_key: &str, email_text: &str) -> Result<Extraction, &'static str> {
    let mut seed = [0u8; 32];
    let mut entropy = [[0u8; 56]; 2];
    let mut marker = [0u8; 12];
    host.random(&mut seed).map_err(|_| "entropy_failed")?;
    host.random(&mut entropy[0]).map_err(|_| "entropy_failed")?;
    host.random(&mut entropy[1]).map_err(|_| "entropy_failed")?;
    host.random(&mut marker).map_err(|_| "entropy_failed")?;
    let reply = ReplyKey::from_seed(&seed);

    // A random marker: an email can't close a block whose name it can't guess.
    let user = user_message(email_text, &format!("email-{}", hex::encode(marker)));
    let body = build_body(model, &reply, &user, &entropy)?;
    let response = host
        .http(HttpRequest {
            method: "POST",
            url: format!("{NEAR_AI_BASE}/chat/completions"),
            headers: headers(model, &reply, api_key),
            body: body.clone(),
            timeout_secs: CHAT_TIMEOUT_SECS,
        })
        .map_err(|_| "model_unreachable")?;
    if response.status != 200 {
        return Err("model_error");
    }
    let parsed: Value = serde_json::from_slice(&response.body).map_err(|_| "model_reply_invalid")?;
    if parsed["choices"][0]["finish_reason"] == "length" {
        return Err("model_reply_truncated");
    }
    let chat_id = parsed["id"].as_str().ok_or("model_reply_invalid")?;
    let ciphertext = parsed["choices"][0]["message"]["content"].as_str().ok_or("model_reply_invalid")?;
    let content = reply.decrypt(ciphertext).map_err(|_| "model_reply_undecryptable")?;

    let signature = fetch_signature(host, chat_id, api_key)?;
    verify_signature(model, &signature, &body, &response.body)?;
    parse_reply(&content)
}

/// A successful answer can still mean "unavailable". It then carries `error_code`
/// and no signature, and it's worth asking again.
fn is_signature(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body).is_ok_and(|v| v.get("error_code").is_none() && v.get("signature").is_some())
}

fn fetch_signature(host: &dyn Host, chat_id: &str, api_key: &str) -> Result<Vec<u8>, &'static str> {
    let mut last = "model_signature_missing";
    for attempt in 0..SIGNATURE_ATTEMPTS {
        if attempt > 0 {
            host.sleep_ms(SIGNATURE_WAIT_MS);
        }
        let response = host.http(HttpRequest {
            method: "GET",
            url: format!("{NEAR_AI_BASE}/signature/{chat_id}?signing_algo=ed25519"),
            headers: vec![("authorization".into(), format!("Bearer {api_key}")), ("accept-encoding".into(), "identity".into())],
            body: vec![],
            timeout_secs: SIGNATURE_TIMEOUT_SECS,
        });
        match response {
            Ok(r) if r.status == 200 && is_signature(&r.body) => return Ok(r.body),
            Ok(_) => last = "model_signature_missing",
            Err(_) => last = "model_unreachable",
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn model() -> (SigningKey, ModelRef) {
        let k = SigningKey::from_bytes(&[3u8; 32]);
        let r = ModelRef { id: "z-ai/glm-5.3-flash".into(), key: hex::encode(k.verifying_key().to_bytes()) };
        (k, r)
    }

    fn sig_json(k: &SigningKey, m: &ModelRef, text: &str, kind: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "text": text, "signature": hex::encode(k.sign(text.as_bytes()).to_bytes()),
            "signing_address": m.key, "signing_algo": "ed25519", "signature_kind": kind,
        }))
        .unwrap()
    }

    fn good_text(m: &ModelRef, req: &[u8], res: &[u8]) -> String {
        format!("{}:{}:{}", m.id, sha256_hex(req), sha256_hex(res))
    }

    #[test]
    fn a_real_exchange_verifies() {
        let (k, m) = model();
        let s = sig_json(&k, &m, &good_text(&m, b"req", b"res"), "provider_tee");
        assert_eq!(verify_signature(&m, &s, b"req", b"res"), Ok(()));
    }

    #[test]
    fn a_swapped_response_is_refused() {
        let (k, m) = model();
        let s = sig_json(&k, &m, &good_text(&m, b"req", b"res"), "provider_tee");
        assert_eq!(verify_signature(&m, &s, b"req", b"other"), Err("model_signature_mismatch"));
    }

    #[test]
    fn a_swapped_request_is_refused() {
        let (k, m) = model();
        let s = sig_json(&k, &m, &good_text(&m, b"req", b"res"), "provider_tee");
        assert_eq!(verify_signature(&m, &s, b"different prompt", b"res"), Err("model_signature_mismatch"));
    }

    #[test]
    fn a_gateway_signature_is_not_a_model_signature() {
        let (k, m) = model();
        let s = sig_json(&k, &m, &good_text(&m, b"req", b"res"), "gateway");
        assert_eq!(verify_signature(&m, &s, b"req", b"res"), Err("model_signature_not_tee"));
    }

    #[test]
    fn a_signature_of_unknown_kind_is_refused() {
        let (k, m) = model();
        let text = good_text(&m, b"req", b"res");
        let unlabelled = serde_json::to_vec(&json!({
            "text": text, "signature": hex::encode(k.sign(text.as_bytes()).to_bytes()),
            "signing_address": m.key, "signing_algo": "ed25519",
        }))
        .unwrap();
        assert_eq!(verify_signature(&m, &unlabelled, b"req", b"res"), Err("model_signature_not_tee"));
    }

    #[test]
    fn thinking_is_capped_for_each_model() {
        let reply = ReplyKey::from_seed(&[1u8; 32]);
        let key = hex::encode(SigningKey::from_bytes(&[3u8; 32]).verifying_key().to_bytes());
        let body = |id: &str| -> Value {
            let m = ModelRef { id: id.into(), key: key.clone() };
            serde_json::from_slice(&build_body(&m, &reply, "x", &[[2u8; 56], [3u8; 56]]).unwrap()).unwrap()
        };
        let glm = body("z-ai/glm-5.3-flash");
        assert_eq!(glm["thinking_token_budget"], 512);
        assert_eq!(glm["max_tokens"], MAX_TOKENS);
        let qwen = body("Qwen/Qwen3.8-27B");
        assert_eq!(qwen["chat_template_kwargs"]["enable_thinking"], false);
        assert_eq!(qwen["max_tokens"], MAX_TOKENS);
    }

    #[test]
    fn only_a_real_signature_ends_the_wait() {
        assert!(is_signature(br#"{"text":"t","signature":"s"}"#));
        assert!(!is_signature(br#"{"error_code":"not_found","message":"unavailable"}"#));
        assert!(!is_signature(b"not json"));
    }

    #[test]
    fn another_key_is_refused() {
        let (_, m) = model();
        let other = SigningKey::from_bytes(&[4u8; 32]);
        let s = sig_json(&other, &m, &good_text(&m, b"req", b"res"), "provider_tee");
        assert_eq!(verify_signature(&m, &s, b"req", b"res"), Err("model_signature_invalid"));
    }

    #[test]
    fn replies_parse_with_or_without_fences() {
        let plain = r#"{"status":"success","direction":"debit","amount":"10","currency":"INR"}"#;
        assert_eq!(parse_reply(plain).unwrap().status, "success");
        assert_eq!(parse_reply(&format!("```json\n{plain}\n```")).unwrap().amount, "10");
        assert!(parse_reply("sorry, I can't").is_err());
        assert!(parse_reply("{\"status\":1}").is_err());
    }

    #[test]
    fn the_request_body_hides_the_email() {
        let (_, m) = model();
        let reply = ReplyKey::from_seed(&[1u8; 32]);
        let secret = "Rs. 8,850.37 debited";
        let body = build_body(&m, &reply, &user_message(secret, "x"), &[[2u8; 56], [3u8; 56]]).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(!text.contains("8,850.37"));
        assert!(!text.contains("bank payment notification"));
        assert!(text.contains("z-ai/glm-5.3-flash"));
    }
}
