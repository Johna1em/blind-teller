//! The actions the enclave answers.
//!
//! `pubkey`   publishes the sealing and verdict keys, and the policy hash.
//! `reveal`   re-seals a seller's payee details to the buyer of a live order.
//! `prove`    reads one sealed email and, if every rule passes, signs a verdict.
//! `inspect`  checks any email's DKIM signature and answers pass or fail.
//! `probe`    reports which allowed hosts this run can reach.
//!
//! **Nothing is kept after a response returns.** `Host` has no storage call, so
//! this code can't save an email, a verdict or anything else. Each run starts
//! empty, and its memory ends with it.
//!
//! Nothing here writes a log, and errors are codes, never content: stdout is the
//! only channel out, and it carries no email text, name or amount.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use teller_core::{email_aad, keys_message, payee_aad, reveal_aad, terms_line, verdict_message, Terms};

use crate::checks::{evaluate, Extraction, Payee};
use crate::dkim::{self, DkimError, Verified};
use crate::host::{Host, HttpRequest};
use crate::nearai::{self, ModelRef};
use crate::policy::{self, Issuer, KeySource, Rail};
use crate::{mime, seal};

/// A bank alert is small; refuse anything that could slow a run down.
const MAX_EMAIL_BYTES: usize = 512 * 1024;
const MAX_SEALED_BYTES: usize = 700 * 1024;
const CLOCK_SKEW_MS: u64 = 5 * 60_000;
const DOH_TIMEOUT_SECS: u64 = 10;

/// Fixed message the seal key is derived from. The verdict key's deterministic
/// signature over it is a secret only this code can compute, and no caller can
/// ever obtain it: every other signed message starts with another prefix.
const SEAL_SEED_MESSAGE: &[u8] = b"blind-teller/v1|seal-seed";

#[derive(Debug, Clone, Deserialize)]
pub struct TermsInput {
    pub contract: String,
    pub order_id: u64,
    pub offer_id: u64,
    pub seller: String,
    pub buyer: String,
    pub token: String,
    pub token_amount: String,
    pub currency: String,
    pub fiat_minor: u64,
    pub rail: String,
    pub payee_commit: String,
    pub created_ms: u64,
    pub deadline_ms: u64,
}

impl TermsInput {
    fn into_terms(self) -> Result<Terms, &'static str> {
        Ok(Terms {
            contract: self.contract,
            order_id: self.order_id,
            offer_id: self.offer_id,
            seller: self.seller,
            buyer: self.buyer,
            token: self.token,
            token_amount: self.token_amount.parse().map_err(|_| "bad_terms")?,
            currency: self.currency,
            fiat_minor: self.fiat_minor,
            rail: self.rail,
            payee_commit: self.payee_commit,
            created_ms: self.created_ms,
            deadline_ms: self.deadline_ms,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct ProveInput {
    pub terms: TermsInput,
    pub sealed_email: String,
    pub sealed_payee: String,
    #[serde(default)]
    pub models: Vec<ModelRef>,
    /// Sandbox builds only: skip the models and use the regex reader.
    #[serde(default)]
    pub dev: bool,
}

#[derive(Debug, Deserialize)]
pub struct RevealInput {
    pub contract: String,
    pub order_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct InspectInput {
    pub sealed_email: String,
}

/// Associated data for `inspect`, so an order's sealed email can't be replayed here.
pub const INSPECT_AAD: &str = "blind-teller/v1|inspect";

/// Steps the browser shows, ticking as they pass. Names only, never values.
#[derive(Default)]
struct Trace(Vec<Value>);

impl Trace {
    fn pass(&mut self, step: &str) {
        self.0.push(json!({ "step": step, "ok": true }));
    }
    fn fail(&mut self, step: &str, code: &str) {
        self.0.push(json!({ "step": step, "ok": false, "code": code }));
    }
}

fn refused(trace: Trace, step: &str, code: &str) -> Value {
    let mut trace = trace;
    trace.fail(step, code);
    json!({ "ok": false, "code": code, "trace": trace.0 })
}

/// The enclave's sealing secret.
pub fn seal_secret(host: &dyn Host) -> Result<[u8; 32], String> {
    let signature = host.sign(SEAL_SEED_MESSAGE)?;
    Ok(Sha256::digest(signature).into())
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub fn pubkey(host: &dyn Host) -> Result<Value, String> {
    let seal_public = hex::encode(seal::public_of(&seal_secret(host)?));
    let verdict_public = hex::encode(host.verdict_public()?);
    let policy_hash = policy::policy_hash();
    let signature = host.sign(keys_message(&seal_public, &verdict_public, &policy_hash).as_bytes())?;
    Ok(json!({
        "seal_public": seal_public,
        "verdict_public": verdict_public,
        "policy_hash": policy_hash,
        "signature": hex::encode(signature),
        "extractor": if cfg!(feature = "dev-extractor") { "dev-allowed" } else { "near-ai-only" },
        "models": policy::MODELS,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ---- reveal ----

fn rpc_view(host: &dyn Host, endpoint: &str, contract: &str, method: &str, args: &Value) -> Result<Value, &'static str> {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "query",
        "params": { "request_type": "call_function", "finality": "final", "account_id": contract, "method_name": method,
                    "args_base64": STANDARD.encode(args.to_string()) },
    });
    let response = host
        .http(HttpRequest {
            method: "POST",
            url: endpoint.to_string(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_string().into_bytes(),
            timeout_secs: 12,
        })
        .map_err(|_| "rpc_unreachable")?;
    let parsed: Value = serde_json::from_slice(&response.body).map_err(|_| "rpc_invalid")?;
    let bytes: Vec<u8> = parsed["result"]["result"]
        .as_array()
        .ok_or("rpc_invalid")?
        .iter()
        .map(|b| b.as_u64().and_then(|v| u8::try_from(v).ok()))
        .collect::<Option<_>>()
        .ok_or("rpc_invalid")?;
    serde_json::from_slice(&bytes).map_err(|_| "rpc_invalid")
}

/// Read a view from two RPC providers and require the same answer, so one
/// lying node can't invent an order and pull out a seller's details.
fn rpc_agree(host: &dyn Host, contract: &str, method: &str, args: &Value) -> Result<Value, &'static str> {
    let [first, second] = policy::RPC_ENDPOINTS;
    let a = rpc_view(host, first, contract, method, args)?;
    let b = rpc_view(host, second, contract, method, args)?;
    if a != b {
        return Err("rpc_disagree");
    }
    Ok(a)
}

pub fn reveal(host: &dyn Host, input: RevealInput) -> Value {
    match reveal_inner(host, input) {
        Ok(sealed) => json!({ "ok": true, "sealed": sealed }),
        Err(code) => json!({ "ok": false, "code": code }),
    }
}

fn reveal_inner(host: &dyn Host, input: RevealInput) -> Result<String, &'static str> {
    if input.contract != policy::TELLER_CONTRACT {
        return Err("unknown_contract");
    }
    let order = rpc_agree(host, &input.contract, "get_order", &json!({ "order_id": input.order_id.to_string() }))?;
    if order["status"] != "Open" {
        return Err("order_not_open");
    }
    let offer_id = order["offer_id"].as_str().ok_or("rpc_invalid")?;
    let offer = rpc_agree(host, &input.contract, "get_offer", &json!({ "offer_id": offer_id }))?;
    let sealed = offer["sealed_payee"].as_str().ok_or("rpc_invalid")?;
    let seller = offer["seller"].as_str().ok_or("rpc_invalid")?;
    if sha256_hex(sealed.as_bytes()) != offer["payee_commit"].as_str().unwrap_or_default() {
        return Err("payee_commit_mismatch");
    }
    let buyer_key: [u8; 32] = order["buyer_pubkey"]
        .as_str()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or("rpc_invalid")?;
    let secret = seal_secret(host).map_err(|_| "key_unavailable")?;
    let plain = seal::open(&secret, sealed, payee_aad(&input.contract, seller).as_bytes()).map_err(|_| "payee_unreadable")?;
    let mut entropy = [0u8; 44];
    host.random(&mut entropy).map_err(|_| "entropy_failed")?;
    seal::seal(&buyer_key, &plain, reveal_aad(&input.contract, input.order_id).as_bytes(), &entropy).map_err(|_| "seal_failed")
}

// ---- prove ----

fn txt_lookup(host: &dyn Host, resolver: &str, name: &str) -> Result<Vec<String>, DkimError> {
    let url = format!("{resolver}?name={name}&type=TXT");
    let response = host
        .http(HttpRequest {
            method: "GET",
            url,
            headers: vec![("accept".into(), "application/dns-json".into())],
            body: vec![],
            timeout_secs: DOH_TIMEOUT_SECS,
        })
        .map_err(|_| DkimError::KeyMissing)?;
    let parsed: Value = serde_json::from_slice(&response.body).map_err(|_| DkimError::KeyMissing)?;
    let answers = parsed["Answer"].as_array().ok_or(DkimError::KeyMissing)?;
    Ok(answers.iter().filter(|a| a["type"] == 16).filter_map(|a| a["data"].as_str()).map(unquote_txt).collect())
}

/// Resolvers disagree on TXT format. Cloudflare sends quoted chunks, `"v=DKIM1;
/// p=abc" "def"`; Google sends the joined text. Both mean the same record.
pub fn unquote_txt(data: &str) -> String {
    if data.contains('"') {
        data.split('"').enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, s)| s).collect()
    } else {
        data.to_string()
    }
}

/// Fetch a key from two independent resolvers. They must agree, so one poisoned
/// answer can't swap a bank's key for an attacker's.
fn dns_key(host: &dyn Host, domain: &str, selector: &str) -> Result<Vec<u8>, DkimError> {
    let valid = |s: &str| !s.is_empty() && s.len() <= 120 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
    if !valid(domain) || !valid(selector) {
        return Err(DkimError::Malformed);
    }
    let name = format!("{selector}._domainkey.{domain}");
    let a = txt_lookup(host, "https://dns.google/resolve", &name)?;
    let b = txt_lookup(host, "https://cloudflare-dns.com/dns-query", &name)?;
    if a != b {
        return Err(DkimError::KeyMissing);
    }
    dkim::parse_key_record(a.first().ok_or(DkimError::KeyMissing)?)
}

/// The issuer key for a signature, or a refusal if this rail doesn't accept
/// that domain. Refusing here means an unknown domain costs no DNS lookup.
fn issuer_key(host: &dyn Host, rail: &Rail, domain: &str, selector: &str) -> Result<Vec<u8>, DkimError> {
    let Some(Issuer { key, .. }) = policy::issuer(rail, domain) else {
        return Err(DkimError::FromNotAligned);
    };
    match key {
        KeySource::Sandbox => STANDARD.decode(policy::SANDBOX_KEY_DER_B64.trim()).map_err(|_| DkimError::KeyMissing),
        KeySource::Dns => dns_key(host, domain, selector),
    }
}

/// When the bank signed: the DKIM `t=` tag, or the signed `Date` header.
fn signed_time_ms(v: &Verified) -> Option<u64> {
    v.signed_at.map(|t| t * 1_000).or_else(|| v.header("date").and_then(parse_date_ms))
}

/// RFC 5322 date, for example `Sat, 07 Nov 2026 10:00:00 +0530`.
pub fn parse_date_ms(s: &str) -> Option<u64> {
    let s = s.split('(').next()?.trim();
    let s = s.split_once(',').map_or(s, |(_, rest)| rest).trim();
    let p: Vec<&str> = s.split_whitespace().collect();
    if p.len() < 4 {
        return None;
    }
    let day: i64 = p[0].parse().ok()?;
    let months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let month = months.iter().position(|m| p[1].to_ascii_lowercase().starts_with(m))? as i64 + 1;
    let year: i64 = p[2].parse().ok()?;
    let clock: Vec<i64> = p[3].split(':').map(|n| n.parse().ok()).collect::<Option<_>>()?;
    let (h, m, sec) = (*clock.first()?, *clock.get(1)?, clock.get(2).copied().unwrap_or(0));
    let offset_min = match p.get(4).copied() {
        Some(z) if z.len() == 5 && (z.starts_with('+') || z.starts_with('-')) => {
            let v: i64 = z[1..].parse().ok()?;
            (v / 100 * 60 + v % 100) * if z.starts_with('-') { -1 } else { 1 }
        }
        _ => 0,
    };
    // Days from the civil calendar (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 + h * 3_600 + m * 60 + sec - offset_min * 60;
    u64::try_from(seconds).ok().map(|s| s * 1_000)
}

/// One email, one nullifier, however many signatures it carries. Keyed with the
/// enclave secret so nobody can test whether a given email was used.
fn nullifier(secret: &[u8; 32], v: &Verified) -> String {
    let mut h = Sha256::new();
    h.update(b"blind-teller/v1|nullifier");
    h.update(secret);
    for part in [v.domain.as_bytes(), v.header("date").unwrap_or("").as_bytes(), v.header("message-id").unwrap_or("").as_bytes(), v.header("subject").unwrap_or("").as_bytes(), &v.body] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    hex::encode(h.finalize())
}

fn read_with_models(host: &dyn Host, input: &ProveInput, text: &str) -> Result<(Vec<Extraction>, Vec<String>), &'static str> {
    let api_key = host.secret("NEAR_AI_API_KEY").filter(|k| !k.trim().is_empty()).ok_or("model_key_not_configured")?;
    if input.models.len() != policy::MODELS.len() || !policy::MODELS.iter().all(|m| input.models.iter().any(|r| r.id == *m)) {
        return Err("model_set_invalid");
    }
    let mut readings = Vec::with_capacity(input.models.len());
    let mut keys: Vec<String> = Vec::with_capacity(input.models.len());
    for model in &input.models {
        readings.push(nearai::read_email(host, model, &api_key, text)?);
        if !keys.contains(&model.key) {
            keys.push(model.key.clone());
        }
    }
    keys.sort();
    Ok((readings, keys))
}

#[cfg(feature = "dev-extractor")]
fn read_with_rules(text: &str) -> Result<(Vec<Extraction>, Vec<String>), &'static str> {
    Ok((vec![crate::devrules::read(text)?], vec![]))
}

#[cfg(not(feature = "dev-extractor"))]
fn read_with_rules(_: &str) -> Result<(Vec<Extraction>, Vec<String>), &'static str> {
    Err("dev_extractor_not_in_this_build")
}

pub fn prove(host: &dyn Host, input: ProveInput) -> Value {
    let mut trace = Trace::default();
    let terms = match input.terms.clone().into_terms() {
        Ok(t) => t,
        Err(code) => return refused(trace, "terms", code),
    };
    let rail = match policy::rail(&terms.rail) {
        Some(r) if r.currency == terms.currency => r,
        _ => return refused(trace, "terms", "unknown_rail"),
    };
    if input.sealed_email.len() > MAX_SEALED_BYTES {
        return refused(trace, "terms", "email_too_large");
    }
    if sha256_hex(input.sealed_payee.as_bytes()) != terms.payee_commit {
        return refused(trace, "terms", "payee_commit_mismatch");
    }
    trace.pass("terms");

    let secret = match seal_secret(host) {
        Ok(s) => s,
        Err(_) => return refused(trace, "decrypt", "key_unavailable"),
    };
    let email = match seal::open(&secret, &input.sealed_email, email_aad(&terms.contract, terms.order_id).as_bytes()) {
        Ok(e) if e.len() <= MAX_EMAIL_BYTES => e,
        Ok(_) => return refused(trace, "decrypt", "email_too_large"),
        Err(code) => return refused(trace, "decrypt", code),
    };
    let payee: Payee = match seal::open(&secret, &input.sealed_payee, payee_aad(&terms.contract, &terms.seller).as_bytes())
        .ok()
        .and_then(|p| serde_json::from_slice(&p).ok())
    {
        Some(p) => p,
        None => return refused(trace, "decrypt", "payee_unreadable"),
    };
    trace.pass("decrypt");

    let min_bits = rail.issuers.iter().map(|i| i.min_bits).min().unwrap_or(2048);
    let verified = match dkim::verify(&email, min_bits, |domain, selector| issuer_key(host, rail, domain, selector)) {
        Ok(v) => v,
        Err(e) => return refused(trace, "dkim", e.code()),
    };
    if policy::issuer(rail, &verified.domain).is_none() {
        return refused(trace, "dkim", "issuer_not_allowed");
    }
    trace.pass("dkim");

    let now = host.now_ms();
    match signed_time_ms(&verified) {
        Some(t) if t + CLOCK_SKEW_MS >= terms.created_ms && t <= now + CLOCK_SKEW_MS => trace.pass("timing"),
        Some(_) => return refused(trace, "timing", "email_outside_order_window"),
        None => return refused(trace, "timing", "email_undated"),
    }

    let text = mime::authenticated_text(&verified);
    let result = if input.dev { read_with_rules(&text) } else { read_with_models(host, &input, &text) };
    let (readings, model_keys) = match result {
        Ok(r) => r,
        Err(code) => return refused(trace, "read", code),
    };
    trace.pass("read");

    if let Err(code) = evaluate(&text, &readings, &terms.currency, terms.fiat_minor, &payee) {
        return refused(trace, "rules", code);
    }
    trace.pass("rules");

    let extractor = if input.dev { teller_core::EXTRACTOR_DEV } else { teller_core::EXTRACTOR_NEAR_AI };
    let issued_ms = now;
    let spent = nullifier(&secret, &verified);
    let terms_hash = sha256_hex(terms_line(&terms).as_bytes());
    let message = verdict_message(&terms.contract, terms.order_id, &terms_hash, &spent, &model_keys, extractor, issued_ms);
    let signature = match host.sign(message.as_bytes()) {
        Ok(s) => s,
        Err(_) => return refused(trace, "sign", "key_unavailable"),
    };
    trace.pass("sign");

    json!({
        "ok": true,
        "verdict": {
            "nullifier": spent,
            "model_keys": model_keys,
            "extractor": extractor,
            "issued_ms": issued_ms.to_string(),
            "signature": hex::encode(signature),
        },
        "trace": trace.0,
    })
}

/// Check any real email against live DNS, and answer pass or fail. This is how a
/// viewer can see that DKIM here isn't a sandbox trick. It settles nothing, signs
/// nothing and has no issuer list. The answer names no domain, sender or subject:
/// the browser already knows those, and the run's output shouldn't.
pub fn inspect(host: &dyn Host, input: InspectInput) -> Value {
    if input.sealed_email.len() > MAX_SEALED_BYTES {
        return json!({ "ok": false, "code": "email_too_large" });
    }
    let Ok(secret) = seal_secret(host) else {
        return json!({ "ok": false, "code": "key_unavailable" });
    };
    let email = match seal::open(&secret, &input.sealed_email, INSPECT_AAD.as_bytes()) {
        Ok(e) if e.len() <= MAX_EMAIL_BYTES => e,
        Ok(_) => return json!({ "ok": false, "code": "email_too_large" }),
        Err(code) => return json!({ "ok": false, "code": code }),
    };
    match dkim::verify(&email, 2048, |domain, selector| dns_key(host, domain, selector)) {
        Ok(v) => {
            let names: Vec<&str> = v.headers.iter().map(|(n, _)| n.as_str()).collect();
            json!({ "ok": true, "signed_headers": names, "signed_at": v.signed_at })
        }
        Err(e) => json!({ "ok": false, "code": e.code() }),
    }
}

/// Reach each host the manifest allows, and report status codes only. It proves
/// the path to NEAR AI works from inside the enclave before a key is ever used.
pub fn probe(host: &dyn Host) -> Value {
    let get = |url: &str, headers: Vec<(String, String)>| {
        host.http(HttpRequest { method: "GET", url: url.to_string(), headers, body: vec![], timeout_secs: 20 })
            .map_or(json!("unreachable"), |r| json!(r.status))
    };
    let dns = || vec![("accept".to_string(), "application/dns-json".to_string())];
    let started = host.now_ms();
    host.sleep_ms(20);
    let slept = host.now_ms().saturating_sub(started);
    json!({
        "ok": true,
        "slept_ms": slept,
        "near_ai": get(&format!("{}/models", policy::NEAR_AI_BASE), vec![]),
        "dns_google": get("https://dns.google/resolve?name=near.org&type=TXT", dns()),
        "dns_cloudflare": get("https://cloudflare-dns.com/dns-query?name=near.org&type=TXT", dns()),
        "model_key_set": host.secret("NEAR_AI_API_KEY").is_some_and(|k| !k.trim().is_empty()),
    })
}

/// Dispatch one call. The input is JSON with an `action` field.
pub fn run(host: &dyn Host, input: &[u8]) -> Value {
    let parsed: Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(_) => return json!({ "ok": false, "code": "bad_input" }),
    };
    match parsed["action"].as_str() {
        Some("pubkey") => pubkey(host).unwrap_or_else(|_| json!({ "ok": false, "code": "key_unavailable" })),
        Some("probe") => probe(host),
        Some("inspect") => match serde_json::from_value(parsed) {
            Ok(i) => inspect(host, i),
            Err(_) => json!({ "ok": false, "code": "bad_input" }),
        },
        Some("reveal") => match serde_json::from_value(parsed) {
            Ok(i) => reveal(host, i),
            Err(_) => json!({ "ok": false, "code": "bad_input" }),
        },
        Some("prove") => match serde_json::from_value(parsed) {
            Ok(i) => prove(host, i),
            Err(_) => json!({ "ok": false, "code": "bad_input" }),
        },
        _ => json!({ "ok": false, "code": "unknown_action" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_records_parse_from_either_resolver() {
        assert_eq!(unquote_txt("v=DKIM1; k=rsa; p=abc"), "v=DKIM1; k=rsa; p=abc");
        assert_eq!(unquote_txt("\"v=DKIM1; k=rsa; p=abc\" \"def\""), "v=DKIM1; k=rsa; p=abcdef");
        assert_eq!(unquote_txt("\"v=DKIM1; p=abc\""), unquote_txt("v=DKIM1; p=abc"));
    }

    #[test]
    fn dates_parse_with_their_offsets() {
        // 2026-11-07 10:00:00 UTC.
        assert_eq!(parse_date_ms("Sat, 07 Nov 2026 10:00:00 +0000"), Some(1_794_045_600_000));
        assert_eq!(parse_date_ms("Sat, 07 Nov 2026 15:30:00 +0530"), Some(1_794_045_600_000));
        assert_eq!(parse_date_ms("7 Nov 2026 10:00:00 GMT"), Some(1_794_045_600_000));
        assert_eq!(parse_date_ms("Sat, 07 Nov 2026 10:00:00 +0000 (UTC)"), Some(1_794_045_600_000));
        assert_eq!(parse_date_ms("not a date"), None);
    }
}
