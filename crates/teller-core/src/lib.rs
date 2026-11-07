//! The two strings the contract and the enclave must agree on, byte for byte.
//!
//! A disagreement between two implementations raises no error anywhere: the
//! contract would refuse a correct proof. So both sides compile this one crate,
//! and `web/src/lib/canonical.ts` is held to the same vectors by
//! `fixtures/canonical-vectors.json`, which `cargo test` regenerates and checks.
//!
//! Every field is a NEAR account id, a number, lowercase hex or a token this
//! contract validated, so none can contain the `|` separator.

/// Domain separator. A signature for one use can't be replayed for another.
pub const DOMAIN: &str = "blind-teller/v1";

/// Which extractor produced a verdict. The contract refuses `dev-rules` unless
/// it was deployed with `allow_dev`, and the release enclave can't emit it.
pub const EXTRACTOR_NEAR_AI: &str = "near-ai";
pub const EXTRACTOR_DEV: &str = "dev-rules";

/// Everything a verdict commits to about an order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    pub contract: String,
    pub order_id: u64,
    pub offer_id: u64,
    pub seller: String,
    pub buyer: String,
    pub token: String,
    /// Token amount, in the token's smallest unit.
    pub token_amount: u128,
    /// ISO 4217 code, for example `INR`.
    pub currency: String,
    /// Exact fiat amount in minor units, including the order's penny tag.
    pub fiat_minor: u64,
    pub rail: String,
    /// sha256 of the sealed payee record, lowercase hex.
    pub payee_commit: String,
    pub created_ms: u64,
    pub deadline_ms: u64,
}

/// The line the contract and the enclave each hash to get `terms_hash`.
pub fn terms_line(t: &Terms) -> String {
    format!(
        "{DOMAIN}|terms|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        t.contract,
        t.order_id,
        t.offer_id,
        t.seller,
        t.buyer,
        t.token,
        t.token_amount,
        t.currency,
        t.fiat_minor,
        t.rail,
        t.payee_commit,
        t.created_ms,
        t.deadline_ms
    )
}

/// The exact message the enclave signs and the contract verifies.
///
/// A verdict exists only for a proof that passed: a refusal is never signed.
pub fn verdict_message(
    contract: &str,
    order_id: u64,
    terms_hash: &str,
    nullifier: &str,
    model_keys: &[String],
    extractor: &str,
    issued_ms: u64,
) -> String {
    format!(
        "{DOMAIN}|verdict|paid|{contract}|{order_id}|{terms_hash}|{nullifier}|{}|{extractor}|{issued_ms}",
        model_keys.join(",")
    )
}

/// The message the enclave signs when it publishes its public keys.
pub fn keys_message(seal_public: &str, verdict_public: &str, policy_hash: &str) -> String {
    format!("{DOMAIN}|keys|{seal_public}|{verdict_public}|{policy_hash}")
}

/// Associated data that binds a sealed email to one order, so a ciphertext
/// lifted from one order can't be replayed against another.
pub fn email_aad(contract: &str, order_id: u64) -> String {
    format!("{DOMAIN}|email|{contract}|{order_id}")
}

/// Associated data that binds a sealed payee record to the seller who sealed it.
pub fn payee_aad(contract: &str, seller: &str) -> String {
    format!("{DOMAIN}|payee|{contract}|{seller}")
}

/// Associated data for the payee details re-sealed to one buyer.
pub fn reveal_aad(contract: &str, order_id: u64) -> String {
    format!("{DOMAIN}|reveal|{contract}|{order_id}")
}

/// Fiat owed for a token amount, rounded up so a seller never receives less
/// than the listed rate. `rate_minor` is fiat minor units per whole token.
pub fn fiat_base(token_amount: u128, rate_minor: u64, token_decimals: u8) -> Option<u64> {
    let scale = 10u128.checked_pow(token_decimals as u32)?;
    let product = token_amount.checked_mul(rate_minor as u128)?;
    let rounded = product.checked_add(scale - 1)? / scale;
    u64::try_from(rounded).ok()
}

/// True for a lowercase hex string of exactly `bytes` bytes.
pub fn is_hex(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// True for a token that is safe inside a canonical line.
pub fn is_token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn sample() -> Terms {
        Terms {
            contract: "teller.blindteller.testnet".into(),
            order_id: 7,
            offer_id: 2,
            seller: "seller.testnet".into(),
            buyer: "buyer.testnet".into(),
            token: "usdc.fakes.testnet".into(),
            token_amount: 100_000_000,
            currency: "INR".into(),
            fiat_minor: 885_037,
            rail: "sandbox-upi".into(),
            payee_commit: "ab".repeat(32),
            created_ms: 1_794_000_000_000,
            deadline_ms: 1_794_001_800_000,
        }
    }

    #[test]
    fn terms_line_is_stable() {
        assert_eq!(
            terms_line(&sample()),
            format!(
                "blind-teller/v1|terms|teller.blindteller.testnet|7|2|seller.testnet|buyer.testnet|usdc.fakes.testnet|100000000|INR|885037|sandbox-upi|{}|1794000000000|1794001800000",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn verdict_message_is_stable() {
        let keys = vec!["aa".repeat(32), "bb".repeat(32)];
        let m = verdict_message("c.testnet", 1, "h", "n", &keys, EXTRACTOR_NEAR_AI, 5);
        assert_eq!(
            m,
            format!("blind-teller/v1|verdict|paid|c.testnet|1|h|n|{},{}|near-ai|5", "aa".repeat(32), "bb".repeat(32))
        );
    }

    #[test]
    fn fiat_base_rounds_up_for_the_seller() {
        assert_eq!(fiat_base(1_000_000, 8850, 6), Some(8850));
        assert_eq!(fiat_base(1, 8850, 6), Some(1));
        assert_eq!(fiat_base(100_000_000, 8850, 6), Some(885_000));
        assert_eq!(fiat_base(u128::MAX, 8850, 6), None);
    }

    #[test]
    fn validators_reject_separators() {
        assert!(is_hex(&"0f".repeat(32), 32));
        assert!(!is_hex(&"0F".repeat(32), 32));
        assert!(!is_token("a|b", 16));
        assert!(!is_token("", 16));
        assert!(is_token("sandbox-upi", 16));
    }

    /// The cross-language contract: regenerates the vectors the web app's
    /// tests assert, and fails if a committed file has drifted.
    #[test]
    fn canonical_vectors_match_the_committed_file() {
        let t = sample();
        let line = terms_line(&t);
        let terms_hash = hex::encode(Sha256::digest(line.as_bytes()));
        let keys = vec!["aa".repeat(32), "bb".repeat(32)];
        let v = serde_json::json!({
            "terms": {
                "contract": t.contract, "order_id": t.order_id, "offer_id": t.offer_id,
                "seller": t.seller, "buyer": t.buyer, "token": t.token,
                "token_amount": t.token_amount.to_string(), "currency": t.currency,
                "fiat_minor": t.fiat_minor, "rail": t.rail, "payee_commit": t.payee_commit,
                "created_ms": t.created_ms, "deadline_ms": t.deadline_ms,
            },
            "terms_line": line,
            "terms_hash": terms_hash,
            "verdict_message": verdict_message(&t.contract, t.order_id, &terms_hash, &"cd".repeat(32), &keys, EXTRACTOR_NEAR_AI, 1_794_000_100_000),
            "model_keys": keys,
            "nullifier": "cd".repeat(32),
            "issued_ms": 1_794_000_100_000u64,
            "email_aad": email_aad(&t.contract, t.order_id),
            "payee_aad": payee_aad(&t.contract, &t.seller),
            "reveal_aad": reveal_aad(&t.contract, t.order_id),
        });
        let text = serde_json::to_string_pretty(&v).unwrap() + "\n";
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/canonical-vectors.json");
        match std::fs::read_to_string(path) {
            Ok(existing) => assert_eq!(existing.replace("\r\n", "\n"), text, "canonical vectors drifted"),
            Err(_) => {
                std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures")).unwrap();
                std::fs::write(path, text).unwrap();
            }
        }
    }
}
