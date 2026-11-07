//! A public registry of NEAR AI Cloud model keys, on NEAR.
//!
//! NEAR AI Cloud's measurement allowlist lives on Base, and no NEAR contract can
//! ask whether a model key is genuine. This contract fills that gap. Any account
//! can prove a key by relaying a fresh attestation; the Intel signature chain
//! is checked by the same `tee-verifier` contract NEAR's MPC network trusts, so
//! nobody here is trusted, and the relayer can't forge anything.
//!
//! Any contract can then ask `are_attested(keys)` before acting on a model's
//! output. The flow:
//!   1. `new_nonce()` issues a one-time nonce.
//!   2. The relayer fetches a NEAR AI attestation for that nonce.
//!   3. `submit(...)` forwards the quote and Intel collateral to `tee-verifier`.
//!   4. `on_verified` checks the report binds this key and this nonce, the
//!      platform is `UpToDate`, and debug is off, then records the key.
//!
//! What this does NOT prove: GPU evidence can't be checked on-chain (there's no
//! P-384 host function), and the quote measures NEAR AI's launcher, not the
//! model weights. `model` is a label the relayer supplies; the quote binds a
//! key, not a name. See docs/THREAT_MODEL.md.

use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::{Base64VecU8, U64};
use near_sdk::store::{IterableMap, LookupMap};
use near_sdk::{
    env, log, near, require, serde_json, AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault,
    Promise,
};

/// `verify_quote` burns about 176 Tgas on mainnet.
const GAS_VERIFY: Gas = Gas::from_tgas(220);
const GAS_ON_VERIFIED: Gas = Gas::from_tgas(15);
const NONCE_TTL_MS: u64 = 15 * 60_000;
/// How long a proven key stays attested. Refreshing is open to anyone.
const KEY_TTL_MS: u64 = 21 * 24 * 60 * 60_000;
const MAX_MODEL_LABEL: usize = 96;
const MAX_RESULT_BYTES: usize = 64 * 1024;

/// A storage reserve the caller of `submit` covers; the unused part comes back.
const SUBMIT_DEPOSIT: NearToken = NearToken::from_millinear(10);

// Borsh mirror of tee-verifier's output (near/mpc crates/tee-verifier-interface).
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
#[borsh(crate = "borsh")]
pub struct TcbStatusWithAdvisory {
    pub status: u8,
    pub advisory_ids: Vec<String>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
#[borsh(crate = "borsh")]
pub struct EnclaveReport {
    pub cpu_svn: [u8; 16],
    pub misc_select: u32,
    pub reserved1: [u8; 28],
    pub attributes: [u8; 16],
    pub mr_enclave: [u8; 32],
    pub reserved2: [u8; 32],
    pub mr_signer: [u8; 32],
    pub reserved3: [u8; 96],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub reserved4: [u8; 60],
    pub report_data: [u8; 64],
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
#[borsh(crate = "borsh")]
pub struct TdReport10 {
    pub tee_tcb_svn: [u8; 16],
    pub mr_seam: [u8; 48],
    pub mr_signer_seam: [u8; 48],
    pub seam_attributes: [u8; 8],
    pub td_attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub rt_mr0: [u8; 48],
    pub rt_mr1: [u8; 48],
    pub rt_mr2: [u8; 48],
    pub rt_mr3: [u8; 48],
    pub report_data: [u8; 64],
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
#[borsh(crate = "borsh")]
pub struct TdReport15 {
    pub base: TdReport10,
    pub tee_tcb_svn2: [u8; 16],
    pub mr_service_td: [u8; 48],
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
#[borsh(crate = "borsh")]
pub struct TdReport15Ex {
    pub base: TdReport15,
    pub vmid: u8,
    pub td_id: [u8; 32],
    pub dev_info: [u8; 48],
    pub init_service_td_hash: [u8; 48],
    pub init_service_td_attributes: [u8; 8],
    pub init_cpu_svn: [u8; 16],
    pub init_tee_tcb_svn: [u8; 16],
    pub init_tee_fmspc: [u8; 12],
    pub cur_service_td_hash: [u8; 48],
    pub cur_service_td_attributes: [u8; 8],
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
#[borsh(crate = "borsh")]
pub enum Report {
    SgxEnclave(EnclaveReport),
    Td10(TdReport10),
    Td15(TdReport15),
    Td15Ex(TdReport15Ex),
}

impl Report {
    fn as_td10(&self) -> Option<&TdReport10> {
        match self {
            Report::Td10(r) => Some(r),
            Report::Td15(r) => Some(&r.base),
            Report::Td15Ex(r) => Some(&r.base.base),
            Report::SgxEnclave(_) => None,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
#[borsh(crate = "borsh")]
pub struct VerifiedReport {
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub report: Report,
    pub ppid: Vec<u8>,
    pub qe_status: TcbStatusWithAdvisory,
    pub platform_status: TcbStatusWithAdvisory,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
#[borsh(crate = "borsh")]
pub enum VerifierError {
    DcapVerification(String),
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
#[borsh(crate = "borsh")]
pub enum VerificationResult {
    Verified(VerifiedReport),
    Rejected(VerifierError),
}

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    Keys,
    Nonces,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct ModelKey {
    /// The relayer's label. The quote binds the key, not this name.
    pub model: String,
    /// ed25519 public key, lowercase hex.
    pub signing_key: String,
    /// sha256 of the attested app compose, from MRCONFIGID.
    pub compose_hash: String,
    pub mr_td: String,
    pub rtmr3: String,
    pub tcb_status: String,
    pub relayer: AccountId,
    pub verified_ms: U64,
    pub expires_ms: U64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Registry {
    verifier: AccountId,
    keys: IterableMap<String, ModelKey>,
    nonces: LookupMap<String, u64>,
    proofs: u64,
}

/// Apply the policy `tee-verifier` deliberately leaves to its caller. Pure, so
/// it's tested against a real captured quote result.
pub fn check_report(v: &VerifiedReport, key: &[u8; 32], nonce: &[u8; 32]) -> Result<(), &'static str> {
    if v.status != "UpToDate" {
        return Err("the platform's TCB isn't UpToDate");
    }
    let td = v.report.as_td10().ok_or("the quote isn't a TDX quote")?;
    if td.td_attributes[0] & 1 != 0 {
        return Err("the TD is in debug mode");
    }
    if &td.report_data[..32] != key {
        return Err("report_data doesn't bind this key");
    }
    if &td.report_data[32..] != nonce {
        return Err("report_data doesn't bind this nonce");
    }
    if td.mr_config_id[0] != 1 {
        return Err("MRCONFIGID isn't a compose hash");
    }
    Ok(())
}

fn hex32(s: &str, what: &str) -> [u8; 32] {
    let ok = s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    require!(ok, format!("{what} must be 32 bytes of lowercase hex"));
    hex::decode(s).unwrap().try_into().unwrap()
}

#[near]
impl Registry {
    #[init]
    pub fn new(verifier: AccountId) -> Self {
        Self {
            verifier,
            keys: IterableMap::new(StorageKey::Keys),
            nonces: LookupMap::new(StorageKey::Nonces),
            proofs: 0,
        }
    }

    /// A one-time nonce for the next attestation. It proves freshness: a quote
    /// carries no timestamp.
    pub fn new_nonce(&mut self) -> String {
        let mut seed = env::random_seed();
        seed.extend_from_slice(env::predecessor_account_id().as_bytes());
        seed.extend_from_slice(&env::block_timestamp().to_le_bytes());
        seed.extend_from_slice(&self.proofs.to_le_bytes());
        let nonce = hex::encode(env::sha256(&seed));
        self.nonces.insert(nonce.clone(), env::block_timestamp_ms() + NONCE_TTL_MS);
        log!("EVENT_JSON:{}", serde_json::json!({ "standard": "model-registry", "version": "1.0.0", "event": "nonce", "data": [{ "nonce": nonce }] }));
        nonce
    }

    /// Prove a model key. `verify_args` is the Borsh `(QuoteBytes, Collateral)`
    /// for `tee-verifier`. Attach 0.01 NEAR for storage; the rest is returned.
    #[payable]
    pub fn submit(&mut self, model: String, signing_key: String, nonce: String, verify_args: Base64VecU8) -> Promise {
        require!(!model.is_empty() && model.len() <= MAX_MODEL_LABEL, "model label has a bad size");
        hex32(&signing_key, "signing_key");
        hex32(&nonce, "nonce");
        require!(env::attached_deposit() >= SUBMIT_DEPOSIT, "attach 0.01 NEAR for storage");
        let expires = self.nonces.remove(&nonce).unwrap_or_else(|| env::panic_str("unknown or used nonce"));
        require!(env::block_timestamp_ms() <= expires, "this nonce has expired");
        Promise::new(self.verifier.clone())
            .function_call("verify_quote".to_string(), verify_args.0, NearToken::from_yoctonear(0), GAS_VERIFY)
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_ON_VERIFIED).on_verified(
                model,
                signing_key,
                nonce,
                env::predecessor_account_id(),
                near_sdk::json_types::U128(env::attached_deposit().as_yoctonear()),
            ))
    }

    /// Check `tee-verifier`'s answer and record the key.
    #[private]
    pub fn on_verified(
        &mut self,
        model: String,
        signing_key: String,
        nonce: String,
        relayer: AccountId,
        deposit: near_sdk::json_types::U128,
    ) -> bool {
        let refund = |reason: &str| {
            log!("key not recorded: {reason}");
            Promise::new(relayer.clone()).transfer(NearToken::from_yoctonear(deposit.0)).detach();
            false
        };
        let bytes = match env::promise_result_checked(0, MAX_RESULT_BYTES) {
            Ok(b) => b,
            Err(_) => return refund("tee-verifier didn't answer"),
        };
        let report = match VerificationResult::try_from_slice(&bytes) {
            Ok(VerificationResult::Verified(r)) => r,
            Ok(VerificationResult::Rejected(_)) => return refund("tee-verifier rejected the quote"),
            Err(_) => return refund("unreadable verifier result"),
        };
        if let Err(reason) = check_report(&report, &hex32(&signing_key, "signing_key"), &hex32(&nonce, "nonce")) {
            return refund(reason);
        }
        let td = report.report.as_td10().unwrap();
        let before = env::storage_usage();
        let now = env::block_timestamp_ms();
        self.keys.insert(
            signing_key.clone(),
            ModelKey {
                model: model.clone(),
                signing_key: signing_key.clone(),
                compose_hash: hex::encode(&td.mr_config_id[1..33]),
                mr_td: hex::encode(td.mr_td),
                rtmr3: hex::encode(td.rt_mr3),
                tcb_status: report.status.clone(),
                relayer: relayer.clone(),
                verified_ms: U64(now),
                expires_ms: U64(now + KEY_TTL_MS),
            },
        );
        self.keys.flush();
        self.proofs += 1;
        let used = env::storage_usage().saturating_sub(before) as u128 * env::storage_byte_cost().as_yoctonear();
        let back = deposit.0.saturating_sub(used);
        if back > 0 {
            Promise::new(relayer.clone()).transfer(NearToken::from_yoctonear(back)).detach();
        }
        log!(
            "EVENT_JSON:{}",
            serde_json::json!({ "standard": "model-registry", "version": "1.0.0", "event": "key_attested", "data": [{ "model": model, "signing_key": signing_key }] })
        );
        true
    }

    /// True when this key has a live proof.
    pub fn is_attested(&self, key: String) -> bool {
        self.keys.get(&key).is_some_and(|k| env::block_timestamp_ms() < k.expires_ms.0)
    }

    /// True when every key has a live proof. An empty list is false, so a
    /// caller can't pass by naming nothing.
    pub fn are_attested(&self, keys: Vec<String>) -> bool {
        !keys.is_empty() && keys.iter().all(|k| self.is_attested(k.clone()))
    }

    pub fn get_key(&self, key: String) -> Option<ModelKey> {
        self.keys.get(&key).cloned()
    }

    pub fn list_keys(&self, limit: Option<u32>) -> Vec<ModelKey> {
        self.keys.values().take(limit.unwrap_or(50).min(100) as usize).cloned().collect()
    }

    pub fn get_verifier(&self) -> AccountId {
        self.verifier.clone()
    }

    pub fn get_proof_count(&self) -> U64 {
        U64(self.proofs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn ctx(now_ms: u64, deposit: NearToken) {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id("relayer.testnet".parse().unwrap())
            .block_timestamp(now_ms * 1_000_000)
            .attached_deposit(deposit)
            .prepaid_gas(Gas::from_tgas(300))
            .build());
    }

    fn report(status: &str, data: [u8; 64], debug: bool) -> VerifiedReport {
        let tcb = || TcbStatusWithAdvisory { status: 0, advisory_ids: vec![] };
        let mut attrs = [0u8; 8];
        attrs[0] = debug as u8;
        let mut cfg = [0u8; 48];
        cfg[0] = 1;
        VerifiedReport {
            status: status.into(),
            advisory_ids: vec![],
            report: Report::Td10(TdReport10 {
                tee_tcb_svn: [0; 16],
                mr_seam: [0; 48],
                mr_signer_seam: [0; 48],
                seam_attributes: [0; 8],
                td_attributes: attrs,
                xfam: [0; 8],
                mr_td: [0; 48],
                mr_config_id: cfg,
                mr_owner: [0; 48],
                mr_owner_config: [0; 48],
                rt_mr0: [0; 48],
                rt_mr1: [0; 48],
                rt_mr2: [0; 48],
                rt_mr3: [0; 48],
                report_data: data,
            }),
            ppid: vec![],
            qe_status: tcb(),
            platform_status: tcb(),
        }
    }

    fn bound(key: [u8; 32], nonce: [u8; 32]) -> [u8; 64] {
        let mut d = [0u8; 64];
        d[..32].copy_from_slice(&key);
        d[32..].copy_from_slice(&nonce);
        d
    }

    #[test]
    fn a_bound_up_to_date_report_passes() {
        let (k, n) = ([1u8; 32], [2u8; 32]);
        assert_eq!(check_report(&report("UpToDate", bound(k, n), false), &k, &n), Ok(()));
    }

    #[test]
    fn stale_platforms_fail() {
        let (k, n) = ([1u8; 32], [2u8; 32]);
        assert!(check_report(&report("OutOfDate", bound(k, n), false), &k, &n).is_err());
    }

    #[test]
    fn debug_tds_fail() {
        let (k, n) = ([1u8; 32], [2u8; 32]);
        assert_eq!(check_report(&report("UpToDate", bound(k, n), true), &k, &n), Err("the TD is in debug mode"));
    }

    #[test]
    fn a_quote_for_another_key_or_nonce_fails() {
        let (k, n) = ([1u8; 32], [2u8; 32]);
        let r = report("UpToDate", bound(k, n), false);
        assert!(check_report(&r, &[9u8; 32], &n).is_err());
        assert!(check_report(&r, &k, &[9u8; 32]).is_err());
    }

    /// Mirrors `tee-verifier`'s wire format: a real result captured from the
    /// live contract decodes here.
    #[test]
    fn decodes_a_real_verifier_result() {
        let bytes = include_bytes!("../testdata/verify_quote_result.bin");
        let parsed = VerificationResult::try_from_slice(bytes).expect("borsh mirror matches tee-verifier");
        let VerificationResult::Verified(r) = parsed else { panic!("expected Verified") };
        assert_eq!(r.status, "UpToDate");
        let td = r.report.as_td10().unwrap();
        assert_eq!(td.td_attributes[0] & 1, 0);
    }

    #[test]
    fn nonces_are_single_use() {
        ctx(1_000, NearToken::from_millinear(10));
        let mut reg = Registry::new("tee-verifier.testnet".parse().unwrap());
        let n = reg.new_nonce();
        reg.submit("m".into(), "11".repeat(32), n.clone(), Base64VecU8(vec![1]));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reg.submit("m".into(), "11".repeat(32), n, Base64VecU8(vec![1]));
        }));
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "this nonce has expired")]
    fn expired_nonces_fail() {
        ctx(1_000, NearToken::from_millinear(10));
        let mut reg = Registry::new("tee-verifier.testnet".parse().unwrap());
        let n = reg.new_nonce();
        ctx(1_000 + NONCE_TTL_MS + 1, NearToken::from_millinear(10));
        reg.submit("m".into(), "11".repeat(32), n, Base64VecU8(vec![1]));
    }

    #[test]
    fn empty_lists_are_never_attested() {
        ctx(1_000, NearToken::from_yoctonear(0));
        let reg = Registry::new("tee-verifier.testnet".parse().unwrap());
        assert!(!reg.are_attested(vec![]));
        assert!(!reg.is_attested("11".repeat(32)));
    }
}
