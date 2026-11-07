use super::*;
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;

const T0: u64 = 1_794_000_000_000;

fn acct(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn contract_id() -> AccountId {
    acct("teller.testnet")
}
fn enclave() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn ctx(pred: &str, now_ms: u64, deposit: u128) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(contract_id())
        .predecessor_account_id(acct(pred))
        .signer_account_id(acct(pred))
        .block_timestamp(now_ms * 1_000_000)
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .prepaid_gas(Gas::from_tgas(300))
        .build());
}

fn fresh(allow_dev: bool) -> Teller {
    ctx("owner.testnet", T0, 0);
    Teller::new(
        acct("owner.testnet"),
        acct("models.testnet"),
        acct("usdc.testnet"),
        6,
        hex::encode(enclave().verifying_key().to_bytes()),
        "11".repeat(32),
        allow_dev,
        25,
    )
}

fn offer_msg() -> String {
    serde_json::json!({
        "rate_minor": "8850", "currency": "INR", "rail": "sandbox-upi",
        "min_amount": "1000000", "max_amount": "500000000",
        "sealed_payee": "c2VhbGVk", "payee_commit": "ab".repeat(32),
    })
    .to_string()
}

fn funded(allow_dev: bool) -> Teller {
    let mut t = fresh(allow_dev);
    ctx("usdc.testnet", T0, 0);
    t.ft_on_transfer(acct("seller.testnet"), U128(1_000_000_000), offer_msg());
    t
}

fn with_order(allow_dev: bool) -> (Teller, U64) {
    let mut t = funded(allow_dev);
    ctx("buyer.testnet", T0 + 1_000, 0);
    let id = t.take_offer(U64(0), U128(100_000_000), "22".repeat(32));
    (t, id)
}

fn sign(t: &Teller, id: U64, nullifier: &str, keys: Vec<String>, extractor: &str, issued: u64) -> Verdict {
    let hash = hex::encode(env::sha256(t.get_terms_line(id).as_bytes()));
    let msg = verdict_message(contract_id().as_str(), id.0, &hash, nullifier, &keys, extractor, issued);
    Verdict {
        nullifier: nullifier.into(),
        model_keys: keys,
        extractor: extractor.into(),
        issued_ms: U64(issued),
        signature: hex::encode(enclave().sign(msg.as_bytes()).to_bytes()),
    }
}

fn dev(t: &Teller, id: U64, nullifier: &str) -> Verdict {
    sign(t, id, nullifier, vec![], EXTRACTOR_DEV, T0 + 2_000)
}

#[test]
#[should_panic(expected = "this token is not accepted")]
fn offer_refuses_other_tokens() {
    let mut t = fresh(true);
    ctx("evil.testnet", T0, 0);
    t.ft_on_transfer(acct("seller.testnet"), U128(1), offer_msg());
}

#[test]
fn take_offer_tags_every_open_order_with_a_distinct_amount() {
    let mut t = funded(true);
    ctx("buyer.testnet", T0, 0);
    let a = t.take_offer(U64(0), U128(100_000_000), "22".repeat(32));
    let b = t.take_offer(U64(0), U128(100_000_000), "22".repeat(32));
    let (fa, fb) = (t.get_order(a).unwrap().fiat_minor.0, t.get_order(b).unwrap().fiat_minor.0);
    assert_eq!(fa, 885_001);
    assert_eq!(fb, 885_002);
    let offer = t.get_offer(U64(0)).unwrap();
    assert_eq!(offer.available.0, 800_000_000);
    assert_eq!(offer.locked.0, 200_000_000);
}

#[test]
fn a_released_tag_is_reused() {
    let (mut t, id) = with_order(true);
    ctx("buyer.testnet", T0 + 2_000, 0);
    t.cancel_order(id);
    ctx("buyer.testnet", T0 + 3_000, 0);
    let next = t.take_offer(U64(0), U128(100_000_000), "22".repeat(32));
    assert_eq!(t.get_order(next).unwrap().fiat_minor.0, 885_001);
}

#[test]
#[should_panic(expected = "you can't take your own offer")]
fn sellers_cannot_take_their_own_offer() {
    let mut t = funded(true);
    ctx("seller.testnet", T0, 0);
    t.take_offer(U64(0), U128(100_000_000), "22".repeat(32));
}

#[test]
#[should_panic(expected = "attach the offer's buyer bond")]
fn the_bond_is_enforced() {
    let mut t = fresh(true);
    ctx("usdc.testnet", T0, 0);
    let msg = serde_json::json!({
        "rate_minor": "8850", "currency": "INR", "rail": "sandbox-upi",
        "min_amount": "1000000", "max_amount": "500000000",
        "sealed_payee": "c2VhbGVk", "payee_commit": "ab".repeat(32), "buyer_bond": "1000",
    })
    .to_string();
    t.ft_on_transfer(acct("seller.testnet"), U128(1_000_000_000), msg);
    ctx("buyer.testnet", T0, 999);
    t.take_offer(U64(0), U128(100_000_000), "22".repeat(32));
}

#[test]
fn a_valid_dev_verdict_moves_the_order_to_settling() {
    let (mut t, id) = with_order(true);
    let v = dev(&t, id, &"aa".repeat(32));
    ctx("relayer.testnet", T0 + 3_000, 0);
    t.settle(id, v);
    assert_eq!(t.get_order(id).unwrap().status, OrderStatus::Settling);
    assert!(t.is_nullifier_used("aa".repeat(32)));
}

#[test]
#[should_panic(expected = "the verdict signature is invalid")]
fn a_verdict_for_another_order_is_refused() {
    let (mut t, a) = with_order(true);
    ctx("buyer.testnet", T0 + 1_500, 0);
    let b = t.take_offer(U64(0), U128(100_000_000), "22".repeat(32));
    let v = dev(&t, a, &"aa".repeat(32));
    ctx("buyer.testnet", T0 + 3_000, 0);
    t.settle(b, v);
}

#[test]
#[should_panic(expected = "the verdict signature is invalid")]
fn a_tampered_verdict_is_refused() {
    let (mut t, id) = with_order(true);
    let mut v = dev(&t, id, &"aa".repeat(32));
    v.nullifier = "bb".repeat(32);
    ctx("buyer.testnet", T0 + 3_000, 0);
    t.settle(id, v);
}

#[test]
#[should_panic(expected = "the verdict signature is invalid")]
fn a_stranger_cannot_sign_a_verdict() {
    let (mut t, id) = with_order(true);
    let hash = hex::encode(env::sha256(t.get_terms_line(id).as_bytes()));
    let n = "aa".repeat(32);
    let msg = verdict_message(contract_id().as_str(), id.0, &hash, &n, &[], EXTRACTOR_DEV, T0 + 2_000);
    let v = Verdict {
        nullifier: n,
        model_keys: vec![],
        extractor: EXTRACTOR_DEV.into(),
        issued_ms: U64(T0 + 2_000),
        signature: hex::encode(SigningKey::from_bytes(&[9u8; 32]).sign(msg.as_bytes()).to_bytes()),
    };
    ctx("buyer.testnet", T0 + 3_000, 0);
    t.settle(id, v);
}

#[test]
#[should_panic(expected = "this email has already been used")]
fn one_email_cannot_settle_two_orders() {
    let (mut t, a) = with_order(true);
    ctx("buyer.testnet", T0 + 1_500, 0);
    let b = t.take_offer(U64(0), U128(100_000_000), "22".repeat(32));
    let n = "aa".repeat(32);
    let (va, vb) = (dev(&t, a, &n), dev(&t, b, &n));
    ctx("buyer.testnet", T0 + 3_000, 0);
    t.settle(a, va);
    t.settle(b, vb);
}

#[test]
#[should_panic(expected = "the dev extractor is disabled")]
fn the_dev_extractor_is_refused_in_production() {
    let (mut t, id) = with_order(false);
    let v = dev(&t, id, &"aa".repeat(32));
    ctx("buyer.testnet", T0 + 3_000, 0);
    t.settle(id, v);
}

#[test]
#[should_panic(expected = "a model verdict must name its model keys")]
fn a_model_verdict_must_name_keys() {
    let (mut t, id) = with_order(false);
    let v = sign(&t, id, &"aa".repeat(32), vec![], EXTRACTOR_NEAR_AI, T0 + 2_000);
    ctx("buyer.testnet", T0 + 3_000, 0);
    t.settle(id, v);
}

#[test]
#[should_panic(expected = "this verdict is older than the order")]
fn a_verdict_cannot_predate_the_order() {
    let (mut t, id) = with_order(true);
    let v = sign(&t, id, &"aa".repeat(32), vec![], EXTRACTOR_DEV, T0 - 1);
    ctx("buyer.testnet", T0 + 3_000, 0);
    t.settle(id, v);
}

#[test]
#[should_panic(expected = "this order has expired")]
fn an_order_cannot_settle_after_its_grace() {
    let (mut t, id) = with_order(true);
    let v = dev(&t, id, &"aa".repeat(32));
    let deadline = t.get_order(id).unwrap().deadline_ms.0;
    ctx("buyer.testnet", deadline + GRACE_MS + 1, 0);
    t.settle(id, v);
}

#[test]
fn a_proof_inside_the_grace_period_still_lands() {
    let (mut t, id) = with_order(true);
    let v = dev(&t, id, &"aa".repeat(32));
    let deadline = t.get_order(id).unwrap().deadline_ms.0;
    ctx("buyer.testnet", deadline + GRACE_MS, 0);
    t.settle(id, v);
    assert_eq!(t.get_order(id).unwrap().status, OrderStatus::Settling);
}

#[test]
fn cancelling_returns_the_funds_to_the_offer() {
    let (mut t, id) = with_order(true);
    ctx("buyer.testnet", T0 + 2_000, 0);
    t.cancel_order(id);
    let offer = t.get_offer(U64(0)).unwrap();
    assert_eq!(offer.available.0, 1_000_000_000);
    assert_eq!(offer.locked.0, 0);
    assert!(offer.open_ids.is_empty());
    assert_eq!(t.get_order(id).unwrap().status, OrderStatus::Cancelled);
}

#[test]
fn abandoned_orders_are_swept_so_they_cannot_block_the_board() {
    let mut t = funded(true);
    ctx("buyer.testnet", T0, 0);
    for _ in 0..MAX_OPEN_PER_OFFER {
        t.take_offer(U64(0), U128(1_000_000), "22".repeat(32));
    }
    assert_eq!(t.get_offer(U64(0)).unwrap().open_ids.len(), MAX_OPEN_PER_OFFER);
    let lapsed = t.get_order(U64(0)).unwrap().deadline_ms.0 + GRACE_MS + 1;
    ctx("buyer.testnet", lapsed, 0);
    let next = t.take_offer(U64(0), U128(1_000_000), "22".repeat(32));
    let offer = t.get_offer(U64(0)).unwrap();
    assert_eq!(offer.open_ids, vec![next]);
    assert_eq!(offer.locked.0, 1_000_000);
    assert_eq!(t.get_order(U64(0)).unwrap().status, OrderStatus::Expired);
}

#[test]
#[should_panic(expected = "this offer has too many open orders")]
fn live_orders_are_not_swept() {
    let mut t = funded(true);
    ctx("buyer.testnet", T0, 0);
    for _ in 0..=MAX_OPEN_PER_OFFER {
        t.take_offer(U64(0), U128(1_000_000), "22".repeat(32));
    }
}

#[test]
fn a_settled_order_keeps_its_verdict_for_anyone_to_recheck() {
    let (mut t, id) = with_order(true);
    let v = dev(&t, id, &"aa".repeat(32));
    ctx("relayer.testnet", T0 + 3_000, 0);
    t.settle(id, v.clone());
    let o = t.get_order(id).unwrap();
    assert_eq!(o.verdict_signature, Some(v.signature));
    assert_eq!(o.verdict_issued_ms, Some(v.issued_ms));
}

/// Drive `on_paid` the way the runtime does, with the transfer's outcome set.
fn paid(t: &mut Teller, id: U64, ok: bool) -> bool {
    use near_sdk::PromiseResult;
    let result = if ok { PromiseResult::Successful(vec![]) } else { PromiseResult::Failed };
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(contract_id())
            .predecessor_account_id(contract_id())
            .block_timestamp((T0 + 4_000) * 1_000_000)
            .prepaid_gas(Gas::from_tgas(100))
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![result]
    );
    t.on_paid(id, if ok { Ok(()) } else { Err(PromiseError::Failed) })
}

#[test]
fn a_failed_payout_can_be_retried_and_still_closes_the_order() {
    let (mut t, id) = with_order(true);
    let v = dev(&t, id, &"aa".repeat(32));
    ctx("relayer.testnet", T0 + 3_000, 0);
    t.settle(id, v);
    assert!(!paid(&mut t, id, false));
    assert_eq!(t.get_order(id).unwrap().status, OrderStatus::PayoutFailed);
    assert_eq!(t.get_config().settled.0, 0);

    assert!(paid(&mut t, id, true));
    let order = t.get_order(id).unwrap();
    assert_eq!(order.status, OrderStatus::Settled);
    let offer = t.get_offer(U64(0)).unwrap();
    assert_eq!(offer.locked.0, 0, "the lock must clear on a retry too");
    assert!(offer.open_ids.is_empty());
    assert_eq!(t.get_config().settled.0, 1);
    assert_eq!(t.get_config().fees_accrued.0, 250_000);
}

#[test]
fn a_seller_can_only_withdraw_what_is_unlocked() {
    let (mut t, _) = with_order(true);
    ctx("seller.testnet", T0 + 2_000, 1);
    t.withdraw_offer(U64(0));
    let offer = t.get_offer(U64(0)).unwrap();
    assert_eq!(offer.available.0, 0);
    assert_eq!(offer.locked.0, 100_000_000);
}

#[test]
#[should_panic(expected = "only the seller can withdraw")]
fn a_stranger_cannot_withdraw_an_offer() {
    let mut t = funded(true);
    ctx("evil.testnet", T0, 1);
    t.withdraw_offer(U64(0));
}

#[test]
#[should_panic(expected = "only the owner")]
fn a_stranger_cannot_take_the_fees() {
    let mut t = funded(true);
    ctx("evil.testnet", T0, 1);
    t.withdraw_fees(acct("evil.testnet"));
}

#[test]
#[should_panic(expected = "only the buyer can cancel")]
fn a_stranger_cannot_cancel() {
    let (mut t, id) = with_order(true);
    ctx("seller.testnet", T0 + 2_000, 0);
    t.cancel_order(id);
}

#[test]
#[should_panic(expected = "this order hasn't expired")]
fn nobody_can_expire_a_live_order() {
    let (mut t, id) = with_order(true);
    let deadline = t.get_order(id).unwrap().deadline_ms.0;
    ctx("anyone.testnet", deadline + GRACE_MS, 0);
    t.expire_order(id);
}

#[test]
fn an_expired_order_goes_back_to_the_seller() {
    let (mut t, id) = with_order(true);
    let deadline = t.get_order(id).unwrap().deadline_ms.0;
    ctx("anyone.testnet", deadline + GRACE_MS + 1, 0);
    t.expire_order(id);
    assert_eq!(t.get_offer(U64(0)).unwrap().available.0, 1_000_000_000);
    assert_eq!(t.get_order(id).unwrap().status, OrderStatus::Expired);
}

#[test]
#[should_panic(expected = "this order isn't open")]
fn a_settled_order_cannot_be_cancelled() {
    let (mut t, id) = with_order(true);
    let v = dev(&t, id, &"aa".repeat(32));
    ctx("buyer.testnet", T0 + 3_000, 0);
    t.settle(id, v);
    t.cancel_order(id);
}

#[test]
#[should_panic(expected = "fee_bps is above the cap")]
fn fees_are_capped() {
    ctx("owner.testnet", T0, 0);
    Teller::new(acct("o.testnet"), acct("m.testnet"), acct("u.testnet"), 6, "33".repeat(32), "11".repeat(32), true, 201);
}

#[test]
#[should_panic(expected = "only the owner")]
fn strangers_cannot_rotate_keys() {
    let mut t = fresh(true);
    ctx("evil.testnet", T0, 0);
    t.set_enclave_keys("33".repeat(32), "44".repeat(32));
}

#[test]
fn the_terms_line_matches_the_shared_format() {
    let (t, id) = with_order(true);
    let line = t.get_terms_line(id);
    let o = t.get_order(id).unwrap();
    assert!(line.starts_with("blind-teller/v1|terms|teller.testnet|0|0|seller.testnet|buyer.testnet|usdc.testnet|100000000|INR|885001|sandbox-upi|"));
    assert!(line.ends_with(&format!("|{}|{}", o.created_ms.0, o.deadline_ms.0)));
}
