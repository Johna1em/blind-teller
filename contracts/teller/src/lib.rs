//! Blind Teller escrow.
//!
//! A seller locks a token and lists a rate. A buyer takes the offer and pays
//! the seller over an ordinary bank rail. Their bank emails them a receipt, an
//! enclave checks it privately, and this contract releases the token when it
//! sees the enclave's signature over the order's terms.
//!
//! The contract never sees an email, an amount in fiat text, or a name. It
//! learns one thing: a code-bound key says this order was paid.
//!
//! Three checks stand between a verdict and the money:
//!   1. The ed25519 signature covers `terms_hash`, which this contract rebuilds
//!      from its own state, so a verdict can't be moved to another order.
//!   2. The nullifier is single-use, so one bank email can't settle two orders.
//!   3. The model keys must be attested in the registry, checked by the same
//!      `tee-verifier` contract NEAR's MPC network relies on.

use near_sdk::json_types::{U128, U64};
use near_sdk::store::{IterableMap, LookupSet};
use near_sdk::{
    env, ext_contract, log, near, require, serde_json, AccountId, BorshStorageKey, Gas, NearToken,
    PanicOnDefault, Promise, PromiseError, PromiseOrValue,
};
use teller_core::{
    fiat_base, is_hex, is_token, terms_line, verdict_message, Terms, EXTRACTOR_DEV,
    EXTRACTOR_NEAR_AI,
};

const GAS_FT_TRANSFER: Gas = Gas::from_tgas(15);
const GAS_ON_PAID: Gas = Gas::from_tgas(12);
const GAS_REGISTRY: Gas = Gas::from_tgas(8);
const GAS_ON_ATTESTED: Gas = Gas::from_tgas(40);
const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);

/// A proof may land this long after the deadline. Banks email late, and a
/// buyer who paid in time shouldn't lose the order to a slow mail server.
const GRACE_MS: u64 = 15 * 60_000;
/// How far ahead of block time an enclave clock may read.
const CLOCK_SKEW_MS: u64 = 5 * 60_000;
const MAX_WINDOW_MINUTES: u32 = 24 * 60;
const MIN_WINDOW_MINUTES: u32 = 5;
const MAX_TAG: u64 = 99;
const MAX_OPEN_PER_OFFER: usize = 20;
const MAX_SEALED_PAYEE: usize = 1_024;
const MAX_MODEL_KEYS: usize = 3;
const MAX_FEE_BPS: u16 = 200;

#[ext_contract(ext_ft)]
#[allow(dead_code)]
trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[ext_contract(ext_registry)]
#[allow(dead_code)]
trait ModelRegistry {
    fn are_attested(&self, keys: Vec<String>) -> bool;
}

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    Offers,
    Orders,
    Nullifiers,
    OpenAmounts,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderStatus {
    /// Waiting for proof of payment.
    Open,
    /// A verdict passed; the registry check or token transfer is in flight.
    Settling,
    /// The buyer has the token.
    Settled,
    /// The verdict stood but the transfer failed. `retry_payout` finishes it.
    PayoutFailed,
    /// The buyer walked away.
    Cancelled,
    /// The deadline passed unproven.
    Expired,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Offer {
    pub seller: AccountId,
    pub available: U128,
    pub locked: U128,
    /// Fiat minor units per whole token.
    pub rate_minor: U64,
    pub currency: String,
    pub rail: String,
    pub min_amount: U128,
    pub max_amount: U128,
    /// Payment details sealed to the enclave, base64.
    pub sealed_payee: String,
    pub payee_commit: String,
    /// Refundable NEAR bond a buyer attaches, in yoctoNEAR.
    pub buyer_bond: U128,
    pub window_minutes: u32,
    pub open_ids: Vec<U64>,
    pub created_ms: U64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Order {
    pub offer_id: U64,
    pub seller: AccountId,
    pub buyer: AccountId,
    /// X25519 key the seller's payee details are re-sealed to, hex.
    pub buyer_pubkey: String,
    pub token_amount: U128,
    pub currency: String,
    pub fiat_minor: U64,
    pub rail: String,
    pub payee_commit: String,
    pub bond: U128,
    pub created_ms: U64,
    pub deadline_ms: U64,
    pub status: OrderStatus,
    pub nullifier: Option<String>,
    pub extractor: Option<String>,
    pub model_keys: Vec<String>,
    /// The verdict, kept so anyone can re-verify a settled order later.
    pub verdict_signature: Option<String>,
    pub verdict_issued_ms: Option<U64>,
    pub settled_ms: Option<U64>,
}

/// What a seller puts in `msg` of `ft_transfer_call`.
#[near(serializers = [json])]
pub struct NewOffer {
    pub rate_minor: U64,
    pub currency: String,
    pub rail: String,
    pub min_amount: U128,
    pub max_amount: U128,
    pub sealed_payee: String,
    pub payee_commit: String,
    #[serde(default)]
    pub buyer_bond: Option<U128>,
    #[serde(default)]
    pub window_minutes: Option<u32>,
}

/// The enclave's output for a proof that passed.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct Verdict {
    pub nullifier: String,
    pub model_keys: Vec<String>,
    pub extractor: String,
    pub issued_ms: U64,
    /// ed25519 signature, lowercase hex.
    pub signature: String,
}

#[near(serializers = [json])]
pub struct Config {
    pub owner: AccountId,
    pub registry: AccountId,
    pub token: AccountId,
    pub token_decimals: u8,
    pub verdict_key: String,
    pub seal_key: String,
    pub allow_dev: bool,
    pub fee_bps: u16,
    pub fees_accrued: U128,
    pub offers: U64,
    pub orders: U64,
    pub settled: U64,
    pub volume: U128,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Teller {
    owner: AccountId,
    registry: AccountId,
    token: AccountId,
    token_decimals: u8,
    /// The enclave's verdict key, 32 bytes.
    verdict_key: [u8; 32],
    /// The enclave's sealing key, hex. Clients read it here.
    seal_key: String,
    allow_dev: bool,
    fee_bps: u16,
    fees_accrued: u128,
    offers: IterableMap<u64, Offer>,
    orders: IterableMap<u64, Order>,
    nullifiers: LookupSet<String>,
    /// `(offer, fiat_minor)` of open orders, so each amount tags one order.
    open_amounts: LookupSet<(u64, u64)>,
    next_offer: u64,
    next_order: u64,
    settled: u64,
    volume: u128,
}

fn now_ms() -> u64 {
    env::block_timestamp_ms()
}

fn event(name: &str, data: serde_json::Value) {
    log!(
        "EVENT_JSON:{}",
        serde_json::json!({ "standard": "blind-teller", "version": "1.0.0", "event": name, "data": [data] })
    );
}

fn hex32(s: &str, what: &str) -> [u8; 32] {
    require!(is_hex(s, 32), format!("{what} must be 32 bytes of lowercase hex"));
    hex::decode(s).unwrap().try_into().unwrap()
}

#[near]
impl Teller {
    #[init]
    pub fn new(
        owner: AccountId,
        registry: AccountId,
        token: AccountId,
        token_decimals: u8,
        verdict_key: String,
        seal_key: String,
        allow_dev: bool,
        fee_bps: u16,
    ) -> Self {
        require!(fee_bps <= MAX_FEE_BPS, "fee_bps is above the cap");
        require!(token_decimals <= 24, "token_decimals is out of range");
        hex32(&seal_key, "seal_key");
        Self {
            owner,
            registry,
            token,
            token_decimals,
            verdict_key: hex32(&verdict_key, "verdict_key"),
            seal_key,
            allow_dev,
            fee_bps,
            fees_accrued: 0,
            offers: IterableMap::new(StorageKey::Offers),
            orders: IterableMap::new(StorageKey::Orders),
            nullifiers: LookupSet::new(StorageKey::Nullifiers),
            open_amounts: LookupSet::new(StorageKey::OpenAmounts),
            next_offer: 0,
            next_order: 0,
            settled: 0,
            volume: 0,
        }
    }

    /// Rotate to a new enclave release. Open orders then need the new key, which
    /// is why a lock (removing this account's access keys) is the final step.
    pub fn set_enclave_keys(&mut self, verdict_key: String, seal_key: String) {
        self.assert_owner();
        hex32(&seal_key, "seal_key");
        self.verdict_key = hex32(&verdict_key, "verdict_key");
        self.seal_key = seal_key;
        event("enclave_keys_changed", serde_json::json!({ "verdict_key": verdict_key }));
    }

    /// One-way: a production deployment turns the dev extractor off for good.
    pub fn disable_dev(&mut self) {
        self.assert_owner();
        self.allow_dev = false;
    }

    /// NEP-141 receiver. A seller funds an offer with
    /// `ft_transfer_call(amount, msg = NewOffer as JSON)`.
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        require!(env::predecessor_account_id() == self.token, "this token is not accepted");
        require!(amount.0 > 0, "amount must be positive");
        let n: NewOffer = serde_json::from_str(&msg).unwrap_or_else(|_| env::panic_str("msg is not a valid offer"));
        require!(n.rate_minor.0 > 0, "rate_minor must be positive");
        require!(is_token(&n.currency, 8), "currency is not a valid token");
        require!(is_token(&n.rail, 32), "rail is not a valid token");
        require!(n.min_amount.0 > 0 && n.min_amount.0 <= n.max_amount.0, "min_amount and max_amount are out of order");
        require!(!n.sealed_payee.is_empty() && n.sealed_payee.len() <= MAX_SEALED_PAYEE, "sealed_payee has a bad size");
        hex32(&n.payee_commit, "payee_commit");
        let window = n.window_minutes.unwrap_or(30);
        require!((MIN_WINDOW_MINUTES..=MAX_WINDOW_MINUTES).contains(&window), "window_minutes is out of range");

        let id = self.next_offer;
        self.next_offer += 1;
        self.offers.insert(
            id,
            Offer {
                seller: sender_id.clone(),
                available: amount,
                locked: U128(0),
                rate_minor: n.rate_minor,
                currency: n.currency.clone(),
                rail: n.rail.clone(),
                min_amount: n.min_amount,
                max_amount: n.max_amount,
                sealed_payee: n.sealed_payee,
                payee_commit: n.payee_commit,
                buyer_bond: n.buyer_bond.unwrap_or(U128(0)),
                window_minutes: window,
                open_ids: vec![],
                created_ms: U64(now_ms()),
            },
        );
        event(
            "offer_created",
            serde_json::json!({ "offer_id": U64(id), "seller": sender_id, "amount": amount, "currency": n.currency, "rail": n.rail, "rate_minor": n.rate_minor }),
        );
        PromiseOrValue::Value(U128(0))
    }

    /// Lock part of an offer and get an exact fiat amount to pay.
    #[payable]
    pub fn take_offer(&mut self, offer_id: U64, amount: U128, buyer_pubkey: String) -> U64 {
        hex32(&buyer_pubkey, "buyer_pubkey");
        self.sweep(offer_id.0);
        let mut offer = self.offers.get(&offer_id.0).cloned().unwrap_or_else(|| env::panic_str("no such offer"));
        let buyer = env::predecessor_account_id();
        require!(buyer != offer.seller, "you can't take your own offer");
        require!(amount.0 >= offer.min_amount.0 && amount.0 <= offer.max_amount.0, "amount is outside this offer's limits");
        require!(amount.0 <= offer.available.0, "the offer doesn't have that much left");
        require!(offer.open_ids.len() < MAX_OPEN_PER_OFFER, "this offer has too many open orders");
        let bond = env::attached_deposit();
        require!(bond.as_yoctonear() >= offer.buyer_bond.0, "attach the offer's buyer bond");

        let base = fiat_base(amount.0, offer.rate_minor.0, self.token_decimals)
            .unwrap_or_else(|| env::panic_str("the fiat amount is too large"));
        let fiat_minor = (1..=MAX_TAG)
            .map(|tag| base.saturating_add(tag))
            .find(|fiat| !self.open_amounts.contains(&(offer_id.0, *fiat)))
            .unwrap_or_else(|| env::panic_str("no free amount tag on this offer; try again shortly"));

        let id = self.next_order;
        self.next_order += 1;
        offer.available = U128(offer.available.0 - amount.0);
        offer.locked = U128(offer.locked.0 + amount.0);
        offer.open_ids.push(U64(id));

        let created = now_ms();
        let order = Order {
            offer_id,
            seller: offer.seller.clone(),
            buyer: buyer.clone(),
            buyer_pubkey,
            token_amount: amount,
            currency: offer.currency.clone(),
            fiat_minor: U64(fiat_minor),
            rail: offer.rail.clone(),
            payee_commit: offer.payee_commit.clone(),
            bond: U128(bond.as_yoctonear()),
            created_ms: U64(created),
            deadline_ms: U64(created + offer.window_minutes as u64 * 60_000),
            status: OrderStatus::Open,
            nullifier: None,
            extractor: None,
            model_keys: vec![],
            verdict_signature: None,
            verdict_issued_ms: None,
            settled_ms: None,
        };
        self.open_amounts.insert((offer_id.0, fiat_minor));
        self.offers.insert(offer_id.0, offer);
        self.orders.insert(id, order);
        event("order_opened", serde_json::json!({ "order_id": U64(id), "offer_id": offer_id, "buyer": buyer, "amount": amount }));
        U64(id)
    }

    /// Settle an order with the enclave's verdict. Anyone may relay it: the
    /// signature decides, not the sender.
    pub fn settle(&mut self, order_id: U64, verdict: Verdict) -> PromiseOrValue<bool> {
        let mut order = self.order(order_id.0);
        require!(order.status == OrderStatus::Open, "this order isn't open");
        require!(now_ms() <= order.deadline_ms.0 + GRACE_MS, "this order has expired");
        require!(verdict.issued_ms.0 >= order.created_ms.0, "this verdict is older than the order");
        require!(verdict.issued_ms.0 <= now_ms() + CLOCK_SKEW_MS, "this verdict is from the future");
        require!(is_hex(&verdict.nullifier, 32), "bad nullifier");
        require!(verdict.model_keys.len() <= MAX_MODEL_KEYS, "too many model keys");
        verdict.model_keys.iter().for_each(|k| {
            hex32(k, "model key");
        });
        require!(!self.nullifiers.contains(&verdict.nullifier), "this email has already been used");

        let is_dev = verdict.extractor == EXTRACTOR_DEV;
        require!(is_dev || verdict.extractor == EXTRACTOR_NEAR_AI, "unknown extractor");
        require!(!is_dev || self.allow_dev, "the dev extractor is disabled");
        require!(is_dev || !verdict.model_keys.is_empty(), "a model verdict must name its model keys");

        let signature: [u8; 64] = hex::decode(&verdict.signature)
            .ok()
            .and_then(|b| b.try_into().ok())
            .unwrap_or_else(|| env::panic_str("bad signature encoding"));
        let terms_hash = hex::encode(env::sha256(terms_line(&self.terms(order_id.0, &order)).as_bytes()));
        let message = verdict_message(
            env::current_account_id().as_str(),
            order_id.0,
            &terms_hash,
            &verdict.nullifier,
            &verdict.model_keys,
            &verdict.extractor,
            verdict.issued_ms.0,
        );
        require!(env::ed25519_verify(&signature, message.as_bytes(), &self.verdict_key), "the verdict signature is invalid");

        // Reserve the nullifier now: a second settle in the same block must fail.
        self.nullifiers.insert(verdict.nullifier.clone());
        order.status = OrderStatus::Settling;
        order.nullifier = Some(verdict.nullifier.clone());
        order.extractor = Some(verdict.extractor.clone());
        order.model_keys = verdict.model_keys.clone();
        order.verdict_signature = Some(verdict.signature.clone());
        order.verdict_issued_ms = Some(verdict.issued_ms);
        self.orders.insert(order_id.0, order);

        if is_dev {
            return PromiseOrValue::Promise(self.pay(order_id.0));
        }
        PromiseOrValue::Promise(
            ext_registry::ext(self.registry.clone())
                .with_static_gas(GAS_REGISTRY)
                .are_attested(verdict.model_keys)
                .then(Self::ext(env::current_account_id()).with_static_gas(GAS_ON_ATTESTED).on_attested(order_id)),
        )
    }

    /// Finish or unwind a settle after the registry answers.
    #[private]
    pub fn on_attested(
        &mut self,
        order_id: U64,
        #[callback_result] attested: Result<bool, PromiseError>,
    ) -> PromiseOrValue<bool> {
        if matches!(attested, Ok(true)) {
            return PromiseOrValue::Promise(self.pay(order_id.0));
        }
        // Not proven attested: the proof stays unused, so a retry can land once
        // the registry is refreshed. The nullifier goes back with it.
        let mut order = self.order(order_id.0);
        if let Some(n) = order.nullifier.take() {
            self.nullifiers.remove(&n);
        }
        order.status = OrderStatus::Open;
        order.extractor = None;
        order.model_keys = vec![];
        order.verdict_signature = None;
        order.verdict_issued_ms = None;
        self.orders.insert(order_id.0, order);
        event("settle_unwound", serde_json::json!({ "order_id": order_id, "reason": "model key not attested" }));
        PromiseOrValue::Value(false)
    }

    /// Record the transfer's outcome.
    #[private]
    pub fn on_paid(&mut self, order_id: U64, #[callback_result] paid: Result<(), PromiseError>) -> bool {
        let mut order = self.order(order_id.0);
        if paid.is_err() {
            order.status = OrderStatus::PayoutFailed;
            self.orders.insert(order_id.0, order);
            event("payout_failed", serde_json::json!({ "order_id": order_id }));
            return false;
        }
        // A failed payout left the order on its offer, so this runs exactly once
        // whether the transfer worked first time or on a retry.
        order.status = OrderStatus::Settled;
        order.settled_ms = Some(U64(now_ms()));
        self.fees_accrued += self.fee_on(order.token_amount.0);
        self.settled += 1;
        self.volume += order.token_amount.0;
        self.close_order_on_offer(order_id.0, &order);
        let bond = order.bond.0;
        let buyer = order.buyer.clone();
        order.bond = U128(0);
        self.orders.insert(order_id.0, order);
        if bond > 0 {
            Promise::new(buyer).transfer(NearToken::from_yoctonear(bond)).detach();
        }
        event("order_settled", serde_json::json!({ "order_id": order_id }));
        true
    }

    /// Finish a payout that failed, usually because the buyer wasn't registered
    /// with the token. Open to anyone: the receiver is fixed.
    pub fn retry_payout(&mut self, order_id: U64) -> Promise {
        let order = self.order(order_id.0);
        require!(order.status == OrderStatus::PayoutFailed, "this order has no failed payout");
        self.pay(order_id.0)
    }

    /// The buyer gives up. Their bond comes back: they gave the seller's funds
    /// back early, and a buyer who has already paid wouldn't do this.
    pub fn cancel_order(&mut self, order_id: U64) {
        let mut order = self.order(order_id.0);
        require!(env::predecessor_account_id() == order.buyer, "only the buyer can cancel");
        require!(order.status == OrderStatus::Open, "this order isn't open");
        self.release(order_id.0, &order);
        let bond = order.bond.0;
        let buyer = order.buyer.clone();
        order.status = OrderStatus::Cancelled;
        order.bond = U128(0);
        self.orders.insert(order_id.0, order);
        if bond > 0 {
            Promise::new(buyer).transfer(NearToken::from_yoctonear(bond)).detach();
        }
        event("order_cancelled", serde_json::json!({ "order_id": order_id }));
    }

    /// Release an unproven order after its deadline and grace. Open to anyone.
    /// The bond goes to the seller, whose funds sat locked.
    pub fn expire_order(&mut self, order_id: U64) {
        let order = self.order(order_id.0);
        require!(order.status == OrderStatus::Open, "this order isn't open");
        require!(now_ms() > order.deadline_ms.0 + GRACE_MS, "this order hasn't expired");
        self.expire(order_id.0);
    }

    /// The seller takes back whatever isn't locked in an order.
    #[payable]
    pub fn withdraw_offer(&mut self, offer_id: U64) -> Promise {
        near_sdk::assert_one_yocto();
        let mut offer = self.offers.get(&offer_id.0).cloned().unwrap_or_else(|| env::panic_str("no such offer"));
        require!(env::predecessor_account_id() == offer.seller, "only the seller can withdraw");
        let amount = offer.available;
        require!(amount.0 > 0, "nothing to withdraw");
        offer.available = U128(0);
        let seller = offer.seller.clone();
        self.offers.insert(offer_id.0, offer);
        event("offer_withdrawn", serde_json::json!({ "offer_id": offer_id, "amount": amount }));
        ext_ft::ext(self.token.clone())
            .with_attached_deposit(ONE_YOCTO)
            .with_static_gas(GAS_FT_TRANSFER)
            .ft_transfer(seller, amount, Some("blind teller withdrawal".into()))
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_ON_PAID).on_withdrawn(offer_id, amount))
    }

    /// A failed withdrawal puts the funds back on the offer instead of losing them.
    #[private]
    pub fn on_withdrawn(&mut self, offer_id: U64, amount: U128, #[callback_result] sent: Result<(), PromiseError>) {
        if sent.is_err() {
            if let Some(mut offer) = self.offers.get(&offer_id.0).cloned() {
                offer.available = U128(offer.available.0 + amount.0);
                self.offers.insert(offer_id.0, offer);
            }
        }
    }

    /// The owner collects settled fees. Only fees: seller funds aren't reachable.
    #[payable]
    pub fn withdraw_fees(&mut self, receiver: AccountId) -> Promise {
        near_sdk::assert_one_yocto();
        self.assert_owner();
        let amount = self.fees_accrued;
        require!(amount > 0, "no fees to withdraw");
        self.fees_accrued = 0;
        ext_ft::ext(self.token.clone())
            .with_attached_deposit(ONE_YOCTO)
            .with_static_gas(GAS_FT_TRANSFER)
            .ft_transfer(receiver, U128(amount), Some("blind teller fees".into()))
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_ON_PAID).on_fees_withdrawn(U128(amount)))
    }

    #[private]
    pub fn on_fees_withdrawn(&mut self, amount: U128, #[callback_result] sent: Result<(), PromiseError>) {
        if sent.is_err() {
            self.fees_accrued += amount.0;
        }
    }

    // ---- views ----

    pub fn get_config(&self) -> Config {
        Config {
            owner: self.owner.clone(),
            registry: self.registry.clone(),
            token: self.token.clone(),
            token_decimals: self.token_decimals,
            verdict_key: hex::encode(self.verdict_key),
            seal_key: self.seal_key.clone(),
            allow_dev: self.allow_dev,
            fee_bps: self.fee_bps,
            fees_accrued: U128(self.fees_accrued),
            offers: U64(self.next_offer),
            orders: U64(self.next_order),
            settled: U64(self.settled),
            volume: U128(self.volume),
        }
    }

    pub fn get_offer(&self, offer_id: U64) -> Option<Offer> {
        self.offers.get(&offer_id.0).cloned()
    }

    pub fn list_offers(&self, from: Option<U64>, limit: Option<u32>) -> Vec<(U64, Offer)> {
        let from = from.map_or(0, |f| f.0);
        (from..self.next_offer)
            .take(limit.unwrap_or(50).min(100) as usize)
            .filter_map(|id| self.offers.get(&id).map(|o| (U64(id), o.clone())))
            .collect()
    }

    pub fn get_order(&self, order_id: U64) -> Option<Order> {
        self.orders.get(&order_id.0).cloned()
    }

    pub fn list_orders(&self, from: Option<U64>, limit: Option<u32>) -> Vec<(U64, Order)> {
        let from = from.map_or(0, |f| f.0);
        (from..self.next_order)
            .take(limit.unwrap_or(50).min(100) as usize)
            .filter_map(|id| self.orders.get(&id).map(|o| (U64(id), o.clone())))
            .collect()
    }

    /// The canonical line for an order, so anyone can recompute `terms_hash`.
    pub fn get_terms_line(&self, order_id: U64) -> String {
        terms_line(&self.terms(order_id.0, &self.order(order_id.0)))
    }

    pub fn is_nullifier_used(&self, nullifier: String) -> bool {
        self.nullifiers.contains(&nullifier)
    }
}

impl Teller {
    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "only the owner");
    }

    fn order(&self, id: u64) -> Order {
        self.orders.get(&id).cloned().unwrap_or_else(|| env::panic_str("no such order"))
    }

    fn terms(&self, id: u64, o: &Order) -> Terms {
        Terms {
            contract: env::current_account_id().to_string(),
            order_id: id,
            offer_id: o.offer_id.0,
            seller: o.seller.to_string(),
            buyer: o.buyer.to_string(),
            token: self.token.to_string(),
            token_amount: o.token_amount.0,
            currency: o.currency.clone(),
            fiat_minor: o.fiat_minor.0,
            rail: o.rail.clone(),
            payee_commit: o.payee_commit.clone(),
            created_ms: o.created_ms.0,
            deadline_ms: o.deadline_ms.0,
        }
    }

    fn fee_on(&self, amount: u128) -> u128 {
        amount * self.fee_bps as u128 / 10_000
    }

    fn pay(&mut self, order_id: u64) -> Promise {
        let order = self.order(order_id);
        let net = order.token_amount.0 - self.fee_on(order.token_amount.0);
        ext_ft::ext(self.token.clone())
            .with_attached_deposit(ONE_YOCTO)
            .with_static_gas(GAS_FT_TRANSFER)
            .ft_transfer(order.buyer.clone(), U128(net), Some(format!("blind teller order {order_id}")))
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_ON_PAID).on_paid(U64(order_id)))
    }

    /// Take a closed order off its offer without returning funds to it.
    fn close_order_on_offer(&mut self, order_id: u64, order: &Order) {
        if let Some(mut offer) = self.offers.get(&order.offer_id.0).cloned() {
            offer.locked = U128(offer.locked.0 - order.token_amount.0);
            offer.open_ids.retain(|id| id.0 != order_id);
            self.offers.insert(order.offer_id.0, offer);
        }
        self.open_amounts.remove(&(order.offer_id.0, order.fiat_minor.0));
    }

    /// Return an order's funds to its offer.
    fn release(&mut self, order_id: u64, order: &Order) {
        if let Some(mut offer) = self.offers.get(&order.offer_id.0).cloned() {
            offer.available = U128(offer.available.0 + order.token_amount.0);
            offer.locked = U128(offer.locked.0 - order.token_amount.0);
            offer.open_ids.retain(|id| id.0 != order_id);
            self.offers.insert(order.offer_id.0, offer);
        }
        self.open_amounts.remove(&(order.offer_id.0, order.fiat_minor.0));
    }

    /// Close an unproven order. The bond goes to the seller, whose funds sat locked.
    fn expire(&mut self, order_id: u64) {
        let mut order = self.order(order_id);
        self.release(order_id, &order);
        let bond = order.bond.0;
        let seller = order.seller.clone();
        order.status = OrderStatus::Expired;
        order.bond = U128(0);
        self.orders.insert(order_id, order);
        if bond > 0 {
            Promise::new(seller).transfer(NearToken::from_yoctonear(bond)).detach();
        }
        event("order_expired", serde_json::json!({ "order_id": U64(order_id) }));
    }

    /// Clear this offer's lapsed orders, so abandoned orders can't fill its slots
    /// and block the board until someone remembers to expire them.
    fn sweep(&mut self, offer_id: u64) {
        let open = self.offers.get(&offer_id).map_or_else(Vec::new, |o| o.open_ids.clone());
        for id in open {
            let order = self.order(id.0);
            if order.status == OrderStatus::Open && now_ms() > order.deadline_ms.0 + GRACE_MS {
                self.expire(id.0);
            }
        }
    }
}

#[cfg(test)]
mod tests;
