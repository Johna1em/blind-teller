//! Holds the browser's sandbox bank to the Rust verifier. These `.eml` files are
//! written by TypeScript (`npm run fixtures`) and read here, so a canonicalization
//! bug on either side fails this test instead of a live demo.

#![cfg(feature = "dev-extractor")]

use base64::{engine::general_purpose::STANDARD, Engine};
use enclave::checks::{evaluate, Payee};
use enclave::{devrules, dkim, mime, policy};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../fixtures/sandbox/{name}.eml", env!("CARGO_MANIFEST_DIR"))).expect("run `npm run fixtures` in web/")
}

fn sandbox_key() -> Vec<u8> {
    STANDARD.decode(policy::SANDBOX_KEY_DER_B64.trim()).unwrap()
}

fn check(name: &str, domain: &str, currency: &str) {
    let raw = fixture(name);
    let v = dkim::verify(&raw, 2048, |_, _| Ok(sandbox_key())).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    assert_eq!(v.domain, domain);
    assert_eq!(v.signed_at, Some(1_794_045_660));

    let text = mime::authenticated_text(&v);
    let reading = devrules::read(&text).unwrap();
    assert_eq!(reading.status, "success", "{name}");
    assert_eq!(reading.direction, "debit", "{name}");
    assert_eq!(reading.currency, currency, "{name}");
    let payee = Payee { handle: "asha.rao@meridian".into(), name: String::new(), account_tail: String::new() };
    assert_eq!(evaluate(&text, &[reading], currency, 885_037, &payee), Ok(()), "{name}: {text}");
}

#[test]
fn english_upi_receipt() {
    check("meridian", "alerts.meridianbank.example", "INR");
}

#[test]
fn portuguese_pix_receipt() {
    check("aurora", "avisos.bancoaurora.example", "BRL");
}

#[test]
fn german_sepa_receipt() {
    check("rhein", "service.rheinbank.example", "EUR");
}

#[test]
fn a_utf8_subject_survives_the_round_trip() {
    let v = dkim::verify(&fixture("rhein"), 2048, |_, _| Ok(sandbox_key())).unwrap();
    assert!(mime::authenticated_text(&v).contains("Echtzeitüberweisung"));
}
