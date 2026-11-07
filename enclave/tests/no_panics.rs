//! Email and model replies are untrusted, and in wasm a panic kills the run. A
//! crash fails closed, but it refuses an honest buyer with no reason given. So
//! everything that parses untrusted text gets thrown a lot of hostile text here.

use enclave::checks::{evaluate, marked_amounts, numbers_in, Extraction, Payee};
use enclave::dkim::{self, DkimError, Verified};
use enclave::mime::authenticated_text;
use enclave::nearai::parse_reply;

const RUNS: usize = 20_000;

/// Each piece has broken a parser somewhere: boundaries, entities, encoded words,
/// characters that change length when lowercased, and bytes that look like syntax.
const PIECES: &[&str] = &[
    "&", ";", "<", ">", "</", "<!--", "-->", "=", "=?", "?=", "?", "&#8377;", "&amp", "&#xZZ;", "é", "₹", "日本", "🙂", "İ", "\u{212a}", "ß", "\u{200b}",
    "a", "1", ",", ".", "8,850.37", " ", "\t", "\r\n", "\r\n\r\n", "\n", "--", "--b", "Rs.", "INR", "{", "}", "\"", "\\", ":", "<div style=\"display:none\">",
    "</div>", "<td", "=?utf-8?b?", "=?utf-8?q?", "=E2=82", "=\r\n", "From:", "DKIM-Signature: v=1; a=rsa-sha256; d=x; s=y; b=z; bh=z; h=from",
    "Content-Type: multipart/mixed; boundary=b", "Content-Transfer-Encoding: base64",
];

/// A small repeatable generator, so a failure here is the same failure every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 16) as usize
    }

    fn text(&mut self, pieces: usize) -> String {
        let count = self.next() % pieces;
        (0..count).map(|_| PIECES[self.next() % PIECES.len()]).collect()
    }
}

#[test]
fn text_rules_survive_anything() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let payee = Payee { handle: "asha.rao@meridian".into(), name: "Asha Rao".into(), account_tail: "4021".into() };
    for _ in 0..RUNS {
        let text = rng.text(40);
        let _ = numbers_in(&text);
        let _ = marked_amounts(&text, "INR");
        let reading = Extraction { status: "success".into(), direction: "debit".into(), amount: rng.text(4), currency: "INR".into(), recipient: rng.text(4), note: rng.text(8), balance: rng.text(4), injection: false };
        let _ = evaluate(&text, &[reading.clone(), reading], "INR", 885_037, &payee);
    }
}

#[test]
fn model_replies_survive_anything() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..RUNS {
        let _ = parse_reply(&rng.text(40));
    }
}

#[test]
fn email_parsers_survive_anything() {
    let mut rng = Rng(0xd1b5_4a32_d192_ed03);
    for _ in 0..RUNS {
        let raw = rng.text(40);
        let _ = dkim::verify(raw.as_bytes(), 2048, |_, _| Err(DkimError::KeyMissing));
    }
}

#[test]
fn text_extraction_survives_anything() {
    let mut rng = Rng(0xa076_1d64_78bd_642f);
    let types = ["text/plain; charset=utf-8", "text/html; charset=utf-8", "multipart/alternative; boundary=b", "multipart/mixed; boundary=\"b\"", "application/pdf"];
    let encodings = ["7bit", "quoted-printable", "base64"];
    for _ in 0..RUNS {
        let verified = Verified {
            domain: "x.example".into(),
            selector: "s".into(),
            signed_at: None,
            signature: vec![],
            headers: vec![
                ("subject".into(), rng.text(6)),
                ("content-type".into(), types[rng.next() % types.len()].into()),
                ("content-transfer-encoding".into(), encodings[rng.next() % encodings.len()].into()),
            ],
            body: rng.text(40).into_bytes(),
        };
        let _ = authenticated_text(&verified);
    }
}
