//! DKIM verification (RFC 6376), written for an adversary who controls the
//! whole message except the signature.
//!
//! The classic attacks are refused by construction:
//!   * `l=` body-length tag: lets anyone append content below the signed part.
//!   * Prepended headers: a second `From:` above the signed one. Any covered
//!     header that appears more often than the signature lists it is refused.
//!   * Unsigned `Content-Type`: Gmail and others leave it unsigned, so refusing
//!     would refuse real mail. Instead an unsigned header doesn't exist: `Verified`
//!     carries signed headers only, and `mime` reads framing from the signed body.
//!   * Unsigned `From`: the domain would mean nothing.
//!   * Weak keys: RSA under 2048 bits needs an explicit issuer exception.
//!
//! The result exposes only signed headers. A caller can't read an unsigned value
//! by mistake, because it never gets one.

use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};

/// Headers that change how a reader understands the message. Each must appear
/// no more often than the signature covers it.
const SINGLETONS: &[&str] = &["from", "to", "subject", "date", "reply-to", "sender", "content-type", "content-transfer-encoding", "mime-version"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimError {
    Malformed,
    NoSignature,
    UnsupportedAlgorithm,
    BodyLengthTag,
    FromUnsigned,
    DuplicateHeader,
    BodyHashMismatch,
    KeyMissing,
    KeyRevoked,
    KeyWeak,
    BadSignature,
    FromNotAligned,
}

impl DkimError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "dkim_malformed",
            Self::NoSignature => "dkim_missing",
            Self::UnsupportedAlgorithm => "dkim_algorithm",
            Self::BodyLengthTag => "dkim_length_tag",
            Self::FromUnsigned => "dkim_from_unsigned",
            Self::DuplicateHeader => "dkim_duplicate_header",
            Self::BodyHashMismatch => "dkim_body_hash",
            Self::KeyMissing => "dkim_key_missing",
            Self::KeyRevoked => "dkim_key_revoked",
            Self::KeyWeak => "dkim_key_weak",
            Self::BadSignature => "dkim_signature",
            Self::FromNotAligned => "dkim_alignment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Canon {
    Simple,
    Relaxed,
}

#[derive(Debug, Clone)]
pub struct Header {
    /// Lowercased name.
    pub name: String,
    /// Exact bytes, from the name through the final CRLF.
    pub raw: Vec<u8>,
}

impl Header {
    /// The unfolded value, trimmed.
    pub fn value(&self) -> String {
        let text = String::from_utf8_lossy(&self.raw);
        let after = text.split_once(':').map_or("", |(_, v)| v);
        after.replace("\r\n", "").replace('\n', "").trim().to_string()
    }
}

/// A message that passed verification. Holds only authenticated content.
#[derive(Debug, Clone)]
pub struct Verified {
    /// `d=`, lowercased.
    pub domain: String,
    pub selector: String,
    /// `t=` in seconds, when the signer set one.
    pub signed_at: Option<u64>,
    /// The raw `b=` bytes, unique to this signature. Feeds the nullifier.
    pub signature: Vec<u8>,
    /// Covered headers only, in signature order.
    pub headers: Vec<(String, String)>,
    /// The canonical body exactly as hashed.
    pub body: Vec<u8>,
}

impl Verified {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

/// Turn bare LF into CRLF so mail saved by any client hashes the same.
pub fn normalize(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 64);
    for (i, &b) in raw.iter().enumerate() {
        if b == b'\n' && (i == 0 || raw[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

/// Split into headers and body. The body starts after the first blank line.
pub fn split(raw: &[u8]) -> Result<(Vec<Header>, Vec<u8>), DkimError> {
    let mut headers: Vec<Header> = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let end = find_crlf(raw, i).ok_or(DkimError::Malformed)?;
        let line = &raw[i..end + 2];
        if line == b"\r\n" {
            return Ok((headers, raw[end + 2..].to_vec()));
        }
        if line[0] == b' ' || line[0] == b'\t' {
            headers.last_mut().ok_or(DkimError::Malformed)?.raw.extend_from_slice(line);
        } else {
            let colon = line.iter().position(|&b| b == b':').ok_or(DkimError::Malformed)?;
            let name = String::from_utf8_lossy(&line[..colon]).trim().to_ascii_lowercase();
            if name.is_empty() {
                return Err(DkimError::Malformed);
            }
            headers.push(Header { name, raw: line.to_vec() });
        }
        i = end + 2;
    }
    Err(DkimError::Malformed)
}

fn find_crlf(b: &[u8], from: usize) -> Option<usize> {
    b[from..].windows(2).position(|w| w == b"\r\n").map(|p| p + from)
}

fn parse_tags(value: &str) -> Vec<(String, String)> {
    value
        .split(';')
        .filter_map(|t| {
            let (k, v) = t.split_once('=')?;
            Some((k.trim().to_string(), v.chars().filter(|c| !c.is_whitespace()).collect()))
        })
        .collect()
}

fn tag<'a>(tags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    tags.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn canon_body(body: &[u8], c: Canon) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = body
        .split_inclusive(|&b| b == b'\n')
        .map(|l| {
            let l = l.strip_suffix(b"\r\n").or_else(|| l.strip_suffix(b"\n")).unwrap_or(l);
            match c {
                Canon::Simple => l.to_vec(),
                Canon::Relaxed => compress_wsp(l, true),
            }
        })
        .collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let mut out = Vec::with_capacity(body.len());
    for l in &lines {
        out.extend_from_slice(l);
        out.extend_from_slice(b"\r\n");
    }
    if out.is_empty() && c == Canon::Simple {
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn compress_wsp(line: &[u8], trim_end: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut in_wsp = false;
    for &b in line {
        if b == b' ' || b == b'\t' {
            in_wsp = true;
        } else {
            if in_wsp {
                out.push(b' ');
            }
            in_wsp = false;
            out.push(b);
        }
    }
    if in_wsp && !trim_end {
        out.push(b' ');
    }
    out
}

fn canon_header(h: &[u8], c: Canon) -> Vec<u8> {
    if c == Canon::Simple {
        return h.to_vec();
    }
    let colon = h.iter().position(|&b| b == b':').unwrap_or(h.len());
    let name: Vec<u8> = h[..colon].iter().filter(|b| !b" \t".contains(b)).map(u8::to_ascii_lowercase).collect();
    let unfolded: Vec<u8> = h[(colon + 1).min(h.len())..].iter().copied().filter(|b| !b"\r\n".contains(b)).collect();
    let value = compress_wsp(&unfolded, true);
    let start = usize::from(value.first() == Some(&b' '));
    let mut out = name;
    out.push(b':');
    out.extend_from_slice(&value[start..]);
    out.extend_from_slice(b"\r\n");
    out
}

/// The DKIM-Signature header with its `b=` value emptied, as RFC 6376 signs it.
fn blank_b_tag(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    let colon = raw.iter().position(|&b| b == b':').unwrap_or(0);
    out.extend_from_slice(&raw[..=colon]);
    i += colon + 1;
    let mut at_tag_start = true;
    while i < raw.len() {
        let b = raw[i];
        if at_tag_start {
            let mut j = i;
            while j < raw.len() && b" \t\r\n".contains(&raw[j]) {
                j += 1;
            }
            if j < raw.len() && raw[j] == b'b' {
                let mut k = j + 1;
                while k < raw.len() && b" \t\r\n".contains(&raw[k]) {
                    k += 1;
                }
                if k < raw.len() && raw[k] == b'=' {
                    out.extend_from_slice(&raw[i..=k]);
                    i = k + 1;
                    while i < raw.len() && raw[i] != b';' && !(raw[i] == b'\r' && i + 2 >= raw.len()) {
                        i += 1;
                    }
                    at_tag_start = false;
                    continue;
                }
            }
            at_tag_start = false;
        }
        out.push(b);
        if b == b';' {
            at_tag_start = true;
        }
        i += 1;
    }
    out
}

fn from_domain(value: &str) -> Option<String> {
    let addr = match (value.rfind('<'), value.rfind('>')) {
        (Some(a), Some(b)) if a < b => &value[a + 1..b],
        _ => value,
    };
    if addr.matches('@').count() != 1 && !value.contains('<') {
        return None;
    }
    let domain = addr.rsplit('@').next()?.trim().trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty() && domain.contains('.') && !domain.contains(' ')).then_some(domain)
}

/// Relaxed alignment: From is the signing domain or a subdomain of it.
fn aligned(from: &str, d: &str) -> bool {
    from == d || from.ends_with(&format!(".{d}"))
}

/// Parse a DNS TXT record's `p=` key. An empty `p=` means revoked.
pub fn parse_key_record(txt: &str) -> Result<Vec<u8>, DkimError> {
    let tags = parse_tags(txt);
    if let Some(k) = tag(&tags, "k") {
        if !k.eq_ignore_ascii_case("rsa") {
            return Err(DkimError::UnsupportedAlgorithm);
        }
    }
    let p = tag(&tags, "p").ok_or(DkimError::KeyMissing)?;
    if p.is_empty() {
        return Err(DkimError::KeyRevoked);
    }
    STANDARD.decode(p).map_err(|_| DkimError::KeyMissing)
}

fn rsa_key(der: &[u8], min_bits: usize) -> Result<RsaPublicKey, DkimError> {
    let key = RsaPublicKey::from_public_key_der(der)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(der))
        .map_err(|_| DkimError::KeyMissing)?;
    if key.size() * 8 < min_bits {
        return Err(DkimError::KeyWeak);
    }
    Ok(key)
}

/// Verify one message. `key_lookup(domain, selector)` returns a DER public key.
/// `min_bits` is the weakest RSA key this issuer may use.
///
/// Tries each DKIM-Signature in order: mail often carries one from the sender
/// and one from a relay, and a relay's signature proves nothing here. So a
/// signature counts only if it is aligned with From.
pub fn verify<F>(raw: &[u8], min_bits: usize, mut key_lookup: F) -> Result<Verified, DkimError>
where
    F: FnMut(&str, &str) -> Result<Vec<u8>, DkimError>,
{
    let normalized = normalize(raw);
    let (headers, body) = split(&normalized)?;
    let signatures: Vec<&Header> = headers.iter().filter(|h| h.name == "dkim-signature").collect();
    if signatures.is_empty() {
        return Err(DkimError::NoSignature);
    }
    let mut first_error = None;
    for sig in signatures {
        match verify_one(sig, &headers, &body, min_bits, &mut key_lookup) {
            Ok(v) => return Ok(v),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error.unwrap_or(DkimError::NoSignature))
}

fn verify_one<F>(sig: &Header, headers: &[Header], body: &[u8], min_bits: usize, key_lookup: &mut F) -> Result<Verified, DkimError>
where
    F: FnMut(&str, &str) -> Result<Vec<u8>, DkimError>,
{
    let tags = parse_tags(&sig.value());
    if tag(&tags, "v") != Some("1") {
        return Err(DkimError::Malformed);
    }
    if !tag(&tags, "a").is_some_and(|a| a.eq_ignore_ascii_case("rsa-sha256")) {
        return Err(DkimError::UnsupportedAlgorithm);
    }
    if tag(&tags, "l").is_some() {
        return Err(DkimError::BodyLengthTag);
    }
    let d = tag(&tags, "d").ok_or(DkimError::Malformed)?.to_ascii_lowercase();
    let s = tag(&tags, "s").ok_or(DkimError::Malformed)?.to_string();
    let bh = STANDARD.decode(tag(&tags, "bh").ok_or(DkimError::Malformed)?).map_err(|_| DkimError::Malformed)?;
    let b = STANDARD.decode(tag(&tags, "b").ok_or(DkimError::Malformed)?).map_err(|_| DkimError::Malformed)?;
    let covered: Vec<String> = tag(&tags, "h")
        .ok_or(DkimError::Malformed)?
        .split(':')
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    let (ch, cb) = match tag(&tags, "c").unwrap_or("simple/simple").to_ascii_lowercase().as_str() {
        "simple" | "simple/simple" => (Canon::Simple, Canon::Simple),
        "simple/relaxed" => (Canon::Simple, Canon::Relaxed),
        "relaxed" | "relaxed/simple" => (Canon::Relaxed, Canon::Simple),
        "relaxed/relaxed" => (Canon::Relaxed, Canon::Relaxed),
        _ => return Err(DkimError::Malformed),
    };

    // Policy checks first: they need no key, so a forged message costs no lookup.
    if !covered.iter().any(|h| h == "from") {
        return Err(DkimError::FromUnsigned);
    }
    for name in SINGLETONS {
        let present = headers.iter().filter(|h| h.name == *name).count();
        let signed = covered.iter().filter(|h| h == name).count();
        if present > 1 && present > signed {
            return Err(DkimError::DuplicateHeader);
        }
    }

    let canon = canon_body(body, cb);
    if Sha256::digest(&canon).as_slice() != bh.as_slice() {
        return Err(DkimError::BodyHashMismatch);
    }

    // RFC 6376 §5.4.2: each name consumes the last unused instance, bottom up.
    let mut used = vec![false; headers.len()];
    let mut signed_data = Vec::new();
    let mut authenticated = Vec::new();
    for name in &covered {
        if let Some(i) = (0..headers.len()).rev().find(|&i| !used[i] && headers[i].name == *name) {
            used[i] = true;
            signed_data.extend_from_slice(&canon_header(&headers[i].raw, ch));
            authenticated.push((name.clone(), headers[i].value()));
        }
    }
    let blanked = canon_header(&blank_b_tag(&sig.raw), ch);
    signed_data.extend_from_slice(blanked.strip_suffix(b"\r\n").unwrap_or(&blanked));

    let from = authenticated.iter().find(|(n, _)| n == "from").ok_or(DkimError::FromUnsigned)?;
    let from_d = from_domain(&from.1).ok_or(DkimError::Malformed)?;
    if !aligned(&from_d, &d) {
        return Err(DkimError::FromNotAligned);
    }

    let der = key_lookup(&d, &s)?;
    let key = rsa_key(&der, min_bits)?;
    let signature = Signature::try_from(b.as_slice()).map_err(|_| DkimError::BadSignature)?;
    VerifyingKey::<Sha256>::new(key).verify(&signed_data, &signature).map_err(|_| DkimError::BadSignature)?;

    Ok(Verified {
        domain: d,
        selector: s,
        signed_at: tag(&tags, "t").and_then(|t| t.parse().ok()),
        signature: b,
        headers: authenticated,
        body: canon,
    })
}

/// Signing, for tests and the sandbox bank's fixtures. The real path never signs.
#[cfg(any(test, feature = "dev-extractor"))]
pub mod sign {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;

    /// Sign with relaxed/relaxed, covering `covered` headers.
    pub fn dkim_sign(raw: &[u8], domain: &str, selector: &str, key: &RsaPrivateKey, covered: &[&str], timestamp: u64) -> Vec<u8> {
        let normalized = normalize(raw);
        let (headers, body) = split(&normalized).unwrap();
        let bh = STANDARD.encode(Sha256::digest(canon_body(&body, Canon::Relaxed)));
        let h = covered.join(":");
        let draft = format!("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; t={timestamp}; h={h}; bh={bh}; b=\r\n");
        let mut used = vec![false; headers.len()];
        let mut signed = Vec::new();
        for name in covered {
            let name = name.to_ascii_lowercase();
            if let Some(i) = (0..headers.len()).rev().find(|&i| !used[i] && headers[i].name == name) {
                used[i] = true;
                signed.extend_from_slice(&canon_header(&headers[i].raw, Canon::Relaxed));
            }
        }
        let blank = canon_header(draft.as_bytes(), Canon::Relaxed);
        signed.extend_from_slice(blank.strip_suffix(b"\r\n").unwrap());
        let sig = SigningKey::<Sha256>::new(key.clone()).sign(&signed).to_vec();
        let header = format!("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; t={timestamp}; h={h}; bh={bh}; b={}\r\n", STANDARD.encode(sig));
        let mut out = header.into_bytes();
        out.extend_from_slice(&normalized);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::sign::dkim_sign;
    use super::*;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::RsaPrivateKey;
    use std::sync::OnceLock;

    fn keypair() -> &'static (RsaPrivateKey, Vec<u8>) {
        static KEY: OnceLock<(RsaPrivateKey, Vec<u8>)> = OnceLock::new();
        KEY.get_or_init(|| {
            let k = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
            let der = k.to_public_key().to_public_key_der().unwrap().as_bytes().to_vec();
            (k, der)
        })
    }

    const MAIL: &str = "From: Meridian Bank <alerts@meridian.example>\r\nTo: buyer@mail.example\r\nSubject: Payment sent\r\nDate: Sat, 07 Nov 2026 10:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\nMessage-ID: <1@meridian.example>\r\n\r\nINR 8,850.37 debited.\r\n";
    const COVERED: &[&str] = &["from", "to", "subject", "date", "content-type", "message-id"];

    fn signed(mail: &str) -> Vec<u8> {
        dkim_sign(mail.as_bytes(), "meridian.example", "s1", &keypair().0, COVERED, 1_794_000_000)
    }
    fn lookup(_: &str, _: &str) -> Result<Vec<u8>, DkimError> {
        Ok(keypair().1.clone())
    }

    #[test]
    fn a_signed_message_verifies() {
        let v = verify(&signed(MAIL), 2048, lookup).unwrap();
        assert_eq!(v.domain, "meridian.example");
        assert_eq!(v.header("subject"), Some("Payment sent"));
        assert_eq!(v.signed_at, Some(1_794_000_000));
        assert!(!v.signature.is_empty());
    }

    #[test]
    fn bare_lf_mail_verifies() {
        let m = String::from_utf8(signed(MAIL)).unwrap().replace("\r\n", "\n");
        verify(m.as_bytes(), 2048, lookup).unwrap();
    }

    #[test]
    fn folded_headers_survive_relaxed_canonicalization() {
        let m = String::from_utf8(signed(MAIL)).unwrap().replace("Subject: Payment sent", "Subject:   Payment\r\n\t sent");
        verify(m.as_bytes(), 2048, lookup).unwrap();
    }

    #[test]
    fn an_edited_body_fails() {
        let m = String::from_utf8(signed(MAIL)).unwrap().replace("8,850.37", "9,850.37");
        assert_eq!(verify(m.as_bytes(), 2048, lookup).unwrap_err(), DkimError::BodyHashMismatch);
    }

    #[test]
    fn an_edited_signed_header_fails() {
        let m = String::from_utf8(signed(MAIL)).unwrap().replace("Subject: Payment sent", "Subject: Payment failed");
        assert_eq!(verify(m.as_bytes(), 2048, lookup).unwrap_err(), DkimError::BadSignature);
    }

    #[test]
    fn a_forged_sender_fails() {
        let m = String::from_utf8(signed(MAIL)).unwrap().replace("alerts@meridian.example", "alerts@evil.example");
        assert_eq!(verify(m.as_bytes(), 2048, lookup).unwrap_err(), DkimError::FromNotAligned);
    }

    #[test]
    fn a_prepended_from_header_fails() {
        let mut m = b"From: Trusted Bank <alerts@meridian.example>\r\n".to_vec();
        m.extend_from_slice(&signed(MAIL));
        assert_eq!(verify(&m, 2048, lookup).unwrap_err(), DkimError::DuplicateHeader);
    }

    #[test]
    fn an_appended_unsigned_body_cannot_use_the_length_tag() {
        let m = String::from_utf8(signed(MAIL)).unwrap().replace("v=1; a=rsa-sha256;", "v=1; l=10; a=rsa-sha256;");
        assert_eq!(verify(m.as_bytes(), 2048, lookup).unwrap_err(), DkimError::BodyLengthTag);
    }

    #[test]
    fn an_unsigned_content_type_is_invisible_to_callers() {
        let m = dkim_sign(MAIL.as_bytes(), "meridian.example", "s1", &keypair().0, &["from", "subject", "date"], 1);
        let v = verify(&m, 2048, lookup).unwrap();
        assert_eq!(v.header("content-type"), None);
    }

    #[test]
    fn an_injected_content_type_cannot_reframe_the_body() {
        let signed = dkim_sign(MAIL.replace("Content-Type: text/plain; charset=utf-8\r\n", "").as_bytes(), "meridian.example", "s1", &keypair().0, &["from", "subject", "date"], 1);
        let mut m = b"Content-Type: multipart/mixed; boundary=evil\r\n".to_vec();
        m.extend_from_slice(&signed);
        assert_eq!(verify(&m, 2048, lookup).unwrap().header("content-type"), None);
    }

    /// A message signed by Google's real servers, with Google's real key. It
    /// runs when `BT_REAL_EML` (a path) and `BT_REAL_KEY` (the DNS `p=` value)
    /// are set; `npm run test:real-dkim` does that. A signer of our own can't
    /// catch a shared misreading of the RFC. This can.
    #[test]
    fn a_real_gmail_message_verifies() {
        let (Ok(path), Ok(key)) = (std::env::var("BT_REAL_EML"), std::env::var("BT_REAL_KEY")) else {
            return;
        };
        let raw = std::fs::read(path).unwrap();
        let der = parse_key_record(&format!("v=DKIM1; k=rsa; p={key}")).unwrap();
        let v = verify(&raw, 2048, |d, s| {
            assert_eq!((d, s), ("gmail.com", "20230601"));
            Ok(der.clone())
        })
        .expect("a real Gmail message verifies");
        assert_eq!(v.domain, "gmail.com");
        assert!(v.header("from").is_some());
        assert_eq!(v.header("content-type"), None, "Gmail doesn't sign Content-Type");
        // Tampering with it must fail too.
        let text = String::from_utf8_lossy(&raw).replace("Subject:", "Subject: x");
        assert!(verify(text.as_bytes(), 2048, |_, _| Ok(der.clone())).is_err());
    }

    #[test]
    fn an_unsigned_from_fails() {
        let m = dkim_sign(MAIL.as_bytes(), "meridian.example", "s1", &keypair().0, &["subject", "content-type"], 1);
        assert_eq!(verify(&m, 2048, lookup).unwrap_err(), DkimError::FromUnsigned);
    }

    #[test]
    fn a_signature_from_another_domain_is_not_aligned() {
        let m = dkim_sign(MAIL.as_bytes(), "relay.example", "s1", &keypair().0, COVERED, 1);
        assert_eq!(verify(&m, 2048, lookup).unwrap_err(), DkimError::FromNotAligned);
    }

    #[test]
    fn a_wrong_key_fails() {
        let other = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let der = other.to_public_key().to_public_key_der().unwrap().as_bytes().to_vec();
        assert_eq!(verify(&signed(MAIL), 2048, |_, _| Ok(der.clone())).unwrap_err(), DkimError::BadSignature);
    }

    #[test]
    fn a_weak_key_needs_an_exception() {
        assert_eq!(verify(&signed(MAIL), 4096, lookup).unwrap_err(), DkimError::KeyWeak);
    }

    #[test]
    fn missing_signature_is_reported() {
        assert_eq!(verify(MAIL.as_bytes(), 2048, lookup).unwrap_err(), DkimError::NoSignature);
    }

    #[test]
    fn subdomains_align_but_lookalikes_do_not() {
        assert!(aligned("alerts.meridian.example", "meridian.example"));
        assert!(!aligned("evilmeridian.example", "meridian.example"));
    }

    #[test]
    fn key_records_parse() {
        assert_eq!(parse_key_record("v=DKIM1; k=rsa; p=").unwrap_err(), DkimError::KeyRevoked);
        assert_eq!(parse_key_record("v=DKIM1; k=ed25519; p=AAAA").unwrap_err(), DkimError::UnsupportedAlgorithm);
        assert_eq!(parse_key_record("v=DKIM1; p=AQID").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn from_domain_reads_display_names() {
        assert_eq!(from_domain("\"Bank, Inc\" <a@bank.example>").as_deref(), Some("bank.example"));
        assert_eq!(from_domain("a@bank.example").as_deref(), Some("bank.example"));
        assert_eq!(from_domain("not an address"), None);
    }

    /// RFC 6376 §3.4.5's worked example.
    #[test]
    fn relaxed_body_canonicalization_matches_the_rfc() {
        assert_eq!(canon_body(b" C \r\nD \t E\r\n\r\n\r\n", Canon::Relaxed), b" C\r\nD E\r\n".to_vec());
        assert_eq!(canon_body(b"", Canon::Simple), b"\r\n".to_vec());
        assert_eq!(canon_body(b"", Canon::Relaxed), b"".to_vec());
    }

    #[test]
    fn relaxed_header_canonicalization_matches_the_rfc() {
        assert_eq!(canon_header(b"A: X\r\n", Canon::Relaxed), b"a:X\r\n".to_vec());
        assert_eq!(canon_header(b"B : Y\t\r\n\tZ  \r\n", Canon::Relaxed), b"b:Y Z\r\n".to_vec());
    }
}
