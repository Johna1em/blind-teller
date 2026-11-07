//! A regex-free stand-in for the models, for sandbox templates only.
//!
//! It exists so every other part of the system can run end to end before an API
//! key is available. It reads the three sandbox bank formats and nothing else.
//! Its verdicts say `dev-rules`, and only a build with the `dev-extractor`
//! feature contains this file at all.

use crate::checks::Extraction;

fn after<'a>(text: &'a str, labels: &[&str]) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let l = line.trim();
        labels.iter().find_map(|label| l.strip_prefix(label).map(str::trim))
    })
}

fn amount_of(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit() || matches!(c, '.' | ',')).collect::<String>().trim_matches(['.', ',']).to_string()
}

pub fn read(text: &str) -> Result<Extraction, &'static str> {
    let amount = after(text, &["Amount:", "Valor:", "Betrag:"]).ok_or("dev_rules_unknown_format")?;
    let currency = after(text, &["Currency:", "Moeda:", "Währung:"]).ok_or("dev_rules_unknown_format")?;
    let status = after(text, &["Status:", "Situação:"]).unwrap_or("unknown").to_lowercase();
    let direction = after(text, &["Type:", "Tipo:", "Art:"]).unwrap_or("unknown").to_lowercase();
    let recipient = after(text, &["To:", "Para:", "An:"]).unwrap_or("").to_string();
    let note = after(text, &["Note:", "Mensagem:", "Verwendungszweck:"]).unwrap_or("").to_string();
    let balance = after(text, &["Available balance:", "Saldo disponível:", "Verfügbarer Saldo:"]).map(amount_of).unwrap_or_default();
    Ok(Extraction {
        status: match status.as_str() {
            "successful" | "success" | "concluído" | "ausgeführt" => "success".into(),
            "failed" | "falhou" | "fehlgeschlagen" => "failed".into(),
            _ => "unknown".into(),
        },
        direction: match direction.as_str() {
            "debit" | "débito" | "lastschrift" => "debit".into(),
            "credit" | "crédito" | "gutschrift" => "credit".into(),
            _ => "unknown".into(),
        },
        amount: amount_of(amount),
        currency: currency.to_uppercase(),
        recipient,
        note,
        balance,
        injection: false,
    })
}
