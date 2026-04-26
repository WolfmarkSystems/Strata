//! Financial artifact detection for IRS-CI / USSS / SEC workflows.

use chrono::{NaiveDateTime, TimeZone, Utc};
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq)]
pub struct OFXTransaction {
    pub transaction_type: String,
    pub date: Option<i64>,
    pub amount: f64,
    pub payee: Option<String>,
    pub memo: Option<String>,
    pub transaction_id: String,
}

impl Default for OFXTransaction {
    fn default() -> Self {
        Self {
            transaction_type: String::new(),
            date: None,
            amount: 0.0,
            payee: None,
            memo: None,
            transaction_id: String::new(),
        }
    }
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let mut out = Vec::new();
    if is_quickbooks_file(path) {
        let mut a = Artifact::new("Financial Artifact", &path.to_string_lossy());
        a.add_field("title", "QuickBooks file detected");
        a.add_field(
            "detail",
            &format!("QuickBooks artifact: {}", path.display()),
        );
        a.add_field("file_type", "Financial Artifact");
        a.add_field("financial_kind", "QuickBooks");
        a.add_field("mitre", "T1657");
        a.add_field("forensic_value", "High");
        a.add_field("suspicious", "true");
        out.push(a);
        if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("qbo"))
            .unwrap_or(false)
        {
            if let Ok(body) = std::fs::read_to_string(path) {
                for txn in parse_ofx_transactions(&body) {
                    let mut t = Artifact::new("Financial Transaction", &path.to_string_lossy());
                    t.timestamp = txn.date.map(|d| d as u64);
                    t.add_field(
                        "title",
                        &format!("OFX {} {}", txn.transaction_type, txn.amount),
                    );
                    t.add_field(
                        "detail",
                        &format!("Payee: {}", txn.payee.as_deref().unwrap_or("-")),
                    );
                    t.add_field("file_type", "Financial Transaction");
                    t.add_field("amount", &txn.amount.to_string());
                    t.add_field("transaction_type", &txn.transaction_type);
                    if let Some(payee) = &txn.payee {
                        t.add_field("payee", payee);
                    }
                    if is_potential_structuring(&txn) {
                        t.add_field(
                            "suspicious_reason",
                            "possible structuring just under $10,000",
                        );
                        t.add_field("suspicious", "true");
                        t.add_field("forensic_value", "High");
                    } else {
                        t.add_field("forensic_value", "Medium");
                    }
                    t.add_field("mitre", "T1657");
                    out.push(t);
                }
            }
        }
    } else if is_financial_statement_pdf(path) {
        let mut a = Artifact::new("Financial Statement", &path.to_string_lossy());
        a.add_field("title", "Financial statement PDF detected");
        a.add_field("detail", &format!("Statement artifact: {}", path.display()));
        a.add_field("file_type", "Financial Statement");
        a.add_field("mitre", "T1657");
        a.add_field("forensic_value", "Medium");
        out.push(a);
    } else if is_suspicious_financial_filename(path) {
        let mut a = Artifact::new("Financial Artifact", &path.to_string_lossy());
        a.add_field("title", "Suspicious financial filename/location");
        a.add_field(
            "detail",
            &format!(
                "Financial-looking file outside normal documents path: {}",
                path.display()
            ),
        );
        a.add_field("file_type", "Financial Artifact");
        a.add_field("mitre", "T1657");
        a.add_field("forensic_value", "High");
        a.add_field("suspicious", "true");
        out.push(a);
    } else if is_wire_transfer_csv(path) {
        let mut a = Artifact::new("Wire Transfer Artifact", &path.to_string_lossy());
        a.add_field("title", "Wire transfer CSV detected");
        a.add_field(
            "detail",
            &format!("Wire-transfer-like CSV columns: {}", path.display()),
        );
        a.add_field("file_type", "Wire Transfer Artifact");
        a.add_field("mitre", "T1657");
        a.add_field("forensic_value", "High");
        a.add_field("suspicious", "true");
        out.push(a);
    }
    out
}

pub fn is_quickbooks_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| matches!(ext.to_ascii_lowercase().as_str(), "qbw" | "qbb" | "qbo"))
        .unwrap_or(false)
}

pub fn parse_ofx_transaction(xml: &str) -> Option<OFXTransaction> {
    let transaction_type = tag(xml, "TRNTYPE").unwrap_or_default();
    let amount = tag(xml, "TRNAMT")?.parse::<f64>().ok()?;
    Some(OFXTransaction {
        transaction_type,
        date: tag(xml, "DTPOSTED").and_then(|d| parse_ofx_date(&d)),
        amount,
        payee: tag(xml, "NAME"),
        memo: tag(xml, "MEMO"),
        transaction_id: tag(xml, "FITID").unwrap_or_default(),
    })
}

pub fn parse_ofx_transactions(xml: &str) -> Vec<OFXTransaction> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<STMTTRN>") {
        let after = &rest[start + "<STMTTRN>".len()..];
        let Some(end) = after.find("</STMTTRN>") else {
            break;
        };
        let block = &after[..end];
        if let Some(txn) = parse_ofx_transaction(block) {
            out.push(txn);
        }
        rest = &after[end + "</STMTTRN>".len()..];
    }
    if out.is_empty() {
        if let Some(txn) = parse_ofx_transaction(xml) {
            out.push(txn);
        }
    }
    out
}

pub fn is_potential_structuring(txn: &OFXTransaction) -> bool {
    let amount = txn.amount.abs();
    (9_000.0..10_000.0).contains(&amount) || (amount >= 10_000.0 && amount % 1_000.0 == 0.0)
}

pub fn is_financial_statement_pdf(path: &Path) -> bool {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    lower.ends_with(".pdf")
        && (lower.contains("/statements/")
            || lower.contains("statement_")
            || lower.contains("_statement.pdf")
            || lower.contains("account_"))
}

pub fn is_suspicious_financial_filename(path: &Path) -> bool {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let interesting_ext =
        lower.ends_with(".xls") || lower.ends_with(".xlsx") || lower.ends_with(".csv");
    if !interesting_ext {
        return false;
    }
    let financial_name = [
        "account",
        "transaction",
        "balance",
        "wire",
        "transfer",
        "offshore",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let unusual_location = lower.contains("/tmp/")
        || lower.contains("/dev/shm/")
        || lower.contains("/desktop/")
        || lower.contains("/appdata/local/temp/");
    financial_name && unusual_location
}

pub fn is_wire_transfer_csv(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if !name.to_ascii_lowercase().ends_with(".csv") {
        return false;
    }
    let Ok(body) = std::fs::read_to_string(path) else {
        return false;
    };
    let header = body.lines().next().unwrap_or("").to_ascii_lowercase();
    header.contains("amount")
        && (header.contains("routing") || header.contains("swift"))
        && (header.contains("beneficiary")
            || header.contains("recipient")
            || header.contains("wire"))
}

fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let rest = xml.get(start..)?;
    let end = rest.find(&close).unwrap_or(rest.len());
    let value = rest[..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn parse_ofx_date(value: &str) -> Option<i64> {
    let normalized = value.get(0..14).unwrap_or(value);
    let ndt = NaiveDateTime::parse_from_str(normalized, "%Y%m%d%H%M%S").ok()?;
    Some(Utc.from_utc_datetime(&ndt).timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ofx_transaction_parsed_correctly() {
        let xml = r#"<STMTTRN><TRNTYPE>DEBIT</TRNTYPE>
        <DTPOSTED>20251104120000</DTPOSTED>
        <TRNAMT>-9999.00</TRNAMT>
        <NAME>CASH WITHDRAWAL</NAME></STMTTRN>"#;
        let txn = parse_ofx_transaction(xml).expect("ofx transaction");
        assert_eq!(txn.transaction_type, "DEBIT");
        assert_eq!(txn.amount, -9999.0);
    }

    #[test]
    fn structuring_detected_under_10k() {
        let txn = OFXTransaction {
            amount: -9500.0,
            transaction_type: "DEBIT".into(),
            ..Default::default()
        };
        assert!(is_potential_structuring(&txn));
    }

    #[test]
    fn quickbooks_qbw_file_detected() {
        let path = std::path::Path::new("C:/Users/user/Documents/company.QBW");
        assert!(is_quickbooks_file(path));
    }
}
