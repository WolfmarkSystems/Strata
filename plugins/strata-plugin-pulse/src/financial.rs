//! FIN-1 — financial / payment / investment / tax app metadata.
//!
//! Most banking and payment apps encrypt per-transaction content but
//! leave login timestamps, account tails, and recent-activity
//! pointers accessible. The unified `FinancialAppArtifact` surfaces
//! those without pretending to decrypt anything.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinancialAppArtifact {
    pub platform: String,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub amount: Option<f64>,
    pub counterparty: Option<String>,
    pub description: Option<String>,
    pub account_reference: Option<String>,
}

/// Parse a Venmo-like transaction feed.
pub fn parse_venmo_feed(json: &str) -> Vec<FinancialAppArtifact> {
    parse_generic("Venmo", json)
}

/// Parse a Cash App transaction feed.
pub fn parse_cash_app_feed(json: &str) -> Vec<FinancialAppArtifact> {
    parse_generic("CashApp", json)
}

/// Parse a Robinhood trade history feed.
pub fn parse_robinhood_trades(json: &str) -> Vec<FinancialAppArtifact> {
    parse_generic("Robinhood", json)
}

/// Generic "login event" parser for banking apps that don't cache
/// transactions but do log successful sign-ins locally.
pub fn parse_bank_logins(platform: &str, json: &str) -> Vec<FinancialAppArtifact> {
    parse_generic(platform, json)
}

fn parse_generic(platform: &str, json: &str) -> Vec<FinancialAppArtifact> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v
        .get("transactions")
        .and_then(|x| x.as_array())
        .or_else(|| v.get("events").and_then(|x| x.as_array()))
        .or_else(|| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for entry in arr {
        let ts = entry
            .get("timestamp")
            .and_then(|x| x.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        out.push(FinancialAppArtifact {
            platform: platform.into(),
            artifact_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Event")
                .into(),
            timestamp: ts,
            amount: entry.get("amount").and_then(|x| x.as_f64()),
            counterparty: entry
                .get("counterparty")
                .and_then(|x| x.as_str())
                .map(String::from),
            description: entry
                .get("description")
                .and_then(|x| x.as_str())
                .map(String::from),
            account_reference: entry
                .get("account_last4")
                .and_then(|x| x.as_str())
                .map(String::from),
        });
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_venmo_transactions() {
        let json = r#"{"transactions":[
            {"type":"Payment","timestamp":"2026-04-10T14:00:00Z","amount":25.00,
             "counterparty":"@alice","description":"dinner","account_last4":"4242"}
        ]}"#;
        let t = parse_venmo_feed(json);
        assert_eq!(t[0].platform, "Venmo");
        assert_eq!(t[0].amount, Some(25.00));
        assert_eq!(t[0].counterparty.as_deref(), Some("@alice"));
    }

    #[test]
    fn parses_robinhood_trade() {
        let json = r#"[{"type":"Trade","timestamp":"2026-04-10T15:00:00Z",
            "amount":1500.00,"description":"AAPL x 10"}]"#;
        let t = parse_robinhood_trades(json);
        assert_eq!(t[0].platform, "Robinhood");
        assert_eq!(t[0].description.as_deref(), Some("AAPL x 10"));
    }

    #[test]
    fn parses_bank_login_event() {
        let json = r#"{"events":[{"type":"Login","timestamp":"2026-04-10T09:00:00Z","account_last4":"8921"}]}"#;
        let t = parse_bank_logins("Chase", json);
        assert_eq!(t[0].artifact_type, "Login");
        assert_eq!(t[0].account_reference.as_deref(), Some("8921"));
    }

    #[test]
    fn bad_json_returns_empty() {
        assert!(parse_venmo_feed("bad").is_empty());
        assert!(parse_cash_app_feed("{}").is_empty());
    }
}
