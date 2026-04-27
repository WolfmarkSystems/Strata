//! iOS Apple Pay — `com.apple.NanoPassKit/`, `passes23.sqlite`.
//!
//! Apple Pay transaction receipts store merchant name, amount, date,
//! and card device account number. No real PAN is stored on device.
//! Critical for financial investigations — proves purchases.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    (util::path_contains(path, "nanopasskit") || util::path_contains(path, "passkit")) && {
        let n = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite") || n.ends_with(".sqlite3")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    for (table, label, fv) in [
        (
            "payment_transaction",
            "Apple Pay transactions",
            ForensicValue::Critical,
        ),
        (
            "payment_pass",
            "Apple Pay cards (DPAN only)",
            ForensicValue::Critical,
        ),
        (
            "felica_transaction",
            "Suica/transit transactions",
            ForensicValue::High,
        ),
    ] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::AccountsCredentials,
                subcategory: format!("Apple Pay {}", table),
                timestamp: None,
                title: label.to_string(),
                detail: format!(
                    "{} {} rows — merchant, amount, date, card DPAN",
                    count, table
                ),
                source_path: source.clone(),
                forensic_value: fv,
                mitre_technique: Some("T1005".to_string()),
                is_suspicious: false,
                raw_data: None,
                confidence: 0,
            });
        }
    }
    // Fallback table inventory
    if out.is_empty() {
        let tables: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .and_then(|mut s| {
                let r = s.query_map([], |row| row.get::<_, String>(0))?;
                Ok(r.flatten().collect())
            })
            .unwrap_or_default();
        if tables.is_empty() {
            return out;
        }
        let mut total = 0_i64;
        for t in &tables {
            total += util::count_rows(&conn, t);
        }
        out.push(ArtifactRecord {
            category: ArtifactCategory::AccountsCredentials,
            subcategory: "Apple Pay".to_string(),
            timestamp: None,
            title: "Apple Pay / PassKit database".to_string(),
            detail: format!("{} rows across {} tables", total, tables.len()),
            source_path: source,
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_passkit() {
        assert!(matches(Path::new(
            "/var/mobile/Library/NanoPassKit/store.sqlite3"
        )));
        assert!(matches(Path::new("/var/mobile/Library/PassKit/passes.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_payment_transactions() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("NanoPassKit");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.sqlite3");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE payment_transaction (id INTEGER PRIMARY KEY, merchant TEXT, amount REAL, ts DOUBLE)", []).unwrap();
        c.execute("INSERT INTO payment_transaction (merchant, amount, ts) VALUES ('Starbucks', 5.50, 700000000.0)", []).unwrap();
        let recs = parse(&p);
        let t = recs
            .iter()
            .find(|r| r.subcategory.contains("payment_transaction"))
            .unwrap();
        assert!(t.detail.contains("1 payment_transaction"));
        assert_eq!(t.forensic_value, ForensicValue::Critical);
    }
    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("NanoPassKit");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.sqlite3");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}
