//! Cash App — Android payment transaction extraction.
//!
//! ALEAPP reference: `scripts/artifacts/cashApp.py`. Source path:
//! `/data/data/com.squareup.cash/databases/cash_money.db`.
//!
//! Key tables: `payment` joined with `customer`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.squareup.cash/databases/cash_money.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "payment") {
        return Vec::new();
    }
    read_payments(&conn, path)
}

fn read_payments(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT p.role, p.state, p.display_date, \
               p.sender_id, p.recipient_id, p.note, p.amount \
               FROM payment p \
               ORDER BY p.display_date DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (role, state, display_ms, sender, recipient, note, amount) in rows.flatten() {
        let role = role.unwrap_or_else(|| "unknown".to_string());
        let state = state.unwrap_or_else(|| "unknown".to_string());
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let recipient = recipient.unwrap_or_else(|| "(unknown)".to_string());
        let note = note.unwrap_or_default();
        let amount = amount.unwrap_or_else(|| "0".to_string());
        let ts = display_ms.and_then(unix_ms_to_i64);
        let title = format!("Cash App {}: {} → {} ({})", role, sender, recipient, amount);
        let detail = format!(
            "Cash App payment role='{}' state='{}' sender='{}' recipient='{}' amount='{}' note='{}'",
            role, state, sender, recipient, amount, note
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Cash App Payment",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE payment (
                _id INTEGER PRIMARY KEY,
                role TEXT,
                state TEXT,
                display_date INTEGER,
                sender_id TEXT,
                recipient_id TEXT,
                note TEXT,
                amount TEXT
            );
            INSERT INTO payment VALUES(1,'SENDER','COMPLETE',1609459200000,'$alice','$bob','Rent','$500.00');
            INSERT INTO payment VALUES(2,'RECEIVER','COMPLETE',1609459300000,'$charlie','$alice','Dinner','$25.50');
            INSERT INTO payment VALUES(3,'SENDER','PENDING',1609459400000,'$alice','$dave','Gas','$40.00');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_payments() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Cash App Payment"));
    }

    #[test]
    fn sender_recipient_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("$alice") && a.title.contains("$bob")));
    }

    #[test]
    fn note_and_amount_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let rent = r.iter().find(|a| a.detail.contains("Rent")).unwrap();
        assert!(rent.detail.contains("amount='$500.00'"));
        assert!(rent.detail.contains("note='Rent'"));
    }

    #[test]
    fn forensic_value_is_critical() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .all(|a| matches!(a.forensic_value, ForensicValue::Critical)));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
