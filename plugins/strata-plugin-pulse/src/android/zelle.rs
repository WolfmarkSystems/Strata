//! Zelle — Android P2P payment transfer extraction.
//!
//! Source path: `/data/data/com.zellepay.zelle/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Zelle uses Room databases with
//! tables like `transfer`, `payee`. Many bank apps embed Zelle as a
//! child feature — this parser targets the standalone Zelle app.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.zellepay.zelle/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["transfer", "transfers", "transaction_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transfers(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "payee") {
        out.extend(read_payees(&conn, path));
    }
    out
}

fn read_transfers(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, direction, amount, recipient_name, recipient_token, \
         memo, status, created_at \
         FROM \"{table}\" ORDER BY created_at DESC LIMIT 10000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, direction, amount, recipient_name, recipient_token, memo, status, created_ms) in
        rows.flatten()
    {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let direction = direction.unwrap_or_default();
        let amount = amount.unwrap_or_default();
        let recipient_name = recipient_name.unwrap_or_default();
        let recipient_token = recipient_token.unwrap_or_default();
        let memo = memo.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Zelle {}: {} to {}", direction, amount, recipient_name);
        let detail = format!(
            "Zelle transfer id='{}' direction='{}' amount='{}' recipient_name='{}' recipient_token='{}' memo='{}' status='{}'",
            id, direction, amount, recipient_name, recipient_token, memo, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Zelle Transfer",
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

fn read_payees(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, token, token_type \
               FROM payee LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, token, token_type) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let token = token.unwrap_or_default();
        let token_type = token_type.unwrap_or_default();
        let title = format!("Zelle payee: {} ({})", name, token);
        let detail = format!(
            "Zelle payee id='{}' name='{}' token='{}' token_type='{}'",
            id, name, token, token_type
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Zelle Payee",
            title,
            detail,
            path,
            None,
            ForensicValue::High,
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
            CREATE TABLE transfer (
                id TEXT,
                direction TEXT,
                amount TEXT,
                recipient_name TEXT,
                recipient_token TEXT,
                memo TEXT,
                status TEXT,
                created_at INTEGER
            );
            INSERT INTO transfer VALUES('z-001','sent','$250.00','Alice Johnson','alice@example.com','Rent','completed',1609459200000);
            INSERT INTO transfer VALUES('z-002','received','$50.00','Bob Smith','555-0100','Dinner','completed',1609545600000);
            CREATE TABLE payee (
                id TEXT,
                name TEXT,
                token TEXT,
                token_type TEXT
            );
            INSERT INTO payee VALUES('p1','Alice Johnson','alice@example.com','email');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_transfers_and_payees() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Zelle Transfer"));
        assert!(r.iter().any(|a| a.subcategory == "Zelle Payee"));
    }

    #[test]
    fn direction_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("sent") && a.title.contains("$250.00")));
        assert!(r
            .iter()
            .any(|a| a.title.contains("received") && a.title.contains("$50.00")));
    }

    #[test]
    fn recipient_token_and_memo_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("recipient_token='alice@example.com'")
                && a.detail.contains("memo='Rent'")));
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
