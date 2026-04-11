//! Venmo — Android peer-to-peer payment history extraction.
//!
//! Source path: `/data/data/com.venmo/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Venmo uses Room databases with
//! tables like `transactions`, `friends`. Transactions store sender,
//! recipient, amount, note, and audience (public/friends/private).

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.venmo/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["transactions", "transaction_history", "payment"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "friends") {
        out.extend(read_friends(&conn, path));
    }
    out
}

fn read_transactions(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, sender_username, recipient_username, amount, note, \
         audience, created_at, type, status \
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
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, sender, recipient, amount, note, audience, created_ms, tx_type, status) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let recipient = recipient.unwrap_or_else(|| "(unknown)".to_string());
        let amount = amount.unwrap_or_default();
        let note = note.unwrap_or_default();
        let audience = audience.unwrap_or_default();
        let tx_type = tx_type.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Venmo: {} → {} ({})", sender, recipient, amount);
        let detail = format!(
            "Venmo transaction id='{}' sender='{}' recipient='{}' amount='{}' type='{}' status='{}' audience='{}' note='{}'",
            id, sender, recipient, amount, tx_type, status, audience, note
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Venmo Transaction",
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

fn read_friends(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT username, display_name, phone, email \
               FROM friends LIMIT 10000";
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
    for (username, display_name, phone, email) in rows.flatten() {
        let username = username.unwrap_or_else(|| "(unknown)".to_string());
        let display_name = display_name.unwrap_or_default();
        let phone = phone.unwrap_or_default();
        let email = email.unwrap_or_default();
        let title = format!("Venmo friend: {} ({})", display_name, username);
        let mut detail = format!(
            "Venmo friend username='{}' display_name='{}'",
            username, display_name
        );
        if !phone.is_empty() {
            detail.push_str(&format!(" phone='{}'", phone));
        }
        if !email.is_empty() {
            detail.push_str(&format!(" email='{}'", email));
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "Venmo Friend",
            title,
            detail,
            path,
            None,
            ForensicValue::Medium,
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
            CREATE TABLE transactions (
                id TEXT,
                sender_username TEXT,
                recipient_username TEXT,
                amount TEXT,
                note TEXT,
                audience TEXT,
                created_at INTEGER,
                type TEXT,
                status TEXT
            );
            INSERT INTO transactions VALUES('tx-1','alice','bob','$50.00','Rent','friends',1609459200000,'payment','settled');
            INSERT INTO transactions VALUES('tx-2','charlie','alice','$15.00','Lunch','private',1609545600000,'payment','settled');
            CREATE TABLE friends (
                username TEXT,
                display_name TEXT,
                phone TEXT,
                email TEXT
            );
            INSERT INTO friends VALUES('bob','Bob Smith','555-0100','bob@example.com');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_transactions_and_friends() {
        let db = make_db();
        let r = parse(db.path());
        let txs: Vec<_> = r.iter().filter(|a| a.subcategory == "Venmo Transaction").collect();
        let friends: Vec<_> = r.iter().filter(|a| a.subcategory == "Venmo Friend").collect();
        assert_eq!(txs.len(), 2);
        assert_eq!(friends.len(), 1);
    }

    #[test]
    fn audience_and_note_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("audience='private'") && a.detail.contains("note='Lunch'")));
    }

    #[test]
    fn friend_phone_email_captured() {
        let db = make_db();
        let r = parse(db.path());
        let f = r.iter().find(|a| a.subcategory == "Venmo Friend").unwrap();
        assert!(f.detail.contains("phone='555-0100'"));
        assert!(f.detail.contains("email='bob@example.com'"));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
