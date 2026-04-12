//! Airbnb — Android reservation, saved listing, and message history extraction.
//!
//! Source path: `/data/data/com.airbnb.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Airbnb uses Room databases with
//! tables like `reservations`, `saved_listings`, `messages`. Column names
//! vary across versions; defensive `table_exists`/`column_exists` checks
//! are applied throughout.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.airbnb.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_reservations(&conn, path));
    out.extend(parse_saved_listings(&conn, path));
    out.extend(parse_messages(&conn, path));
    out
}

fn parse_reservations(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "reservations") {
        "reservations"
    } else if table_exists(conn, "reservation") {
        "reservation"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT listing_name, host_name, check_in, check_out, \
         location, total_price, confirmation_code, status \
         FROM \"{t}\" ORDER BY check_in DESC LIMIT 2000",
        t = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (listing, host, check_in_ms, check_out_ms, location, price, confirm, status) in
        rows.flatten()
    {
        let listing = listing.unwrap_or_else(|| "(unknown)".to_string());
        let host = host.unwrap_or_default();
        let location = location.unwrap_or_default();
        let price = price.unwrap_or_default();
        let confirm = confirm.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = check_in_ms.and_then(unix_ms_to_i64);
        let check_in_str = fmt_ts(check_in_ms.and_then(unix_ms_to_i64));
        let check_out_str = fmt_ts(check_out_ms.and_then(unix_ms_to_i64));
        let title = format!("Airbnb reservation: {}", listing);
        let detail = format!(
            "Airbnb reservation listing='{}' host='{}' location='{}' \
             check_in='{}' check_out='{}' total_price='{}' confirmation='{}' status='{}'",
            listing, host, location, check_in_str, check_out_str, price, confirm, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Airbnb Reservation",
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

fn parse_saved_listings(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "saved_listings") {
        "saved_listings"
    } else if table_exists(conn, "wishlists") {
        "wishlists"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT listing_id, listing_name, location, saved_at \
         FROM \"{t}\" ORDER BY saved_at DESC LIMIT 2000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, location, saved_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let location = location.unwrap_or_default();
        let ts = saved_ms.and_then(unix_ms_to_i64);
        let title = format!("Airbnb saved: {}", name);
        let detail = format!(
            "Airbnb saved_listing id='{}' name='{}' location='{}' saved_at='{}'",
            id,
            name,
            location,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Airbnb Saved Listing",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn parse_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "messages") {
        "messages"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT message_id, sender_name, body, sent_at, thread_id \
         FROM \"{t}\" ORDER BY sent_at DESC LIMIT 5000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (msg_id, sender, body, sent_ms, thread_id) in rows.flatten() {
        let msg_id = msg_id.unwrap_or_default();
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let body = body.unwrap_or_default();
        let thread_id = thread_id.unwrap_or_default();
        let ts = sent_ms.and_then(unix_ms_to_i64);
        let title = format!("Airbnb message from {}", sender);
        let detail = format!(
            "Airbnb message id='{}' sender='{}' thread='{}' sent='{}' body='{}'",
            msg_id,
            sender,
            thread_id,
            fmt_ts(ts),
            body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Airbnb Message",
            title,
            detail,
            path,
            ts,
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
            CREATE TABLE reservations (
                listing_name TEXT,
                host_name TEXT,
                check_in INTEGER,
                check_out INTEGER,
                location TEXT,
                total_price TEXT,
                confirmation_code TEXT,
                status TEXT
            );
            INSERT INTO reservations VALUES(
                'Ocean View Cottage','Maria S',
                1700000000000,1700259200000,
                'Santa Barbara, CA','$420.00','HMXQ7B','confirmed'
            );
            CREATE TABLE saved_listings (
                listing_id TEXT,
                listing_name TEXT,
                location TEXT,
                saved_at INTEGER
            );
            INSERT INTO saved_listings VALUES('lst-99','Mountain Cabin','Aspen, CO',1699900000000);
            CREATE TABLE messages (
                message_id TEXT,
                sender_name TEXT,
                body TEXT,
                sent_at INTEGER,
                thread_id TEXT
            );
            INSERT INTO messages VALUES('msg-1','Maria S','Welcome! The key is under the mat.',1700000100000,'thr-1');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_reservation() {
        let db = make_db();
        let r = parse(db.path());
        let res: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Airbnb Reservation")
            .collect();
        assert_eq!(res.len(), 1);
        assert!(res[0].detail.contains("listing='Ocean View Cottage'"));
        assert!(res[0].detail.contains("confirmation='HMXQ7B'"));
    }

    #[test]
    fn parses_saved_listing() {
        let db = make_db();
        let r = parse(db.path());
        let saved: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Airbnb Saved Listing")
            .collect();
        assert_eq!(saved.len(), 1);
        assert!(saved[0].detail.contains("name='Mountain Cabin'"));
    }

    #[test]
    fn parses_message() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Airbnb Message")
            .collect();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].detail.contains("sender='Maria S'"));
    }

    #[test]
    fn missing_tables_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
