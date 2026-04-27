//! TikTok LIVE — livestream watch history and gifts sent.
//!
//! Source path: `/data/data/com.zhiliaoapp.musically/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. TikTok stores LIVE history in
//! tables like `live_history`, `live_watch_record`, and gifts in
//! `gift_record`. Useful for establishing engagement with specific
//! creators and financial transfers via virtual gifts.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.zhiliaoapp.musically/databases/",
    "com.ss.android.ugc.trill/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["live_history", "live_watch_record", "live_room_history"] {
        if table_exists(&conn, table) {
            out.extend(read_live_watch(&conn, path, table));
            break;
        }
    }
    for table in &["gift_record", "gift_history", "live_gift"] {
        if table_exists(&conn, table) {
            out.extend(read_gifts(&conn, path, table));
            break;
        }
    }
    out
}

fn read_live_watch(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT room_id, anchor_id, anchor_name, start_time, end_time, \
         watch_duration FROM \"{table}\" ORDER BY start_time DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (room_id, anchor_id, anchor_name, start_ms, _end_ms, watch_dur) in rows.flatten() {
        let room_id = room_id.unwrap_or_else(|| "(unknown)".to_string());
        let anchor_id = anchor_id.unwrap_or_default();
        let anchor_name = anchor_name.unwrap_or_default();
        let dur_s = watch_dur.unwrap_or(0) / 1000;
        let ts = start_ms.and_then(unix_ms_to_i64);
        let title = format!("TikTok LIVE: {} ({}s)", anchor_name, dur_s);
        let detail = format!(
            "TikTok LIVE watch room_id='{}' anchor_id='{}' anchor_name='{}' duration={}s",
            room_id, anchor_id, anchor_name, dur_s
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "TikTok LIVE Watch",
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

fn read_gifts(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT gift_id, gift_name, gift_value, receiver_id, receiver_name, \
         send_time, count FROM \"{table}\" ORDER BY send_time DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (gift_id, gift_name, gift_value, receiver_id, receiver_name, send_ms, count) in
        rows.flatten()
    {
        let gift_id = gift_id.unwrap_or_default();
        let gift_name = gift_name.unwrap_or_default();
        let gift_value = gift_value.unwrap_or(0);
        let receiver_id = receiver_id.unwrap_or_default();
        let receiver_name = receiver_name.unwrap_or_default();
        let count = count.unwrap_or(0);
        let total = gift_value * count;
        let ts = send_ms.and_then(unix_ms_to_i64);
        let title = format!("TikTok gift: {} x{} to {}", gift_name, count, receiver_name);
        let detail = format!(
            "TikTok LIVE gift gift_id='{}' gift_name='{}' gift_value={} count={} total_coins={} receiver_id='{}' receiver_name='{}'",
            gift_id, gift_name, gift_value, count, total, receiver_id, receiver_name
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "TikTok LIVE Gift",
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
            CREATE TABLE live_history (
                room_id TEXT,
                anchor_id TEXT,
                anchor_name TEXT,
                start_time INTEGER,
                end_time INTEGER,
                watch_duration INTEGER
            );
            INSERT INTO live_history VALUES('r1','a1','StreamerAlice',1609459200000,1609460000000,800000);
            CREATE TABLE gift_record (
                gift_id TEXT,
                gift_name TEXT,
                gift_value INTEGER,
                receiver_id TEXT,
                receiver_name TEXT,
                send_time INTEGER,
                count INTEGER
            );
            INSERT INTO gift_record VALUES('g1','Rose',1,'a1','StreamerAlice',1609459500000,10);
            INSERT INTO gift_record VALUES('g2','Galaxy',1000,'a1','StreamerAlice',1609459800000,1);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_watch_and_gifts() {
        let db = make_db();
        let r = parse(db.path());
        let watches: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "TikTok LIVE Watch")
            .collect();
        let gifts: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "TikTok LIVE Gift")
            .collect();
        assert_eq!(watches.len(), 1);
        assert_eq!(gifts.len(), 2);
    }

    #[test]
    fn gift_total_coins_calculated() {
        let db = make_db();
        let r = parse(db.path());
        // Rose x10 = 10 coins
        assert!(r.iter().any(|a| a.detail.contains("total_coins=10")));
        // Galaxy x1 = 1000 coins
        assert!(r.iter().any(|a| a.detail.contains("total_coins=1000")));
    }

    #[test]
    fn watch_duration_in_title() {
        let db = make_db();
        let r = parse(db.path());
        let w = r
            .iter()
            .find(|a| a.subcategory == "TikTok LIVE Watch")
            .unwrap();
        assert!(w.title.contains("800s"));
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
