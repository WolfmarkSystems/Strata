//! ANDROID16-1 — Google Device Personalization Services "Turbo App
//! Usage" parser.
//!
//! Android 14+ records per-app launch / close / foreground-time
//! events in `/data/com.google.android.as/databases/reflection_gel_events.db`.
//! The canonical table is `reflection_events` with package_name,
//! event_type, timestamp (unix ms), and optional duration /
//! foreground_time / interaction_count columns.
//!
//! This parser is schema-tolerant — column names have drifted across
//! Google app versions so we pull the real names out of PRAGMA
//! table_info before querying.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;

#[derive(Debug, Clone, PartialEq)]
pub struct TurboUsageEvent {
    pub package_name: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub duration_seconds: Option<u64>,
    pub foreground_time_seconds: Option<u64>,
    pub interaction_count: Option<u32>,
}

pub fn matches(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let n = name.to_ascii_lowercase();
    n == "reflection_gel_events.db" || n == "simplestorage" || n.contains("turbo_usage")
}

pub fn parse(path: &Path) -> Vec<TurboUsageEvent> {
    let conn = match Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_conn(&conn)
}

pub fn parse_conn(conn: &Connection) -> Vec<TurboUsageEvent> {
    let Some(table) = first_known_table(conn, &["reflection_events", "events", "app_usage_events"])
    else {
        return Vec::new();
    };
    let cols = column_names(conn, &table);
    let pkg = pick(&cols, &["package_name", "package", "app_package"])
        .unwrap_or_else(|| "package_name".into());
    let ev = pick(&cols, &["event_type", "event", "type"]).unwrap_or_else(|| "event_type".into());
    let ts = pick(&cols, &["timestamp", "event_time", "ts"]).unwrap_or_else(|| "timestamp".into());
    let dur = pick(&cols, &["duration", "duration_ms", "session_duration"]);
    let fg = pick(&cols, &["foreground_time", "foreground_ms", "fg_time"]);
    let ic = pick(&cols, &["interaction_count", "interactions"]);
    let sql = format!(
        "SELECT {}, {}, {}, {}, {}, {} FROM {}",
        pkg,
        ev,
        ts,
        dur.clone().unwrap_or_else(|| "NULL".into()),
        fg.clone().unwrap_or_else(|| "NULL".into()),
        ic.clone().unwrap_or_else(|| "NULL".into()),
        table
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Option<String>>(0)
                .unwrap_or(None)
                .unwrap_or_default(),
            r.get::<_, Option<String>>(1)
                .unwrap_or(None)
                .unwrap_or_default(),
            r.get::<_, i64>(2).unwrap_or(0),
            r.get::<_, Option<i64>>(3).unwrap_or(None),
            r.get::<_, Option<i64>>(4).unwrap_or(None),
            r.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (pkg, ev, ts_ms, dur_ms, fg_ms, ic) in rows.flatten() {
        let secs = ts_ms / 1000;
        let timestamp = Utc
            .timestamp_opt(secs, 0)
            .single()
            .unwrap_or_else(unix_epoch);
        out.push(TurboUsageEvent {
            package_name: pkg,
            event_type: ev,
            timestamp,
            duration_seconds: dur_ms.map(|v| (v.max(0) / 1000) as u64),
            foreground_time_seconds: fg_ms.map(|v| (v.max(0) / 1000) as u64),
            interaction_count: ic.map(|v| v.max(0) as u32),
        });
    }
    out
}

fn unix_epoch() -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::UNIX_EPOCH)
}

fn first_known_table(conn: &Connection, candidates: &[&str]) -> Option<String> {
    for t in candidates {
        let sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?1";
        if conn.query_row(sql, [t], |r| r.get::<_, String>(0)).is_ok() {
            return Some((*t).into());
        }
    }
    None
}

fn column_names(conn: &Connection, table: &str) -> Vec<String> {
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    stmt.query_map([], |r| r.get::<_, String>(1))
        .ok()
        .map(|r| r.flatten().collect())
        .unwrap_or_default()
}

fn pick(cols: &[String], candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if cols.iter().any(|x| x.eq_ignore_ascii_case(c)) {
            return Some((*c).into());
        }
    }
    None
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE reflection_events (\
                package_name TEXT,\
                event_type TEXT,\
                timestamp INTEGER,\
                duration INTEGER,\
                foreground_time INTEGER,\
                interaction_count INTEGER);",
        )
        .expect("schema");
        c.execute(
            "INSERT INTO reflection_events VALUES ('com.whatsapp', 'launch', 1700000000000, 90000, 75000, 12)",
            [],
        )
        .expect("ins");
        c.execute(
            "INSERT INTO reflection_events VALUES ('com.instagram.android', 'close', 1700000090000, 120000, 90000, NULL)",
            [],
        )
        .expect("ins");
        c
    }

    #[test]
    fn parses_canonical_turbo_events() {
        let c = fixture();
        let events = parse_conn(&c);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].package_name, "com.whatsapp");
        assert_eq!(events[0].duration_seconds, Some(90));
        assert_eq!(events[0].foreground_time_seconds, Some(75));
        assert_eq!(events[0].interaction_count, Some(12));
    }

    #[test]
    fn matches_common_filenames() {
        use std::path::PathBuf;
        assert!(matches(&PathBuf::from(
            "/data/com.google.android.as/databases/reflection_gel_events.db"
        )));
        assert!(matches(&PathBuf::from("/x/SimpleStorage")));
        assert!(!matches(&PathBuf::from("/x/unrelated.db")));
    }

    #[test]
    fn unknown_table_returns_empty() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .expect("s");
        assert!(parse_conn(&c).is_empty());
    }

    #[test]
    fn tolerates_missing_optional_columns() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE reflection_events (\
                package_name TEXT, event_type TEXT, timestamp INTEGER);",
        )
        .expect("schema");
        c.execute(
            "INSERT INTO reflection_events VALUES ('com.signal', 'launch', 1700000000000)",
            [],
        )
        .expect("ins");
        let events = parse_conn(&c);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].duration_seconds, None);
        assert_eq!(events[0].interaction_count, None);
    }
}
