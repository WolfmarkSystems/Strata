//! APPLE26-4 — FaceTime database restructure for iOS 26 / macOS 26.
//!
//! Shared helper used by the pulse plugin (iOS FaceTime) and the
//! mactrace plugin (macOS FaceTime). The Tahoe-era CallHistory
//! storedata reorganised ZDATE, ZANSWERED, group participant tables,
//! and Live-Translation columns; this module parses whatever schema
//! it finds and produces a unified `FaceTimeCall` record so downstream
//! correlation sees one shape.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;

#[derive(Debug, Clone, PartialEq)]
pub struct FaceTimeCall {
    pub call_id: String,
    pub participants: Vec<String>,
    pub direction: String,
    pub started: DateTime<Utc>,
    pub ended: Option<DateTime<Utc>>,
    pub duration_seconds: Option<u64>,
    pub answered: bool,
    pub call_type: String,
    pub live_translation_used: bool,
    pub live_translation_languages: Vec<String>,
    pub device_os_version: Option<String>,
}

/// Detect whether the CallHistory storedata behind `conn` carries
/// the iOS 26 / Tahoe 26 column set. Used by the plugin host to
/// dispatch between the legacy parser and this one.
pub fn is_call_history_26(conn: &Connection) -> bool {
    let cols = column_names(conn, "ZCALLRECORD");
    cols.iter()
        .any(|c| c.eq_ignore_ascii_case("ZLIVETRANSLATION"))
        || cols
            .iter()
            .any(|c| c.eq_ignore_ascii_case("ZGROUPPARTICIPANTS"))
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

pub fn parse_calls(conn: &Connection) -> Vec<FaceTimeCall> {
    if !table_exists(conn, "ZCALLRECORD") {
        return Vec::new();
    }
    let cols = column_names(conn, "ZCALLRECORD");
    let pick = |candidates: &[&str]| -> String {
        for c in candidates {
            if cols.iter().any(|x| x.eq_ignore_ascii_case(c)) {
                return (*c).into();
            }
        }
        "NULL".into()
    };
    let id_col = pick(&["ZUUID", "ZCALLRECORDID", "ROWID"]);
    let date_col = pick(&["ZDATE", "ZSTARTDATE"]);
    let dur_col = pick(&["ZDURATION"]);
    let answered_col = pick(&["ZANSWERED"]);
    let direction_col = pick(&["ZORIGINATED", "ZDIRECTION"]);
    let type_col = pick(&["ZSERVICE_PROVIDER", "ZCALLTYPE"]);
    let participants_col = pick(&["ZGROUPPARTICIPANTS", "ZADDRESS"]);
    let translation_col = pick(&["ZLIVETRANSLATION"]);
    let sql = format!(
        "SELECT {}, {}, {}, {}, {}, {}, {}, {} FROM ZCALLRECORD",
        id_col,
        date_col,
        dur_col,
        answered_col,
        direction_col,
        type_col,
        participants_col,
        translation_col
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, rusqlite::types::Value>(0).ok(),
            r.get::<_, f64>(1).unwrap_or(0.0),
            r.get::<_, Option<i64>>(2).unwrap_or(None),
            r.get::<_, Option<i64>>(3).unwrap_or(None),
            r.get::<_, Option<i64>>(4).unwrap_or(None),
            r.get::<_, Option<String>>(5).unwrap_or(None),
            r.get::<_, Option<String>>(6).unwrap_or(None),
            r.get::<_, Option<i64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for row in rows.flatten() {
        let call_id = match row.0 {
            Some(rusqlite::types::Value::Text(s)) => s,
            Some(rusqlite::types::Value::Integer(i)) => i.to_string(),
            _ => String::new(),
        };
        let started = cocoa_to_utc(row.1).unwrap_or_else(unix_epoch);
        let duration = row.2.map(|v| v.max(0) as u64);
        let ended = duration.map(|d| started + chrono::Duration::seconds(d as i64));
        let answered = row.3.unwrap_or(0) != 0;
        let direction = match row.4.unwrap_or(0) {
            0 => "Incoming",
            _ => "Outgoing",
        }
        .into();
        let call_type = row.5.unwrap_or_else(|| "FaceTime".into());
        let participants: Vec<String> = row
            .6
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let live_translation_used = row.7.unwrap_or(0) != 0;
        out.push(FaceTimeCall {
            call_id,
            participants,
            direction,
            started,
            ended,
            duration_seconds: duration,
            answered,
            call_type,
            live_translation_used,
            live_translation_languages: Vec::new(),
            device_os_version: None,
        });
    }
    out
}

fn unix_epoch() -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::UNIX_EPOCH)
}

fn table_exists(conn: &Connection, t: &str) -> bool {
    let sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?1";
    conn.query_row(sql, [t], |r| r.get::<_, String>(0)).is_ok()
}

fn cocoa_to_utc(secs: f64) -> Option<DateTime<Utc>> {
    if secs <= 0.0 {
        return None;
    }
    let cocoa_epoch_offset = 978_307_200i64;
    Utc.timestamp_opt(secs as i64 + cocoa_epoch_offset, 0)
        .single()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ios26_schema() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE ZCALLRECORD (\
                ZUUID TEXT, ZDATE REAL, ZDURATION INTEGER, ZANSWERED INTEGER, \
                ZORIGINATED INTEGER, ZSERVICE_PROVIDER TEXT, ZGROUPPARTICIPANTS TEXT, \
                ZLIVETRANSLATION INTEGER);",
        )
        .expect("schema");
        c
    }

    #[test]
    fn detects_ios26_schema_via_translation_column() {
        let c = ios26_schema();
        assert!(is_call_history_26(&c));
    }

    #[test]
    fn parses_outgoing_group_call_with_translation() {
        let c = ios26_schema();
        c.execute(
            "INSERT INTO ZCALLRECORD VALUES ('uuid-1', 700000000.0, 120, 1, 1, 'FaceTimeVideo', 'alice@apple.com, bob@apple.com', 1)",
            [],
        )
        .expect("ins");
        let calls = parse_calls(&c);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].direction, "Outgoing");
        assert!(calls[0].answered);
        assert!(calls[0].live_translation_used);
        assert_eq!(calls[0].participants.len(), 2);
        assert_eq!(calls[0].duration_seconds, Some(120));
    }

    #[test]
    fn legacy_schema_returns_empty_for_is_call_history_26() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch("CREATE TABLE ZCALLRECORD (ZDATE REAL, ZDURATION INTEGER);")
            .expect("schema");
        assert!(!is_call_history_26(&c));
    }

    #[test]
    fn legacy_schema_still_parses_into_unified_shape() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE ZCALLRECORD (\
                ZUUID TEXT, ZDATE REAL, ZDURATION INTEGER, ZANSWERED INTEGER, \
                ZORIGINATED INTEGER, ZSERVICE_PROVIDER TEXT, ZADDRESS TEXT);",
        )
        .expect("schema");
        c.execute(
            "INSERT INTO ZCALLRECORD VALUES ('a', 700000000.0, 30, 0, 0, 'FaceTimeAudio', '+15551234567')",
            [],
        )
        .expect("ins");
        let calls = parse_calls(&c);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].direction, "Incoming");
        assert!(!calls[0].live_translation_used);
    }

    #[test]
    fn missing_table_returns_empty() {
        let c = Connection::open_in_memory().expect("open");
        assert!(parse_calls(&c).is_empty());
    }
}
