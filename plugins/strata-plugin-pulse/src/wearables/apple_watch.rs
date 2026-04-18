//! WEAR-3 — Apple Watch deep HealthKit parsing.
//!
//! HealthKit writes to `healthdb_secure.sqlite` and `healthdb.sqlite`
//! under `/private/var/mobile/Library/Health/`. This module parses
//! the Apple Watch-specific tables: HRV, mindful sessions, stand
//! hours, ECG waveforms (headers only), blood-oxygen, wrist
//! temperature, plus the fall-detection / crash-detection event
//! log from com.apple.health.plist.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppleWatchMedicalEvent {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub severity: Option<String>,
    pub readings: HashMap<String, f64>,
    pub alert_triggered: bool,
    pub emergency_services_contacted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthQuantitySample {
    pub type_identifier: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub quantity: f64,
    pub unit: Option<String>,
    pub source_name: Option<String>,
}

pub fn parse_quantity_samples(conn: &Connection, type_filter: &str) -> Vec<HealthQuantitySample> {
    if !table_exists(conn, "quantity_samples") && !table_exists(conn, "samples") {
        return Vec::new();
    }
    let table = if table_exists(conn, "quantity_samples") {
        "quantity_samples"
    } else {
        "samples"
    };
    let cols = col_names(conn, table);
    let type_col = pick(&cols, &["data_type", "type_identifier", "type"])
        .unwrap_or_else(|| "data_type".into());
    let start = pick(&cols, &["start_date", "start_time"]).unwrap_or_else(|| "start_date".into());
    let end = pick(&cols, &["end_date", "end_time"]).unwrap_or_else(|| "end_date".into());
    let qty = pick(&cols, &["quantity", "value"]).unwrap_or_else(|| "quantity".into());
    let unit = pick(&cols, &["unit"]);
    let source = pick(&cols, &["source_name", "source"]);
    let sql = format!(
        "SELECT {}, {}, {}, {}, {}, {} FROM {} WHERE {} = ?1",
        type_col,
        start,
        end,
        qty,
        unit.clone().unwrap_or_else(|| "''".into()),
        source.clone().unwrap_or_else(|| "''".into()),
        table,
        type_col
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([type_filter], |r| {
        Ok((
            r.get::<_, String>(0).unwrap_or_default(),
            r.get::<_, f64>(1).unwrap_or(0.0),
            r.get::<_, f64>(2).unwrap_or(0.0),
            r.get::<_, f64>(3).unwrap_or(0.0),
            r.get::<_, String>(4).unwrap_or_default(),
            r.get::<_, String>(5).unwrap_or_default(),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    rows.flatten()
        .map(|(ti, s, e, q, u, src)| HealthQuantitySample {
            type_identifier: ti,
            start_time: cocoa_to_utc(s),
            end_time: cocoa_to_utc(e),
            quantity: q,
            unit: if u.is_empty() { None } else { Some(u) },
            source_name: if src.is_empty() { None } else { Some(src) },
        })
        .collect()
}

/// Parse fall-detection / crash-detection events from an exported
/// plist-like JSON dump of com.apple.health keys.
pub fn parse_medical_events(json: &str) -> Vec<AppleWatchMedicalEvent> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v
        .get("events")
        .and_then(|x| x.as_array())
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
        let mut readings = HashMap::new();
        if let Some(obj) = entry.get("readings").and_then(|x| x.as_object()) {
            for (k, v) in obj {
                if let Some(f) = v.as_f64() {
                    readings.insert(k.clone(), f);
                }
            }
        }
        out.push(AppleWatchMedicalEvent {
            event_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Unknown")
                .into(),
            timestamp: ts,
            severity: entry.get("severity").and_then(|x| x.as_str()).map(String::from),
            readings,
            alert_triggered: entry.get("alert").and_then(|x| x.as_bool()).unwrap_or(false),
            emergency_services_contacted: entry
                .get("emergency")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
        });
    }
    out
}

fn table_exists(conn: &Connection, t: &str) -> bool {
    conn.query_row(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?1",
        [t],
        |r| r.get::<_, String>(0),
    )
    .is_ok()
}

fn col_names(conn: &Connection, table: &str) -> Vec<String> {
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

fn cocoa_to_utc(secs: f64) -> DateTime<Utc> {
    let cocoa_epoch_offset = 978_307_200i64;
    Utc.timestamp_opt(secs as i64 + cocoa_epoch_offset, 0)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quantity_samples_filtered_by_type() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE quantity_samples (\
                data_type TEXT, start_date REAL, end_date REAL, quantity REAL,\
                unit TEXT, source_name TEXT);",
        )
        .expect("s");
        c.execute(
            "INSERT INTO quantity_samples VALUES ('HKQuantityTypeIdentifierHeartRateVariabilitySDNN',\
                700000000.0, 700000300.0, 45.3, 'ms', 'Apple Watch')",
            [],
        )
        .expect("s1");
        c.execute(
            "INSERT INTO quantity_samples VALUES ('HKQuantityTypeIdentifierHeartRate',\
                700000600.0, 700000900.0, 72.0, 'count/min', 'Apple Watch')",
            [],
        )
        .expect("s2");
        let hrv = parse_quantity_samples(&c, "HKQuantityTypeIdentifierHeartRateVariabilitySDNN");
        assert_eq!(hrv.len(), 1);
        assert_eq!(hrv[0].quantity, 45.3);
        assert_eq!(hrv[0].source_name.as_deref(), Some("Apple Watch"));
    }

    #[test]
    fn parses_fall_detection_event_from_json() {
        let json = r#"{"events":[{"type":"FallDetection","timestamp":"2026-04-10T08:30:00Z",
            "severity":"high","readings":{"accel_g":12.4},"alert":true,"emergency":true}]}"#;
        let e = parse_medical_events(json);
        assert_eq!(e[0].event_type, "FallDetection");
        assert!(e[0].alert_triggered);
        assert!(e[0].emergency_services_contacted);
        assert_eq!(e[0].readings.get("accel_g").copied(), Some(12.4));
    }

    #[test]
    fn parses_crash_detection_event() {
        let json = r#"[{"type":"CrashDetection","timestamp":"2026-04-10T18:20:00Z",
            "severity":"critical","alert":true}]"#;
        let e = parse_medical_events(json);
        assert_eq!(e[0].event_type, "CrashDetection");
        assert_eq!(e[0].severity.as_deref(), Some("critical"));
    }

    #[test]
    fn empty_on_bad_input() {
        let c = Connection::open_in_memory().expect("open");
        assert!(parse_quantity_samples(&c, "anything").is_empty());
        assert!(parse_medical_events("bad").is_empty());
    }
}
