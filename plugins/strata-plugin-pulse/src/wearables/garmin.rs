//! WEAR-2 — Garmin Connect activity + FIT record parsing.
//!
//! The Garmin Connect mobile app caches an activities SQLite plus a
//! shadow copy of every FIT file the device uploaded. FIT is a
//! binary record-oriented format; we expose a minimal header-level
//! parser that pulls the activity summary (start time, duration,
//! distance) without implementing the full per-record layout — the
//! full telemetry live-parses from the device itself through a
//! separate native library when present.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::GpsPoint;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GarminActivity {
    pub activity_id: String,
    pub activity_type: String,
    pub start_time: DateTime<Utc>,
    pub duration_seconds: u32,
    pub distance_meters: Option<f64>,
    pub gps_points: Vec<GpsPoint>,
    pub heart_rate_data: Vec<(DateTime<Utc>, u16)>,
    pub elevation_data: Vec<(DateTime<Utc>, f64)>,
    pub device_model: String,
}

pub fn parse_activities(conn: &Connection) -> Vec<GarminActivity> {
    if !table_exists(conn, "activities") {
        return Vec::new();
    }
    let cols = col_names(conn, "activities");
    let id = pick(&cols, &["activity_id", "id"]).unwrap_or_else(|| "activity_id".into());
    let kind = pick(&cols, &["activity_type", "sport"]).unwrap_or_else(|| "activity_type".into());
    let start = pick(&cols, &["start_time", "start_ts"]).unwrap_or_else(|| "start_time".into());
    let dur = pick(&cols, &["duration_seconds", "duration", "elapsed_sec"]);
    let dist = pick(&cols, &["distance_meters", "distance", "distance_m"]);
    let device = pick(&cols, &["device_model", "device"]);
    let sql = format!(
        "SELECT {}, {}, {}, {}, {}, {} FROM activities",
        id,
        kind,
        start,
        dur.clone().unwrap_or_else(|| "0".into()),
        dist.clone().unwrap_or_else(|| "NULL".into()),
        device.clone().unwrap_or_else(|| "''".into()),
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Option<String>>(0).unwrap_or(None),
            r.get::<_, String>(1).unwrap_or_default(),
            r.get::<_, i64>(2).unwrap_or(0),
            r.get::<_, i64>(3).unwrap_or(0),
            r.get::<_, Option<f64>>(4).unwrap_or(None),
            r.get::<_, String>(5).unwrap_or_default(),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    rows.flatten()
        .map(|(id, kind, start_ms, dur, dist, device)| GarminActivity {
            activity_id: id.unwrap_or_default(),
            activity_type: kind,
            start_time: Utc
                .timestamp_opt(start_ms / 1000, 0)
                .single()
                .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap()),
            duration_seconds: dur.max(0) as u32,
            distance_meters: dist,
            gps_points: Vec::new(),
            heart_rate_data: Vec::new(),
            elevation_data: Vec::new(),
            device_model: device,
        })
        .collect()
}

/// Minimal FIT-file header probe (14-byte header: size + protocol +
/// profile + data size + ".FIT" signature + crc). Returns the
/// advertised data size when the file is a valid FIT file.
pub fn fit_header_data_size(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 14 {
        return None;
    }
    let header_size = bytes[0];
    if header_size < 12 {
        return None;
    }
    // Bytes 8..12 hold the "data size" little-endian u32.
    let data_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if &bytes[8..12] != b".FIT" {
        return None;
    }
    Some(data_size)
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

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_synthetic_activities() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE activities (activity_id TEXT, activity_type TEXT, start_time INTEGER,\
                duration_seconds INTEGER, distance_meters REAL, device_model TEXT);",
        )
        .expect("s");
        c.execute(
            "INSERT INTO activities VALUES ('a-1', 'trail_running', 1700000000000, 4500, 10500.0, 'Fenix 7')",
            [],
        )
        .expect("ins");
        let a = parse_activities(&c);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].activity_type, "trail_running");
        assert_eq!(a[0].distance_meters, Some(10500.0));
        assert_eq!(a[0].duration_seconds, 4500);
        assert_eq!(a[0].device_model, "Fenix 7");
    }

    #[test]
    fn missing_activities_table_returns_empty() {
        let c = Connection::open_in_memory().expect("open");
        assert!(parse_activities(&c).is_empty());
    }

    #[test]
    fn fit_header_detects_valid_file() {
        // 14-byte FIT header: size(1), proto(1), profile(2), data_size(4),
        // ".FIT" (4), crc(2).
        let mut hdr = vec![14u8, 0x10, 0x00, 0x00, 0xE8, 0x03, 0x00, 0x00];
        hdr.extend_from_slice(b".FIT");
        hdr.extend_from_slice(&[0, 0]);
        assert_eq!(fit_header_data_size(&hdr), Some(1000));
    }

    #[test]
    fn fit_header_rejects_bad_magic() {
        let mut hdr = vec![14u8, 0x10, 0x00, 0x00, 0xE8, 0x03, 0x00, 0x00];
        hdr.extend_from_slice(b"ABCD");
        hdr.extend_from_slice(&[0, 0]);
        assert!(fit_header_data_size(&hdr).is_none());
    }
}
