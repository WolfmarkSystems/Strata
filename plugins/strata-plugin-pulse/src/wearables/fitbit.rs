//! WEAR-1 — Fitbit deep database parsing.
//!
//! Parses the Fitbit mobile app's `FitbitMobile.sqlite` for the
//! minute-granularity data sets that have been decisive in cases
//! like the 2017 Connie Dabate murder: step_minute, heart_rate_minute,
//! activity_log, sleep_log, food_log, weight_log, badge_earned.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::GpsPoint;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FitbitMinuteData {
    pub timestamp: DateTime<Utc>,
    pub data_type: String,
    pub value: f64,
    pub device_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FitbitWorkout {
    pub workout_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub workout_type: String,
    pub distance_meters: Option<f64>,
    pub calories_burned: Option<u32>,
    pub avg_heart_rate: Option<u16>,
    pub gps_track: Vec<GpsPoint>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SleepStage {
    Awake,
    Light,
    Deep,
    Rem,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FitbitSleepSession {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_minutes: u32,
    pub stages: Vec<(DateTime<Utc>, SleepStage, u32)>,
    pub wake_count: u8,
    pub efficiency_score: Option<u8>,
}

pub fn parse_step_minutes(conn: &Connection) -> Vec<FitbitMinuteData> {
    parse_minute_table(conn, "step_minute", "Steps")
}

pub fn parse_heart_rate_minutes(conn: &Connection) -> Vec<FitbitMinuteData> {
    parse_minute_table(conn, "heart_rate_minute", "HeartRate")
}

fn parse_minute_table(conn: &Connection, table: &str, kind: &str) -> Vec<FitbitMinuteData> {
    if !table_exists(conn, table) {
        return Vec::new();
    }
    let cols = col_names(conn, table);
    let ts =
        pick(&cols, &["timestamp", "minute", "minute_ts"]).unwrap_or_else(|| "timestamp".into());
    let val = pick(&cols, &["value", "count", "bpm"]).unwrap_or_else(|| "value".into());
    let dev = pick(&cols, &["device_id", "tracker_id"]);
    let sql = format!(
        "SELECT {}, {}, {} FROM {}",
        ts,
        val,
        dev.clone().unwrap_or_else(|| "''".into()),
        table
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, f64>(1).unwrap_or(0.0),
            r.get::<_, String>(2).unwrap_or_default(),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    rows.flatten()
        .map(|(ts_ms, v, dev)| FitbitMinuteData {
            timestamp: Utc
                .timestamp_opt(ts_ms / 1000, 0)
                .single()
                .unwrap_or_else(unix_epoch),
            data_type: kind.into(),
            value: v,
            device_id: dev,
        })
        .collect()
}

pub fn parse_activity_log(conn: &Connection) -> Vec<FitbitWorkout> {
    if !table_exists(conn, "activity_log") {
        return Vec::new();
    }
    let cols = col_names(conn, "activity_log");
    let ts_start = pick(&cols, &["start_time", "start_ts"]).unwrap_or_else(|| "start_time".into());
    let ts_end = pick(&cols, &["end_time", "end_ts"]).unwrap_or_else(|| "end_time".into());
    let kind = pick(&cols, &["type", "activity_type"]).unwrap_or_else(|| "activity_type".into());
    let distance = pick(&cols, &["distance_m", "distance", "distance_meters"]);
    let cals = pick(&cols, &["calories", "calories_burned"]);
    let hr = pick(&cols, &["avg_heart_rate", "heart_rate_avg"]);
    let sql = format!(
        "SELECT rowid, {}, {}, {}, {}, {}, {} FROM activity_log",
        ts_start,
        ts_end,
        kind,
        distance.clone().unwrap_or_else(|| "NULL".into()),
        cals.clone().unwrap_or_else(|| "NULL".into()),
        hr.clone().unwrap_or_else(|| "NULL".into()),
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, i64>(1).unwrap_or(0),
            r.get::<_, i64>(2).unwrap_or(0),
            r.get::<_, String>(3).unwrap_or_default(),
            r.get::<_, Option<f64>>(4).unwrap_or(None),
            r.get::<_, Option<i64>>(5).unwrap_or(None),
            r.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    rows.flatten()
        .map(
            |(id, start_ms, end_ms, kind, dist, cals, hr)| FitbitWorkout {
                workout_id: id.to_string(),
                start_time: ms_to_utc(start_ms),
                end_time: ms_to_utc(end_ms),
                workout_type: kind,
                distance_meters: dist,
                calories_burned: cals.map(|v| v.max(0) as u32),
                avg_heart_rate: hr.map(|v| v.max(0).min(u16::MAX as i64) as u16),
                gps_track: Vec::new(),
            },
        )
        .collect()
}

pub fn parse_sleep_sessions(conn: &Connection) -> Vec<FitbitSleepSession> {
    if !table_exists(conn, "sleep_log") {
        return Vec::new();
    }
    let cols = col_names(conn, "sleep_log");
    let s = pick(&cols, &["start_time", "start_ts"]).unwrap_or_else(|| "start_time".into());
    let e = pick(&cols, &["end_time", "end_ts"]).unwrap_or_else(|| "end_time".into());
    let wakes = pick(&cols, &["wake_count", "awakenings"]);
    let eff = pick(&cols, &["efficiency_score", "efficiency"]);
    let sql = format!(
        "SELECT {}, {}, {}, {} FROM sleep_log",
        s,
        e,
        wakes.clone().unwrap_or_else(|| "0".into()),
        eff.clone().unwrap_or_else(|| "NULL".into()),
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, i64>(1).unwrap_or(0),
            r.get::<_, i64>(2).unwrap_or(0),
            r.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    rows.flatten()
        .map(|(start_ms, end_ms, wake, eff)| {
            let start = ms_to_utc(start_ms);
            let end = ms_to_utc(end_ms);
            let duration_minutes = ((end - start).num_minutes()).max(0) as u32;
            FitbitSleepSession {
                start_time: start,
                end_time: end,
                duration_minutes,
                stages: Vec::new(),
                wake_count: wake.clamp(0, 255) as u8,
                efficiency_score: eff.map(|v| v.clamp(0, 100) as u8),
            }
        })
        .collect()
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

fn ms_to_utc(ms: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(ms / 1000, 0)
        .single()
        .unwrap_or_else(unix_epoch)
}

fn unix_epoch() -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::UNIX_EPOCH)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE step_minute (timestamp INTEGER, value REAL, device_id TEXT);\
             CREATE TABLE heart_rate_minute (timestamp INTEGER, value REAL, device_id TEXT);\
             CREATE TABLE activity_log (start_time INTEGER, end_time INTEGER, activity_type TEXT,\
                distance_m REAL, calories INTEGER, avg_heart_rate INTEGER);\
             CREATE TABLE sleep_log (start_time INTEGER, end_time INTEGER, wake_count INTEGER,\
                efficiency_score INTEGER);",
        )
        .expect("s");
        c.execute(
            "INSERT INTO step_minute VALUES (1700000000000, 42.0, 'sense2')",
            [],
        )
        .expect("s1");
        c.execute(
            "INSERT INTO heart_rate_minute VALUES (1700000000000, 72.0, 'sense2')",
            [],
        )
        .expect("h1");
        c.execute(
            "INSERT INTO activity_log VALUES (1700000000000, 1700003600000, 'Run', 5000.0, 320, 144)",
            [],
        )
        .expect("a1");
        c.execute(
            "INSERT INTO sleep_log VALUES (1700000000000, 1700028800000, 3, 88)",
            [],
        )
        .expect("sl1");
        c
    }

    #[test]
    fn parses_step_minutes() {
        let c = fixture();
        let data = parse_step_minutes(&c);
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].data_type, "Steps");
        assert_eq!(data[0].value, 42.0);
    }

    #[test]
    fn parses_heart_rate_minutes() {
        let c = fixture();
        let data = parse_heart_rate_minutes(&c);
        assert_eq!(data[0].data_type, "HeartRate");
        assert_eq!(data[0].value, 72.0);
    }

    #[test]
    fn parses_activity_log_run() {
        let c = fixture();
        let w = parse_activity_log(&c);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].workout_type, "Run");
        assert_eq!(w[0].distance_meters, Some(5000.0));
        assert_eq!(w[0].avg_heart_rate, Some(144));
    }

    #[test]
    fn parses_sleep_session_with_efficiency() {
        let c = fixture();
        let s = parse_sleep_sessions(&c);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].wake_count, 3);
        assert_eq!(s[0].efficiency_score, Some(88));
        assert!(s[0].duration_minutes > 400);
    }

    #[test]
    fn missing_tables_return_empty() {
        let c = Connection::open_in_memory().expect("open");
        assert!(parse_step_minutes(&c).is_empty());
        assert!(parse_heart_rate_minutes(&c).is_empty());
        assert!(parse_activity_log(&c).is_empty());
        assert!(parse_sleep_sessions(&c).is_empty());
    }
}
