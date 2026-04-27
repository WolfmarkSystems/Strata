//! ANDROID16-2 — Samsung Rubin + Digital Wellbeing Android 15/16
//! schema updates.
//!
//! Adds coverage for the new-in-Android-15/16 fields:
//!   * Rubin location-based app suggestions (proves device location
//!     at suggestion time)
//!   * Rubin routine / context-detection events (driving / at-home /
//!     at-work triggers)
//!   * Digital Wellbeing focus-mode activation + bedtime mode +
//!     app-timer override records
//!
//! The existing `samsung.rs` keeps its legacy-schema coverage; this
//! module sits alongside it and fires when the newer columns are
//! present.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;

#[derive(Debug, Clone, PartialEq)]
pub struct RubinEvent {
    pub timestamp: DateTime<Utc>,
    pub event_kind: RubinEventKind,
    pub package: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub context: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RubinEventKind {
    AppSuggestion,
    RoutineTrigger,
    ContextDetection,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct WellbeingEvent {
    pub timestamp: DateTime<Utc>,
    pub kind: WellbeingEventKind,
    pub package: Option<String>,
    pub duration_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WellbeingEventKind {
    FocusModeEnabled,
    FocusModeDisabled,
    BedtimeModeActivated,
    AppTimerConfigured,
    AppTimerOverride,
    DailySummary,
    Unknown(String),
}

pub fn parse_rubin_events(conn: &Connection) -> Vec<RubinEvent> {
    let Some(table) = first_table(conn, &["rubin_events", "context_events", "suggestions"]) else {
        return Vec::new();
    };
    let cols = col_names(conn, &table);
    let ts = pick(&cols, &["timestamp", "event_time"]).unwrap_or_else(|| "timestamp".into());
    let kind = pick(&cols, &["event_type", "kind"]).unwrap_or_else(|| "event_type".into());
    let pkg = pick(&cols, &["package_name", "package"]);
    let lat = pick(&cols, &["latitude", "lat"]);
    let lon = pick(&cols, &["longitude", "lon", "lng"]);
    let ctx = pick(&cols, &["context", "context_name"]);
    let sql = format!(
        "SELECT {}, {}, {}, {}, {}, {} FROM {}",
        ts,
        kind,
        pkg.clone().unwrap_or_else(|| "NULL".into()),
        lat.clone().unwrap_or_else(|| "NULL".into()),
        lon.clone().unwrap_or_else(|| "NULL".into()),
        ctx.clone().unwrap_or_else(|| "NULL".into()),
        table,
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, Option<String>>(1)
                .unwrap_or(None)
                .unwrap_or_default(),
            r.get::<_, Option<String>>(2).unwrap_or(None),
            r.get::<_, Option<f64>>(3).unwrap_or(None),
            r.get::<_, Option<f64>>(4).unwrap_or(None),
            r.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    let mut out = Vec::new();
    for (ts, kind_raw, pkg, lat, lon, ctx) in rows.flatten() {
        let timestamp = Utc
            .timestamp_opt(ts / 1000, 0)
            .single()
            .unwrap_or_else(unix_epoch);
        let event_kind = match kind_raw.as_str() {
            "app_suggestion" | "suggestion" => RubinEventKind::AppSuggestion,
            "routine" | "routine_trigger" => RubinEventKind::RoutineTrigger,
            "context" | "context_detection" => RubinEventKind::ContextDetection,
            other => RubinEventKind::Unknown(other.to_string()),
        };
        out.push(RubinEvent {
            timestamp,
            event_kind,
            package: pkg,
            latitude: lat,
            longitude: lon,
            context: ctx,
        });
    }
    out
}

pub fn parse_wellbeing_events(conn: &Connection) -> Vec<WellbeingEvent> {
    let Some(table) = first_table(conn, &["wellbeing_events", "app_usage", "focus_events"]) else {
        return Vec::new();
    };
    let cols = col_names(conn, &table);
    let ts = pick(&cols, &["timestamp", "event_time"]).unwrap_or_else(|| "timestamp".into());
    let kind = pick(&cols, &["event_type", "kind"]).unwrap_or_else(|| "event_type".into());
    let pkg = pick(&cols, &["package_name", "package"]);
    let dur = pick(&cols, &["duration_seconds", "duration_ms", "duration"]);
    let sql = format!(
        "SELECT {}, {}, {}, {} FROM {}",
        ts,
        kind,
        pkg.clone().unwrap_or_else(|| "NULL".into()),
        dur.clone().unwrap_or_else(|| "NULL".into()),
        table,
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, Option<String>>(1)
                .unwrap_or(None)
                .unwrap_or_default(),
            r.get::<_, Option<String>>(2).unwrap_or(None),
            r.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    let mut out = Vec::new();
    for (ts, kind_raw, pkg, dur) in rows.flatten() {
        let timestamp = Utc
            .timestamp_opt(ts / 1000, 0)
            .single()
            .unwrap_or_else(unix_epoch);
        let kind = match kind_raw.to_ascii_lowercase().as_str() {
            "focus_on" | "focus_mode_enabled" => WellbeingEventKind::FocusModeEnabled,
            "focus_off" | "focus_mode_disabled" => WellbeingEventKind::FocusModeDisabled,
            "bedtime" | "bedtime_activated" => WellbeingEventKind::BedtimeModeActivated,
            "timer" | "timer_configured" => WellbeingEventKind::AppTimerConfigured,
            "override" | "timer_override" => WellbeingEventKind::AppTimerOverride,
            "daily" | "summary" => WellbeingEventKind::DailySummary,
            other => WellbeingEventKind::Unknown(other.to_string()),
        };
        out.push(WellbeingEvent {
            timestamp,
            kind,
            package: pkg,
            duration_seconds: dur.map(|v| v.max(0) as u64),
        });
    }
    out
}

fn unix_epoch() -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::UNIX_EPOCH)
}

fn first_table(conn: &Connection, candidates: &[&str]) -> Option<String> {
    for t in candidates {
        let sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?1";
        if conn.query_row(sql, [t], |r| r.get::<_, String>(0)).is_ok() {
            return Some((*t).into());
        }
    }
    None
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
    fn parses_rubin_app_suggestion_with_location() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE rubin_events (\
                timestamp INTEGER, event_type TEXT, package_name TEXT,\
                latitude REAL, longitude REAL, context TEXT);",
        )
        .expect("s");
        c.execute(
            "INSERT INTO rubin_events VALUES (1700000000000, 'app_suggestion', 'com.netflix', 40.7128, -74.0060, 'at_home')",
            [],
        )
        .expect("i");
        let events = parse_rubin_events(&c);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_kind, RubinEventKind::AppSuggestion);
        assert_eq!(events[0].latitude, Some(40.7128));
        assert_eq!(events[0].context.as_deref(), Some("at_home"));
    }

    #[test]
    fn parses_wellbeing_focus_mode_events() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE wellbeing_events (\
                timestamp INTEGER, event_type TEXT, package_name TEXT, duration_seconds INTEGER);",
        )
        .expect("s");
        c.execute(
            "INSERT INTO wellbeing_events VALUES (1700000000000, 'focus_on', NULL, NULL)",
            [],
        )
        .expect("i");
        c.execute(
            "INSERT INTO wellbeing_events VALUES (1700001800000, 'focus_off', NULL, 1800)",
            [],
        )
        .expect("i");
        let events = parse_wellbeing_events(&c);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, WellbeingEventKind::FocusModeEnabled);
        assert_eq!(events[1].kind, WellbeingEventKind::FocusModeDisabled);
        assert_eq!(events[1].duration_seconds, Some(1800));
    }

    #[test]
    fn unknown_event_kind_preserved_as_string() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch("CREATE TABLE rubin_events (timestamp INTEGER, event_type TEXT);")
            .expect("s");
        c.execute(
            "INSERT INTO rubin_events VALUES (1700000000000, 'custom_kind_xyz')",
            [],
        )
        .expect("i");
        let events = parse_rubin_events(&c);
        assert_eq!(events.len(), 1);
        match &events[0].event_kind {
            RubinEventKind::Unknown(s) => assert_eq!(s, "custom_kind_xyz"),
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn missing_table_returns_empty() {
        let c = Connection::open_in_memory().expect("open");
        assert!(parse_rubin_events(&c).is_empty());
        assert!(parse_wellbeing_events(&c).is_empty());
    }
}
