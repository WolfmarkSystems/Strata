//! Google Calendar — Android calendar event extraction (Google-specific).
//!
//! ALEAPP reference: `scripts/artifacts/googleCalendar.py`. Source path:
//! `/data/data/com.google.android.calendar/databases/cal_v2a`.
//!
//! This parser targets the Google Calendar app database; the existing
//! `calendar.rs` handles the generic Android calendar provider.
//!
//! Key tables: `Events`, `Calendars`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.google.android.calendar/databases/cal_v2a",
    "com.google.android.calendar/databases/cal_v2",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "Events") {
        return Vec::new();
    }
    read_events(&conn, path)
}

fn read_events(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT dtstart, dtend, title, description, \
               eventLocation, organizer, calendar_displayName, allDay \
               FROM Events \
               ORDER BY dtstart DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
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
    for (start_ms, _end_ms, title, desc, location, organizer, calendar, all_day) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled event)".to_string());
        let ts = start_ms.and_then(unix_ms_to_i64);
        let is_all_day = all_day.unwrap_or(0) != 0;
        let title_out = format!("Calendar: {}", title_str);
        let mut detail = format!("Google Calendar event title='{}'", title_str);
        if let Some(d) = desc.filter(|d| !d.is_empty()) {
            let preview: String = d.chars().take(200).collect();
            detail.push_str(&format!(" description='{}'", preview));
        }
        if let Some(l) = location.filter(|l| !l.is_empty()) {
            detail.push_str(&format!(" location='{}'", l));
        }
        if let Some(o) = organizer.filter(|o| !o.is_empty()) {
            detail.push_str(&format!(" organizer='{}'", o));
        }
        if let Some(c) = calendar.filter(|c| !c.is_empty()) {
            detail.push_str(&format!(" calendar='{}'", c));
        }
        if is_all_day {
            detail.push_str(" allDay=true");
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Google Calendar Event",
            title_out,
            detail,
            path,
            ts,
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
            CREATE TABLE Events (
                _id INTEGER PRIMARY KEY,
                dtstart INTEGER,
                dtend INTEGER,
                title TEXT,
                description TEXT,
                eventLocation TEXT,
                organizer TEXT,
                calendar_displayName TEXT,
                allDay INTEGER
            );
            INSERT INTO Events VALUES(1,1609459200000,1609462800000,'Team Standup','Daily sync meeting','Zoom','boss@company.com','Work',0);
            INSERT INTO Events VALUES(2,1609545600000,1609632000000,'Birthday Party',NULL,'123 Main St',NULL,'Personal',1);
            INSERT INTO Events VALUES(3,1609718400000,1609722000000,'Dentist',NULL,NULL,NULL,NULL,0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_events() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Google Calendar Event"));
    }

    #[test]
    fn location_and_organizer_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let standup = r
            .iter()
            .find(|a| a.detail.contains("Team Standup"))
            .unwrap();
        assert!(standup.detail.contains("location='Zoom'"));
        assert!(standup.detail.contains("organizer='boss@company.com'"));
    }

    #[test]
    fn all_day_flag() {
        let db = make_db();
        let r = parse(db.path());
        let bday = r.iter().find(|a| a.detail.contains("Birthday")).unwrap();
        assert!(bday.detail.contains("allDay=true"));
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
