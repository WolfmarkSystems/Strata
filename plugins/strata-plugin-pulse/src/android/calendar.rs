//! Calendar — events from the Android Calendar provider.
//!
//! ALEAPP reference: `scripts/artifacts/calendarEvents.py`. Source path:
//! `/data/data/com.android.providers.calendar/databases/calendar.db`
//! with the `Events` table:
//!
//! - `_id`
//! - `title`
//! - `description`
//! - `eventLocation`
//! - `dtstart` / `dtend` — Unix milliseconds
//! - `organizer`
//! - `eventStatus`

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["calendar.db", "calendarprovider.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "Events") {
        return Vec::new();
    }
    read_events(&conn, path)
}

fn read_events(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_title = column_exists(conn, "Events", "title");
    let has_desc = column_exists(conn, "Events", "description");
    let has_location = column_exists(conn, "Events", "eventLocation");
    let has_start = column_exists(conn, "Events", "dtstart");
    let has_end = column_exists(conn, "Events", "dtend");
    let has_organizer = column_exists(conn, "Events", "organizer");

    if !has_title {
        return Vec::new();
    }

    let sql = format!(
        "SELECT title, {}, {}, {}, {}, {} FROM Events ORDER BY {} DESC LIMIT 5000",
        if has_desc { "description" } else { "''" },
        if has_location { "eventLocation" } else { "''" },
        if has_start { "dtstart" } else { "0" },
        if has_end { "dtend" } else { "0" },
        if has_organizer { "organizer" } else { "''" },
        if has_start { "dtstart" } else { "_id" }
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
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (title, desc, loc, dtstart_ms, dtend_ms, organizer) in rows.flatten() {
        let title = title.unwrap_or_default();
        if title.is_empty() {
            continue;
        }
        let ts = dtstart_ms.and_then(unix_ms_to_i64);
        let detail = format!(
            "Calendar event title='{}' description='{}' location='{}' organizer='{}' end_ms={}",
            title,
            desc.unwrap_or_default(),
            loc.unwrap_or_default(),
            organizer.unwrap_or_default(),
            dtend_ms.unwrap_or(0)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Android Calendar",
            format!("Event: {}", title),
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
                title TEXT,
                description TEXT,
                eventLocation TEXT,
                dtstart INTEGER,
                dtend INTEGER,
                organizer TEXT
            );
            INSERT INTO Events VALUES (1,'Dentist','Cleaning','Main St',1609459200000,1609462800000,'reception@dentist.example');
            INSERT INTO Events VALUES (2,'Court hearing','Bring docs','Courthouse',1609545600000,1609552800000,'clerk@court.example');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_events() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn title_appears_in_record_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|x| x.title == "Event: Dentist"));
        assert!(r.iter().any(|x| x.title == "Event: Court hearing"));
    }

    #[test]
    fn organizer_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let dentist = r.iter().find(|x| x.title.contains("Dentist")).unwrap();
        assert!(dentist.detail.contains("reception@dentist.example"));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE foo(x INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
