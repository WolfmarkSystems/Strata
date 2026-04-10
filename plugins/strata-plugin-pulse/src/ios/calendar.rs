//! iOS Calendar — `Calendar.sqlitedb`.
//!
//! `Calendar.sqlitedb` lives under `Library/Calendar/`. The relevant
//! tables iLEAPP keys off:
//!   * `CalendarItem` — events with `summary`, `description`,
//!     `start_date`, `end_date` (Cocoa seconds)
//!   * `Calendar`     — calendar metadata (title, color, account)
//!   * `Participant`  — invitees / organizers
//!
//! Pulse v1.0 emits row counts and date range; per-event listing is
//! queued for v1.1.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["calendar.sqlitedb"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "CalendarItem") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let event_count = util::count_rows(&conn, "CalendarItem");

    let (first, last) = conn
        .prepare(
            "SELECT MIN(start_date), MAX(start_date) FROM CalendarItem \
             WHERE start_date IS NOT NULL",
        )
        .and_then(|mut s| {
            s.query_row([], |row| {
                Ok((row.get::<_, Option<f64>>(0)?, row.get::<_, Option<f64>>(1)?))
            })
        })
        .unwrap_or((None, None));
    let first_unix = first.and_then(util::cf_absolute_to_unix);
    let last_unix = last.and_then(util::cf_absolute_to_unix);

    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Calendar".to_string(),
        timestamp: first_unix,
        title: "iOS Calendar".to_string(),
        detail: format!(
            "{} CalendarItem rows (events), date range {:?}..{:?} Unix",
            event_count, first_unix, last_unix
        ),
        source_path: source.clone(),
        forensic_value: ForensicValue::High,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
    });

    if util::table_exists(&conn, "Calendar") {
        let cals = util::count_rows(&conn, "Calendar");
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Calendar accounts".to_string(),
            timestamp: None,
            title: "Calendar accounts".to_string(),
            detail: format!("{} Calendar (account) rows", cals),
            source_path: source.clone(),
            forensic_value: ForensicValue::Medium,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
        });
    }
    if util::table_exists(&conn, "Participant") {
        let p = util::count_rows(&conn, "Participant");
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Calendar participants".to_string(),
            timestamp: None,
            title: "Calendar participants".to_string(),
            detail: format!("{} Participant rows (invitees, organizers)", p),
            source_path: source,
            forensic_value: ForensicValue::Medium,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_calendar_db(events: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE CalendarItem (\
                ROWID INTEGER PRIMARY KEY, \
                summary TEXT, \
                start_date DOUBLE, \
                end_date DOUBLE \
             )",
            [],
        )
        .unwrap();
        c.execute("CREATE TABLE Calendar (ROWID INTEGER PRIMARY KEY, title TEXT)", [])
            .unwrap();
        c.execute(
            "CREATE TABLE Participant (ROWID INTEGER PRIMARY KEY, email TEXT)",
            [],
        )
        .unwrap();
        for i in 0..events {
            c.execute(
                "INSERT INTO CalendarItem (summary, start_date, end_date) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    format!("event {}", i),
                    700_000_000.0_f64 + i as f64,
                    700_000_010.0_f64 + i as f64
                ],
            )
            .unwrap();
        }
        c.execute("INSERT INTO Calendar (title) VALUES ('Personal')", [])
            .unwrap();
        c.execute("INSERT INTO Participant (email) VALUES ('a@b.com')", [])
            .unwrap();
        tmp
    }

    #[test]
    fn matches_calendar_filename() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Calendar/Calendar.sqlitedb"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_event_calendar_and_participant_counts() {
        let tmp = make_calendar_db(4);
        let recs = parse(tmp.path());
        let cal = recs.iter().find(|r| r.subcategory == "Calendar").unwrap();
        assert!(cal.detail.contains("4 CalendarItem"));
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "Calendar accounts"));
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "Calendar participants"));
    }

    #[test]
    fn empty_calendar_db_emits_summary_only() {
        let tmp = make_calendar_db(0);
        let recs = parse(tmp.path());
        let cal = recs.iter().find(|r| r.subcategory == "Calendar").unwrap();
        assert!(cal.detail.contains("0 CalendarItem"));
    }

    #[test]
    fn missing_calendaritem_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }
}
