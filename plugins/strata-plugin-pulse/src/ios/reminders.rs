//! iOS Reminders — `Calendar.sqlitedb` shares the same store as the
//! Calendar app, so this parser keys off `RemindersTodo` rows under
//! `Library/Calendar/`. iLEAPP also pulls from `Reminders.sqlite`
//! when the user has the standalone Reminders extension cache.
//!
//! Pulse v1.0 produces a row count + completed/incomplete breakdown
//! when the schema exposes a `completed_date` column.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["reminders.sqlite", "remindersdata.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    // Try modern table name first, fall back to the legacy variant.
    let table = if util::table_exists(&conn, "ZREMCDREMINDER") {
        Some("ZREMCDREMINDER")
    } else if util::table_exists(&conn, "Reminder") {
        Some("Reminder")
    } else {
        None
    };

    let Some(table) = table else {
        return out;
    };

    let count = util::count_rows(&conn, table);

    // Best-effort completed/incomplete split.
    let completed: i64 = conn
        .prepare(&format!(
            "SELECT COUNT(*) FROM {} WHERE \
             (CASE WHEN ZCOMPLETED IS NULL THEN 0 ELSE ZCOMPLETED END) = 1",
            table
        ))
        .and_then(|mut s| s.query_row([], |row| row.get(0)))
        .unwrap_or(0);

    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Reminders".to_string(),
        timestamp: None,
        title: "iOS Reminders".to_string(),
        detail: format!(
            "{} reminders in `{}` ({} completed)",
            count, table, completed
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_reminders(table: &str, completed: usize, total: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            &format!(
                "CREATE TABLE {} (Z_PK INTEGER PRIMARY KEY, ZTITLE TEXT, ZCOMPLETED INTEGER)",
                table
            ),
            [],
        )
        .unwrap();
        for i in 0..total {
            let done: i64 = if i < completed { 1 } else { 0 };
            c.execute(
                &format!(
                    "INSERT INTO {} (ZTITLE, ZCOMPLETED) VALUES (?1, ?2)",
                    table
                ),
                rusqlite::params![format!("todo {}", i), done],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_reminders_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Reminders/Reminders.sqlite"
        )));
        assert!(matches(Path::new("/copies/RemindersData.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_modern_zremcdreminder_schema() {
        let tmp = make_reminders("ZREMCDREMINDER", 2, 5);
        let recs = parse(tmp.path());
        let r = recs.iter().find(|r| r.subcategory == "Reminders").unwrap();
        assert!(r.detail.contains("5 reminders"));
        assert!(r.detail.contains("2 completed"));
    }

    #[test]
    fn parses_legacy_reminder_schema() {
        let tmp = make_reminders("Reminder", 0, 3);
        let recs = parse(tmp.path());
        let r = recs.iter().find(|r| r.subcategory == "Reminders").unwrap();
        assert!(r.detail.contains("3 reminders"));
        assert!(r.detail.contains("0 completed"));
    }

    #[test]
    fn unknown_schema_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }
}
