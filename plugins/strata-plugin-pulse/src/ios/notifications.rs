//! iOS notification history (iOS 12+).
//!
//! iOS surfaces notifications through several stores:
//!   * `DuetExpertCenter` (`/var/mobile/Library/DuetExpertCenter/`):
//!     `_ExpertCenter.db` records every notification the system has
//!     decided is "expert center"-relevant.
//!   * `usernotificationsd` (`/var/mobile/Library/UserNotifications/`):
//!     `LocalNotifications.db` and `NotificationStorage.db` hold the
//!     payloads delivered to the user.
//!
//! Pulse v1.0 detects each store by filename and reports row counts —
//! every iLEAPP iOS notification parser sources its rows from one of
//! these tables, so a v1.0 examiner already gets the "we have N
//! notifications" headline.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

const NOTIFICATION_DB_NAMES: &[&str] = &[
    "_expertcenter.db",
    "localnotifications.db",
    "notificationstorage.db",
    "notification.db",
];

pub fn matches(path: &Path) -> bool {
    util::name_is(path, NOTIFICATION_DB_NAMES)
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    // Walk every table in sqlite_master and report counts. iOS varies
    // table names by release; this guarantees we never miss a vendor
    // suffix without writing 12 brittle table-name allow-lists.
    let table_names: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master \
             WHERE type='table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name",
        )
        .and_then(|mut s| {
            let r = s.query_map([], |row| row.get::<_, String>(0))?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    if table_names.is_empty() {
        return out;
    }

    let mut total_rows: i64 = 0;
    for t in &table_names {
        let n = util::count_rows(&conn, t);
        total_rows += n;
    }

    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Notifications".to_string(),
        timestamp: None,
        title: "iOS notification database".to_string(),
        detail: format!(
            "{} total rows across {} table(s): {}",
            total_rows,
            table_names.len(),
            table_names.join(", ")
        ),
        source_path: source.clone(),
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
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

    fn make_notification_db(tables: &[(&str, usize)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        for (name, rows) in tables {
            c.execute(&format!("CREATE TABLE {} (x INT)", name), [])
                .unwrap();
            for _ in 0..*rows {
                c.execute(&format!("INSERT INTO {} VALUES (1)", name), [])
                    .unwrap();
            }
        }
        tmp
    }

    #[test]
    fn matches_known_notification_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Library/DuetExpertCenter/_ExpertCenter.db"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/UserNotifications/LocalNotifications.db"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/UserNotifications/NotificationStorage.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_total_row_count_across_tables() {
        let tmp = make_notification_db(&[("notif_a", 4), ("notif_b", 2)]);
        let records = parse(tmp.path());
        let summary = records
            .iter()
            .find(|r| r.subcategory == "Notifications")
            .expect("summary record");
        assert!(summary.detail.contains("6 total rows"));
        assert!(summary.detail.contains("notif_a"));
        assert!(summary.detail.contains("notif_b"));
    }

    #[test]
    fn empty_db_returns_no_records() {
        let tmp = NamedTempFile::new().unwrap();
        {
            // Create a valid SQLite database with zero user tables.
            let _c = Connection::open(tmp.path()).unwrap();
        }
        let records = parse(tmp.path());
        assert!(records.is_empty());
    }

    #[test]
    fn ignores_sqlite_internal_tables() {
        let tmp = make_notification_db(&[("legit", 1)]);
        let records = parse(tmp.path());
        let summary = records
            .iter()
            .find(|r| r.subcategory == "Notifications")
            .unwrap();
        // sqlite_sequence et al. should never appear in the joined list.
        assert!(!summary.detail.contains("sqlite_"));
    }
}
