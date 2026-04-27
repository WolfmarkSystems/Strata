//! Shared helpers for Android parsers.
//!
//! Primarily covers:
//!
//! 1. Opening an on-disk SQLite database read-only with the URI mode
//!    so we never touch the source file (`?mode=ro&immutable=1`). This
//!    is critical: forensic evidence must never be mutated.
//! 2. Timestamp conversions — Android uses three wall-clock epochs in
//!    different artifacts (Unix seconds, Unix milliseconds, and Chrome
//!    / WebKit microseconds since 1601-01-01).
//! 3. Table/column existence checks so schema drift across Android
//!    versions degrades gracefully instead of panicking.
//! 4. A small `build_record` shim that centralises the `ArtifactRecord`
//!    field layout so parsers stay short.

use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

/// Open an on-disk SQLite database in read-only / immutable mode.
///
/// Forensic rule: never write back to the evidence copy. We use
/// `sqlite:` URI mode with `mode=ro&immutable=1` so the sqlite library
/// will not create a rollback journal or update the file header.
pub fn open_sqlite_ro(path: &Path) -> Option<Connection> {
    let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let uri = format!(
        "file:{}?mode=ro&immutable=1",
        canon.to_string_lossy().replace('?', "%3F")
    );
    Connection::open_with_flags(
        &uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()
}

/// Return true if the given table exists in this SQLite database.
pub fn table_exists(conn: &Connection, table: &str) -> bool {
    let mut stmt = match conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND lower(name)=lower(?1) LIMIT 1")
    {
        Ok(s) => s,
        Err(_) => return false,
    };
    stmt.query_row([table], |_| Ok(())).is_ok()
}

/// Return true if the given column exists on the given table.
pub fn column_exists(conn: &Connection, table: &str, column: &str) -> bool {
    let sql = format!("PRAGMA table_info(\"{}\")", table.replace('"', "\"\""));
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let rows = match stmt.query_map([], |row| row.get::<_, String>(1)) {
        Ok(r) => r,
        Err(_) => return false,
    };
    for name in rows.flatten() {
        if name.eq_ignore_ascii_case(column) {
            return true;
        }
    }
    false
}

/// Convert Unix milliseconds to an i64 epoch-seconds timestamp.
pub fn unix_ms_to_i64(ms: i64) -> Option<i64> {
    if ms <= 0 {
        return None;
    }
    Some(ms / 1000)
}

/// Convert Chrome/WebKit microseconds-since-1601 to Unix epoch seconds.
///
/// Chrome and Android browser databases (`urls.last_visit_time`,
/// `visits.visit_time`, `cookies.expires_utc`, etc.) store time as
/// microseconds since `1601-01-01 00:00:00 UTC`. Conversion:
///
/// ```text
/// unix_epoch_seconds = (webkit_microseconds / 1_000_000) - 11_644_473_600
/// ```
pub fn chrome_to_unix(chrome_us: i64) -> Option<i64> {
    if chrome_us <= 0 {
        return None;
    }
    const WEBKIT_TO_UNIX: i64 = 11_644_473_600;
    Some(chrome_us / 1_000_000 - WEBKIT_TO_UNIX)
}

/// Format an optional i64 epoch seconds value as an ISO-8601 string.
pub fn fmt_ts(epoch_seconds: Option<i64>) -> String {
    match epoch_seconds {
        Some(s) => chrono::DateTime::<chrono::Utc>::from_timestamp(s, 0)
            .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| s.to_string()),
        None => "unknown".to_string(),
    }
}

/// Centralised builder for `ArtifactRecord` so every parser stays terse.
///
/// Pulse parsers fill in the category, subcategory, title, detail, and
/// forensic value; everything else is defaulted here.
#[allow(clippy::too_many_arguments)]
pub fn build_record(
    category: ArtifactCategory,
    subcategory: &str,
    title: String,
    detail: String,
    source_path: &Path,
    timestamp: Option<i64>,
    forensic_value: ForensicValue,
    is_suspicious: bool,
) -> ArtifactRecord {
    ArtifactRecord {
        category,
        subcategory: subcategory.to_string(),
        timestamp,
        title,
        detail,
        source_path: source_path.to_string_lossy().into_owned(),
        forensic_value,
        mitre_technique: None,
        is_suspicious,
        raw_data: None,
        confidence: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_epoch_converts_correctly() {
        // 2021-01-01 00:00:00 UTC in WebKit microseconds.
        // Unix epoch for that moment: 1_609_459_200
        // WebKit equivalent: (1_609_459_200 + 11_644_473_600) * 1_000_000
        let us: i64 = (1_609_459_200i64 + 11_644_473_600i64) * 1_000_000;
        assert_eq!(chrome_to_unix(us), Some(1_609_459_200));
    }

    #[test]
    fn chrome_epoch_rejects_zero_or_negative() {
        assert_eq!(chrome_to_unix(0), None);
        assert_eq!(chrome_to_unix(-1), None);
    }

    #[test]
    fn unix_ms_converts_to_seconds() {
        assert_eq!(unix_ms_to_i64(1_609_459_200_000), Some(1_609_459_200));
        assert_eq!(unix_ms_to_i64(0), None);
    }

    #[test]
    fn fmt_ts_returns_unknown_on_none() {
        assert_eq!(fmt_ts(None), "unknown");
        // Stable format for a known epoch.
        assert_eq!(fmt_ts(Some(1_609_459_200)), "2021-01-01T00:00:00Z");
    }

    #[test]
    fn sqlite_ro_open_works_on_real_file() {
        use rusqlite::Connection;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute_batch("CREATE TABLE t (id INTEGER); INSERT INTO t VALUES (42);")
                .unwrap();
        }
        let ro = open_sqlite_ro(tmp.path()).expect("ro open");
        assert!(table_exists(&ro, "t"));
        assert!(column_exists(&ro, "t", "id"));
        assert!(!column_exists(&ro, "t", "missing"));
    }
}
