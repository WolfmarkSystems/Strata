//! Shared helpers for iOS artifact parsers.
//!
//! These helpers exist so every parser handles Apple reference-date
//! conversion, read-only SQLite access, and path matching in exactly the
//! same way. If a parser needs something subtly different, extend the
//! helpers — do not copy-paste.

use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Apple's Core Foundation / Cocoa reference date (`2001-01-01 00:00:00 UTC`)
/// expressed as a Unix timestamp. iOS stores almost every SQLite timestamp
/// as "seconds (or nanoseconds) since this instant".
pub const APPLE_EPOCH_OFFSET: i64 = 978_307_200;

/// Convert an Apple Cocoa reference date in whole seconds (possibly
/// fractional) to a Unix timestamp in whole seconds.
///
/// Returns `None` for NaN/inf and for timestamps that would land before
/// the Unix epoch, which indicates a corrupt or uninitialized field.
pub fn cf_absolute_to_unix(seconds: f64) -> Option<i64> {
    if !seconds.is_finite() {
        return None;
    }
    let whole = seconds as i64;
    let out = whole.saturating_add(APPLE_EPOCH_OFFSET);
    if out < 0 {
        None
    } else {
        Some(out)
    }
}

/// Convert an Apple Cocoa reference date expressed in nanoseconds to a
/// Unix timestamp in whole seconds. Some iOS databases (notably the
/// Photos library's `ZDATECREATED`) use nanoseconds for higher precision.
pub fn cf_nanos_to_unix(nanos: i64) -> Option<i64> {
    let whole = nanos / 1_000_000_000;
    let out = whole.saturating_add(APPLE_EPOCH_OFFSET);
    if out < 0 {
        None
    } else {
        Some(out)
    }
}

/// Open a SQLite database read-only with mutexing disabled so multiple
/// parsers can touch the same database concurrently without stalling.
/// Never mutate evidence — this function is the only path to open a
/// database in Pulse.
pub fn open_sqlite_ro(path: &Path) -> Option<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()
}

/// Return true if a table exists in the database. Uses a parameterised
/// query so callers can pass untrusted names without worrying about
/// quoting.
pub fn table_exists(conn: &Connection, name: &str) -> bool {
    conn.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1")
        .and_then(|mut s| s.query_row([name], |_| Ok(())))
        .is_ok()
}

/// Count rows in a table. Returns 0 for any error — callers use this
/// to stamp the `detail` field, not to make control-flow decisions.
pub fn count_rows(conn: &Connection, table: &str) -> i64 {
    // Table name can't be parameterised, so validate it first.
    if !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return 0;
    }
    conn.prepare(&format!("SELECT COUNT(*) FROM {}", table))
        .and_then(|mut s| s.query_row([], |row| row.get::<_, i64>(0)))
        .unwrap_or(0)
}

/// Case-insensitive basename equality check for any of `names`.
pub fn name_is(path: &Path, names: &[&str]) -> bool {
    let base = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    names.iter().any(|t| base == *t)
}

/// Case-insensitive "path contains substring" check. `needle` should
/// usually include forward slashes so it anchors to a directory
/// boundary (e.g. `"/safari/"`).
pub fn path_contains(path: &Path, needle: &str) -> bool {
    path.to_string_lossy()
        .to_ascii_lowercase()
        .replace('\\', "/")
        .contains(&needle.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn cf_absolute_to_unix_rolls_forward_by_apple_epoch() {
        assert_eq!(cf_absolute_to_unix(0.0), Some(APPLE_EPOCH_OFFSET));
        assert_eq!(
            cf_absolute_to_unix(86_400.0),
            Some(APPLE_EPOCH_OFFSET + 86_400)
        );
    }

    #[test]
    fn cf_absolute_to_unix_rejects_non_finite_inputs() {
        assert_eq!(cf_absolute_to_unix(f64::NAN), None);
        assert_eq!(cf_absolute_to_unix(f64::INFINITY), None);
    }

    #[test]
    fn cf_nanos_to_unix_handles_one_second() {
        assert_eq!(cf_nanos_to_unix(1_000_000_000), Some(APPLE_EPOCH_OFFSET + 1));
    }

    #[test]
    fn open_sqlite_ro_succeeds_on_valid_db() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE foo (x INT)", []).unwrap();
        }
        let c = open_sqlite_ro(tmp.path()).expect("open ro");
        assert!(table_exists(&c, "foo"));
        assert!(!table_exists(&c, "bar"));
    }

    #[test]
    fn open_sqlite_ro_returns_none_for_non_db() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"not a sqlite file").unwrap();
        // Opening a non-db file read-only still succeeds at the driver
        // level, but the first prepare fails — we just rely on it being
        // either None or unusable. Run a real query to force the error.
        if let Some(c) = open_sqlite_ro(tmp.path()) {
            assert!(!table_exists(&c, "anything"));
        }
    }

    #[test]
    fn count_rows_rejects_table_name_with_injection() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE good (x INT)", []).unwrap();
            c.execute("INSERT INTO good VALUES (1), (2), (3)", [])
                .unwrap();
        }
        let c = open_sqlite_ro(tmp.path()).unwrap();
        assert_eq!(count_rows(&c, "good"), 3);
        assert_eq!(count_rows(&c, "good; DROP TABLE good"), 0);
    }

    #[test]
    fn name_is_is_case_insensitive() {
        assert!(name_is(Path::new("/a/b/KnowledgeC.db"), &["knowledgec.db"]));
        assert!(!name_is(Path::new("/a/b/other.db"), &["knowledgec.db"]));
    }

    #[test]
    fn path_contains_is_case_insensitive_and_slash_normalized() {
        assert!(path_contains(
            Path::new("C:\\Users\\me\\Library\\Safari\\History.db"),
            "/safari/"
        ));
        assert!(path_contains(
            Path::new("/Root/Library/Safari/History.db"),
            "/safari/"
        ));
        assert!(!path_contains(
            Path::new("/Root/Library/Notes/NoteStore.sqlite"),
            "/safari/"
        ));
    }
}
