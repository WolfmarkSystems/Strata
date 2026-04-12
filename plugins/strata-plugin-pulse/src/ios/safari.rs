//! iOS Safari — `History.db`, `Bookmarks.db`, `Downloads.plist`.
//!
//! Strata's pulse parser hits the three files iLEAPP keys off:
//!   * `History.db` — `history_items` (URL inventory) joined to
//!     `history_visits` (per-visit timestamps), where `visit_time` is
//!     stored as Cocoa seconds.
//!   * `Bookmarks.db` — `bookmarks` table with title/url
//!   * `Downloads.plist` — binary plist; we report presence + size only
//!     in v1.0 because plist key shapes differ wildly across iOS
//!     releases.
//!
//! This module dispatches on filename, so each file is parsed
//! independently. The router calls `matches()` first, so the parse
//! function is allowed to assume the file at least *claims* to be one
//! of ours.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    let safari_scope = util::path_contains(path, "/safari/");
    if util::name_is(path, &["history.db"]) && safari_scope {
        return true;
    }
    if util::name_is(path, &["bookmarks.db"]) && safari_scope {
        return true;
    }
    if util::name_is(path, &["downloads.plist"]) && safari_scope {
        return true;
    }
    false
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match name.as_str() {
        "history.db" => parse_history(path),
        "bookmarks.db" => parse_bookmarks(path),
        "downloads.plist" => parse_downloads(path),
        _ => Vec::new(),
    }
}

fn parse_history(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "history_items") {
        return out;
    }

    let source = path.to_string_lossy().to_string();
    let item_count = util::count_rows(&conn, "history_items");

    let visit_count = if util::table_exists(&conn, "history_visits") {
        util::count_rows(&conn, "history_visits")
    } else {
        0
    };

    // Earliest / latest visit time (Cocoa seconds).
    let (first, last) = if util::table_exists(&conn, "history_visits") {
        conn.prepare(
            "SELECT MIN(visit_time), MAX(visit_time) FROM history_visits \
             WHERE visit_time IS NOT NULL",
        )
        .and_then(|mut s| {
            s.query_row([], |row| {
                Ok((row.get::<_, Option<f64>>(0)?, row.get::<_, Option<f64>>(1)?))
            })
        })
        .unwrap_or((None, None))
    } else {
        (None, None)
    };
    let first_unix = first.and_then(util::cf_absolute_to_unix);
    let last_unix = last.and_then(util::cf_absolute_to_unix);

    let range = match (first_unix, last_unix) {
        (Some(a), Some(b)) => format!("first {}s, last {}s Unix", a, b),
        _ => "no visit timestamps".to_string(),
    };

    out.push(ArtifactRecord {
        category: ArtifactCategory::WebActivity,
        subcategory: "Safari history".to_string(),
        timestamp: first_unix,
        title: "Safari browsing history".to_string(),
        detail: format!(
            "{} unique URLs, {} visits, {}",
            item_count, visit_count, range
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });

    out
}

fn parse_bookmarks(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "bookmarks") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let count = util::count_rows(&conn, "bookmarks");
    out.push(ArtifactRecord {
        category: ArtifactCategory::WebActivity,
        subcategory: "Safari bookmarks".to_string(),
        timestamp: None,
        title: "Safari bookmarks".to_string(),
        detail: format!("{} bookmark rows", count),
        source_path: source,
        forensic_value: ForensicValue::Medium,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });
    out
}

fn parse_downloads(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    // Downloads.plist is a binary plist whose schema differs between
    // iOS releases. v1.0 just confirms presence + size — full plist
    // walking is queued for v1.1 once we have a stable corpus.
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let source = path.to_string_lossy().to_string();
    out.push(ArtifactRecord {
        category: ArtifactCategory::WebActivity,
        subcategory: "Safari downloads".to_string(),
        timestamp: None,
        title: "Safari Downloads.plist".to_string(),
        detail: format!(
            "Downloads.plist present ({} bytes) — binary plist of in-progress \
             and finished downloads",
            size
        ),
        source_path: source,
        forensic_value: ForensicValue::Medium,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn make_history_db(dir: &Path, items: usize, visits_per_item: usize) -> std::path::PathBuf {
        let safari_dir = dir.join("Library").join("Safari");
        std::fs::create_dir_all(&safari_dir).unwrap();
        let p = safari_dir.join("History.db");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE history_visits (\
                id INTEGER PRIMARY KEY, \
                history_item INTEGER, \
                visit_time DOUBLE \
             )",
            [],
        )
        .unwrap();
        for i in 0..items {
            c.execute(
                "INSERT INTO history_items (url) VALUES (?1)",
                rusqlite::params![format!("https://example.com/{}", i)],
            )
            .unwrap();
            for v in 0..visits_per_item {
                c.execute(
                    "INSERT INTO history_visits (history_item, visit_time) VALUES (?1, ?2)",
                    rusqlite::params![i + 1, 700_000_000.0_f64 + v as f64],
                )
                .unwrap();
            }
        }
        p
    }

    #[test]
    fn matches_files_only_in_safari_directory() {
        assert!(matches(Path::new("/var/mobile/Library/Safari/History.db")));
        assert!(matches(Path::new(
            "/var/mobile/Library/Safari/Bookmarks.db"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/Safari/Downloads.plist"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/History.db")));
    }

    #[test]
    fn parses_history_summary_with_counts() {
        let dir = tempdir().unwrap();
        let p = make_history_db(dir.path(), 4, 2);
        let records = parse(&p);
        let summary = records
            .iter()
            .find(|r| r.subcategory == "Safari history")
            .expect("history record");
        assert!(summary.detail.contains("4 unique URLs"));
        assert!(summary.detail.contains("8 visits"));
        assert_eq!(
            summary.timestamp,
            Some(700_000_000_i64 + util::APPLE_EPOCH_OFFSET)
        );
    }

    #[test]
    fn empty_history_db_returns_summary_without_timestamps() {
        let dir = tempdir().unwrap();
        let p = make_history_db(dir.path(), 0, 0);
        let records = parse(&p);
        let summary = &records[0];
        assert!(summary.detail.contains("0 unique URLs"));
        assert!(summary.timestamp.is_none());
    }

    #[test]
    fn parses_bookmarks_db() {
        let dir = tempdir().unwrap();
        let safari = dir.path().join("Library").join("Safari");
        std::fs::create_dir_all(&safari).unwrap();
        let bm = safari.join("Bookmarks.db");
        let c = Connection::open(&bm).unwrap();
        c.execute(
            "CREATE TABLE bookmarks (id INTEGER PRIMARY KEY, title TEXT, url TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO bookmarks (title, url) VALUES ('a', 'https://a.com')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO bookmarks (title, url) VALUES ('b', 'https://b.com')",
            [],
        )
        .unwrap();
        let recs = parse(&bm);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("2 bookmark rows"));
    }

    #[test]
    fn parses_downloads_plist_presence() {
        let dir = tempdir().unwrap();
        let safari = dir.path().join("Library").join("Safari");
        std::fs::create_dir_all(&safari).unwrap();
        let dl = safari.join("Downloads.plist");
        std::fs::write(&dl, b"\x00bplist00fakeplist").unwrap();
        let recs = parse(&dl);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("Downloads.plist present"));
    }
}
