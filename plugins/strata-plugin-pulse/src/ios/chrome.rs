//! Google Chrome on iOS — `History` SQLite database under
//! `*/com.google.chrome.ios/*`.
//!
//! Chrome iOS uses the standard Chrome history schema:
//!   * `urls` — distinct visited URLs (`url`, `title`, `visit_count`,
//!     `last_visit_time` in WebKit microseconds since 1601-01-01)
//!   * `visits` — per-visit timestamp (`visit_time`)
//!
//! v1.0 reports counts and converts WebKit time to Unix.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

/// Convert WebKit time (microseconds since 1601-01-01 UTC) to Unix
/// seconds. The offset between WebKit and Unix is 11644473600 seconds.
fn webkit_to_unix(micros: i64) -> Option<i64> {
    if micros <= 0 {
        return None;
    }
    Some(micros / 1_000_000 - 11_644_473_600)
}

pub fn matches(path: &Path) -> bool {
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    n == "history" && util::path_contains(path, "chrome")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "urls") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let url_count = util::count_rows(&conn, "urls");
    let visit_count = if util::table_exists(&conn, "visits") {
        util::count_rows(&conn, "visits")
    } else {
        0
    };

    let (first, last): (Option<i64>, Option<i64>) = if util::table_exists(&conn, "visits") {
        conn.prepare(
            "SELECT MIN(visit_time), MAX(visit_time) FROM visits WHERE visit_time IS NOT NULL",
        )
        .and_then(|mut s| {
            s.query_row([], |row| {
                Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?))
            })
        })
        .unwrap_or((None, None))
    } else {
        (None, None)
    };
    let first_unix = first.and_then(webkit_to_unix);
    let last_unix = last.and_then(webkit_to_unix);

    out.push(ArtifactRecord {
        category: ArtifactCategory::WebActivity,
        subcategory: "Chrome iOS history".to_string(),
        timestamp: first_unix,
        title: "Google Chrome iOS history".to_string(),
        detail: format!(
            "{} URLs, {} visits, range {:?}..{:?} Unix",
            url_count, visit_count, first_unix, last_unix
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn make_chrome_history(
        urls: usize,
        visits_per_url: usize,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let chrome = dir
            .path()
            .join("Library")
            .join("Application Support")
            .join("Google")
            .join("Chrome");
        std::fs::create_dir_all(&chrome).unwrap();
        let p = chrome.join("History");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, last_visit_time INTEGER)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)",
            [],
        )
        .unwrap();
        // 2026-01-01 00:00:00 UTC in WebKit micros = (1767225600 + 11644473600) * 1_000_000
        let base_webkit: i64 = (1_767_225_600 + 11_644_473_600) * 1_000_000;
        for i in 0..urls {
            c.execute(
                "INSERT INTO urls (url, last_visit_time) VALUES (?1, ?2)",
                rusqlite::params![format!("https://e.com/{}", i), base_webkit],
            )
            .unwrap();
            for v in 0..visits_per_url {
                c.execute(
                    "INSERT INTO visits (url, visit_time) VALUES (?1, ?2)",
                    rusqlite::params![i + 1, base_webkit + (v as i64) * 1_000_000],
                )
                .unwrap();
            }
        }
        (dir, p)
    }

    #[test]
    fn matches_chrome_history_filename() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Library/Application Support/Google/Chrome/History"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/Safari/History.db")));
    }

    #[test]
    fn parses_count_and_webkit_time_to_unix() {
        let (_d, p) = make_chrome_history(3, 2);
        let recs = parse(&p);
        let h = recs
            .iter()
            .find(|r| r.subcategory == "Chrome iOS history")
            .unwrap();
        assert!(h.detail.contains("3 URLs"));
        assert!(h.detail.contains("6 visits"));
        // 2026-01-01 UTC -> Unix 1767225600
        assert_eq!(h.timestamp, Some(1_767_225_600));
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let chrome = dir.path().join("chrome-data");
        std::fs::create_dir_all(&chrome).unwrap();
        let p = chrome.join("History");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }

    #[test]
    fn webkit_to_unix_rejects_zero() {
        assert!(webkit_to_unix(0).is_none());
        assert!(webkit_to_unix(-5).is_none());
    }
}
