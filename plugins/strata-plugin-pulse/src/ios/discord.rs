//! iOS Discord — `Cache.db` and `Cache.db-wal`.
//!
//! Discord stores its message and asset cache in a NSURLCache-style
//! `Cache.db` (NOT a Discord-specific schema — it's the standard
//! `cfurl_cache_response`/`cfurl_cache_blob_data` layout shared by
//! every CFNetwork-backed app).
//!
//! Pulse v1.0 reports row counts in the cache tables when the file
//! sits under a `*/Discord/*` path. This helps an examiner spot
//! cached message bodies without confusing Discord with other
//! CFNetwork caches.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["cache.db"]) && util::path_contains(path, "discord")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "cfurl_cache_response") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let n = util::count_rows(&conn, "cfurl_cache_response");
    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "Discord cache".to_string(),
        timestamp: None,
        title: "Discord iOS HTTP cache".to_string(),
        detail: format!(
            "{} cfurl_cache_response rows in {} — cached Discord HTTP responses (messages, attachments)",
            n, source
        ),
        source_path: source,
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
    use tempfile::tempdir;

    fn make_discord_cache(rows: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let root = dir.path().join("discord-data");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("Cache.db");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE cfurl_cache_response (entry_ID INTEGER PRIMARY KEY, request_key TEXT)",
            [],
        )
        .unwrap();
        for i in 0..rows {
            c.execute(
                "INSERT INTO cfurl_cache_response (request_key) VALUES (?1)",
                rusqlite::params![format!("https://discord.com/api/messages/{}", i)],
            )
            .unwrap();
        }
        (dir, p)
    }

    #[test]
    fn matches_discord_cache_paths_only() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Library/Caches/Discord/Cache.db"
        )));
        assert!(!matches(Path::new(
            "/var/mobile/Library/Caches/com.example/Cache.db"
        )));
    }

    #[test]
    fn parses_row_count() {
        let (_d, p) = make_discord_cache(7);
        let recs = parse(&p);
        let r = recs.iter().find(|r| r.subcategory == "Discord cache").unwrap();
        assert!(r.detail.contains("7 cfurl_cache_response"));
    }

    #[test]
    fn missing_table_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("discord");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("Cache.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}
