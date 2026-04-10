//! iOS Media Library — `MediaLibrary.sqlitedb`.
//!
//! Stores iTunes/Apple Music library metadata: songs, albums,
//! artists, play counts, last played times. iLEAPP keys off `item`,
//! `item_extra`, `album` tables.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["medialibrary.sqlitedb"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();
    let mut emitted = false;

    for (table, label) in [
        ("item", "media items (songs/videos)"),
        ("item_extra", "extended metadata"),
        ("album", "albums"),
        ("artist", "artists"),
    ] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::Media,
                subcategory: format!("Media Library {}", table),
                timestamp: None,
                title: format!("iOS {}", label),
                detail: format!("{} {} rows", count, table),
                source_path: source.clone(),
                forensic_value: ForensicValue::Medium,
                mitre_technique: None,
                is_suspicious: false,
                raw_data: None,
            });
            emitted = true;
        }
    }
    if !emitted { return Vec::new(); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn matches_medialibrary() {
        assert!(matches(Path::new("/var/mobile/Media/iTunes_Control/iTunes/MediaLibrary.sqlitedb")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_item_and_album_counts() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE item (pid INTEGER PRIMARY KEY, title TEXT)", []).unwrap();
        c.execute("CREATE TABLE album (pid INTEGER PRIMARY KEY, album TEXT)", []).unwrap();
        c.execute("INSERT INTO item (title) VALUES ('Song 1')", []).unwrap();
        c.execute("INSERT INTO album (album) VALUES ('Album A')", []).unwrap();
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory == "Media Library item"));
        assert!(recs.iter().any(|r| r.subcategory == "Media Library album"));
    }

    #[test]
    fn no_known_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
