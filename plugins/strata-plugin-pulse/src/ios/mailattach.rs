//! iOS Mail attachments — `Attachments/` metadata from `Envelope Index`.
//!
//! Extends `mail.rs` by querying the `attachments` table if present,
//! which maps message → file metadata (name, MIME, size).

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    n == "envelope index"
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "attachments") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let count = util::count_rows(&conn, "attachments");
    if count == 0 {
        return out;
    }

    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "Mail attachments".to_string(),
        timestamp: None,
        title: "Apple Mail attachment metadata".to_string(),
        detail: format!(
            "{} attachment rows — filename, MIME type, size (file bytes not read)",
            count
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1114".to_string()),
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

    #[test]
    fn parses_attachment_count() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("Envelope Index");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE attachments (ROWID INTEGER PRIMARY KEY, name TEXT, mime_type TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO attachments (name, mime_type) VALUES ('doc.pdf', 'application/pdf')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO attachments (name, mime_type) VALUES ('img.jpg', 'image/jpeg')",
            [],
        )
        .unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("2 attachment"));
    }
    #[test]
    fn no_attachments_table_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("Envelope Index");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE messages (ROWID INTEGER PRIMARY KEY)", [])
            .unwrap();
        assert!(parse(&p).is_empty());
    }
    #[test]
    fn empty_attachments_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("Envelope Index");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE attachments (ROWID INTEGER PRIMARY KEY)", [])
            .unwrap();
        assert!(parse(&p).is_empty());
    }
}
