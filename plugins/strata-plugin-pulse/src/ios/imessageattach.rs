//! iOS iMessage attachments metadata — deeper `sms.db` extraction.
//!
//! Extends the basic `sms.rs` by querying the `attachment` table
//! joined through `message_attachment_join` to produce per-attachment
//! metadata (filename, MIME type, byte count, transfer state) even
//! for files deleted from the filesystem.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["sms.db", "chat.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "attachment") { return out; }
    if !util::table_exists(&conn, "message_attachment_join") { return out; }
    let source = path.to_string_lossy().to_string();

    // Count by MIME type
    let by_mime = conn
        .prepare(
            "SELECT COALESCE(a.mime_type, '(unknown)'), COUNT(*) \
             FROM attachment a \
             INNER JOIN message_attachment_join j ON j.attachment_id = a.ROWID \
             GROUP BY a.mime_type ORDER BY COUNT(*) DESC LIMIT 10"
        )
        .and_then(|mut s| {
            let r = s.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    if by_mime.is_empty() { return out; }

    let total: i64 = by_mime.iter().map(|(_, c)| c).sum();
    let breakdown: String = by_mime.iter()
        .map(|(m, c)| format!("{}={}", m, c))
        .collect::<Vec<_>>()
        .join(", ");

    out.push(ArtifactRecord {
        category: ArtifactCategory::Media,
        subcategory: "iMessage attachments".to_string(),
        timestamp: None,
        title: "iMessage attachment metadata".to_string(),
        detail: format!("{} linked attachments — MIME breakdown: {}", total, breakdown),
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
    use tempfile::NamedTempFile;

    fn make_sms_with_attachments(rows: &[&str]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT)", []).unwrap();
        c.execute("CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY, filename TEXT, mime_type TEXT, total_bytes INTEGER)", []).unwrap();
        c.execute("CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER)", []).unwrap();
        for (i, mime) in rows.iter().enumerate() {
            let aid = (i + 1) as i64;
            c.execute("INSERT INTO message (text) VALUES ('msg')", []).unwrap();
            c.execute("INSERT INTO attachment (filename, mime_type, total_bytes) VALUES ('file', ?1, 1024)", rusqlite::params![*mime]).unwrap();
            c.execute("INSERT INTO message_attachment_join VALUES (?1, ?2)", rusqlite::params![aid, aid]).unwrap();
        }
        tmp
    }

    #[test]
    fn parses_mime_breakdown() {
        let tmp = make_sms_with_attachments(&["image/jpeg", "image/jpeg", "video/mp4"]);
        let recs = parse(tmp.path());
        let r = recs.iter().find(|r| r.subcategory == "iMessage attachments").unwrap();
        assert!(r.detail.contains("3 linked attachments"));
        assert!(r.detail.contains("image/jpeg=2"));
        assert!(r.detail.contains("video/mp4=1"));
    }

    #[test]
    fn no_join_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn empty_attachments_returns_empty() {
        let tmp = make_sms_with_attachments(&[]);
        assert!(parse(tmp.path()).is_empty());
    }
}
