//! Signal — attachment extraction from Signal Messenger.
//!
//! Source path: `/data/data/org.thoughtcrime.securesms/databases/signal.db`
//! or `messages.db`.
//!
//! Schema note: Signal uses an encrypted SQLCipher database in production,
//! but the `part` table (attachments) is readable after decryption with
//! the device key. This parser targets the `part` table which stores
//! attachment metadata including local file path, content type, and
//! thumbnail data.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["org.thoughtcrime.securesms/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    for table in &["part", "attachment", "attachments"] {
        if table_exists(&conn, table) {
            return read_attachments(&conn, path, table);
        }
    }
    Vec::new()
}

fn read_attachments(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT _id, mid, ct, cl, data_size, file_name, \
         caption, data_random, unique_id \
         FROM \"{table}\" ORDER BY _id DESC LIMIT 10000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        // Fall back to minimal column set
        Err(_) => return read_attachments_minimal(conn, path, table),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (
        id,
        mid,
        content_type,
        local_path,
        data_size,
        file_name,
        caption,
        data_random,
        unique_id,
    ) in rows.flatten()
    {
        let id = id.unwrap_or(0);
        let mid = mid.unwrap_or(0);
        let content_type = content_type.unwrap_or_else(|| "unknown".to_string());
        let local_path = local_path.unwrap_or_default();
        let data_size = data_size.unwrap_or(0);
        let file_name = file_name.unwrap_or_default();
        let caption = caption.unwrap_or_default();
        let data_random = data_random.unwrap_or_default();
        let unique_id = unique_id.unwrap_or_default();
        let title = format!(
            "Signal attachment #{}: {} ({})",
            id, file_name, content_type
        );
        let mut detail = format!(
            "Signal attachment id={} message_id={} content_type='{}' local_path='{}' size={} file_name='{}' unique_id='{}'",
            id, mid, content_type, local_path, data_size, file_name, unique_id
        );
        if !caption.is_empty() {
            detail.push_str(&format!(" caption='{}'", caption));
        }
        if !data_random.is_empty() {
            detail.push_str(&format!(" data_random='{}'", data_random));
        }
        out.push(build_record(
            ArtifactCategory::Media,
            "Signal Attachment",
            title,
            detail,
            path,
            unix_ms_to_i64(mid),
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn read_attachments_minimal(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT _id, ct, cl, data_size FROM \"{table}\" ORDER BY _id DESC LIMIT 10000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, content_type, local_path, data_size) in rows.flatten() {
        let id = id.unwrap_or(0);
        let content_type = content_type.unwrap_or_default();
        let local_path = local_path.unwrap_or_default();
        let data_size = data_size.unwrap_or(0);
        let title = format!("Signal attachment #{}: {}", id, content_type);
        let detail = format!(
            "Signal attachment id={} content_type='{}' local_path='{}' size={}",
            id, content_type, local_path, data_size
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Signal Attachment",
            title,
            detail,
            path,
            None,
            ForensicValue::High,
            false,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE part (
                _id INTEGER PRIMARY KEY,
                mid INTEGER,
                ct TEXT,
                cl TEXT,
                data_size INTEGER,
                file_name TEXT,
                caption TEXT,
                data_random TEXT,
                unique_id TEXT
            );
            INSERT INTO part VALUES(1,1609459200000,'image/jpeg','/data/data/org.thoughtcrime.securesms/app_parts/part-1.jpg',54321,'photo.jpg','Look at this','random_bytes','uid-1');
            INSERT INTO part VALUES(2,1609459300000,'video/mp4','/data/data/org.thoughtcrime.securesms/app_parts/part-2.mp4',1234567,'clip.mp4',NULL,'random_bytes_2','uid-2');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_attachments() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Signal Attachment"));
    }

    #[test]
    fn local_path_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a
            .detail
            .contains("local_path='/data/data/org.thoughtcrime.securesms/app_parts/part-1.jpg'")));
    }

    #[test]
    fn caption_captured_when_present() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("caption='Look at this'")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
