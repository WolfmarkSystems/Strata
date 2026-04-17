//! OneDrive SyncEngineDatabase.db parser (NIMBUS-2).
//!
//! Microsoft migrated OneDrive from a proprietary `.odbin` format to
//! SQLite and replaced SHA-1 with quickXorHash. This module reads the
//! current SyncEngineDatabase.db schema.
//!
//! quickXorHash is NOT cryptographic — recorded as-is for correlation.
//!
//! MITRE: T1567.002 (exfiltration to cloud), T1530.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

const FILETIME_EPOCH_DELTA: i64 = 11_644_473_600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneDriveFile {
    pub local_path: String,
    pub server_path: Option<String>,
    pub quick_xor_hash: Option<String>,
    pub sha1_hash: Option<String>,
    pub file_size: Option<u64>,
    pub modified_time: Option<DateTime<Utc>>,
    pub deleted_time: Option<DateTime<Utc>>,
    pub sync_status: Option<String>,
    pub account_email: Option<String>,
}

pub fn is_onedrive_db(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.eq_ignore_ascii_case("SyncEngineDatabase.db"))
        .unwrap_or(false)
}

pub fn decode_filetime(v: i64) -> Option<DateTime<Utc>> {
    if v == 0 {
        return None;
    }
    if v > 100_000_000_000_000 {
        let secs = (v / 10_000_000).saturating_sub(FILETIME_EPOCH_DELTA);
        return DateTime::<Utc>::from_timestamp(secs, 0);
    }
    if v > 1_000_000_000 && v < 100_000_000_000 {
        return DateTime::<Utc>::from_timestamp(v, 0);
    }
    None
}

fn hex_of(blob: &[u8]) -> String {
    let mut out = String::with_capacity(blob.len() * 2);
    for b in blob {
        out.push_str(&format!("{:02X}", b));
    }
    out
}

pub fn parse(path: &Path) -> Vec<OneDriveFile> {
    let Ok(conn) = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return Vec::new();
    };
    if conn
        .pragma_query_value(None, "schema_version", |_| Ok(()))
        .is_err()
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    // Try `ODSyncData` then fallback to `FileMetaData` or `od_data`.
    for table in ["ODSyncData", "FileMetaData", "od_data"] {
        let sql = format!(
            "SELECT LocalPath, ServerPath, QuickXorHash, SHA1Hash, FileSize, \
                    ModifiedTime, DeletedTime, SyncStatus \
             FROM {}",
            table
        );
        let Ok(mut stmt) = conn.prepare(&sql) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            let local_path: Option<String> = row.get(0)?;
            let server_path: Option<String> = row.get(1)?;
            let qxh: rusqlite::types::Value = row.get(2)?;
            let sha: rusqlite::types::Value = row.get(3)?;
            let size: Option<i64> = row.get(4)?;
            let mtime: Option<i64> = row.get(5)?;
            let dtime: Option<i64> = row.get(6)?;
            let status_int: Option<i64> = row.get::<_, Option<i64>>(7).ok().flatten();
            let status_str: Option<String> = row.get::<_, Option<String>>(7).ok().flatten();
            let qxh_hex = match qxh {
                rusqlite::types::Value::Blob(b) => Some(hex_of(&b)),
                rusqlite::types::Value::Text(s) => Some(s),
                _ => None,
            };
            let sha_hex = match sha {
                rusqlite::types::Value::Blob(b) => Some(hex_of(&b)),
                rusqlite::types::Value::Text(s) => Some(s),
                _ => None,
            };
            Ok((
                local_path,
                server_path,
                qxh_hex,
                sha_hex,
                size,
                mtime,
                dtime,
                status_int,
                status_str,
            ))
        });
        let Ok(rows) = rows else {
            continue;
        };
        for r in rows.flatten() {
            let (local_path, server_path, qxh_hex, sha_hex, size, mtime, dtime, status_int, status_str) = r;
            let Some(local_path) = local_path else {
                continue;
            };
            let status = status_str.or(status_int.map(|n| n.to_string()));
            out.push(OneDriveFile {
                local_path,
                server_path,
                quick_xor_hash: qxh_hex,
                sha1_hash: sha_hex,
                file_size: size.map(|n| n.max(0) as u64),
                modified_time: mtime.and_then(decode_filetime),
                deleted_time: dtime.and_then(decode_filetime),
                sync_status: status,
                account_email: None,
            });
        }
        if !out.is_empty() {
            return out;
        }
    }
    out
}

pub fn forensic_value(file: &OneDriveFile) -> &'static str {
    if file.deleted_time.is_some() {
        "High"
    } else {
        "Medium"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn is_onedrive_db_matches_canonical_filename() {
        assert!(is_onedrive_db(Path::new("/x/SyncEngineDatabase.db")));
        assert!(!is_onedrive_db(Path::new("/x/other.db")));
    }

    #[test]
    fn decode_filetime_handles_both_encodings() {
        let filetime = (1_717_243_200_i64 + FILETIME_EPOCH_DELTA) * 10_000_000;
        let dt = decode_filetime(filetime).expect("ft");
        assert_eq!(dt.timestamp(), 1_717_243_200);
        let unix = decode_filetime(1_717_243_200).expect("unix");
        assert_eq!(unix.timestamp(), 1_717_243_200);
        assert!(decode_filetime(0).is_none());
    }

    #[test]
    fn parse_returns_files_with_deleted_time_flagged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("SyncEngineDatabase.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE ODSyncData ( \
                 LocalPath TEXT, ServerPath TEXT, QuickXorHash BLOB, SHA1Hash BLOB, \
                 FileSize INTEGER, ModifiedTime INTEGER, DeletedTime INTEGER, \
                 SyncStatus TEXT \
             );",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO ODSyncData VALUES ('/local/x.txt', '/OneDrive/x.txt', X'DEADBEEF', NULL, 1024, 1717243200, 1717243500, 'Synced')",
            [],
        )
        .expect("ins");
        drop(conn);
        let out = parse(&path);
        assert_eq!(out.len(), 1);
        assert!(out[0].deleted_time.is_some());
        assert_eq!(out[0].quick_xor_hash.as_deref(), Some("DEADBEEF"));
        assert_eq!(forensic_value(&out[0]), "High");
    }

    #[test]
    fn parse_returns_empty_on_invalid_db() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("SyncEngineDatabase.db");
        std::fs::write(&path, b"not-sqlite").expect("w");
        assert!(parse(&path).is_empty());
    }

    #[test]
    fn forensic_value_medium_without_deleted_time() {
        let file = OneDriveFile {
            local_path: "/x".to_string(),
            server_path: None,
            quick_xor_hash: None,
            sha1_hash: None,
            file_size: None,
            modified_time: None,
            deleted_time: None,
            sync_status: None,
            account_email: None,
        };
        assert_eq!(forensic_value(&file), "Medium");
    }
}
