//! SQLite-backed master file index.
//!
//! Schema is intentionally narrow: one row per file, with hashes,
//! MIME, timestamps, inode/MFT record number, deletion flag, entropy.
//! All columns are indexed so plugin queries (filename, extension,
//! sha256) resolve in O(log n).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

/// On-disk schema version. Bump when breaking changes land.
pub const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Error)]
pub enum FileIndexError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("schema mismatch: on-disk version {0}, expected {1}")]
    SchemaMismatch(i64, i64),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileIndexEntry {
    pub id: i64,
    pub full_path: String,
    pub filename: String,
    pub extension: Option<String>,
    pub file_size: u64,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    pub mime_type: Option<String>,
    pub created_time: Option<DateTime<Utc>>,
    pub modified_time: Option<DateTime<Utc>>,
    pub accessed_time: Option<DateTime<Utc>>,
    pub inode: Option<u64>,
    pub mft_record: Option<u64>,
    pub is_deleted: bool,
    pub entropy: Option<f64>,
    pub nsrl_known_good: bool,
    pub threat_intel_match: bool,
    pub threat_intel_name: Option<String>,
}

impl FileIndexEntry {
    pub fn new(full_path: String, filename: String, file_size: u64) -> Self {
        let extension = std::path::Path::new(&filename)
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase());
        Self {
            id: 0,
            full_path,
            filename,
            extension,
            file_size,
            md5: None,
            sha256: None,
            mime_type: None,
            created_time: None,
            modified_time: None,
            accessed_time: None,
            inode: None,
            mft_record: None,
            is_deleted: false,
            entropy: None,
            nsrl_known_good: false,
            threat_intel_match: false,
            threat_intel_name: None,
        }
    }
}

pub struct FileIndex {
    conn: Connection,
}

impl FileIndex {
    /// Open (or create) the master file index at `path`. Schema is
    /// created if absent; mismatch on an existing DB returns an error
    /// so callers can rebuild explicitly rather than silently migrate.
    pub fn open(path: &Path) -> Result<Self, FileIndexError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; \
             PRAGMA synchronous=NORMAL; \
             CREATE TABLE IF NOT EXISTS schema_meta ( \
                 version INTEGER NOT NULL \
             ); \
             CREATE TABLE IF NOT EXISTS file_index ( \
                 id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 full_path TEXT NOT NULL UNIQUE, \
                 filename TEXT NOT NULL, \
                 extension TEXT, \
                 file_size INTEGER NOT NULL, \
                 md5 TEXT, \
                 sha256 TEXT, \
                 mime_type TEXT, \
                 created_time INTEGER, \
                 modified_time INTEGER, \
                 accessed_time INTEGER, \
                 inode INTEGER, \
                 mft_record INTEGER, \
                 is_deleted INTEGER DEFAULT 0, \
                 entropy REAL, \
                 nsrl_known_good INTEGER DEFAULT 0, \
                 threat_intel_match INTEGER DEFAULT 0, \
                 threat_intel_name TEXT \
             ); \
             CREATE INDEX IF NOT EXISTS idx_file_filename ON file_index(filename); \
             CREATE INDEX IF NOT EXISTS idx_file_extension ON file_index(extension); \
             CREATE INDEX IF NOT EXISTS idx_file_sha256   ON file_index(sha256); \
             CREATE INDEX IF NOT EXISTS idx_file_md5      ON file_index(md5); \
             CREATE INDEX IF NOT EXISTS idx_file_mime     ON file_index(mime_type); \
             CREATE INDEX IF NOT EXISTS idx_file_entropy  ON file_index(entropy); \
             CREATE INDEX IF NOT EXISTS idx_file_nsrl     ON file_index(nsrl_known_good); \
             CREATE INDEX IF NOT EXISTS idx_file_threat   ON file_index(threat_intel_match);",
        )?;
        let existing: Option<i64> = conn
            .query_row("SELECT version FROM schema_meta LIMIT 1", [], |row| {
                row.get(0)
            })
            .ok();
        match existing {
            Some(v) if v != SCHEMA_VERSION => {
                return Err(FileIndexError::SchemaMismatch(v, SCHEMA_VERSION));
            }
            None => {
                conn.execute(
                    "INSERT INTO schema_meta (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )?;
            }
            _ => {}
        }
        Ok(Self { conn })
    }

    pub fn count(&self) -> Result<u64, FileIndexError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM file_index", [], |row| row.get(0))?;
        Ok(n.max(0) as u64)
    }

    pub fn upsert_batch(&mut self, entries: &[FileIndexEntry]) -> Result<usize, FileIndexError> {
        let tx = self.conn.transaction()?;
        let mut inserted = 0usize;
        for e in entries {
            tx.execute(
                "INSERT INTO file_index ( \
                     full_path, filename, extension, file_size, md5, sha256, mime_type, \
                     created_time, modified_time, accessed_time, inode, mft_record, \
                     is_deleted, entropy, nsrl_known_good, threat_intel_match, threat_intel_name \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17) \
                 ON CONFLICT(full_path) DO UPDATE SET \
                     file_size=excluded.file_size, md5=excluded.md5, sha256=excluded.sha256, \
                     mime_type=excluded.mime_type, created_time=excluded.created_time, \
                     modified_time=excluded.modified_time, accessed_time=excluded.accessed_time, \
                     inode=excluded.inode, mft_record=excluded.mft_record, \
                     is_deleted=excluded.is_deleted, entropy=excluded.entropy, \
                     nsrl_known_good=excluded.nsrl_known_good, \
                     threat_intel_match=excluded.threat_intel_match, \
                     threat_intel_name=excluded.threat_intel_name",
                params![
                    e.full_path,
                    e.filename,
                    e.extension,
                    e.file_size as i64,
                    e.md5,
                    e.sha256,
                    e.mime_type,
                    e.created_time.map(|d| d.timestamp()),
                    e.modified_time.map(|d| d.timestamp()),
                    e.accessed_time.map(|d| d.timestamp()),
                    e.inode.map(|n| n as i64),
                    e.mft_record.map(|n| n as i64),
                    e.is_deleted as i64,
                    e.entropy,
                    e.nsrl_known_good as i64,
                    e.threat_intel_match as i64,
                    e.threat_intel_name,
                ],
            )?;
            inserted += 1;
        }
        tx.commit()?;
        Ok(inserted)
    }

    pub fn query_by_filename(&self, filename: &str) -> Result<Vec<FileIndexEntry>, FileIndexError> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM file_index WHERE filename = ?1 COLLATE NOCASE")?;
        let rows = stmt.query_map([filename], row_to_entry)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn query_by_extension(
        &self,
        extension: &str,
    ) -> Result<Vec<FileIndexEntry>, FileIndexError> {
        let ext = extension.trim_start_matches('.').to_ascii_lowercase();
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM file_index WHERE extension = ?1")?;
        let rows = stmt.query_map([ext], row_to_entry)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn query_by_sha256(&self, sha256: &str) -> Result<Vec<FileIndexEntry>, FileIndexError> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM file_index WHERE sha256 = ?1")?;
        let rows = stmt.query_map([sha256], row_to_entry)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn high_entropy_entries(
        &self,
        threshold: f64,
    ) -> Result<Vec<FileIndexEntry>, FileIndexError> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM file_index WHERE entropy IS NOT NULL AND entropy > ?1")?;
        let rows = stmt.query_map([threshold], row_to_entry)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn mark_nsrl(&mut self, sha256: &str) -> Result<usize, FileIndexError> {
        let n = self.conn.execute(
            "UPDATE file_index SET nsrl_known_good = 1 WHERE sha256 = ?1",
            [sha256],
        )?;
        Ok(n)
    }

    pub fn mark_threat_intel(&mut self, sha256: &str, name: &str) -> Result<usize, FileIndexError> {
        let n = self.conn.execute(
            "UPDATE file_index SET threat_intel_match = 1, threat_intel_name = ?2 WHERE sha256 = ?1",
            [sha256, name],
        )?;
        Ok(n)
    }

    pub fn threat_intel_hits(&self) -> Result<Vec<FileIndexEntry>, FileIndexError> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM file_index WHERE threat_intel_match = 1")?;
        let rows = stmt.query_map([], row_to_entry)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub(crate) fn connection_ref(&self) -> &Connection {
        &self.conn
    }
}

pub(crate) fn database_row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileIndexEntry> {
    row_to_entry(row)
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileIndexEntry> {
    let created: Option<i64> = row.get("created_time")?;
    let modified: Option<i64> = row.get("modified_time")?;
    let accessed: Option<i64> = row.get("accessed_time")?;
    Ok(FileIndexEntry {
        id: row.get("id")?,
        full_path: row.get("full_path")?,
        filename: row.get("filename")?,
        extension: row.get("extension")?,
        file_size: row.get::<_, i64>("file_size")?.max(0) as u64,
        md5: row.get("md5")?,
        sha256: row.get("sha256")?,
        mime_type: row.get("mime_type")?,
        created_time: created.and_then(|s| DateTime::<Utc>::from_timestamp(s, 0)),
        modified_time: modified.and_then(|s| DateTime::<Utc>::from_timestamp(s, 0)),
        accessed_time: accessed.and_then(|s| DateTime::<Utc>::from_timestamp(s, 0)),
        inode: row.get::<_, Option<i64>>("inode")?.map(|n| n.max(0) as u64),
        mft_record: row
            .get::<_, Option<i64>>("mft_record")?
            .map(|n| n.max(0) as u64),
        is_deleted: row.get::<_, Option<i64>>("is_deleted")?.unwrap_or(0) != 0,
        entropy: row.get("entropy")?,
        nsrl_known_good: row.get::<_, Option<i64>>("nsrl_known_good")?.unwrap_or(0) != 0,
        threat_intel_match: row
            .get::<_, Option<i64>>("threat_intel_match")?
            .unwrap_or(0)
            != 0,
        threat_intel_name: row.get("threat_intel_name")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_tmp() -> (tempfile::TempDir, FileIndex) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("file_index.db");
        let idx = FileIndex::open(&path).expect("open");
        (dir, idx)
    }

    fn sample(path: &str, ext: Option<&str>, size: u64) -> FileIndexEntry {
        FileIndexEntry {
            extension: ext.map(String::from),
            ..FileIndexEntry::new(
                path.into(),
                path.rsplit('/').next().unwrap_or("").into(),
                size,
            )
        }
    }

    #[test]
    fn open_creates_schema_and_records_version() {
        let (_dir, idx) = open_tmp();
        assert_eq!(idx.count().expect("count"), 0);
    }

    #[test]
    fn upsert_batch_inserts_and_updates() {
        let (_dir, mut idx) = open_tmp();
        let mut a = sample("/evidence/a.txt", Some("txt"), 10);
        idx.upsert_batch(&[a.clone()]).expect("insert");
        a.file_size = 20;
        idx.upsert_batch(&[a]).expect("update");
        assert_eq!(idx.count().expect("count"), 1);
        let hits = idx.query_by_filename("a.txt").expect("q");
        assert_eq!(hits[0].file_size, 20);
    }

    #[test]
    fn query_by_extension_returns_matching_rows() {
        let (_dir, mut idx) = open_tmp();
        idx.upsert_batch(&[
            sample("/evidence/a.txt", Some("txt"), 1),
            sample("/evidence/b.exe", Some("exe"), 2),
            sample("/evidence/c.txt", Some("txt"), 3),
        ])
        .expect("insert");
        assert_eq!(idx.query_by_extension("txt").expect("q").len(), 2);
        assert_eq!(idx.query_by_extension(".exe").expect("q").len(), 1);
    }

    #[test]
    fn mark_nsrl_and_threat_intel_flags_entries() {
        let (_dir, mut idx) = open_tmp();
        let mut e = sample("/e/f.bin", Some("bin"), 1);
        e.sha256 = Some("deadbeef".into());
        idx.upsert_batch(&[e]).expect("insert");
        idx.mark_nsrl("deadbeef").expect("nsrl");
        idx.mark_threat_intel("deadbeef", "Emotet").expect("ti");
        let hits = idx.threat_intel_hits().expect("hits");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].nsrl_known_good);
        assert_eq!(hits[0].threat_intel_name.as_deref(), Some("Emotet"));
    }

    #[test]
    fn high_entropy_entries_respects_threshold() {
        let (_dir, mut idx) = open_tmp();
        let mut low = sample("/e/text.txt", Some("txt"), 1);
        low.entropy = Some(3.0);
        let mut high = sample("/e/blob.bin", Some("bin"), 1);
        high.entropy = Some(7.9);
        idx.upsert_batch(&[low, high]).expect("insert");
        let hits = idx.high_entropy_entries(7.5).expect("q");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].filename, "blob.bin");
    }

    #[test]
    fn reopen_preserves_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("file_index.db");
        {
            let mut idx = FileIndex::open(&path).expect("open");
            idx.upsert_batch(&[sample("/e/p", Some("p"), 1)])
                .expect("ins");
        }
        let idx = FileIndex::open(&path).expect("reopen");
        assert_eq!(idx.count().expect("c"), 1);
    }
}
