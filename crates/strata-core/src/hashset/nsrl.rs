//! NSRL hash-set import + query (WF-4).
//!
//! Air-gapped: the NSRL distribution is downloaded once by the
//! examiner and imported as a local CSV or SQLite file. No network
//! access during import or query.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use rusqlite::{params, Connection, OpenFlags};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NsrlError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsrlEntry {
    pub sha256: Option<Vec<u8>>,
    pub sha1: Option<Vec<u8>>,
    pub md5: Option<Vec<u8>>,
    pub filename: Option<String>,
    pub filesize: Option<u64>,
}

pub struct NsrlDatabase {
    conn: Connection,
}

impl NsrlDatabase {
    pub fn open(path: &Path) -> Result<Self, NsrlError> {
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
            "CREATE TABLE IF NOT EXISTS nsrl ( \
                 sha256 BLOB, sha1 BLOB, md5 BLOB, \
                 filename TEXT, filesize INTEGER \
             ); \
             CREATE INDEX IF NOT EXISTS idx_nsrl_sha256 ON nsrl(sha256); \
             CREATE INDEX IF NOT EXISTS idx_nsrl_md5 ON nsrl(md5); \
             CREATE INDEX IF NOT EXISTS idx_nsrl_sha1 ON nsrl(sha1);",
        )?;
        Ok(Self { conn })
    }

    pub fn record_count(&self) -> Result<u64, NsrlError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM nsrl", [], |row| row.get(0))?;
        Ok(n.max(0) as u64)
    }

    /// Import a legacy RDS 1.x `NSRLFile.txt` (quoted, comma-delimited).
    pub fn import_from_csv(&mut self, csv_path: &Path) -> Result<usize, NsrlError> {
        let f = fs::File::open(csv_path)?;
        let reader = BufReader::new(f);
        let tx = self.conn.transaction()?;
        let mut count = 0usize;
        for (idx, line) in reader.lines().enumerate() {
            let line = line?;
            if idx == 0 && line.contains("SHA") {
                continue;
            }
            let parts = parse_csv_line(&line);
            if parts.len() < 3 {
                continue;
            }
            let sha1 = hex_decode(&parts[0]);
            let md5 = hex_decode(&parts[1]);
            let _crc = &parts[2];
            let filename = parts.get(3).cloned();
            let filesize = parts.get(4).and_then(|s| s.parse::<i64>().ok());
            tx.execute(
                "INSERT INTO nsrl (sha256, sha1, md5, filename, filesize) VALUES (NULL, ?1, ?2, ?3, ?4)",
                params![sha1, md5, filename, filesize],
            )?;
            count += 1;
        }
        tx.commit()?;
        Ok(count)
    }

    /// Import from a modern RDSv3 SQLite database. Reads the `FILE`
    /// table: `(sha256, md5, crc32, file_name, file_size)`.
    pub fn import_from_sqlite(&mut self, rds_path: &Path) -> Result<usize, NsrlError> {
        let src = Connection::open_with_flags(
            rds_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        // The exact column layout varies across RDS releases; probe
        // both common shapes.
        let sql = if src
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='FILE'",
                [],
                |_| Ok(()),
            )
            .is_ok()
        {
            "SELECT sha256, md5, file_name, file_size FROM FILE"
        } else {
            "SELECT sha256, md5, file_name, file_size FROM file"
        };
        let mut stmt = src.prepare(sql)?;
        let tx = self.conn.transaction()?;
        let mut count = 0usize;
        let rows = stmt.query_map([], |row| {
            let sha256: Option<String> = row.get(0)?;
            let md5: Option<String> = row.get(1)?;
            let name: Option<String> = row.get(2)?;
            let size: Option<i64> = row.get(3)?;
            Ok((sha256, md5, name, size))
        })?;
        for r in rows.flatten() {
            let (sha256, md5, name, size) = r;
            let sha256_b = sha256.and_then(|s| hex_decode(&s));
            let md5_b = md5.and_then(|s| hex_decode(&s));
            tx.execute(
                "INSERT INTO nsrl (sha256, sha1, md5, filename, filesize) VALUES (?1, NULL, ?2, ?3, ?4)",
                params![sha256_b, md5_b, name, size],
            )?;
            count += 1;
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn is_known_good_sha256(&self, hash: &[u8; 32]) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM nsrl WHERE sha256 = ?1 LIMIT 1",
                params![&hash[..]],
                |_| Ok(()),
            )
            .is_ok()
    }

    pub fn is_known_good_md5(&self, hash: &[u8; 16]) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM nsrl WHERE md5 = ?1 LIMIT 1",
                params![&hash[..]],
                |_| Ok(()),
            )
            .is_ok()
    }

    pub fn lookup_sha256(&self, hash: &[u8; 32]) -> Option<NsrlEntry> {
        self.conn
            .query_row(
                "SELECT sha256, sha1, md5, filename, filesize FROM nsrl WHERE sha256 = ?1 LIMIT 1",
                params![&hash[..]],
                |row| {
                    let sha256: Option<Vec<u8>> = row.get(0)?;
                    let sha1: Option<Vec<u8>> = row.get(1)?;
                    let md5: Option<Vec<u8>> = row.get(2)?;
                    let filename: Option<String> = row.get(3)?;
                    let filesize: Option<i64> = row.get(4)?;
                    Ok(NsrlEntry {
                        sha256,
                        sha1,
                        md5,
                        filename,
                        filesize: filesize.map(|n| n.max(0) as u64),
                    })
                },
            )
            .ok()
    }
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(current.trim().trim_matches('"').to_string());
                current = String::new();
            }
            _ => current.push(c),
        }
    }
    out.push(current.trim().trim_matches('"').to_string());
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) || clean.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn open_tmp() -> (tempfile::TempDir, NsrlDatabase) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nsrl.db");
        let db = NsrlDatabase::open(&path).expect("open");
        (dir, db)
    }

    #[test]
    fn open_creates_schema_and_empty_count() {
        let (_dir, db) = open_tmp();
        assert_eq!(db.record_count().expect("count"), 0);
    }

    #[test]
    fn import_from_csv_accepts_header_and_rows() {
        let (_dir, mut db) = open_tmp();
        let dir2 = tempfile::tempdir().expect("tempdir");
        let csv = dir2.path().join("NSRLFile.txt");
        fs::write(
            &csv,
            "\"SHA-1\",\"MD5\",\"CRC32\",\"FileName\",\"FileSize\"\n\
             \"0123456789abcdef0123456789abcdef01234567\",\"0123456789abcdef0123456789abcdef\",\"DEADBEEF\",\"explorer.exe\",1024\n",
        )
        .expect("w");
        let n = db.import_from_csv(&csv).expect("import");
        assert_eq!(n, 1);
        assert_eq!(db.record_count().expect("count"), 1);
    }

    #[test]
    fn is_known_good_sha256_lookup_works() {
        let (_dir, db) = open_tmp();
        // Hand-insert a 32-byte hash.
        let hash = [0xAA; 32];
        db.conn
            .execute(
                "INSERT INTO nsrl (sha256, sha1, md5, filename, filesize) VALUES (?1, NULL, NULL, 'f', 1)",
                params![&hash[..]],
            )
            .expect("ins");
        assert!(db.is_known_good_sha256(&hash));
        assert!(!db.is_known_good_sha256(&[0x00; 32]));
    }

    #[test]
    fn lookup_sha256_returns_entry_fields() {
        let (_dir, db) = open_tmp();
        let hash = [0xBB; 32];
        db.conn
            .execute(
                "INSERT INTO nsrl (sha256, sha1, md5, filename, filesize) VALUES (?1, NULL, NULL, 'notepad.exe', 2048)",
                params![&hash[..]],
            )
            .expect("ins");
        let entry = db.lookup_sha256(&hash).expect("found");
        assert_eq!(entry.filename.as_deref(), Some("notepad.exe"));
        assert_eq!(entry.filesize, Some(2048));
    }

    #[test]
    fn import_from_sqlite_reads_file_table() {
        let (_dir, mut db) = open_tmp();
        let dir2 = tempfile::tempdir().expect("tempdir");
        let rds = dir2.path().join("RDSv3.db");
        let src = Connection::open(&rds).expect("open");
        src.execute_batch(
            "CREATE TABLE FILE (sha256 TEXT, md5 TEXT, crc32 TEXT, file_name TEXT, file_size INTEGER);",
        )
        .expect("schema");
        src.execute(
            "INSERT INTO FILE VALUES ('cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00', \
                                      'cc00cc00cc00cc00cc00cc00cc00cc00', 'DEADBEEF', 'cmd.exe', 1024)",
            [],
        )
        .expect("ins");
        drop(src);
        let n = db.import_from_sqlite(&rds).expect("import");
        assert_eq!(n, 1);
        assert_eq!(db.record_count().expect("count"), 1);
    }

    #[test]
    fn parse_csv_line_handles_quoted_commas() {
        let fields = parse_csv_line("\"abc\",\"d,e,f\",\"ghi\"");
        assert_eq!(
            fields,
            vec!["abc".to_string(), "d,e,f".to_string(), "ghi".to_string()]
        );
    }
}
