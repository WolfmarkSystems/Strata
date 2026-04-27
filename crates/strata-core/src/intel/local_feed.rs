//! Local threat-intelligence feed import (WF-8).
//!
//! Air-gapped: the examiner downloads feeds out of band and imports
//! them with explicit commands. No network access.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::Utc;
use rusqlite::{params, Connection, OpenFlags};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntelError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
}

pub struct ThreatIntelDatabase {
    conn: Connection,
}

impl ThreatIntelDatabase {
    pub fn open(path: &Path) -> Result<Self, IntelError> {
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
            "CREATE TABLE IF NOT EXISTS ip_reputation ( \
                 ip_cidr TEXT NOT NULL, malware_family TEXT, source TEXT, \
                 first_seen TEXT, last_seen TEXT, confidence REAL DEFAULT 1.0 \
             ); \
             CREATE INDEX IF NOT EXISTS idx_ip_cidr ON ip_reputation(ip_cidr); \
             CREATE TABLE IF NOT EXISTS domain_reputation ( \
                 domain TEXT NOT NULL, category TEXT, source TEXT, confidence REAL DEFAULT 1.0 \
             ); \
             CREATE INDEX IF NOT EXISTS idx_domain ON domain_reputation(domain); \
             CREATE TABLE IF NOT EXISTS hash_reputation ( \
                 sha256 BLOB, md5 BLOB, malware_name TEXT, file_type TEXT, \
                 source TEXT, confidence REAL DEFAULT 1.0 \
             ); \
             CREATE INDEX IF NOT EXISTS idx_hash_sha256 ON hash_reputation(sha256); \
             CREATE INDEX IF NOT EXISTS idx_hash_md5 ON hash_reputation(md5); \
             CREATE TABLE IF NOT EXISTS feed_status ( \
                 feed_name TEXT PRIMARY KEY, kind TEXT, imported_at INTEGER, record_count INTEGER \
             );",
        )?;
        Ok(Self { conn })
    }

    pub fn import_ip_plaintext(&mut self, path: &Path, source: &str) -> Result<usize, IntelError> {
        let body = fs::read_to_string(path)?;
        let tx = self.conn.transaction()?;
        let mut n = 0usize;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            tx.execute(
                "INSERT INTO ip_reputation (ip_cidr, source) VALUES (?1, ?2)",
                params![line, source],
            )?;
            n += 1;
        }
        tx.commit()?;
        self.record_feed_status(source, "ip", n)?;
        Ok(n)
    }

    pub fn import_domain_plaintext(
        &mut self,
        path: &Path,
        source: &str,
    ) -> Result<usize, IntelError> {
        let body = fs::read_to_string(path)?;
        let tx = self.conn.transaction()?;
        let mut n = 0usize;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            tx.execute(
                "INSERT INTO domain_reputation (domain, source) VALUES (?1, ?2)",
                params![line, source],
            )?;
            n += 1;
        }
        tx.commit()?;
        self.record_feed_status(source, "domain", n)?;
        Ok(n)
    }

    pub fn import_hash_plaintext(
        &mut self,
        path: &Path,
        source: &str,
    ) -> Result<usize, IntelError> {
        let body = fs::read_to_string(path)?;
        let tx = self.conn.transaction()?;
        let mut n = 0usize;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let Some(hex) = parts.next() else {
                continue;
            };
            let malware_name = parts.next().unwrap_or("").trim().to_string();
            let Some(bytes) = hex_decode(hex) else {
                continue;
            };
            match bytes.len() {
                16 => {
                    tx.execute(
                        "INSERT INTO hash_reputation (md5, malware_name, source) VALUES (?1, ?2, ?3)",
                        params![bytes, malware_name, source],
                    )?;
                }
                32 => {
                    tx.execute(
                        "INSERT INTO hash_reputation (sha256, malware_name, source) VALUES (?1, ?2, ?3)",
                        params![bytes, malware_name, source],
                    )?;
                }
                _ => continue,
            }
            n += 1;
        }
        tx.commit()?;
        self.record_feed_status(source, "hash", n)?;
        Ok(n)
    }

    pub fn ip_known_bad(&self, ip: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM ip_reputation WHERE ip_cidr = ?1 LIMIT 1",
                [ip],
                |_| Ok(()),
            )
            .is_ok()
    }

    pub fn domain_known_bad(&self, domain: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM domain_reputation WHERE domain = ?1 LIMIT 1",
                [domain],
                |_| Ok(()),
            )
            .is_ok()
    }

    pub fn hash_known_bad_sha256(&self, hash: &[u8; 32]) -> Option<String> {
        self.conn
            .query_row(
                "SELECT malware_name FROM hash_reputation WHERE sha256 = ?1 LIMIT 1",
                [&hash[..]],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten()
    }

    pub fn status(&self) -> Result<Vec<(String, String, i64, i64)>, IntelError> {
        let mut stmt = self
            .conn
            .prepare("SELECT feed_name, kind, imported_at, record_count FROM feed_status")?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let kind: String = row.get(1)?;
            let imported: i64 = row.get(2)?;
            let count: i64 = row.get(3)?;
            Ok((name, kind, imported, count))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn record_feed_status(
        &mut self,
        source: &str,
        kind: &str,
        count: usize,
    ) -> Result<(), IntelError> {
        let now = Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO feed_status (feed_name, kind, imported_at, record_count) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(feed_name) DO UPDATE SET kind=excluded.kind, \
                                                  imported_at=excluded.imported_at, \
                                                  record_count=excluded.record_count",
            params![source, kind, now, count as i64],
        )?;
        Ok(())
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
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

    fn open_tmp() -> (tempfile::TempDir, ThreatIntelDatabase) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("intel.db");
        let db = ThreatIntelDatabase::open(&path).expect("open");
        (dir, db)
    }

    #[test]
    fn import_ip_plaintext_populates_ip_reputation() {
        let (_dir, mut db) = open_tmp();
        let dir2 = tempfile::tempdir().expect("tempdir");
        let p = dir2.path().join("ip.txt");
        fs::write(&p, "# header\n192.0.2.5\n10.0.0.1\n").expect("w");
        let n = db.import_ip_plaintext(&p, "emerging_threats").expect("imp");
        assert_eq!(n, 2);
        assert!(db.ip_known_bad("192.0.2.5"));
        assert!(!db.ip_known_bad("8.8.8.8"));
    }

    #[test]
    fn import_hash_plaintext_routes_by_length() {
        let (_dir, mut db) = open_tmp();
        let dir2 = tempfile::tempdir().expect("tempdir");
        let p = dir2.path().join("hash.txt");
        fs::write(
            &p,
            "00112233445566778899aabbccddeeff AgentTesla\n\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Emotet\n",
        )
        .expect("w");
        let n = db.import_hash_plaintext(&p, "loki").expect("imp");
        assert_eq!(n, 2);
        let hash = [0xAA; 32];
        assert_eq!(db.hash_known_bad_sha256(&hash).as_deref(), Some("Emotet"));
    }

    #[test]
    fn import_domain_plaintext_populates_domain_reputation() {
        let (_dir, mut db) = open_tmp();
        let dir2 = tempfile::tempdir().expect("tempdir");
        let p = dir2.path().join("d.txt");
        fs::write(&p, "evil.example.com\nbaddomain.test\n").expect("w");
        let n = db
            .import_domain_plaintext(&p, "malware_domain_list")
            .expect("imp");
        assert_eq!(n, 2);
        assert!(db.domain_known_bad("evil.example.com"));
    }

    #[test]
    fn status_reflects_imported_feeds() {
        let (_dir, mut db) = open_tmp();
        let dir2 = tempfile::tempdir().expect("tempdir");
        let p = dir2.path().join("ip.txt");
        fs::write(&p, "10.0.0.1\n").expect("w");
        db.import_ip_plaintext(&p, "ET").expect("imp");
        let s = db.status().expect("s");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].0, "ET");
        assert_eq!(s[0].3, 1);
    }

    #[test]
    fn hex_decode_handles_whitespace_and_length() {
        assert_eq!(hex_decode("AABB"), Some(vec![0xAA, 0xBB]));
        assert!(hex_decode("ABC").is_none());
    }
}
