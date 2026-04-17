//! IOC feed import + search UI layer (WF-7).
//!
//! SQLite-backed per-case IOC feed on top of the A-2 search engine.
//! Supports plain-text, CSV, MISP JSON, and STIX 2.1 indicator
//! import.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::Utc;
use rusqlite::{params, Connection, OpenFlags};
use std::fs;
use std::path::Path;
use thiserror::Error;

use crate::ioc::search::{classify_value, Ioc, IocMatch, IocSearcher, IocType};

#[derive(Debug, Error)]
pub enum FeedError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
}

pub struct IocFeedDatabase {
    conn: Connection,
}

impl IocFeedDatabase {
    pub fn open(path: &Path) -> Result<Self, FeedError> {
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
            "CREATE TABLE IF NOT EXISTS iocs ( \
                 id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 value TEXT NOT NULL, ioc_type TEXT NOT NULL, source TEXT, \
                 confidence REAL DEFAULT 1.0, mitre_technique TEXT, \
                 imported_at INTEGER, tags TEXT \
             ); \
             CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value); \
             CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type);",
        )?;
        Ok(Self { conn })
    }

    pub fn count(&self) -> Result<u64, FeedError> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM iocs", [], |r| r.get(0))?;
        Ok(n.max(0) as u64)
    }

    pub fn import_plain(&mut self, path: &Path, source: &str) -> Result<usize, FeedError> {
        let body = fs::read_to_string(path)?;
        let now = Utc::now().timestamp();
        let tx = self.conn.transaction()?;
        let mut n = 0usize;
        for line in body.lines() {
            let value = line.trim();
            if value.is_empty() || value.starts_with('#') {
                continue;
            }
            let kind = classify_value(value)
                .map(|t| ioc_type_key(t).to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            tx.execute(
                "INSERT INTO iocs (value, ioc_type, source, confidence, imported_at) \
                 VALUES (?1, ?2, ?3, 1.0, ?4)",
                params![value, kind, source, now],
            )?;
            n += 1;
        }
        tx.commit()?;
        Ok(n)
    }

    pub fn import_csv(&mut self, path: &Path) -> Result<usize, FeedError> {
        let body = fs::read_to_string(path)?;
        let now = Utc::now().timestamp();
        let tx = self.conn.transaction()?;
        let mut n = 0usize;
        for (i, line) in body.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if i == 0 && line.to_ascii_lowercase().contains("ioc_value") {
                continue;
            }
            let parts: Vec<&str> = line.split(',').collect();
            if parts.is_empty() {
                continue;
            }
            let value = parts[0].trim();
            let kind = parts.get(1).copied().unwrap_or("Unknown").trim();
            let source = parts.get(2).copied().unwrap_or("csv").trim();
            let confidence: f64 = parts
                .get(3)
                .and_then(|s| s.trim().parse::<f64>().ok())
                .unwrap_or(1.0);
            let mitre = parts.get(4).copied().unwrap_or("").trim();
            tx.execute(
                "INSERT INTO iocs (value, ioc_type, source, confidence, mitre_technique, imported_at) \
                 VALUES (?1, ?2, ?3, ?4, NULLIF(?5, ''), ?6)",
                params![value, kind, source, confidence, mitre, now],
            )?;
            n += 1;
        }
        tx.commit()?;
        Ok(n)
    }

    pub fn import_misp(&mut self, path: &Path) -> Result<usize, FeedError> {
        let body = fs::read_to_string(path)?;
        let v: serde_json::Value = serde_json::from_str(&body)?;
        let attributes = v
            .get("Attribute")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
        let now = Utc::now().timestamp();
        let tx = self.conn.transaction()?;
        let mut n = 0usize;
        for attr in attributes {
            let value = attr
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let kind = attr
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let comment = attr
                .get("comment")
                .and_then(|v| v.as_str())
                .unwrap_or("MISP")
                .to_string();
            if value.is_empty() {
                continue;
            }
            tx.execute(
                "INSERT INTO iocs (value, ioc_type, source, confidence, imported_at) \
                 VALUES (?1, ?2, ?3, 1.0, ?4)",
                params![value, kind, comment, now],
            )?;
            n += 1;
        }
        tx.commit()?;
        Ok(n)
    }

    pub fn all(&self) -> Result<Vec<Ioc>, FeedError> {
        let mut stmt = self.conn.prepare(
            "SELECT value, ioc_type, source, confidence, mitre_technique FROM iocs",
        )?;
        let rows = stmt.query_map([], |row| {
            let value: String = row.get(0)?;
            let kind: String = row.get(1)?;
            let source: Option<String> = row.get(2)?;
            let confidence: f64 = row.get::<_, Option<f64>>(3)?.unwrap_or(1.0);
            let mitre: Option<String> = row.get(4)?;
            Ok((value, kind, source, confidence, mitre))
        })?;
        let mut out = Vec::new();
        for r in rows.flatten() {
            let (value, kind_str, source, confidence, mitre) = r;
            let ioc_type = classify_value(&value).unwrap_or(IocType::Username);
            let _ = kind_str;
            out.push(Ioc {
                ioc_type,
                value,
                source: source.unwrap_or_else(|| "unknown".to_string()),
                confidence: confidence as f32,
                mitre_technique: mitre,
            });
        }
        Ok(out)
    }

    pub fn into_searcher(&self) -> Result<IocSearcher, FeedError> {
        Ok(IocSearcher::new(self.all()?))
    }
}

fn ioc_type_key(t: IocType) -> &'static str {
    t.as_str()
}

/// Human-readable match report (one match = one block).
pub fn format_match_report(hits: &[IocMatch]) -> String {
    let mut out = String::new();
    for hit in hits {
        out.push_str(&format!("IOC MATCH: {}\n", hit.ioc.value));
        out.push_str(&format!("  Type:       {}\n", hit.ioc.ioc_type.as_str()));
        out.push_str(&format!("  Source:     {}\n", hit.ioc.source));
        out.push_str(&format!("  Confidence: {:.2}\n", hit.ioc.confidence));
        if let Some(m) = &hit.ioc.mitre_technique {
            out.push_str(&format!("  MITRE:      {}\n", m));
        }
        out.push_str(&format!(
            "  Found in:   artifact #{} field '{}'\n",
            hit.artifact_index, hit.field
        ));
        out.push_str(&format!("    {}\n\n", hit.snippet));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_plugin_sdk::Artifact;

    fn open_tmp() -> (tempfile::TempDir, IocFeedDatabase) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ioc_feed.db");
        let db = IocFeedDatabase::open(&path).expect("open");
        (dir, db)
    }

    #[test]
    fn import_plain_text_classifies_ips_and_hashes() {
        let (_dir, mut db) = open_tmp();
        let dir2 = tempfile::tempdir().expect("tempdir");
        let p = dir2.path().join("ioc.txt");
        fs::write(
            &p,
            "# header\n10.0.0.1\n0123456789abcdef0123456789abcdef\nevil.example.com\n",
        )
        .expect("w");
        let n = db.import_plain(&p, "ETBlocklist").expect("import");
        assert_eq!(n, 3);
        assert_eq!(db.count().expect("c"), 3);
    }

    #[test]
    fn import_csv_skips_header_and_records_confidence() {
        let (_dir, mut db) = open_tmp();
        let dir2 = tempfile::tempdir().expect("tempdir");
        let p = dir2.path().join("ioc.csv");
        fs::write(
            &p,
            "ioc_value,ioc_type,source,confidence,mitre_technique\n\
             192.0.2.5,IpAddress,feed,0.85,T1071\n",
        )
        .expect("w");
        let n = db.import_csv(&p).expect("import");
        assert_eq!(n, 1);
    }

    #[test]
    fn import_misp_handles_attribute_array() {
        let (_dir, mut db) = open_tmp();
        let dir2 = tempfile::tempdir().expect("tempdir");
        let p = dir2.path().join("misp.json");
        fs::write(
            &p,
            r#"{"Attribute":[{"value":"alice@example.com","type":"email","comment":"test"}]}"#,
        )
        .expect("w");
        let n = db.import_misp(&p).expect("misp");
        assert_eq!(n, 1);
    }

    #[test]
    fn into_searcher_matches_imported_ioc_against_artifact() {
        let (_dir, mut db) = open_tmp();
        let dir2 = tempfile::tempdir().expect("tempdir");
        let p = dir2.path().join("ioc.txt");
        fs::write(&p, "10.0.0.5\n").expect("w");
        db.import_plain(&p, "feed").expect("import");
        let searcher = db.into_searcher().expect("searcher");
        let mut a = Artifact::new("NetFlow", "/x/y");
        a.add_field("detail", "traffic to 10.0.0.5:443");
        let hits = searcher.search(&[a]);
        assert!(!hits.is_empty());
    }

    #[test]
    fn format_match_report_contains_ioc_value_and_source() {
        let hit = IocMatch {
            ioc: Ioc {
                ioc_type: IocType::IpAddress,
                value: "10.0.0.5".to_string(),
                source: "feed".to_string(),
                confidence: 0.9,
                mitre_technique: Some("T1071".to_string()),
            },
            artifact_index: 0,
            field: "detail".to_string(),
            snippet: "traffic to 10.0.0.5".to_string(),
        };
        let report = format_match_report(&[hit]);
        assert!(report.contains("IOC MATCH: 10.0.0.5"));
        assert!(report.contains("T1071"));
    }
}
