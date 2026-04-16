//! Unified timeline SQLite store (Sprint A-1).
//!
//! Aggregates artifacts produced by every Strata plugin into a single
//! queryable database so the UI and CLI can drive time-range, MITRE,
//! and full-text searches without re-running parsers.
//!
//! Schema:
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS timeline (
//!     id INTEGER PRIMARY KEY AUTOINCREMENT,
//!     timestamp_us INTEGER NOT NULL,
//!     artifact_type TEXT NOT NULL,
//!     plugin TEXT NOT NULL,
//!     description TEXT NOT NULL,
//!     raw_data TEXT,
//!     mitre_technique TEXT,
//!     confidence REAL DEFAULT 1.0,
//!     source_file TEXT,
//!     suspicious INTEGER DEFAULT 0
//! );
//! ```
//!
//! Plus a time-index, artifact-type index, MITRE index, and an FTS5
//! virtual table mirroring `description` + `raw_data`.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_plugin_sdk::Artifact;
use thiserror::Error;

/// Errors surfaced by the timeline database layer.
#[derive(Debug, Error)]
pub enum TimelineError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

/// One row from the `timeline` table — denormalized so callers don't
/// have to re-query to render a row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub id: i64,
    /// Event time in Unix microseconds (negative values permitted for
    /// pre-1970 events, although these are rare in forensic artifacts).
    pub timestamp_us: i64,
    pub artifact_type: String,
    pub plugin: String,
    pub description: String,
    pub raw_data: Option<String>,
    pub mitre_technique: Option<String>,
    pub confidence: f64,
    pub source_file: Option<String>,
    pub suspicious: bool,
}

/// Unified timeline store.
pub struct TimelineDatabase {
    conn: Connection,
}

impl TimelineDatabase {
    /// Open (or create) a timeline database at `path`. The enclosing
    /// directory must already exist.
    pub fn open(path: &Path) -> Result<Self, TimelineError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
        let conn = Connection::open_with_flags(path, flags)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; \
             PRAGMA synchronous=NORMAL; \
             CREATE TABLE IF NOT EXISTS timeline ( \
                 id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 timestamp_us INTEGER NOT NULL, \
                 artifact_type TEXT NOT NULL, \
                 plugin TEXT NOT NULL, \
                 description TEXT NOT NULL, \
                 raw_data TEXT, \
                 mitre_technique TEXT, \
                 confidence REAL DEFAULT 1.0, \
                 source_file TEXT, \
                 suspicious INTEGER DEFAULT 0 \
             ); \
             CREATE INDEX IF NOT EXISTS idx_timeline_timestamp \
                 ON timeline(timestamp_us); \
             CREATE INDEX IF NOT EXISTS idx_timeline_artifact_type \
                 ON timeline(artifact_type); \
             CREATE INDEX IF NOT EXISTS idx_timeline_mitre \
                 ON timeline(mitre_technique); \
             CREATE VIRTUAL TABLE IF NOT EXISTS timeline_fts \
                 USING fts5(description, raw_data, content=timeline, content_rowid=id);",
        )?;
        Ok(Self { conn })
    }

    /// Open a read-only handle (for query-only consumers).
    pub fn open_readonly(path: &Path) -> Result<Self, TimelineError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)?;
        Ok(Self { conn })
    }

    /// Insert one artifact. Returns the generated row id.
    pub fn insert(&mut self, artifact: &Artifact, plugin: &str) -> Result<i64, TimelineError> {
        let row = Self::artifact_to_row(artifact, plugin)?;
        let tx = self.conn.transaction()?;
        let id = {
            tx.execute(
                "INSERT INTO timeline ( \
                     timestamp_us, artifact_type, plugin, description, raw_data, \
                     mitre_technique, confidence, source_file, suspicious \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    row.timestamp_us,
                    row.artifact_type,
                    row.plugin,
                    row.description,
                    row.raw_data,
                    row.mitre_technique,
                    row.confidence,
                    row.source_file,
                    row.suspicious as i64,
                ],
            )?;
            let id = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO timeline_fts(rowid, description, raw_data) VALUES (?1, ?2, ?3)",
                params![id, row.description, row.raw_data],
            )?;
            id
        };
        tx.commit()?;
        Ok(id)
    }

    /// Insert a batch of artifacts inside one transaction. Returns the
    /// number of inserted rows.
    pub fn insert_all(
        &mut self,
        artifacts: &[Artifact],
        plugin: &str,
    ) -> Result<usize, TimelineError> {
        let tx = self.conn.transaction()?;
        let mut count = 0usize;
        for a in artifacts {
            let row = Self::artifact_to_row(a, plugin)?;
            tx.execute(
                "INSERT INTO timeline ( \
                     timestamp_us, artifact_type, plugin, description, raw_data, \
                     mitre_technique, confidence, source_file, suspicious \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    row.timestamp_us,
                    row.artifact_type,
                    row.plugin,
                    row.description,
                    row.raw_data,
                    row.mitre_technique,
                    row.confidence,
                    row.source_file,
                    row.suspicious as i64,
                ],
            )?;
            let id = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO timeline_fts(rowid, description, raw_data) VALUES (?1, ?2, ?3)",
                params![id, row.description, row.raw_data],
            )?;
            count += 1;
        }
        tx.commit()?;
        Ok(count)
    }

    /// Return every row whose `timestamp_us` falls in `[start, end]`
    /// (inclusive) ordered ascending.
    pub fn query_range(
        &self,
        start_us: i64,
        end_us: i64,
    ) -> Result<Vec<TimelineEntry>, TimelineError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp_us, artifact_type, plugin, description, \
                    raw_data, mitre_technique, confidence, source_file, suspicious \
             FROM timeline \
             WHERE timestamp_us BETWEEN ?1 AND ?2 \
             ORDER BY timestamp_us ASC",
        )?;
        let rows = stmt.query_map(params![start_us, end_us], Self::map_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// FTS5 search across `description` and `raw_data`. The query is
    /// passed verbatim to SQLite's FTS5 match syntax.
    pub fn search(&self, query: &str) -> Result<Vec<TimelineEntry>, TimelineError> {
        let mut stmt = self.conn.prepare(
            "SELECT t.id, t.timestamp_us, t.artifact_type, t.plugin, t.description, \
                    t.raw_data, t.mitre_technique, t.confidence, t.source_file, t.suspicious \
             FROM timeline t \
             JOIN timeline_fts f ON f.rowid = t.id \
             WHERE timeline_fts MATCH ?1 \
             ORDER BY t.timestamp_us ASC",
        )?;
        let rows = stmt.query_map(params![query], Self::map_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Return every row tagged with the given MITRE technique
    /// (`"T1547.001"`, etc.), ordered ascending.
    pub fn query_mitre(&self, technique: &str) -> Result<Vec<TimelineEntry>, TimelineError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp_us, artifact_type, plugin, description, \
                    raw_data, mitre_technique, confidence, source_file, suspicious \
             FROM timeline \
             WHERE mitre_technique = ?1 \
             ORDER BY timestamp_us ASC",
        )?;
        let rows = stmt.query_map(params![technique], Self::map_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Count rows in the timeline.
    pub fn count(&self) -> Result<i64, TimelineError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM timeline", [], |row| row.get(0))?;
        Ok(n)
    }

    fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TimelineEntry> {
        Ok(TimelineEntry {
            id: row.get(0)?,
            timestamp_us: row.get(1)?,
            artifact_type: row.get(2)?,
            plugin: row.get(3)?,
            description: row.get(4)?,
            raw_data: row.get(5)?,
            mitre_technique: row.get(6)?,
            confidence: row.get(7)?,
            source_file: row.get(8)?,
            suspicious: row.get::<_, i64>(9)? != 0,
        })
    }

    fn artifact_to_row(a: &Artifact, plugin: &str) -> Result<RowInsert, TimelineError> {
        // Artifact.timestamp is Option<u64> Unix seconds; convert to us.
        let timestamp_us = a
            .timestamp
            .map(|s| (s as i64).saturating_mul(1_000_000))
            .unwrap_or(0);
        let artifact_type = a
            .data
            .get("file_type")
            .cloned()
            .unwrap_or_else(|| a.category.clone());
        let description = a
            .data
            .get("title")
            .cloned()
            .or_else(|| a.data.get("detail").cloned())
            .unwrap_or_else(|| a.source.clone());
        let raw_data = serde_json::to_string(&a.data).ok();
        let mitre_technique = a.data.get("mitre").cloned();
        let confidence = a
            .data
            .get("confidence")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(1.0);
        let source_file = Some(a.source.clone());
        let suspicious = a
            .data
            .get("suspicious")
            .map(|v| v == "true")
            .unwrap_or(false);
        Ok(RowInsert {
            timestamp_us,
            artifact_type,
            plugin: plugin.to_string(),
            description,
            raw_data,
            mitre_technique,
            confidence,
            source_file,
            suspicious,
        })
    }
}

struct RowInsert {
    timestamp_us: i64,
    artifact_type: String,
    plugin: String,
    description: String,
    raw_data: Option<String>,
    mitre_technique: Option<String>,
    confidence: f64,
    source_file: Option<String>,
    suspicious: bool,
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_artifact(
        kind: &str,
        src: &str,
        ts: u64,
        title: &str,
        mitre: &str,
        suspicious: bool,
    ) -> Artifact {
        let mut a = Artifact::new(kind, src);
        a.timestamp = Some(ts);
        a.add_field("title", title);
        a.add_field("file_type", kind);
        a.add_field("mitre", mitre);
        if suspicious {
            a.add_field("suspicious", "true");
        }
        a
    }

    fn open_tmp() -> (tempfile::TempDir, TimelineDatabase) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("timeline.db");
        let db = TimelineDatabase::open(&path).expect("open");
        (dir, db)
    }

    #[test]
    fn open_creates_schema() {
        let (_dir, db) = open_tmp();
        assert_eq!(db.count().expect("count"), 0);
    }

    #[test]
    fn insert_and_query_range_round_trip() {
        let (_dir, mut db) = open_tmp();
        let a1 = make_artifact(
            "Prefetch Execution",
            "/pf/notepad.pf",
            1_717_243_200,
            "notepad executed",
            "T1204",
            false,
        );
        let a2 = make_artifact(
            "ShimCache",
            "SYSTEM",
            1_717_243_300,
            "shim entry",
            "T1546.012",
            true,
        );
        db.insert(&a1, "phantom").expect("insert 1");
        db.insert(&a2, "phantom").expect("insert 2");
        assert_eq!(db.count().expect("count"), 2);

        let in_range = db
            .query_range(
                1_717_243_000_000_000,
                1_717_243_400_000_000,
            )
            .expect("range");
        assert_eq!(in_range.len(), 2);
        assert_eq!(in_range[0].artifact_type, "Prefetch Execution");
        assert!(in_range[1].suspicious);
        assert_eq!(in_range[1].plugin, "phantom");
    }

    #[test]
    fn insert_all_is_transactional_and_fast() {
        let (_dir, mut db) = open_tmp();
        let mut batch: Vec<Artifact> = Vec::new();
        for i in 0..50 {
            batch.push(make_artifact(
                "FSEvent",
                "/evidence/evt",
                1_717_243_000 + i as u64,
                &format!("evt {}", i),
                "T1083",
                i % 3 == 0,
            ));
        }
        let n = db.insert_all(&batch, "mactrace").expect("insert_all");
        assert_eq!(n, 50);
        assert_eq!(db.count().expect("count"), 50);
    }

    #[test]
    fn query_mitre_filters_by_technique() {
        let (_dir, mut db) = open_tmp();
        db.insert(
            &make_artifact("A", "s1", 1, "t1", "T1059", false),
            "x",
        )
        .expect("ins a");
        db.insert(
            &make_artifact("B", "s2", 2, "t2", "T1204", false),
            "x",
        )
        .expect("ins b");
        db.insert(
            &make_artifact("C", "s3", 3, "t3", "T1059", true),
            "x",
        )
        .expect("ins c");
        let hits = db.query_mitre("T1059").expect("mitre");
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|e| e.mitre_technique.as_deref() == Some("T1059")));
    }

    #[test]
    fn search_fts_finds_description_tokens() {
        let (_dir, mut db) = open_tmp();
        db.insert(
            &make_artifact("LNK", "/r/a.lnk", 1, "suspicious payload.exe", "T1204", true),
            "phantom",
        )
        .expect("ins");
        db.insert(
            &make_artifact("LNK", "/r/b.lnk", 2, "ordinary office document", "T1204", false),
            "phantom",
        )
        .expect("ins");
        let hits = db.search("payload").expect("search");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("payload"));
    }

    #[test]
    fn query_range_is_inclusive_and_sorted() {
        let (_dir, mut db) = open_tmp();
        db.insert(
            &make_artifact("E", "/s", 100, "late", "T1", false),
            "p",
        )
        .expect("ins");
        db.insert(
            &make_artifact("E", "/s", 50, "mid", "T1", false),
            "p",
        )
        .expect("ins");
        db.insert(
            &make_artifact("E", "/s", 10, "early", "T1", false),
            "p",
        )
        .expect("ins");
        let hits = db
            .query_range(10_000_000, 100_000_000)
            .expect("range");
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].description, "early");
        assert_eq!(hits[2].description, "late");
    }
}
