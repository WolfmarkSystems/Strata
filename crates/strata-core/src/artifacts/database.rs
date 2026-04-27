//! PERSIST-1 — artifacts SQLite database.
//!
//! Per-case `artifacts.sqlite` with one row per artifact emitted by a
//! plugin. Schema mirrors the plugin SDK's `ArtifactRecord` plus
//! examiner-facing fields (approved / notes / tags) and per-run
//! bookkeeping (case_id, plugin_name, created_at). Batch inserts run
//! inside a single transaction for throughput.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Transaction};
use serde::{Deserialize, Serialize};
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredArtifact {
    pub id: i64,
    pub case_id: String,
    pub plugin_name: String,
    pub category: String,
    pub subcategory: String,
    pub title: String,
    pub detail: String,
    pub source_path: String,
    pub timestamp: Option<i64>,
    pub forensic_value: String,
    pub mitre_technique: Option<String>,
    pub confidence: u8,
    pub is_suspicious: bool,
    pub raw_data: Option<String>,
    pub created_at: DateTime<Utc>,
    pub examiner_approved: bool,
    pub examiner_notes: Option<String>,
    pub examiner_tags: Option<String>,
}

pub struct ArtifactDatabase {
    conn: Connection,
    case_id: String,
}

impl ArtifactDatabase {
    pub fn open_or_create(case_dir: &Path, case_id: &str) -> rusqlite::Result<Self> {
        std::fs::create_dir_all(case_dir).ok();
        let path = case_dir.join("artifacts.sqlite");
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                plugin_name TEXT NOT NULL,
                category TEXT NOT NULL,
                subcategory TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL,
                detail TEXT,
                source_path TEXT,
                timestamp INTEGER,
                forensic_value TEXT NOT NULL,
                mitre_technique TEXT,
                confidence INTEGER,
                is_suspicious INTEGER DEFAULT 0,
                raw_data TEXT,
                created_at INTEGER NOT NULL,
                examiner_approved INTEGER DEFAULT 0,
                examiner_notes TEXT,
                examiner_tags TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
            CREATE INDEX IF NOT EXISTS idx_artifacts_plugin ON artifacts(plugin_name);
            CREATE INDEX IF NOT EXISTS idx_artifacts_category ON artifacts(category);
            CREATE INDEX IF NOT EXISTS idx_artifacts_timestamp ON artifacts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_artifacts_forensic_value ON artifacts(forensic_value);
            CREATE INDEX IF NOT EXISTS idx_artifacts_suspicious ON artifacts(is_suspicious);
            CREATE INDEX IF NOT EXISTS idx_artifacts_approved ON artifacts(examiner_approved);

            CREATE TABLE IF NOT EXISTS artifact_relationships (
                source_id INTEGER NOT NULL,
                target_id INTEGER NOT NULL,
                relationship_type TEXT NOT NULL,
                confidence REAL,
                PRIMARY KEY (source_id, target_id, relationship_type),
                FOREIGN KEY (source_id) REFERENCES artifacts(id),
                FOREIGN KEY (target_id) REFERENCES artifacts(id)
            );",
        )?;
        Ok(Self {
            conn,
            case_id: case_id.to_string(),
        })
    }

    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    pub fn insert(&mut self, plugin: &str, record: &ArtifactRecord) -> rusqlite::Result<i64> {
        let tx = self.conn.transaction()?;
        let id = insert_one(&tx, &self.case_id, plugin, record)?;
        tx.commit()?;
        Ok(id)
    }

    pub fn insert_batch(
        &mut self,
        plugin: &str,
        records: &[ArtifactRecord],
    ) -> rusqlite::Result<Vec<i64>> {
        let tx = self.conn.transaction()?;
        let mut ids = Vec::with_capacity(records.len());
        for record in records {
            ids.push(insert_one(&tx, &self.case_id, plugin, record)?);
        }
        tx.commit()?;
        Ok(ids)
    }

    pub fn count(&self) -> rusqlite::Result<u64> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM artifacts WHERE case_id = ?1",
                [&self.case_id],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u64)
    }

    pub fn count_by_plugin(&self) -> rusqlite::Result<HashMap<String, u64>> {
        let mut stmt = self.conn.prepare(
            "SELECT plugin_name, COUNT(*) FROM artifacts WHERE case_id = ?1 GROUP BY plugin_name",
        )?;
        let rows = stmt.query_map([&self.case_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?;
        let mut out = HashMap::new();
        for row in rows.flatten() {
            out.insert(row.0, row.1);
        }
        Ok(out)
    }

    pub fn query_by_plugin(&self, plugin: &str) -> rusqlite::Result<Vec<StoredArtifact>> {
        let sql = "SELECT id, case_id, plugin_name, category, subcategory, title, detail, \
                    source_path, timestamp, forensic_value, mitre_technique, confidence, \
                    is_suspicious, raw_data, created_at, examiner_approved, examiner_notes, \
                    examiner_tags \
                    FROM artifacts WHERE case_id = ?1 AND plugin_name = ?2 ORDER BY id";
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![&self.case_id, plugin], row_to_stored)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    }

    pub fn query_by_category(&self, category: &str) -> rusqlite::Result<Vec<StoredArtifact>> {
        let sql = "SELECT id, case_id, plugin_name, category, subcategory, title, detail, \
                    source_path, timestamp, forensic_value, mitre_technique, confidence, \
                    is_suspicious, raw_data, created_at, examiner_approved, examiner_notes, \
                    examiner_tags \
                    FROM artifacts WHERE case_id = ?1 AND category = ?2 ORDER BY id";
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![&self.case_id, category], row_to_stored)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    }

    pub fn query_by_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> rusqlite::Result<Vec<StoredArtifact>> {
        let sql = "SELECT id, case_id, plugin_name, category, subcategory, title, detail, \
                    source_path, timestamp, forensic_value, mitre_technique, confidence, \
                    is_suspicious, raw_data, created_at, examiner_approved, examiner_notes, \
                    examiner_tags \
                    FROM artifacts WHERE case_id = ?1 AND timestamp BETWEEN ?2 AND ?3 ORDER BY timestamp";
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(
            params![&self.case_id, start.timestamp(), end.timestamp()],
            row_to_stored,
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    }

    pub fn search(&self, query: &str) -> rusqlite::Result<Vec<StoredArtifact>> {
        let like = format!("%{}%", query);
        let sql = "SELECT id, case_id, plugin_name, category, subcategory, title, detail, \
                    source_path, timestamp, forensic_value, mitre_technique, confidence, \
                    is_suspicious, raw_data, created_at, examiner_approved, examiner_notes, \
                    examiner_tags \
                    FROM artifacts WHERE case_id = ?1 AND (title LIKE ?2 OR detail LIKE ?2) ORDER BY id";
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![&self.case_id, &like], row_to_stored)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    }

    pub fn query_by_title_contains(&self, needle: &str) -> rusqlite::Result<Vec<StoredArtifact>> {
        let like = format!("%{}%", needle);
        let sql = "SELECT id, case_id, plugin_name, category, subcategory, title, detail, \
                    source_path, timestamp, forensic_value, mitre_technique, confidence, \
                    is_suspicious, raw_data, created_at, examiner_approved, examiner_notes, \
                    examiner_tags \
                    FROM artifacts WHERE case_id = ?1 AND title LIKE ?2 ORDER BY id";
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![&self.case_id, &like], row_to_stored)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    }
}

fn row_to_stored(r: &rusqlite::Row) -> rusqlite::Result<StoredArtifact> {
    let created_ts: i64 = r.get(14)?;
    let created_at = chrono::TimeZone::timestamp_opt(&Utc, created_ts, 0)
        .single()
        .unwrap_or_else(Utc::now);
    Ok(StoredArtifact {
        id: r.get(0)?,
        case_id: r.get(1)?,
        plugin_name: r.get(2)?,
        category: r.get(3)?,
        subcategory: r.get(4)?,
        title: r.get(5)?,
        detail: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
        source_path: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
        timestamp: r.get(8)?,
        forensic_value: r.get(9)?,
        mitre_technique: r.get(10)?,
        confidence: r.get::<_, i64>(11).unwrap_or(0).clamp(0, 100) as u8,
        is_suspicious: r.get::<_, i64>(12).unwrap_or(0) != 0,
        raw_data: r.get(13)?,
        created_at,
        examiner_approved: r.get::<_, i64>(15).unwrap_or(0) != 0,
        examiner_notes: r.get(16)?,
        examiner_tags: r.get(17)?,
    })
}

fn insert_one(
    tx: &Transaction,
    case_id: &str,
    plugin: &str,
    record: &ArtifactRecord,
) -> rusqlite::Result<i64> {
    let forensic_value = match record.forensic_value {
        ForensicValue::Critical => "Critical",
        ForensicValue::High => "High",
        ForensicValue::Medium => "Medium",
        ForensicValue::Low => "Low",
        ForensicValue::Informational => "Info",
    };
    let raw = record.raw_data.as_ref().map(|v| v.to_string());
    tx.execute(
        "INSERT INTO artifacts (\
            case_id, plugin_name, category, subcategory, title, detail, source_path, \
            timestamp, forensic_value, mitre_technique, confidence, is_suspicious, \
            raw_data, created_at, examiner_approved \
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,0)",
        params![
            case_id,
            plugin,
            record.category.as_str(),
            record.subcategory,
            record.title,
            record.detail,
            record.source_path,
            record.timestamp,
            forensic_value,
            record.mitre_technique,
            record.confidence as i64,
            record.is_suspicious as i64,
            raw,
            Utc::now().timestamp(),
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

// Ensures ArtifactCategory is still in scope even when the set of
// plugins using all variants shrinks — keeps the import graph honest.
#[allow(dead_code)]
fn _ensure_category_used(_c: ArtifactCategory) {}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(title: &str) -> ArtifactRecord {
        ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: "test".into(),
            timestamp: Some(1_700_000_000),
            title: title.into(),
            detail: "detail".into(),
            source_path: "/x".into(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".into()),
            is_suspicious: false,
            raw_data: None,
            confidence: 80,
        }
    }

    #[test]
    fn open_create_round_trip() {
        let tmp = tempfile::tempdir().expect("t");
        let mut db = ArtifactDatabase::open_or_create(tmp.path(), "case-1").expect("o");
        let id = db.insert("Phantom", &sample("Hostname")).expect("i");
        assert!(id > 0);
        assert_eq!(db.count().expect("c"), 1);
    }

    #[test]
    fn batch_insert_round_trip() {
        let tmp = tempfile::tempdir().expect("t");
        let mut db = ArtifactDatabase::open_or_create(tmp.path(), "case-2").expect("o");
        let records: Vec<ArtifactRecord> = (0..100).map(|i| sample(&format!("evt-{i}"))).collect();
        let ids = db.insert_batch("Phantom", &records).expect("b");
        assert_eq!(ids.len(), 100);
        assert_eq!(db.count().expect("c"), 100);
    }

    #[test]
    fn query_by_plugin_returns_rows() {
        let tmp = tempfile::tempdir().expect("t");
        let mut db = ArtifactDatabase::open_or_create(tmp.path(), "case-3").expect("o");
        db.insert("A", &sample("a1")).expect("a");
        db.insert("B", &sample("b1")).expect("b");
        let a = db.query_by_plugin("A").expect("q");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].title, "a1");
    }

    #[test]
    fn query_by_category_filters() {
        let tmp = tempfile::tempdir().expect("t");
        let mut db = ArtifactDatabase::open_or_create(tmp.path(), "case-4").expect("o");
        db.insert("A", &sample("a1")).expect("a");
        let rs = db.query_by_category("System Activity").expect("q");
        assert_eq!(rs.len(), 1);
    }

    #[test]
    fn query_by_title_contains_supports_partial_match() {
        let tmp = tempfile::tempdir().expect("t");
        let mut db = ArtifactDatabase::open_or_create(tmp.path(), "case-5").expect("o");
        db.insert("X", &sample("User Account jean")).expect("a");
        db.insert("X", &sample("unrelated")).expect("b");
        let r = db.query_by_title_contains("jean").expect("q");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn count_by_plugin_aggregates() {
        let tmp = tempfile::tempdir().expect("t");
        let mut db = ArtifactDatabase::open_or_create(tmp.path(), "case-6").expect("o");
        db.insert_batch("A", &vec![sample("x"); 3]).expect("a");
        db.insert_batch("B", &vec![sample("y"); 2]).expect("b");
        let by = db.count_by_plugin().expect("c");
        assert_eq!(by.get("A").copied(), Some(3));
        assert_eq!(by.get("B").copied(), Some(2));
    }

    #[test]
    fn reopen_preserves_data() {
        let tmp = tempfile::tempdir().expect("t");
        {
            let mut db = ArtifactDatabase::open_or_create(tmp.path(), "persist").expect("o");
            db.insert("P", &sample("row1")).expect("i");
        }
        let db = ArtifactDatabase::open_or_create(tmp.path(), "persist").expect("reopen");
        assert_eq!(db.count().expect("c"), 1);
    }
}
