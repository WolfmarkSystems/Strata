//! Examiner artifact notes database (WF-2).
//!
//! SQLite-backed, separate from the artifact store so notes never
//! modify forensic data. Indexed by artifact_id + is_case_critical.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NotesError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub id: i64,
    pub artifact_id: String,
    pub artifact_type: String,
    pub examiner: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub note_text: String,
    pub is_case_critical: bool,
    pub tags: Vec<String>,
}

pub struct NotesDatabase {
    conn: Connection,
}

impl NotesDatabase {
    pub fn open(path: &Path) -> Result<Self, NotesError> {
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
            "CREATE TABLE IF NOT EXISTS notes ( \
                 id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 artifact_id TEXT NOT NULL, \
                 artifact_type TEXT NOT NULL, \
                 examiner TEXT NOT NULL, \
                 created_at INTEGER NOT NULL, \
                 updated_at INTEGER NOT NULL, \
                 note_text TEXT NOT NULL, \
                 is_case_critical INTEGER DEFAULT 0, \
                 tags TEXT \
             ); \
             CREATE INDEX IF NOT EXISTS idx_notes_artifact ON notes(artifact_id); \
             CREATE INDEX IF NOT EXISTS idx_notes_critical ON notes(is_case_critical);",
        )?;
        Ok(Self { conn })
    }

    pub fn add_note(
        &mut self,
        artifact_id: &str,
        artifact_type: &str,
        examiner: &str,
        text: &str,
    ) -> Result<i64, NotesError> {
        let now = Utc::now().timestamp_micros();
        self.conn.execute(
            "INSERT INTO notes (artifact_id, artifact_type, examiner, created_at, updated_at, \
                                note_text, is_case_critical, tags) \
             VALUES (?1, ?2, ?3, ?4, ?4, ?5, 0, '')",
            params![artifact_id, artifact_type, examiner, now, text],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_notes(&self, artifact_id: &str) -> Result<Vec<Note>, NotesError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, artifact_id, artifact_type, examiner, created_at, updated_at, \
                    note_text, is_case_critical, tags \
             FROM notes WHERE artifact_id = ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([artifact_id], map_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn set_case_critical(
        &mut self,
        artifact_id: &str,
        critical: bool,
    ) -> Result<(), NotesError> {
        let val = if critical { 1 } else { 0 };
        let now = Utc::now().timestamp_micros();
        self.conn.execute(
            "UPDATE notes SET is_case_critical = ?1, updated_at = ?2 WHERE artifact_id = ?3",
            params![val, now, artifact_id],
        )?;
        Ok(())
    }

    pub fn get_case_critical(&self) -> Result<Vec<Note>, NotesError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, artifact_id, artifact_type, examiner, created_at, updated_at, \
                    note_text, is_case_critical, tags \
             FROM notes WHERE is_case_critical = 1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], map_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn search_notes(&self, query: &str) -> Result<Vec<Note>, NotesError> {
        let pattern = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT id, artifact_id, artifact_type, examiner, created_at, updated_at, \
                    note_text, is_case_critical, tags \
             FROM notes WHERE note_text LIKE ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([pattern], map_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn add_tag(&mut self, artifact_id: &str, tag: &str) -> Result<(), NotesError> {
        let current: String = self
            .conn
            .query_row(
                "SELECT tags FROM notes WHERE artifact_id = ?1 LIMIT 1",
                [artifact_id],
                |row| row.get(0),
            )
            .unwrap_or_default();
        let mut tags: Vec<String> = current
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !tags.iter().any(|t| t == tag) {
            tags.push(tag.to_string());
        }
        let joined = tags.join(",");
        let now = Utc::now().timestamp_micros();
        self.conn.execute(
            "UPDATE notes SET tags = ?1, updated_at = ?2 WHERE artifact_id = ?3",
            params![joined, now, artifact_id],
        )?;
        Ok(())
    }

    pub fn get_by_tag(&self, tag: &str) -> Result<Vec<Note>, NotesError> {
        let pattern = format!("%{}%", tag);
        let mut stmt = self.conn.prepare(
            "SELECT id, artifact_id, artifact_type, examiner, created_at, updated_at, \
                    note_text, is_case_critical, tags \
             FROM notes WHERE tags LIKE ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([pattern], map_row)?;
        let mut out = Vec::new();
        for r in rows {
            let note = r?;
            if note.tags.iter().any(|t| t == tag) {
                out.push(note);
            }
        }
        Ok(out)
    }
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Note> {
    let created_us: i64 = row.get(4)?;
    let updated_us: i64 = row.get(5)?;
    let tags_raw: Option<String> = row.get(8)?;
    let tags = tags_raw
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Ok(Note {
        id: row.get(0)?,
        artifact_id: row.get(1)?,
        artifact_type: row.get(2)?,
        examiner: row.get(3)?,
        created_at: DateTime::<Utc>::from_timestamp_micros(created_us).unwrap_or_default(),
        updated_at: DateTime::<Utc>::from_timestamp_micros(updated_us).unwrap_or_default(),
        note_text: row.get(6)?,
        is_case_critical: row.get::<_, i64>(7)? != 0,
        tags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_tmp() -> (tempfile::TempDir, NotesDatabase) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("examiner_notes.db");
        let db = NotesDatabase::open(&path).expect("open");
        (dir, db)
    }

    #[test]
    fn open_creates_schema_and_add_note_returns_id() {
        let (_dir, mut db) = open_tmp();
        let id = db
            .add_note(
                "art-1",
                "Prefetch",
                "examiner.doe",
                "notepad was opened at 12:00",
            )
            .expect("add");
        assert!(id > 0);
    }

    #[test]
    fn get_notes_returns_entries_for_artifact() {
        let (_dir, mut db) = open_tmp();
        db.add_note("art-2", "MRU", "examiner", "first").expect("1");
        db.add_note("art-2", "MRU", "examiner", "second")
            .expect("2");
        db.add_note("art-3", "MRU", "examiner", "other").expect("3");
        let notes = db.get_notes("art-2").expect("get");
        assert_eq!(notes.len(), 2);
    }

    #[test]
    fn case_critical_toggle_reflected_in_get_case_critical() {
        let (_dir, mut db) = open_tmp();
        db.add_note("art-9", "ShimCache", "examiner", "key evidence")
            .expect("add");
        db.set_case_critical("art-9", true).expect("set");
        let critical = db.get_case_critical().expect("get");
        assert_eq!(critical.len(), 1);
        assert!(critical[0].is_case_critical);
    }

    #[test]
    fn search_notes_matches_substring() {
        let (_dir, mut db) = open_tmp();
        db.add_note("a", "T", "examiner", "contains password")
            .expect("1");
        db.add_note("b", "T", "examiner", "benign").expect("2");
        let matches = db.search_notes("password").expect("search");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn tag_add_and_lookup() {
        let (_dir, mut db) = open_tmp();
        db.add_note("a-tag", "T", "examiner", "tagged").expect("n");
        db.add_tag("a-tag", "Priority").expect("tag");
        db.add_tag("a-tag", "FinancialCrimes").expect("tag2");
        let tagged = db.get_by_tag("Priority").expect("get");
        assert_eq!(tagged.len(), 1);
        assert!(tagged[0].tags.contains(&"Priority".to_string()));
        assert!(tagged[0].tags.contains(&"FinancialCrimes".to_string()));
    }
}
