//! Artifact notes — examiner-authored freetext annotations on any artifact.
//!
//! Notes are stored in the case SQLite database and included in reports
//! when present. Every note creation/edit is timestamped and attributed
//! to the examiner who wrote it.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactNote {
    pub id: String,
    pub artifact_id: String,
    pub note_text: String,
    pub created_at: String,
    pub updated_at: String,
    pub examiner_name: String,
}

#[derive(Debug, thiserror::Error)]
pub enum NotesError {
    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),
}

/// Manages artifact notes in a SQLite database.
pub struct NotesStore {
    conn: Connection,
}

impl NotesStore {
    /// Open or create the notes table in an existing case database.
    pub fn open(conn: Connection) -> Result<Self, NotesError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS artifact_notes (
                id TEXT PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                note_text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                examiner_name TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_notes_artifact ON artifact_notes(artifact_id);",
        )?;
        Ok(Self { conn })
    }

    /// Open an in-memory store (for testing).
    pub fn open_memory() -> Result<Self, NotesError> {
        let conn = Connection::open_in_memory()?;
        Self::open(conn)
    }

    /// Add a new note to an artifact.
    pub fn add_note(
        &self,
        artifact_id: &str,
        note_text: &str,
        examiner_name: &str,
    ) -> Result<ArtifactNote, NotesError> {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let id = uuid::Uuid::new_v4().to_string();
        self.conn.execute(
            "INSERT INTO artifact_notes (id, artifact_id, note_text, created_at, updated_at, examiner_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, artifact_id, note_text, now, now, examiner_name],
        )?;
        Ok(ArtifactNote {
            id,
            artifact_id: artifact_id.to_string(),
            note_text: note_text.to_string(),
            created_at: now.clone(),
            updated_at: now,
            examiner_name: examiner_name.to_string(),
        })
    }

    /// Update an existing note's text.
    pub fn update_note(&self, note_id: &str, new_text: &str) -> Result<(), NotesError> {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.conn.execute(
            "UPDATE artifact_notes SET note_text = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_text, now, note_id],
        )?;
        Ok(())
    }

    /// Delete a note by ID.
    pub fn delete_note(&self, note_id: &str) -> Result<(), NotesError> {
        self.conn.execute(
            "DELETE FROM artifact_notes WHERE id = ?1",
            params![note_id],
        )?;
        Ok(())
    }

    /// Get all notes for a specific artifact.
    pub fn notes_for_artifact(&self, artifact_id: &str) -> Result<Vec<ArtifactNote>, NotesError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, artifact_id, note_text, created_at, updated_at, examiner_name
             FROM artifact_notes WHERE artifact_id = ?1 ORDER BY created_at",
        )?;
        let rows = stmt.query_map(params![artifact_id], |row| {
            Ok(ArtifactNote {
                id: row.get(0)?,
                artifact_id: row.get(1)?,
                note_text: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                examiner_name: row.get(5)?,
            })
        })?;
        Ok(rows.flatten().collect())
    }

    /// Get all notes in the database (for report generation).
    pub fn all_notes(&self) -> Result<Vec<ArtifactNote>, NotesError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, artifact_id, note_text, created_at, updated_at, examiner_name
             FROM artifact_notes ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ArtifactNote {
                id: row.get(0)?,
                artifact_id: row.get(1)?,
                note_text: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                examiner_name: row.get(5)?,
            })
        })?;
        Ok(rows.flatten().collect())
    }

    /// Count total notes.
    pub fn count(&self) -> Result<usize, NotesError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM artifact_notes", [], |row| row.get(0))?;
        Ok(n as usize)
    }

    /// Format all notes for a given artifact as a report block.
    pub fn format_for_report(notes: &[ArtifactNote]) -> String {
        if notes.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for note in notes {
            out.push_str(&format!(
                "[{}] {} — {}:\n{}\n\n",
                note.created_at, note.examiner_name, note.artifact_id, note.note_text
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_retrieve_note() {
        let store = NotesStore::open_memory().unwrap();
        let note = store
            .add_note("artifact-001", "Suspicious file — needs review", "SA Randolph")
            .unwrap();
        assert_eq!(note.artifact_id, "artifact-001");
        assert_eq!(note.examiner_name, "SA Randolph");

        let notes = store.notes_for_artifact("artifact-001").unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note_text, "Suspicious file — needs review");
    }

    #[test]
    fn update_note_changes_text_and_timestamp() {
        let store = NotesStore::open_memory().unwrap();
        let note = store
            .add_note("artifact-002", "Initial note", "SA Smith")
            .unwrap();
        store
            .update_note(&note.id, "Updated note text")
            .unwrap();

        let notes = store.notes_for_artifact("artifact-002").unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note_text, "Updated note text");
    }

    #[test]
    fn delete_note_removes_entry() {
        let store = NotesStore::open_memory().unwrap();
        let note = store
            .add_note("artifact-003", "To be deleted", "SA Jones")
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);

        store.delete_note(&note.id).unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.notes_for_artifact("artifact-003").unwrap().is_empty());
    }

    #[test]
    fn multiple_notes_per_artifact() {
        let store = NotesStore::open_memory().unwrap();
        store.add_note("artifact-004", "First observation", "SA A").unwrap();
        store.add_note("artifact-004", "Second observation", "SA B").unwrap();
        store.add_note("artifact-005", "Different artifact", "SA A").unwrap();

        let notes_4 = store.notes_for_artifact("artifact-004").unwrap();
        assert_eq!(notes_4.len(), 2);

        let all = store.all_notes().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn format_for_report_produces_readable_output() {
        let notes = vec![ArtifactNote {
            id: "n1".into(),
            artifact_id: "art-001".into(),
            note_text: "Evidence of data exfiltration".into(),
            created_at: "2026-04-12T10:00:00Z".into(),
            updated_at: "2026-04-12T10:00:00Z".into(),
            examiner_name: "SA Randolph".into(),
        }];
        let block = NotesStore::format_for_report(&notes);
        assert!(block.contains("SA Randolph"));
        assert!(block.contains("Evidence of data exfiltration"));
        assert!(block.contains("art-001"));
    }

    #[test]
    fn serializes_to_json() {
        let note = ArtifactNote {
            id: "n1".into(),
            artifact_id: "art-001".into(),
            note_text: "Test".into(),
            created_at: "2026-04-12T10:00:00Z".into(),
            updated_at: "2026-04-12T10:00:00Z".into(),
            examiner_name: "SA Test".into(),
        };
        let json = serde_json::to_string(&note).unwrap();
        let rt: ArtifactNote = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.artifact_id, "art-001");
    }
}
