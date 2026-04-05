use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use uuid::Uuid;

/// Represents a single AI interaction audit log entry per AI_AUDIT_TRAIL.md.
/// Written BEFORE the inference call; updated AFTER completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiInteractionLog {
    pub entry_id: String,
    pub case_id: String,
    pub examiner_id: String,
    pub timestamp_utc: String,
    pub operation_type: String,
    pub tier: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_char_count: Option<i64>,
    pub result_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_documents: Option<Vec<String>>,
    pub kb_available: bool,
    pub elapsed_ms: i64,
    pub fallback_used: bool,
    pub examiner_action: String,
}

impl AiInteractionLog {
    /// Create a new pre-inference log entry with default result fields.
    pub fn new(
        case_id: &str,
        examiner_id: &str,
        operation_type: &str,
        tier: i32,
        query_text: Option<String>,
        input_char_count: Option<i64>,
    ) -> Self {
        Self {
            entry_id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            examiner_id: examiner_id.to_string(),
            timestamp_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            operation_type: operation_type.to_string(),
            tier,
            query_text,
            input_char_count,
            result_count: 0,
            source_documents: None,
            kb_available: true,
            elapsed_ms: 0,
            fallback_used: false,
            examiner_action: "no_action".to_string(),
        }
    }

    /// Write the log entry to BOTH the JSONL file and the case SQLite database.
    /// Called BEFORE the inference call as required by AI_AUDIT_TRAIL.md Section 7.1.
    pub fn write_entry(&self) -> Result<(), String> {
        // 1. Append to the JSONL file
        self.append_to_jsonl()?;

        // 2. Write to the case SQLite database
        self.insert_into_sqlite()?;

        Ok(())
    }

    /// Update result fields AFTER inference completes.
    pub fn update_result(
        &mut self,
        result_count: i64,
        elapsed_ms: i64,
        kb_available: bool,
        fallback_used: bool,
        source_documents: Option<Vec<String>>,
    ) -> Result<(), String> {
        self.result_count = result_count;
        self.elapsed_ms = elapsed_ms;
        self.kb_available = kb_available;
        self.fallback_used = fallback_used;
        self.source_documents = source_documents;

        // Re-append updated entry to JSONL (append-only — no in-place edits)
        self.append_to_jsonl()?;

        // Update the SQLite row
        self.update_sqlite_result()?;

        Ok(())
    }

    /// Record what the examiner did with the AI result.
    pub fn update_examiner_action(&mut self, action: &str) -> Result<(), String> {
        self.examiner_action = action.to_string();

        // Append updated entry to JSONL
        self.append_to_jsonl()?;

        // Update SQLite
        self.update_sqlite_examiner_action()?;

        Ok(())
    }

    // ── Private helpers ──────────────────────────────────────────────

    fn jsonl_path() -> PathBuf {
        PathBuf::from(r"D:\Strata\logs\strata_ai_audit.jsonl")
    }

    fn append_to_jsonl(&self) -> Result<(), String> {
        let path = Self::jsonl_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create log directory: {}", e))?;
        }

        let line = serde_json::to_string(self)
            .map_err(|e| format!("Failed to serialize audit entry: {}", e))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("Failed to open JSONL audit file: {}", e))?;

        writeln!(file, "{}", line)
            .map_err(|e| format!("Failed to write JSONL audit entry: {}", e))?;

        Ok(())
    }

    fn case_db_path(&self) -> PathBuf {
        if self.case_id == "NO_CASE" {
            // Fallback: write to a shared audit-only database
            PathBuf::from(r"D:\Strata\apps\shield\cases\_no_case_audit.sqlite")
        } else {
            PathBuf::from(format!(
                r"D:\Strata\apps\shield\cases\{}.sqlite",
                self.case_id
            ))
        }
    }

    fn ensure_table(conn: &rusqlite::Connection) -> Result<(), String> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ai_interaction_log (
                entry_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                examiner_id TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL CHECK(timestamp_utc != ''),
                operation_type TEXT NOT NULL CHECK(operation_type IN ('kb_search', 'summarize', 'health_check')),
                tier INTEGER NOT NULL,
                query_text TEXT,
                input_char_count INTEGER,
                result_count INTEGER NOT NULL DEFAULT 0,
                source_documents TEXT,
                kb_available INTEGER NOT NULL DEFAULT 1,
                elapsed_ms INTEGER NOT NULL DEFAULT 0,
                fallback_used INTEGER NOT NULL DEFAULT 0,
                examiner_action TEXT NOT NULL DEFAULT 'no_action'
            );",
        )
        .map_err(|e| format!("Failed to ensure ai_interaction_log table: {}", e))?;
        Ok(())
    }

    fn insert_into_sqlite(&self) -> Result<(), String> {
        let db_path = self.case_db_path();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create cases directory: {}", e))?;
        }

        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| format!("Failed to open case DB: {}", e))?;

        Self::ensure_table(&conn)?;

        let source_docs_json = self
            .source_documents
            .as_ref()
            .map(|docs| serde_json::to_string(docs).unwrap_or_else(|_| "[]".to_string()));

        conn.execute(
            "INSERT INTO ai_interaction_log (
                entry_id, case_id, examiner_id, timestamp_utc,
                operation_type, tier, query_text, input_char_count,
                result_count, source_documents, kb_available,
                elapsed_ms, fallback_used, examiner_action
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            rusqlite::params![
                self.entry_id,
                self.case_id,
                self.examiner_id,
                self.timestamp_utc,
                self.operation_type,
                self.tier,
                self.query_text,
                self.input_char_count,
                self.result_count,
                source_docs_json,
                self.kb_available as i32,
                self.elapsed_ms,
                self.fallback_used as i32,
                self.examiner_action,
            ],
        )
        .map_err(|e| format!("Failed to insert audit entry: {}", e))?;

        Ok(())
    }

    fn update_sqlite_result(&self) -> Result<(), String> {
        let db_path = self.case_db_path();
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| format!("Failed to open case DB for update: {}", e))?;

        let source_docs_json = self
            .source_documents
            .as_ref()
            .map(|docs| serde_json::to_string(docs).unwrap_or_else(|_| "[]".to_string()));

        conn.execute(
            "UPDATE ai_interaction_log SET
                result_count = ?1,
                elapsed_ms = ?2,
                kb_available = ?3,
                fallback_used = ?4,
                source_documents = ?5
            WHERE entry_id = ?6",
            rusqlite::params![
                self.result_count,
                self.elapsed_ms,
                self.kb_available as i32,
                self.fallback_used as i32,
                source_docs_json,
                self.entry_id,
            ],
        )
        .map_err(|e| format!("Failed to update audit result: {}", e))?;

        Ok(())
    }

    fn update_sqlite_examiner_action(&self) -> Result<(), String> {
        let db_path = self.case_db_path();
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| format!("Failed to open case DB for action update: {}", e))?;

        conn.execute(
            "UPDATE ai_interaction_log SET examiner_action = ?1 WHERE entry_id = ?2",
            rusqlite::params![self.examiner_action, self.entry_id],
        )
        .map_err(|e| format!("Failed to update examiner action: {}", e))?;

        Ok(())
    }
}
