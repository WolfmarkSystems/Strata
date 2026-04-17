use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub mod correlation;
pub mod database;
pub mod query_ui;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEntry {
    pub id: i64,
    pub timestamp: Option<i64>,
    pub artifact_type: String,
    pub description: String,
    pub source_path: String,
    pub json_data: serde_json::Value,
    pub created_utc: String,
}

impl From<strata_fs::timeline::TimelineEntry> for TimelineEntry {
    fn from(entry: strata_fs::timeline::TimelineEntry) -> Self {
        TimelineEntry {
            id: 0,
            timestamp: entry.timestamp,
            artifact_type: entry.artifact_type,
            description: entry.description,
            source_path: entry.source_path,
            json_data: entry.json_data,
            created_utc: entry.created_utc,
        }
    }
}

impl TimelineEntry {
    pub fn new(
        timestamp: Option<i64>,
        artifact_type: String,
        description: String,
        source_path: String,
        json_data: serde_json::Value,
    ) -> Self {
        Self {
            id: 0,
            timestamp,
            artifact_type,
            description,
            source_path,
            json_data,
            created_utc: chrono::Utc::now().to_rfc3339(),
        }
    }
}

pub struct TimelineManager {
    conn: Connection,
}

impl TimelineManager {
    pub fn new(db_path: &Path) -> Result<Self, String> {
        let conn =
            Connection::open(db_path).map_err(|e| format!("Failed to open timeline DB: {}", e))?;

        let _: Result<String, _> = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0));
        let _: Result<i32, _> = conn.query_row("PRAGMA synchronous=NORMAL", [], |row| row.get(0));
        let _: Result<i32, _> = conn.query_row("PRAGMA cache_size=-64000", [], |row| row.get(0));
        let _: Result<i32, _> = conn.query_row("PRAGMA temp_store=MEMORY", [], |row| row.get(0));

        conn.execute(
            "CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY,
                timestamp INTEGER,
                artifact_type TEXT NOT NULL,
                description TEXT,
                source_path TEXT,
                json_data TEXT,
                created_utc TEXT DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )
        .map_err(|e| format!("Failed to create timeline table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline(timestamp)",
            [],
        )
        .ok();

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timeline_type ON timeline(artifact_type)",
            [],
        )
        .ok();

        Ok(Self { conn })
    }

    pub fn get_initial_entries(&self, limit: usize) -> Result<Vec<TimelineEntry>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, artifact_type, description, source_path, json_data, created_utc 
             FROM timeline ORDER BY id DESC LIMIT ?1"
        ).map_err(|e| e.to_string())?;

        let entries_iter = stmt
            .query_map([limit], |row| {
                let json_str: String = row.get(5).unwrap_or_default();
                let json_data: serde_json::Value =
                    serde_json::from_str(&json_str).unwrap_or(serde_json::json!({}));

                Ok(TimelineEntry {
                    id: row.get(0).unwrap_or(0),
                    timestamp: row.get(1).ok(),
                    artifact_type: row.get(2).unwrap_or_default(),
                    description: row.get(3).unwrap_or_default(),
                    source_path: row.get(4).unwrap_or_default(),
                    json_data,
                    created_utc: row.get(6).unwrap_or_default(),
                })
            })
            .map_err(|e| e.to_string())?;

        let mut entries = Vec::new();
        for e in entries_iter.flatten() {
            entries.push(e);
        }
        Ok(entries)
    }

    pub fn insert_entry(&mut self, entry: &TimelineEntry) -> Result<i64, String> {
        self.conn.execute(
            "INSERT INTO timeline (timestamp, artifact_type, description, source_path, json_data) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                entry.timestamp,
                entry.artifact_type,
                entry.description,
                entry.source_path,
                entry.json_data.to_string(),
            ],
        ).map_err(|e| e.to_string())?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn insert_entries_batch(&mut self, entries: &[TimelineEntry]) -> Result<usize, String> {
        const BATCH_SIZE: usize = 5000;

        self.conn
            .execute("BEGIN TRANSACTION", [])
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        let mut stmt = self.conn.prepare(
            "INSERT INTO timeline (timestamp, artifact_type, description, source_path, json_data) VALUES (?1, ?2, ?3, ?4, ?5)"
        ).map_err(|e| format!("Failed to prepare statement: {}", e))?;

        let mut total_inserted = 0;
        let mut batch_count = 0;

        for entry in entries {
            let json_str = entry.json_data.to_string();
            stmt.execute(params![
                entry.timestamp,
                entry.artifact_type,
                entry.description,
                entry.source_path,
                json_str,
            ])
            .map_err(|e| {
                let _ = self.conn.execute("ROLLBACK", []);
                format!("Failed to insert timeline entry: {}", e)
            })?;

            total_inserted += 1;
            batch_count += 1;

            if batch_count >= BATCH_SIZE {
                self.conn
                    .execute("COMMIT", [])
                    .map_err(|e| format!("Failed to commit batch: {}", e))?;
                self.conn
                    .execute("BEGIN TRANSACTION", [])
                    .map_err(|e| format!("Failed to begin next transaction: {}", e))?;
                batch_count = 0;
            }
        }

        self.conn
            .execute("COMMIT", [])
            .map_err(|e| format!("Failed to commit final batch: {}", e))?;

        Ok(total_inserted)
    }

    pub fn get_count(&self) -> Result<usize, String> {
        let count: usize = self
            .conn
            .query_row("SELECT COUNT(*) FROM timeline", [], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        Ok(count)
    }
}
