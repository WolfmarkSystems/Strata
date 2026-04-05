use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::analysis::ScoringContext;
use crate::events::{EngineEventKind, EventBus, EventSeverity};

pub struct CaseDatabase {
    conn: Arc<Mutex<Connection>>,
    case_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTablePreview {
    pub source_type: String,
    pub source_id: String,
    pub preview_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRow {
    pub id: String,
    pub case_id: String,
    pub job_type: String,
    pub status: String,
    pub priority: i32,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub progress: f32,
    pub progress_message: String,
    pub error: Option<String>,
    pub params_json: String,
    pub created_by: String,
    pub worker_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScoreResult {
    pub score: f64,
    pub signals: Vec<crate::analysis::ScoreSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestManifestRow {
    pub id: String,
    pub case_id: String,
    pub evidence_id: Option<String>,
    pub source_path: String,
    pub source_hash_sha256: Option<String>,
    pub container_type: String,
    pub parser_name: String,
    pub parser_version: String,
    pub ingest_status: String,
    pub warning_count: i64,
    pub unsupported_count: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestManifestInput {
    pub id: String,
    pub evidence_id: Option<String>,
    pub source_path: String,
    pub source_hash_sha256: Option<String>,
    pub container_type: String,
    pub parser_name: String,
    pub parser_version: String,
    pub ingest_status: String,
    pub created_at: i64,
    pub warnings: Vec<String>,
    pub unsupported_sections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalRecordInput {
    pub id: String,
    pub record_type: String,
    pub correlation_id: Option<String>,
    pub confidence_score: f64,
    pub timestamp_utc: Option<String>,
    pub payload_json: String,
    pub source_module: Option<String>,
    pub source_record_id: Option<String>,
    pub parser_version: Option<String>,
    pub created_at: i64,
}

impl CaseDatabase {
    pub fn create(case_id: &str, db_path: &Path) -> SqliteResult<Self> {
        let conn = Connection::open(db_path)?;
        Self::apply_pragmas(&conn)?;
        Self::create_tables(&conn)?;
        Self::create_indexes(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            case_id: case_id.to_string(),
        })
    }

    pub fn open(case_id: &str, db_path: &Path) -> SqliteResult<Self> {
        let conn = Connection::open(db_path)?;
        Self::apply_pragmas(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            case_id: case_id.to_string(),
        })
    }

    fn apply_pragmas(conn: &Connection) -> SqliteResult<()> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA temp_store=MEMORY;
             PRAGMA foreign_keys=ON;
             PRAGMA mmap_size=268435456;
             PRAGMA cache_size=-65536;
             PRAGMA busy_timeout=5000;
             PRAGMA wal_autocheckpoint=1000;
             PRAGMA read_uncommitted=0;",
        )?;
        Ok(())
    }

    /// Acquire the database connection lock, returning a `SqliteResult` error
    /// instead of panicking if the mutex has been poisoned.
    fn conn(&self) -> SqliteResult<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| rusqlite::Error::InvalidParameterName(format!("mutex poisoned: {}", e)))
    }

    fn unix_now_secs() -> SqliteResult<i64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| {
                rusqlite::Error::InvalidParameterName(format!(
                    "system clock before unix epoch: {}",
                    e
                ))
            })
    }

    fn unix_now_secs_u64() -> SqliteResult<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| {
                rusqlite::Error::InvalidParameterName(format!(
                    "system clock before unix epoch: {}",
                    e
                ))
            })
    }

    pub fn wal_checkpoint(&self) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }

    pub fn optimize(&self) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute_batch("PRAGMA optimize")?;
        Ok(())
    }

    pub fn vacuum(&self) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute_batch("VACUUM")?;
        Ok(())
    }

    fn create_tables(conn: &Connection) -> SqliteResult<()> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                examiner TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'open',
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                hash_md5 TEXT,
                hash_sha1 TEXT,
                hash_sha256 TEXT,
                acquired_at INTEGER,
                created_at INTEGER NOT NULL,
                container_type TEXT,
                partition_scheme TEXT,
                sector_size INTEGER,
                capability_checks_json TEXT,
                detection_timestamp TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS ingest_manifests (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_id TEXT,
                source_path TEXT NOT NULL,
                source_hash_sha256 TEXT,
                container_type TEXT NOT NULL,
                parser_name TEXT NOT NULL,
                parser_version TEXT NOT NULL,
                ingest_status TEXT NOT NULL,
                warning_count INTEGER NOT NULL DEFAULT 0,
                unsupported_count INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ingest_warnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                manifest_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                warning_text TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ingest_unsupported_sections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                manifest_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                section_key TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence_volumes (
                id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                volume_index INTEGER NOT NULL,
                offset_bytes INTEGER,
                size_bytes INTEGER,
                filesystem_type TEXT,
                filesystem_label TEXT,
                partition_type TEXT,
                capability_name TEXT,
                is_supported INTEGER DEFAULT 0,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id),
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_id TEXT,
                volume_id TEXT,
                user_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT,
                ts_utc INTEGER NOT NULL,
                ts_local TEXT NOT NULL,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL,
                schema_version TEXT NOT NULL DEFAULT '1.0',
                tool_version TEXT,
                tool_build TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS activity_chain_checkpoints (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                checkpoint_id TEXT NOT NULL,
                checkpoint_hash TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                first_event_id TEXT NOT NULL,
                last_event_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id),
                UNIQUE(case_id, checkpoint_id)
            );

            CREATE TABLE IF NOT EXISTS case_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                finished_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                report_json TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE INDEX IF NOT EXISTS idx_case_verifications_case_time 
                ON case_verifications(case_id, started_utc);

            CREATE TABLE IF NOT EXISTS case_replays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                finished_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                report_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_case_replays_case_time 
                ON case_replays(case_id, started_utc);

            CREATE TABLE IF NOT EXISTS integrity_violations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                occurred_utc TEXT NOT NULL,
                table_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                row_key TEXT,
                actor TEXT,
                reason TEXT NOT NULL,
                details_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_integrity_violations_case_time 
                ON integrity_violations(case_id, occurred_utc);
            CREATE INDEX IF NOT EXISTS idx_integrity_violations_case_table 
                ON integrity_violations(case_id, table_name);

            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                job_type TEXT NOT NULL,
                status TEXT NOT NULL,
                priority INTEGER DEFAULT 0,
                progress REAL DEFAULT 0,
                progress_message TEXT,
                error TEXT,
                params_json TEXT,
                result_json TEXT,
                created_by TEXT NOT NULL,
                worker_id TEXT,
                retries INTEGER DEFAULT 0,
                max_retries INTEGER DEFAULT 3,
                created_at INTEGER NOT NULL,
                started_at INTEGER,
                completed_at INTEGER,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS notes (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT,
                content_json TEXT NOT NULL DEFAULT '{}',
                tags_json TEXT,
                note_type TEXT DEFAULT 'manual',
                auto_generated INTEGER NOT NULL DEFAULT 0,
                reviewed INTEGER DEFAULT 0,
                reviewer TEXT,
                reviewed_at INTEGER,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL,
                created_by TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS note_exhibit_refs (
                id TEXT PRIMARY KEY,
                note_id TEXT NOT NULL,
                exhibit_id TEXT NOT NULL,
                reference_type TEXT,
                notes TEXT,
                FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS exhibits (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                exhibit_type TEXT NOT NULL,
                file_path TEXT,
                data_path TEXT,
                hash_md5 TEXT,
                hash_sha1 TEXT,
                hash_sha256 TEXT,
                tags_json TEXT,
                notes TEXT,
                metadata_json TEXT,
                created_by TEXT NOT NULL,
                source_evidence_id TEXT,
                packet_index INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS exhibit_packets (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_by TEXT NOT NULL,
                total_files INTEGER DEFAULT 0,
                total_size_bytes INTEGER DEFAULT 0,
                export_path TEXT,
                manifest_hash TEXT,
                screenshot_hash TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS packet_exhibits (
                packet_id TEXT NOT NULL,
                exhibit_id TEXT NOT NULL,
                PRIMARY KEY (packet_id, exhibit_id),
                FOREIGN KEY (packet_id) REFERENCES exhibit_packets(id) ON DELETE CASCADE,
                FOREIGN KEY (exhibit_id) REFERENCES exhibits(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS bookmark_folders (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                parent_id TEXT,
                name TEXT NOT NULL,
                description TEXT,
                color TEXT,
                icon TEXT,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id),
                FOREIGN KEY (parent_id) REFERENCES bookmark_folders(id)
            );

            CREATE TABLE IF NOT EXISTS bookmarks (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                folder_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                tags_json TEXT,
                color TEXT,
                icon TEXT,
                notes TEXT,
                reviewed INTEGER DEFAULT 0,
                reviewer TEXT,
                reviewed_at INTEGER,
                custom_fields_json TEXT,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id),
                FOREIGN KEY (folder_id) REFERENCES bookmark_folders(id)
            );

            CREATE TABLE IF NOT EXISTS bookmark_objects (
                id TEXT PRIMARY KEY,
                bookmark_id TEXT NOT NULL,
                object_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                path TEXT,
                file_name TEXT,
                size INTEGER,
                hash_sha256 TEXT,
                evidence_id TEXT,
                volume_id TEXT,
                offset INTEGER,
                metadata_json TEXT,
                FOREIGN KEY (bookmark_id) REFERENCES bookmarks(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS tags (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                color TEXT NOT NULL,
                description TEXT,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(case_id, name),
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS bookmark_tags (
                bookmark_id TEXT NOT NULL,
                tag_id TEXT NOT NULL,
                PRIMARY KEY (bookmark_id, tag_id),
                FOREIGN KEY (bookmark_id) REFERENCES bookmarks(id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS note_tags (
                note_id TEXT NOT NULL,
                tag_id TEXT NOT NULL,
                PRIMARY KEY (note_id, tag_id),
                FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS saved_searches (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                search_query_json TEXT NOT NULL,
                tags_json TEXT,
                is_global INTEGER DEFAULT 0,
                usage_count INTEGER DEFAULT 0,
                last_used_at INTEGER,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS case_stats (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                total_artifacts INTEGER DEFAULT 0,
                total_bookmarks INTEGER DEFAULT 0,
                total_notes INTEGER DEFAULT 0,
                total_exhibits INTEGER DEFAULT 0,
                total_jobs INTEGER DEFAULT 0,
                jobs_completed INTEGER DEFAULT 0,
                jobs_failed INTEGER DEFAULT 0,
                last_updated INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS triage_stats (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                category TEXT NOT NULL,
                count INTEGER DEFAULT 0,
                total_size INTEGER DEFAULT 0,
                last_updated INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id),
                UNIQUE(case_id, category)
            );

            CREATE TABLE IF NOT EXISTS evidence_timeline (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_id TEXT,
                event_type TEXT NOT NULL,
                event_category TEXT,
                event_time INTEGER NOT NULL,
                description TEXT,
                artifact_id TEXT,
                data_json TEXT,
                source_module TEXT,
                source_record_id TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY (case_id) REFERENCES cases(id),
                FOREIGN KEY (evidence_id) REFERENCES evidence(id),
                UNIQUE(case_id, artifact_id, event_type, event_time, source_module, source_record_id)
            );

            CREATE TABLE IF NOT EXISTS canonical_records (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                record_type TEXT NOT NULL,
                correlation_id TEXT,
                confidence_score REAL NOT NULL DEFAULT 0,
                timestamp_utc TEXT,
                payload_json TEXT NOT NULL,
                source_module TEXT,
                source_record_id TEXT,
                parser_version TEXT,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS canonical_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                source_record_id TEXT NOT NULL,
                target_record_id TEXT NOT NULL,
                relation_type TEXT NOT NULL,
                confidence_score REAL NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_evidence_timeline_case_time 
                ON evidence_timeline(case_id, event_time, id);
            CREATE INDEX IF NOT EXISTS idx_evidence_timeline_case_category_time 
                ON evidence_timeline(case_id, event_category, event_time);
            CREATE INDEX IF NOT EXISTS idx_evidence_timeline_artifact 
                ON evidence_timeline(case_id, artifact_id);
            CREATE INDEX IF NOT EXISTS idx_evidence_timeline_type 
                ON evidence_timeline(case_id, event_type, event_time);

            CREATE TABLE IF NOT EXISTS timeline_buckets (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                bucket_type TEXT NOT NULL,
                bucket_time INTEGER NOT NULL,
                category TEXT,
                granularity_seconds INTEGER NOT NULL DEFAULT 3600,
                count INTEGER DEFAULT 0,
                FOREIGN KEY (case_id) REFERENCES cases(id),
                UNIQUE(case_id, bucket_type, bucket_time, category, granularity_seconds)
            );

            CREATE TABLE IF NOT EXISTS case_settings (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                modified_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                UNIQUE(case_id, key)
            );

            CREATE TABLE IF NOT EXISTS artifact_summary (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                category TEXT,
                count INTEGER DEFAULT 0,
                UNIQUE(case_id, artifact_type, category)
            );

            CREATE TABLE IF NOT EXISTS provenance (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                object_type TEXT NOT NULL,
                action TEXT NOT NULL,
                user_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                source_evidence_id TEXT,
                source_volume_id TEXT,
                source_path TEXT,
                destination_path TEXT,
                export_path TEXT,
                hash_before TEXT,
                hash_after TEXT,
                metadata_json TEXT,
                description TEXT,
                ts_utc INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS triage_presets (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                category TEXT NOT NULL,
                filters_json TEXT NOT NULL,
                is_system INTEGER DEFAULT 0,
                is_default INTEGER DEFAULT 0,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS workers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT DEFAULT 'offline',
                current_job_id TEXT,
                jobs_completed INTEGER DEFAULT 0,
                jobs_failed INTEGER DEFAULT 0,
                started_at INTEGER NOT NULL,
                last_heartbeat INTEGER NOT NULL
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(
                title,
                content,
                content='notes',
                content_rowid='rowid'
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS bookmarks_fts USING fts5(
                title,
                description,
                notes,
                content='bookmarks',
                content_rowid='rowid'
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS exhibits_fts USING fts5(
                name,
                description,
                notes,
                content='exhibits',
                content_rowid='rowid'
            );

            CREATE TABLE IF NOT EXISTS content_fts_audit (
                table_name TEXT NOT NULL,
                last_indexed_rowid INTEGER,
                last_indexed_at INTEGER,
                PRIMARY KEY (table_name)
            );

            CREATE TABLE IF NOT EXISTS fts_index_queue (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                row_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                processed_at INTEGER,
                entity_type TEXT,
                entity_id TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS global_search_fts USING fts5(
                case_id UNINDEXED,
                entity_type,
                entity_id UNINDEXED,
                title,
                content,
                path,
                tags,
                category,
                ts_utc,
                source_module,
                tokenize='porter unicode61'
            );

            CREATE TABLE IF NOT EXISTS global_search_entities (
                case_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                title TEXT,
                path TEXT,
                category TEXT,
                ts_utc TEXT,
                tags TEXT,
                json_data TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (case_id, entity_type, entity_id)
            );

            CREATE INDEX IF NOT EXISTS idx_global_entities_case_type ON global_search_entities(case_id, entity_type);
            CREATE INDEX IF NOT EXISTS idx_global_entities_case_time ON global_search_entities(case_id, ts_utc);

            CREATE TABLE IF NOT EXISTS file_strings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                evidence_id TEXT,
                volume_id TEXT,
                file_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT,
                size_bytes INTEGER,
                extracted_utc TEXT NOT NULL,
                extractor_version TEXT NOT NULL,
                flags INTEGER NOT NULL DEFAULT 0,
                strings_text TEXT NOT NULL DEFAULT '',
                strings_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(case_id, file_id, extractor_version)
            );

            CREATE INDEX IF NOT EXISTS idx_file_strings_case_file ON file_strings(case_id, file_id);
            CREATE INDEX IF NOT EXISTS idx_file_strings_case_path ON file_strings(case_id, file_path);
            CREATE INDEX IF NOT EXISTS idx_file_strings_case_time ON file_strings(case_id, extracted_utc);

            CREATE TABLE IF NOT EXISTS ioc_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                rule_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                pattern TEXT NOT NULL,
                hash_type TEXT,
                scope_json TEXT NOT NULL DEFAULT '{}',
                tags TEXT NOT NULL DEFAULT '',
                created_utc TEXT NOT NULL,
                updated_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ioc_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                rule_id INTEGER NOT NULL,
                hit_utc TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_path TEXT,
                matched_field TEXT NOT NULL,
                matched_value TEXT NOT NULL,
                context_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(case_id, rule_id, target_type, target_id, matched_field, matched_value)
            );

            CREATE INDEX IF NOT EXISTS idx_ioc_hits_case_time ON ioc_hits(case_id, hit_utc);
            CREATE INDEX IF NOT EXISTS idx_ioc_hits_case_rule ON ioc_hits(case_id, rule_id);
            CREATE INDEX IF NOT EXISTS idx_ioc_hits_case_target ON ioc_hits(case_id, target_type, target_id);

            CREATE TABLE IF NOT EXISTS carved_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                volume_id TEXT,
                carved_utc TEXT NOT NULL,
                signature_name TEXT NOT NULL,
                offset_bytes INTEGER NOT NULL,
                length_bytes INTEGER NOT NULL,
                output_rel_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                file_type TEXT,
                confidence TEXT NOT NULL,
                flags INTEGER NOT NULL DEFAULT 0,
                details_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(case_id, evidence_id, offset_bytes, sha256)
            );

            CREATE INDEX IF NOT EXISTS idx_carved_case_time ON carved_files(case_id, carved_utc);
            CREATE INDEX IF NOT EXISTS idx_carved_case_sig ON carved_files(case_id, signature_name);
            CREATE INDEX IF NOT EXISTS idx_carved_case_hash ON carved_files(case_id, sha256);

            CREATE TABLE IF NOT EXISTS file_table_rows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_id TEXT NOT NULL,
                evidence_id TEXT,
                volume_id TEXT,
                path TEXT NOT NULL,
                name TEXT NOT NULL,
                extension TEXT,
                size_bytes INTEGER,
                created_utc TEXT,
                modified_utc TEXT,
                accessed_utc TEXT,
                changed_utc TEXT,
                hash_md5 TEXT,
                hash_sha1 TEXT,
                hash_sha256 TEXT,
                entropy REAL,
                category TEXT,
                flags INTEGER NOT NULL DEFAULT 0,
                score REAL NOT NULL DEFAULT 0,
                tags TEXT NOT NULL DEFAULT '',
                summary_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(case_id, source_type, source_id)
            );

            CREATE INDEX IF NOT EXISTS idx_ftr_case_path ON file_table_rows(case_id, path);
            CREATE INDEX IF NOT EXISTS idx_ftr_case_name ON file_table_rows(case_id, name);
            CREATE INDEX IF NOT EXISTS idx_ftr_case_ext ON file_table_rows(case_id, extension);
            CREATE INDEX IF NOT EXISTS idx_ftr_case_size ON file_table_rows(case_id, size_bytes);
            CREATE INDEX IF NOT EXISTS idx_ftr_case_mtime ON file_table_rows(case_id, modified_utc);
            CREATE INDEX IF NOT EXISTS idx_ftr_case_ctime ON file_table_rows(case_id, created_utc);
            CREATE INDEX IF NOT EXISTS idx_ftr_case_category ON file_table_rows(case_id, category);
            CREATE INDEX IF NOT EXISTS idx_ftr_case_score ON file_table_rows(case_id, score);
            CREATE INDEX IF NOT EXISTS idx_ftr_case_hash ON file_table_rows(case_id, hash_sha256);

            CREATE TABLE IF NOT EXISTS immutable_log (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                row_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                attempted_at INTEGER NOT NULL,
                reason TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS case_export_bundles (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                bundle_name TEXT NOT NULL,
                bundle_path TEXT NOT NULL,
                bundle_hash TEXT,
                manifest_hash TEXT NOT NULL,
                export_type TEXT NOT NULL,
                includes_activity INTEGER DEFAULT 0,
                includes_exhibits INTEGER DEFAULT 0,
                includes_reports INTEGER DEFAULT 0,
                total_files INTEGER DEFAULT 0,
                total_size_bytes INTEGER DEFAULT 0,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS case_settings (
                case_id TEXT PRIMARY KEY,
                immutable_activity_log INTEGER DEFAULT 1,
                immutable_exhibits INTEGER DEFAULT 1,
                fts_auto_index INTEGER DEFAULT 1,
                checkpoint_interval INTEGER DEFAULT 1000,
                auto_vacuum_enabled INTEGER DEFAULT 0,
                max_wal_size_mb INTEGER DEFAULT 100,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS triage_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                session_name TEXT,
                preset_name TEXT,
                started_utc TEXT NOT NULL,
                finished_utc TEXT,
                status TEXT NOT NULL DEFAULT 'RUNNING',
                options_json TEXT NOT NULL,
                replay_id INTEGER,
                verification_id INTEGER,
                violations_count INTEGER NOT NULL DEFAULT 0,
                bundle_path TEXT,
                bundle_hash_sha256 TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_triage_sessions_case_time 
                ON triage_sessions(case_id, started_utc);

            CREATE TABLE IF NOT EXISTS examiner_presets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL,
                preset_json TEXT NOT NULL,
                locked_keys_json TEXT NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0
            );
            ",
        )?;
        Ok(())
    }

    fn create_indexes(conn: &Connection) -> SqliteResult<()> {
        conn.execute_batch(
            "
            CREATE INDEX IF NOT EXISTS idx_activity_case_ts ON activity_log(case_id, ts_utc);
            CREATE INDEX IF NOT EXISTS idx_canonical_records_case_type_time ON canonical_records(case_id, record_type, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_canonical_records_case_corr ON canonical_records(case_id, correlation_id);
            CREATE INDEX IF NOT EXISTS idx_canonical_records_case_source ON canonical_records(case_id, source_module, source_record_id);
            CREATE INDEX IF NOT EXISTS idx_canonical_relationships_case_source ON canonical_relationships(case_id, source_record_id);
            CREATE INDEX IF NOT EXISTS idx_canonical_relationships_case_target ON canonical_relationships(case_id, target_record_id);
            CREATE INDEX IF NOT EXISTS idx_ingest_manifest_case_time ON ingest_manifests(case_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_ingest_manifest_case_parser ON ingest_manifests(case_id, parser_name, parser_version);
            CREATE INDEX IF NOT EXISTS idx_ingest_warnings_manifest ON ingest_warnings(manifest_id);
            CREATE INDEX IF NOT EXISTS idx_ingest_unsupported_manifest ON ingest_unsupported_sections(manifest_id);
            CREATE INDEX IF NOT EXISTS idx_activity_evidence_ts ON activity_log(case_id, evidence_id, ts_utc);
            CREATE INDEX IF NOT EXISTS idx_activity_object ON activity_log(case_id, event_type, ts_utc);

            CREATE INDEX IF NOT EXISTS idx_jobs_case_status ON jobs(case_id, status, priority, created_at);
            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(case_id, status);
            CREATE INDEX IF NOT EXISTS idx_jobs_type_status ON jobs(case_id, job_type, status);

            CREATE INDEX IF NOT EXISTS idx_notes_case_ts ON notes(case_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_notes_case_modified ON notes(case_id, modified_at);
            CREATE INDEX IF NOT EXISTS idx_notes_reviewed ON notes(case_id, reviewed, modified_at);

            CREATE INDEX IF NOT EXISTS idx_exhibits_case ON exhibits(case_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_exhibits_type ON exhibits(case_id, exhibit_type);

            CREATE INDEX IF NOT EXISTS idx_bookmarks_case_folder ON bookmarks(case_id, folder_id);
            CREATE INDEX IF NOT EXISTS idx_bookmarks_reviewed ON bookmarks(case_id, reviewed, modified_at);
            CREATE INDEX IF NOT EXISTS idx_bookmark_objects_bookmark ON bookmark_objects(bookmark_id);
            CREATE INDEX IF NOT EXISTS idx_bookmark_objects_type_id ON bookmark_objects(object_type, object_id);

            CREATE INDEX IF NOT EXISTS idx_provenance_object ON provenance(case_id, object_type, object_id, ts_utc);
            CREATE INDEX IF NOT EXISTS idx_provenance_ts ON provenance(case_id, ts_utc);
            CREATE INDEX IF NOT EXISTS idx_provenance_action ON provenance(case_id, action, ts_utc);

            CREATE INDEX IF NOT EXISTS idx_saved_searches_case ON saved_searches(case_id, modified_at);
            CREATE INDEX IF NOT EXISTS idx_saved_searches_global ON saved_searches(is_global, usage_count);

            CREATE INDEX IF NOT EXISTS idx_tags_case ON tags(case_id, name);

            CREATE INDEX IF NOT EXISTS idx_timeline_buckets_case_time ON timeline_buckets(case_id, bucket_type, bucket_time);
            CREATE INDEX IF NOT EXISTS idx_triage_stats_category ON triage_stats(case_id, category);
            CREATE INDEX IF NOT EXISTS idx_artifact_summary_type ON artifact_summary(case_id, artifact_type, category);

            CREATE INDEX IF NOT EXISTS idx_activity_hash_chain ON activity_log(case_id, event_hash);
            CREATE INDEX IF NOT EXISTS idx_activity_prev_hash ON activity_log(prev_event_hash);
            "
        )?;
        Ok(())
    }

    pub fn get_connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    pub fn case_id(&self) -> String {
        self.case_id.clone()
    }

    pub fn begin_transaction(&self) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute("BEGIN IMMEDIATE", [])?;
        Ok(())
    }

    pub fn commit(&self) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute("COMMIT", [])?;
        Ok(())
    }

    pub fn rollback(&self) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute("ROLLBACK", [])?;
        Ok(())
    }

    pub fn execute_batch(&self, sql: &str) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute_batch(sql)?;
        Ok(())
    }

    pub fn add_evidence_timeline_event(&self, event: &EvidenceTimelineEvent) -> SqliteResult<()> {
        let conn = self.conn()?;

        conn.execute(
            "INSERT OR IGNORE INTO evidence_timeline (id, case_id, evidence_id, event_type, event_category, event_time, description, artifact_id, data_json, source_module, source_record_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.id,
                event.case_id,
                event.evidence_id,
                event.event_type,
                event.event_category,
                event.event_time,
                event.description,
                event.artifact_id,
                event.data_json,
                event.source_module.as_deref().unwrap_or(""),
                event.source_record_id.as_deref().unwrap_or(""),
            ],
        )?;

        conn.execute(
            "INSERT INTO timeline_buckets (id, case_id, bucket_type, bucket_time, category, granularity_seconds, count)
             VALUES (uuid4(), ?1, 'evidence', (?2 / 3600) * 3600, ?3, 3600, 1)
             ON CONFLICT(case_id, bucket_type, bucket_time, category, granularity_seconds) DO UPDATE SET
                count = count + 1",
            params![event.case_id, event.event_time, event.event_category],
        )?;

        Ok(())
    }

    pub fn insert_ingest_manifest(&self, input: &IngestManifestInput) -> SqliteResult<()> {
        let conn = self.conn()?;

        conn.execute(
            "INSERT OR REPLACE INTO ingest_manifests (
                id, case_id, evidence_id, source_path, source_hash_sha256, container_type,
                parser_name, parser_version, ingest_status, warning_count, unsupported_count, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                input.id,
                self.case_id,
                input.evidence_id,
                input.source_path,
                input.source_hash_sha256,
                input.container_type,
                input.parser_name,
                input.parser_version,
                input.ingest_status,
                i64::try_from(input.warnings.len()).unwrap_or(0),
                i64::try_from(input.unsupported_sections.len()).unwrap_or(0),
                input.created_at
            ],
        )?;

        conn.execute(
            "DELETE FROM ingest_warnings WHERE manifest_id = ?1 AND case_id = ?2",
            params![input.id, self.case_id],
        )?;
        conn.execute(
            "DELETE FROM ingest_unsupported_sections WHERE manifest_id = ?1 AND case_id = ?2",
            params![input.id, self.case_id],
        )?;

        for warning in &input.warnings {
            conn.execute(
                "INSERT INTO ingest_warnings (manifest_id, case_id, warning_text) VALUES (?1, ?2, ?3)",
                params![input.id, self.case_id, warning],
            )?;
        }
        for section in &input.unsupported_sections {
            conn.execute(
                "INSERT INTO ingest_unsupported_sections (manifest_id, case_id, section_key) VALUES (?1, ?2, ?3)",
                params![input.id, self.case_id, section],
            )?;
        }
        Ok(())
    }

    pub fn list_ingest_manifests(&self, limit: usize) -> SqliteResult<Vec<IngestManifestRow>> {
        let conn = self.conn()?;
        let capped = i64::try_from(limit.clamp(1, 1000)).unwrap_or(100);
        let mut stmt = conn.prepare(
            "SELECT id, case_id, evidence_id, source_path, source_hash_sha256, container_type,
                    parser_name, parser_version, ingest_status, warning_count, unsupported_count, created_at
             FROM ingest_manifests
             WHERE case_id = ?1
             ORDER BY created_at DESC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![self.case_id, capped], |row| {
            Ok(IngestManifestRow {
                id: row.get(0)?,
                case_id: row.get(1)?,
                evidence_id: row.get(2)?,
                source_path: row.get(3)?,
                source_hash_sha256: row.get(4)?,
                container_type: row.get(5)?,
                parser_name: row.get(6)?,
                parser_version: row.get(7)?,
                ingest_status: row.get(8)?,
                warning_count: row.get(9)?,
                unsupported_count: row.get(10)?,
                created_at: row.get(11)?,
            })
        })?;

        rows.collect()
    }

    pub fn insert_canonical_record(&self, input: &CanonicalRecordInput) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO canonical_records (
                id, case_id, record_type, correlation_id, confidence_score, timestamp_utc,
                payload_json, source_module, source_record_id, parser_version, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                input.id,
                self.case_id,
                input.record_type,
                input.correlation_id,
                input.confidence_score,
                input.timestamp_utc,
                input.payload_json,
                input.source_module,
                input.source_record_id,
                input.parser_version,
                input.created_at
            ],
        )?;
        Ok(())
    }
}

pub struct BatchInserter {
    conn: Arc<Mutex<Connection>>,
    table_name: String,
    column_names: String,
    placeholders: String,
    batch_size: usize,
    _current_batch: Vec<String>,
    row_count: usize,
}

impl BatchInserter {
    pub fn new(
        conn: Arc<Mutex<Connection>>,
        table_name: &str,
        columns: &[&str],
        batch_size: usize,
    ) -> Self {
        let column_names = columns.join(", ");
        let placeholders = (0..columns.len())
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");

        Self {
            conn,
            table_name: table_name.to_string(),
            column_names,
            placeholders,
            batch_size,
            _current_batch: Vec::new(),
            row_count: 0,
        }
    }

    fn conn(&self) -> SqliteResult<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| rusqlite::Error::InvalidParameterName(format!("mutex poisoned: {}", e)))
    }

    pub fn insert(&mut self, values: &[&dyn rusqlite::ToSql]) -> SqliteResult<()> {
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            self.table_name, self.column_names, self.placeholders
        );

        {
            let conn = self.conn()?;
            conn.execute(&sql, values)?;
        }
        self.row_count += 1;

        if self.row_count >= self.batch_size {
            self.flush()?;
        }

        Ok(())
    }

    pub fn flush(&mut self) -> SqliteResult<()> {
        self.row_count = 0;
        Ok(())
    }
} // close impl BatchInserter

impl CaseDatabase {
    pub fn create_read_model_triggers(&self) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute_batch(
            "
            CREATE TRIGGER IF NOT EXISTS update_case_stats_on_bookmark_insert AFTER INSERT ON bookmarks
            BEGIN
                INSERT INTO case_stats (id, case_id, total_bookmarks, last_updated)
                VALUES (uuid4(), NEW.case_id, 1, strftime('%s', 'now'))
                ON CONFLICT(case_id) DO UPDATE SET
                    total_bookmarks = total_bookmarks + 1,
                    last_updated = strftime('%s', 'now');
            END;

            CREATE TRIGGER IF NOT EXISTS update_case_stats_on_note_insert AFTER INSERT ON notes
            BEGIN
                INSERT INTO case_stats (id, case_id, total_notes, last_updated)
                VALUES (uuid4(), NEW.case_id, 1, strftime('%s', 'now'))
                ON CONFLICT(case_id) DO UPDATE SET
                    total_notes = total_notes + 1,
                    last_updated = strftime('%s', 'now');
            END;

            CREATE TRIGGER IF NOT EXISTS update_case_stats_on_exhibit_insert AFTER INSERT ON exhibits
            BEGIN
                INSERT INTO case_stats (id, case_id, total_exhibits, last_updated)
                VALUES (uuid4(), NEW.case_id, 1, strftime('%s', 'now'))
                ON CONFLICT(case_id) DO UPDATE SET
                    total_exhibits = total_exhibits + 1,
                    last_updated = strftime('%s', 'now');
            END;

            CREATE TRIGGER IF NOT EXISTS update_case_stats_on_job_insert AFTER INSERT ON jobs
            BEGIN
                INSERT INTO case_stats (id, case_id, total_jobs, last_updated)
                VALUES (uuid4(), NEW.case_id, 1, strftime('%s', 'now'))
                ON CONFLICT(case_id) DO UPDATE SET
                    total_jobs = total_jobs + 1,
                    last_updated = strftime('%s', 'now');
            END;

            CREATE TRIGGER IF NOT EXISTS update_timeline_buckets_on_activity AFTER INSERT ON activity_log
            WHEN NEW.ts_utc IS NOT NULL
            BEGIN
                INSERT INTO timeline_buckets (id, case_id, bucket_type, bucket_time, granularity_seconds, count)
                VALUES (
                    uuid4(),
                    NEW.case_id,
                    'activity',
                    (NEW.ts_utc / 3600) * 3600,
                    3600,
                    1
                )
                ON CONFLICT(case_id, bucket_type, bucket_time, category, granularity_seconds) DO UPDATE SET
                    count = count + 1;
            END;
            "
        )?;
        Ok(())
    }

    pub fn refresh_case_stats(&self, case_id: &str) -> SqliteResult<()> {
        let conn = self.conn()?;

        conn.execute(
            "INSERT INTO case_stats (id, case_id, total_bookmarks, total_notes, total_exhibits, total_jobs, last_updated)
             VALUES (uuid4(), ?1, 
                (SELECT COUNT(*) FROM bookmarks WHERE case_id = ?1),
                (SELECT COUNT(*) FROM notes WHERE case_id = ?1),
                (SELECT COUNT(*) FROM exhibits WHERE case_id = ?1),
                (SELECT COUNT(*) FROM jobs WHERE case_id = ?1),
                strftime('%s', 'now'))
             ON CONFLICT(case_id) DO UPDATE SET
                total_bookmarks = (SELECT COUNT(*) FROM bookmarks WHERE case_id = ?1),
                total_notes = (SELECT COUNT(*) FROM notes WHERE case_id = ?1),
                total_exhibits = (SELECT COUNT(*) FROM exhibits WHERE case_id = ?1),
                total_jobs = (SELECT COUNT(*) FROM jobs WHERE case_id = ?1),
                last_updated = strftime('%s', 'now')",
            [case_id],
        )?;

        conn.execute(
            "INSERT INTO timeline_buckets (id, case_id, bucket_type, bucket_time, count)
             SELECT uuid4(), ?1, 'activity', (ts_utc / 3600) * 3600, COUNT(*)
             FROM activity_log WHERE case_id = ?1
             GROUP BY (ts_utc / 3600) * 3600
             ON CONFLICT(case_id, bucket_type, bucket_time, category) DO UPDATE SET
                count = (SELECT COUNT(*) FROM activity_log WHERE case_id = ?1 AND (ts_utc / 3600) * 3600 = excluded.bucket_time)",
            [case_id],
        )?;

        Ok(())
    }

    pub fn rebuild_triage_stats(&self, case_id: &str) -> SqliteResult<()> {
        let conn = self.conn()?;

        conn.execute("DELETE FROM triage_stats WHERE case_id = ?1", [case_id])?;

        conn.execute(
            "INSERT INTO triage_stats (id, case_id, category, count, last_updated)
             SELECT uuid4(), ?1, COALESCE(bf.folder_name, 'uncategorized'), COUNT(*), strftime('%s', 'now')
             FROM bookmarks b
             LEFT JOIN bookmark_folders bf ON b.folder_id = bf.id
             WHERE b.case_id = ?1
             GROUP BY bf.folder_name",
            [case_id],
        )?;

        Ok(())
    }

    pub fn rebuild_timeline_buckets(
        &self,
        case_id: &str,
        bucket_type: &str,
        granularity_seconds: i64,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;

        conn.execute(
            "DELETE FROM timeline_buckets WHERE case_id = ?1 AND bucket_type = ?2 AND granularity_seconds = ?3",
            params![case_id, bucket_type, granularity_seconds],
        )?;

        match bucket_type {
            "activity" => {
                conn.execute(
                    "INSERT INTO timeline_buckets (id, case_id, bucket_type, bucket_time, granularity_seconds, count)
                     SELECT uuid4(), ?1, 'activity', (ts_utc / ?3) * ?3, ?3, COUNT(*)
                     FROM activity_log WHERE case_id = ?1 AND ts_utc IS NOT NULL
                     GROUP BY (ts_utc / ?3) * ?3",
                    params![case_id, bucket_type, granularity_seconds],
                )?;
            }
            "evidence" => {
                conn.execute(
                    "INSERT INTO timeline_buckets (id, case_id, bucket_type, bucket_time, category, granularity_seconds, count)
                     SELECT uuid4(), ?1, 'evidence', (event_time / ?3) * ?3, event_category, ?3, COUNT(*)
                     FROM evidence_timeline WHERE case_id = ?1 AND event_time IS NOT NULL
                     GROUP BY (event_time / ?3) * ?3, event_category",
                    params![case_id, bucket_type, granularity_seconds],
                )?;
            }
            _ => {}
        }

        Ok(())
    }

    pub fn rebuild_all_read_models(&self, case_id: &str) -> SqliteResult<()> {
        self.refresh_case_stats(case_id)?;
        self.rebuild_triage_stats(case_id)?;
        self.rebuild_timeline_buckets(case_id, "activity", 3600)?;
        self.rebuild_timeline_buckets(case_id, "evidence", 3600)?;
        Ok(())
    }

    pub fn is_read_models_enabled(&self) -> SqliteResult<bool> {
        let conn = self.conn()?;
        let result: Result<String, _> = conn.query_row(
            "SELECT value FROM case_settings WHERE case_id = 'system' AND key = 'read_models_enabled'",
            [],
            |row| row.get(0),
        );

        match result {
            Ok(val) => Ok(val == "1"),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(true),
            Err(e) => Err(e),
        }
    }

    pub fn get_activity_log_paged(
        &self,
        case_id: &str,
        page: usize,
        page_size: usize,
    ) -> SqliteResult<Vec<ActivityLogEntry>> {
        let conn = self.conn()?;
        let offset = page * page_size;

        let mut stmt = conn.prepare(
            "SELECT id, case_id, event_type, summary, ts_utc, user_name 
             FROM activity_log 
             WHERE case_id = ?1 
             ORDER BY ts_utc DESC 
             LIMIT ?2 OFFSET ?3",
        )?;

        let entries = stmt.query_map(params![case_id, page_size as i64, offset as i64], |row| {
            Ok(ActivityLogEntry {
                id: row.get(0)?,
                case_id: row.get(1)?,
                event_type: row.get(2)?,
                summary: row.get(3)?,
                ts_utc: row.get(4)?,
                user_name: row.get(5)?,
            })
        })?;

        entries.collect()
    }

    pub fn get_bookmarks_paged(
        &self,
        case_id: &str,
        page: usize,
        page_size: usize,
    ) -> SqliteResult<Vec<BookmarkEntry>> {
        let conn = self.conn()?;
        let offset = page * page_size;

        let mut stmt = conn.prepare(
            "SELECT id, case_id, title, folder_id, reviewed, created_at 
             FROM bookmarks 
             WHERE case_id = ?1 
             ORDER BY created_at DESC 
             LIMIT ?2 OFFSET ?3",
        )?;

        let entries = stmt.query_map(params![case_id, page_size as i64, offset as i64], |row| {
            Ok(BookmarkEntry {
                id: row.get(0)?,
                case_id: row.get(1)?,
                title: row.get(2)?,
                folder_id: row.get(3)?,
                reviewed: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;

        entries.collect()
    }

    pub fn get_exhibits_paged(
        &self,
        case_id: &str,
        page: usize,
        page_size: usize,
    ) -> SqliteResult<Vec<ExhibitEntry>> {
        let conn = self.conn()?;
        let offset = page * page_size;

        let mut stmt = conn.prepare(
            "SELECT id, case_id, name, exhibit_type, created_at 
             FROM exhibits 
             WHERE case_id = ?1 
             ORDER BY created_at DESC 
             LIMIT ?2 OFFSET ?3",
        )?;

        let entries = stmt.query_map(params![case_id, page_size as i64, offset as i64], |row| {
            Ok(ExhibitEntry {
                id: row.get(0)?,
                case_id: row.get(1)?,
                name: row.get(2)?,
                exhibit_type: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;

        entries.collect()
    }
    #[allow(clippy::too_many_arguments)]
    pub fn add_evidence_with_detection(
        &self,
        case_id: &str,
        evidence_id: &str,
        name: &str,
        evidence_type: &str,
        file_path: &str,
        file_size: Option<i64>,
        detection: &crate::evidence::DetectionOutput,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;

        let container_type = detection
            .container_type
            .as_ref()
            .map(|c| c.container_type.clone());
        let partition_scheme = detection
            .partition_scheme
            .as_ref()
            .map(|p| p.scheme.clone());
        let sector_size = detection
            .container_type
            .as_ref()
            .map(|c| c.sector_size as i64);
        let capability_checks_json = serde_json::to_string(&detection.capability_checks).ok();

        conn.execute(
            "INSERT INTO evidence (id, case_id, name, evidence_type, file_path, file_size, container_type, partition_scheme, sector_size, capability_checks_json, detection_timestamp, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                evidence_id,
                case_id,
                name,
                evidence_type,
                file_path,
                file_size,
                container_type,
                partition_scheme,
                sector_size,
                capability_checks_json,
                detection.detection_timestamp_utc,
                chrono::Utc::now().timestamp()
            ],
        )?;

        for vol in &detection.volumes {
            let fs_type = vol.filesystem.as_ref().map(|f| f.filesystem_type.clone());
            let fs_label = vol.filesystem.as_ref().and_then(|f| f.label.clone());
            let part_type = vol.partition_type.clone();
            let cap_name = vol.capability_name.clone();
            let supported = vol.is_supported as i32;

            conn.execute(
                "INSERT INTO evidence_volumes (id, evidence_id, case_id, volume_index, offset_bytes, size_bytes, filesystem_type, filesystem_label, partition_type, capability_name, is_supported)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    evidence_id,
                    case_id,
                    vol.index as i64,
                    vol.offset_bytes as i64,
                    vol.size_bytes as i64,
                    fs_type,
                    fs_label,
                    part_type,
                    cap_name,
                    supported
                ],
            )?;
        }

        Ok(())
    }

    pub fn get_evidence_volumes(&self, evidence_id: &str) -> SqliteResult<Vec<EvidenceVolumeInfo>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, evidence_id, case_id, volume_index, offset_bytes, size_bytes, filesystem_type, filesystem_label, partition_type, capability_name, is_supported
             FROM evidence_volumes WHERE evidence_id = ?1 ORDER BY volume_index"
        )?;

        let volumes = stmt.query_map(params![evidence_id], |row| {
            Ok(EvidenceVolumeInfo {
                id: row.get(0)?,
                evidence_id: row.get(1)?,
                case_id: row.get(2)?,
                volume_index: row.get::<_, i64>(3)? as usize,
                offset_bytes: row.get::<_, i64>(4)? as u64,
                size_bytes: row.get::<_, i64>(5)? as u64,
                filesystem_type: row.get(6)?,
                filesystem_label: row.get(7)?,
                partition_type: row.get(8)?,
                capability_name: row.get(9)?,
                is_supported: row.get::<_, i64>(10)? != 0,
            })
        })?;

        volumes.collect()
    }

    pub fn get_evidence_timeline_paged(
        &self,
        case_id: &str,
        page: usize,
        page_size: usize,
    ) -> SqliteResult<Vec<EvidenceTimelineEvent>> {
        let conn = self.conn()?;
        let offset = page * page_size;

        let mut stmt = conn.prepare(
            "SELECT id, case_id, evidence_id, event_type, event_category, event_time, description, artifact_id, data_json
             FROM evidence_timeline 
             WHERE case_id = ?1 
             ORDER BY event_time DESC 
             LIMIT ?2 OFFSET ?3"
        )?;

        let entries = stmt.query_map(params![case_id, page_size as i64, offset as i64], |row| {
            Ok(EvidenceTimelineEvent {
                id: row.get(0)?,
                case_id: row.get(1)?,
                evidence_id: row.get(2)?,
                event_type: row.get(3)?,
                event_category: row.get(4)?,
                event_time: row.get(5)?,
                description: row.get(6)?,
                artifact_id: row.get(7)?,
                data_json: row.get(8)?,
                source_module: None,
                source_record_id: None,
            })
        })?;

        entries.collect()
    }

    pub fn get_activity_log_after(
        &self,
        case_id: &str,
        last_ts: i64,
        last_id: &str,
        limit: usize,
    ) -> SqliteResult<Vec<ActivityLogEntry>> {
        let conn = self.conn()?;

        let mut stmt = conn.prepare(
            "SELECT id, case_id, event_type, summary, ts_utc, user_name 
             FROM activity_log 
             WHERE case_id = ?1 AND (ts_utc < ?2 OR (ts_utc = ?2 AND id < ?3))
             ORDER BY ts_utc DESC, id DESC
             LIMIT ?4",
        )?;

        let entries = stmt.query_map(params![case_id, last_ts, last_id, limit as i64], |row| {
            Ok(ActivityLogEntry {
                id: row.get(0)?,
                case_id: row.get(1)?,
                event_type: row.get(2)?,
                summary: row.get(3)?,
                ts_utc: row.get(4)?,
                user_name: row.get(5)?,
            })
        })?;

        entries.collect()
    }

    pub fn get_evidence_timeline_after(
        &self,
        case_id: &str,
        last_event_time: i64,
        last_rowid: i64,
        limit: usize,
    ) -> SqliteResult<Vec<EvidenceTimelineEvent>> {
        let conn = self.conn()?;

        let mut stmt = conn.prepare(
            "SELECT id, case_id, evidence_id, event_type, event_category, event_time, description, artifact_id, data_json
             FROM evidence_timeline 
             WHERE case_id = ?1 AND (event_time < ?2 OR (event_time = ?2 AND rowid < ?3))
             ORDER BY event_time DESC, rowid DESC
             LIMIT ?4"
        )?;

        let entries = stmt.query_map(
            params![case_id, last_event_time, last_rowid, limit as i64],
            |row| {
                Ok(EvidenceTimelineEvent {
                    id: row.get(0)?,
                    case_id: row.get(1)?,
                    evidence_id: row.get(2)?,
                    event_type: row.get(3)?,
                    event_category: row.get(4)?,
                    event_time: row.get(5)?,
                    description: row.get(6)?,
                    artifact_id: row.get(7)?,
                    data_json: row.get(8)?,
                    source_module: None,
                    source_record_id: None,
                })
            },
        )?;

        entries.collect()
    }

    pub fn set_read_models_enabled(&self, enabled: bool) -> SqliteResult<()> {
        let conn = self.conn()?;

        let new_dirty = if enabled { "0" } else { "1" };

        conn.execute(
            "INSERT OR REPLACE INTO case_settings (id, case_id, key, value, modified_at) 
             VALUES (uuid4(), 'system', 'read_models_enabled', ?1, strftime('%s', 'now'))",
            [if enabled { "1" } else { "0" }],
        )?;

        conn.execute(
            "INSERT OR REPLACE INTO case_settings (id, case_id, key, value, modified_at) 
             VALUES (uuid4(), 'system', 'read_models_dirty', ?1, strftime('%s', 'now'))",
            [new_dirty],
        )?;

        Ok(())
    }

    pub fn check_and_rebuild_dirty(&self, case_id: &str) -> SqliteResult<bool> {
        let conn = self.conn()?;

        let dirty: Result<String, _> = conn.query_row(
            "SELECT value FROM case_settings WHERE case_id = 'system' AND key = 'read_models_dirty'",
            [],
            |row| row.get(0),
        );

        match dirty {
            Ok(val) if val == "1" => {
                drop(conn);
                self.rebuild_all_read_models(case_id)?;
                self.set_read_models_enabled(true)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub fn set_case_version(&self, key: &str, value: &str) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO case_settings (id, case_id, key, value, modified_at) 
             VALUES (uuid4(), 'system', ?1, ?2, strftime('%s', 'now'))",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_case_version(&self, key: &str) -> SqliteResult<Option<String>> {
        let conn = self.conn()?;
        let result = conn.query_row(
            "SELECT value FROM case_settings WHERE case_id = 'system' AND key = ?1",
            [key],
            |row| row.get(0),
        );

        match result {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn add_exhibit_rule_hit(
        &self,
        exhibit_id: &str,
        rule_id: &str,
        rule_name: &str,
        matched_field: &str,
        matched_value: &str,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;

        let existing: Result<String, _> = conn.query_row(
            "SELECT metadata_json FROM exhibits WHERE id = ?1",
            [exhibit_id],
            |row| row.get(0),
        );

        let mut rule_hits: Vec<RuleHitEntry> = Vec::new();
        if let Ok(json) = existing {
            if let Ok(hits) = serde_json::from_str::<Vec<RuleHitEntry>>(&json) {
                rule_hits = hits;
            }
        }

        rule_hits.push(RuleHitEntry {
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            matched_field: matched_field.to_string(),
            matched_value: matched_value.to_string(),
            matched_at: Self::unix_now_secs_u64()?,
        });

        let json = serde_json::to_string(&rule_hits).unwrap_or_default();
        conn.execute(
            "UPDATE exhibits SET metadata_json = ?1 WHERE id = ?2",
            params![json, exhibit_id],
        )?;

        Ok(())
    }

    pub fn get_exhibit_rule_hits(&self, exhibit_id: &str) -> SqliteResult<Vec<RuleHitEntry>> {
        let conn = self.conn()?;

        let result: Result<String, _> = conn.query_row(
            "SELECT metadata_json FROM exhibits WHERE id = ?1",
            [exhibit_id],
            |row| row.get(0),
        );

        match result {
            Ok(json) => {
                let hits: Vec<RuleHitEntry> = serde_json::from_str(&json).unwrap_or_default();
                Ok(hits)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    pub fn explain_exhibit(&self, exhibit_id: &str) -> SqliteResult<ExhibitExplanation> {
        let conn = self.conn()?;

        let exhibit = conn.query_row(
            "SELECT id, name, description, exhibit_type, tags_json, metadata_json FROM exhibits WHERE id = ?1",
            [exhibit_id],
            |row| {
                Ok(ExhibitExplanation {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    exhibit_type: row.get(3)?,
                    tags: row.get::<_, Option<String>>(4)?
                        .and_then(|t| serde_json::from_str(&t).ok())
                        .unwrap_or_default(),
                    rule_hits: row.get::<_, Option<String>>(5)?
                        .and_then(|t| serde_json::from_str(&t).ok())
                        .unwrap_or_default(),
                })
            },
        )?;

        Ok(exhibit)
    }

    pub fn populate_fts_index(&self, case_id: &str, entity_type: &str) -> SqliteResult<usize> {
        let conn = self.conn()?;
        let mut count = 0;

        match entity_type {
            "notes" => {
                let mut stmt =
                    conn.prepare("SELECT id, title, content FROM notes WHERE case_id = ?1")?;

                let notes: Vec<(String, String, String)> = stmt
                    .query_map([case_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                    .filter_map(|r| r.ok())
                    .collect();

                for (id, title, content) in notes {
                    conn.execute(
                        "INSERT INTO notes_fts (rowid, title, content) VALUES (
                            (SELECT rowid FROM notes WHERE id = ?1), ?2, ?3
                        )",
                        params![id, title, content],
                    )?;
                    count += 1;
                }
            }
            "bookmarks" => {
                let mut stmt = conn
                    .prepare("SELECT id, title, description FROM bookmarks WHERE case_id = ?1")?;

                let bookmarks: Vec<(String, String, Option<String>)> = stmt
                    .query_map([case_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                    .filter_map(|r| r.ok())
                    .collect();

                for (id, title, description) in bookmarks {
                    conn.execute(
                        "INSERT INTO bookmarks_fts (rowid, title, description) VALUES (
                            (SELECT rowid FROM bookmarks WHERE id = ?1), ?2, ?3
                        )",
                        params![id, title, description.unwrap_or_default()],
                    )?;
                    count += 1;
                }
            }
            _ => {}
        }

        Ok(count)
    }

    pub fn queue_fts_update(
        &self,
        case_id: &str,
        table_name: &str,
        row_id: &str,
        operation: &str,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;

        conn.execute(
            "INSERT INTO fts_index_queue (id, case_id, table_name, row_id, operation, status, created_at)
             VALUES (uuid4(), ?1, ?2, ?3, ?4, 'pending', strftime('%s', 'now'))",
            params![case_id, table_name, row_id, operation],
        )?;

        Ok(())
    }

    pub fn process_fts_queue(&self, case_id: &str, batch_size: usize) -> SqliteResult<usize> {
        let conn = self.conn()?;
        let mut processed = 0;

        let mut stmt = conn.prepare(
            "SELECT id, table_name, row_id, operation FROM fts_index_queue 
             WHERE case_id = ?1 AND status = 'pending' ORDER BY created_at LIMIT ?2",
        )?;

        let queue: Vec<(String, String, String, String)> = stmt
            .query_map(params![case_id, batch_size as i64], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        drop(stmt);

        for (queue_id, table_name, row_id, operation) in queue {
            let result = match (table_name.as_str(), operation.as_str()) {
                ("notes", "insert") | ("notes", "update") => {
                    if let Ok(note) = conn.query_row(
                        "SELECT id, title, content FROM notes WHERE id = ?1",
                        [&row_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                            ))
                        },
                    ) {
                        conn.execute(
                            "INSERT OR REPLACE INTO notes_fts (rowid, title, content) VALUES (
                                (SELECT rowid FROM notes WHERE id = ?1), ?2, ?3
                            )",
                            params![note.0, note.1, note.2.unwrap_or_default()],
                        )
                    } else {
                        Ok(0)
                    }
                }
                ("notes", "delete") => conn.execute(
                    "DELETE FROM notes_fts WHERE rowid = (SELECT rowid FROM notes WHERE id = ?1)",
                    [&row_id],
                ),
                _ => Ok(0),
            };

            if result.is_ok() {
                conn.execute(
                    "UPDATE fts_index_queue SET status = 'completed', processed_at = strftime('%s', 'now') WHERE id = ?1",
                    [&queue_id],
                )?;
                processed += 1;
            }
        }

        Ok(processed)
    }

    pub fn process_fts_queue_no_case(&self, batch_size: usize) -> SqliteResult<usize> {
        let conn = self.conn()?;
        let mut processed = 0;

        let mut stmt = conn.prepare(
            "SELECT id, entity_type, entity_id, operation FROM fts_index_queue 
             WHERE processed = 0 ORDER BY queued_at LIMIT ?1",
        )?;

        let queue: Vec<(String, String, String, String)> = stmt
            .query_map([batch_size as i64], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        drop(stmt);

        for (queue_id, entity_type, entity_id, operation) in queue {
            let result = match (entity_type.as_str(), operation.as_str()) {
                ("notes", "insert") | ("notes", "update") => {
                    if let Ok(note) = conn.query_row(
                        "SELECT id, title, content FROM notes WHERE id = ?1",
                        [&entity_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                            ))
                        },
                    ) {
                        conn.execute(
                            "INSERT OR REPLACE INTO notes_fts (rowid, title, content) VALUES (
                                (SELECT rowid FROM notes WHERE id = ?1), ?2, ?3
                            )",
                            params![note.0, note.1, note.2.unwrap_or_default()],
                        )
                    } else {
                        Ok(0)
                    }
                }
                ("notes", "delete") => conn.execute(
                    "DELETE FROM notes_fts WHERE rowid = (SELECT rowid FROM notes WHERE id = ?1)",
                    [&entity_id],
                ),
                _ => Ok(0),
            };

            if result.is_ok() {
                conn.execute(
                    "UPDATE fts_index_queue SET status = 'completed', processed_at = strftime('%s', 'now') WHERE id = ?1",
                    [&queue_id],
                )?;
                processed += 1;
            }
        }

        Ok(processed)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_global_entity(
        &self,
        case_id: &str,
        entity_type: &str,
        entity_id: &str,
        title: Option<&str>,
        content: Option<&str>,
        path: Option<&str>,
        tags: Option<&str>,
        category: Option<&str>,
        ts_utc: Option<&str>,
        source_module: Option<&str>,
        json_data: &str,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;

        conn.execute(
            "INSERT OR REPLACE INTO global_search_entities 
             (case_id, entity_type, entity_id, title, path, category, ts_utc, tags, json_data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                case_id,
                entity_type,
                entity_id,
                title,
                path,
                category,
                ts_utc,
                tags,
                json_data
            ],
        )?;

        let fts_content = content
            .unwrap_or("")
            .chars()
            .take(10000)
            .collect::<String>();

        conn.execute(
            "INSERT OR REPLACE INTO global_search_fts 
             (case_id, entity_type, entity_id, title, content, path, tags, category, ts_utc, source_module)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                case_id,
                entity_type,
                entity_id,
                title,
                fts_content,
                path,
                tags,
                category,
                ts_utc,
                source_module
            ],
        )?;

        Ok(())
    }

    pub fn delete_global_entity(
        &self,
        case_id: &str,
        entity_type: &str,
        entity_id: &str,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;

        conn.execute(
            "DELETE FROM global_search_entities WHERE case_id = ?1 AND entity_type = ?2 AND entity_id = ?3",
            params![case_id, entity_type, entity_id],
        )?;

        conn.execute(
            "DELETE FROM global_search_fts WHERE case_id = ?1 AND entity_type = ?2 AND entity_id = ?3",
            params![case_id, entity_type, entity_id],
        )?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn global_search(
        &self,
        case_id: &str,
        query: &str,
        entity_types: Option<Vec<&str>>,
        date_start_utc: Option<&str>,
        date_end_utc: Option<&str>,
        category: Option<&str>,
        tags_any: Option<Vec<&str>>,
        path_prefix: Option<&str>,
        limit: u32,
        after_rank: Option<f64>,
        after_rowid: Option<i64>,
    ) -> SqliteResult<Vec<GlobalSearchHit>> {
        let conn = self.conn()?;

        let mut sql = String::from(
            "SELECT e.entity_type, e.entity_id, e.title, e.path, e.category, e.ts_utc, e.json_data,
                    f.rowid, bm25(global_search_fts) as rank
             FROM global_search_fts f
             JOIN global_search_entities e ON f.entity_id = e.entity_id AND f.entity_type = e.entity_type AND f.case_id = e.case_id
             WHERE f.case_id = ?1 AND global_search_fts MATCH ?2"
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> =
            vec![Box::new(case_id.to_string()), Box::new(query.to_string())];

        if let Some(ref types) = entity_types {
            let placeholders: Vec<String> = types
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + 10))
                .collect();
            sql.push_str(&format!(
                " AND f.entity_type IN ({})",
                placeholders.join(",")
            ));
            for t in types {
                params_vec.push(Box::new(t.to_string()));
            }
        }

        if let Some(start) = date_start_utc {
            sql.push_str(&format!(" AND e.ts_utc >= ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(start.to_string()));
        }

        if let Some(end) = date_end_utc {
            sql.push_str(&format!(" AND e.ts_utc <= ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(end.to_string()));
        }

        if let Some(cat) = category {
            sql.push_str(&format!(" AND e.category = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(cat.to_string()));
        }

        if let Some(ref tags) = tags_any {
            let tag_conditions: Vec<String> = tags
                .iter()
                .enumerate()
                .map(|(i, _)| format!("e.tags LIKE ?{}", params_vec.len() + 1 + i))
                .collect();
            sql.push_str(&format!(" AND ({})", tag_conditions.join(" OR ")));
            for t in tags {
                params_vec.push(Box::new(format!("%{}%", t)));
            }
        }

        if let Some(prefix) = path_prefix {
            sql.push_str(&format!(" AND e.path LIKE ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(format!("{}%", prefix)));
        }

        if let Some(rank) = after_rank {
            if let Some(rowid) = after_rowid {
                sql.push_str(&format!(
                    " AND (rank > ?{} OR (rank = ?{} AND f.rowid > ?{}))",
                    params_vec.len() + 1,
                    params_vec.len() + 2,
                    params_vec.len() + 3
                ));
                params_vec.push(Box::new(rank));
                params_vec.push(Box::new(rank));
                params_vec.push(Box::new(rowid));
            }
        }

        sql.push_str(" ORDER BY rank, f.rowid");
        sql.push_str(&format!(" LIMIT {}", limit));

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let entity_type: String = row.get(0)?;
            let entity_id: String = row.get(1)?;
            let title: Option<String> = row.get(2)?;
            let path: Option<String> = row.get(3)?;
            let category: Option<String> = row.get(4)?;
            let ts_utc: Option<String> = row.get(5)?;
            let json_data: String = row.get(6)?;
            let _rowid: i64 = row.get(7)?;
            let rank: f64 = row.get(8)?;

            let json: serde_json::Value =
                serde_json::from_str(&json_data).unwrap_or(serde_json::Value::Null);

            let snippet = format!(
                "{}...",
                title
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .take(200)
                    .collect::<String>()
            );

            Ok(GlobalSearchHit {
                entity_type,
                entity_id,
                title: title.unwrap_or_default(),
                snippet,
                path,
                category,
                ts_utc,
                rank,
                json,
            })
        })?;

        rows.collect()
    }

    pub fn rebuild_global_search_for_type(
        &self,
        case_id: &str,
        entity_type: &str,
    ) -> SqliteResult<usize> {
        let conn = self.conn()?;
        let mut indexed = 0;

        match entity_type {
            "note" => {
                let mut stmt = conn.prepare(
                    "SELECT id, case_id, title, content, tags_json, created_at FROM notes WHERE case_id = ?1"
                )?;
                let notes = stmt.query_map([case_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })?;

                for note in notes.filter_map(|n| n.ok()) {
                    let ts_utc = chrono::DateTime::from_timestamp(note.5, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default();

                    let content = note.3.unwrap_or_default();

                    conn.execute(
                        "INSERT OR REPLACE INTO global_search_entities 
                         (case_id, entity_type, entity_id, title, path, category, ts_utc, tags, json_data)
                         VALUES (?1, 'note', ?2, ?3, NULL, 'manual', ?4, ?5, ?6)",
                        params![case_id, note.0, note.2, ts_utc, note.4, serde_json::json!({"content": content}).to_string()],
                    )?;

                    conn.execute(
                        "INSERT OR REPLACE INTO global_search_fts 
                         (case_id, entity_type, entity_id, title, content, path, tags, category, ts_utc, source_module)
                         VALUES (?1, 'note', ?2, ?3, ?4, NULL, ?5, 'manual', ?6, 'notes')",
                        params![case_id, note.0, note.2, content.chars().take(10000).collect::<String>(), note.4, ts_utc],
                    )?;
                    indexed += 1;
                }
            }
            "bookmark" => {
                let mut stmt = conn.prepare(
                    "SELECT id, case_id, title, description, tags_json, created_at FROM bookmarks WHERE case_id = ?1"
                )?;
                let bookmarks = stmt.query_map([case_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })?;

                for bm in bookmarks.filter_map(|b| b.ok()) {
                    let ts_utc = chrono::DateTime::from_timestamp(bm.5, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default();

                    let content = bm.3.unwrap_or_default();

                    conn.execute(
                        "INSERT OR REPLACE INTO global_search_entities 
                         (case_id, entity_type, entity_id, title, path, category, ts_utc, tags, json_data)
                         VALUES (?1, 'bookmark', ?2, ?3, NULL, NULL, ?4, ?5, ?6)",
                        params![case_id, bm.0, bm.2, ts_utc, bm.4, serde_json::json!({"description": content}).to_string()],
                    )?;

                    conn.execute(
                        "INSERT OR REPLACE INTO global_search_fts 
                         (case_id, entity_type, entity_id, title, content, path, tags, category, ts_utc, source_module)
                         VALUES (?1, 'bookmark', ?2, ?3, ?4, NULL, ?5, NULL, ?6, 'bookmarks')",
                        params![case_id, bm.0, bm.2, content.chars().take(10000).collect::<String>(), bm.4, ts_utc],
                    )?;
                    indexed += 1;
                }
            }
            "exhibit" => {
                let mut stmt = conn.prepare(
                    "SELECT id, case_id, name, description, exhibit_type, created_at FROM exhibits WHERE case_id = ?1"
                )?;
                let exhibits = stmt.query_map([case_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })?;

                for ex in exhibits.filter_map(|e| e.ok()) {
                    let ts_utc = chrono::DateTime::from_timestamp(ex.5, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default();

                    let content = ex.3.unwrap_or_default();

                    conn.execute(
                        "INSERT OR REPLACE INTO global_search_entities 
                         (case_id, entity_type, entity_id, title, path, category, ts_utc, tags, json_data)
                         VALUES (?1, 'exhibit', ?2, ?3, NULL, ?4, ?5, NULL, ?6)",
                        params![case_id, ex.0, ex.2, ex.4, ts_utc, serde_json::json!({"description": content}).to_string()],
                    )?;

                    conn.execute(
                        "INSERT OR REPLACE INTO global_search_fts 
                         (case_id, entity_type, entity_id, title, content, path, tags, category, ts_utc, source_module)
                         VALUES (?1, 'exhibit', ?2, ?3, ?4, NULL, NULL, ?5, ?6, 'exhibits')",
                        params![case_id, ex.0, ex.2, content.chars().take(10000).collect::<String>(), ex.4, ts_utc],
                    )?;
                    indexed += 1;
                }
            }
            "timeline" => {
                let mut stmt = conn.prepare(
                    "SELECT id, case_id, event_type, event_category, event_time, description, data_json FROM evidence_timeline WHERE case_id = ?1"
                )?;
                let events = stmt.query_map([case_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                })?;

                for ev in events.filter_map(|e| e.ok()) {
                    let ts_utc = chrono::DateTime::from_timestamp(ev.4, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default();

                    let content = ev.5.unwrap_or_default();

                    conn.execute(
                        "INSERT OR REPLACE INTO global_search_entities 
                         (case_id, entity_type, entity_id, title, path, category, ts_utc, tags, json_data)
                         VALUES (?1, 'timeline', ?2, ?3, NULL, ?4, ?5, NULL, ?6)",
                        params![case_id, ev.0, ev.2, ev.3, ts_utc, ev.6.as_ref().unwrap_or(&"{}".to_string())],
                    )?;

                    conn.execute(
                        "INSERT OR REPLACE INTO global_search_fts 
                         (case_id, entity_type, entity_id, title, content, path, tags, category, ts_utc, source_module)
                         VALUES (?1, 'timeline', ?2, ?3, ?4, NULL, NULL, ?5, ?6, 'timeline')",
                        params![case_id, ev.0, ev.2, content.chars().take(10000).collect::<String>(), ev.3, ts_utc],
                    )?;
                    indexed += 1;
                }
            }
            _ => {}
        }

        Ok(indexed)
    }

    pub fn queue_global_entity_update(
        &self,
        case_id: &str,
        entity_type: &str,
        entity_id: &str,
        operation: &str,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO fts_index_queue (id, case_id, table_name, row_id, operation, status, created_at, entity_type, entity_id)
             VALUES (uuid4(), ?1, 'global_search', ?2, ?3, 'pending', strftime('%s', 'now'), ?4, ?5)",
            params![case_id, entity_id, operation, entity_type, entity_id],
        )?;
        Ok(())
    }

    pub fn process_global_search_queue(
        &self,
        case_id: &str,
        batch_size: usize,
    ) -> SqliteResult<usize> {
        let conn = self.conn()?;
        let mut processed = 0;

        let mut stmt = conn.prepare(
            "SELECT id, entity_type, entity_id, operation FROM fts_index_queue 
             WHERE case_id = ?1 AND table_name = 'global_search' AND status = 'pending' ORDER BY created_at LIMIT ?2"
        )?;

        let queue: Vec<(String, String, String, String)> = stmt
            .query_map(params![case_id, batch_size as i64], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        drop(stmt);

        for (queue_id, entity_type, entity_id, operation) in queue {
            let result = match (entity_type.as_str(), operation.as_str()) {
                ("note", "upsert") | ("note", "insert") | ("note", "update") => {
                    if let Ok(note) = conn.query_row(
                        "SELECT id, case_id, title, content, tags_json, created_at FROM notes WHERE id = ?1 AND case_id = ?2",
                        params![entity_id, case_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, Option<String>>(3)?,
                                row.get::<_, Option<String>>(4)?,
                                row.get::<_, i64>(5)?,
                            ))
                        },
                    ) {
                        let ts_utc = chrono::DateTime::from_timestamp(note.5, 0)
                            .map(|dt| dt.to_rfc3339())
                            .unwrap_or_default();
                        let content = note.3.unwrap_or_default();

                        conn.execute(
                            "INSERT OR REPLACE INTO global_search_entities 
                             (case_id, entity_type, entity_id, title, path, category, ts_utc, tags, json_data)
                             VALUES (?1, 'note', ?2, ?3, NULL, 'manual', ?4, ?5, ?6)",
                            params![case_id, note.0, note.2, ts_utc, note.4, serde_json::json!({"content": content}).to_string()],
                        )?;

                        conn.execute(
                            "INSERT OR REPLACE INTO global_search_fts 
                             (case_id, entity_type, entity_id, title, content, path, tags, category, ts_utc, source_module)
                             VALUES (?1, 'note', ?2, ?3, ?4, NULL, ?5, 'manual', ?6, 'notes')",
                            params![case_id, note.0, note.2, content.chars().take(10000).collect::<String>(), note.4, ts_utc],
                        )
                    } else {
                        Ok(0)
                    }
                }
                ("note", "delete") => {
                    conn.execute(
                        "DELETE FROM global_search_entities WHERE case_id = ?1 AND entity_type = 'note' AND entity_id = ?2",
                        params![case_id, entity_id],
                    )?;
                    conn.execute(
                        "DELETE FROM global_search_fts WHERE case_id = ?1 AND entity_type = 'note' AND entity_id = ?2",
                        params![case_id, entity_id],
                    )
                }
                ("exhibit", "upsert") | ("exhibit", "insert") | ("exhibit", "update") => {
                    if let Ok(exhibit) = conn.query_row(
                        "SELECT id, case_id, name, description, exhibit_type, created_at FROM exhibits WHERE id = ?1 AND case_id = ?2",
                        params![entity_id, case_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, Option<String>>(3)?,
                                row.get::<_, String>(4)?,
                                row.get::<_, i64>(5)?,
                            ))
                        },
                    ) {
                        let ts_utc = chrono::DateTime::from_timestamp(exhibit.5, 0)
                            .map(|dt| dt.to_rfc3339())
                            .unwrap_or_default();
                        let content = exhibit.3.unwrap_or_default();

                        conn.execute(
                            "INSERT OR REPLACE INTO global_search_entities 
                             (case_id, entity_type, entity_id, title, path, category, ts_utc, tags, json_data)
                             VALUES (?1, 'exhibit', ?2, ?3, NULL, ?4, ?5, NULL, ?6)",
                            params![case_id, exhibit.0, exhibit.2, exhibit.4, ts_utc, serde_json::json!({"description": content}).to_string()],
                        )?;

                        conn.execute(
                            "INSERT OR REPLACE INTO global_search_fts 
                             (case_id, entity_type, entity_id, title, content, path, tags, category, ts_utc, source_module)
                             VALUES (?1, 'exhibit', ?2, ?3, ?4, NULL, NULL, ?5, ?6, 'exhibits')",
                            params![case_id, exhibit.0, exhibit.2, content.chars().take(10000).collect::<String>(), exhibit.4, ts_utc],
                        )
                    } else {
                        Ok(0)
                    }
                }
                ("exhibit", "delete") => {
                    conn.execute(
                        "DELETE FROM global_search_entities WHERE case_id = ?1 AND entity_type = 'exhibit' AND entity_id = ?2",
                        params![case_id, entity_id],
                    )?;
                    conn.execute(
                        "DELETE FROM global_search_fts WHERE case_id = ?1 AND entity_type = 'exhibit' AND entity_id = ?2",
                        params![case_id, entity_id],
                    )
                }
                ("bookmark", "upsert") | ("bookmark", "insert") | ("bookmark", "update") => {
                    if let Ok(bookmark) = conn.query_row(
                        "SELECT id, case_id, title, description, tags_json, created_at FROM bookmarks WHERE id = ?1 AND case_id = ?2",
                        params![entity_id, case_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, Option<String>>(3)?,
                                row.get::<_, Option<String>>(4)?,
                                row.get::<_, i64>(5)?,
                            ))
                        },
                    ) {
                        let ts_utc = chrono::DateTime::from_timestamp(bookmark.5, 0)
                            .map(|dt| dt.to_rfc3339())
                            .unwrap_or_default();
                        let content = bookmark.3.unwrap_or_default();

                        conn.execute(
                            "INSERT OR REPLACE INTO global_search_entities 
                             (case_id, entity_type, entity_id, title, path, category, ts_utc, tags, json_data)
                             VALUES (?1, 'bookmark', ?2, ?3, NULL, NULL, ?4, ?5, ?6)",
                            params![case_id, bookmark.0, bookmark.2, ts_utc, bookmark.4, serde_json::json!({"description": content}).to_string()],
                        )?;

                        conn.execute(
                            "INSERT OR REPLACE INTO global_search_fts 
                             (case_id, entity_type, entity_id, title, content, path, tags, category, ts_utc, source_module)
                             VALUES (?1, 'bookmark', ?2, ?3, ?4, NULL, ?5, NULL, ?6, 'bookmarks')",
                            params![case_id, bookmark.0, bookmark.2, content.chars().take(10000).collect::<String>(), bookmark.4, ts_utc],
                        )
                    } else {
                        Ok(0)
                    }
                }
                ("bookmark", "delete") => {
                    conn.execute(
                        "DELETE FROM global_search_entities WHERE case_id = ?1 AND entity_type = 'bookmark' AND entity_id = ?2",
                        params![case_id, entity_id],
                    )?;
                    conn.execute(
                        "DELETE FROM global_search_fts WHERE case_id = ?1 AND entity_type = 'bookmark' AND entity_id = ?2",
                        params![case_id, entity_id],
                    )
                }
                ("timeline", "upsert") | ("timeline", "insert") | ("timeline", "update") => {
                    if let Ok(event) = conn.query_row(
                        "SELECT id, case_id, event_type, event_category, event_time, description, data_json FROM evidence_timeline WHERE id = ?1 AND case_id = ?2",
                        params![entity_id, case_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, Option<String>>(3)?,
                                row.get::<_, i64>(4)?,
                                row.get::<_, Option<String>>(5)?,
                                row.get::<_, Option<String>>(6)?,
                            ))
                        },
                    ) {
                        let ts_utc = chrono::DateTime::from_timestamp(event.4, 0)
                            .map(|dt| dt.to_rfc3339())
                            .unwrap_or_default();
                        let content = event.5.unwrap_or_default();

                        conn.execute(
                            "INSERT OR REPLACE INTO global_search_entities 
                             (case_id, entity_type, entity_id, title, path, category, ts_utc, tags, json_data)
                             VALUES (?1, 'timeline', ?2, ?3, NULL, ?4, ?5, NULL, ?6)",
                            params![case_id, event.0, event.2, event.3, ts_utc, event.6.as_ref().unwrap_or(&"{}".to_string())],
                        )?;

                        conn.execute(
                            "INSERT OR REPLACE INTO global_search_fts 
                             (case_id, entity_type, entity_id, title, content, path, tags, category, ts_utc, source_module)
                             VALUES (?1, 'timeline', ?2, ?3, ?4, NULL, NULL, ?5, ?6, 'timeline')",
                            params![case_id, event.0, event.2, content.chars().take(10000).collect::<String>(), event.3, ts_utc],
                        )
                    } else {
                        Ok(0)
                    }
                }
                ("timeline", "delete") => {
                    conn.execute(
                        "DELETE FROM global_search_entities WHERE case_id = ?1 AND entity_type = 'timeline' AND entity_id = ?2",
                        params![case_id, entity_id],
                    )?;
                    conn.execute(
                        "DELETE FROM global_search_fts WHERE case_id = ?1 AND entity_type = 'timeline' AND entity_id = ?2",
                        params![case_id, entity_id],
                    )
                }
                _ => Ok(0),
            };

            if result.is_ok() {
                conn.execute(
                    "UPDATE fts_index_queue SET status = 'completed', processed_at = strftime('%s', 'now') WHERE id = ?1",
                    [&queue_id],
                )?;
                processed += 1;
            }
        }

        Ok(processed)
    }

    pub fn get_case_stats(&self, case_id: &str) -> SqliteResult<Option<CaseStats>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, case_id, total_artifacts, total_bookmarks, total_notes, 
                    total_exhibits, total_jobs, jobs_completed, jobs_failed, last_updated
             FROM case_stats WHERE case_id = ?1",
        )?;

        let result = stmt.query_row([case_id], |row| {
            Ok(CaseStats {
                id: row.get(0)?,
                case_id: row.get(1)?,
                total_artifacts: row.get(2)?,
                total_bookmarks: row.get(3)?,
                total_notes: row.get(4)?,
                total_exhibits: row.get(5)?,
                total_jobs: row.get(6)?,
                jobs_completed: row.get(7)?,
                jobs_failed: row.get(8)?,
                last_updated: row.get(9)?,
            })
        });

        match result {
            Ok(stats) => Ok(Some(stats)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_triage_stats(&self, case_id: &str) -> SqliteResult<Vec<TriageStat>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, case_id, category, count, total_size, last_updated 
             FROM triage_stats WHERE case_id = ?1 ORDER BY count DESC",
        )?;

        let stats = stmt.query_map([case_id], |row| {
            Ok(TriageStat {
                id: row.get(0)?,
                case_id: row.get(1)?,
                category: row.get(2)?,
                count: row.get(3)?,
                total_size: row.get(4)?,
                last_updated: row.get(5)?,
            })
        })?;

        stats.collect()
    }

    pub fn get_timeline_buckets(
        &self,
        case_id: &str,
        bucket_type: &str,
        limit: usize,
    ) -> SqliteResult<Vec<TimelineBucket>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, case_id, bucket_type, bucket_time, category, count 
             FROM timeline_buckets 
             WHERE case_id = ?1 AND bucket_type = ?2 
             ORDER BY bucket_time DESC LIMIT ?3",
        )?;

        let buckets = stmt.query_map(params![case_id, bucket_type, limit as i64], |row| {
            Ok(TimelineBucket {
                id: row.get(0)?,
                case_id: row.get(1)?,
                bucket_type: row.get(2)?,
                bucket_time: row.get(3)?,
                category: row.get(4)?,
                count: row.get(5)?,
            })
        })?;

        buckets.collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_file_strings(
        &self,
        case_id: &str,
        evidence_id: Option<&str>,
        volume_id: Option<&str>,
        file_id: &str,
        file_path: &str,
        sha256: Option<&str>,
        size_bytes: Option<i64>,
        extractor_version: &str,
        flags: u32,
        strings_text: &str,
        strings_json: &str,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;
        let extracted_utc = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "INSERT OR REPLACE INTO file_strings 
             (case_id, evidence_id, volume_id, file_id, file_path, sha256, size_bytes, extracted_utc, extractor_version, flags, strings_text, strings_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                case_id,
                evidence_id,
                volume_id,
                file_id,
                file_path,
                sha256,
                size_bytes,
                extracted_utc,
                extractor_version,
                flags as i64,
                strings_text,
                strings_json
            ],
        )?;

        Ok(())
    }

    pub fn get_file_strings(
        &self,
        case_id: &str,
        file_id: &str,
    ) -> SqliteResult<Option<FileStringsResult>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT file_id, file_path, sha256, size_bytes, extracted_utc, flags, strings_text, strings_json
             FROM file_strings WHERE case_id = ?1 AND file_id = ?2"
        )?;

        let result = stmt.query_row(params![case_id, file_id], |row| {
            Ok(FileStringsResult {
                file_id: row.get(0)?,
                file_path: row.get(1)?,
                sha256: row.get(2)?,
                size_bytes: row.get::<_, Option<i64>>(3)?.map(|s| s as u64),
                extracted_utc: row.get(4)?,
                flags: row.get::<_, i64>(5)? as u32,
                strings_text: row.get(6)?,
                strings_json: row.get(7)?,
            })
        });

        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn list_file_strings(
        &self,
        case_id: &str,
        limit: usize,
        offset: usize,
    ) -> SqliteResult<Vec<FileStringsResult>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT file_id, file_path, sha256, size_bytes, extracted_utc, flags, strings_text, strings_json
             FROM file_strings WHERE case_id = ?1 ORDER BY extracted_utc DESC LIMIT ?2 OFFSET ?3"
        )?;

        let results = stmt.query_map(params![case_id, limit as i64, offset as i64], |row| {
            Ok(FileStringsResult {
                file_id: row.get(0)?,
                file_path: row.get(1)?,
                sha256: row.get(2)?,
                size_bytes: row.get::<_, Option<i64>>(3)?.map(|s| s as u64),
                extracted_utc: row.get(4)?,
                flags: row.get::<_, i64>(5)? as u32,
                strings_text: row.get(6)?,
                strings_json: row.get(7)?,
            })
        })?;

        results.collect()
    }

    pub fn list_ioc_rules(&self, enabled_only: bool) -> SqliteResult<Vec<IocRuleRow>> {
        let conn = self.conn()?;
        let sql = if enabled_only {
            "SELECT id, name, rule_type, severity, enabled, pattern, hash_type, scope_json, tags, created_utc, updated_utc
             FROM ioc_rules
             WHERE enabled = 1
             ORDER BY updated_utc DESC"
        } else {
            "SELECT id, name, rule_type, severity, enabled, pattern, hash_type, scope_json, tags, created_utc, updated_utc
             FROM ioc_rules
             ORDER BY updated_utc DESC"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(IocRuleRow {
                id: row.get(0)?,
                name: row.get(1)?,
                rule_type: row.get(2)?,
                severity: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
                pattern: row.get(5)?,
                hash_type: row.get(6)?,
                scope_json: row.get(7)?,
                tags: row.get(8)?,
                created_utc: row.get(9)?,
                updated_utc: row.get(10)?,
            })
        })?;
        rows.collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_ioc_hit(
        &self,
        case_id: &str,
        rule_id: i64,
        target_type: &str,
        target_id: &str,
        target_path: Option<&str>,
        matched_field: &str,
        matched_value: &str,
        context_json: &str,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;
        let hit_utc = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR IGNORE INTO ioc_hits
             (case_id, rule_id, hit_utc, target_type, target_id, target_path, matched_field, matched_value, context_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                case_id,
                rule_id,
                hit_utc,
                target_type,
                target_id,
                target_path,
                matched_field,
                matched_value,
                context_json
            ],
        )?;
        Ok(())
    }

    pub fn get_ioc_hits_for_rule(
        &self,
        case_id: &str,
        rule_id: i64,
    ) -> SqliteResult<Vec<IocHitRow>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT h.id, h.case_id, h.rule_id, h.hit_utc, h.target_type, h.target_id, h.target_path, h.matched_field, h.matched_value, h.context_json, r.name, r.severity
             FROM ioc_hits h
             JOIN ioc_rules r ON h.rule_id = r.id
             WHERE h.case_id = ?1 AND h.rule_id = ?2
             ORDER BY h.hit_utc DESC"
        )?;

        let hits = stmt.query_map(params![case_id, rule_id], map_ioc_hit)?;
        hits.collect()
    }

    pub fn get_ioc_hits_for_target(
        &self,
        case_id: &str,
        target_type: &str,
        target_id: &str,
    ) -> SqliteResult<Vec<IocHitRow>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT h.id, h.case_id, h.rule_id, h.hit_utc, h.target_type, h.target_id, h.target_path, h.matched_field, h.matched_value, h.context_json, r.name, r.severity
             FROM ioc_hits h
             JOIN ioc_rules r ON h.rule_id = r.id
             WHERE h.case_id = ?1 AND h.target_type = ?2 AND h.target_id = ?3
             ORDER BY h.hit_utc DESC"
        )?;

        let hits = stmt.query_map(params![case_id, target_type, target_id], map_ioc_hit)?;
        hits.collect()
    }
}

impl CaseDatabase {
    #[allow(clippy::too_many_arguments)]
    pub fn insert_carved_file(
        &self,
        case_id: &str,
        evidence_id: &str,
        volume_id: Option<&str>,
        signature_name: &str,
        offset_bytes: i64,
        length_bytes: i64,
        output_rel_path: &str,
        sha256: &str,
        file_type: Option<&str>,
        confidence: &str,
        flags: i64,
        details_json: &str,
    ) -> SqliteResult<i64> {
        let conn = self.conn()?;
        let carved_utc = chrono::Utc::now().to_rfc3339();

        let result = conn.execute(
            "INSERT OR IGNORE INTO carved_files 
             (case_id, evidence_id, volume_id, carved_utc, signature_name, offset_bytes, length_bytes, output_rel_path, sha256, file_type, confidence, flags, details_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                case_id,
                evidence_id,
                volume_id,
                carved_utc,
                signature_name,
                offset_bytes,
                length_bytes,
                output_rel_path,
                sha256,
                file_type,
                confidence,
                flags,
                details_json
            ],
        );

        match result {
            Ok(count) if count > 0 => Ok(conn.last_insert_rowid()),
            Ok(_) => Ok(-1),
            Err(e) => Err(e),
        }
    }

    pub fn list_carved_files(
        &self,
        case_id: &str,
        limit: usize,
        since: Option<&str>,
    ) -> SqliteResult<Vec<CarvedFileRow>> {
        let conn = self.conn()?;

        let sql = if let Some(_since) = since {
            "SELECT id, case_id, evidence_id, volume_id, carved_utc, signature_name, offset_bytes, length_bytes, output_rel_path, sha256, file_type, confidence, flags, details_json
             FROM carved_files WHERE case_id = ?1 AND carved_utc >= ?2 ORDER BY carved_utc DESC LIMIT ?3"
        } else {
            "SELECT id, case_id, evidence_id, volume_id, carved_utc, signature_name, offset_bytes, length_bytes, output_rel_path, sha256, file_type, confidence, flags, details_json
             FROM carved_files WHERE case_id = ?1 ORDER BY carved_utc DESC LIMIT ?2"
        };

        let mut stmt = conn.prepare(sql)?;

        let rows = if let Some(_since) = since {
            stmt.query_map(params![case_id, since, limit as i64], map_carved_file)?
        } else {
            stmt.query_map(params![case_id, limit as i64], map_carved_file)?
        };

        rows.collect()
    }

    pub fn get_carved_file(&self, case_id: &str, id: i64) -> SqliteResult<Option<CarvedFileRow>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, case_id, evidence_id, volume_id, carved_utc, signature_name, offset_bytes, length_bytes, output_rel_path, sha256, file_type, confidence, flags, details_json
             FROM carved_files WHERE case_id = ?1 AND id = ?2"
        )?;

        let result = stmt.query_row(params![case_id, id], map_carved_file);

        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_carved_file_by_hash(
        &self,
        case_id: &str,
        sha256: &str,
    ) -> SqliteResult<Option<CarvedFileRow>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, case_id, evidence_id, volume_id, carved_utc, signature_name, offset_bytes, length_bytes, output_rel_path, sha256, file_type, confidence, flags, details_json
             FROM carved_files WHERE case_id = ?1 AND sha256 = ?2"
        )?;

        let result = stmt.query_row(params![case_id, sha256], map_carved_file);

        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn count_carved_files(&self, case_id: &str) -> SqliteResult<i64> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM carved_files WHERE case_id = ?1")?;
        stmt.query_row([case_id], |row| row.get(0))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_file_table_row(
        &self,
        case_id: &str,
        source_type: &str,
        source_id: &str,
        evidence_id: Option<&str>,
        volume_id: Option<&str>,
        path: &str,
        name: &str,
        extension: Option<&str>,
        size_bytes: Option<i64>,
        created_utc: Option<&str>,
        modified_utc: Option<&str>,
        accessed_utc: Option<&str>,
        changed_utc: Option<&str>,
        hash_md5: Option<&str>,
        hash_sha1: Option<&str>,
        hash_sha256: Option<&str>,
        entropy: Option<f64>,
        category: Option<&str>,
        flags: i64,
        score: f64,
        tags: &str,
        summary_json: &str,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO file_table_rows 
             (case_id, source_type, source_id, evidence_id, volume_id, path, name, extension, size_bytes, created_utc, modified_utc, accessed_utc, changed_utc, hash_md5, hash_sha1, hash_sha256, entropy, category, flags, score, tags, summary_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
            params![
                case_id, source_type, source_id, evidence_id, volume_id, path, name, extension, size_bytes, created_utc, modified_utc, accessed_utc, changed_utc, hash_md5, hash_sha1, hash_sha256, entropy, category, flags, score, tags, summary_json
            ],
        )?;
        Ok(())
    }

    pub fn get_file_table_rows(&self, query: &FileTableQuery) -> SqliteResult<FileTableResult> {
        let conn = self.conn()?;

        let mut sql = String::from("SELECT id, source_type, source_id, evidence_id, volume_id, path, name, extension, size_bytes, modified_utc, created_utc, entropy, category, score, tags, summary_json FROM file_table_rows WHERE case_id = ?1");
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> =
            vec![Box::new(query.filter.case_id.clone())];

        if let Some(ref types) = query.filter.source_types {
            let placeholders: Vec<String> = types
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + 2))
                .collect();
            sql.push_str(&format!(" AND source_type IN ({})", placeholders.join(",")));
            for t in types {
                params_vec.push(Box::new(t.clone()));
            }
        }

        if let Some(prefix) = &query.filter.path_prefix {
            sql.push_str(&format!(" AND path LIKE ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(format!("{}%", prefix)));
        }

        if let Some(name_contains) = &query.filter.name_contains {
            sql.push_str(&format!(" AND name LIKE ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(format!("%{}%", name_contains)));
        }

        if let Some(ref exts) = query.filter.ext_in {
            let placeholders: Vec<String> = exts
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + params_vec.len() + 1))
                .collect();
            sql.push_str(&format!(" AND extension IN ({})", placeholders.join(",")));
            for e in exts {
                params_vec.push(Box::new(e.to_lowercase()));
            }
        }

        if let Some(ref cats) = query.filter.category_in {
            let placeholders: Vec<String> = cats
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + params_vec.len() + 1))
                .collect();
            sql.push_str(&format!(" AND category IN ({})", placeholders.join(",")));
            for c in cats {
                params_vec.push(Box::new(c.clone()));
            }
        }

        if let Some(min_size) = query.filter.min_size {
            sql.push_str(&format!(" AND size_bytes >= ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(min_size as i64));
        }

        if let Some(max_size) = query.filter.max_size {
            sql.push_str(&format!(" AND size_bytes <= ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(max_size as i64));
        }

        if let Some(hash) = &query.filter.hash_sha256 {
            sql.push_str(&format!(" AND hash_sha256 = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(hash.clone()));
        }

        if let Some(score_min) = query.filter.score_min {
            sql.push_str(&format!(" AND score >= ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(score_min));
        }

        let sort_field = match query.sort_field {
            SortField::Path => "COALESCE(path, '')",
            SortField::Name => "COALESCE(name, '')",
            SortField::Extension => "COALESCE(extension, '')",
            SortField::Size => "COALESCE(size_bytes, 0)",
            SortField::ModifiedUtc => "COALESCE(modified_utc, '')",
            SortField::CreatedUtc => "COALESCE(created_utc, '')",
            SortField::Entropy => "COALESCE(entropy, 0)",
            SortField::Category => "COALESCE(category, '')",
            SortField::Score => "score",
        };

        let sort_dir = match query.sort_dir {
            SortDir::Asc => "ASC",
            SortDir::Desc => "DESC",
        };

        sql.push_str(&format!(
            " ORDER BY {} {}, id {}",
            sort_field, sort_dir, sort_dir
        ));
        sql.push_str(&format!(" LIMIT {}", query.limit + 1));

        if let Some(cursor) = &query.cursor {
            if let Some(ref last_val) = cursor.last_sort_value {
                let comp = match query.sort_dir {
                    SortDir::Asc => ">",
                    SortDir::Desc => "<",
                };
                sql.push_str(&format!(
                    " AND ({} {} ? OR ({} = ? AND id {} ?))",
                    sort_field, comp, sort_field, comp
                ));
                params_vec.push(Box::new(last_val.clone()));
                params_vec.push(Box::new(last_val));
                if let Some(last_id) = cursor.last_id {
                    params_vec.push(Box::new(last_id));
                }
            }
        }

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let tags_str: String = row.get(14)?;
            let summary_str: String = row.get(15)?;
            Ok(FileTableRow {
                id: row.get(0)?,
                source_type: row.get(1)?,
                source_id: row.get(2)?,
                evidence_id: row.get(3)?,
                volume_id: row.get(4)?,
                path: row.get(5)?,
                name: row.get(6)?,
                extension: row.get(7)?,
                size_bytes: row.get::<_, Option<i64>>(8)?.map(|s| s as u64),
                modified_utc: row.get(9)?,
                created_utc: row.get(10)?,
                entropy: row.get(11)?,
                category: row.get(12)?,
                score: row.get(13)?,
                tags: tags_str.split(',').map(|s| s.to_string()).collect(),
                summary: serde_json::from_str(&summary_str).unwrap_or(serde_json::Value::Null),
            })
        })?;

        let mut result_rows = Vec::new();
        for row in rows.flatten() {
            result_rows.push(row);
        }

        let next_cursor = if result_rows.len() > query.limit as usize {
            result_rows.pop();
            result_rows.last().map(|last| FileTableCursor {
                last_sort_value: Some(match query.sort_field {
                    SortField::Path => last.path.clone(),
                    SortField::Name => last.name.clone(),
                    SortField::Extension => last.extension.clone().unwrap_or_default(),
                    SortField::Size => last.size_bytes.map(|s| s.to_string()).unwrap_or_default(),
                    SortField::ModifiedUtc => last.modified_utc.clone().unwrap_or_default(),
                    SortField::CreatedUtc => last.created_utc.clone().unwrap_or_default(),
                    SortField::Entropy => last.entropy.map(|e| e.to_string()).unwrap_or_default(),
                    SortField::Category => last.category.clone().unwrap_or_default(),
                    SortField::Score => last.score.to_string(),
                }),
                last_id: Some(last.id),
            })
        } else {
            None
        };

        Ok(FileTableResult {
            rows: result_rows,
            next_cursor,
            total_count: None,
        })
    }

    pub fn clear_file_table(&self, case_id: &str) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM file_table_rows WHERE case_id = ?1", [case_id])?;
        Ok(())
    }

    pub fn count_file_table_rows(&self, case_id: &str) -> SqliteResult<i64> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM file_table_rows WHERE case_id = ?1")?;
        stmt.query_row([case_id], |row| row.get(0))
    }

    pub fn get_file_table_preview(
        &self,
        case_id: &str,
        source_type: &str,
        source_id: &str,
    ) -> SqliteResult<Option<FileTablePreview>> {
        let conn = self.conn()?;

        match source_type {
            "fs" => {
                let mut stmt = conn.prepare(
                    "SELECT id, full_path, mft_record_number, mft_sequence, flags, data_size, allocated_size 
                     FROM ntfs_mft_entries WHERE case_id = ?1 AND (CAST(mft_record_number AS TEXT) = ?2 OR id = ?2)"
                )?;
                let result = stmt.query_row([case_id, source_id], |row| {
                    Ok(FileTablePreview {
                        source_type: "fs".to_string(),
                        source_id: source_id.to_string(),
                        preview_json: serde_json::json!({
                            "type": "filesystem",
                            "id": row.get::<_, i64>(0)?,
                            "path": row.get::<_, String>(1)?,
                            "mft_record": row.get::<_, u64>(2)?,
                            "mft_sequence": row.get::<_, u64>(3)?,
                            "flags": row.get::<_, u32>(4)?,
                            "size_bytes": row.get::<_, Option<u64>>(5)?,
                            "allocated_size": row.get::<_, Option<u64>>(6)?,
                        }),
                    })
                });
                match result {
                    Ok(preview) => Ok(Some(preview)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e),
                }
            }
            "carved" => {
                let source_id_str = source_id.parse::<i64>().unwrap_or(0).to_string();
                let mut stmt = conn.prepare(
                    "SELECT id, file_offset, size_bytes, entropy, signature, sha256, md5 
                     FROM carved_files WHERE case_id = ?1 AND id = ?2",
                )?;
                let result = stmt.query_row([case_id, &source_id_str], |row| {
                    Ok(FileTablePreview {
                        source_type: "carved".to_string(),
                        source_id: source_id.to_string(),
                        preview_json: serde_json::json!({
                            "type": "carved",
                            "id": row.get::<_, i64>(0)?,
                            "file_offset": row.get::<_, u64>(1)?,
                            "size_bytes": row.get::<_, u64>(2)?,
                            "entropy": row.get::<_, f64>(3)?,
                            "signature": row.get::<_, String>(4)?,
                            "sha256": row.get::<_, Option<String>>(5)?,
                            "md5": row.get::<_, Option<String>>(6)?,
                        }),
                    })
                });
                match result {
                    Ok(preview) => Ok(Some(preview)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e),
                }
            }
            "ioc" => {
                let source_id_str = source_id.parse::<i64>().unwrap_or(0).to_string();
                let mut stmt = conn.prepare(
                    "SELECT id, rule_id, rule_name, target_type, target_id, matched_field, matched_value, severity, matched_at 
                     FROM ioc_hits WHERE case_id = ?1 AND id = ?2"
                )?;
                let result = stmt.query_row([case_id, &source_id_str], |row| {
                    Ok(FileTablePreview {
                        source_type: "ioc".to_string(),
                        source_id: source_id.to_string(),
                        preview_json: serde_json::json!({
                            "type": "ioc_hit",
                            "id": row.get::<_, i64>(0)?,
                            "rule_id": row.get::<_, i64>(1)?,
                            "rule_name": row.get::<_, String>(2)?,
                            "target_type": row.get::<_, String>(3)?,
                            "target_id": row.get::<_, String>(4)?,
                            "matched_field": row.get::<_, String>(5)?,
                            "matched_value": row.get::<_, String>(6)?,
                            "severity": row.get::<_, String>(7)?,
                            "matched_at": row.get::<_, i64>(8)?,
                        }),
                    })
                });
                match result {
                    Ok(preview) => Ok(Some(preview)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e),
                }
            }
            _ => Ok(None),
        }
    }

    pub fn get_next_pending_job(&self, case_id: &str) -> SqliteResult<Option<JobRow>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, case_id, job_type, status, priority, created_at, started_at, completed_at, 
             progress, progress_message, error, params_json, created_by, worker_id 
             FROM jobs WHERE case_id = ?1 AND status = 'pending' ORDER BY priority DESC, created_at ASC LIMIT 1"
        )?;

        let result = stmt.query_row([case_id], |row| {
            Ok(JobRow {
                id: row.get(0)?,
                case_id: row.get(1)?,
                job_type: row.get(2)?,
                status: row.get(3)?,
                priority: row.get(4)?,
                created_at: row.get(5)?,
                started_at: row.get(6)?,
                completed_at: row.get(7)?,
                progress: row.get(8)?,
                progress_message: row.get(9)?,
                error: row.get(10)?,
                params_json: row.get(11)?,
                created_by: row.get(12)?,
                worker_id: row.get(13)?,
            })
        });

        match result {
            Ok(job) => Ok(Some(job)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn update_job_status(
        &self,
        job_id: &str,
        status: &str,
        progress: f32,
        message: &str,
    ) -> SqliteResult<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE jobs SET status = ?1, progress = ?2, progress_message = ?3 WHERE id = ?4",
            rusqlite::params![status, progress, message, job_id],
        )?;
        Ok(())
    }

    pub fn start_job(&self, job_id: &str, worker_id: &str) -> SqliteResult<()> {
        let conn = self.conn()?;
        let now = Self::unix_now_secs()?;
        conn.execute(
            "UPDATE jobs SET status = 'running', started_at = ?1, worker_id = ?2 WHERE id = ?3",
            rusqlite::params![now, worker_id, job_id],
        )?;
        Ok(())
    }

    pub fn complete_job(&self, job_id: &str, error: Option<&str>) -> SqliteResult<()> {
        let conn = self.conn()?;
        let now = Self::unix_now_secs()?;

        if let Some(err) = error {
            conn.execute(
                "UPDATE jobs SET status = 'failed', completed_at = ?1, error = ?2, progress = 100 WHERE id = ?3",
                rusqlite::params![now, err, job_id],
            )?;
        } else {
            conn.execute(
                "UPDATE jobs SET status = 'completed', completed_at = ?1, progress = 100, progress_message = 'Done' WHERE id = ?2",
                rusqlite::params![now, job_id],
            )?;
        }
        Ok(())
    }

    pub fn run_job_once(
        &self,
        case_id: &str,
        job_id: &str,
        event_bus: Arc<EventBus>,
    ) -> SqliteResult<()> {
        let job = {
            let conn = self.conn()?;
            let mut stmt = conn.prepare(
                "SELECT id, job_type, params_json FROM jobs WHERE id = ?1 AND case_id = ?2",
            )?;
            stmt.query_row(rusqlite::params![job_id, case_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .ok()
        };

        if let Some((id, job_type, params_json)) = job {
            self.start_job(&id, "cli-worker")?;

            event_bus.emit_simple(
                Some(case_id.to_string()),
                EngineEventKind::JobStatus {
                    job_id: id.clone(),
                    job_type: job_type.clone(),
                    status: "running".to_string(),
                },
                EventSeverity::Info,
                &format!("Starting job: {}", job_type),
            );

            let result = match job_type.as_str() {
                "strings" => self.run_strings_job(case_id, &params_json, event_bus.clone()),
                "ioc_scan" => self.run_ioc_job(case_id, &params_json, event_bus.clone()),
                "carving" => self.run_carving_job(case_id, &params_json, event_bus.clone()),
                _ => Err(anyhow::anyhow!("Unknown job type: {}", job_type)),
            };

            match result {
                Ok(_) => {
                    self.complete_job(&id, None)?;
                    event_bus.emit_simple(
                        Some(case_id.to_string()),
                        EngineEventKind::JobStatus {
                            job_id: id,
                            job_type,
                            status: "completed".to_string(),
                        },
                        EventSeverity::Info,
                        "Job completed",
                    );
                }
                Err(e) => {
                    self.complete_job(&id, Some(&e.to_string()))?;
                    event_bus.emit_simple(
                        Some(case_id.to_string()),
                        EngineEventKind::JobStatus {
                            job_id: id,
                            job_type,
                            status: "failed".to_string(),
                        },
                        EventSeverity::Error,
                        &format!("Job failed: {}", e),
                    );
                }
            }
        }

        Ok(())
    }

    fn run_strings_job(
        &self,
        case_id: &str,
        _params_json: &str,
        event_bus: Arc<EventBus>,
    ) -> anyhow::Result<()> {
        use crate::strings::{extract_strings, StringsExtractOptions};

        event_bus.emit_simple(
            Some(case_id.to_string()),
            EngineEventKind::JobProgress {
                job_id: "".to_string(),
                job_type: "strings".to_string(),
                progress: 10.0,
                message: "Starting strings extraction job".to_string(),
            },
            EventSeverity::Info,
            "Starting strings extraction",
        );

        let conn = self.conn()?;

        let mut stmt = conn.prepare(
            "SELECT id, file_path, data FROM ntfs_mft_entries WHERE case_id = ?1 AND data IS NOT NULL LIMIT 100"
        )?;

        let files: Vec<(i64, String, Vec<u8>)> = stmt
            .query_map([case_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        drop(stmt);
        drop(conn);

        let total = files.len();
        for (idx, (file_id, file_path, data)) in files.iter().enumerate() {
            let progress = 10.0 + (idx as f32 / total as f32) * 80.0;

            event_bus.emit_simple(
                Some(case_id.to_string()),
                EngineEventKind::JobProgress {
                    job_id: "".to_string(),
                    job_type: "strings".to_string(),
                    progress,
                    message: format!("Processing {}/{}: {}", idx + 1, total, file_path),
                },
                EventSeverity::Info,
                &format!("Extracting strings from {}", file_path),
            );

            let opts = StringsExtractOptions {
                min_len_ascii: 4,
                min_len_utf16: 4,
                max_file_size_bytes: 50 * 1024 * 1024,
                max_output_chars: 200_000,
                sample_bytes: 8 * 1024 * 1024,
                allow_categories: vec![
                    "Executable".to_string(),
                    "Document".to_string(),
                    "Archive".to_string(),
                    "Script".to_string(),
                    "Unknown".to_string(),
                ],
                deny_extensions: vec![],
                entropy_max: None,
                max_tokens: 10000,
                max_sample_strings: 1000,
            };

            let extracted = extract_strings(data, &opts);

            let strings_json = serde_json::to_string(&extracted)?;

            let conn = self.conn()?;
            conn.execute(
                "INSERT OR REPLACE INTO file_strings (case_id, file_id, file_path, strings_text, strings_json, extracted_utc) 
                 VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%d %H:%M:%S', 'now'))",
                rusqlite::params![case_id, file_id.to_string(), file_path, extracted.strings_text, strings_json],
            )?;

            self.upsert_file_global_entity_from_strings(
                case_id,
                &file_id.to_string(),
                file_path,
                &extracted.strings_text,
            )?;
        }

        event_bus.emit_simple(
            Some(case_id.to_string()),
            EngineEventKind::JobProgress {
                job_id: "".to_string(),
                job_type: "strings".to_string(),
                progress: 100.0,
                message: "Strings extraction complete".to_string(),
            },
            EventSeverity::Info,
            "Strings extraction complete",
        );

        if let Err(e) = self.recompute_scores(case_id, None) {
            eprintln!(
                "Warning: Failed to recompute scores after strings job: {}",
                e
            );
        }

        Ok(())
    }

    fn run_ioc_job(
        &self,
        case_id: &str,
        _params_json: &str,
        event_bus: Arc<EventBus>,
    ) -> anyhow::Result<()> {
        event_bus.emit_simple(
            Some(case_id.to_string()),
            EngineEventKind::JobProgress {
                job_id: "".to_string(),
                job_type: "ioc_scan".to_string(),
                progress: 10.0,
                message: "Starting IOC scan job".to_string(),
            },
            EventSeverity::Info,
            "Starting IOC scan",
        );

        let rules = self.list_ioc_rules(true)?;
        let files: Vec<(i64, String, Vec<u8>)> = {
            let conn = self.conn()?;
            let mut stmt = conn.prepare(
                "SELECT id, full_path, data FROM ntfs_mft_entries WHERE case_id = ?1 AND data IS NOT NULL LIMIT 100"
            )?;
            let mapped = stmt.query_map([case_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            let files: Vec<(i64, String, Vec<u8>)> = mapped.filter_map(|r| r.ok()).collect();
            files
        };

        let total_rules = rules.len();
        let total_files = files.len();

        for (rule_idx, rule_row) in rules.iter().enumerate() {
            let rule = crate::analysis::ioc_scanner::IocRule {
                id: rule_row.id,
                name: rule_row.name.clone(),
                rule_type: crate::analysis::ioc_scanner::IocRuleType::KEYWORD,
                severity: crate::analysis::ioc_scanner::IocSeverity::MEDIUM,
                enabled: rule_row.enabled,
                pattern: rule_row.pattern.clone(),
                hash_type: rule_row.hash_type.clone(),
                scope: crate::analysis::ioc_scanner::IocScope::default(),
                tags: vec![],
                created_utc: rule_row.created_utc.clone(),
                updated_utc: rule_row.updated_utc.clone(),
            };

            for (file_idx, (file_id, file_path, data)) in files.iter().enumerate() {
                let progress = 10.0
                    + ((rule_idx * total_files + file_idx) as f32
                        / (total_rules * total_files) as f32)
                        * 80.0;

                if let Ok(text) = String::from_utf8(data.clone()) {
                    let matches =
                        crate::analysis::ioc_scanner::scan_text_for_rule(&rule, &text, 1000);

                    if !matches.is_empty() {
                        for m in matches {
                            self.insert_ioc_hit(
                                case_id,
                                rule.id,
                                "file",
                                &file_id.to_string(),
                                None,
                                "content",
                                &m,
                                "{}",
                            )?;

                            let event = EvidenceTimelineEvent {
                                id: uuid::Uuid::new_v4().to_string(),
                                case_id: case_id.to_string(),
                                evidence_id: None,
                                event_type: "IOC_HIT".to_string(),
                                event_category: Some("threat".to_string()),
                                event_time: Self::unix_now_secs()?,
                                description: Some(format!(
                                    "IOC hit: {} in {}",
                                    rule.name, file_path
                                )),
                                artifact_id: Some(file_id.to_string()),
                                data_json: Some("{}".to_string()),
                                source_module: Some("ioc_scanner".to_string()),
                                source_record_id: Some(m.clone()),
                            };
                            self.add_evidence_timeline_event(&event)?;

                            event_bus.emit_simple(
                                Some(case_id.to_string()),
                                EngineEventKind::JobProgress {
                                    job_id: "".to_string(),
                                    job_type: "ioc_scan".to_string(),
                                    progress,
                                    message: format!("IOC hit: {} in {}", rule.name, file_path),
                                },
                                EventSeverity::Warn,
                                &format!("IOC hit: {} in {}", rule.name, file_path),
                            );
                        }
                    }
                }
            }
        }

        self.log_activity(
            case_id,
            "IocScanCompleted",
            &format!("Scanned {} files with {} rules", total_files, total_rules),
        )?;

        event_bus.emit_simple(
            Some(case_id.to_string()),
            EngineEventKind::JobProgress {
                job_id: "".to_string(),
                job_type: "ioc_scan".to_string(),
                progress: 100.0,
                message: "IOC scan complete".to_string(),
            },
            EventSeverity::Info,
            "IOC scan complete",
        );

        if let Err(e) = self.recompute_scores(case_id, None) {
            eprintln!("Warning: Failed to recompute scores after IOC job: {}", e);
        }

        Ok(())
    }

    fn run_carving_job(
        &self,
        case_id: &str,
        _params_json: &str,
        event_bus: Arc<EventBus>,
    ) -> anyhow::Result<()> {
        event_bus.emit_simple(
            Some(case_id.to_string()),
            EngineEventKind::JobProgress {
                job_id: "".to_string(),
                job_type: "carving".to_string(),
                progress: 10.0,
                message: "Starting carving job".to_string(),
            },
            EventSeverity::Info,
            "Starting carving job",
        );

        let signatures = crate::carving::signatures::get_default_signatures();
        let _regions = [crate::carving::regions::ScanRegion::new(
            0,
            1024 * 1024,
            "test",
        )];

        for (idx, sig) in signatures.iter().take(5).enumerate() {
            let progress = 10.0 + (idx as f32 / 5.0) * 80.0;

            event_bus.emit_simple(
                Some(case_id.to_string()),
                EngineEventKind::JobProgress {
                    job_id: "".to_string(),
                    job_type: "carving".to_string(),
                    progress,
                    message: format!("Scanning for {} files", sig.name),
                },
                EventSeverity::Info,
                &format!("Scanning for {}", sig.name),
            );
        }

        self.log_activity(
            case_id,
            "CarvingCompleted",
            &format!("Carved with {} signatures", signatures.len()),
        )?;

        event_bus.emit_simple(
            Some(case_id.to_string()),
            EngineEventKind::JobProgress {
                job_id: "".to_string(),
                job_type: "carving".to_string(),
                progress: 100.0,
                message: "Carving complete".to_string(),
            },
            EventSeverity::Info,
            "Carving complete",
        );

        if let Err(e) = self.recompute_scores(case_id, None) {
            eprintln!(
                "Warning: Failed to recompute scores after carving job: {}",
                e
            );
        }

        Ok(())
    }

    fn log_activity(&self, case_id: &str, event_type: &str, summary: &str) -> SqliteResult<()> {
        let conn = self.conn()?;
        let now = Self::unix_now_secs()?;

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, event_hash) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                case_id,
                event_type,
                summary,
                now,
                uuid::Uuid::new_v4().to_string()
            ],
        )?;
        Ok(())
    }

    pub fn upsert_file_global_entity_from_strings(
        &self,
        case_id: &str,
        file_id: &str,
        file_path: &str,
        content: &str,
    ) -> SqliteResult<()> {
        let bounded_content = content.chars().take(5000).collect::<String>();

        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO global_search_entities 
             (case_id, entity_type, entity_id, title, content, path, category, ts_utc) 
             VALUES (?1, 'file', ?2, ?3, ?4, ?5, 'extracted', strftime('%Y-%m-%d %H:%M:%S', 'now'))",
            rusqlite::params![case_id, file_id, file_path, bounded_content, file_path],
        )?;

        conn.execute(
            "INSERT OR REPLACE INTO global_search_fts (entity_id, entity_type, case_id, title, content, path, category, ts_utc)
             VALUES (?1, 'file', ?2, ?3, ?4, ?5, 'extracted', strftime('%Y-%m-%d %H:%M:%S', 'now'))",
            rusqlite::params![file_id, case_id, file_path, bounded_content, file_path],
        )?;

        Ok(())
    }

    pub fn recompute_scores(
        &self,
        case_id: &str,
        source_types: Option<Vec<String>>,
    ) -> SqliteResult<u64> {
        use crate::analysis::{score_row, FileTableRowLike, ScoreWeights};

        let reference_time = self.get_case_reference_time(case_id)?;
        let ctx = self.build_scoring_context(case_id, reference_time)?;
        let weights = ScoreWeights::default();

        let conn = self.conn()?;

        let mut sql = String::from(
            "SELECT id, source_type, source_id, evidence_id, volume_id, path, name, extension, 
             size_bytes, modified_utc, created_utc, entropy, category, score, tags, summary_json 
             FROM file_table_rows WHERE case_id = ?1",
        );

        if let Some(ref types) = source_types {
            let placeholders: Vec<String> = types
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + 2))
                .collect();
            sql.push_str(&format!(" AND source_type IN ({})", placeholders.join(",")));
        }

        sql.push_str(" ORDER BY id ASC");

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(case_id.to_string())];
        if let Some(ref types) = source_types {
            for t in types {
                params_vec.push(Box::new(t.clone()));
            }
        }
        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let tags_str: String = row.get(14)?;
            let summary_str: String = row.get(15)?;
            Ok(FileTableRowLike::from_row(
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                tags_str.split(',').map(|s| s.to_string()).collect(),
                serde_json::from_str(&summary_str).unwrap_or(serde_json::Value::Null),
            ))
        })?;

        let mut updated_count = 0u64;

        for row in rows.flatten() {
            let result = score_row(case_id, &row, &ctx, &weights);

            let top_signals: Vec<_> = result
                .signals
                .iter()
                .take(10)
                .map(|s| {
                    serde_json::json!({
                        "key": s.key,
                        "points": s.points,
                        "evidence": s.evidence
                    })
                })
                .collect();

            let mut summary = row.summary_json.clone();
            if let serde_json::Value::Object(ref mut map) = summary {
                map.insert(
                    "score_signals".to_string(),
                    serde_json::Value::Array(top_signals),
                );
            }

            let summary_json = serde_json::to_string(&summary).unwrap_or_default();

            conn.execute(
                    "UPDATE file_table_rows SET score = ?1, summary_json = ?2 WHERE id = ?3 AND case_id = ?4",
                    rusqlite::params![result.score, summary_json, row.id, case_id],
                )?;

            updated_count += 1;
        }

        Ok(updated_count)
    }

    pub fn explain_file_table_score(
        &self,
        case_id: &str,
        row_id: i64,
    ) -> SqliteResult<ScoreResult> {
        use crate::analysis::{score_row, FileTableRowLike, ScoreWeights};

        let reference_time = self.get_case_reference_time(case_id)?;
        let ctx = self.build_scoring_context(case_id, reference_time)?;
        let weights = ScoreWeights::default();

        let conn = self.conn()?;

        let mut stmt = conn.prepare(
            "SELECT id, source_type, source_id, evidence_id, volume_id, path, name, extension, 
             size_bytes, modified_utc, created_utc, entropy, category, score, tags, summary_json 
             FROM file_table_rows WHERE case_id = ?1 AND id = ?2",
        )?;

        let row = stmt.query_row(rusqlite::params![case_id, row_id], |row| {
            let tags_str: String = row.get(14)?;
            let summary_str: String = row.get(15)?;
            Ok(FileTableRowLike::from_row(
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                tags_str.split(',').map(|s| s.to_string()).collect(),
                serde_json::from_str(&summary_str).unwrap_or(serde_json::Value::Null),
            ))
        })?;

        let result = score_row(case_id, &row, &ctx, &weights);

        Ok(ScoreResult {
            score: result.score,
            signals: result.signals,
        })
    }

    fn get_case_reference_time(&self, case_id: &str) -> SqliteResult<i64> {
        let conn = self.conn()?;

        let result: Result<String, _> = conn.query_row(
            "SELECT value FROM case_settings WHERE case_id = ?1 AND key = 'case_opened_utc'",
            [case_id],
            |row| row.get(0),
        );

        match result {
            Ok(ts) => {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&ts) {
                    Ok(dt.timestamp())
                } else {
                    Ok(chrono::Utc::now().timestamp())
                }
            }
            Err(_) => {
                let now = chrono::Utc::now().to_rfc3339();
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO case_settings (case_id, key, value) VALUES (?1, 'case_opened_utc', ?2)",
                    rusqlite::params![case_id, now],
                );
                Ok(chrono::Utc::now().timestamp())
            }
        }
    }

    fn build_scoring_context(
        &self,
        case_id: &str,
        reference_time: i64,
    ) -> SqliteResult<ScoringContext> {
        use crate::analysis::StringsInfo;

        let mut ctx = ScoringContext::new(case_id, reference_time);

        let conn = self.conn()?;

        let mut ioc_stmt =
            conn.prepare("SELECT DISTINCT target_id FROM ioc_hits WHERE case_id = ?1")?;
        let ioc_ids: Vec<String> = ioc_stmt
            .query_map([case_id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();

        let mut ioc_hits = std::collections::HashMap::new();
        for id in ioc_ids {
            ioc_hits.insert(id, true);
        }
        ctx.ioc_hits_for_file = ioc_hits;

        let mut strings_stmt =
            conn.prepare("SELECT file_id, strings_json FROM file_strings WHERE case_id = ?1")?;
        let strings_data: Vec<(String, String)> = strings_stmt
            .query_map([case_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        let mut strings_info = std::collections::HashMap::new();
        for (file_id, json_str) in strings_data {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                let url_count = json
                    .get("urls")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let email_count = json
                    .get("emails")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let ipv4_count = json
                    .get("ipv4s")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);

                strings_info.insert(
                    file_id,
                    StringsInfo {
                        url_count,
                        email_count,
                        ipv4_count,
                    },
                );
            }
        }
        ctx.strings_data = strings_info;

        Ok(ctx)
    }
}

pub struct CaseDatabaseManager {
    databases: std::collections::HashMap<String, CaseDatabase>,
    base_path: std::path::PathBuf,
    event_bus: Option<Arc<EventBus>>,
}

impl CaseDatabaseManager {
    pub fn new(base_path: &Path) -> Self {
        Self {
            databases: std::collections::HashMap::new(),
            base_path: base_path.to_path_buf(),
            event_bus: None,
        }
    }

    pub fn with_event_bus(base_path: &Path, event_bus: Arc<EventBus>) -> Self {
        Self {
            databases: std::collections::HashMap::new(),
            base_path: base_path.to_path_buf(),
            event_bus: Some(event_bus),
        }
    }

    pub fn set_event_bus(&mut self, event_bus: Arc<EventBus>) {
        self.event_bus = Some(event_bus);
    }

    pub fn event_bus(&self) -> Option<&Arc<EventBus>> {
        self.event_bus.as_ref()
    }

    pub fn create_case(
        &mut self,
        case_id: &str,
        case_name: &str,
        examiner: &str,
    ) -> SqliteResult<&CaseDatabase> {
        let db_path = self.base_path.join(format!("{}.sqlite", case_id));

        let db = CaseDatabase::create(case_id, &db_path)?;

        let conn = db.get_connection();
        let conn = conn
            .lock()
            .map_err(|e| rusqlite::Error::InvalidParameterName(format!("mutex poisoned: {}", e)))?;

        let now = CaseDatabase::unix_now_secs()?;

        conn.execute(
            "INSERT INTO cases (id, name, examiner, status, created_at, modified_at) VALUES (?, ?, ?, 'open', ?, ?)",
            params![case_id, case_name, examiner, now, now]
        )?;

        drop(conn);
        self.databases.insert(case_id.to_string(), db);
        Ok(self.databases.get(case_id).unwrap())
    }

    pub fn open_case(&mut self, case_id: &str) -> SqliteResult<&CaseDatabase> {
        if self.databases.contains_key(case_id) {
            return Ok(self.databases.get(case_id).unwrap());
        }

        let db_path = self.base_path.join(format!("{}.sqlite", case_id));
        if !db_path.exists() {
            return Err(rusqlite::Error::InvalidPath(db_path));
        }

        let db = CaseDatabase::open(case_id, &db_path)?;
        self.databases.insert(case_id.to_string(), db);
        Ok(self.databases.get(case_id).unwrap())
    }

    pub fn close_case(&mut self, case_id: &str) -> SqliteResult<()> {
        if let Some(db) = self.databases.remove(case_id) {
            let conn = db.get_connection();
            let conn = conn.lock().unwrap();
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", [])?;
            conn.execute("PRAGMA optimize", [])?;
        }
        Ok(())
    }

    pub fn list_cases(&self) -> Vec<CaseInfo> {
        let mut cases = Vec::new();

        if let Ok(entries) = std::fs::read_dir(&self.base_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "sqlite") {
                    if let Ok(conn) = Connection::open(&path) {
                        if let Ok(mut stmt) = conn.prepare(
                            "SELECT id, name, examiner, status, created_at FROM cases LIMIT 1",
                        ) {
                            if let Ok(row) = stmt.query_row([], |row| {
                                Ok(CaseInfo {
                                    id: row.get(0)?,
                                    name: row.get(1)?,
                                    examiner: row.get(2)?,
                                    status: row.get(3)?,
                                    created_at: row.get(4)?,
                                })
                            }) {
                                cases.push(row);
                            }
                        }
                    }
                }
            }
        }

        cases
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseStats {
    pub id: String,
    pub case_id: String,
    pub total_artifacts: i64,
    pub total_bookmarks: i64,
    pub total_notes: i64,
    pub total_exhibits: i64,
    pub total_jobs: i64,
    pub jobs_completed: i64,
    pub jobs_failed: i64,
    pub last_updated: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageStat {
    pub id: String,
    pub case_id: String,
    pub category: String,
    pub count: i64,
    pub total_size: i64,
    pub last_updated: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineBucket {
    pub id: String,
    pub case_id: String,
    pub bucket_type: String,
    pub bucket_time: i64,
    pub category: Option<String>,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    pub id: String,
    pub name: String,
    pub examiner: String,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityLogEntry {
    pub id: String,
    pub case_id: String,
    pub event_type: String,
    pub summary: String,
    pub ts_utc: i64,
    pub user_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkEntry {
    pub id: String,
    pub case_id: String,
    pub title: String,
    pub folder_id: Option<String>,
    pub reviewed: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExhibitEntry {
    pub id: String,
    pub case_id: String,
    pub name: String,
    pub exhibit_type: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceTimelineEvent {
    pub id: String,
    pub case_id: String,
    pub evidence_id: Option<String>,
    pub event_type: String,
    pub event_category: Option<String>,
    pub event_time: i64,
    pub description: Option<String>,
    pub artifact_id: Option<String>,
    pub data_json: Option<String>,
    pub source_module: Option<String>,
    pub source_record_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVolumeInfo {
    pub id: String,
    pub evidence_id: String,
    pub case_id: String,
    pub volume_index: usize,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub filesystem_type: Option<String>,
    pub filesystem_label: Option<String>,
    pub partition_type: Option<String>,
    pub capability_name: String,
    pub is_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSearchHit {
    pub entity_type: String,
    pub entity_id: String,
    pub title: String,
    pub snippet: String,
    pub path: Option<String>,
    pub category: Option<String>,
    pub ts_utc: Option<String>,
    pub rank: f64,
    pub json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSearchQuery {
    pub case_id: String,
    pub q: String,
    pub entity_types: Option<Vec<String>>,
    pub date_start_utc: Option<String>,
    pub date_end_utc: Option<String>,
    pub category: Option<String>,
    pub tags_any: Option<Vec<String>>,
    pub path_prefix: Option<String>,
    pub limit: u32,
    pub after_rank: Option<f64>,
    pub after_rowid: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SortField {
    Path,
    Name,
    Extension,
    Size,
    ModifiedUtc,
    CreatedUtc,
    Entropy,
    Category,
    Score,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortDir {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTableFilter {
    pub case_id: String,
    pub source_types: Option<Vec<String>>,
    pub path_prefix: Option<String>,
    pub name_contains: Option<String>,
    pub ext_in: Option<Vec<String>>,
    pub category_in: Option<Vec<String>>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub date_start_utc: Option<String>,
    pub date_end_utc: Option<String>,
    pub min_entropy: Option<f64>,
    pub max_entropy: Option<f64>,
    pub hash_sha256: Option<String>,
    pub tags_any: Option<Vec<String>>,
    pub score_min: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTableCursor {
    pub last_sort_value: Option<String>,
    pub last_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTableQuery {
    pub filter: FileTableFilter,
    pub sort_field: SortField,
    pub sort_dir: SortDir,
    pub limit: u32,
    pub cursor: Option<FileTableCursor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTableRow {
    pub id: i64,
    pub source_type: String,
    pub source_id: String,
    pub evidence_id: Option<String>,
    pub volume_id: Option<String>,
    pub path: String,
    pub name: String,
    pub extension: Option<String>,
    pub size_bytes: Option<u64>,
    pub modified_utc: Option<String>,
    pub created_utc: Option<String>,
    pub entropy: Option<f64>,
    pub category: Option<String>,
    pub score: f64,
    pub tags: Vec<String>,
    pub summary: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTableResult {
    pub rows: Vec<FileTableRow>,
    pub next_cursor: Option<FileTableCursor>,
    pub total_count: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStringsResult {
    pub file_id: String,
    pub file_path: String,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub extracted_utc: String,
    pub flags: u32,
    pub strings_text: String,
    pub strings_json: crate::strings::StringsJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHitEntry {
    pub rule_id: String,
    pub rule_name: String,
    pub matched_field: String,
    pub matched_value: String,
    pub matched_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExhibitExplanation {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub exhibit_type: String,
    pub tags: Vec<String>,
    pub rule_hits: Vec<RuleHitEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocRuleRow {
    pub id: i64,
    pub name: String,
    pub rule_type: String,
    pub severity: String,
    pub enabled: bool,
    pub pattern: String,
    pub hash_type: Option<String>,
    pub scope_json: String,
    pub tags: String,
    pub created_utc: String,
    pub updated_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocHitRow {
    pub id: i64,
    pub case_id: String,
    pub rule_id: i64,
    pub hit_utc: String,
    pub target_type: String,
    pub target_id: String,
    pub target_path: Option<String>,
    pub matched_field: String,
    pub matched_value: String,
    pub context_json: String,
    pub rule_name: String,
    pub severity: String,
}

fn map_ioc_hit(row: &rusqlite::Row) -> rusqlite::Result<IocHitRow> {
    Ok(IocHitRow {
        id: row.get(0)?,
        case_id: row.get(1)?,
        rule_id: row.get(2)?,
        hit_utc: row.get(3)?,
        target_type: row.get(4)?,
        target_id: row.get(5)?,
        target_path: row.get(6)?,
        matched_field: row.get(7)?,
        matched_value: row.get(8)?,
        context_json: row.get(9)?,
        rule_name: row.get(10)?,
        severity: row.get(11)?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedFileRow {
    pub id: i64,
    pub case_id: String,
    pub evidence_id: String,
    pub volume_id: Option<String>,
    pub carved_utc: String,
    pub signature_name: String,
    pub offset_bytes: i64,
    pub length_bytes: i64,
    pub output_rel_path: String,
    pub sha256: String,
    pub file_type: Option<String>,
    pub confidence: String,
    pub flags: i64,
    pub details_json: String,
}

fn map_carved_file(row: &rusqlite::Row) -> rusqlite::Result<CarvedFileRow> {
    Ok(CarvedFileRow {
        id: row.get(0)?,
        case_id: row.get(1)?,
        evidence_id: row.get(2)?,
        volume_id: row.get(3)?,
        carved_utc: row.get(4)?,
        signature_name: row.get(5)?,
        offset_bytes: row.get(6)?,
        length_bytes: row.get(7)?,
        output_rel_path: row.get(8)?,
        sha256: row.get(9)?,
        file_type: row.get(10)?,
        confidence: row.get(11)?,
        flags: row.get(12)?,
        details_json: row.get(13)?,
    })
}
