//! VTP case file (.vtp) — SQLite database.

use anyhow::{Context, Result};
use rusqlite::{types::ValueRef, Connection};
use std::path::Path;

pub struct VtpProject {
    pub conn: Connection,
    pub case_name: String,
}

type CompareLoadRecord = (crate::state::EvidenceDiff, Option<String>, Option<String>);

impl VtpProject {
    pub fn create(path: impl AsRef<Path>, case_name: &str, examiner: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&path)
            .with_context(|| format!("Cannot create case file: {}", path.display()))?;

        conn.execute_batch(SCHEMA)?;
        let project_for_index = Self {
            conn,
            case_name: case_name.to_string(),
        };
        project_for_index.ensure_required_indexes()?;
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        project_for_index.conn.execute(
            "INSERT INTO case_metadata (key, value) VALUES ('case_name', ?1)",
            rusqlite::params![case_name],
        )?;
        project_for_index.conn.execute(
            "INSERT INTO case_metadata (key, value) VALUES ('examiner', ?1)",
            rusqlite::params![examiner],
        )?;
        project_for_index.conn.execute(
            "INSERT INTO case_metadata (key, value) VALUES ('created_utc', ?1)",
            rusqlite::params![now],
        )?;
        project_for_index.conn.execute(
            "INSERT INTO case_metadata (key, value) VALUES ('schema_version', '3')",
            [],
        )?;
        project_for_index.conn.execute(
            "INSERT INTO activity_log (id, examiner_id, timestamp_utc, action_type, description)
             VALUES (?1, ?2, ?3, 'SESSION_START', 'Case created')",
            rusqlite::params![uuid::Uuid::new_v4().to_string(), examiner, now],
        )?;

        Ok(project_for_index)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path)
            .with_context(|| format!("Cannot open case: {}", path.display()))?;
        // Run schema to add any missing tables/columns from newer versions.
        let _ = conn.execute_batch(SCHEMA);
        let mut project = Self {
            conn,
            case_name: String::new(),
        };
        let _ = project.ensure_required_indexes();
        let case_name: String = project
            .conn
            .query_row(
                "SELECT value FROM case_metadata WHERE key='case_name'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_default();
        project.case_name = case_name;
        Ok(project)
    }

    /// Save all evidence sources to the VTP file.
    pub fn save_evidence_sources(&self, sources: &[crate::state::EvidenceSource]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM evidence_sources", [])?;
        for src in sources {
            tx.execute(
                "INSERT INTO evidence_sources (id, path, format, sha256, hash_verified, loaded_utc, size_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![src.id, src.path, src.format, src.sha256, src.hash_verified as i32,
                                  src.loaded_utc, src.size_bytes.map(|s| s as i64)],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Save file index to the VTP file in batches.
    pub fn save_file_index(&self, files: &[crate::state::FileEntry]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM file_index", [])?;
        for f in files {
            tx.execute(
                "INSERT INTO file_index (id, evidence_id, path, vfs_path, parent_path, name, extension,
                 size, is_dir, is_deleted, is_carved, is_system, is_hidden,
                 created_utc, modified_utc, accessed_utc, mft_record, md5, sha256, category, hash_flag, signature)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
                rusqlite::params![
                    f.id, f.evidence_id, f.path, f.vfs_path, f.parent_path, f.name, f.extension,
                    f.size.map(|s| s as i64), f.is_dir as i32, f.is_deleted as i32,
                    f.is_carved as i32, f.is_system as i32, f.is_hidden as i32,
                    f.created_utc, f.modified_utc, f.accessed_utc,
                    f.mft_record.map(|m| m as i64), f.md5, f.sha256, f.category, f.hash_flag, f.signature,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn save_bookmarks(&self, bookmarks: &[crate::state::Bookmark]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM bookmarks", [])?;
        for bm in bookmarks {
            tx.execute(
                "INSERT INTO bookmarks (id, file_id, registry_path, tag, examiner_id, note, created_utc)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    bm.id,
                    bm.file_id,
                    bm.registry_path,
                    bm.tag,
                    bm.examiner,
                    bm.note,
                    bm.created_utc
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn save_audit_log(&self, entries: &[crate::state::AuditEntry]) -> Result<()> {
        self.ensure_audit_log_columns()?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM audit_log", [])?;
        for e in entries {
            tx.execute(
                "INSERT INTO audit_log (
                    id, sequence, timestamp_utc, examiner_id, action_type, detail, evidence_id, file_path, prev_hash, entry_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    e.id,
                    e.sequence as i64,
                    e.timestamp_utc,
                    e.examiner,
                    e.action,
                    e.detail,
                    e.evidence_id,
                    e.file_path,
                    e.prev_hash,
                    e.entry_hash,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_audit_log(&self) -> Result<Vec<crate::state::AuditEntry>> {
        self.ensure_audit_log_columns()?;
        let mut stmt = self.conn.prepare(
            "SELECT id, COALESCE(sequence, 0), timestamp_utc, examiner_id, action_type,
                    COALESCE(detail, ''), evidence_id, file_path,
                    COALESCE(prev_hash, ''), COALESCE(entry_hash, '')
             FROM audit_log
             ORDER BY sequence ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::state::AuditEntry {
                id: r.get(0)?,
                sequence: r.get::<_, i64>(1)?.max(0) as u64,
                timestamp_utc: r.get(2)?,
                examiner: r.get(3)?,
                action: r.get(4)?,
                detail: r.get(5)?,
                evidence_id: r.get(6)?,
                file_path: r.get(7)?,
                prev_hash: r.get(8)?,
                entry_hash: r.get(9)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn load_bookmarks(&self) -> Result<Vec<crate::state::Bookmark>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, file_id, registry_path, tag, examiner_id, note, created_utc FROM bookmarks",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::state::Bookmark {
                id: r.get(0)?,
                file_id: r.get(1)?,
                registry_path: r.get(2)?,
                tag: r.get(3)?,
                examiner: r.get(4)?,
                note: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                created_utc: r.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn save_search_results(&self, hits: &[crate::state::SearchHit]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM search_results", [])?;
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        for hit in hits {
            tx.execute(
                "INSERT INTO search_results (id, file_id, query, context, hit_type, searched_utc)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(),
                    hit.file_id,
                    hit.query,
                    hit.context,
                    hit.hit_type,
                    now,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_search_results(&self) -> Result<Vec<crate::state::SearchHit>> {
        let mut stmt = self.conn.prepare(
            "SELECT file_id, query, context, COALESCE(hit_type, '')
             FROM search_results
             ORDER BY searched_utc DESC, rowid DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::state::SearchHit {
                file_id: r.get(0)?,
                query: r.get(1)?,
                context: r.get(2)?,
                hit_type: r.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Load evidence sources from the VTP file.
    pub fn load_evidence_sources(&self) -> Result<Vec<crate::state::EvidenceSource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, path, format, sha256, hash_verified, loaded_utc, size_bytes FROM evidence_sources"
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::state::EvidenceSource {
                id: r.get(0)?,
                path: r.get(1)?,
                format: r.get(2)?,
                sha256: r.get(3)?,
                hash_verified: r.get::<_, i32>(4)? != 0,
                loaded_utc: r.get(5)?,
                size_bytes: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
            })
        })?;
        let mut sources = Vec::new();
        for row in rows {
            sources.push(row?);
        }
        Ok(sources)
    }

    /// Load file index from the VTP file.
    pub fn load_file_index(&self) -> Result<Vec<crate::state::FileEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, evidence_id, path, COALESCE(vfs_path,''), COALESCE(parent_path,''), name, extension,
                    size, is_dir, is_deleted, is_carved, COALESCE(is_system,0), COALESCE(is_hidden,0),
                    created_utc, modified_utc, accessed_utc, mft_record, md5, sha256, category, hash_flag,
                    COALESCE(signature,NULL)
             FROM file_index"
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::state::FileEntry {
                id: r.get(0)?,
                evidence_id: r.get(1)?,
                path: r.get(2)?,
                vfs_path: r.get(3)?,
                parent_path: r.get(4)?,
                name: r.get(5)?,
                extension: r.get(6)?,
                size: r.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                is_dir: r.get::<_, i32>(8)? != 0,
                is_deleted: r.get::<_, i32>(9)? != 0,
                is_carved: r.get::<_, i32>(10)? != 0,
                is_system: r.get::<_, i32>(11)? != 0,
                is_hidden: r.get::<_, i32>(12)? != 0,
                created_utc: r.get(13)?,
                modified_utc: r.get(14)?,
                accessed_utc: r.get(15)?,
                mft_record: r.get::<_, Option<i64>>(16)?.map(|v| v as u64),
                md5: r.get(17)?,
                sha256: r.get(18)?,
                category: r.get(19)?,
                hash_flag: r.get(20)?,
                signature: r.get(21)?,
            })
        })?;
        let mut files = Vec::new();
        for row in rows {
            files.push(row?);
        }
        Ok(files)
    }

    /// Get metadata value by key.
    pub fn get_meta(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM case_metadata WHERE key=?1",
                rusqlite::params![key],
                |r| r.get(0),
            )
            .ok()
    }

    /// Set metadata value.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO case_metadata (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    pub fn get_ui_pref(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM ui_prefs WHERE key=?1",
                rusqlite::params![key],
                |r| r.get(0),
            )
            .ok()
    }

    pub fn set_ui_pref(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO ui_prefs (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    pub fn save_compare_result(
        &self,
        evidence_a: Option<&str>,
        evidence_b: Option<&str>,
        compare_result: Option<&crate::state::EvidenceDiff>,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM compare_results", [])?;
        if let Some(diff) = compare_result {
            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let result_json = serde_json::to_string(diff).unwrap_or_else(|_| "{}".to_string());
            tx.execute(
                "INSERT INTO compare_results (id, evidence_a, evidence_b, result_json, run_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(),
                    evidence_a.unwrap_or(""),
                    evidence_b.unwrap_or(""),
                    result_json,
                    now
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_latest_compare_result(&self) -> Result<Option<CompareLoadRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT evidence_a, evidence_b, result_json
             FROM compare_results
             ORDER BY run_at DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        let evidence_a: String = row.get(0)?;
        let evidence_b: String = row.get(1)?;
        let result_json: String = row.get(2)?;
        let parsed = serde_json::from_str::<crate::state::EvidenceDiff>(&result_json).ok();
        Ok(parsed.map(|diff| {
            let a = if evidence_a.trim().is_empty() {
                None
            } else {
                Some(evidence_a)
            };
            let b = if evidence_b.trim().is_empty() {
                None
            } else {
                Some(evidence_b)
            };
            (diff, a, b)
        }))
    }

    pub fn save_hash_set_refs(&self, items: &[crate::state::HashSetListItem]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM hash_set_refs", [])?;
        for item in items {
            tx.execute(
                "INSERT INTO hash_set_refs (id, name, path, category, entry_count)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(),
                    item.name,
                    item.source,
                    item.category,
                    item.entry_count as i64
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_hash_set_refs(&self) -> Result<Vec<crate::state::HashSetListItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, category, path, COALESCE(entry_count, 0)
             FROM hash_set_refs
             ORDER BY name ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::state::HashSetListItem {
                name: r.get(0)?,
                category: r.get(1)?,
                source: r.get(2)?,
                entry_count: r.get::<_, i64>(3)?.max(0) as usize,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn save_hash_sets(&self, items: &[crate::state::HashSetListItem]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM hash_sets", [])?;
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        for item in items {
            tx.execute(
                "INSERT INTO hash_sets (id, name, category, source_path, loaded_utc)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(),
                    item.name,
                    item.category,
                    item.source,
                    now,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_hash_sets(&self) -> Result<Vec<crate::state::HashSetListItem>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, category, source_path FROM hash_sets ORDER BY loaded_utc ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok(crate::state::HashSetListItem {
                name: r.get(0)?,
                category: r.get(1)?,
                source: r.get(2)?,
                entry_count: 0,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn compute_integrity_hash(&self) -> Result<String> {
        use sha2::Digest;

        let mut hasher = sha2::Sha256::new();
        let mut tables_stmt = self.conn.prepare(
            "SELECT name FROM sqlite_master
             WHERE type='table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name ASC",
        )?;
        let table_rows = tables_stmt.query_map([], |r| r.get::<_, String>(0))?;

        for table_row in table_rows {
            let table_name = table_row?;
            hasher.update(format!("table:{}\n", table_name).as_bytes());

            let quoted_table = quote_identifier(&table_name);
            let pragma_sql = format!("PRAGMA table_info({})", quoted_table);
            let mut cols_stmt = self.conn.prepare(&pragma_sql)?;
            let cols_rows = cols_stmt.query_map([], |r| r.get::<_, String>(1))?;
            let mut columns = Vec::<String>::new();
            for col in cols_rows {
                columns.push(col?);
            }
            if columns.is_empty() {
                continue;
            }

            let quoted_cols: Vec<String> = columns.iter().map(|c| quote_identifier(c)).collect();
            let select_cols = quoted_cols.join(", ");
            let order_cols = quoted_cols.join(", ");
            let where_clause = if table_name.eq_ignore_ascii_case("case_metadata") {
                " WHERE key <> 'case_integrity_hash' "
            } else {
                ""
            };
            let query_sql = format!(
                "SELECT {} FROM {}{}ORDER BY {}",
                select_cols, quoted_table, where_clause, order_cols
            );
            let mut rows_stmt = self.conn.prepare(&query_sql)?;
            let mut rows = rows_stmt.query([])?;

            while let Some(row) = rows.next()? {
                for idx in 0..columns.len() {
                    let value = row.get_ref(idx)?;
                    hasher.update(value_ref_bytes(value));
                    hasher.update(b"|");
                }
                hasher.update(b"\n");
            }
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn save_timeline_entries(&self, entries: &[crate::state::TimelineEntry]) -> Result<()> {
        self.ensure_timeline_entries_columns()?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM timeline_entries", [])?;
        for entry in entries {
            let event_type = match entry.event_type {
                crate::state::TimelineEventType::FileCreated => "FileCreated",
                crate::state::TimelineEventType::FileModified => "FileModified",
                crate::state::TimelineEventType::FileAccessed => "FileAccessed",
                crate::state::TimelineEventType::FileMftModified => "FileMftModified",
                crate::state::TimelineEventType::FileDeleted => "FileDeleted",
                crate::state::TimelineEventType::RegistryKeyCreated => "RegistryKeyCreated",
                crate::state::TimelineEventType::RegistryKeyModified => "RegistryKeyModified",
                crate::state::TimelineEventType::RegistryValueSet => "RegistryValueSet",
                crate::state::TimelineEventType::ProcessExecuted => "ProcessExecuted",
                crate::state::TimelineEventType::UserLogin => "UserLogin",
                crate::state::TimelineEventType::UserActivity => "UserActivity",
                crate::state::TimelineEventType::WebVisit => "WebVisit",
            };
            tx.execute(
                "INSERT INTO timeline_entries
                 (id, timestamp_utc, event_type, path, evidence_id, detail, file_id, suspicious)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(),
                    entry
                        .timestamp
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    event_type,
                    entry.path,
                    entry.evidence_id,
                    entry.detail,
                    entry.file_id,
                    entry.suspicious as i32,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_timeline_entries(&self) -> Result<Vec<crate::state::TimelineEntry>> {
        self.ensure_timeline_entries_columns()?;
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_utc, event_type, path, evidence_id, COALESCE(detail, ''), file_id, COALESCE(suspicious, 0)
             FROM timeline_entries
             ORDER BY timestamp_utc ASC"
        )?;

        let rows = stmt.query_map([], |r| {
            let timestamp_text: String = r.get(0)?;
            let parsed = chrono::DateTime::parse_from_rfc3339(&timestamp_text)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            let event_text: String = r.get(1)?;
            let event_type = match event_text.as_str() {
                "FileCreated" => crate::state::TimelineEventType::FileCreated,
                "FileModified" => crate::state::TimelineEventType::FileModified,
                "FileAccessed" => crate::state::TimelineEventType::FileAccessed,
                "FileMftModified" => crate::state::TimelineEventType::FileMftModified,
                "FileDeleted" => crate::state::TimelineEventType::FileDeleted,
                "RegistryKeyCreated" => crate::state::TimelineEventType::RegistryKeyCreated,
                "RegistryKeyModified" => crate::state::TimelineEventType::RegistryKeyModified,
                "RegistryValueSet" => crate::state::TimelineEventType::RegistryValueSet,
                "ProcessExecuted" => crate::state::TimelineEventType::ProcessExecuted,
                "UserLogin" => crate::state::TimelineEventType::UserLogin,
                "UserActivity" => crate::state::TimelineEventType::UserActivity,
                "WebVisit" => crate::state::TimelineEventType::WebVisit,
                _ => crate::state::TimelineEventType::FileModified,
            };
            Ok(crate::state::TimelineEntry {
                timestamp: parsed,
                event_type,
                path: r.get(2)?,
                evidence_id: r.get(3)?,
                detail: r.get(4)?,
                file_id: r.get(5)?,
                suspicious: r.get::<_, i32>(6)? != 0,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    fn ensure_timeline_entries_columns(&self) -> Result<()> {
        let mut cols = std::collections::HashSet::<String>::new();
        let mut stmt = self.conn.prepare("PRAGMA table_info(timeline_entries)")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
        for row in rows {
            cols.insert(row?.to_lowercase());
        }
        if !cols.contains("suspicious") {
            let _ = self.conn.execute(
                "ALTER TABLE timeline_entries ADD COLUMN suspicious INTEGER DEFAULT 0",
                [],
            );
        }
        Ok(())
    }

    pub fn integrity_check(&self) -> Result<String> {
        let result: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        Ok(result)
    }

    pub fn count_files_for_evidence(&self, evidence_id: &str) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM file_index WHERE evidence_id = ?1",
            rusqlite::params![evidence_id],
            |r| r.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    fn ensure_audit_log_columns(&self) -> Result<()> {
        let mut cols = std::collections::HashSet::<String>::new();
        let mut stmt = self.conn.prepare("PRAGMA table_info(audit_log)")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
        for row in rows {
            cols.insert(row?.to_lowercase());
        }

        if !cols.contains("evidence_id") {
            let _ = self
                .conn
                .execute("ALTER TABLE audit_log ADD COLUMN evidence_id TEXT", []);
        }
        if !cols.contains("file_path") {
            let _ = self
                .conn
                .execute("ALTER TABLE audit_log ADD COLUMN file_path TEXT", []);
        }
        Ok(())
    }

    fn ensure_required_indexes(&self) -> Result<()> {
        let required = [
            ("idx_parent", "file_entries", "CREATE INDEX IF NOT EXISTS idx_parent ON file_entries(evidence_id, parent_path)"),
            ("idx_name", "file_entries", "CREATE INDEX IF NOT EXISTS idx_name ON file_entries(name COLLATE NOCASE)"),
            ("idx_ext", "file_entries", "CREATE INDEX IF NOT EXISTS idx_ext ON file_entries(extension)"),
            ("idx_deleted", "file_entries", "CREATE INDEX IF NOT EXISTS idx_deleted ON file_entries(is_deleted)"),
            ("idx_hash", "file_entries", "CREATE INDEX IF NOT EXISTS idx_hash ON file_entries(hash_sha256)"),
            ("idx_size", "file_entries", "CREATE INDEX IF NOT EXISTS idx_size ON file_entries(size)"),
            ("idx_modified", "file_entries", "CREATE INDEX IF NOT EXISTS idx_modified ON file_entries(modified_utc)"),
            ("idx_file_index_path", "file_index", "CREATE INDEX IF NOT EXISTS idx_file_index_path ON file_index(path)"),
            ("idx_file_index_name", "file_index", "CREATE INDEX IF NOT EXISTS idx_file_index_name ON file_index(name)"),
            ("idx_file_index_parent", "file_index", "CREATE INDEX IF NOT EXISTS idx_file_index_parent ON file_index(evidence_id, parent_path)"),
            ("idx_file_index_extension", "file_index", "CREATE INDEX IF NOT EXISTS idx_file_index_extension ON file_index(extension)"),
            ("idx_file_index_deleted", "file_index", "CREATE INDEX IF NOT EXISTS idx_file_index_deleted ON file_index(is_deleted)"),
            ("idx_file_index_hash", "file_index", "CREATE INDEX IF NOT EXISTS idx_file_index_hash ON file_index(sha256)"),
        ];

        for (name, table, sql) in required {
            let existing_table: Option<String> = self
                .conn
                .query_row(
                    "SELECT tbl_name FROM sqlite_master WHERE type='index' AND name=?1",
                    rusqlite::params![name],
                    |r| r.get(0),
                )
                .ok();
            if let Some(found) = existing_table {
                if !found.eq_ignore_ascii_case(table) {
                    let drop_sql = format!("DROP INDEX IF EXISTS {}", name);
                    let _ = self.conn.execute(&drop_sql, []);
                }
            }
            let _ = self.conn.execute(sql, []);
        }
        Ok(())
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS case_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_sources (
    id            TEXT PRIMARY KEY,
    path          TEXT NOT NULL,
    format        TEXT NOT NULL,
    sha256        TEXT,
    hash_verified INTEGER DEFAULT 0,
    loaded_utc    TEXT NOT NULL,
    size_bytes    INTEGER
);
CREATE TABLE IF NOT EXISTS file_index (
    id           TEXT PRIMARY KEY,
    evidence_id  TEXT NOT NULL,
    path         TEXT NOT NULL,
    vfs_path     TEXT DEFAULT '',
    parent_path  TEXT DEFAULT '',
    name         TEXT NOT NULL,
    extension    TEXT,
    size         INTEGER,
    is_dir       INTEGER DEFAULT 0,
    is_deleted   INTEGER DEFAULT 0,
    is_carved    INTEGER DEFAULT 0,
    is_system    INTEGER DEFAULT 0,
    is_hidden    INTEGER DEFAULT 0,
    created_utc  TEXT,
    modified_utc TEXT,
    accessed_utc TEXT,
    mft_record   INTEGER,
    md5          TEXT,
    sha256       TEXT,
    category     TEXT,
    hash_flag    TEXT,
    signature    TEXT
);
CREATE TABLE IF NOT EXISTS bookmarks (
    id          TEXT PRIMARY KEY,
    file_id     TEXT,
    registry_path TEXT,
    tag         TEXT NOT NULL,
    examiner_id TEXT NOT NULL,
    note        TEXT,
    created_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activity_log (
    id            TEXT PRIMARY KEY,
    examiner_id   TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    action_type   TEXT NOT NULL,
    description   TEXT
);
CREATE TABLE IF NOT EXISTS volumes (
    id            TEXT PRIMARY KEY,
    evidence_id   TEXT NOT NULL,
    label         TEXT,
    filesystem    TEXT,
    total_files   INTEGER DEFAULT 0,
    deleted_files INTEGER DEFAULT 0,
    carved_files  INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS timeline_entries (
    id            TEXT PRIMARY KEY,
    timestamp_utc TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    path          TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    detail        TEXT,
    file_id       TEXT
);
CREATE TABLE IF NOT EXISTS compare_results (
    id          TEXT PRIMARY KEY,
    evidence_a  TEXT,
    evidence_b  TEXT,
    result_json TEXT,
    run_at      TEXT
);
CREATE TABLE IF NOT EXISTS hash_sets (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    source_path TEXT NOT NULL,
    loaded_utc  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hash_set_refs (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    path        TEXT,
    category    TEXT,
    entry_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ui_prefs (
    key         TEXT PRIMARY KEY,
    value       TEXT
);
CREATE TABLE IF NOT EXISTS search_results (
    id          TEXT PRIMARY KEY,
    file_id     TEXT NOT NULL,
    query       TEXT NOT NULL,
    context     TEXT NOT NULL,
    hit_type    TEXT NOT NULL,
    searched_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id            TEXT PRIMARY KEY,
    sequence      INTEGER,
    timestamp_utc TEXT NOT NULL,
    examiner_id   TEXT NOT NULL,
    action_type   TEXT NOT NULL,
    detail        TEXT,
    evidence_id   TEXT,
    file_path     TEXT,
    prev_hash     TEXT,
    entry_hash    TEXT
);
CREATE TABLE IF NOT EXISTS file_entries (
    id           TEXT PRIMARY KEY,
    evidence_id  TEXT NOT NULL,
    path         TEXT NOT NULL,
    parent_path  TEXT DEFAULT '',
    name         TEXT NOT NULL,
    extension    TEXT,
    size         INTEGER,
    is_deleted   INTEGER DEFAULT 0,
    modified_utc TEXT,
    hash_sha256  TEXT
);
CREATE INDEX IF NOT EXISTS idx_file_index_path ON file_index(path);
CREATE INDEX IF NOT EXISTS idx_file_index_name ON file_index(name);
CREATE INDEX IF NOT EXISTS idx_file_index_parent ON file_index(evidence_id, parent_path);
CREATE INDEX IF NOT EXISTS idx_file_index_extension ON file_index(extension);
CREATE INDEX IF NOT EXISTS idx_file_index_deleted ON file_index(is_deleted);
CREATE INDEX IF NOT EXISTS idx_file_index_hash ON file_index(sha256);
CREATE INDEX IF NOT EXISTS idx_parent ON file_entries(evidence_id, parent_path);
CREATE INDEX IF NOT EXISTS idx_name ON file_entries(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_ext ON file_entries(extension);
CREATE INDEX IF NOT EXISTS idx_deleted ON file_entries(is_deleted);
CREATE INDEX IF NOT EXISTS idx_hash ON file_entries(hash_sha256);
CREATE INDEX IF NOT EXISTS idx_size ON file_entries(size);
CREATE INDEX IF NOT EXISTS idx_modified ON file_entries(modified_utc);
";

fn quote_identifier(input: &str) -> String {
    format!("\"{}\"", input.replace('"', "\"\""))
}

fn value_ref_bytes(value: ValueRef<'_>) -> Vec<u8> {
    match value {
        ValueRef::Null => b"NULL".to_vec(),
        ValueRef::Integer(v) => format!("I{}", v).into_bytes(),
        ValueRef::Real(v) => format!("F{:.17}", v).into_bytes(),
        ValueRef::Text(v) => {
            let mut out = Vec::with_capacity(v.len() + 1);
            out.push(b'T');
            out.extend_from_slice(v);
            out
        }
        ValueRef::Blob(v) => {
            let mut out = Vec::with_capacity(v.len() * 2 + 1);
            out.push(b'B');
            out.extend_from_slice(hex::encode(v).as_bytes());
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VtpProject;

    #[test]
    fn search_results_round_trip() {
        let root = std::env::temp_dir().join(format!(
            "strata_project_search_test_{}",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::create_dir_all(&root);
        let case_path = root.join("case.vtp");

        let project =
            VtpProject::create(&case_path, "Search Test Case", "Examiner").expect("create project");
        let hits = vec![
            crate::state::SearchHit {
                file_id: "f1".to_string(),
                query: "mimikatz".to_string(),
                context: "score=0.8 windows/system32".to_string(),
                hit_type: "content".to_string(),
            },
            crate::state::SearchHit {
                file_id: "f2".to_string(),
                query: "runonce".to_string(),
                context: "registry key".to_string(),
                hit_type: "metadata".to_string(),
            },
        ];
        project
            .save_search_results(&hits)
            .expect("save search results");

        let loaded = project.load_search_results().expect("load search results");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].query, "runonce");
        assert_eq!(loaded[1].query, "mimikatz");

        let _ = std::fs::remove_file(&case_path);
        let _ = std::fs::remove_dir_all(&root);
    }
}
