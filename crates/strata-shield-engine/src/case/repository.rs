use crate::case::activity_log::{ActivityEvent, ActivityEventType};
use crate::case::bookmarks::{Bookmark, BookmarkFolder};
use crate::case::jobs::{Job, JobPriority, JobStatus, JobType};
use crate::case::notes::Note;
use crate::case::provenance::{ProvenanceAction, ProvenanceObjectType, ProvenanceRecord};
use rusqlite::{params, Connection, Result as SqliteResult};
use std::sync::{Arc, Mutex};

pub struct ActivityLogRepository {
    conn: Arc<Mutex<Connection>>,
    case_id: String,
}

impl ActivityLogRepository {
    pub fn new(conn: Arc<Mutex<Connection>>, case_id: String) -> Self {
        Self { conn, case_id }
    }

    pub fn insert(&self, event: &ActivityEvent) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO activity_log (id, case_id, evidence_id, volume_id, user_name, session_id, event_type, summary, details_json, ts_utc, ts_local)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.id,
                self.case_id,
                event.evidence_id,
                event.volume_id,
                event.user,
                event.session_id,
                format!("{:?}", event.event_type),
                event.summary,
                serde_json::to_string(&event.details).ok(),
                event.timestamp_utc as i64,
                event.timestamp_local
            ]
        )?;
        Ok(())
    }

    pub fn batch_insert(&self, events: &[ActivityEvent]) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare_cached(
            "INSERT INTO activity_log (id, case_id, evidence_id, volume_id, user_name, session_id, event_type, summary, details_json, ts_utc, ts_local)"
        )?;

        for event in events {
            stmt.execute(params![
                event.id,
                self.case_id,
                event.evidence_id,
                event.volume_id,
                event.user,
                event.session_id,
                format!("{:?}", event.event_type),
                event.summary,
                serde_json::to_string(&event.details).ok(),
                event.timestamp_utc as i64,
                event.timestamp_local
            ])?;
        }

        Ok(())
    }

    pub fn get_recent(&self, limit: usize) -> SqliteResult<Vec<ActivityEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, evidence_id, volume_id, user_name, session_id, event_type, summary, details_json, ts_utc, ts_local
             FROM activity_log WHERE case_id = ?1 ORDER BY ts_utc DESC LIMIT ?2"
        )?;

        let events = stmt
            .query_map(params![self.case_id, limit as i64], |row| {
                Ok(ActivityEvent {
                    id: row.get(0)?,
                    case_id: row.get(1)?,
                    evidence_id: row.get(2)?,
                    volume_id: row.get(3)?,
                    user: row.get(4)?,
                    session_id: row.get(5)?,
                    event_type: parse_event_type(&row.get::<_, String>(6)?),
                    summary: row.get(7)?,
                    details: row
                        .get::<_, Option<String>>(8)?
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default(),
                    object_refs: Vec::new(),
                    timestamp_utc: row.get::<_, i64>(9)? as u64,
                    timestamp_local: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    pub fn get_by_time_range(&self, start: i64, end: i64) -> SqliteResult<Vec<ActivityEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, evidence_id, volume_id, user_name, session_id, event_type, summary, details_json, ts_utc, ts_local
             FROM activity_log WHERE case_id = ?1 AND ts_utc >= ?2 AND ts_utc <= ?3 ORDER BY ts_utc"
        )?;

        let events = stmt
            .query_map(params![self.case_id, start, end], |row| {
                Ok(ActivityEvent {
                    id: row.get(0)?,
                    case_id: row.get(1)?,
                    evidence_id: row.get(2)?,
                    volume_id: row.get(3)?,
                    user: row.get(4)?,
                    session_id: row.get(5)?,
                    event_type: parse_event_type(&row.get::<_, String>(6)?),
                    summary: row.get(7)?,
                    details: row
                        .get::<_, Option<String>>(8)?
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default(),
                    object_refs: Vec::new(),
                    timestamp_utc: row.get::<_, i64>(9)? as u64,
                    timestamp_local: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }
}

fn parse_event_type(s: &str) -> ActivityEventType {
    match s {
        "EvidenceOpened" => ActivityEventType::EvidenceOpened,
        "EvidenceAdded" => ActivityEventType::EvidenceAdded,
        "VolumeSwitched" => ActivityEventType::VolumeSwitched,
        "FilterApplied" => ActivityEventType::FilterApplied,
        "FilterCleared" => ActivityEventType::FilterCleared,
        "SearchExecuted" => ActivityEventType::SearchExecuted,
        "SearchResultViewed" => ActivityEventType::SearchResultViewed,
        "ArtifactViewed" => ActivityEventType::ArtifactViewed,
        "ArtifactPreviewOpened" => ActivityEventType::ArtifactPreviewOpened,
        "HexViewOpened" => ActivityEventType::HexViewOpened,
        "BookmarkCreated" => ActivityEventType::BookmarkCreated,
        "TagCreated" => ActivityEventType::TagCreated,
        "ExportStarted" => ActivityEventType::ExportStarted,
        "ExportCompleted" => ActivityEventType::ExportCompleted,
        "ModuleStarted" => ActivityEventType::ModuleStarted,
        "ModuleCompleted" => ActivityEventType::ModuleCompleted,
        "ModuleFailed" => ActivityEventType::ModuleFailed,
        "NotesAdded" => ActivityEventType::NotesAdded,
        "ExhibitCreated" => ActivityEventType::ExhibitCreated,
        "ViewChanged" => ActivityEventType::ViewChanged,
        "PresetApplied" => ActivityEventType::PresetApplied,
        "SessionStarted" => ActivityEventType::SessionStarted,
        "SessionEnded" => ActivityEventType::SessionEnded,
        "CaseOpened" => ActivityEventType::CaseOpened,
        "CaseCreated" => ActivityEventType::CaseCreated,
        _ => ActivityEventType::ArtifactViewed,
    }
}

pub struct BookmarkRepository {
    conn: Arc<Mutex<Connection>>,
    case_id: String,
}

impl BookmarkRepository {
    pub fn new(conn: Arc<Mutex<Connection>>, case_id: String) -> Self {
        Self { conn, case_id }
    }

    pub fn insert_bookmark(&self, bookmark: &Bookmark) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO bookmarks (id, case_id, folder_id, title, description, tags_json, color, icon, notes, reviewed, reviewer, reviewed_at, custom_fields_json, created_by, created_at, modified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                bookmark.id,
                self.case_id,
                bookmark.parent_id,
                bookmark.title,
                bookmark.description,
                serde_json::to_string(&bookmark.tags).ok(),
                bookmark.color,
                bookmark.icon,
                bookmark.notes,
                bookmark.reviewed as i32,
                bookmark.reviewer,
                bookmark.reviewed_at.map(|t| t as i64),
                serde_json::to_string(&bookmark.custom_fields).ok(),
                bookmark.created_by,
                bookmark.created_at as i64,
                bookmark.modified_at as i64
            ]
        )?;

        for obj in &bookmark.objects {
            conn.execute(
                "INSERT INTO bookmark_objects (id, bookmark_id, object_type, object_id, path, file_name, size, hash_sha256, evidence_id, volume_id, offset, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    bookmark.id,
                    format!("{:?}", obj.object_type),
                    obj.object_id,
                    obj.path,
                    obj.file_name,
                    obj.size.map(|s| s as i64),
                    obj.hash_sha256,
                    obj.evidence_id,
                    obj.volume_id,
                    obj.offset.map(|o| o as i64),
                    serde_json::to_string(&obj.metadata).ok()
                ]
            )?;
        }

        Ok(())
    }

    pub fn list_bookmarks(&self, folder_id: Option<&str>) -> SqliteResult<Vec<Bookmark>> {
        let conn = self.conn.lock().unwrap();

        let sql = match folder_id {
            Some(_) => "SELECT id, case_id, folder_id, title, description, tags_json, color, icon, notes, reviewed, reviewer, reviewed_at, custom_fields_json, created_by, created_at, modified_at
                        FROM bookmarks WHERE case_id = ?1 AND folder_id = ?2 ORDER BY modified_at DESC",
            None => "SELECT id, case_id, folder_id, title, description, tags_json, color, icon, notes, reviewed, reviewer, reviewed_at, custom_fields_json, created_by, created_at, modified_at
                     FROM bookmarks WHERE case_id = ?1 AND folder_id IS NULL ORDER BY modified_at DESC",
        };

        let mut stmt = conn.prepare(sql)?;

        let bookmarks: Vec<Bookmark> = if let Some(fid) = folder_id {
            stmt.query_map(params![self.case_id, fid], map_bookmark)?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map(params![self.case_id], map_bookmark)?
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(bookmarks)
    }

    pub fn get_unreviewed(&self) -> SqliteResult<Vec<Bookmark>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, folder_id, title, description, tags_json, color, icon, notes, reviewed, reviewer, reviewed_at, custom_fields_json, created_by, created_at, modified_at
             FROM bookmarks WHERE case_id = ?1 AND reviewed = 0 ORDER BY modified_at DESC"
        )?;

        let bookmarks = stmt
            .query_map(params![self.case_id], map_bookmark)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(bookmarks)
    }

    pub fn insert_folder(&self, folder: &BookmarkFolder) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO bookmark_folders (id, case_id, parent_id, name, description, color, icon, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                folder.id,
                self.case_id,
                folder.parent_id,
                folder.name,
                folder.description,
                folder.color,
                folder.icon,
                folder.created_by,
                folder.created_at as i64
            ]
        )?;
        Ok(())
    }

    pub fn list_folders(&self) -> SqliteResult<Vec<BookmarkFolder>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, parent_id, name, description, color, icon, created_by, created_at
             FROM bookmark_folders WHERE case_id = ?1 ORDER BY name",
        )?;

        let folders = stmt
            .query_map(params![self.case_id], |row| {
                Ok(BookmarkFolder {
                    id: row.get(0)?,
                    case_id: row.get(1)?,
                    parent_id: row.get(2)?,
                    name: row.get(3)?,
                    description: row.get(4)?,
                    color: row.get(5)?,
                    icon: row.get(6)?,
                    created_by: row.get(7)?,
                    created_at: row.get::<_, i64>(8)? as u64,
                    bookmark_count: 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(folders)
    }
}

fn map_bookmark(row: &rusqlite::Row) -> rusqlite::Result<Bookmark> {
    Ok(Bookmark {
        id: row.get(0)?,
        case_id: row.get(1)?,
        parent_id: row.get(2)?,
        title: row.get(3)?,
        description: row.get(4)?,
        tags: row
            .get::<_, Option<String>>(5)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        color: row.get(6)?,
        icon: row.get(7)?,
        notes: row.get(8)?,
        reviewed: row.get::<_, i32>(9)? != 0,
        reviewer: row.get(10)?,
        reviewed_at: row.get::<_, Option<i64>>(11)?.map(|t| t as u64),
        custom_fields: row
            .get::<_, Option<String>>(12)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        created_by: row.get(13)?,
        created_at: row.get::<_, i64>(14)? as u64,
        modified_at: row.get::<_, i64>(15)? as u64,
        objects: Vec::new(),
    })
}

pub struct NotesRepository {
    conn: Arc<Mutex<Connection>>,
    case_id: String,
}

impl NotesRepository {
    pub fn new(conn: Arc<Mutex<Connection>>, case_id: String) -> Self {
        Self { conn, case_id }
    }

    pub fn insert_note(&self, note: &Note) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO notes (id, case_id, title, content, tags_json, reviewed, reviewer, reviewed_at, created_at, modified_at, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                note.id,
                self.case_id,
                note.title,
                note.content,
                serde_json::to_string(&note.tags).ok(),
                note.reviewed as i32,
                note.reviewer,
                note.reviewed_at.map(|t| t as i64),
                note.created_at as i64,
                note.modified_at as i64,
                note.linked_objects.iter().map(|o| o.object_id.clone()).collect::<Vec<_>>().join(",")
            ]
        )?;
        Ok(())
    }

    pub fn list_notes(&self) -> SqliteResult<Vec<Note>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, title, content, tags_json, reviewed, reviewer, reviewed_at, created_at, modified_at, created_by
             FROM notes WHERE case_id = ?1 ORDER BY modified_at DESC"
        )?;

        let notes = stmt
            .query_map(params![self.case_id], |row| {
                Ok(Note {
                    id: row.get(0)?,
                    case_id: row.get(1)?,
                    title: row.get(2)?,
                    content: row.get(3)?,
                    tags: row
                        .get::<_, Option<String>>(4)?
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default(),
                    reviewed: row.get::<_, i32>(5)? != 0,
                    reviewer: row.get(6)?,
                    reviewed_at: row.get::<_, Option<i64>>(7)?.map(|t| t as u64),
                    created_at: row.get::<_, i64>(8)? as u64,
                    modified_at: row.get::<_, i64>(9)? as u64,
                    exhibit_refs: Vec::new(),
                    linked_objects: Vec::new(),
                    screenshot_paths: Vec::new(),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(notes)
    }
}

pub struct JobsRepository {
    conn: Arc<Mutex<Connection>>,
    case_id: String,
}

impl JobsRepository {
    pub fn new(conn: Arc<Mutex<Connection>>, case_id: String) -> Self {
        Self { conn, case_id }
    }

    pub fn insert_job(&self, job: &Job) -> SqliteResult<()> {
        let priority_i32 = match job.priority {
            JobPriority::Low => 0i32,
            JobPriority::Normal => 1i32,
            JobPriority::High => 2i32,
            JobPriority::Critical => 3i32,
        };

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO jobs (id, case_id, job_type, status, priority, progress, progress_message, error, params_json, result_json, created_by, worker_id, retries, max_retries, created_at, started_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                job.id,
                self.case_id,
                format!("{:?}", job.job_type),
                format!("{:?}", job.status),
                priority_i32,
                job.progress,
                job.progress_message,
                job.error,
                serde_json::to_string(&job.params).ok(),
                job.result
                    .as_ref()
                    .and_then(|r| serde_json::to_string(r).ok())
                    .unwrap_or_default(),
                job.created_by,
                job.worker_id,
                job.retries as i32,
                job.max_retries as i64,
                job.created_at as i64,
                job.started_at.map(|t| t as i64),
                job.completed_at.map(|t| t as i64)
            ]
        )?;
        Ok(())
    }

    pub fn update_job(&self, job: &Job) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE jobs SET status = ?1, progress = ?2, progress_message = ?3, error = ?4, worker_id = ?5, retries = ?6, started_at = ?7, completed_at = ?8 WHERE id = ?9",
            params![
                format!("{:?}", job.status),
                job.progress,
                job.progress_message,
                job.error,
                job.worker_id,
                job.retries as i32,
                job.started_at.map(|t| t as i64),
                job.completed_at.map(|t| t as i64),
                job.id
            ]
        )?;
        Ok(())
    }

    pub fn list_pending(&self) -> SqliteResult<Vec<Job>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, job_type, status, priority, progress, progress_message, error, params_json, result_json, created_by, worker_id, retries, max_retries, created_at, started_at, completed_at
             FROM jobs WHERE case_id = ?1 AND status = 'Pending' ORDER BY priority DESC, created_at ASC"
        )?;

        let jobs = stmt
            .query_map(params![self.case_id], map_job)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(jobs)
    }

    pub fn list_failed(&self) -> SqliteResult<Vec<Job>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, job_type, status, priority, progress, progress_message, error, params_json, result_json, created_by, worker_id, retries, max_retries, created_at, started_at, completed_at
             FROM jobs WHERE case_id = ?1 AND status = 'Failed' ORDER BY created_at DESC"
        )?;

        let jobs = stmt
            .query_map(params![self.case_id], map_job)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(jobs)
    }
}

fn map_job(row: &rusqlite::Row) -> rusqlite::Result<Job> {
    Ok(Job {
        id: row.get(0)?,
        case_id: row.get(1)?,
        job_type: parse_job_type(&row.get::<_, String>(2)?),
        status: parse_job_status(&row.get::<_, String>(3)?),
        priority: match row.get::<_, i32>(4)? {
            0 => JobPriority::Low,
            1 => JobPriority::Normal,
            2 => JobPriority::High,
            3 => JobPriority::Critical,
            _ => JobPriority::Normal,
        },
        progress: row.get(5)?,
        progress_message: row.get(6)?,
        error: row.get(7)?,
        params: row
            .get::<_, Option<String>>(8)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        result: row
            .get::<_, Option<String>>(9)?
            .and_then(|s| serde_json::from_str(&s).ok()),
        created_by: row.get(10)?,
        worker_id: row.get(11)?,
        retries: row.get::<_, i32>(12)? as u32,
        max_retries: row.get::<_, i64>(13)? as u32,
        created_at: row.get::<_, i64>(14)? as u64,
        started_at: row.get::<_, Option<i64>>(15)?.map(|t| t as u64),
        completed_at: row.get::<_, Option<i64>>(16)?.map(|t| t as u64),
    })
}

fn parse_job_type(s: &str) -> JobType {
    match s {
        "ImageAcquisition" => JobType::ImageAcquisition,
        "Carving" => JobType::Carving,
        "HashComputation" => JobType::HashComputation,
        "Indexing" => JobType::Indexing,
        "ArtifactExtraction" => JobType::ArtifactExtraction,
        "TimelineGeneration" => JobType::TimelineGeneration,
        "ReportGeneration" => JobType::ReportGeneration,
        "Export" => JobType::Export,
        "Verification" => JobType::Verification,
        "Deduplication" => JobType::Deduplication,
        "EnCaseImport" => JobType::EnCaseImport,
        "FTKImport" => JobType::FTKImport,
        _ => JobType::Custom(s.to_string()),
    }
}

fn parse_job_status(s: &str) -> JobStatus {
    match s {
        "Pending" => JobStatus::Pending,
        "Running" => JobStatus::Running,
        "Paused" => JobStatus::Paused,
        "Completed" => JobStatus::Completed,
        "Failed" => JobStatus::Failed,
        "Cancelled" => JobStatus::Cancelled,
        _ => JobStatus::Pending,
    }
}

pub struct ProvenanceRepository {
    conn: Arc<Mutex<Connection>>,
    case_id: String,
}

impl ProvenanceRepository {
    pub fn new(conn: Arc<Mutex<Connection>>, case_id: String) -> Self {
        Self { conn, case_id }
    }

    pub fn insert(&self, record: &ProvenanceRecord) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO provenance (id, case_id, object_id, object_type, action, user_name, session_id, source_evidence_id, source_volume_id, source_path, destination_path, export_path, hash_before, hash_after, metadata_json, description, ts_utc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                record.id,
                self.case_id,
                record.object_id,
                format!("{:?}", record.object_type),
                format!("{:?}", record.action),
                record.user,
                record.session_id,
                record.source_evidence_id,
                record.source_volume_id,
                record.source_path,
                record.destination_path,
                record.export_path,
                record.hash_before,
                record.hash_after,
                serde_json::to_string(&record.metadata).ok(),
                record.description,
                record.timestamp_utc as i64
            ]
        )?;
        Ok(())
    }

    pub fn get_for_object(&self, object_id: &str) -> SqliteResult<Vec<ProvenanceRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, object_id, object_type, action, user_name, session_id, source_evidence_id, source_volume_id, source_path, destination_path, export_path, hash_before, hash_after, metadata_json, description, ts_utc
             FROM provenance WHERE case_id = ?1 AND object_id = ?2 ORDER BY ts_utc ASC"
        )?;

        let records = stmt
            .query_map(params![self.case_id, object_id], |row| {
                Ok(ProvenanceRecord {
                    id: row.get(0)?,
                    case_id: row.get(1)?,
                    object_id: row.get(2)?,
                    object_type: parse_provenance_type(&row.get::<_, String>(3)?),
                    action: parse_provenance_action(&row.get::<_, String>(4)?),
                    user: row.get(5)?,
                    session_id: row.get(6)?,
                    source_evidence_id: row.get(7)?,
                    source_volume_id: row.get(8)?,
                    source_path: row.get(9)?,
                    destination_path: row.get(10)?,
                    export_path: row.get(11)?,
                    hash_before: row.get(12)?,
                    hash_after: row.get(13)?,
                    metadata: row
                        .get::<_, Option<String>>(14)?
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default(),
                    description: row.get(15)?,
                    timestamp_utc: row.get::<_, i64>(16)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }
}

fn parse_provenance_type(s: &str) -> ProvenanceObjectType {
    match s {
        "File" => ProvenanceObjectType::File,
        "Directory" => ProvenanceObjectType::Directory,
        "MftEntry" => ProvenanceObjectType::MftEntry,
        "RegistryKey" => ProvenanceObjectType::RegistryKey,
        "RegistryValue" => ProvenanceObjectType::RegistryValue,
        "Artifact" => ProvenanceObjectType::Artifact,
        "TimelineEvent" => ProvenanceObjectType::TimelineEvent,
        "Process" => ProvenanceObjectType::Process,
        "Memory" => ProvenanceObjectType::Memory,
        "DiskImage" => ProvenanceObjectType::DiskImage,
        "Evidence" => ProvenanceObjectType::Evidence,
        "Volume" => ProvenanceObjectType::Volume,
        "Bookmark" => ProvenanceObjectType::Bookmark,
        "Note" => ProvenanceObjectType::Note,
        "Exhibit" => ProvenanceObjectType::Exhibit,
        "Export" => ProvenanceObjectType::Export,
        "Report" => ProvenanceObjectType::Report,
        _ => ProvenanceObjectType::Custom(s.to_string()),
    }
}

fn parse_provenance_action(s: &str) -> ProvenanceAction {
    match s {
        "Created" => ProvenanceAction::Created,
        "Modified" => ProvenanceAction::Modified,
        "Deleted" => ProvenanceAction::Deleted,
        "Copied" => ProvenanceAction::Copied,
        "Moved" => ProvenanceAction::Moved,
        "Renamed" => ProvenanceAction::Renamed,
        "Accessed" => ProvenanceAction::Accessed,
        "Exported" => ProvenanceAction::Exported,
        "Imported" => ProvenanceAction::Imported,
        "Hashed" => ProvenanceAction::Hashed,
        "Verified" => ProvenanceAction::Verified,
        "Tagged" => ProvenanceAction::Tagged,
        "Bookmarked" => ProvenanceAction::Bookmarked,
        "Noted" => ProvenanceAction::Noted,
        "Analyzed" => ProvenanceAction::Analyzed,
        "Processed" => ProvenanceAction::Processed,
        "Extracted" => ProvenanceAction::Extracted,
        "Carved" => ProvenanceAction::Carved,
        "Decrypted" => ProvenanceAction::Decrypted,
        "Parsed" => ProvenanceAction::Parsed,
        "Indexed" => ProvenanceAction::Indexed,
        "Archived" => ProvenanceAction::Archived,
        "Restored" => ProvenanceAction::Restored,
        "Quarantined" => ProvenanceAction::Quarantined,
        "Blocked" => ProvenanceAction::Blocked,
        "Flagged" => ProvenanceAction::Flagged,
        _ => ProvenanceAction::Processed,
    }
}
