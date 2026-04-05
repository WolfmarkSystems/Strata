use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::case::database::CaseDatabase;
use crate::case::exhibit_packet::{
    create_exhibit_packet_with_context, ExhibitPacketSelection, SelectionContext, SelectionItem,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AddToNotesMode {
    #[default]
    NoteOnly,
    NotePlusExhibits,
    NotePlusSinglePacket,
}

impl std::fmt::Display for AddToNotesMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddToNotesMode::NoteOnly => write!(f, "NoteOnly"),
            AddToNotesMode::NotePlusExhibits => write!(f, "NotePlusExhibits"),
            AddToNotesMode::NotePlusSinglePacket => write!(f, "NotePlusSinglePacket"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddToNotesRequest {
    pub case_id: String,
    pub mode: AddToNotesMode,
    pub context: SelectionContext,
    pub items: Vec<SelectionItem>,
    pub tags: Vec<String>,
    pub screenshot_path: Option<String>,
    pub screenshot_id: Option<String>,
    pub explain: bool,
    pub max_items: Option<u64>,
}

impl Default for AddToNotesRequest {
    fn default() -> Self {
        Self {
            case_id: String::new(),
            mode: AddToNotesMode::NoteOnly,
            context: SelectionContext {
                case_id: String::new(),
                examiner: String::new(),
                selection_time: 0,
                active_filters: vec![],
                search_query: None,
                search_fuzzy: false,
                timeline_range_start: None,
                timeline_range_end: None,
            },
            items: vec![],
            tags: vec![],
            screenshot_path: None,
            screenshot_id: None,
            explain: false,
            max_items: Some(200),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddToNotesResult {
    pub note_id: String,
    pub exhibit_ids: Vec<String>,
    pub exhibit_packet_id: Option<String>,
    pub screenshot_id: Option<String>,
    pub activity_event_id: Option<String>,
}

pub fn add_to_notes(db: &CaseDatabase, req: AddToNotesRequest) -> anyhow::Result<AddToNotesResult> {
    let max_items = req.max_items.unwrap_or(200);
    if req.items.len() > max_items as usize {
        anyhow::bail!(
            "Too many items ({}). Maximum allowed is {}. Consider using packet export instead.",
            req.items.len(),
            max_items
        );
    }

    let conn = db.get_connection();
    let conn = conn.lock().unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let note_id = Uuid::new_v4().to_string();
    let title = generate_note_title(&req.items, &req.context);
    let content = generate_note_content(&req.items, &req.context, max_items as usize);
    let content_json = serde_json::to_string(&generate_note_content_json(&req.items, &req.context))
        .unwrap_or_else(|_| "{}".to_string());
    let tags_json = serde_json::to_string(&req.tags).unwrap_or_else(|_| "[]".to_string());

    let note_type = match req.mode {
        AddToNotesMode::NoteOnly => "selection_note",
        AddToNotesMode::NotePlusExhibits => "selection_exhibits",
        AddToNotesMode::NotePlusSinglePacket => "selection_packet",
    };

    conn.execute(
        "INSERT INTO notes (id, case_id, title, content, content_json, tags_json, note_type, auto_generated, created_at, modified_at, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10)",
        params![
            &note_id,
            &req.case_id,
            &title,
            &content,
            &content_json,
            &tags_json,
            note_type,
            now,
            now,
            &req.context.examiner
        ],
    )?;

    for tag in &req.tags {
        conn.execute(
            "INSERT OR IGNORE INTO tags (id, case_id, name, color, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                Uuid::new_v4().to_string(),
                &req.case_id,
                tag,
                "#808080",
                &req.context.examiner,
                now
            ],
        )?;

        conn.execute(
            "INSERT OR IGNORE INTO note_tags (note_id, tag_id)
             VALUES (?1, (SELECT id FROM tags WHERE case_id = ?2 AND name = ?3))",
            params![&note_id, &req.case_id, tag],
        )?;
    }

    let mut screenshot_id: Option<String> = None;
    if let Some(ref ss_id) = req.screenshot_id {
        screenshot_id = Some(ss_id.clone());
    } else if let Some(ref ss_path) = req.screenshot_path {
        let ss_new_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO screenshots (id, case_id, capture_type, created_at, created_by, description, format, file_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &ss_new_id,
                &req.case_id,
                "artifact",
                now,
                &req.context.examiner,
                "Selection screenshot",
                "png",
                ss_path
            ],
        )?;
        screenshot_id = Some(ss_new_id);
    }

    let mut exhibit_ids: Vec<String> = vec![];
    let mut exhibit_packet_id: Option<String> = None;

    match req.mode {
        AddToNotesMode::NoteOnly => {}

        AddToNotesMode::NotePlusExhibits => {
            for item in &req.items {
                let exhibit_id = Uuid::new_v4().to_string();

                conn.execute(
                    "INSERT INTO exhibits (id, case_id, name, description, exhibit_type, file_path, hash_md5, hash_sha1, hash_sha256, tags_json, created_by, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        &exhibit_id,
                        &req.case_id,
                        item.artifact_path.as_deref().unwrap_or(&item.item_id),
                        "",
                        item.item_type.as_str(),
                        item.file_path.as_deref().unwrap_or(""),
                        item.hash_md5.as_deref().unwrap_or(""),
                        item.hash_sha1.as_deref().unwrap_or(""),
                        item.hash_sha256.as_deref().unwrap_or(""),
                        &tags_json,
                        &req.context.examiner,
                        now
                    ],
                )?;

                for prov in &item.provenance {
                    conn.execute(
                        "INSERT INTO provenance (id, case_id, object_id, object_type, action, user_name, session_id, source_evidence_id, source_path, ts_utc)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            Uuid::new_v4().to_string(),
                            &req.case_id,
                            &item.item_id,
                            &item.item_type,
                            "LinkedToNote",
                            &req.context.examiner,
                            "",
                            &prov.source_evidence_id,
                            &prov.source_path,
                            prov.extraction_time
                        ],
                    )?;
                }

                conn.execute(
                    "INSERT INTO note_exhibit_refs (id, note_id, exhibit_id, reference_type, notes)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        Uuid::new_v4().to_string(),
                        &note_id,
                        &exhibit_id,
                        "selection_item",
                        item.artifact_path.as_deref().unwrap_or(&item.item_id)
                    ],
                )?;

                for tag in &req.tags {
                    conn.execute(
                        "INSERT OR IGNORE INTO bookmark_tags (bookmark_id, tag_id)
                         SELECT ?1, id FROM tags WHERE case_id = ?2 AND name = ?3",
                        params![&exhibit_id, &req.case_id, tag],
                    )
                    .ok();
                }

                exhibit_ids.push(exhibit_id);
            }
        }

        AddToNotesMode::NotePlusSinglePacket => {
            let packet_selection = ExhibitPacketSelection {
                packet_id: Uuid::new_v4().to_string(),
                packet_name: format!("Selection Packet - {}", req.context.examiner),
                description: content.clone(),
                selection_context: req.context.clone(),
                items: req.items.clone(),
                screenshot_path: req.screenshot_path.clone(),
                auto_notes: vec![],
                tags: req.tags.clone(),
                created_at: now,
            };

            let packet_result = create_exhibit_packet_with_context(
                &req.case_id,
                "Auto-generated",
                "System",
                packet_selection.items.clone(),
                SelectionContext {
                    case_id: req.case_id.clone(),
                    examiner: "System".to_string(),
                    selection_time: now,
                    active_filters: vec![],
                    search_query: None,
                    search_fuzzy: false,
                    timeline_range_start: None,
                    timeline_range_end: None,
                },
                req.screenshot_path.as_deref(),
                req.tags.clone(),
            );

            exhibit_packet_id = Some(packet_result.packet_id.clone());

            conn.execute(
                "UPDATE notes SET content_json = json_set(coalesce(content_json, '{}'), '$.packet_id', ?1) WHERE id = ?2",
                params![&packet_result.packet_id, &note_id],
            )?;
        }
    }

    drop(conn);

    let activity_event_id = log_activity_event(db, &req, &note_id)?;

    Ok(AddToNotesResult {
        note_id,
        exhibit_ids,
        exhibit_packet_id,
        screenshot_id,
        activity_event_id,
    })
}

fn generate_note_title(items: &[SelectionItem], context: &SelectionContext) -> String {
    let count = items.len();
    let category = classify_items_category(items);

    let search_part = context
        .search_query
        .as_ref()
        .map(|q| format!("Search={}", q))
        .unwrap_or_default();

    if count == 0 {
        "Selection saved: empty".to_string()
    } else if count == 1 {
        let item = &items[0];
        let path = item
            .artifact_path
            .as_ref()
            .or(item.file_path.as_ref())
            .map(|p| p.rsplit(['/', '\\']).next().unwrap_or(p).to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        format!("Selection saved: {} ({})", path, category)
    } else {
        let search_suffix = if !search_part.is_empty() {
            format!(" ({})", search_part)
        } else {
            String::new()
        };
        format!(
            "Selection saved: {} items ({}{})",
            count, category, search_suffix
        )
    }
}

fn generate_note_content(
    items: &[SelectionItem],
    context: &SelectionContext,
    max_items: usize,
) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mut content = String::new();

    content.push_str(&format!("Saved on: {}\n", now));
    content.push_str(&format!("Items: {}\n\n", items.len()));

    if !context.active_filters.is_empty() {
        content.push_str("Active Filters:\n");
        for filter in &context.active_filters {
            content.push_str(&format!(
                "  - {} ({} results)\n",
                filter.filter_type, filter.results_count
            ));
            for (key, value) in &filter.criteria {
                content.push_str(&format!("    {}: {}\n", key, value));
            }
        }
        content.push('\n');
    }

    if let Some(ref query) = context.search_query {
        content.push_str(&format!("Search Query: {}\n", query));
        if context.search_fuzzy {
            content.push_str("  (fuzzy search)\n");
        }
        content.push('\n');
    }

    if let (Some(start), Some(end)) = (context.timeline_range_start, context.timeline_range_end) {
        content.push_str(&format!(
            "Timeline Range: {} - {}\n\n",
            chrono::DateTime::from_timestamp(start as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| start.to_string()),
            chrono::DateTime::from_timestamp(end as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| end.to_string())
        ));
    }

    content.push_str("Selected Items:\n");
    let display_items = items.iter().take(max_items).enumerate();
    for (i, item) in display_items {
        let path = item
            .artifact_path
            .as_ref()
            .or(item.file_path.as_ref())
            .cloned()
            .unwrap_or_else(|| item.item_id.clone());

        let size = item
            .size_bytes
            .map(format_size)
            .unwrap_or_else(|| "unknown size".to_string());

        let hashes = if item.hash_sha256.is_some() {
            " [hash present]"
        } else {
            ""
        };

        content.push_str(&format!(
            "  {}. {} ({}){}{}\n",
            i + 1,
            path,
            size,
            hashes,
            item.evidence_id
                .as_ref()
                .map(|e| format!(" [evidence:{}]", e))
                .unwrap_or_default()
        ));
    }

    if items.len() > max_items {
        content.push_str(&format!(
            "  ... and {} more items\n",
            items.len() - max_items
        ));
    }

    content
}

fn generate_note_content_json(
    items: &[SelectionItem],
    context: &SelectionContext,
) -> serde_json::Value {
    let mut items_json: Vec<serde_json::Value> = items
        .iter()
        .map(|item| {
            serde_json::json!({
                "item_id": item.item_id,
                "item_type": item.item_type,
                "file_path": item.file_path,
                "artifact_path": item.artifact_path,
                "size_bytes": item.size_bytes,
                "hash_md5": item.hash_md5,
                "hash_sha1": item.hash_sha1,
                "hash_sha256": item.hash_sha256,
                "evidence_id": item.evidence_id,
                "volume_id": item.volume_id,
                "created_at": item.created_at,
                "modified_at": item.modified_at,
            })
        })
        .collect();

    items_json.sort_by(|a, b| {
        let a_path = a
            .get("artifact_path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let b_path = b
            .get("artifact_path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        a_path.cmp(b_path)
    });

    let filters_json: Vec<serde_json::Value> = context
        .active_filters
        .iter()
        .map(|f| {
            serde_json::json!({
                "filter_type": f.filter_type,
                "criteria": f.criteria,
                "results_count": f.results_count,
            })
        })
        .collect();

    serde_json::json!({
        "selection_context": {
            "case_id": context.case_id,
            "examiner": context.examiner,
            "selection_time": context.selection_time,
            "active_filters": filters_json,
            "search_query": context.search_query,
            "search_fuzzy": context.search_fuzzy,
            "timeline_range_start": context.timeline_range_start,
            "timeline_range_end": context.timeline_range_end,
        },
        "items": items_json,
        "items_count": items.len(),
    })
}

fn log_activity_event(
    db: &CaseDatabase,
    req: &AddToNotesRequest,
    note_id: &str,
) -> anyhow::Result<Option<String>> {
    let conn = db.get_connection();
    let conn = conn.lock().unwrap();

    let event_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let details = serde_json::json!({
        "note_id": note_id,
        "items_count": req.items.len(),
        "mode": req.mode.to_string(),
        "tags": req.tags,
        "explain": req.explain,
    });

    conn.execute(
        "INSERT INTO activity_log (id, case_id, user_name, session_id, event_type, summary, details_json, ts_utc, ts_local, event_hash, schema_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, '1.0')",
        params![
            &event_id,
            &req.case_id,
            &req.context.examiner,
            "",
            "AddToNotes",
            format!("Added {} items to notes", req.items.len()),
            details.to_string(),
            now.timestamp(),
            now.format("%Y-%m-%d %H:%M:%S").to_string(),
            &event_id
        ],
    )?;

    Ok(Some(event_id))
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn classify_items_category(items: &[SelectionItem]) -> String {
    let mut categories: HashMap<String, usize> = HashMap::new();

    for item in items {
        let category = if let Some(ref path) = item.artifact_path {
            let path_lower = path.to_lowercase();

            if path_lower.contains("history")
                || path_lower.contains("cookies")
                || path_lower.contains("login")
                || path_lower.contains("bookmark")
            {
                "Browser Data"
            } else if path_lower.contains("temp")
                || path_lower.contains("tmp")
                || path_lower.contains("cache")
            {
                "Temporary Files"
            } else if path_lower.contains("document")
                || path_lower.contains(".doc")
                || path_lower.contains(".pdf")
            {
                "Documents"
            } else if path_lower.contains("image")
                || path_lower.contains(".jpg")
                || path_lower.contains(".png")
                || path_lower.contains(".gif")
            {
                "Images"
            } else if path_lower.contains("video")
                || path_lower.contains(".mp4")
                || path_lower.contains(".avi")
            {
                "Videos"
            } else if path_lower.contains("audio")
                || path_lower.contains(".mp3")
                || path_lower.contains(".wav")
            {
                "Audio"
            } else if path_lower.contains("download") {
                "Downloads"
            } else if path_lower.contains("desktop") {
                "Desktop"
            } else if path_lower.contains("document") || path_lower.contains("my document") {
                "My Documents"
            } else {
                "Files"
            }
        } else {
            "Unknown"
        };

        *categories.entry(category.to_string()).or_insert(0) += 1;
    }

    let mut sorted: Vec<_> = categories.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));

    sorted
        .first()
        .map(|(k, _)| k.as_str())
        .unwrap_or("Files")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Result as SqliteResult;
    use tempfile::TempDir;

    fn create_test_db(temp_dir: &TempDir) -> SqliteResult<(rusqlite::Connection, String)> {
        let db_path = temp_dir.path().join("test_case.sqlite");
        let case_id = "test_case_001".to_string();

        let conn = rusqlite::Connection::open(&db_path)?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                examiner TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL
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
                created_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS note_exhibit_refs (
                id TEXT PRIMARY KEY,
                note_id TEXT NOT NULL,
                exhibit_id TEXT NOT NULL,
                reference_type TEXT,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS exhibits (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                exhibit_type TEXT NOT NULL,
                file_path TEXT,
                hash_md5 TEXT,
                hash_sha1 TEXT,
                hash_sha256 TEXT,
                tags_json TEXT,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tags (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                color TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(case_id, name)
            );

            CREATE TABLE IF NOT EXISTS note_tags (
                note_id TEXT NOT NULL,
                tag_id TEXT NOT NULL,
                PRIMARY KEY (note_id, tag_id)
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
                schema_version TEXT NOT NULL DEFAULT '1.0'
            );

            CREATE TABLE IF NOT EXISTS provenance (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                object_type TEXT NOT NULL,
                action TEXT NOT NULL,
                user_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                ts_utc INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS screenshots (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                capture_type TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                created_by TEXT NOT NULL,
                description TEXT,
                format TEXT NOT NULL,
                file_path TEXT
            );",
        )?;
        conn.execute(
            "INSERT INTO cases (id, name, examiner, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&case_id, "Test Case", "tester", 1700000000, 1700000000],
        )?;

        Ok((conn, case_id))
    }

    #[test]
    fn test_note_only_mode() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        let context = SelectionContext {
            case_id: case_id.clone(),
            examiner: "tester".to_string(),
            selection_time: 1700000000,
            active_filters: vec![],
            search_query: Some("suspicious".to_string()),
            search_fuzzy: false,
            timeline_range_start: None,
            timeline_range_end: None,
        };

        let items = vec![SelectionItem {
            item_id: "item1".to_string(),
            item_type: "file".to_string(),
            file_path: Some("/test/file1.txt".to_string()),
            artifact_path: Some("evidence1/file1.txt".to_string()),
            size_bytes: Some(1024),
            hash_md5: Some("abc123".to_string()),
            hash_sha1: None,
            hash_sha256: Some("def456".to_string()),
            evidence_id: Some("ev1".to_string()),
            volume_id: None,
            created_at: Some(1700000000),
            modified_at: Some(1700000000),
            provenance: vec![],
        }];

        let request = AddToNotesRequest {
            case_id: case_id.clone(),
            mode: AddToNotesMode::NoteOnly,
            context,
            items,
            tags: vec!["suspicious".to_string()],
            screenshot_path: None,
            screenshot_id: None,
            explain: false,
            max_items: Some(200),
        };

        let db = CaseDatabase::open(&case_id, &temp_dir.path().join("test_case.sqlite")).unwrap();
        let result = add_to_notes(&db, request).unwrap();

        assert!(!result.note_id.is_empty());

        let note: Option<String> = conn
            .query_row(
                "SELECT title FROM notes WHERE id = ?1",
                [&result.note_id],
                |row| row.get(0),
            )
            .ok();
        assert!(note.is_some());
        assert!(note.unwrap().contains("Selection saved"));
    }

    #[test]
    fn test_note_plus_exhibits_mode() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        let context = SelectionContext {
            case_id: case_id.clone(),
            examiner: "tester".to_string(),
            selection_time: 1700000000,
            active_filters: vec![],
            search_query: None,
            search_fuzzy: false,
            timeline_range_start: None,
            timeline_range_end: None,
        };

        let items = vec![
            SelectionItem {
                item_id: "item1".to_string(),
                item_type: "file".to_string(),
                file_path: Some("/test/file1.txt".to_string()),
                artifact_path: Some("evidence1/file1.txt".to_string()),
                size_bytes: Some(1024),
                hash_md5: Some("abc123".to_string()),
                hash_sha1: None,
                hash_sha256: Some("def456".to_string()),
                evidence_id: Some("ev1".to_string()),
                volume_id: None,
                created_at: Some(1700000000),
                modified_at: Some(1700000000),
                provenance: vec![],
            },
            SelectionItem {
                item_id: "item2".to_string(),
                item_type: "file".to_string(),
                file_path: Some("/test/file2.txt".to_string()),
                artifact_path: Some("evidence1/file2.txt".to_string()),
                size_bytes: Some(2048),
                hash_md5: Some("xyz789".to_string()),
                hash_sha1: None,
                hash_sha256: Some("uvw012".to_string()),
                evidence_id: Some("ev1".to_string()),
                volume_id: None,
                created_at: Some(1700000001),
                modified_at: Some(1700000001),
                provenance: vec![],
            },
        ];

        let request = AddToNotesRequest {
            case_id: case_id.clone(),
            mode: AddToNotesMode::NotePlusExhibits,
            context,
            items,
            tags: vec!["important".to_string(), "review".to_string()],
            screenshot_path: None,
            screenshot_id: None,
            explain: false,
            max_items: Some(200),
        };

        let db = CaseDatabase::open(&case_id, &temp_dir.path().join("test_case.sqlite")).unwrap();
        let result = add_to_notes(&db, request).unwrap();

        assert!(!result.note_id.is_empty());
        assert_eq!(result.exhibit_ids.len(), 2);

        let link_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM note_exhibit_refs WHERE note_id = ?1",
                [&result.note_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(link_count, 2);
    }

    #[test]
    fn test_max_items_validation() {
        let temp_dir = TempDir::new().unwrap();
        let (_conn, case_id) = create_test_db(&temp_dir).unwrap();

        let context = SelectionContext {
            case_id: case_id.clone(),
            examiner: "tester".to_string(),
            selection_time: 1700000000,
            active_filters: vec![],
            search_query: None,
            search_fuzzy: false,
            timeline_range_start: None,
            timeline_range_end: None,
        };

        let items: Vec<SelectionItem> = (0..250)
            .map(|i| SelectionItem {
                item_id: format!("item{}", i),
                item_type: "file".to_string(),
                file_path: None,
                artifact_path: Some(format!("path{}", i)),
                size_bytes: Some(1024),
                hash_md5: None,
                hash_sha1: None,
                hash_sha256: None,
                evidence_id: None,
                volume_id: None,
                created_at: None,
                modified_at: None,
                provenance: vec![],
            })
            .collect();

        let request = AddToNotesRequest {
            case_id: case_id.clone(),
            mode: AddToNotesMode::NoteOnly,
            context,
            items,
            tags: vec![],
            screenshot_path: None,
            screenshot_id: None,
            explain: false,
            max_items: Some(200),
        };

        let db = CaseDatabase::open(&case_id, &temp_dir.path().join("test_case.sqlite")).unwrap();
        let result = add_to_notes(&db, request);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many items"));
    }

    #[test]
    fn test_deterministic_content_json() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        let context = SelectionContext {
            case_id: case_id.clone(),
            examiner: "tester".to_string(),
            selection_time: 1700000000,
            active_filters: vec![],
            search_query: None,
            search_fuzzy: false,
            timeline_range_start: None,
            timeline_range_end: None,
        };

        let items = vec![
            SelectionItem {
                item_id: "item2".to_string(),
                item_type: "file".to_string(),
                file_path: Some("/z/file2.txt".to_string()),
                artifact_path: Some("z/file2.txt".to_string()),
                size_bytes: Some(2048),
                hash_md5: None,
                hash_sha1: None,
                hash_sha256: None,
                evidence_id: None,
                volume_id: None,
                created_at: None,
                modified_at: None,
                provenance: vec![],
            },
            SelectionItem {
                item_id: "item1".to_string(),
                item_type: "file".to_string(),
                file_path: Some("/a/file1.txt".to_string()),
                artifact_path: Some("a/file1.txt".to_string()),
                size_bytes: Some(1024),
                hash_md5: None,
                hash_sha1: None,
                hash_sha256: None,
                evidence_id: None,
                volume_id: None,
                created_at: None,
                modified_at: None,
                provenance: vec![],
            },
        ];

        let request1 = AddToNotesRequest {
            case_id: case_id.clone(),
            mode: AddToNotesMode::NoteOnly,
            context: context.clone(),
            items: items.clone(),
            tags: vec![],
            screenshot_path: None,
            screenshot_id: None,
            explain: false,
            max_items: Some(200),
        };

        let db = CaseDatabase::open(&case_id, &temp_dir.path().join("test_case.sqlite")).unwrap();
        let result1 = add_to_notes(&db, request1).unwrap();

        let content_json1: String = conn
            .query_row(
                "SELECT content_json FROM notes WHERE id = ?1",
                [&result1.note_id],
                |row| row.get(0),
            )
            .unwrap();

        drop(conn);
        let conn2 = rusqlite::Connection::open(temp_dir.path().join("test_case.sqlite")).unwrap();

        let request2 = AddToNotesRequest {
            case_id: case_id.clone(),
            mode: AddToNotesMode::NoteOnly,
            context,
            items,
            tags: vec![],
            screenshot_path: None,
            screenshot_id: None,
            explain: false,
            max_items: Some(200),
        };

        let db2 = CaseDatabase::open(&case_id, &temp_dir.path().join("test_case.sqlite")).unwrap();
        let result2 = add_to_notes(&db2, request2).unwrap();

        let content_json2: String = conn2
            .query_row(
                "SELECT content_json FROM notes WHERE id = ?1",
                [&result2.note_id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(content_json1, content_json2);
    }
}
