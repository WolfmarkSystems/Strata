use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub id: String,
    pub timestamp_utc: u64,
    pub timestamp_local: String,
    pub case_id: String,
    pub evidence_id: Option<String>,
    pub volume_id: Option<String>,
    pub user: String,
    pub session_id: String,
    pub event_type: ActivityEventType,
    pub summary: String,
    pub details: ActivityDetails,
    pub object_refs: Vec<ObjectRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityEventType {
    EvidenceOpened,
    EvidenceAdded,
    VolumeSwitched,
    FilterApplied,
    FilterCleared,
    SearchExecuted,
    SearchResultViewed,
    ArtifactViewed,
    ArtifactPreviewOpened,
    HexViewOpened,
    BookmarkCreated,
    TagCreated,
    ExportStarted,
    ExportCompleted,
    ModuleStarted,
    ModuleCompleted,
    ModuleFailed,
    NotesAdded,
    NoteCreated,
    AddToNotes,
    ExhibitCreated,
    ViewChanged,
    PresetApplied,
    SessionStarted,
    SessionEnded,
    CaseOpened,
    CaseCreated,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActivityDetails {
    pub filters: Option<Vec<FilterDetail>>,
    pub search_query: Option<String>,
    pub result_count: Option<usize>,
    pub module_name: Option<String>,
    pub module_version: Option<String>,
    pub export_type: Option<String>,
    pub export_count: Option<usize>,
    pub view_name: Option<String>,
    pub preset_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterDetail {
    pub filter_type: String,
    pub field: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRef {
    pub object_type: ObjectType,
    pub object_id: String,
    pub path: Option<String>,
    pub hash_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectType {
    File,
    Artifact,
    TimelineEvent,
    SearchResult,
    Bookmark,
    Exhibit,
}

pub struct ActivityLogger {
    case_id: String,
    session_id: String,
    user: String,
    events: Vec<ActivityEvent>,
}

impl ActivityLogger {
    pub fn new(case_id: &str, user: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            session_id: Uuid::new_v4().to_string(),
            user: user.to_string(),
            events: Vec::new(),
        }
    }

    pub fn log(&mut self, event_type: ActivityEventType, summary: &str, details: ActivityDetails) {
        let event = ActivityEvent {
            id: Uuid::new_v4().to_string(),
            timestamp_utc: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            timestamp_local: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            case_id: self.case_id.clone(),
            evidence_id: None,
            volume_id: None,
            user: self.user.clone(),
            session_id: self.session_id.clone(),
            event_type,
            summary: summary.to_string(),
            details,
            object_refs: Vec::new(),
        };
        self.events.push(event);
    }

    pub fn log_with_evidence(
        &mut self,
        evidence_id: &str,
        event_type: ActivityEventType,
        summary: &str,
        details: ActivityDetails,
    ) {
        let event = ActivityEvent {
            id: Uuid::new_v4().to_string(),
            timestamp_utc: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            timestamp_local: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            case_id: self.case_id.clone(),
            evidence_id: Some(evidence_id.to_string()),
            volume_id: None,
            user: self.user.clone(),
            session_id: self.session_id.clone(),
            event_type,
            summary: summary.to_string(),
            details,
            object_refs: Vec::new(),
        };
        self.events.push(event);
    }

    pub fn log_with_object(
        &mut self,
        event_type: ActivityEventType,
        summary: &str,
        details: ActivityDetails,
        object_refs: Vec<ObjectRef>,
    ) {
        let event = ActivityEvent {
            id: Uuid::new_v4().to_string(),
            timestamp_utc: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            timestamp_local: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            case_id: self.case_id.clone(),
            evidence_id: None,
            volume_id: None,
            user: self.user.clone(),
            session_id: self.session_id.clone(),
            event_type,
            summary: summary.to_string(),
            details,
            object_refs,
        };
        self.events.push(event);
    }

    pub fn get_events(&self) -> &Vec<ActivityEvent> {
        &self.events
    }

    pub fn get_session_id(&self) -> &str {
        &self.session_id
    }

    pub fn start_session(&mut self) {
        self.log(
            ActivityEventType::SessionStarted,
            "Examination session started",
            ActivityDetails {
                filters: None,
                search_query: None,
                result_count: None,
                module_name: None,
                module_version: None,
                export_type: None,
                export_count: None,
                view_name: None,
                preset_name: None,
            },
        );
    }

    pub fn end_session(&mut self) {
        self.log(
            ActivityEventType::SessionEnded,
            "Examination session ended",
            ActivityDetails {
                filters: None,
                search_query: None,
                result_count: None,
                module_name: None,
                module_version: None,
                export_type: None,
                export_count: None,
                view_name: None,
                preset_name: None,
            },
        );
    }

    pub fn log_filter_applied(&mut self, filters: Vec<FilterDetail>, result_count: usize) {
        self.log(
            ActivityEventType::FilterApplied,
            &format!("Filter applied, {} results", result_count),
            ActivityDetails {
                filters: Some(filters),
                search_query: None,
                result_count: Some(result_count),
                module_name: None,
                module_version: None,
                export_type: None,
                export_count: None,
                view_name: None,
                preset_name: None,
            },
        );
    }

    pub fn log_search(&mut self, query: &str, result_count: usize) {
        self.log(
            ActivityEventType::SearchExecuted,
            &format!("Search executed: {}", query),
            ActivityDetails {
                filters: None,
                search_query: Some(query.to_string()),
                result_count: Some(result_count),
                module_name: None,
                module_version: None,
                export_type: None,
                export_count: None,
                view_name: None,
                preset_name: None,
            },
        );
    }

    pub fn log_module_run(&mut self, module_name: &str, module_version: &str, success: bool) {
        let event_type = if success {
            ActivityEventType::ModuleCompleted
        } else {
            ActivityEventType::ModuleFailed
        };

        self.log(
            event_type,
            &format!(
                "Module {} {}",
                module_name,
                if success { "completed" } else { "failed" }
            ),
            ActivityDetails {
                filters: None,
                search_query: None,
                result_count: None,
                module_name: Some(module_name.to_string()),
                module_version: Some(module_version.to_string()),
                export_type: None,
                export_count: None,
                view_name: None,
                preset_name: None,
            },
        );
    }

    pub fn log_export(&mut self, export_type: &str, count: usize) {
        self.log(
            ActivityEventType::ExportCompleted,
            &format!("Exported {} items ({})", count, export_type),
            ActivityDetails {
                filters: None,
                search_query: None,
                result_count: None,
                module_name: None,
                module_version: None,
                export_type: Some(export_type.to_string()),
                export_count: Some(count),
                view_name: None,
                preset_name: None,
            },
        );
    }

    pub fn log_artifact_view(&mut self, artifact_type: &str, object_refs: Vec<ObjectRef>) {
        self.log_with_object(
            ActivityEventType::ArtifactViewed,
            &format!("Viewed artifact: {}", artifact_type),
            ActivityDetails {
                filters: None,
                search_query: None,
                result_count: None,
                module_name: Some(artifact_type.to_string()),
                module_version: None,
                export_type: None,
                export_count: None,
                view_name: None,
                preset_name: None,
            },
            object_refs,
        );
    }

    pub fn log_bookmark(&mut self, object_refs: Vec<ObjectRef>, tags: Vec<String>) {
        self.log_with_object(
            ActivityEventType::BookmarkCreated,
            &format!("Bookmark created with tags: {:?}", tags),
            ActivityDetails {
                filters: None,
                search_query: None,
                result_count: Some(object_refs.len()),
                module_name: None,
                module_version: None,
                export_type: None,
                export_count: None,
                view_name: None,
                preset_name: None,
            },
            object_refs,
        );
    }
}
