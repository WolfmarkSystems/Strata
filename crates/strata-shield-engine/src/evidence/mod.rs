use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use tracing::{error, info};
use uuid::Uuid;

use crate::capabilities::{can_run, CapabilityStatus};
use crate::carving::{Carver, CarverResult};
use crate::container::open_evidence_container;
use crate::events::{EngineEventKind, EventSeverity};
use crate::filesystem::{MftMetadata, NtfsParser};
use crate::hashing::{hash_and_categorize_parallel, FileCategory, FileHashResult};
use crate::hashset::{HashCategory, HashSetManager, SqliteHashSetManager};
use crate::memory::MemoryParser;
use crate::parser::{ParsedArtifact, ParserRegistry};
use crate::timeline::{TimelineEntry, TimelineManager};
use crate::virtualization::{FileSystemType, VfsEntry, VirtualFileSystem};

#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceCase {
    pub case_id: Uuid,
    pub created_utc: OffsetDateTime,
    pub containers: Vec<EvidenceContainer>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceContainer {
    pub container_id: Uuid,
    pub description: String,
    pub acquired_utc: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionOutput {
    pub evidence_id: String,
    pub source_path: String,
    pub container_type: Option<ContainerDetection>,
    pub partition_scheme: Option<PartitionDetection>,
    pub volumes: Vec<VolumeDetection>,
    pub detection_timestamp_utc: String,
    pub capability_checks: Vec<CapabilityCheckResult>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub tree: Option<TreeNode>,
    pub categorization_summary: Option<std::collections::HashMap<String, usize>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerDetection {
    pub container_type: String,
    pub size_bytes: u64,
    pub sector_size: u64,
    pub is_supported: bool,
    pub capability_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionDetection {
    pub scheme: String,
    pub partition_count: usize,
    pub is_supported: bool,
    pub capability_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeDetection {
    pub index: usize,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub filesystem: Option<FilesystemDetection>,
    pub partition_type: Option<String>,
    pub is_supported: bool,
    pub capability_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemDetection {
    pub filesystem_type: String,
    pub label: Option<String>,
    pub size_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub is_supported: bool,
    pub capability_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCheckResult {
    pub capability_name: String,
    pub required_status: String,
    pub actual_status: String,
    pub is_satisfied: bool,
}

impl DetectionOutput {
    pub fn new(source_path: &Path) -> Self {
        Self {
            evidence_id: Uuid::new_v4().to_string(),
            source_path: source_path.display().to_string(),
            container_type: None,
            partition_scheme: None,
            volumes: Vec::new(),
            detection_timestamp_utc: chrono::Utc::now().to_rfc3339(),
            capability_checks: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            tree: None,
            categorization_summary: None,
        }
    }

    pub fn with_container_detection(
        mut self,
        container_type: &str,
        size_bytes: u64,
        sector_size: u64,
        capability_name: &str,
    ) -> Self {
        let is_supported = can_run(capability_name, CapabilityStatus::Stub);
        self.container_type = Some(ContainerDetection {
            container_type: container_type.to_string(),
            size_bytes,
            sector_size,
            is_supported,
            capability_name: capability_name.to_string(),
        });
        self.capability_checks.push(CapabilityCheckResult {
            capability_name: capability_name.to_string(),
            required_status: "Stub".to_string(),
            actual_status: if is_supported {
                "Available".to_string()
            } else {
                "Unsupported".to_string()
            },
            is_satisfied: is_supported,
        });
        self
    }

    pub fn with_partition_detection(
        mut self,
        scheme: &str,
        partition_count: usize,
        capability_name: &str,
    ) -> Self {
        let is_supported = can_run(capability_name, CapabilityStatus::Stub);
        self.partition_scheme = Some(PartitionDetection {
            scheme: scheme.to_string(),
            partition_count,
            is_supported,
            capability_name: capability_name.to_string(),
        });
        self.capability_checks.push(CapabilityCheckResult {
            capability_name: capability_name.to_string(),
            required_status: "Stub".to_string(),
            actual_status: if is_supported {
                "Available".to_string()
            } else {
                "Unsupported".to_string()
            },
            is_satisfied: is_supported,
        });
        self
    }

    pub fn add_volume(mut self, volume: VolumeDetection) -> Self {
        if let Some(fs) = &volume.filesystem {
            self.capability_checks.push(CapabilityCheckResult {
                capability_name: fs.capability_name.clone(),
                required_status: "Stub".to_string(),
                actual_status: if fs.is_supported {
                    "Available".to_string()
                } else {
                    "Unsupported".to_string()
                },
                is_satisfied: fs.is_supported,
            });
        }
        self.capability_checks.push(CapabilityCheckResult {
            capability_name: volume.capability_name.clone(),
            required_status: "Stub".to_string(),
            actual_status: if volume.is_supported {
                "Available".to_string()
            } else {
                "Unsupported".to_string()
            },
            is_satisfied: volume.is_supported,
        });
        self.volumes.push(volume);
        self
    }

    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn supported_count(&self) -> usize {
        let mut count = 0;
        if self
            .container_type
            .as_ref()
            .map(|c| c.is_supported)
            .unwrap_or(false)
        {
            count += 1;
        }
        if self
            .partition_scheme
            .as_ref()
            .map(|p| p.is_supported)
            .unwrap_or(false)
        {
            count += 1;
        }
        count += self.volumes.iter().filter(|v| v.is_supported).count();
        count
    }

    pub fn unsupported_count(&self) -> usize {
        let mut count = 0;
        if self
            .container_type
            .as_ref()
            .map(|c| !c.is_supported)
            .unwrap_or(false)
        {
            count += 1;
        }
        if self
            .partition_scheme
            .as_ref()
            .map(|p| !p.is_supported)
            .unwrap_or(false)
        {
            count += 1;
        }
        count += self.volumes.iter().filter(|v| !v.is_supported).count();
        count
    }
}

pub struct EvidenceOpener {
    case_id: String,
    user_name: String,
    session_id: String,
}

impl EvidenceOpener {
    pub fn new(case_id: &str, user_name: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            user_name: user_name.to_string(),
            session_id: Uuid::new_v4().to_string(),
        }
    }

    pub fn open_evidence(&self, source_path: &Path) -> Result<DetectionOutput, String> {
        let mut detection = DetectionOutput::new(source_path);

        if !source_path.exists() {
            let err = format!("Source path does not exist: {}", source_path.display());
            detection.add_error(err.clone());
            return Err(err);
        }

        let metadata = std::fs::metadata(source_path).map_err(|e| {
            let err = format!("Failed to read source metadata: {}", e);
            detection.add_error(err.clone());
            err
        })?;

        if metadata.is_file() {
            let ext = source_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            let (container_type, cap_name) = match ext.as_str() {
                "e01" | "E01" => ("EnCase E01".to_string(), "container.e01"),
                "aff" | "aff4" => ("AFF4".to_string(), "container.aff4"),
                "vmdk" => ("VMDK".to_string(), "container.vmdk"),
                "vhd" | "vhdx" => ("VHD".to_string(), "container.vhd"),
                "001" | "002" | "raw" => ("Split RAW".to_string(), "container.split"),
                _ => ("Raw DD".to_string(), "container.raw"),
            };

            detection =
                detection.with_container_detection(&container_type, metadata.len(), 512, cap_name);
        } else if metadata.is_dir() {
            detection = detection.with_container_detection(
                "Directory (logical)",
                0,
                512,
                "container.directory",
            );
        }

        detection = detection.with_partition_detection("Unknown", 0, "partition.unknown");

        Ok(detection)
    }

    pub fn open_evidence_with_triage(
        &self,
        source_path: &Path,
        ctx: &crate::context::EngineContext,
        _enable_hashset: bool,
        nsrl_path: Option<&Path>,
        custom_bad_path: Option<&Path>,
    ) -> Result<DetectionOutput, String> {
        let mut detection = self.open_evidence(source_path)?;

        if !source_path.exists() {
            return Err(format!("Path does not exist: {}", source_path.display()));
        }

        let event_bus = ctx.event_bus.clone();
        let case_id = Some(self.case_id.clone());
        let job_id = "evidence_triage";

        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobStatus {
                job_id: job_id.to_string(),
                job_type: "triage".to_string(),
                status: "started".to_string(),
            },
            EventSeverity::Info,
            "Starting triage analysis",
        );

        let evidence_source = open_evidence_container(source_path)
            .map_err(|e| format!("Failed to open evidence: {}", e))?;

        let manager = SqliteHashSetManager::new()
            .map_err(|e| format!("Failed to create hashset manager: {}", e))?;

        // Load NSRL if path provided
        if let Some(nsrl) = nsrl_path {
            if nsrl.exists() {
                event_bus.emit_simple(
                    case_id.clone(),
                    EngineEventKind::JobProgress {
                        job_id: job_id.to_string(),
                        job_type: "triage".to_string(),
                        progress: 10.0,
                        message: "Loading NSRL hashset...".to_string(),
                    },
                    EventSeverity::Info,
                    "Loading NSRL",
                );

                match manager.load_nsrl_sqlite(nsrl) {
                    Ok(count) => {
                        event_bus.emit_simple(
                            case_id.clone(),
                            EngineEventKind::JobProgress {
                                job_id: job_id.to_string(),
                                job_type: "triage".to_string(),
                                progress: 20.0,
                                message: format!("Loaded {} NSRL hashes", count),
                            },
                            EventSeverity::Info,
                            "NSRL loaded",
                        );
                    }
                    Err(e) => {
                        event_bus.emit_simple(
                            case_id.clone(),
                            EngineEventKind::JobProgress {
                                job_id: job_id.to_string(),
                                job_type: "triage".to_string(),
                                progress: 20.0,
                                message: format!("Failed to load NSRL: {}", e),
                            },
                            EventSeverity::Warn,
                            "NSRL load failed",
                        );
                    }
                }
            }
        }

        // Load custom bad hashset if path provided
        if let Some(custom) = custom_bad_path {
            if custom.exists() {
                event_bus.emit_simple(
                    case_id.clone(),
                    EngineEventKind::JobProgress {
                        job_id: job_id.to_string(),
                        job_type: "triage".to_string(),
                        progress: 25.0,
                        message: "Loading custom bad hashset...".to_string(),
                    },
                    EventSeverity::Info,
                    "Loading custom hashset",
                );

                match manager.load_custom_hashset(custom, HashCategory::KnownBad) {
                    Ok(count) => {
                        event_bus.emit_simple(
                            case_id.clone(),
                            EngineEventKind::JobProgress {
                                job_id: job_id.to_string(),
                                job_type: "triage".to_string(),
                                progress: 30.0,
                                message: format!("Loaded {} custom bad hashes", count),
                            },
                            EventSeverity::Info,
                            "Custom hashset loaded",
                        );
                    }
                    Err(e) => {
                        event_bus.emit_simple(
                            case_id.clone(),
                            EngineEventKind::JobProgress {
                                job_id: job_id.to_string(),
                                job_type: "triage".to_string(),
                                progress: 30.0,
                                message: format!("Failed to load custom hashset: {}", e),
                            },
                            EventSeverity::Warn,
                            "Custom hashset load failed",
                        );
                    }
                }
            }
        }

        let file_paths: Vec<PathBuf> = if source_path.is_dir() {
            let mut paths: Vec<PathBuf> = Vec::new();
            fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
                let entries = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        collect_files(&path, files)?;
                    } else if path.is_file() {
                        files.push(path);
                    }
                }
                Ok(())
            }
            collect_files(source_path, &mut paths)
                .map_err(|e| format!("Failed to collect files: {}", e))?;
            paths
        } else if let Some(ref _vfs) = evidence_source.vfs {
            event_bus.emit_simple(
                case_id.clone(),
                EngineEventKind::JobProgress {
                    job_id: job_id.to_string(),
                    job_type: "triage".to_string(),
                    progress: 25.0,
                    message: "Container detected - logical file listing not yet implemented for this format".to_string(),
                },
                EventSeverity::Warn,
                "Container format requires filesystem driver",
            );
            detection
                .warnings
                .push("Container triage requires additional filesystem support".to_string());
            Vec::new()
        } else {
            Vec::new()
        };

        if file_paths.is_empty() {
            detection.tree = Some(TreeNode::new_dir(
                source_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| source_path.display().to_string()),
                source_path.to_path_buf(),
            ));
            detection.categorization_summary = Some(std::collections::HashMap::new());

            event_bus.emit_simple(
                case_id,
                EngineEventKind::JobStatus {
                    job_id: job_id.to_string(),
                    job_type: "triage".to_string(),
                    status: "completed".to_string(),
                },
                EventSeverity::Info,
                "Triage analysis complete (no files)",
            );

            return Ok(detection);
        }

        let hash_results = hash_and_categorize_parallel(
            file_paths,
            &manager,
            event_bus.clone(),
            case_id.clone(),
            job_id,
        );

        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for result in &hash_results {
            if let Some(cat) = &result.category {
                *counts.entry(cat.to_string()).or_insert(0) += 1;
            }
        }

        // Build tree - use VFS for disk images
        let tree = build_filtered_tree(source_path, &hash_results, &manager, None)
            .map_err(|e| format!("Failed to build tree: {}", e))?;

        detection.tree = Some(tree);
        detection.categorization_summary = Some(counts);

        event_bus.emit_simple(
            case_id,
            EngineEventKind::JobStatus {
                job_id: job_id.to_string(),
                job_type: "triage".to_string(),
                status: "completed".to_string(),
            },
            EventSeverity::Info,
            "Triage analysis complete",
        );

        Ok(detection)
    }

    pub fn log_detection_to_activity(
        &self,
        detection: &DetectionOutput,
    ) -> crate::case::activity_log::ActivityEvent {
        let summary = format!(
            "Evidence opened: {} ({} volumes detected)",
            detection.source_path,
            detection.volumes.len()
        );

        let details = crate::case::activity_log::ActivityDetails {
            filters: None,
            search_query: None,
            result_count: Some(detection.volumes.len()),
            module_name: Some("evidence_detection".to_string()),
            module_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            export_type: None,
            export_count: None,
            view_name: None,
            preset_name: None,
        };

        crate::case::activity_log::ActivityEvent {
            id: Uuid::new_v4().to_string(),
            timestamp_utc: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            timestamp_local: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            case_id: self.case_id.clone(),
            evidence_id: Some(detection.evidence_id.clone()),
            volume_id: None,
            user: self.user_name.clone(),
            session_id: self.session_id.clone(),
            event_type: crate::case::activity_log::ActivityEventType::EvidenceOpened,
            summary,
            details,
            object_refs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeNode {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub children: Vec<TreeNode>,
    pub visible_by_default: bool,
    pub category: Option<String>,
    pub hash: Option<String>,
    pub size: u64,
    pub mft_record_id: Option<u32>,
    pub sequence_number: Option<u16>,
    pub is_deleted: bool,
    pub ads_names: Vec<String>,
    pub slack_size: Option<u64>,
    pub created_time: Option<i64>,
    pub modified_time: Option<i64>,
    pub accessed_time: Option<i64>,
    pub mft_changed_time: Option<i64>,
    pub is_carved: bool,
    pub carved_offset: Option<u64>,
    pub carved_confidence: Option<String>,
    pub is_memory_process: bool,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub loaded_dlls: Vec<String>,
}

impl TreeNode {
    pub fn new_file(
        name: String,
        path: PathBuf,
        hash: Option<String>,
        size: u64,
        category: FileCategory,
    ) -> Self {
        let visible = matches!(
            category,
            FileCategory::Unknown | FileCategory::KnownBad | FileCategory::Changed
        );

        Self {
            name,
            path,
            is_dir: false,
            children: Vec::new(),
            visible_by_default: visible,
            category: Some(category.to_string()),
            hash,
            size,
            mft_record_id: None,
            sequence_number: None,
            is_deleted: false,
            ads_names: Vec::new(),
            slack_size: None,
            created_time: None,
            modified_time: None,
            accessed_time: None,
            mft_changed_time: None,
            is_carved: false,
            carved_offset: None,
            carved_confidence: None,
            is_memory_process: false,
            pid: None,
            process_name: None,
            loaded_dlls: Vec::new(),
        }
    }

    pub fn new_dir(name: String, path: PathBuf) -> Self {
        Self {
            name,
            path,
            is_dir: true,
            children: Vec::new(),
            visible_by_default: false,
            category: None,
            hash: None,
            size: 0,
            mft_record_id: None,
            sequence_number: None,
            is_deleted: false,
            ads_names: Vec::new(),
            slack_size: None,
            created_time: None,
            modified_time: None,
            accessed_time: None,
            mft_changed_time: None,
            is_carved: false,
            carved_offset: None,
            carved_confidence: None,
            is_memory_process: false,
            pid: None,
            process_name: None,
            loaded_dlls: Vec::new(),
        }
    }

    pub fn new_memory_process(name: String, pid: u32, path: PathBuf) -> Self {
        Self {
            name: name.clone(),
            path,
            is_dir: false,
            children: Vec::new(),
            visible_by_default: true,
            category: Some("memory".to_string()),
            hash: None,
            size: 0,
            mft_record_id: None,
            sequence_number: None,
            is_deleted: false,
            ads_names: Vec::new(),
            slack_size: None,
            created_time: None,
            modified_time: None,
            accessed_time: None,
            mft_changed_time: None,
            is_carved: false,
            carved_offset: None,
            carved_confidence: None,
            is_memory_process: true,
            pid: Some(pid),
            process_name: Some(name),
            loaded_dlls: Vec::new(),
        }
    }

    pub fn merge_mft_metadata(&mut self, mft: &crate::filesystem::MftMetadata) {
        self.mft_record_id = Some(mft.record_number);
        self.sequence_number = Some(mft.sequence_number);
        self.is_deleted = mft.is_deleted;
        self.ads_names = mft.ads_names.clone();
        self.slack_size = mft.slack_size;
        self.created_time = mft.created;
        self.modified_time = mft.modified;
        self.accessed_time = mft.accessed;
        self.mft_changed_time = mft.mft_modified;

        if mft.is_deleted || !mft.ads_names.is_empty() {
            self.visible_by_default = true;
        }

        if let Some(ref name) = mft.name {
            if !name.is_empty() {
                self.name = name.clone();
            }
        }
    }

    pub fn has_ads(&self) -> bool {
        !self.ads_names.is_empty()
    }

    pub fn is_suspicious(&self) -> bool {
        self.is_deleted || self.has_ads() || self.slack_size.is_some()
    }

    pub fn add_child(&mut self, child: TreeNode) {
        if child.visible_by_default {
            self.visible_by_default = true;
        }
        self.children.push(child);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactTag {
    pub tag_id: i64,
    pub name: String,
    pub color: String,
    pub is_system: bool,
}

impl ArtifactTag {
    pub fn notable() -> Self {
        Self {
            tag_id: 1,
            name: "Notable".to_string(),
            color: "#fbbf24".to_string(),
            is_system: true,
        }
    }

    pub fn malware() -> Self {
        Self {
            tag_id: 2,
            name: "Malware".to_string(),
            color: "#ef4444".to_string(),
            is_system: true,
        }
    }

    pub fn csam() -> Self {
        Self {
            tag_id: 3,
            name: "CSAM".to_string(),
            color: "#dc2626".to_string(),
            is_system: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactNote {
    pub note_id: i64,
    pub artifact_path: String,
    pub content: String,
    pub author: String,
    pub created_utc: String,
    pub modified_utc: String,
}

impl ArtifactNote {
    pub fn new(artifact_path: String, content: String, author: String) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            note_id: 0,
            artifact_path,
            content,
            author,
            created_utc: now.clone(),
            modified_utc: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub result_type: SearchResultType,
    pub path: String,
    pub name: String,
    pub description: String,
    pub score: f32,
    pub matched_field: String,
    pub timestamp: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SearchResultType {
    TreeNode,
    TimelineEntry,
    CarvedFile,
    MemoryArtifact,
    BrowserHistory,
    Note,
    YaraHit,
    Tag,
}

pub struct TagManager {
    conn: Connection,
}

impl TagManager {
    pub fn new(db_path: &Path) -> Result<Self, String> {
        let conn =
            Connection::open(db_path).map_err(|e| format!("Failed to open tag DB: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS tags (
                tag_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                color TEXT NOT NULL,
                is_system INTEGER DEFAULT 0
            )",
            [],
        )
        .map_err(|e| format!("Failed to create tags table: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS artifact_tags (
                artifact_path TEXT NOT NULL,
                tag_id INTEGER NOT NULL,
                created_utc TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (artifact_path, tag_id),
                FOREIGN KEY (tag_id) REFERENCES tags(tag_id)
            )",
            [],
        )
        .map_err(|e| format!("Failed to create artifact_tags table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_artifact_tags_path ON artifact_tags(artifact_path)",
            [],
        )
        .ok();

        Self::init_system_tags(&conn)?;

        Ok(Self { conn })
    }

    fn init_system_tags(conn: &Connection) -> Result<(), String> {
        let system_tags = [
            ("Notable", "#fbbf24", 1i64),
            ("Malware", "#ef4444", 2i64),
            ("CSAM", "#dc2626", 3i64),
        ];

        for (name, color, id) in system_tags {
            conn.execute(
                "INSERT OR IGNORE INTO tags (tag_id, name, color, is_system) VALUES (?1, ?2, ?3, 1)",
                params![id, name, color],
            ).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    pub fn get_all_tags(&self) -> Result<Vec<ArtifactTag>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT tag_id, name, color, is_system FROM tags ORDER BY is_system DESC, name",
            )
            .map_err(|e| e.to_string())?;

        let tags = stmt
            .query_map([], |row| {
                Ok(ArtifactTag {
                    tag_id: row.get(0)?,
                    name: row.get(1)?,
                    color: row.get(2)?,
                    is_system: row.get::<_, i32>(3)? == 1,
                })
            })
            .map_err(|e| e.to_string())?;

        tags.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn create_tag(&self, name: String, color: String) -> Result<ArtifactTag, String> {
        self.conn
            .execute(
                "INSERT INTO tags (name, color, is_system) VALUES (?1, ?2, 0)",
                params![name, color],
            )
            .map_err(|e| format!("Failed to create tag: {}", e))?;

        let tag_id = self.conn.last_insert_rowid();

        Ok(ArtifactTag {
            tag_id,
            name,
            color,
            is_system: false,
        })
    }

    pub fn add_tag_to_artifact(&self, artifact_path: &str, tag_id: i64) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO artifact_tags (artifact_path, tag_id) VALUES (?1, ?2)",
                params![artifact_path, tag_id],
            )
            .map_err(|e| format!("Failed to add tag: {}", e))?;

        Ok(())
    }

    pub fn remove_tag_from_artifact(&self, artifact_path: &str, tag_id: i64) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM artifact_tags WHERE artifact_path = ?1 AND tag_id = ?2",
                params![artifact_path, tag_id],
            )
            .map_err(|e| format!("Failed to remove tag: {}", e))?;

        Ok(())
    }

    pub fn get_tags_for_artifact(&self, artifact_path: &str) -> Result<Vec<ArtifactTag>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT t.tag_id, t.name, t.color, t.is_system 
             FROM tags t 
             JOIN artifact_tags at ON t.tag_id = at.tag_id 
             WHERE at.artifact_path = ?1",
            )
            .map_err(|e| e.to_string())?;

        let tags = stmt
            .query_map([artifact_path], |row| {
                Ok(ArtifactTag {
                    tag_id: row.get(0)?,
                    name: row.get(1)?,
                    color: row.get(2)?,
                    is_system: row.get::<_, i32>(3)? == 1,
                })
            })
            .map_err(|e| e.to_string())?;

        tags.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn get_artifact_paths_with_tag(&self, tag_id: i64) -> Result<Vec<String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT artifact_path FROM artifact_tags WHERE tag_id = ?1")
            .map_err(|e| e.to_string())?;

        let paths = stmt
            .query_map([tag_id], |row| row.get(0))
            .map_err(|e| e.to_string())?;

        paths
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn get_tag_counts(&self) -> Result<HashMap<String, usize>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT t.name, COUNT(at.artifact_path) as count 
             FROM tags t 
             LEFT JOIN artifact_tags at ON t.tag_id = at.tag_id 
             GROUP BY t.tag_id",
            )
            .map_err(|e| e.to_string())?;

        let counts = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?))
            })
            .map_err(|e| e.to_string())?;

        let mut result = HashMap::new();
        for count in counts {
            if let Ok((name, cnt)) = count {
                result.insert(name, cnt);
            }
        }
        Ok(result)
    }
}

pub struct NoteManager {
    conn: Connection,
}

impl NoteManager {
    pub fn new(db_path: &Path) -> Result<Self, String> {
        let conn =
            Connection::open(db_path).map_err(|e| format!("Failed to open note DB: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS notes (
                note_id INTEGER PRIMARY KEY,
                artifact_path TEXT NOT NULL,
                content TEXT NOT NULL,
                author TEXT NOT NULL,
                created_utc TEXT DEFAULT CURRENT_TIMESTAMP,
                modified_utc TEXT DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )
        .map_err(|e| format!("Failed to create notes table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_notes_artifact ON notes(artifact_path)",
            [],
        )
        .ok();

        Ok(Self { conn })
    }

    pub fn add_note(
        &self,
        artifact_path: String,
        content: String,
        author: String,
    ) -> Result<ArtifactNote, String> {
        let note = ArtifactNote::new(artifact_path, content, author);

        self.conn
            .execute(
                "INSERT INTO notes (artifact_path, content, author, created_utc, modified_utc) 
             VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    note.artifact_path,
                    note.content,
                    note.author,
                    note.created_utc,
                    note.modified_utc
                ],
            )
            .map_err(|e| format!("Failed to add note: {}", e))?;

        let mut note = note;
        note.note_id = self.conn.last_insert_rowid();

        Ok(note)
    }

    pub fn update_note(&self, note_id: i64, content: String) -> Result<(), String> {
        let modified = chrono::Utc::now().to_rfc3339();

        self.conn
            .execute(
                "UPDATE notes SET content = ?1, modified_utc = ?2 WHERE note_id = ?3",
                params![content, modified, note_id],
            )
            .map_err(|e| format!("Failed to update note: {}", e))?;

        Ok(())
    }

    pub fn delete_note(&self, note_id: i64) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM notes WHERE note_id = ?1", params![note_id])
            .map_err(|e| format!("Failed to delete note: {}", e))?;

        Ok(())
    }

    pub fn get_notes_for_artifact(&self, artifact_path: &str) -> Result<Vec<ArtifactNote>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT note_id, artifact_path, content, author, created_utc, modified_utc 
             FROM notes WHERE artifact_path = ?1 ORDER BY created_utc DESC",
            )
            .map_err(|e| e.to_string())?;

        let notes = stmt
            .query_map([artifact_path], |row| {
                Ok(ArtifactNote {
                    note_id: row.get(0)?,
                    artifact_path: row.get(1)?,
                    content: row.get(2)?,
                    author: row.get(3)?,
                    created_utc: row.get(4)?,
                    modified_utc: row.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;

        notes
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn get_all_notes(&self) -> Result<Vec<ArtifactNote>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT note_id, artifact_path, content, author, created_utc, modified_utc 
             FROM notes ORDER BY created_utc DESC",
            )
            .map_err(|e| e.to_string())?;

        let notes = stmt
            .query_map([], |row| {
                Ok(ArtifactNote {
                    note_id: row.get(0)?,
                    artifact_path: row.get(1)?,
                    content: row.get(2)?,
                    author: row.get(3)?,
                    created_utc: row.get(4)?,
                    modified_utc: row.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;

        notes
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn search_notes(&self, query: &str) -> Result<Vec<ArtifactNote>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT note_id, artifact_path, content, author, created_utc, modified_utc 
             FROM notes WHERE content LIKE ?1 ORDER BY created_utc DESC",
            )
            .map_err(|e| e.to_string())?;

        let search_pattern = format!("%{}%", query);
        let notes = stmt
            .query_map([search_pattern], |row| {
                Ok(ArtifactNote {
                    note_id: row.get(0)?,
                    artifact_path: row.get(1)?,
                    content: row.get(2)?,
                    author: row.get(3)?,
                    created_utc: row.get(4)?,
                    modified_utc: row.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;

        notes
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
}

pub struct SearchManager {
    conn: Connection,
    tag_manager: TagManager,
    note_manager: NoteManager,
}

impl SearchManager {
    pub fn new(db_path: &Path) -> Result<Self, String> {
        let conn =
            Connection::open(db_path).map_err(|e| format!("Failed to open search DB: {}", e))?;

        let _: Result<String, _> = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0));
        let _: Result<i32, _> = conn.query_row("PRAGMA synchronous=NORMAL", [], |row| row.get(0));
        let _: Result<i32, _> = conn.query_row("PRAGMA cache_size=-64000", [], |row| row.get(0));
        let _: Result<i32, _> = conn.query_row("PRAGMA temp_store=MEMORY", [], |row| row.get(0));

        conn.execute(
            "CREATE TABLE IF NOT EXISTS search_index (
                id INTEGER PRIMARY KEY,
                item_type TEXT NOT NULL,
                path TEXT NOT NULL,
                name TEXT NOT NULL,
                content TEXT,
                timestamp INTEGER,
                indexed_utc TEXT DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )
        .map_err(|e| format!("Failed to create search_index table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_search_path ON search_index(path)",
            [],
        )
        .ok();

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_search_name ON search_index(name)",
            [],
        )
        .ok();

        let tag_manager = TagManager::new(db_path)?;
        let note_manager = NoteManager::new(db_path)?;

        Ok(Self {
            conn,
            tag_manager,
            note_manager,
        })
    }

    pub fn index_tree_node(&self, path: &str, name: &str, is_dir: bool) -> Result<(), String> {
        let item_type = if is_dir { "directory" } else { "file" };

        self.conn.execute(
            "INSERT OR REPLACE INTO search_index (item_type, path, name, content) VALUES (?1, ?2, ?3, ?4)",
            params![item_type, path, name, path],
        ).map_err(|e| format!("Failed to index tree node: {}", e))?;

        Ok(())
    }

    pub fn index_tree_nodes_batch(&self, nodes: &[(String, String, bool)]) -> Result<(), String> {
        const BATCH_SIZE: usize = 5000;

        self.conn
            .execute("BEGIN TRANSACTION", [])
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        let mut stmt = self.conn.prepare(
            "INSERT OR REPLACE INTO search_index (item_type, path, name, content) VALUES (?1, ?2, ?3, ?4)"
        ).map_err(|e| format!("Failed to prepare statement: {}", e))?;

        let mut count = 0;
        for (path, name, is_dir) in nodes {
            let item_type = if *is_dir { "directory" } else { "file" };
            stmt.execute(params![item_type, path, name, path])
                .map_err(|e| {
                    let _ = self.conn.execute("ROLLBACK", []);
                    format!("Failed to index tree node: {}", e)
                })?;

            count += 1;
            if count % BATCH_SIZE == 0 {
                drop(stmt);
                self.conn
                    .execute("COMMIT", [])
                    .map_err(|e| format!("Failed to commit: {}", e))?;
                self.conn
                    .execute("BEGIN TRANSACTION", [])
                    .map_err(|e| format!("Failed to begin transaction: {}", e))?;
                stmt = self.conn.prepare(
                    "INSERT OR REPLACE INTO search_index (item_type, path, name, content) VALUES (?1, ?2, ?3, ?4)"
                ).map_err(|e| format!("Failed to prepare statement: {}", e))?;
            }
        }

        drop(stmt);
        self.conn
            .execute("COMMIT", [])
            .map_err(|e| format!("Failed to commit final batch: {}", e))?;

        Ok(())
    }

    pub fn get_node_count(&self) -> Result<usize, String> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM search_index", [], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        Ok(count as usize)
    }

    pub fn index_timeline_entry(
        &self,
        path: &str,
        name: &str,
        description: &str,
        timestamp: Option<i64>,
    ) -> Result<(), String> {
        self.conn.execute(
            "INSERT INTO search_index (item_type, path, name, content, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["timeline", path, name, description, timestamp],
        ).map_err(|e| format!("Failed to index timeline: {}", e))?;

        Ok(())
    }

    pub fn index_yara_hit(
        &self,
        path: &str,
        rule_name: &str,
        description: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO search_index (item_type, path, name, content) VALUES (?1, ?2, ?3, ?4)",
                params!["yarahit", path, rule_name, description],
            )
            .map_err(|e| format!("Failed to index YARA hit: {}", e))?;

        Ok(())
    }

    pub fn search(
        &self,
        query: &str,
        result_types: Option<Vec<SearchResultType>>,
    ) -> Result<Vec<SearchResult>, String> {
        let search_pattern = format!("%{}%", query.to_lowercase());
        let mut results = Vec::new();

        let type_filter = if let Some(ref types) = result_types {
            let type_strings: Vec<String> = types
                .iter()
                .map(|t| {
                    match t {
                        SearchResultType::TreeNode => "file",
                        SearchResultType::TimelineEntry => "timeline",
                        SearchResultType::CarvedFile => "carved",
                        SearchResultType::MemoryArtifact => "memory",
                        SearchResultType::BrowserHistory => "browser",
                        SearchResultType::Note => "note",
                        SearchResultType::YaraHit => "yarahit",
                        SearchResultType::Tag => "tag",
                    }
                    .to_string()
                })
                .collect();
            Some(type_strings)
        } else {
            None
        };

        let sql = if let Some(ref types) = type_filter {
            let placeholders: Vec<String> = types
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + 1))
                .collect();
            format!(
                "SELECT item_type, path, name, content, timestamp FROM search_index WHERE item_type IN ({}) AND (LOWER(name) LIKE ?{} OR LOWER(content) LIKE ?{})",
                placeholders.join(", "),
                types.len() + 1,
                types.len() + 2
            )
        } else {
            "SELECT item_type, path, name, content, timestamp FROM search_index WHERE LOWER(name) LIKE ?1 OR LOWER(content) LIKE ?2".to_string()
        };

        let mut stmt = self.conn.prepare(&sql).map_err(|e| e.to_string())?;

        let search_name = search_pattern.clone();
        let search_content = search_pattern.clone();

        let rows = if let Some(ref types) = type_filter {
            let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
            for t in types {
                params_vec.push(Box::new(t.clone()));
            }
            params_vec.push(Box::new(search_name.clone()));
            params_vec.push(Box::new(search_content.clone()));

            let params_refs: Vec<&dyn rusqlite::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            stmt.query(params_refs.as_slice())
                .map_err(|e| e.to_string())?
        } else {
            stmt.query([search_name, search_content])
                .map_err(|e| e.to_string())?
        };

        let mut rows = rows;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let item_type: String = row.get(0).unwrap_or_default();
            let path: String = row.get(1).unwrap_or_default();
            let name: String = row.get(2).unwrap_or_default();
            let content: String = row.get(3).unwrap_or_default();
            let timestamp: Option<i64> = row.get(4).ok();

            let result_type = match item_type.as_str() {
                "file" | "directory" => SearchResultType::TreeNode,
                "timeline" => SearchResultType::TimelineEntry,
                "carved" => SearchResultType::CarvedFile,
                "memory" => SearchResultType::MemoryArtifact,
                "browser" => SearchResultType::BrowserHistory,
                "note" => SearchResultType::Note,
                "yarahit" => SearchResultType::YaraHit,
                _ => continue,
            };

            if let Some(ref types) = result_types {
                if !types.contains(&result_type) {
                    continue;
                }
            }

            let matched_field = if name.to_lowercase().contains(&query.to_lowercase()) {
                "name".to_string()
            } else {
                "content".to_string()
            };

            let score = if matched_field == "name" { 1.0 } else { 0.5 };

            results.push(SearchResult {
                result_type,
                path,
                name,
                description: content,
                score,
                matched_field,
                timestamp,
            });
        }

        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(results)
    }

    pub fn get_tag_manager(&self) -> &TagManager {
        &self.tag_manager
    }

    pub fn get_note_manager(&self) -> &NoteManager {
        &self.note_manager
    }
}

fn normalize_tree_path(path: &Path) -> String {
    let mut text = path.to_string_lossy().replace('\\', "/");
    if text.is_empty() {
        return "/".to_string();
    }
    if !text.starts_with('/') {
        text.insert(0, '/');
    }
    while text.contains("//") {
        text = text.replace("//", "/");
    }
    while text.len() > 1 && text.ends_with('/') {
        text.pop();
    }
    text.to_ascii_lowercase()
}

fn get_or_create_dir_child<'a>(
    parent: &'a mut TreeNode,
    name: &str,
    path: PathBuf,
) -> &'a mut TreeNode {
    if let Some(existing_idx) = parent
        .children
        .iter()
        .position(|child| child.is_dir && child.name.eq_ignore_ascii_case(name))
    {
        return &mut parent.children[existing_idx];
    }
    parent.add_child(TreeNode::new_dir(name.to_string(), path));
    let idx = parent.children.len() - 1;
    &mut parent.children[idx]
}

fn sort_tree_recursively(node: &mut TreeNode) {
    node.children.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    for child in &mut node.children {
        if child.is_dir {
            sort_tree_recursively(child);
        }
    }
}

fn add_vfs_entry_to_volume_tree(
    volume_node: &mut TreeNode,
    volume_index: usize,
    entry: &VfsEntry,
    hash_lookup: &HashMap<String, &FileHashResult>,
) {
    fn apply_vfs_metadata(node: &mut TreeNode, entry: &VfsEntry) {
        if node.modified_time.is_none() {
            node.modified_time = entry.modified.map(|dt| dt.timestamp_millis());
        }
    }

    let volume_root = PathBuf::from(format!("/vol{}", volume_index));
    let mut components: Vec<String> = entry
        .path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(name) => Some(name.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();

    let volume_component = format!("vol{}", volume_index);
    if components
        .first()
        .map(|c| c.eq_ignore_ascii_case(&volume_component))
        .unwrap_or(false)
    {
        components.remove(0);
    }
    if components.is_empty() {
        components.push(entry.name.clone());
    }

    let mut current = volume_node;
    let mut current_path = volume_root.clone();

    for part in components.iter().take(components.len().saturating_sub(1)) {
        current_path.push(part);
        current = get_or_create_dir_child(current, part, current_path.clone());
    }

    let leaf_name = components
        .last()
        .cloned()
        .unwrap_or_else(|| entry.name.clone());
    let leaf_path = if entry.path.as_os_str().is_empty() {
        let mut p = current_path;
        p.push(&leaf_name);
        p
    } else {
        entry.path.clone()
    };
    let leaf_norm = normalize_tree_path(leaf_path.as_path());

    if entry.is_dir {
        let dir_node = get_or_create_dir_child(current, &leaf_name, leaf_path);
        apply_vfs_metadata(dir_node, entry);
    } else if !current
        .children
        .iter()
        .any(|child| !child.is_dir && normalize_tree_path(child.path.as_path()) == leaf_norm)
    {
        let hash_result = hash_lookup.get(&leaf_norm).copied();
        let hash = hash_result.map(|h| h.sha256.clone());
        let category = hash_result
            .and_then(|h| h.category)
            .unwrap_or(FileCategory::Unknown);
        let mut node = TreeNode::new_file(leaf_name, leaf_path, hash, entry.size, category);
        apply_vfs_metadata(&mut node, entry);
        info!(
            "[TREE] Added real file: {} (size {}, created {:?}, modified {:?})",
            node.name, node.size, node.created_time, node.modified_time
        );
        current.add_child(node);
    }
}

pub fn build_filtered_tree(
    root_path: &Path,
    hash_results: &[FileHashResult],
    manager: &SqliteHashSetManager,
    vfs: Option<&dyn crate::virtualization::VirtualFileSystem>,
) -> Result<TreeNode, String> {
    info!("build_filtered_tree called for: {:?}", root_path);

    if !root_path.exists() {
        error!("Root path does not exist: {}", root_path.display());
        return Err(format!("Root path does not exist: {}", root_path.display()));
    }

    let root_name = root_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| root_path.display().to_string());

    info!("Root name: {}", root_name);
    let mut root = TreeNode::new_dir(root_name, root_path.to_path_buf());
    let hash_lookup: HashMap<String, &FileHashResult> = hash_results
        .iter()
        .map(|h| (normalize_tree_path(h.path.as_path()), h))
        .collect();

    // Process based on path type
    if root_path.is_dir() {
        build_dir_tree(root_path, &mut root, hash_results, manager)?;
    } else if root_path.is_file() {
        // REAL MOUNTING PATH: Use VFS to enumerate volumes
        info!("[CRITICAL] Processing disk image with real VFS...");

        if let Some(vfs) = vfs {
            info!("[CRITICAL] VFS available - enumerating volumes...");
            let volumes = vfs.get_volumes();
            let volume_count = volumes.len();
            info!("[CRITICAL] Found {} volumes", volume_count);

            #[cfg(feature = "parallel")]
            {
                use rayon::prelude::*;

                let processed_volumes: Vec<TreeNode> = volumes
                    .par_iter()
                    .map(|volume| {
                        let vol_name =
                            format!("Volume{} ({:?})", volume.volume_index, volume.filesystem);
                        let mut vol_node = TreeNode::new_dir(vol_name, root_path.to_path_buf());

                        let mut entries: Vec<VfsEntry> = Vec::new();

                        if let Ok(vol_entries) = vfs.enumerate_volume(volume.volume_index) {
                            entries = vol_entries;
                        }

                        if entries.is_empty() {
                            let volume_path = PathBuf::from(format!("/vol{}", volume.volume_index));
                            if let Ok(root_entries) = vfs.read_dir(&volume_path) {
                                entries = root_entries;
                            }
                        }

                        for entry in &entries {
                            add_vfs_entry_to_volume_tree(
                                &mut vol_node,
                                volume.volume_index,
                                entry,
                                &hash_lookup,
                            );
                        }

                        if volume.filesystem == FileSystemType::NTFS {
                            let parser = NtfsParser::new().with_max_records(120_000);
                            if let Ok(mft) = parser.analyze_volume(vfs, volume) {
                                let metadata_map = NtfsParser::build_metadata_map(&mft);
                                merge_mft_metadata_into_tree(&mut vol_node, &metadata_map);
                            }
                        }

                        vol_node
                    })
                    .collect();

                for vol_node in processed_volumes {
                    if !vol_node.children.is_empty() {
                        root.add_child(vol_node);
                    }
                }
            }

            #[cfg(not(feature = "parallel"))]
            {
                for volume in &volumes {
                    let vol_name =
                        format!("Volume{} ({:?})", volume.volume_index, volume.filesystem);
                    let mut vol_node = TreeNode::new_dir(vol_name, root_path.to_path_buf());

                    let mut entries: Vec<VfsEntry> = Vec::new();
                    match vfs.enumerate_volume(volume.volume_index) {
                        Ok(vol_entries) => entries = vol_entries,
                        Err(e) => error!("[CRITICAL] enumerate_volume error: {:?}", e),
                    }

                    if entries.is_empty() {
                        let volume_path = PathBuf::from(format!("/vol{}", volume.volume_index));
                        if let Ok(root_entries) = vfs.read_dir(&volume_path) {
                            entries = root_entries;
                        }
                    }

                    for entry in &entries {
                        add_vfs_entry_to_volume_tree(
                            &mut vol_node,
                            volume.volume_index,
                            entry,
                            &hash_lookup,
                        );
                    }

                    if volume.filesystem == FileSystemType::NTFS {
                        let parser = NtfsParser::new().with_max_records(120_000);
                        if let Ok(mft) = parser.analyze_volume(vfs, volume) {
                            let metadata_map = NtfsParser::build_metadata_map(&mft);
                            merge_mft_metadata_into_tree(&mut vol_node, &metadata_map);
                        }
                    }

                    if !vol_node.children.is_empty() {
                        root.add_child(vol_node);
                    }
                }
            }

            // If no volumes found, still add the raw file as fallback
            if volume_count == 0 {
                info!("[CRITICAL] No volumes found - adding raw file entry");
                let file_size = std::fs::metadata(root_path).map(|m| m.len()).unwrap_or(0);
                let hash_result = hash_results.iter().find(|h| h.path == root_path);
                let sha256 = hash_result.map(|h| h.sha256.clone());
                let category = if let Some(h) = hash_result {
                    manager.categorize_with_path(h)
                } else {
                    FileCategory::Unknown
                };
                let node = TreeNode::new_file(
                    root.name.clone(),
                    root_path.to_path_buf(),
                    sha256,
                    file_size,
                    category,
                );
                root.add_child(node);
            }
        } else {
            info!("[CRITICAL] No VFS - using raw file fallback");
            let file_size = std::fs::metadata(root_path).map(|m| m.len()).unwrap_or(0);
            let hash_result = hash_results.iter().find(|h| h.path == root_path);
            let sha256 = hash_result.map(|h| h.sha256.clone());
            let category = if let Some(h) = hash_result {
                manager.categorize_with_path(h)
            } else {
                FileCategory::Unknown
            };
            let node = TreeNode::new_file(
                root.name.clone(),
                root_path.to_path_buf(),
                sha256,
                file_size,
                category,
            );
            root.add_child(node);
        }
        info!("[CRITICAL] Tree built with real VFS");
    }

    sort_tree_recursively(&mut root);

    Ok(root)
}

fn build_dir_tree(
    dir_path: &Path,
    parent: &mut TreeNode,
    hash_results: &[FileHashResult],
    manager: &SqliteHashSetManager,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir_path)
        .map_err(|e| format!("Failed to read directory {}: {}", dir_path.display(), e))?;

    let mut children: Vec<TreeNode> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if path.is_dir() {
            let mut dir_node = TreeNode::new_dir(name, path.clone());
            build_dir_tree(&path, &mut dir_node, hash_results, manager)?;
            if !dir_node.children.is_empty() {
                children.push(dir_node);
            }
        } else if path.is_file() {
            let hash_result = hash_results.iter().find(|h| h.path == path);

            if let Some(result) = hash_result {
                let category = manager.categorize_with_path(result);
                let node = TreeNode::new_file(
                    name,
                    path,
                    Some(result.sha256.clone()),
                    result.size,
                    category,
                );
                children.push(node);
            } else {
                let metadata = std::fs::metadata(&path).ok();
                let size = metadata.map(|m| m.len()).unwrap_or(0);
                let node = TreeNode::new_file(name, path, None, size, FileCategory::Unknown);
                children.push(node);
            }
        }
    }

    children.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    for child in children {
        parent.add_child(child);
    }

    Ok(())
}

pub fn categorize_hash_results(
    results: &mut [FileHashResult],
    manager: &HashSetManager,
) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();

    for result in results.iter_mut() {
        let category = manager.categorize(result);
        result.category = Some(category);
        *counts.entry(category.to_string()).or_insert(0) += 1;
    }

    counts
}

pub fn merge_mft_metadata_into_tree(
    tree: &mut TreeNode,
    mft_metadata: &HashMap<String, MftMetadata>,
) {
    let file_name = tree.name.to_lowercase();

    if let Some(mft) = mft_metadata.get(&file_name) {
        tree.merge_mft_metadata(mft);
    }

    if tree.is_dir {
        for child in &mut tree.children {
            merge_mft_metadata_into_tree(child, mft_metadata);
        }
    }
}

pub struct EvidenceAnalyzer {
    registry: ParserRegistry,
    timeline_manager: TimelineManager,
    search_manager: Option<SearchManager>,
    plugin_manager: Option<crate::plugin::PluginManager>,
}

impl EvidenceAnalyzer {
    pub fn new(timeline_db_path: &Path) -> Result<Self, String> {
        let timeline_manager = TimelineManager::new(timeline_db_path)?;
        let search_manager = SearchManager::new(timeline_db_path).ok();

        let mut registry = ParserRegistry::new();
        registry.register_default_parsers();

        Ok(Self {
            registry,
            timeline_manager,
            search_manager,
            plugin_manager: None,
        })
    }

    pub fn load_plugins(&mut self, plugin_dir: &Path) -> Result<usize, String> {
        let mut manager = crate::plugin::PluginManager::new(plugin_dir);

        let loaded = manager
            .load_all()
            .map_err(|e| format!("Failed to load plugins: {}", e))?;

        self.plugin_manager = Some(manager);

        Ok(loaded)
    }

    pub fn get_loaded_plugins(&self) -> Vec<crate::plugin::PluginInfo> {
        self.plugin_manager
            .as_ref()
            .map(|pm| pm.plugin_infos())
            .unwrap_or_default()
    }

    pub fn analyze(
        &mut self,
        root_path: &Path,
        vfs: Option<&dyn VirtualFileSystem>,
        event_bus: &Arc<crate::events::EventBus>,
        case_id: Option<String>,
    ) -> Result<usize, String> {
        let job_id = "artifact_analysis";

        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobStatus {
                job_id: job_id.to_string(),
                job_type: "artifact_parsing".to_string(),
                status: "started".to_string(),
            },
            EventSeverity::Info,
            "Starting artifact analysis",
        );

        let mut total_artifacts = 0;

        let parser_info: Vec<_> = self
            .registry
            .parsers()
            .iter()
            .map(|p| {
                (
                    p.name().to_string(),
                    p.artifact_type().to_string(),
                    p.target_patterns(),
                )
            })
            .collect();

        let mut pending_artifacts: Vec<ParsedArtifact> = Vec::new();

        for (parser_name, _artifact_type, patterns) in parser_info {
            event_bus.emit_simple(
                case_id.clone(),
                EngineEventKind::ParserProgress {
                    parser_name: parser_name.clone(),
                    progress: 0.0,
                    message: format!("Starting {}", parser_name),
                },
                EventSeverity::Info,
                &format!("Parser started: {}", parser_name),
            );

            let file_paths = if let Some(vfs) = vfs {
                self.collect_matching_files(vfs, patterns)
            } else {
                self.collect_matching_files_local(root_path, patterns)
            };

            let total_files = file_paths.len();
            let mut parser_artifacts = 0;

            for (i, file_path) in file_paths.iter().enumerate() {
                let data = if let Some(vfs) = vfs {
                    vfs.open_file(file_path).unwrap_or_default()
                } else {
                    std::fs::read(file_path).unwrap_or_default()
                };

                for parser in self.registry.parsers() {
                    if parser.name() != parser_name {
                        continue;
                    }

                    if let Ok(artifacts) = parser.parse_file(file_path, &data) {
                        for artifact in artifacts {
                            pending_artifacts.push(artifact);
                            parser_artifacts += 1;
                        }
                    }
                    break;
                }

                if i > 0 && i % 10 == 0 || i == total_files - 1 {
                    let progress = ((i + 1) as f32 / total_files as f32) * 100.0;
                    event_bus.emit_simple(
                        case_id.clone(),
                        EngineEventKind::ParserProgress {
                            parser_name: parser_name.clone(),
                            progress,
                            message: format!("Processed {}/{} files", i + 1, total_files),
                        },
                        EventSeverity::Info,
                        &format!("Parsing: {}/{}", i + 1, total_files),
                    );
                }
            }

            event_bus.emit_simple(
                case_id.clone(),
                EngineEventKind::ParserComplete {
                    parser_name: parser_name.clone(),
                    artifacts_found: parser_artifacts,
                },
                EventSeverity::Info,
                &format!(
                    "Parser {} found {} artifacts",
                    parser_name, parser_artifacts
                ),
            );

            total_artifacts += parser_artifacts;
        }

        if let Some(ref plugin_manager) = self.plugin_manager {
            let plugin_artifacts =
                plugin_manager.run_plugins(vfs, root_path, Some(event_bus), case_id.as_deref());

            for artifact in plugin_artifacts {
                if let Ok(entry_id) = self.insert_artifact(&artifact) {
                    event_bus.emit_simple(
                        case_id.clone(),
                        EngineEventKind::TimelineEntryAdded {
                            entry_id: entry_id.to_string(),
                            artifact_type: artifact.artifact_type.clone(),
                        },
                        EventSeverity::Info,
                        &format!(
                            "Plugin Timeline: {} - {}",
                            artifact.artifact_type, artifact.description
                        ),
                    );
                }
            }
        }

        for artifact in pending_artifacts {
            if let Ok(entry_id) = self.insert_artifact(&artifact) {
                event_bus.emit_simple(
                    case_id.clone(),
                    EngineEventKind::TimelineEntryAdded {
                        entry_id: entry_id.to_string(),
                        artifact_type: artifact.artifact_type.clone(),
                    },
                    EventSeverity::Info,
                    &format!(
                        "Timeline: {} - {}",
                        artifact.artifact_type, artifact.description
                    ),
                );
            }
        }

        event_bus.emit_simple(
            case_id,
            EngineEventKind::JobStatus {
                job_id: job_id.to_string(),
                job_type: "artifact_parsing".to_string(),
                status: "completed".to_string(),
            },
            EventSeverity::Info,
            &format!(
                "Artifact analysis complete: {} total artifacts",
                total_artifacts
            ),
        );

        Ok(total_artifacts)
    }

    fn collect_matching_files(
        &self,
        vfs: &dyn VirtualFileSystem,
        patterns: Vec<&str>,
    ) -> Vec<PathBuf> {
        let mut matches = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut stack: Vec<PathBuf> = vec![PathBuf::from("/")];

        while let Some(dir) = stack.pop() {
            let normalized = normalize_tree_path(dir.as_path());
            if !visited.insert(normalized) {
                continue;
            }
            if let Ok(entries) = vfs.read_dir(dir.as_path()) {
                self.find_matching_entries(vfs, &entries, &patterns, &mut matches, &mut stack);
            }
        }

        matches
    }

    fn find_matching_entries(
        &self,
        _vfs: &dyn VirtualFileSystem,
        entries: &[VfsEntry],
        patterns: &[&str],
        results: &mut Vec<PathBuf>,
        recurse_stack: &mut Vec<PathBuf>,
    ) {
        for entry in entries {
            if entry.is_dir {
                recurse_stack.push(entry.path.clone());
            } else {
                let name_lower = entry.name.to_lowercase();
                let path_lower = entry.path.to_string_lossy().to_lowercase();
                for pattern in patterns {
                    let pattern_lower = pattern.to_lowercase();
                    if pattern_lower.starts_with('.') && name_lower.ends_with(&pattern_lower) {
                        results.push(entry.path.clone());
                        break;
                    } else if name_lower.contains(&pattern_lower)
                        || path_lower.contains(&pattern_lower)
                    {
                        results.push(entry.path.clone());
                        break;
                    }
                }
            }
        }
    }

    fn collect_matching_files_local(&self, root: &Path, patterns: Vec<&str>) -> Vec<PathBuf> {
        let mut matches = Vec::new();

        fn walk_dir(dir: &Path, patterns: &[&str], results: &mut Vec<PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        walk_dir(&path, patterns, results);
                    } else {
                        let name = entry.file_name().to_string_lossy().to_lowercase();
                        let path_lower = path.to_string_lossy().to_lowercase();
                        for pattern in patterns {
                            let pattern_lower = pattern.to_lowercase();
                            if name.ends_with(&pattern_lower)
                                || name.contains(&pattern_lower)
                                || path_lower.contains(&pattern_lower)
                            {
                                results.push(path);
                                break;
                            }
                        }
                    }
                }
            }
        }

        walk_dir(root, &patterns, &mut matches);
        matches
    }

    fn insert_artifact(&mut self, artifact: &ParsedArtifact) -> Result<i64, String> {
        let entry = TimelineEntry::new(
            artifact.timestamp,
            artifact.artifact_type.clone(),
            artifact.description.clone(),
            artifact.source_path.clone(),
            artifact.json_data.clone(),
        );

        self.timeline_manager.insert_entry(&entry)
    }

    pub fn get_timeline_count(&self) -> Result<usize, String> {
        self.timeline_manager.get_count()
    }

    pub fn get_initial_timeline(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::timeline::TimelineEntry>, String> {
        self.timeline_manager.get_initial_entries(limit)
    }

    pub fn analyze_ntfs_volumes<V: VirtualFileSystem>(
        &mut self,
        vfs: &V,
        event_bus: &Arc<crate::events::EventBus>,
        case_id: Option<String>,
    ) -> Result<usize, String> {
        let job_id = "ntfs_analysis";

        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobStatus {
                job_id: job_id.to_string(),
                job_type: "ntfs_mft".to_string(),
                status: "started".to_string(),
            },
            EventSeverity::Info,
            "Starting NTFS MFT analysis",
        );

        let volumes = vfs.get_volumes();

        if volumes.is_empty() {
            event_bus.emit_simple(
                case_id.clone(),
                EngineEventKind::JobStatus {
                    job_id: job_id.to_string(),
                    job_type: "ntfs_mft".to_string(),
                    status: "completed".to_string(),
                },
                EventSeverity::Info,
                "No NTFS volumes detected",
            );
            return Ok(0);
        }

        let parser = NtfsParser::new();
        let mut total_entries = 0;

        for vol in &volumes {
            if vol.filesystem != crate::virtualization::FileSystemType::NTFS {
                continue;
            }

            event_bus.emit_simple(
                case_id.clone(),
                EngineEventKind::JobProgress {
                    job_id: job_id.to_string(),
                    job_type: "ntfs_mft".to_string(),
                    progress: 0.0,
                    message: format!(
                        "Analyzing NTFS volume {} (MFT at offset {:?})",
                        vol.volume_index, vol.mft_offset
                    ),
                },
                EventSeverity::Info,
                "Analyzing NTFS volume",
            );

            match parser.analyze_volume(vfs, vol) {
                Ok(metadata) => {
                    let timeline_entries = NtfsParser::to_timeline_entries(&metadata);

                    for te in &timeline_entries {
                        if self.timeline_manager.insert_entry(te).is_ok() {
                            total_entries += 1;

                            event_bus.emit_simple(
                                case_id.clone(),
                                EngineEventKind::TimelineEntryAdded {
                                    entry_id: te.id.to_string(),
                                    artifact_type: te.artifact_type.clone(),
                                },
                                EventSeverity::Info,
                                &format!("NTFS: {}", te.description),
                            );
                        }
                    }

                    event_bus.emit_simple(
                        case_id.clone(),
                        EngineEventKind::JobProgress {
                            job_id: job_id.to_string(),
                            job_type: "ntfs_mft".to_string(),
                            progress: 100.0,
                            message: format!(
                                "Found {} MFT entries, {} timeline events",
                                metadata.len(),
                                timeline_entries.len()
                            ),
                        },
                        EventSeverity::Info,
                        "NTFS volume analyzed",
                    );
                }
                Err(e) => {
                    event_bus.emit_simple(
                        case_id.clone(),
                        EngineEventKind::JobProgress {
                            job_id: job_id.to_string(),
                            job_type: "ntfs_mft".to_string(),
                            progress: 0.0,
                            message: format!("Error analyzing NTFS: {}", e),
                        },
                        EventSeverity::Warn,
                        "NTFS analysis error",
                    );
                }
            }
        }

        event_bus.emit_simple(
            case_id,
            EngineEventKind::JobStatus {
                job_id: job_id.to_string(),
                job_type: "ntfs_mft".to_string(),
                status: "completed".to_string(),
            },
            EventSeverity::Info,
            &format!("NTFS analysis complete: {} timeline entries", total_entries),
        );

        Ok(total_entries)
    }

    pub fn run_carving<V: VirtualFileSystem>(
        &mut self,
        vfs: &V,
        event_bus: &Arc<crate::events::EventBus>,
        case_id: Option<String>,
    ) -> Result<Vec<CarverResult>, String> {
        let job_id = "carving";

        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobStatus {
                job_id: job_id.to_string(),
                job_type: "carving".to_string(),
                status: "started".to_string(),
            },
            EventSeverity::Info,
            "Starting file carving",
        );

        let output_dir = std::env::temp_dir().join("forensic_carved");

        let carver = Carver::new()
            .with_max_size(50 * 1024 * 1024)
            .with_max_hits(1000);

        let output_path = output_dir.clone();

        let callback = |count: usize, msg: &str| {
            if count % 10 == 0 {
                println!("Carving: {} - {}", count, msg);
            }
        };

        match carver.carve(vfs, &output_path, Some(&callback)) {
            Ok(results) => {
                let count = results.len();

                for result in &results {
                    let entry = TimelineEntry::new(
                        Some(result.timestamp),
                        "carved".to_string(),
                        format!(
                            "Carved: {}.{} (offset: {}, confidence: {})",
                            result.signature_name,
                            result.extension,
                            result.original_offset,
                            result.confidence
                        ),
                        result.carved_path.to_string_lossy().to_string(),
                        serde_json::json!({
                            "offset": result.original_offset,
                            "size": result.size,
                            "type": result.carved_type,
                            "confidence": result.confidence,
                        }),
                    );

                    let _ = self.timeline_manager.insert_entry(&entry);

                    event_bus.emit_simple(
                        case_id.clone(),
                        EngineEventKind::TimelineEntryAdded {
                            entry_id: entry.id.to_string(),
                            artifact_type: "carved".to_string(),
                        },
                        EventSeverity::Info,
                        &format!("Carved: {}.{}", result.signature_name, result.extension),
                    );
                }

                event_bus.emit_simple(
                    case_id.clone(),
                    EngineEventKind::JobStatus {
                        job_id: job_id.to_string(),
                        job_type: "carving".to_string(),
                        status: "completed".to_string(),
                    },
                    EventSeverity::Info,
                    &format!("Carving complete: {} files recovered", count),
                );

                Ok(results)
            }
            Err(e) => {
                event_bus.emit_simple(
                    case_id.clone(),
                    EngineEventKind::JobStatus {
                        job_id: job_id.to_string(),
                        job_type: "carving".to_string(),
                        status: "failed".to_string(),
                    },
                    EventSeverity::Warn,
                    &format!("Carving failed: {}", e),
                );

                Err(e)
            }
        }
    }

    pub fn analyze_memory_dump<V: VirtualFileSystem>(
        &mut self,
        vfs: &V,
        event_bus: &Arc<crate::events::EventBus>,
        case_id: Option<String>,
    ) -> Result<usize, String> {
        if !vfs.is_memory_dump() {
            return Ok(0);
        }

        let job_id = "memory_analysis";

        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobStatus {
                job_id: job_id.to_string(),
                job_type: "memory".to_string(),
                status: "started".to_string(),
            },
            EventSeverity::Info,
            "Starting memory analysis",
        );

        let parser = MemoryParser::new();

        let mem = parser
            .parse_memory_dump(vfs.root())
            .map_err(|e| format!("Failed to parse memory dump: {}", e))?;

        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobProgress {
                job_id: job_id.to_string(),
                job_type: "memory".to_string(),
                progress: 30.0,
                message: format!("Memory dump: {} bytes", mem.size),
            },
            EventSeverity::Info,
            "Parsing memory dump",
        );

        let strings = parser
            .extract_strings(vfs.root())
            .map_err(|e| format!("Failed to extract strings: {}", e))?;

        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobProgress {
                job_id: job_id.to_string(),
                job_type: "memory".to_string(),
                progress: 60.0,
                message: format!("Extracted {} strings", strings.len()),
            },
            EventSeverity::Info,
            "Extracting strings",
        );

        let artifacts = parser.to_artifacts(&mem, &strings);
        let mut count = 0;

        for artifact in &artifacts {
            if let Ok(entry_id) = self.insert_artifact(artifact) {
                count += 1;

                event_bus.emit_simple(
                    case_id.clone(),
                    EngineEventKind::TimelineEntryAdded {
                        entry_id: entry_id.to_string(),
                        artifact_type: artifact.artifact_type.clone(),
                    },
                    EventSeverity::Info,
                    &format!("Memory: {}", artifact.description),
                );
            }
        }

        event_bus.emit_simple(
            case_id,
            EngineEventKind::JobStatus {
                job_id: job_id.to_string(),
                job_type: "memory".to_string(),
                status: "completed".to_string(),
            },
            EventSeverity::Info,
            &format!("Memory analysis complete: {} artifacts", count),
        );

        Ok(count)
    }

    pub fn global_search(
        &self,
        query: &str,
        result_types: Option<Vec<SearchResultType>>,
    ) -> Result<Vec<SearchResult>, String> {
        if let Some(ref sm) = self.search_manager {
            sm.search(query, result_types)
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn index_tree_for_search(&self, tree: &TreeNode) -> Result<(), String> {
        if let Some(ref sm) = self.search_manager {
            let mut nodes: Vec<(String, String, bool)> = Vec::new();
            self.collect_tree_nodes(tree, &mut nodes);

            let total_nodes = nodes.len();
            info!("Indexing {} tree nodes for search...", total_nodes);

            if total_nodes == 0 {
                return Ok(());
            }

            const BATCH_SIZE: usize = 5000;
            let mut processed = 0;

            for chunk in nodes.chunks(BATCH_SIZE) {
                sm.index_tree_nodes_batch(chunk)?;
                processed += chunk.len();
                let progress = (processed as f64 / total_nodes as f64) * 100.0;
                if processed % 50000 == 0 || processed == total_nodes {
                    info!(
                        "Search indexing: {}/{} nodes ({:.1}%)",
                        processed, total_nodes, progress
                    );
                }
            }

            info!("Search indexing complete: {} nodes indexed", total_nodes);
            Ok(())
        } else {
            Ok(())
        }
    }

    fn collect_tree_nodes(&self, node: &TreeNode, nodes: &mut Vec<(String, String, bool)>) {
        nodes.push((
            node.path.to_string_lossy().to_string(),
            node.name.clone(),
            node.is_dir,
        ));
        for child in &node.children {
            self.collect_tree_nodes(child, nodes);
        }
    }

    pub fn get_all_tags(&self) -> Result<Vec<ArtifactTag>, String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_tag_manager().get_all_tags()
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn create_tag(&self, name: String, color: String) -> Result<ArtifactTag, String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_tag_manager().create_tag(name, color)
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn add_tag_to_artifact(&self, artifact_path: &str, tag_id: i64) -> Result<(), String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_tag_manager()
                .add_tag_to_artifact(artifact_path, tag_id)
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn remove_tag_from_artifact(&self, artifact_path: &str, tag_id: i64) -> Result<(), String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_tag_manager()
                .remove_tag_from_artifact(artifact_path, tag_id)
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn get_tags_for_artifact(&self, artifact_path: &str) -> Result<Vec<ArtifactTag>, String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_tag_manager().get_tags_for_artifact(artifact_path)
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn get_tag_counts(&self) -> Result<HashMap<String, usize>, String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_tag_manager().get_tag_counts()
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn add_note(
        &self,
        artifact_path: String,
        content: String,
        author: String,
    ) -> Result<ArtifactNote, String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_note_manager()
                .add_note(artifact_path, content, author)
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn update_note(&self, note_id: i64, content: String) -> Result<(), String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_note_manager().update_note(note_id, content)
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn delete_note(&self, note_id: i64) -> Result<(), String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_note_manager().delete_note(note_id)
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn get_notes_for_artifact(&self, artifact_path: &str) -> Result<Vec<ArtifactNote>, String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_note_manager().get_notes_for_artifact(artifact_path)
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn get_all_notes(&self) -> Result<Vec<ArtifactNote>, String> {
        if let Some(ref sm) = self.search_manager {
            sm.get_note_manager().get_all_notes()
        } else {
            Err("Search manager not initialized".to_string())
        }
    }

    pub fn export_artifact(
        &self,
        source_path: &str,
        destination_dir: &Path,
        include_metadata: bool,
        verify_hash: bool,
    ) -> Result<String, String> {
        let source = Path::new(source_path);
        if !source.exists() {
            return Err(format!("Source file does not exist: {}", source_path));
        }

        if !destination_dir.exists() {
            std::fs::create_dir_all(destination_dir)
                .map_err(|e| format!("Failed to create destination directory: {}", e))?;
        }

        let file_name = source
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown_file".to_string());

        let dest_path = destination_dir.join(&file_name);

        std::fs::copy(source, &dest_path).map_err(|e| format!("Failed to copy file: {}", e))?;

        let mut result = format!("Exported to: {}", dest_path.display());

        if verify_hash {
            let source_hash = crate::hashing::hash_file(source)
                .map_err(|e| format!("Failed to calculate hash: {}", e))?
                .sha256;
            let dest_hash = crate::hashing::hash_file(&dest_path)
                .map_err(|e| format!("Failed to verify hash: {}", e))?
                .sha256;

            if source_hash == dest_hash {
                result.push_str(&format!("\nHash verified: {}", source_hash));
            } else {
                return Err("Hash verification failed!".to_string());
            }
        }

        if include_metadata {
            let metadata_json = dest_path.with_extension("metadata.json");
            let meta = serde_json::json!({
                "original_path": source_path,
                "exported_at": chrono::Utc::now().to_rfc3339(),
                "size_bytes": std::fs::metadata(&dest_path).map(|m| m.len()).unwrap_or(0),
            });

            std::fs::write(&metadata_json, serde_json::to_string_pretty(&meta).unwrap())
                .map_err(|e| format!("Failed to write metadata: {}", e))?;

            result.push_str(&format!(
                "\nMetadata written to: {}",
                metadata_json.display()
            ));
        }

        Ok(result)
    }

    pub fn export_tagged_artifacts(
        &self,
        tag_id: i64,
        destination_dir: &Path,
        include_metadata: bool,
        verify_hash: bool,
    ) -> Result<usize, String> {
        if let Some(ref sm) = self.search_manager {
            let paths = sm.get_tag_manager().get_artifact_paths_with_tag(tag_id)?;

            let mut exported = 0;
            for path in &paths {
                match self.export_artifact(path, destination_dir, include_metadata, verify_hash) {
                    Ok(_) => exported += 1,
                    Err(e) => {
                        eprintln!("Failed to export {}: {}", path, e);
                    }
                }
            }

            Ok(exported)
        } else {
            Err("Search manager not initialized".to_string())
        }
    }
}
