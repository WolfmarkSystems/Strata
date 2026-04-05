use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use chrono::Utc;

use crate::case::activity_log::ActivityLogger;
use crate::case::notes::{Exhibit, ExhibitType, Note};
use crate::case::verify::{get_latest_verification, write_verification_artifacts, ExportOptions};
use rusqlite::Connection;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExhibitPacketConfig {
    pub case_id: String,
    pub case_name: String,
    pub examiner: String,
    pub output_path: PathBuf,
    pub include_screenshots: bool,
    pub include_metadata: bool,
    pub compression: CompressionType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompressionType {
    None,
    Zip,
    TarGz,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExhibitManifest {
    pub packet_id: String,
    pub packet_name: String,
    pub case_id: String,
    pub case_name: String,
    pub examiner: String,
    pub created_at: u64,
    pub manifest_version: String,
    pub exhibits: Vec<ExhibitManifestEntry>,
    pub notes: Vec<NoteManifestEntry>,
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub manifest_hash: String,
    pub previous_manifest_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExhibitManifestEntry {
    pub exhibit_id: String,
    pub name: String,
    pub exhibit_type: String,
    pub file_path: Option<String>,
    pub hash_md5: Option<String>,
    pub hash_sha1: Option<String>,
    pub hash_sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub tags: Vec<String>,
    pub source_evidence_id: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteManifestEntry {
    pub note_id: String,
    pub title: String,
    pub content_preview: String,
    pub tags: Vec<String>,
    pub linked_exhibits: Vec<String>,
    pub created_at: u64,
    pub modified_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketExportResult {
    pub success: bool,
    pub packet_id: String,
    pub output_path: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest_hash: String,
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub error: Option<String>,
}

pub struct ExhibitPacketGenerator {
    config: ExhibitPacketConfig,
    case_base_path: PathBuf,
}

impl ExhibitPacketGenerator {
    pub fn new(config: ExhibitPacketConfig) -> Self {
        let case_base_path = config.output_path.join(&config.case_id);

        Self {
            config,
            case_base_path,
        }
    }

    pub fn generate_packet(
        &self,
        exhibits: Vec<Exhibit>,
        notes: Vec<Note>,
        previous_manifest_hash: Option<String>,
    ) -> PacketExportResult {
        let packet_id = Uuid::new_v4().to_string();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut total_size: u64 = 0;
        let mut exhibit_entries = Vec::new();

        let exhibits_dir = self.case_base_path.join("exhibits");
        if let Err(e) = strata_fs::create_dir_all(&exhibits_dir) {
            return PacketExportResult {
                success: false,
                packet_id,
                output_path: self.config.output_path.clone(),
                manifest_path: PathBuf::new(),
                manifest_hash: String::new(),
                total_files: 0,
                total_size_bytes: 0,
                error: Some(format!("Failed to create exhibits directory: {}", e)),
            };
        }

        for exhibit in &exhibits {
            let mut size: u64 = 0;
            let mut exhibit_file_path: Option<String> = None;

            if let Some(ref data) = exhibit.data {
                size = data.len() as u64;
                total_size += size;

                let ext = match exhibit.exhibit_type {
                    ExhibitType::File => "bin",
                    ExhibitType::Image => "img",
                    ExhibitType::Text => "txt",
                    ExhibitType::WebArchive => "html",
                    ExhibitType::Email => "eml",
                    ExhibitType::ChatMessage => "json",
                    ExhibitType::Document => "doc",
                    ExhibitType::Registry => "reg",
                    ExhibitType::Memory => "mem",
                    ExhibitType::Custom(ref s) => s,
                };

                let file_name = format!("{}.{}", exhibit.id, ext);
                let file_path = exhibits_dir.join(&file_name);

                if let Ok(mut file) = File::create(&file_path) {
                    let _ = file.write_all(data);
                    exhibit_file_path = Some(file_path.to_string_lossy().to_string());
                }
            }

            exhibit_entries.push(ExhibitManifestEntry {
                exhibit_id: exhibit.id.clone(),
                name: exhibit.name.clone(),
                exhibit_type: format!("{:?}", exhibit.exhibit_type),
                file_path: exhibit_file_path,
                hash_md5: exhibit.hash_md5.clone(),
                hash_sha1: exhibit.hash_sha1.clone(),
                hash_sha256: exhibit.hash_sha256.clone(),
                size_bytes: Some(size),
                tags: exhibit.tags.clone(),
                source_evidence_id: exhibit.source_evidence_id.clone(),
                created_at: exhibit.created_at,
            });
        }

        let notes_dir = self.case_base_path.join("notes");
        let _ = strata_fs::create_dir_all(&notes_dir);

        let note_entries: Vec<NoteManifestEntry> = notes
            .iter()
            .map(|note| {
                let content_preview = if note.content.len() > 500 {
                    format!("{}...", &note.content[..500])
                } else {
                    note.content.clone()
                };

                let linked: Vec<String> = note
                    .linked_objects
                    .iter()
                    .map(|o| o.object_id.clone())
                    .collect();

                let note_file = notes_dir.join(format!("{}.json", note.id));
                let _ = File::create(&note_file).and_then(|mut f| {
                    f.write_all(
                        serde_json::to_string_pretty(note)
                            .unwrap_or_default()
                            .as_bytes(),
                    )
                });

                NoteManifestEntry {
                    note_id: note.id.clone(),
                    title: note.title.clone(),
                    content_preview,
                    tags: note.tags.clone(),
                    linked_exhibits: linked,
                    created_at: note.created_at,
                    modified_at: note.modified_at,
                }
            })
            .collect();

        let manifest = ExhibitManifest {
            packet_id: packet_id.clone(),
            packet_name: format!("Exhibit Packet {}", created_at),
            case_id: self.config.case_id.clone(),
            case_name: self.config.case_name.clone(),
            examiner: self.config.examiner.clone(),
            created_at,
            manifest_version: "1.0".to_string(),
            exhibits: exhibit_entries,
            notes: note_entries.clone(),
            total_files: exhibits.len(),
            total_size_bytes: total_size,
            manifest_hash: String::new(),
            previous_manifest_hash: previous_manifest_hash.clone(),
        };

        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap_or_default();
        let manifest_hash = compute_hash(manifest_json.as_bytes());

        let manifest_with_hash = ExhibitManifest {
            manifest_hash: manifest_hash.clone(),
            ..manifest
        };

        let manifest_path = self.case_base_path.join("manifest.json");
        let final_manifest_json =
            serde_json::to_string_pretty(&manifest_with_hash).unwrap_or_default();

        let _ = File::create(&manifest_path)
            .and_then(|mut f| f.write_all(final_manifest_json.as_bytes()));

        PacketExportResult {
            success: true,
            packet_id,
            output_path: self.case_base_path.clone(),
            manifest_path,
            manifest_hash,
            total_files: exhibits.len(),
            total_size_bytes: total_size,
            error: None,
        }
    }

    pub fn generate_activity_export(
        &self,
        activity_logger: &ActivityLogger,
    ) -> Result<PathBuf, String> {
        let activity_dir = self.case_base_path.join("activity");
        strata_fs::create_dir_all(&activity_dir).map_err(|e| e.to_string())?;

        let activity_path = activity_dir.join("activity_log.json");
        let events = activity_logger.get_events();

        let json = serde_json::to_string_pretty(events).map_err(|e| e.to_string())?;
        File::create(&activity_path)
            .map_err(|e| e.to_string())?
            .write_all(json.as_bytes())
            .map_err(|e| e.to_string())?;

        let manifest_path = self.case_base_path.join("activity_manifest.json");
        let activity_manifest = serde_json::json!({
            "export_type": "activity_log",
            "case_id": self.config.case_id,
            "case_name": self.config.case_name,
            "examiner": self.config.examiner,
            "event_count": events.len(),
            "exported_at": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        File::create(&manifest_path)
            .map_err(|e| e.to_string())?
            .write_all(
                serde_json::to_string_pretty(&activity_manifest)
                    .unwrap_or_default()
                    .as_bytes(),
            )
            .map_err(|e| e.to_string())?;

        Ok(activity_path)
    }
}

pub fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn verify_manifest_chain(manifest: &ExhibitManifest, previous_hash: Option<&str>) -> bool {
    if let Some(expected) = previous_hash {
        if manifest.previous_manifest_hash.as_ref() != Some(&expected.to_string()) {
            return false;
        }
    }

    let mut manifest_for_verify = manifest.clone();
    manifest_for_verify.manifest_hash = String::new();
    manifest_for_verify.previous_manifest_hash = manifest.previous_manifest_hash.clone();

    let json = serde_json::to_string(&manifest_for_verify).unwrap_or_default();
    let computed = compute_hash(json.as_bytes());

    computed == manifest.manifest_hash
}

pub fn create_exhibit_packet_from_files(
    case_id: &str,
    case_name: &str,
    examiner: &str,
    output_dir: &Path,
    selected_files: &[String],
    search_context: Option<&str>,
    filter_context: Option<&str>,
) -> Result<PacketExportResult, String> {
    let config = ExhibitPacketConfig {
        case_id: case_id.to_string(),
        case_name: case_name.to_string(),
        examiner: examiner.to_string(),
        output_path: output_dir.to_path_buf(),
        include_screenshots: true,
        include_metadata: true,
        compression: CompressionType::Zip,
    };

    let generator = ExhibitPacketGenerator::new(config);

    let exhibits: Vec<Exhibit> = selected_files
        .iter()
        .map(|f| {
            let mut exhibit = Exhibit::new(case_id, examiner, f, ExhibitType::File);
            exhibit.source_evidence_id = Some("selection".to_string());
            exhibit
        })
        .collect();

    let mut notes = Vec::new();

    if let Some(ctx) = search_context {
        let mut note = Note::new(case_id, "Search Context", ctx);
        note.add_tag("automatic");
        notes.push(note);
    }

    if let Some(ctx) = filter_context {
        let mut note = Note::new(case_id, "Filter Context", ctx);
        note.add_tag("automatic");
        notes.push(note);
    }

    Ok(generator.generate_packet(exhibits, notes, None))
}

pub fn generate_case_export(
    case_id: &str,
    case_name: &str,
    examiner: &str,
    output_dir: &Path,
    include_activity: bool,
    activity_logger: Option<&ActivityLogger>,
) -> Result<HashMap<String, String>, String> {
    let mut results = HashMap::new();

    let config = ExhibitPacketConfig {
        case_id: case_id.to_string(),
        case_name: case_name.to_string(),
        examiner: examiner.to_string(),
        output_path: output_dir.to_path_buf(),
        include_screenshots: true,
        include_metadata: true,
        compression: CompressionType::Zip,
    };

    let generator = ExhibitPacketGenerator::new(config);

    let empty_exhibits: Vec<Exhibit> = Vec::new();
    let empty_notes: Vec<Note> = Vec::new();

    let packet_result = generator.generate_packet(empty_exhibits, empty_notes, None);
    results.insert(
        "main_packet".to_string(),
        format!("{:?}", packet_result.success),
    );

    if include_activity {
        if let Some(logger) = activity_logger {
            if let Ok(activity_path) = generator.generate_activity_export(logger) {
                results.insert(
                    "activity_export".to_string(),
                    activity_path.to_string_lossy().to_string(),
                );
            }
        }
    }

    let summary_path = output_dir.join("export_summary.json");
    let summary = serde_json::json!({
        "case_id": case_id,
        "case_name": case_name,
        "examiner": examiner,
        "exported_at": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "components": results
    });

    File::create(&summary_path)
        .map_err(|e| e.to_string())?
        .write_all(
            serde_json::to_string_pretty(&summary)
                .unwrap_or_default()
                .as_bytes(),
        )
        .map_err(|e| e.to_string())?;

    Ok(results)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseExportBundle {
    pub bundle_id: String,
    pub case_id: String,
    pub case_name: String,
    pub examiner: String,
    pub created_at: u64,
    pub version: String,
    pub manifest: BundleManifest,
    pub structure: BundleStructure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub manifest_version: String,
    pub bundle_hash: String,
    pub previous_bundle_hash: Option<String>,
    pub components: Vec<BundleComponent>,
    pub total_files: usize,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleComponent {
    pub component_type: String,
    pub path: String,
    pub hash_sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub record_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleStructure {
    pub root: String,
    pub folders: Vec<BundleFolder>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleFolder {
    pub name: String,
    pub path: String,
    pub description: String,
}

pub fn get_standard_bundle_structure() -> Vec<BundleFolder> {
    vec![
        BundleFolder {
            name: "manifest".to_string(),
            path: "manifest.json".to_string(),
            description: "Export manifest with hashes".to_string(),
        },
        BundleFolder {
            name: "activity".to_string(),
            path: "activity".to_string(),
            description: "Activity log exports".to_string(),
        },
        BundleFolder {
            name: "exhibits".to_string(),
            path: "exhibits".to_string(),
            description: "Exported exhibit files".to_string(),
        },
        BundleFolder {
            name: "notes".to_string(),
            path: "notes".to_string(),
            description: "Examiner notes".to_string(),
        },
        BundleFolder {
            name: "reports".to_string(),
            path: "reports".to_string(),
            description: "Generated reports".to_string(),
        },
        BundleFolder {
            name: "bookmarks".to_string(),
            path: "bookmarks".to_string(),
            description: "Bookmarked items".to_string(),
        },
        BundleFolder {
            name: "db".to_string(),
            path: "db".to_string(),
            description: "Optional SQLite database".to_string(),
        },
    ]
}

pub fn create_bundle_manifest(
    bundle_id: &str,
    case_id: &str,
    case_name: &str,
    examiner: &str,
    components: Vec<BundleComponent>,
    total_size: u64,
    previous_hash: Option<&str>,
) -> CaseExportBundle {
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let manifest = BundleManifest {
        manifest_version: "1.0".to_string(),
        bundle_hash: String::new(),
        previous_bundle_hash: previous_hash.map(|s| s.to_string()),
        components: components.clone(),
        total_files: components.len(),
        total_size_bytes: total_size,
    };

    let manifest_json = serde_json::to_string(&manifest).unwrap_or_default();
    let bundle_hash = compute_hash(manifest_json.as_bytes());

    let final_manifest = BundleManifest {
        bundle_hash: bundle_hash.clone(),
        ..manifest
    };

    CaseExportBundle {
        bundle_id: bundle_id.to_string(),
        case_id: case_id.to_string(),
        case_name: case_name.to_string(),
        examiner: examiner.to_string(),
        created_at,
        version: "1.0".to_string(),
        manifest: final_manifest,
        structure: BundleStructure {
            root: "case_export".to_string(),
            folders: get_standard_bundle_structure(),
        },
    }
}

pub fn export_with_bundle_structure(
    case_id: &str,
    case_name: &str,
    examiner: &str,
    output_dir: &Path,
) -> Result<CaseExportBundle, String> {
    let bundle_id = Uuid::new_v4().to_string();
    let _created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let export_root = output_dir.join("case_export");
    strata_fs::create_dir_all(&export_root).map_err(|e| e.to_string())?;

    let folders = get_standard_bundle_structure();
    for folder in &folders {
        let folder_path = export_root.join(&folder.name);
        strata_fs::create_dir_all(&folder_path).map_err(|e| e.to_string())?;
    }

    let components = vec![
        BundleComponent {
            component_type: "activity".to_string(),
            path: "activity/".to_string(),
            hash_sha256: None,
            size_bytes: None,
            record_count: None,
        },
        BundleComponent {
            component_type: "exhibits".to_string(),
            path: "exhibits/".to_string(),
            hash_sha256: None,
            size_bytes: None,
            record_count: None,
        },
        BundleComponent {
            component_type: "notes".to_string(),
            path: "notes/".to_string(),
            hash_sha256: None,
            size_bytes: None,
            record_count: None,
        },
    ];

    let bundle = create_bundle_manifest(
        &bundle_id, case_id, case_name, examiner, components, 0, None,
    );

    let manifest_path = export_root.join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?;
    File::create(&manifest_path)
        .map_err(|e| e.to_string())?
        .write_all(manifest_json.as_bytes())
        .map_err(|e| e.to_string())?;

    let manifest_hash_path = export_root.join("manifest.sha256");
    let hash_content = format!("{}  manifest.json", bundle.manifest.bundle_hash);
    File::create(&manifest_hash_path)
        .map_err(|e| e.to_string())?
        .write_all(hash_content.as_bytes())
        .map_err(|e| e.to_string())?;

    Ok(bundle)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionFilterContext {
    pub filter_type: String,
    pub criteria: HashMap<String, String>,
    pub results_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionItem {
    pub item_id: String,
    pub item_type: String,
    pub file_path: Option<String>,
    pub artifact_path: Option<String>,
    pub size_bytes: Option<u64>,
    pub hash_md5: Option<String>,
    pub hash_sha1: Option<String>,
    pub hash_sha256: Option<String>,
    pub evidence_id: Option<String>,
    pub volume_id: Option<String>,
    pub created_at: Option<u64>,
    pub modified_at: Option<u64>,
    pub provenance: Vec<ProvenancePointer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenancePointer {
    pub source_evidence_id: String,
    pub source_path: String,
    pub extraction_module: String,
    pub extraction_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionContext {
    pub case_id: String,
    pub examiner: String,
    pub selection_time: u64,
    pub active_filters: Vec<SelectionFilterContext>,
    pub search_query: Option<String>,
    pub search_fuzzy: bool,
    pub timeline_range_start: Option<u64>,
    pub timeline_range_end: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExhibitPacketSelection {
    pub packet_id: String,
    pub packet_name: String,
    pub description: String,
    pub selection_context: SelectionContext,
    pub items: Vec<SelectionItem>,
    pub screenshot_path: Option<String>,
    pub auto_notes: Vec<AutoGeneratedNote>,
    pub tags: Vec<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoGeneratedNote {
    pub note_type: String,
    pub title: String,
    pub content: String,
    pub linked_item_ids: Vec<String>,
    pub generated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemDeterministicSummary {
    pub note_title: String,
    pub note_summary: String,
    pub note_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketDeterministicSummary {
    pub packet_title: String,
    pub packet_summary: String,
    pub packet_key: String,
    pub item_summaries: Vec<ItemDeterministicSummary>,
}

const MAX_SUMMARY_LENGTH: usize = 120;

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

fn classify_item(item: &SelectionItem) -> String {
    if let Some(ref path) = item.artifact_path {
        let path_lower = path.to_lowercase();

        let browser_path_indicators = [
            "history",
            "cookies",
            "login data",
            "web data",
            "extensions",
            "default/extensions",
            "default/history",
            "default/cookies",
            "places",
            "favicons",
            "login",
            "webdata",
        ];

        if path_lower.contains("chrome")
            || path_lower.contains("chromium")
            || path_lower.contains("edge")
            || path_lower.contains("brave")
            || path_lower.contains("vivaldi")
            || path_lower.contains("opera")
            || path_lower.contains("firefox")
            || path_lower.contains("browser")
            || browser_path_indicators
                .iter()
                .any(|p| path_lower.contains(p))
        {
            return "browser".to_string();
        }

        let chat_paths = [
            "teams",
            "slack",
            "discord",
            "signal",
            "telegram",
            "whatsapp",
            "skype",
            "messenger",
            "messages",
            "chat",
            "signal",
            "viber",
            "line",
            "wechat",
        ];
        if chat_paths.iter().any(|p| path_lower.contains(p)) {
            return "chat".to_string();
        }

        let windows_paths = [
            "windows",
            "system32",
            "registry",
            "event logs",
            "eventlog",
            "prefetch",
            "tasks",
            "scheduled",
            "mft",
            "$mft",
            "sam",
            "security",
            "system",
            "software",
        ];
        if windows_paths.iter().any(|p| path_lower.contains(p)) {
            return "windows".to_string();
        }

        let network_paths = [
            "network",
            "dns",
            "dhcp",
            "firewall",
            "connections",
            "sockets",
            "arp",
            "netstat",
            "wifi",
            "wlan",
            "arpcache",
        ];
        if network_paths.iter().any(|p| path_lower.contains(p)) {
            return "network".to_string();
        }
    }

    if let Some(prov) = item.provenance.first() {
        let module = prov.extraction_module.to_lowercase();

        if module.contains("chrome") || module.contains("browser") || module.contains("edge") {
            return "browser".to_string();
        }
        if module.contains("teams")
            || module.contains("slack")
            || module.contains("discord")
            || module.contains("chat")
            || module.contains("message")
        {
            return "chat".to_string();
        }
        if module.contains("registry") || module.contains("eventlog") || module.contains("mft") {
            return "windows".to_string();
        }
        if module.contains("network") || module.contains("dns") || module.contains("wifi") {
            return "network".to_string();
        }
    }

    if let Some(ref ev_id) = item.evidence_id {
        if ev_id.to_lowercase().contains("memory") {
            return "memory".to_string();
        }
    }

    "file".to_string()
}

fn generate_item_note_title(item: &SelectionItem, classification: &str) -> String {
    let file_name = item
        .file_path
        .as_ref()
        .or(item.artifact_path.as_ref())
        .and_then(|p| std::path::Path::new(p).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    match classification {
        "browser" => format!("Browser: {}", truncate(file_name, 80)),
        "chat" => format!("Chat: {}", truncate(file_name, 80)),
        "windows" => format!("Windows: {}", truncate(file_name, 80)),
        "network" => format!("Network: {}", truncate(file_name, 80)),
        "memory" => format!("Memory: {}", truncate(file_name, 80)),
        _ => truncate(file_name, 100),
    }
}

fn generate_item_note_summary(item: &SelectionItem, _classification: &str) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(ref path) = item.artifact_path {
        parts.push(format!("path:{}", truncate(path, MAX_SUMMARY_LENGTH)));
    } else if let Some(ref path) = item.file_path {
        parts.push(format!("path:{}", truncate(path, MAX_SUMMARY_LENGTH)));
    }

    if let Some(ref size) = item.size_bytes {
        parts.push(format!("size:{} bytes", size));
    }

    if let Some(ref sha256) = item.hash_sha256 {
        parts.push(format!("sha256:{}", &sha256[..16.min(sha256.len())]));
    } else if let Some(ref sha1) = item.hash_sha1 {
        parts.push(format!("sha1:{}", &sha1[..16.min(sha1.len())]));
    } else if let Some(ref md5) = item.hash_md5 {
        parts.push(format!("md5:{}", &md5[..16.min(md5.len())]));
    }

    if let Some(ref ev_id) = item.evidence_id {
        parts.push(format!("evidence:{}", truncate(ev_id, 40)));
    }

    if let Some(ref vol_id) = item.volume_id {
        parts.push(format!("volume:{}", truncate(vol_id, 40)));
    }

    if !item.provenance.is_empty() {
        let modules: Vec<&str> = item
            .provenance
            .iter()
            .map(|p| p.extraction_module.as_str())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        parts.push(format!("modules:[{}]", modules.join(",")));
    }

    if let Some(ref created) = item.created_at {
        parts.push(format!("created:{}", created));
    }

    if let Some(ref modified) = item.modified_at {
        parts.push(format!("modified:{}", modified));
    }

    parts.sort();
    truncate(&parts.join(" | "), MAX_SUMMARY_LENGTH * 2)
}

fn generate_item_note_key(item: &SelectionItem) -> String {
    if let Some(ref sha256) = item.hash_sha256 {
        return sha256.clone();
    }

    let mut key_parts: Vec<&str> = Vec::new();

    if let Some(ref vol_id) = item.volume_id {
        key_parts.push(vol_id);
    }

    if let Some(ref path) = item.file_path {
        key_parts.push(path);
    } else if let Some(ref path) = item.artifact_path {
        key_parts.push(path);
    }

    if let Some(ref ev_id) = item.evidence_id {
        if key_parts.is_empty() {
            key_parts.push(ev_id);
        }
    }

    let combined = key_parts.join(":");

    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn generate_item_deterministic_summary(item: &SelectionItem) -> ItemDeterministicSummary {
    let classification = classify_item(item);
    let note_title = generate_item_note_title(item, &classification);
    let note_summary = generate_item_note_summary(item, &classification);
    let note_key = generate_item_note_key(item);

    ItemDeterministicSummary {
        note_title,
        note_summary,
        note_key,
    }
}

fn generate_packet_note_title(selection: &[SelectionItem], context: &SelectionContext) -> String {
    let count = selection.len();
    let filter_count = context.active_filters.len();

    if filter_count > 0 {
        let filter_types: Vec<&str> = context
            .active_filters
            .iter()
            .map(|f| f.filter_type.as_str())
            .collect();
        let filter_summary = filter_types.join(", ");
        format!("Selection: {} items, filters: {}", count, filter_summary)
    } else if let Some(ref query) = context.search_query {
        if !query.is_empty() {
            format!("Search '{}': {} items", truncate(query, 30), count)
        } else {
            format!("Selection: {} items", count)
        }
    } else {
        format!("Selection: {} items", count)
    }
}

fn generate_packet_note_summary(selection: &[SelectionItem], context: &SelectionContext) -> String {
    let mut parts: Vec<String> = Vec::new();

    let count = selection.len();
    parts.push(format!("items:{}", count));

    let mut classifications: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for item in selection {
        let c = classify_item(item);
        *classifications.get_mut(&c).unwrap_or(&mut 0) += 1;
    }

    let mut class_parts: Vec<String> = classifications
        .keys()
        .map(|k| format!("{}:{}", k, classifications[k]))
        .collect();
    class_parts.sort();
    parts.push(format!("types:[{}]", class_parts.join(",")));

    if let Some(ref start) = context.timeline_range_start {
        parts.push(format!("time_from:{}", start));
    }
    if let Some(ref end) = context.timeline_range_end {
        parts.push(format!("time_to:{}", end));
    }

    if let Some(ref query) = context.search_query {
        if !query.is_empty() {
            parts.push(format!("query:{}", truncate(query, 50)));
            parts.push(format!("fuzzy:{}", context.search_fuzzy));
        }
    }

    let total_size: u64 = selection.iter().filter_map(|i| i.size_bytes).sum();
    if total_size > 0 {
        parts.push(format!("total_size:{} bytes", total_size));
    }

    let unique_evidence: std::collections::HashSet<_> = selection
        .iter()
        .filter_map(|i| i.evidence_id.clone())
        .collect();
    if !unique_evidence.is_empty() {
        parts.push(format!("evidence_sources:{}", unique_evidence.len()));
    }

    parts.sort();
    truncate(&parts.join(" | "), MAX_SUMMARY_LENGTH * 2)
}

fn generate_packet_note_key(selection: &[SelectionItem], context: &SelectionContext) -> String {
    let mut key_parts: Vec<String> = Vec::new();

    key_parts.push(format!("items:{}", selection.len()));

    let mut sorted_items = selection.to_vec();
    sorted_items.sort_by(|a, b| {
        let a_key = generate_item_note_key(a);
        let b_key = generate_item_note_key(b);
        a_key.cmp(&b_key)
    });

    let first_keys: Vec<String> = sorted_items
        .iter()
        .take(3)
        .map(generate_item_note_key)
        .collect();
    key_parts.push(format!("first_items:[{}]", first_keys.join(",")));

    if let Some(ref start) = context.timeline_range_start {
        key_parts.push(format!("t0:{}", start));
    }
    if let Some(ref end) = context.timeline_range_end {
        key_parts.push(format!("t1:{}", end));
    }

    if let Some(ref query) = context.search_query {
        if !query.is_empty() {
            key_parts.push(format!("q:{}", query));
        }
    }

    let combined = key_parts.join(";");

    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn generate_packet_deterministic_summary(
    selection: &[SelectionItem],
    context: &SelectionContext,
) -> PacketDeterministicSummary {
    let mut item_summaries: Vec<ItemDeterministicSummary> = selection
        .iter()
        .map(generate_item_deterministic_summary)
        .collect();

    item_summaries.sort_by(|a, b| a.note_key.cmp(&b.note_key));

    let packet_title = generate_packet_note_title(selection, context);
    let packet_summary = generate_packet_note_summary(selection, context);
    let packet_key = generate_packet_note_key(selection, context);

    PacketDeterministicSummary {
        packet_title,
        packet_summary,
        packet_key,
        item_summaries,
    }
}

pub fn create_exhibit_packet_with_context(
    _case_id: &str,
    _case_name: &str,
    _examiner: &str,
    selection: Vec<SelectionItem>,
    context: SelectionContext,
    screenshot_path: Option<&str>,
    existing_tags: Vec<String>,
) -> ExhibitPacketSelection {
    let packet_id = Uuid::new_v4().to_string();
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let packet_name = format!("Selection Packet {}", Utc::now().format("%Y-%m-%d %H:%M"));

    let auto_notes = generate_auto_notes_from_selection(&selection, &context);

    ExhibitPacketSelection {
        packet_id,
        packet_name,
        description: format!(
            "Auto-generated packet from {} items, filters: {:?}",
            selection.len(),
            context
                .active_filters
                .iter()
                .map(|f| &f.filter_type)
                .collect::<Vec<_>>()
        ),
        selection_context: context,
        items: selection,
        screenshot_path: screenshot_path.map(|s| s.to_string()),
        auto_notes,
        tags: existing_tags,
        created_at,
    }
}

pub fn create_exhibit_packet_from_selection(
    _case_id: &str,
    _case_name: &str,
    _examiner: &str,
    selection: Vec<SelectionItem>,
    context: SelectionContext,
    screenshot_path: Option<&str>,
    existing_tags: Vec<String>,
) -> ExhibitPacketSelection {
    let packet_id = Uuid::new_v4().to_string();
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let packet_name = format!(
        "Selection Packet {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M")
    );

    let auto_notes = generate_auto_notes_from_selection(&selection, &context);

    ExhibitPacketSelection {
        packet_id,
        packet_name,
        description: format!(
            "Auto-generated packet from {} items, filters: {:?}",
            selection.len(),
            context
                .active_filters
                .iter()
                .map(|f| &f.filter_type)
                .collect::<Vec<_>>()
        ),
        selection_context: context,
        items: selection,
        screenshot_path: screenshot_path.map(|s| s.to_string()),
        auto_notes,
        tags: existing_tags,
        created_at,
    }
}

fn generate_auto_notes_from_selection(
    selection: &[SelectionItem],
    context: &SelectionContext,
) -> Vec<AutoGeneratedNote> {
    let mut notes = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let file_items: Vec<&SelectionItem> =
        selection.iter().filter(|i| i.item_type == "file").collect();

    if !file_items.is_empty() {
        let content = format!(
            "## Selection Summary\n\n\
            Total items: {}\n\
            Files: {}\n\
            Examiner: {}\n\
            Time: {}\n\n\
            ## Active Filters\n\n{}\n\n\
            ## Search Context\n\n{}\n",
            selection.len(),
            file_items.len(),
            context.examiner,
            format_time_unix(now),
            context
                .active_filters
                .iter()
                .map(|f| format!("- {}: {:?}", f.filter_type, f.criteria))
                .collect::<Vec<_>>()
                .join("\n"),
            context.search_query.as_deref().unwrap_or("None"),
        );

        notes.push(AutoGeneratedNote {
            note_type: "selection_summary".to_string(),
            title: "Selection Summary".to_string(),
            content,
            linked_item_ids: file_items.iter().map(|i| i.item_id.clone()).collect(),
            generated_at: now,
        });
    }

    let evidence_ids: Vec<&str> = selection
        .iter()
        .filter_map(|i| i.evidence_id.as_deref())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if !evidence_ids.is_empty() {
        let content = format!(
            "## Evidence Sources\n\n{}\n",
            evidence_ids
                .iter()
                .map(|id| format!("- {}", id))
                .collect::<Vec<_>>()
                .join("\n")
        );

        notes.push(AutoGeneratedNote {
            note_type: "evidence_sources".to_string(),
            title: "Evidence Sources".to_string(),
            content,
            linked_item_ids: Vec::new(),
            generated_at: now,
        });
    }

    notes
}

fn format_time_unix(timestamp: u64) -> String {
    let secs = timestamp as i64;
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    format!(
        "{} days since epoch, {:02}:{:02}:{:02} UTC",
        days_since_epoch, hours, minutes, seconds
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketWithContextExport {
    pub packet: ExhibitPacketSelection,
    pub manifest: PacketManifestV2,
    pub bundle_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketManifestV2 {
    pub manifest_version: String,
    pub packet_id: String,
    pub case_id: String,
    pub case_name: String,
    pub examiner: String,
    pub created_at: u64,
    pub export_time: u64,
    pub item_count: usize,
    pub total_size_bytes: u64,
    pub filter_context_json: String,
    pub items_json: String,
    pub auto_notes_json: String,
    pub screenshot_included: bool,
    pub manifest_hash: String,
    pub previous_manifest_hash: Option<String>,
}

pub fn export_packet_with_context(
    packet: &ExhibitPacketSelection,
    output_dir: &Path,
    previous_manifest_hash: Option<&str>,
) -> Result<PacketWithContextExport, String> {
    let export_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let total_size: u64 = packet.items.iter().filter_map(|i| i.size_bytes).sum();

    let filter_context_json =
        serde_json::to_string(&packet.selection_context).map_err(|e| e.to_string())?;

    let items_json = serde_json::to_string(&packet.items).map_err(|e| e.to_string())?;

    let auto_notes_json = serde_json::to_string(&packet.auto_notes).map_err(|e| e.to_string())?;

    let manifest = PacketManifestV2 {
        manifest_version: "2.0".to_string(),
        packet_id: packet.packet_id.clone(),
        case_id: packet.selection_context.case_id.clone(),
        case_name: "".to_string(),
        examiner: packet.selection_context.examiner.clone(),
        created_at: packet.created_at,
        export_time,
        item_count: packet.items.len(),
        total_size_bytes: total_size,
        filter_context_json,
        items_json,
        auto_notes_json,
        screenshot_included: packet.screenshot_path.is_some(),
        manifest_hash: String::new(),
        previous_manifest_hash: previous_manifest_hash.map(|s| s.to_string()),
    };

    let manifest_hash = calculate_manifest_hash_v2(&manifest);
    let manifest_hash = format_manifest_hash(&manifest_hash);

    let manifest_with_hash = PacketManifestV2 {
        manifest_hash: manifest_hash.clone(),
        ..manifest
    };

    let export_dir = output_dir.join(format!("packet_{}", packet.packet_id));
    strata_fs::create_dir_all(&export_dir).map_err(|e| e.to_string())?;

    let manifest_path = export_dir.join("selection_manifest.json");
    let manifest_json =
        serde_json::to_string_pretty(&manifest_with_hash).map_err(|e| e.to_string())?;
    strata_fs::write(&manifest_path, &manifest_json).map_err(|e| e.to_string())?;

    if let Some(ref ss_path) = packet.screenshot_path {
        if std::path::Path::new(ss_path).exists() {
            let ss_dest = export_dir.join("screenshot.png");
            strata_fs::copy(ss_path, &ss_dest).map_err(|e| e.to_string())?;
        }
    }

    let hash_path = export_dir.join("manifest.sha256");
    let hash_content = format!("{}  selection_manifest.json", manifest_hash);
    strata_fs::write(&hash_path, &hash_content).map_err(|e| e.to_string())?;

    Ok(PacketWithContextExport {
        packet: packet.clone(),
        manifest: manifest_with_hash,
        bundle_path: export_dir,
    })
}

pub fn export_packet_with_verification(
    packet: &ExhibitPacketSelection,
    output_dir: &Path,
    db_path: &Path,
    export_options: &ExportOptions,
    previous_manifest_hash: Option<&str>,
) -> Result<PacketWithContextExport, String> {
    let case_id = &packet.selection_context.case_id;

    let mut conn =
        Connection::open(db_path).map_err(|e| format!("Failed to open database: {}", e))?;

    if export_options.require_verification {
        let max_age = export_options.max_report_age_seconds;
        let allow_warn = export_options.allow_warn;

        let report = get_latest_verification(&mut conn, case_id)
            .map_err(|e| format!("Failed to get verification: {}", e))?;

        match report {
            Some(r) => {
                match r.status {
                    crate::case::verify::VerificationStatus::Fail => {
                        return Err(format!(
                            "Verification failed for case '{}'. Export blocked.",
                            case_id
                        ));
                    }
                    crate::case::verify::VerificationStatus::Warn if !allow_warn => {
                        return Err(format!(
                            "Verification has warnings for case '{}'. Use --strict to allow or fix the warnings.",
                            case_id
                        ));
                    }
                    _ => {}
                }

                if let Some(max_age_sec) = max_age {
                    let report_time = chrono::DateTime::parse_from_rfc3339(&r.started_utc)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .ok();

                    if let Some(report_time) = report_time {
                        let now = chrono::Utc::now();
                        let age_seconds = (now - report_time).num_seconds() as u64;

                        if age_seconds > max_age_sec {
                            return Err(format!(
                                "Verification report for case '{}' is too old ({} seconds). Re-run verification.",
                                case_id, age_seconds
                            ));
                        }
                    }
                }
            }
            None => {
                return Err(format!(
                    "No verification report found for case '{}'. Run verification first.",
                    case_id
                ));
            }
        }
    }

    let result = export_packet_with_context(packet, output_dir, previous_manifest_hash)?;

    let report = if export_options.require_verification {
        get_latest_verification(&mut conn, case_id).ok().flatten()
    } else {
        None
    };

    if let Err(e) = write_verification_artifacts(output_dir, case_id, report.as_ref()) {
        eprintln!("Warning: Failed to write verification artifacts: {}", e);
    }

    Ok(result)
}

pub fn export_case_bundle_with_verification(
    case_id: &str,
    db_path: &Path,
    output_dir: &Path,
    export_options: &ExportOptions,
) -> Result<(), String> {
    let mut conn =
        Connection::open(db_path).map_err(|e| format!("Failed to open database: {}", e))?;

    if export_options.require_verification {
        let max_age = export_options.max_report_age_seconds;
        let allow_warn = export_options.allow_warn;

        let report = get_latest_verification(&mut conn, case_id)
            .map_err(|e| format!("Failed to get verification: {}", e))?;

        match report {
            Some(r) => {
                match r.status {
                    crate::case::verify::VerificationStatus::Fail => {
                        return Err(format!(
                            "Verification failed for case '{}'. Export blocked.",
                            case_id
                        ));
                    }
                    crate::case::verify::VerificationStatus::Warn if !allow_warn => {
                        return Err(format!(
                            "Verification has warnings for case '{}'. Use --strict to allow or fix the warnings.",
                            case_id
                        ));
                    }
                    _ => {}
                }

                if let Some(max_age_sec) = max_age {
                    let report_time = chrono::DateTime::parse_from_rfc3339(&r.started_utc)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .ok();

                    if let Some(report_time) = report_time {
                        let now = chrono::Utc::now();
                        let age_seconds = (now - report_time).num_seconds() as u64;

                        if age_seconds > max_age_sec {
                            return Err(format!(
                                "Verification report for case '{}' is too old ({} seconds). Re-run verification.",
                                case_id, age_seconds
                            ));
                        }
                    }
                }
            }
            None => {
                return Err(format!(
                    "No verification report found for case '{}'. Run verification first.",
                    case_id
                ));
            }
        }
    }

    strata_fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output directory: {}", e))?;

    let report = if export_options.require_verification {
        get_latest_verification(&mut conn, case_id).ok().flatten()
    } else {
        None
    };

    write_verification_artifacts(output_dir, case_id, report.as_ref())
        .map_err(|e| format!("Failed to write verification artifacts: {}", e))?;

    let export_summary_path = output_dir.join("export_summary.txt");
    let mut summary = format!(
        "Case: {}\nExport Time: {}\nVerification Required: {}\n",
        case_id,
        chrono::Utc::now().to_rfc3339(),
        export_options.require_verification
    );

    if let Some(ref r) = report {
        summary.push_str(&format!("Verification Status: {:?}\n", r.status));
        summary.push_str(&format!("Verification Time: {}\n", r.started_utc));
    } else if !export_options.require_verification {
        summary.push_str("Verification Status: SKIPPED\n");
    }

    strata_fs::write(&export_summary_path, summary)
        .map_err(|e| format!("Failed to write export summary: {}", e))?;

    Ok(())
}

fn calculate_manifest_hash_v2(manifest: &PacketManifestV2) -> String {
    let mut hasher = Sha256::new();

    hasher.update(manifest.manifest_version.as_bytes());
    hasher.update(manifest.packet_id.as_bytes());
    hasher.update(manifest.case_id.as_bytes());
    hasher.update(manifest.examiner.as_bytes());
    hasher.update(manifest.item_count.to_string().as_bytes());
    hasher.update(manifest.total_size_bytes.to_string().as_bytes());
    hasher.update(manifest.filter_context_json.as_bytes());
    hasher.update(manifest.items_json.as_bytes());

    if let Some(ref prev) = manifest.previous_manifest_hash {
        hasher.update(prev.as_bytes());
    }

    format!("{:x}", hasher.finalize())
}

fn format_manifest_hash(hash: &str) -> String {
    hash.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_item_with_sha256() {
        let item = SelectionItem {
            item_id: "item1".to_string(),
            item_type: "file".to_string(),
            file_path: Some("/data/evidence/test.exe".to_string()),
            artifact_path: None,
            size_bytes: Some(1024),
            hash_md5: Some("abc123".to_string()),
            hash_sha1: Some("def456".to_string()),
            hash_sha256: Some(
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            ),
            evidence_id: Some("evidence1".to_string()),
            volume_id: Some("volume1".to_string()),
            created_at: Some(1700000000),
            modified_at: Some(1700010000),
            provenance: vec![],
        };

        let summary = generate_item_deterministic_summary(&item);

        assert!(summary.note_title.contains("test.exe"));
        assert!(summary.note_summary.contains("sha256:a1b2c3d4e5f6a1b2"));
        assert!(summary.note_summary.contains("size:1024 bytes"));
        assert!(summary.note_summary.contains("evidence:evidence1"));
        assert_eq!(
            summary.note_key,
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        );
    }

    #[test]
    fn test_chrome_history_artifact() {
        let item = SelectionItem {
            item_id: "chrome1".to_string(),
            item_type: "artifact".to_string(),
            file_path: None,
            artifact_path: Some("C:/Users/Test/AppData/Local/Google/Chrome/User Data/Default/History".to_string()),
            size_bytes: Some(204800),
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: Some("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe".to_string()),
            evidence_id: Some("e01-image-001".to_string()),
            volume_id: Some("vol_c".to_string()),
            created_at: Some(1699000000),
            modified_at: Some(1699100000),
            provenance: vec![
                ProvenancePointer {
                    source_evidence_id: "e01-image-001".to_string(),
                    source_path: "\\Device\\HarddiskVolume2\\Users\\Test\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History".to_string(),
                    extraction_module: "chrome_history".to_string(),
                    extraction_time: 1699000000,
                }
            ],
        };

        let summary = generate_item_deterministic_summary(&item);
        let classification = classify_item(&item);

        assert_eq!(classification, "browser");
        assert!(summary.note_title.contains("Browser:"));
        assert!(summary.note_title.contains("History"));
        assert!(summary.note_summary.contains("modules:[chrome_history]"));
    }

    #[test]
    fn test_teams_chat_message() {
        let item = SelectionItem {
            item_id: "teams1".to_string(),
            item_type: "artifact".to_string(),
            file_path: None,
            artifact_path: Some(
                "%APPDATA%/Microsoft/Teams/IndexedDB/https_team.microsoft.com_0.indexeddb.leveldb"
                    .to_string(),
            ),
            size_bytes: Some(51200),
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: Some(
                "babebabebabebabebabebabebabebabebabebabebabebabebabebabebabe".to_string(),
            ),
            evidence_id: Some("memory_dump_001".to_string()),
            volume_id: None,
            created_at: Some(1698000000),
            modified_at: Some(1698000000),
            provenance: vec![ProvenancePointer {
                source_evidence_id: "memory_dump_001".to_string(),
                source_path: "teams.exe".to_string(),
                extraction_module: "teams_chat_parser".to_string(),
                extraction_time: 1698000000,
            }],
        };

        let summary = generate_item_deterministic_summary(&item);
        let classification = classify_item(&item);

        assert_eq!(classification, "chat");
        assert!(summary.note_title.contains("Chat:"));
        assert!(summary.note_summary.contains("chat"));
        assert!(summary.note_summary.contains("modules:[teams_chat_parser]"));
    }

    #[test]
    fn test_evidence_timeline_event() {
        let item = SelectionItem {
            item_id: "evt1".to_string(),
            item_type: "timeline_event".to_string(),
            file_path: None,
            artifact_path: Some("MFT entry 12345".to_string()),
            size_bytes: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: Some(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            ),
            evidence_id: Some("ntfs_image.e01".to_string()),
            volume_id: Some("C:".to_string()),
            created_at: Some(1700000000),
            modified_at: None,
            provenance: vec![ProvenancePointer {
                source_evidence_id: "ntfs_image.e01".to_string(),
                source_path: "$MFT".to_string(),
                extraction_module: "mft_parser".to_string(),
                extraction_time: 1700000000,
            }],
        };

        let summary = generate_item_deterministic_summary(&item);

        assert!(summary.note_summary.contains("evidence:ntfs_image.e01"));
        assert!(summary.note_summary.contains("volume:C:"));
        assert!(summary.note_summary.contains("modules:[mft_parser]"));
    }

    #[test]
    fn test_packet_with_mixed_items_and_context() {
        let selection = vec![
            SelectionItem {
                item_id: "file1".to_string(),
                item_type: "file".to_string(),
                file_path: Some("/documents/important.pdf".to_string()),
                artifact_path: None,
                size_bytes: Some(1024000),
                hash_md5: None,
                hash_sha1: None,
                hash_sha256: Some(
                    "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
                ),
                evidence_id: Some("evidence1".to_string()),
                volume_id: None,
                created_at: Some(1700000000),
                modified_at: Some(1700010000),
                provenance: vec![],
            },
            SelectionItem {
                item_id: "chrome2".to_string(),
                item_type: "artifact".to_string(),
                file_path: None,
                artifact_path: Some("Chrome/Cookies".to_string()),
                size_bytes: Some(8192),
                hash_md5: None,
                hash_sha1: None,
                hash_sha256: Some(
                    "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
                ),
                evidence_id: Some("evidence1".to_string()),
                volume_id: None,
                created_at: Some(1699900000),
                modified_at: None,
                provenance: vec![ProvenancePointer {
                    source_evidence_id: "evidence1".to_string(),
                    source_path: "cookies".to_string(),
                    extraction_module: "chrome_cookies".to_string(),
                    extraction_time: 1699900000,
                }],
            },
            SelectionItem {
                item_id: "teams2".to_string(),
                item_type: "artifact".to_string(),
                file_path: None,
                artifact_path: Some("Teams/chat.db".to_string()),
                size_bytes: Some(4096),
                hash_md5: None,
                hash_sha1: None,
                hash_sha256: Some(
                    "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
                ),
                evidence_id: Some("memory.dmp".to_string()),
                volume_id: None,
                created_at: Some(1699800000),
                modified_at: None,
                provenance: vec![ProvenancePointer {
                    source_evidence_id: "memory.dmp".to_string(),
                    source_path: "teams.exe".to_string(),
                    extraction_module: "teams_chat".to_string(),
                    extraction_time: 1699800000,
                }],
            },
        ];

        let context = SelectionContext {
            case_id: "case123".to_string(),
            examiner: " analyst ".to_string(),
            selection_time: 1700100000,
            active_filters: vec![
                SelectionFilterContext {
                    filter_type: "file_type".to_string(),
                    criteria: [("extension".to_string(), "pdf".to_string())]
                        .into_iter()
                        .collect(),
                    results_count: 10,
                },
                SelectionFilterContext {
                    filter_type: "date_range".to_string(),
                    criteria: [("start".to_string(), "2024-01-01".to_string())]
                        .into_iter()
                        .collect(),
                    results_count: 50,
                },
            ],
            search_query: Some("confidential".to_string()),
            search_fuzzy: true,
            timeline_range_start: Some(1699000000),
            timeline_range_end: Some(1700000000),
        };

        let packet_summary = generate_packet_deterministic_summary(&selection, &context);

        assert!(packet_summary.packet_title.contains("Selection: 3 items"));
        assert!(packet_summary.packet_title.contains("filters:"));
        assert!(packet_summary.packet_summary.contains("items:3"));
        assert!(packet_summary.packet_summary.contains("types:["));
        assert!(packet_summary.packet_summary.contains("query:confidential"));
        assert!(packet_summary
            .packet_summary
            .contains("time_from:1699000000"));
        assert!(packet_summary.packet_summary.contains("time_to:1700000000"));
        assert_eq!(packet_summary.item_summaries.len(), 3);

        let keys: Vec<&str> = packet_summary
            .item_summaries
            .iter()
            .map(|s| s.note_key.as_str())
            .collect();
        assert!(keys[0] < keys[1]);
        assert!(keys[1] < keys[2]);
    }

    #[test]
    fn test_classification_from_artifact_path() {
        let browser_item = SelectionItem {
            item_id: "b1".to_string(),
            item_type: "artifact".to_string(),
            file_path: None,
            artifact_path: Some("Firefox/places.sqlite".to_string()),
            size_bytes: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: None,
            evidence_id: None,
            volume_id: None,
            created_at: None,
            modified_at: None,
            provenance: vec![],
        };
        assert_eq!(classify_item(&browser_item), "browser");

        let chat_item = SelectionItem {
            item_id: "c1".to_string(),
            item_type: "artifact".to_string(),
            file_path: None,
            artifact_path: Some("Signal/db.sqlite".to_string()),
            size_bytes: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: None,
            evidence_id: None,
            volume_id: None,
            created_at: None,
            modified_at: None,
            provenance: vec![],
        };
        assert_eq!(classify_item(&chat_item), "chat");

        let network_item = SelectionItem {
            item_id: "n1".to_string(),
            item_type: "artifact".to_string(),
            file_path: None,
            artifact_path: Some("Network Connections/arp_cache.bin".to_string()),
            size_bytes: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: None,
            evidence_id: None,
            volume_id: None,
            created_at: None,
            modified_at: None,
            provenance: vec![],
        };
        assert_eq!(classify_item(&network_item), "network");
    }

    #[test]
    fn test_classification_from_provenance_module() {
        let item = SelectionItem {
            item_id: "p1".to_string(),
            item_type: "artifact".to_string(),
            file_path: None,
            artifact_path: Some("/some/unknown/path".to_string()),
            size_bytes: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: None,
            evidence_id: None,
            volume_id: None,
            created_at: None,
            modified_at: None,
            provenance: vec![ProvenancePointer {
                source_evidence_id: "ev1".to_string(),
                source_path: "registry".to_string(),
                extraction_module: "windows_registry_parser".to_string(),
                extraction_time: 0,
            }],
        };
        assert_eq!(classify_item(&item), "windows");
    }

    #[test]
    fn test_note_key_preference_sha256() {
        let item_with_sha256 = SelectionItem {
            item_id: "k1".to_string(),
            item_type: "file".to_string(),
            file_path: Some("/test/path".to_string()),
            artifact_path: None,
            size_bytes: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: Some(
                "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc".to_string(),
            ),
            evidence_id: None,
            volume_id: None,
            created_at: None,
            modified_at: None,
            provenance: vec![],
        };
        let summary1 = generate_item_deterministic_summary(&item_with_sha256);
        assert_eq!(
            summary1.note_key,
            "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc"
        );

        let item_with_volume_path = SelectionItem {
            item_id: "k2".to_string(),
            item_type: "file".to_string(),
            file_path: Some("/test/path2".to_string()),
            artifact_path: None,
            size_bytes: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: None,
            evidence_id: None,
            volume_id: Some("vol1".to_string()),
            created_at: None,
            modified_at: None,
            provenance: vec![],
        };
        let summary2 = generate_item_deterministic_summary(&item_with_volume_path);
        assert!(!summary2.note_key.is_empty());

        let item_with_evidence = SelectionItem {
            item_id: "k3".to_string(),
            item_type: "file".to_string(),
            file_path: Some("/test/path3".to_string()),
            artifact_path: None,
            size_bytes: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: None,
            evidence_id: Some("ev1".to_string()),
            volume_id: None,
            created_at: None,
            modified_at: None,
            provenance: vec![],
        };
        let summary3 = generate_item_deterministic_summary(&item_with_evidence);
        assert!(!summary3.note_key.is_empty());
    }

    #[test]
    fn test_truncation() {
        let long_path = "/this/is/a/very/long/path/that/exceeds/the/maximum/length/we/want/to/include/in/the/summary/and/should/be/truncated/properly/file.exe";
        let item = SelectionItem {
            item_id: "t1".to_string(),
            item_type: "file".to_string(),
            file_path: Some(long_path.to_string()),
            artifact_path: None,
            size_bytes: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: Some(
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string(),
            ),
            evidence_id: None,
            volume_id: None,
            created_at: None,
            modified_at: None,
            provenance: vec![],
        };

        let summary = generate_item_deterministic_summary(&item);

        for part in summary.note_summary.split(" | ") {
            if part.starts_with("path:") {
                let path_value = part.strip_prefix("path:").unwrap();
                assert!(path_value.len() <= MAX_SUMMARY_LENGTH + 3);
                assert!(path_value.ends_with("..."));
            }
        }
    }

    #[test]
    fn test_deterministic_output() {
        let item = SelectionItem {
            item_id: "det1".to_string(),
            item_type: "file".to_string(),
            file_path: Some("/test/deterministic/path.exe".to_string()),
            artifact_path: None,
            size_bytes: Some(1024),
            hash_md5: Some("md5hash".to_string()),
            hash_sha1: Some("sha1hash".to_string()),
            hash_sha256: Some(
                "detdetdetdetdetdetdetdetdetdetdetdetdetdetdetdetdetdetdetdetdet".to_string(),
            ),
            evidence_id: Some("evdet".to_string()),
            volume_id: Some("voldet".to_string()),
            created_at: Some(1700000000),
            modified_at: Some(1700010000),
            provenance: vec![],
        };

        let summary1 = generate_item_deterministic_summary(&item);
        let summary2 = generate_item_deterministic_summary(&item);

        assert_eq!(summary1.note_title, summary2.note_title);
        assert_eq!(summary1.note_summary, summary2.note_summary);
        assert_eq!(summary1.note_key, summary2.note_key);
    }
}
