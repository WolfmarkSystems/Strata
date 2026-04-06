use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tauri::Emitter;

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct TreeNode {
    pub id: String,
    pub name: String,
    pub node_type: String,
    pub count: u64,
    pub is_deleted: bool,
    pub is_flagged: bool,
    pub is_suspicious: bool,
    pub has_children: bool,
    pub parent_id: Option<String>,
    pub depth: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub id: String,
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub size_display: String,
    pub modified: String,
    pub created: String,
    pub sha256: Option<String>,
    pub is_deleted: bool,
    pub is_suspicious: bool,
    pub is_flagged: bool,
    pub category: String,
    pub tag: Option<String>,
    pub tag_color: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileMetadata {
    pub id: String,
    pub name: String,
    pub full_path: String,
    pub size: u64,
    pub size_display: String,
    pub modified: String,
    pub created: String,
    pub accessed: String,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub category: String,
    pub is_deleted: bool,
    pub is_suspicious: bool,
    pub is_flagged: bool,
    pub mft_entry: Option<u64>,
    pub extension: String,
    pub mime_type: Option<String>,
    pub inode: Option<u64>,
    pub permissions: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EvidenceLoadResult {
    pub success: bool,
    pub evidence_id: String,
    pub name: String,
    pub size_display: String,
    pub file_count: u64,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Stats {
    pub files: u64,
    pub suspicious: u64,
    pub flagged: u64,
    pub carved: u64,
    pub hashed: u64,
    pub artifacts: u64,
}

#[derive(Serialize, Deserialize)]
pub struct HexLine {
    pub offset: String,
    pub hex: String,
    pub ascii: String,
}

#[derive(Serialize, Deserialize)]
pub struct HexData {
    pub lines: Vec<HexLine>,
    pub total_size: u64,
    pub offset: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TaggedFile {
    pub file_id: String,
    pub name: String,
    pub extension: String,
    pub size_display: String,
    pub modified: String,
    pub full_path: String,
    pub tag: String,
    pub tag_color: String,
    pub tagged_at: String,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TagSummary {
    pub name: String,
    pub color: String,
    pub count: u64,
}

static TAG_STORE: OnceLock<Arc<Mutex<HashMap<String, TaggedFile>>>> = OnceLock::new();

fn get_tag_store() -> Arc<Mutex<HashMap<String, TaggedFile>>> {
    TAG_STORE
        .get_or_init(|| {
            let mut map: HashMap<String, TaggedFile> = HashMap::new();
            map.insert("f004".to_string(), TaggedFile {
                file_id: "f004".to_string(),
                name: "mimikatz.exe".to_string(),
                extension: "exe".to_string(),
                size_display: "1.2 MB".to_string(),
                modified: "2009-11-15 14:33".to_string(),
                full_path: "\\Windows\\Temp\\mimikatz.exe".to_string(),
                tag: "Critical Evidence".to_string(),
                tag_color: "#a84040".to_string(),
                tagged_at: "2009-11-16 09:00".to_string(),
                note: Some("Known credential dumping tool".to_string()),
            });
            map.insert("f003".to_string(), TaggedFile {
                file_id: "f003".to_string(),
                name: "svchost32.exe".to_string(),
                extension: "exe".to_string(),
                size_display: "892 KB".to_string(),
                modified: "2009-11-15 14:32".to_string(),
                full_path: "\\Windows\\System32\\svchost32.exe".to_string(),
                tag: "Suspicious".to_string(),
                tag_color: "#b87840".to_string(),
                tagged_at: "2009-11-16 09:01".to_string(),
                note: None,
            });
            map.insert("f010".to_string(), TaggedFile {
                file_id: "f010".to_string(),
                name: "cleanup.ps1".to_string(),
                extension: "ps1".to_string(),
                size_display: "4.8 KB".to_string(),
                modified: "2009-11-15 14:31".to_string(),
                full_path: "\\Windows\\Temp\\cleanup.ps1".to_string(),
                tag: "Suspicious".to_string(),
                tag_color: "#b87840".to_string(),
                tagged_at: "2009-11-16 09:02".to_string(),
                note: Some("Anti-forensic script".to_string()),
            });
            map.insert("f005".to_string(), TaggedFile {
                file_id: "f005".to_string(),
                name: "Security.evtx".to_string(),
                extension: "evtx".to_string(),
                size_display: "44 MB".to_string(),
                modified: "2009-11-16 03:44".to_string(),
                full_path: "\\Windows\\System32\\winevt\\Logs\\Security.evtx".to_string(),
                tag: "Key Artifact".to_string(),
                tag_color: "#4a7890".to_string(),
                tagged_at: "2009-11-16 09:03".to_string(),
                note: None,
            });
            Arc::new(Mutex::new(map))
        })
        .clone()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ArtifactCategory {
    pub name: String,
    pub icon: String,
    pub count: u64,
    pub color: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Artifact {
    pub id: String,
    pub category: String,
    pub name: String,
    pub value: String,
    pub timestamp: Option<String>,
    pub source_file: String,
    pub source_path: String,
    pub forensic_value: String,
    pub mitre_technique: Option<String>,
    pub mitre_name: Option<String>,
    pub plugin: String,
    pub raw_data: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PluginRunResult {
    pub plugin_name: String,
    pub success: bool,
    pub artifact_count: u64,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PluginStatus {
    pub name: String,
    pub status: String,
    pub progress: u8,
    pub artifact_count: u64,
}

static PLUGIN_STATUS: OnceLock<Arc<Mutex<HashMap<String, PluginStatus>>>> = OnceLock::new();

fn get_plugin_status_store() -> Arc<Mutex<HashMap<String, PluginStatus>>> {
    PLUGIN_STATUS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

const PLUGIN_NAMES: &[&str] = &[
    "Remnant", "Chronicle", "Cipher", "Trace", "Specter", "Conduit", "Nimbus", "Wraith", "Vector",
    "Recon", "Sigma",
];

fn mock_artifact_count(name: &str) -> u64 {
    match name {
        "Remnant" => 47,
        "Chronicle" => 183,
        "Cipher" => 12,
        "Trace" => 89,
        "Specter" => 0,
        "Conduit" => 34,
        "Nimbus" => 5,
        "Wraith" => 2,
        "Vector" => 8,
        "Recon" => 23,
        "Sigma" => 156,
        _ => 0,
    }
}

#[derive(Serialize, Deserialize)]
pub struct SearchResult {
    pub id: String,
    pub name: String,
    pub full_path: String,
    pub extension: String,
    pub size_display: String,
    pub modified: String,
    pub is_deleted: bool,
    pub is_flagged: bool,
    pub is_suspicious: bool,
    pub match_field: String,
    pub match_value: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Existing commands
// ──────────────────────────────────────────────────────────────────────────────

#[tauri::command]
fn get_app_version() -> String {
    "0.3.0".to_string()
}

#[tauri::command]
fn check_license() -> serde_json::Value {
    json!({
        "status": "dev",
        "days": 999,
        "licensee": "Dev Mode",
        "tier": "pro"
    })
}

#[tauri::command]
fn get_examiner_profile() -> serde_json::Value {
    json!({
        "name": "Dev Examiner",
        "agency": "Wolfmark Systems",
        "badge": "DEV-001"
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Day 3 commands — mock data, real engine wiring comes Day 11-12
// ──────────────────────────────────────────────────────────────────────────────

#[tauri::command]
async fn open_evidence_dialog(_app: tauri::AppHandle) -> Result<Option<String>, String> {
    Ok(Some("/mock/evidence/jo-2009-11-16.E01".to_string()))
}

#[tauri::command]
async fn load_evidence(path: String) -> Result<EvidenceLoadResult, String> {
    let name = std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());
    Ok(EvidenceLoadResult {
        success: true,
        evidence_id: "ev-001".to_string(),
        name,
        size_display: "9.8 GB".to_string(),
        file_count: 26235,
        error: None,
    })
}

#[tauri::command]
async fn get_tree_root(_evidence_id: String) -> Result<Vec<TreeNode>, String> {
    Ok(vec![TreeNode {
        id: "node-root".to_string(),
        name: "jo-2009-11-16.E01 (9.8 GB)".to_string(),
        node_type: "evidence".to_string(),
        count: 26235,
        is_deleted: false,
        is_flagged: false,
        is_suspicious: false,
        has_children: true,
        parent_id: None,
        depth: 0,
    }])
}

#[tauri::command]
async fn get_tree_children(node_id: String) -> Result<Vec<TreeNode>, String> {
    let children = match node_id.as_str() {
        "node-root" => vec![TreeNode {
            id: "vol-ntfs".to_string(),
            name: "[NTFS NTFS] (26235)".to_string(),
            node_type: "volume".to_string(),
            count: 26235,
            is_deleted: false,
            is_flagged: false,
            is_suspicious: false,
            has_children: true,
            parent_id: Some("node-root".to_string()),
            depth: 1,
        }],
        "vol-ntfs" => vec![
            TreeNode {
                id: "folder-docs".to_string(),
                name: "Documents and Settings".to_string(),
                node_type: "folder".to_string(),
                count: 2050,
                is_deleted: false,
                is_flagged: false,
                is_suspicious: false,
                has_children: true,
                parent_id: Some("vol-ntfs".to_string()),
                depth: 2,
            },
            TreeNode {
                id: "folder-prog".to_string(),
                name: "Program Files".to_string(),
                node_type: "folder".to_string(),
                count: 4890,
                is_deleted: false,
                is_flagged: false,
                is_suspicious: false,
                has_children: true,
                parent_id: Some("vol-ntfs".to_string()),
                depth: 2,
            },
            TreeNode {
                id: "folder-recycler".to_string(),
                name: "RECYCLER".to_string(),
                node_type: "folder".to_string(),
                count: 3,
                is_deleted: false,
                is_flagged: false,
                is_suspicious: false,
                has_children: true,
                parent_id: Some("vol-ntfs".to_string()),
                depth: 2,
            },
            TreeNode {
                id: "folder-sysinfo".to_string(),
                name: "System Volume Information".to_string(),
                node_type: "folder".to_string(),
                count: 1481,
                is_deleted: false,
                is_flagged: false,
                is_suspicious: false,
                has_children: true,
                parent_id: Some("vol-ntfs".to_string()),
                depth: 2,
            },
            TreeNode {
                id: "folder-windows".to_string(),
                name: "Windows".to_string(),
                node_type: "folder".to_string(),
                count: 8200,
                is_deleted: false,
                is_flagged: false,
                is_suspicious: false,
                has_children: true,
                parent_id: Some("vol-ntfs".to_string()),
                depth: 2,
            },
            TreeNode {
                id: "folder-ie8".to_string(),
                name: "ie8".to_string(),
                node_type: "folder".to_string(),
                count: 740,
                is_deleted: false,
                is_flagged: true,
                is_suspicious: true,
                has_children: true,
                parent_id: Some("vol-ntfs".to_string()),
                depth: 2,
            },
            TreeNode {
                id: "folder-users".to_string(),
                name: "Users".to_string(),
                node_type: "folder".to_string(),
                count: 1200,
                is_deleted: false,
                is_flagged: false,
                is_suspicious: false,
                has_children: true,
                parent_id: Some("vol-ntfs".to_string()),
                depth: 2,
            },
        ],
        _ => vec![],
    };
    Ok(children)
}

#[tauri::command]
async fn get_files(
    _node_id: String,
    _filter: Option<String>,
    _sort_col: Option<String>,
    _sort_asc: Option<bool>,
) -> Result<Vec<FileEntry>, String> {
    Ok(vec![
        FileEntry {
            id: "f001".to_string(),
            name: "ntuser.dat".to_string(),
            extension: "dat".to_string(),
            size: 2516582,
            size_display: "2.4 MB".to_string(),
            modified: "2009-11-14 09:22".to_string(),
            created: "2009-10-01 00:00".to_string(),
            sha256: Some("a3f9c2d8e1b447f6...".to_string()),
            is_deleted: false,
            is_suspicious: false,
            is_flagged: false,
            category: "Registry Hive".to_string(),
            tag: None,
            tag_color: None,
        },
        FileEntry {
            id: "f002".to_string(),
            name: "setupapi.log".to_string(),
            extension: "log".to_string(),
            size: 1258291,
            size_display: "1.2 MB".to_string(),
            modified: "2009-11-10 14:00".to_string(),
            created: "2009-10-01 00:00".to_string(),
            sha256: None,
            is_deleted: false,
            is_suspicious: false,
            is_flagged: false,
            category: "System Log".to_string(),
            tag: None,
            tag_color: None,
        },
        FileEntry {
            id: "f003".to_string(),
            name: "svchost32.exe".to_string(),
            extension: "exe".to_string(),
            size: 913408,
            size_display: "892 KB".to_string(),
            modified: "2009-11-15 14:32".to_string(),
            created: "2009-11-15 14:32".to_string(),
            sha256: None,
            is_deleted: false,
            is_suspicious: true,
            is_flagged: false,
            category: "Executable".to_string(),
            tag: Some("Suspicious".to_string()),
            tag_color: Some("#b87840".to_string()),
        },
        FileEntry {
            id: "f004".to_string(),
            name: "mimikatz.exe".to_string(),
            extension: "exe".to_string(),
            size: 1258291,
            size_display: "1.2 MB".to_string(),
            modified: "2009-11-15 14:33".to_string(),
            created: "2009-11-15 14:33".to_string(),
            sha256: None,
            is_deleted: false,
            is_suspicious: false,
            is_flagged: true,
            category: "Known Malware Tool".to_string(),
            tag: Some("Critical Evidence".to_string()),
            tag_color: Some("#a84040".to_string()),
        },
        FileEntry {
            id: "f005".to_string(),
            name: "Security.evtx".to_string(),
            extension: "evtx".to_string(),
            size: 46137344,
            size_display: "44 MB".to_string(),
            modified: "2009-11-16 03:44".to_string(),
            created: "2009-10-01 00:00".to_string(),
            sha256: None,
            is_deleted: false,
            is_suspicious: false,
            is_flagged: false,
            category: "Event Log".to_string(),
            tag: None,
            tag_color: None,
        },
        FileEntry {
            id: "f006".to_string(),
            name: "SYSTEM".to_string(),
            extension: "".to_string(),
            size: 19083264,
            size_display: "18.2 MB".to_string(),
            modified: "2009-11-01 00:00".to_string(),
            created: "2009-10-01 00:00".to_string(),
            sha256: None,
            is_deleted: false,
            is_suspicious: false,
            is_flagged: false,
            category: "Registry Hive".to_string(),
            tag: None,
            tag_color: None,
        },
        FileEntry {
            id: "f007".to_string(),
            name: "evidence_backup.zip".to_string(),
            extension: "zip".to_string(),
            size: 23068672,
            size_display: "22 MB".to_string(),
            modified: "2009-11-14 22:11".to_string(),
            created: "2009-11-14 22:10".to_string(),
            sha256: None,
            is_deleted: true,
            is_suspicious: false,
            is_flagged: false,
            category: "Archive".to_string(),
            tag: None,
            tag_color: None,
        },
        FileEntry {
            id: "f008".to_string(),
            name: "cmd.lnk".to_string(),
            extension: "lnk".to_string(),
            size: 2150,
            size_display: "2.1 KB".to_string(),
            modified: "2009-11-15 14:35".to_string(),
            created: "2009-11-15 14:35".to_string(),
            sha256: None,
            is_deleted: false,
            is_suspicious: true,
            is_flagged: false,
            category: "Shell Link".to_string(),
            tag: None,
            tag_color: None,
        },
        FileEntry {
            id: "f009".to_string(),
            name: "WebCacheV01.dat".to_string(),
            extension: "dat".to_string(),
            size: 12582912,
            size_display: "12 MB".to_string(),
            modified: "2009-11-16 03:40".to_string(),
            created: "2009-10-01 00:00".to_string(),
            sha256: None,
            is_deleted: false,
            is_suspicious: false,
            is_flagged: false,
            category: "Browser Cache".to_string(),
            tag: None,
            tag_color: None,
        },
        FileEntry {
            id: "f010".to_string(),
            name: "cleanup.ps1".to_string(),
            extension: "ps1".to_string(),
            size: 4915,
            size_display: "4.8 KB".to_string(),
            modified: "2009-11-15 14:31".to_string(),
            created: "2009-11-15 14:31".to_string(),
            sha256: None,
            is_deleted: false,
            is_suspicious: true,
            is_flagged: false,
            category: "PowerShell Script".to_string(),
            tag: None,
            tag_color: None,
        },
    ])
}

#[tauri::command]
async fn get_file_metadata(file_id: String) -> Result<FileMetadata, String> {
    let meta = match file_id.as_str() {
        "f001" => FileMetadata {
            id: "f001".to_string(),
            name: "ntuser.dat".to_string(),
            full_path: "\\Documents and Settings\\Administrator\\ntuser.dat".to_string(),
            size: 2516582,
            size_display: "2.4 MB".to_string(),
            modified: "2009-11-14 09:22:14".to_string(),
            created: "2009-10-01 00:00:00".to_string(),
            accessed: "2009-11-16 03:44:00".to_string(),
            sha256: Some(
                "a3f9c2d8e1b447f609c382da554f1b9e7d2ca3f8b4e601d288f5a29c3e7b1d4f".to_string(),
            ),
            md5: Some("5f4dcc3b5aa765d61d8327deb882cf99".to_string()),
            category: "Registry Hive".to_string(),
            is_deleted: false,
            is_suspicious: false,
            is_flagged: false,
            mft_entry: Some(4922),
            extension: "dat".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
            inode: None,
            permissions: Some("rw-r--r--".to_string()),
        },
        "f003" => FileMetadata {
            id: "f003".to_string(),
            name: "svchost32.exe".to_string(),
            full_path: "\\Windows\\System32\\svchost32.exe".to_string(),
            size: 913408,
            size_display: "892 KB".to_string(),
            modified: "2009-11-15 14:32:00".to_string(),
            created: "2009-11-15 14:32:00".to_string(),
            accessed: "2009-11-15 14:32:00".to_string(),
            sha256: None,
            md5: None,
            category: "Executable".to_string(),
            is_deleted: false,
            is_suspicious: true,
            is_flagged: false,
            mft_entry: Some(6101),
            extension: "exe".to_string(),
            mime_type: Some("application/x-msdownload".to_string()),
            inode: None,
            permissions: Some("rwxr-xr-x".to_string()),
        },
        "f004" => FileMetadata {
            id: "f004".to_string(),
            name: "mimikatz.exe".to_string(),
            full_path: "\\Windows\\Temp\\mimikatz.exe".to_string(),
            size: 1258291,
            size_display: "1.2 MB".to_string(),
            modified: "2009-11-15 14:33:02".to_string(),
            created: "2009-11-15 14:33:02".to_string(),
            accessed: "2009-11-15 14:33:05".to_string(),
            sha256: None,
            md5: None,
            category: "Known Malware Tool".to_string(),
            is_deleted: false,
            is_suspicious: false,
            is_flagged: true,
            mft_entry: Some(7745),
            extension: "exe".to_string(),
            mime_type: Some("application/x-msdownload".to_string()),
            inode: None,
            permissions: Some("rwxr-xr-x".to_string()),
        },
        "f007" => FileMetadata {
            id: "f007".to_string(),
            name: "evidence_backup.zip".to_string(),
            full_path: "\\Users\\Admin\\Desktop\\evidence_backup.zip".to_string(),
            size: 23068672,
            size_display: "22 MB".to_string(),
            modified: "2009-11-14 22:11:00".to_string(),
            created: "2009-11-14 22:10:00".to_string(),
            accessed: "2009-11-14 22:11:00".to_string(),
            sha256: None,
            md5: None,
            category: "Archive".to_string(),
            is_deleted: true,
            is_suspicious: false,
            is_flagged: false,
            mft_entry: Some(8210),
            extension: "zip".to_string(),
            mime_type: Some("application/zip".to_string()),
            inode: None,
            permissions: Some("rw-r--r--".to_string()),
        },
        "f010" => FileMetadata {
            id: "f010".to_string(),
            name: "cleanup.ps1".to_string(),
            full_path: "\\Windows\\Temp\\cleanup.ps1".to_string(),
            size: 4915,
            size_display: "4.8 KB".to_string(),
            modified: "2009-11-15 14:31:00".to_string(),
            created: "2009-11-15 14:31:00".to_string(),
            accessed: "2009-11-15 14:31:00".to_string(),
            sha256: None,
            md5: None,
            category: "PowerShell Script".to_string(),
            is_deleted: false,
            is_suspicious: true,
            is_flagged: false,
            mft_entry: Some(7720),
            extension: "ps1".to_string(),
            mime_type: Some("text/x-powershell".to_string()),
            inode: None,
            permissions: Some("rw-r--r--".to_string()),
        },
        _ => FileMetadata {
            id: file_id.clone(),
            name: "Unknown".to_string(),
            full_path: "\\Unknown".to_string(),
            size: 0,
            size_display: "0 B".to_string(),
            modified: "\u{2014}".to_string(),
            created: "\u{2014}".to_string(),
            accessed: "\u{2014}".to_string(),
            sha256: None,
            md5: None,
            category: "Unknown".to_string(),
            is_deleted: false,
            is_suspicious: false,
            is_flagged: false,
            mft_entry: None,
            extension: "".to_string(),
            mime_type: None,
            inode: None,
            permissions: None,
        },
    };
    Ok(meta)
}

#[tauri::command]
async fn get_file_hex(
    _file_id: String,
    offset: u64,
    _length: u64,
) -> Result<HexData, String> {
    let bytes: Vec<u8> = vec![
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0x8C, 0x00, 0x00, 0x54, 0x68, 0x69, 0x73,
        0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20,
        0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F,
        0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut lines = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let off = offset + (i as u64 * 16);
        let hex_str = chunk
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii_str: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' })
            .collect();
        lines.push(HexLine {
            offset: format!("{:08X}", off),
            hex: hex_str,
            ascii: ascii_str,
        });
    }

    Ok(HexData {
        lines,
        total_size: 1258291,
        offset,
    })
}

#[tauri::command]
async fn get_file_text(file_id: String, _offset: u64) -> Result<String, String> {
    let content = match file_id.as_str() {
        "f010" => "# Cleanup script\n\
                   # Remove evidence files\n\
                   \n\
                   Remove-Item -Path C:\\Windows\\Temp\\mimikatz.exe -Force\n\
                   Remove-Item -Path C:\\Windows\\Temp\\lsass.dmp -Force\n\
                   Clear-EventLog -LogName Security\n\
                   Clear-EventLog -LogName System\n\
                   wevtutil cl Security\n\
                   wevtutil cl System\n\
                   # Delete VSS snapshots\n\
                   vssadmin delete shadows /all /quiet\n\
                   Write-Host 'Cleanup complete'"
            .to_string(),
        "f008" => "[Binary file - use HEX tab to view]".to_string(),
        _ => "[Text content not available for this file type.\nUse HEX tab to view raw bytes.]"
            .to_string(),
    };
    Ok(content)
}

#[tauri::command]
async fn search_files(query: String, _evidence_id: String) -> Result<Vec<SearchResult>, String> {
    if query.is_empty() {
        return Ok(vec![]);
    }
    let q = query.to_lowercase();
    let all = vec![
        SearchResult {
            id: "f004".to_string(),
            name: "mimikatz.exe".to_string(),
            full_path: "\\Windows\\Temp\\mimikatz.exe".to_string(),
            extension: "exe".to_string(),
            size_display: "1.2 MB".to_string(),
            modified: "2009-11-15 14:33".to_string(),
            is_deleted: false,
            is_flagged: true,
            is_suspicious: false,
            match_field: "filename".to_string(),
            match_value: "mimikatz.exe".to_string(),
        },
        SearchResult {
            id: "f003".to_string(),
            name: "svchost32.exe".to_string(),
            full_path: "\\Windows\\System32\\svchost32.exe".to_string(),
            extension: "exe".to_string(),
            size_display: "892 KB".to_string(),
            modified: "2009-11-15 14:32".to_string(),
            is_deleted: false,
            is_flagged: false,
            is_suspicious: true,
            match_field: "filename".to_string(),
            match_value: "svchost32.exe".to_string(),
        },
        SearchResult {
            id: "f010".to_string(),
            name: "cleanup.ps1".to_string(),
            full_path: "\\Windows\\Temp\\cleanup.ps1".to_string(),
            extension: "ps1".to_string(),
            size_display: "4.8 KB".to_string(),
            modified: "2009-11-15 14:31".to_string(),
            is_deleted: false,
            is_flagged: false,
            is_suspicious: true,
            match_field: "content".to_string(),
            match_value: "Remove-Item mimikatz.exe".to_string(),
        },
        SearchResult {
            id: "f007".to_string(),
            name: "evidence_backup.zip".to_string(),
            full_path: "\\Users\\Admin\\Desktop\\evidence_backup.zip".to_string(),
            extension: "zip".to_string(),
            size_display: "22 MB".to_string(),
            modified: "2009-11-14 22:11".to_string(),
            is_deleted: true,
            is_flagged: false,
            is_suspicious: false,
            match_field: "filename".to_string(),
            match_value: "evidence_backup.zip".to_string(),
        },
    ];

    let results: Vec<SearchResult> = all
        .into_iter()
        .filter(|r| {
            r.name.to_lowercase().contains(&q)
                || r.full_path.to_lowercase().contains(&q)
                || r.match_value.to_lowercase().contains(&q)
        })
        .collect();

    Ok(results)
}

#[tauri::command]
async fn get_tag_summaries() -> Result<Vec<TagSummary>, String> {
    let store = get_tag_store();
    let map = store.lock().map_err(|e| e.to_string())?;

    let tag_defs = [
        ("Critical Evidence", "#a84040"),
        ("Suspicious",        "#b87840"),
        ("Needs Review",      "#b8a840"),
        ("Confirmed Clean",   "#487858"),
        ("Key Artifact",      "#4a7890"),
        ("Excluded",          "#3a4858"),
    ];

    let summaries = tag_defs
        .iter()
        .map(|(name, color)| {
            let count = map.values().filter(|f| f.tag == *name).count() as u64;
            TagSummary {
                name: name.to_string(),
                color: color.to_string(),
                count,
            }
        })
        .collect();

    Ok(summaries)
}

#[tauri::command]
async fn get_tagged_files(tag: String) -> Result<Vec<TaggedFile>, String> {
    let store = get_tag_store();
    let map = store.lock().map_err(|e| e.to_string())?;
    let files: Vec<TaggedFile> = map.values().filter(|f| f.tag == tag).cloned().collect();
    Ok(files)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn tag_file(
    file_id: String,
    file_name: String,
    extension: String,
    size_display: String,
    modified: String,
    full_path: String,
    tag: String,
    tag_color: String,
    note: Option<String>,
) -> Result<(), String> {
    let store = get_tag_store();
    let mut map = store.lock().map_err(|e| e.to_string())?;
    map.insert(file_id.clone(), TaggedFile {
        file_id,
        name: file_name,
        extension,
        size_display,
        modified,
        full_path,
        tag,
        tag_color,
        tagged_at: "2009-11-16 09:00".to_string(),
        note,
    });
    Ok(())
}

#[tauri::command]
async fn untag_file(file_id: String) -> Result<(), String> {
    let store = get_tag_store();
    let mut map = store.lock().map_err(|e| e.to_string())?;
    map.remove(&file_id);
    Ok(())
}

#[tauri::command]
async fn get_artifact_categories(
    _evidence_id: String,
) -> Result<Vec<ArtifactCategory>, String> {
    Ok(vec![
        ArtifactCategory { name: "User Activity".to_string(), icon: "\u{1F464}".to_string(), count: 183, color: "#c8a040".to_string() },
        ArtifactCategory { name: "Execution History".to_string(), icon: "\u{25B6}".to_string(), count: 89, color: "#4a70c0".to_string() },
        ArtifactCategory { name: "Deleted & Recovered".to_string(), icon: "\u{1F5D1}".to_string(), count: 47, color: "#4a9060".to_string() },
        ArtifactCategory { name: "Network Artifacts".to_string(), icon: "\u{1F517}".to_string(), count: 34, color: "#40a0a0".to_string() },
        ArtifactCategory { name: "Identity & Accounts".to_string(), icon: "\u{1FAAA}".to_string(), count: 23, color: "#a0a040".to_string() },
        ArtifactCategory { name: "Credentials".to_string(), icon: "\u{1F511}".to_string(), count: 12, color: "#c05050".to_string() },
        ArtifactCategory { name: "Malware Indicators".to_string(), icon: "\u{1F6E1}".to_string(), count: 8, color: "#c07040".to_string() },
        ArtifactCategory { name: "Cloud & Sync".to_string(), icon: "\u{2601}".to_string(), count: 5, color: "#6090d0".to_string() },
        ArtifactCategory { name: "Memory Artifacts".to_string(), icon: "\u{1F4BE}".to_string(), count: 2, color: "#8090a0".to_string() },
        ArtifactCategory { name: "Communications".to_string(), icon: "\u{1F4AC}".to_string(), count: 0, color: "#8050c0".to_string() },
        ArtifactCategory { name: "Social Media".to_string(), icon: "\u{1F4F1}".to_string(), count: 0, color: "#8050c0".to_string() },
        ArtifactCategory { name: "Web Activity".to_string(), icon: "\u{1F310}".to_string(), count: 0, color: "#4a7890".to_string() },
    ])
}

#[tauri::command]
async fn get_artifacts(
    _evidence_id: String,
    category: String,
) -> Result<Vec<Artifact>, String> {
    let artifacts = match category.as_str() {
        "User Activity" => vec![
            Artifact { id: "a001".to_string(), category: "User Activity".to_string(), name: "UserAssist: cmd.exe".to_string(), value: "23 executions".to_string(), timestamp: Some("2009-11-15 14:33:01".to_string()), source_file: "NTUSER.DAT".to_string(), source_path: "\\Documents and Settings\\Administrator\\ntuser.dat".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1204".to_string()), mitre_name: Some("User Execution".to_string()), plugin: "Chronicle".to_string(), raw_data: Some("UEME_RUNPATH:C:\\Windows\\System32\\cmd.exe".to_string()) },
            Artifact { id: "a002".to_string(), category: "User Activity".to_string(), name: "UserAssist: mimikatz.exe".to_string(), value: "3 executions".to_string(), timestamp: Some("2009-11-15 14:33:05".to_string()), source_file: "NTUSER.DAT".to_string(), source_path: "\\Documents and Settings\\Administrator\\ntuser.dat".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1003".to_string()), mitre_name: Some("OS Credential Dumping".to_string()), plugin: "Chronicle".to_string(), raw_data: Some("UEME_RUNPATH:C:\\Windows\\Temp\\mimikatz.exe".to_string()) },
            Artifact { id: "a003".to_string(), category: "User Activity".to_string(), name: "RecentDocs: evidence_backup.zip".to_string(), value: "Last accessed".to_string(), timestamp: Some("2009-11-14 22:10:44".to_string()), source_file: "NTUSER.DAT".to_string(), source_path: "\\Documents and Settings\\Administrator\\ntuser.dat".to_string(), forensic_value: "medium".to_string(), mitre_technique: Some("T1083".to_string()), mitre_name: Some("File and Directory Discovery".to_string()), plugin: "Chronicle".to_string(), raw_data: None },
            Artifact { id: "a004".to_string(), category: "User Activity".to_string(), name: "TypedPath: C:\\Windows\\Temp".to_string(), value: "Explorer address bar entry".to_string(), timestamp: Some("2009-11-15 14:30:12".to_string()), source_file: "NTUSER.DAT".to_string(), source_path: "\\Documents and Settings\\Administrator\\ntuser.dat".to_string(), forensic_value: "medium".to_string(), mitre_technique: Some("T1083".to_string()), mitre_name: Some("File and Directory Discovery".to_string()), plugin: "Chronicle".to_string(), raw_data: None },
            Artifact { id: "a005".to_string(), category: "User Activity".to_string(), name: "WordWheelQuery: lsass".to_string(), value: "Start menu search term".to_string(), timestamp: Some("2009-11-15 14:28:33".to_string()), source_file: "NTUSER.DAT".to_string(), source_path: "\\Documents and Settings\\Administrator\\ntuser.dat".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1057".to_string()), mitre_name: Some("Process Discovery".to_string()), plugin: "Chronicle".to_string(), raw_data: None },
        ],
        "Execution History" => vec![
            Artifact { id: "b001".to_string(), category: "Execution History".to_string(), name: "BAM: mimikatz.exe".to_string(), value: "Last executed".to_string(), timestamp: Some("2009-11-15 14:33:02".to_string()), source_file: "SYSTEM".to_string(), source_path: "\\Windows\\System32\\config\\SYSTEM".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1003".to_string()), mitre_name: Some("OS Credential Dumping".to_string()), plugin: "Trace".to_string(), raw_data: Some("Path: C:\\Windows\\Temp\\mimikatz.exe\nSequenceNumber: 0x0000047A".to_string()) },
            Artifact { id: "b002".to_string(), category: "Execution History".to_string(), name: "BAM: cleanup.ps1".to_string(), value: "Last executed".to_string(), timestamp: Some("2009-11-15 14:31:00".to_string()), source_file: "SYSTEM".to_string(), source_path: "\\Windows\\System32\\config\\SYSTEM".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1059.001".to_string()), mitre_name: Some("PowerShell".to_string()), plugin: "Trace".to_string(), raw_data: Some("Path: C:\\Windows\\Temp\\cleanup.ps1".to_string()) },
            Artifact { id: "b003".to_string(), category: "Execution History".to_string(), name: "Scheduled Task: WindowsUpdate".to_string(), value: "Persistence mechanism".to_string(), timestamp: Some("2009-11-14 03:00:00".to_string()), source_file: "WindowsUpdate.xml".to_string(), source_path: "\\Windows\\System32\\Tasks\\WindowsUpdate".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1053.005".to_string()), mitre_name: Some("Scheduled Task".to_string()), plugin: "Trace".to_string(), raw_data: Some("<Command>C:\\Windows\\Temp\\svchost32.exe</Command>".to_string()) },
            Artifact { id: "b004".to_string(), category: "Execution History".to_string(), name: "Prefetch: MIMIKATZ.EXE-ABC123.pf".to_string(), value: "3 runs".to_string(), timestamp: Some("2009-11-15 14:33:05".to_string()), source_file: "MIMIKATZ.EXE-ABC123.pf".to_string(), source_path: "\\Windows\\Prefetch\\MIMIKATZ.EXE-ABC123.pf".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1003".to_string()), mitre_name: Some("OS Credential Dumping".to_string()), plugin: "Trace".to_string(), raw_data: None },
        ],
        "Deleted & Recovered" => vec![
            Artifact { id: "c001".to_string(), category: "Deleted & Recovered".to_string(), name: "Recycle Bin: lsass.dmp".to_string(), value: "Deleted credential dump".to_string(), timestamp: Some("2009-11-15 14:45:00".to_string()), source_file: "$I001234.dat".to_string(), source_path: "\\RECYCLER\\S-1-5-21-XXX\\$I001234.dat".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1003.001".to_string()), mitre_name: Some("LSASS Memory".to_string()), plugin: "Remnant".to_string(), raw_data: Some("Original path: C:\\Windows\\Temp\\lsass.dmp\nOriginal size: 44,040,192 bytes".to_string()) },
            Artifact { id: "c002".to_string(), category: "Deleted & Recovered".to_string(), name: "USN Journal: mimikatz.exe created".to_string(), value: "File system operation".to_string(), timestamp: Some("2009-11-15 14:32:58".to_string()), source_file: "$UsnJrnl".to_string(), source_path: "\\$Extend\\$UsnJrnl".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1070.004".to_string()), mitre_name: Some("File Deletion".to_string()), plugin: "Remnant".to_string(), raw_data: Some("USN: 0x000000001A4F8800\nReason: FILE_CREATE | CLOSE\nFileName: mimikatz.exe".to_string()) },
            Artifact { id: "c003".to_string(), category: "Deleted & Recovered".to_string(), name: "USN Journal: lsass.dmp deleted".to_string(), value: "File deletion event".to_string(), timestamp: Some("2009-11-15 14:44:55".to_string()), source_file: "$UsnJrnl".to_string(), source_path: "\\$Extend\\$UsnJrnl".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1070.004".to_string()), mitre_name: Some("File Deletion".to_string()), plugin: "Remnant".to_string(), raw_data: Some("USN: 0x000000001A512400\nReason: FILE_DELETE | CLOSE\nFileName: lsass.dmp".to_string()) },
        ],
        "Credentials" => vec![
            Artifact { id: "d001".to_string(), category: "Credentials".to_string(), name: "WiFi Profile: CorpNetwork".to_string(), value: "WPA2-Enterprise saved credential".to_string(), timestamp: None, source_file: "CorpNetwork.xml".to_string(), source_path: "\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1552.001".to_string()), mitre_name: Some("Credentials in Files".to_string()), plugin: "Cipher".to_string(), raw_data: Some("<SSID>CorpNetwork</SSID>\n<keyMaterial>[ENCRYPTED]</keyMaterial>".to_string()) },
            Artifact { id: "d002".to_string(), category: "Credentials".to_string(), name: "WiFi Profile: HomeNetwork_5G".to_string(), value: "WPA2-Personal saved credential".to_string(), timestamp: None, source_file: "HomeNetwork_5G.xml".to_string(), source_path: "\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\".to_string(), forensic_value: "medium".to_string(), mitre_technique: Some("T1552.001".to_string()), mitre_name: Some("Credentials in Files".to_string()), plugin: "Cipher".to_string(), raw_data: None },
        ],
        "Malware Indicators" => vec![
            Artifact { id: "e001".to_string(), category: "Malware Indicators".to_string(), name: "Known Tool: mimikatz.exe".to_string(), value: "Credential dumping tool".to_string(), timestamp: Some("2009-11-15 14:33:02".to_string()), source_file: "mimikatz.exe".to_string(), source_path: "\\Windows\\Temp\\mimikatz.exe".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1003".to_string()), mitre_name: Some("OS Credential Dumping".to_string()), plugin: "Vector".to_string(), raw_data: Some("PE signature match: Mimikatz v2.x\nImports: LsaOpenPolicy, SamConnect\nMD5: [not computed]".to_string()) },
            Artifact { id: "e002".to_string(), category: "Malware Indicators".to_string(), name: "Anti-forensic: Event log cleared".to_string(), value: "Evidence destruction".to_string(), timestamp: Some("2009-11-15 14:31:05".to_string()), source_file: "cleanup.ps1".to_string(), source_path: "\\Windows\\Temp\\cleanup.ps1".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1070.001".to_string()), mitre_name: Some("Clear Windows Event Logs".to_string()), plugin: "Vector".to_string(), raw_data: Some("Content: wevtutil cl Security\nContent: wevtutil cl System\nContent: vssadmin delete shadows".to_string()) },
        ],
        "Network Artifacts" => vec![
            Artifact { id: "f001".to_string(), category: "Network Artifacts".to_string(), name: "RDP Connection: 192.168.1.50".to_string(), value: "Remote Desktop target".to_string(), timestamp: Some("2009-11-15 13:45:00".to_string()), source_file: "NTUSER.DAT".to_string(), source_path: "\\Documents and Settings\\Administrator\\ntuser.dat".to_string(), forensic_value: "high".to_string(), mitre_technique: Some("T1021.001".to_string()), mitre_name: Some("Remote Desktop Protocol".to_string()), plugin: "Conduit".to_string(), raw_data: Some("MRU: 192.168.1.50\nUsername hint: Administrator".to_string()) },
            Artifact { id: "f002".to_string(), category: "Network Artifacts".to_string(), name: "WiFi History: CorpNetwork".to_string(), value: "Previously connected network".to_string(), timestamp: None, source_file: "SOFTWARE".to_string(), source_path: "\\Windows\\System32\\config\\SOFTWARE".to_string(), forensic_value: "medium".to_string(), mitre_technique: Some("T1016".to_string()), mitre_name: Some("System Network Config Discovery".to_string()), plugin: "Conduit".to_string(), raw_data: None },
        ],
        "Identity & Accounts" => vec![
            Artifact { id: "g001".to_string(), category: "Identity & Accounts".to_string(), name: "Local Account: Administrator".to_string(), value: "Last login: 2009-11-15 14:30".to_string(), timestamp: Some("2009-11-15 14:30:00".to_string()), source_file: "SAM".to_string(), source_path: "\\Windows\\System32\\config\\SAM".to_string(), forensic_value: "medium".to_string(), mitre_technique: Some("T1087.001".to_string()), mitre_name: Some("Local Account".to_string()), plugin: "Recon".to_string(), raw_data: None },
            Artifact { id: "g002".to_string(), category: "Identity & Accounts".to_string(), name: "Email: admin@corpnetwork.local".to_string(), value: "Found in document metadata".to_string(), timestamp: None, source_file: "ntuser.dat".to_string(), source_path: "\\Documents and Settings\\Administrator\\ntuser.dat".to_string(), forensic_value: "medium".to_string(), mitre_technique: Some("T1589.002".to_string()), mitre_name: Some("Email Addresses".to_string()), plugin: "Recon".to_string(), raw_data: None },
        ],
        _ => vec![],
    };
    Ok(artifacts)
}

#[tauri::command]
async fn get_plugin_statuses() -> Result<Vec<PluginStatus>, String> {
    let store = get_plugin_status_store();
    let map = store.lock().map_err(|e| e.to_string())?;

    let statuses = PLUGIN_NAMES
        .iter()
        .map(|n| {
            map.get(*n).cloned().unwrap_or(PluginStatus {
                name: n.to_string(),
                status: "idle".to_string(),
                progress: 0,
                artifact_count: 0,
            })
        })
        .collect();

    Ok(statuses)
}

#[tauri::command]
async fn run_plugin(
    plugin_name: String,
    _evidence_id: String,
    app: tauri::AppHandle,
) -> Result<PluginRunResult, String> {
    let store = get_plugin_status_store();

    {
        let mut map = store.lock().map_err(|e| e.to_string())?;
        map.insert(
            plugin_name.clone(),
            PluginStatus {
                name: plugin_name.clone(),
                status: "running".to_string(),
                progress: 0,
                artifact_count: 0,
            },
        );
    }

    let plugin = plugin_name.clone();
    let store2 = store.clone();
    let app2 = app.clone();

    tokio::spawn(async move {
        let steps: [u8; 7] = [10, 25, 40, 55, 70, 85, 95];
        for p in steps {
            tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
            if let Ok(mut map) = store2.lock() {
                if let Some(s) = map.get_mut(&plugin) {
                    s.progress = p;
                }
            }
            let _ = app2.emit(
                "plugin-progress",
                json!({
                    "name": plugin,
                    "progress": p,
                    "status": "running"
                }),
            );
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
        let count = mock_artifact_count(&plugin);

        if let Ok(mut map) = store2.lock() {
            map.insert(
                plugin.clone(),
                PluginStatus {
                    name: plugin.clone(),
                    status: "complete".to_string(),
                    progress: 100,
                    artifact_count: count,
                },
            );
        }

        let _ = app2.emit(
            "plugin-progress",
            json!({
                "name": plugin,
                "progress": 100,
                "status": "complete",
                "artifact_count": count
            }),
        );
    });

    Ok(PluginRunResult {
        plugin_name: plugin_name.clone(),
        success: true,
        artifact_count: 0,
        duration_ms: 0,
        error: None,
    })
}

#[tauri::command]
async fn run_all_plugins(evidence_id: String, app: tauri::AppHandle) -> Result<(), String> {
    for plugin in PLUGIN_NAMES {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        let _ = run_plugin(plugin.to_string(), evidence_id.clone(), app.clone()).await;
    }
    Ok(())
}

#[tauri::command]
async fn get_stats(_evidence_id: String) -> Result<Stats, String> {
    Ok(Stats {
        files: 26235,
        suspicious: 8993,
        flagged: 12,
        carved: 0,
        hashed: 0,
        artifacts: 0,
    })
}

// ──────────────────────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_version,
            check_license,
            get_examiner_profile,
            open_evidence_dialog,
            load_evidence,
            get_tree_root,
            get_tree_children,
            get_files,
            get_file_metadata,
            get_stats,
            get_file_hex,
            get_file_text,
            search_files,
            get_plugin_statuses,
            run_plugin,
            run_all_plugins,
            get_artifact_categories,
            get_artifacts,
            get_tag_summaries,
            get_tagged_files,
            tag_file,
            untag_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
