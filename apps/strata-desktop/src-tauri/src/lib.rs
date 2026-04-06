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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
