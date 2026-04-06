use serde::{Deserialize, Serialize};
use serde_json::json;

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
            mft_entry: Some(4922),
            extension: "dat".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
            inode: None,
            permissions: Some("rw-r--r--".to_string()),
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
            mft_entry: Some(7745),
            extension: "exe".to_string(),
            mime_type: Some("application/x-msdownload".to_string()),
            inode: None,
            permissions: Some("rwxr-xr-x".to_string()),
        },
        _ => FileMetadata {
            id: file_id.clone(),
            name: "Unknown".to_string(),
            full_path: "\\Unknown".to_string(),
            size: 0,
            size_display: "0 B".to_string(),
            modified: "—".to_string(),
            created: "—".to_string(),
            accessed: "—".to_string(),
            sha256: None,
            md5: None,
            category: "Unknown".to_string(),
            is_deleted: false,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
