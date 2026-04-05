use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriagePreset {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: TriagePresetCategory,
    pub filters: TriageFilter,
    pub is_system: bool,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TriagePresetCategory {
    Quick,
    Malware,
    UserActivity,
    System,
    Network,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TriageFilter {
    pub extensions: Vec<String>,
    pub exclude_extensions: Vec<String>,
    pub paths_include: Vec<String>,
    pub paths_exclude: Vec<String>,
    pub size_min: Option<u64>,
    pub size_max: Option<u64>,
    pub date_start: Option<u64>,
    pub date_end: Option<u64>,
    pub categories: Vec<String>,
    pub artifacts: Vec<String>,
    pub keywords: Vec<String>,
    pub exclude_keywords: Vec<String>,
    pub hash_known_good: bool,
    pub hash_known_bad: bool,
    pub entropy_min: Option<f32>,
    pub entropy_max: Option<f32>,
    pub is_hidden: Option<bool>,
    pub is_system: Option<bool>,
    pub is_readonly: Option<bool>,
    pub is_directory: Option<bool>,
}

impl TriageFilter {
    pub fn quick() -> Self {
        Self {
            extensions: vec![
                "exe".to_string(),
                "dll".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "ps1".to_string(),
                "vbs".to_string(),
                "js".to_string(),
                "hta".to_string(),
                "scr".to_string(),
                "pif".to_string(),
                "com".to_string(),
                "jar".to_string(),
                "elf".to_string(),
            ],
            ..Default::default()
        }
    }

    pub fn malware() -> Self {
        Self {
            extensions: vec![
                "exe".to_string(),
                "dll".to_string(),
                "sys".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "ps1".to_string(),
                "vbs".to_string(),
                "js".to_string(),
                "jse".to_string(),
                "vbe".to_string(),
                "wsf".to_string(),
                "wsh".to_string(),
                "hta".to_string(),
                "msi".to_string(),
                "scr".to_string(),
                "pif".to_string(),
                "com".to_string(),
                "jar".to_string(),
                "elf".to_string(),
                "sh".to_string(),
                "bash".to_string(),
                "bin".to_string(),
            ],
            paths_exclude: vec![
                "Windows\\System32".to_string(),
                "Windows\\SysWOW64".to_string(),
                "Program Files".to_string(),
                "ProgramData".to_string(),
            ],
            entropy_min: Some(7.0),
            hash_known_bad: true,
            ..Default::default()
        }
    }

    pub fn user_activity() -> Self {
        Self {
            categories: vec![
                "browser".to_string(),
                "chat".to_string(),
                "email".to_string(),
                "document".to_string(),
                "download".to_string(),
                "media".to_string(),
                "recent".to_string(),
            ],
            paths_include: vec![
                "Users".to_string(),
                "AppData".to_string(),
                "ProgramData".to_string(),
            ],
            date_start: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - 86400 * 30,
            ),
            ..Default::default()
        }
    }

    pub fn system() -> Self {
        Self {
            paths_include: vec![
                "Windows".to_string(),
                "Program Files".to_string(),
                "Program Files (x86)".to_string(),
                "ProgramData".to_string(),
            ],
            categories: vec![
                "system".to_string(),
                "service".to_string(),
                "driver".to_string(),
                "registry".to_string(),
                "eventlog".to_string(),
            ],
            ..Default::default()
        }
    }

    pub fn network() -> Self {
        Self {
            categories: vec![
                "network".to_string(),
                "browser".to_string(),
                "download".to_string(),
                "email".to_string(),
            ],
            extensions: vec![
                "pcap".to_string(),
                "cap".to_string(),
                "etl".to_string(),
                "evtx".to_string(),
                "log".to_string(),
            ],
            ..Default::default()
        }
    }

    pub fn recent_documents() -> Self {
        Self {
            categories: vec!["document".to_string(), "recent".to_string()],
            date_start: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - 86400 * 7,
            ),
            ..Default::default()
        }
    }

    pub fn suspicious() -> Self {
        Self {
            entropy_min: Some(7.2),
            size_min: Some(1024),
            size_max: Some(10 * 1024 * 1024),
            paths_exclude: vec![
                "Windows\\System32".to_string(),
                "Windows\\SysWOW64".to_string(),
                "Program Files".to_string(),
            ],
            hash_known_bad: true,
            ..Default::default()
        }
    }

    pub fn large_files() -> Self {
        Self {
            size_min: Some(100 * 1024 * 1024),
            ..Default::default()
        }
    }

    pub fn images() -> Self {
        Self {
            extensions: vec![
                "jpg".to_string(),
                "jpeg".to_string(),
                "png".to_string(),
                "gif".to_string(),
                "bmp".to_string(),
                "tiff".to_string(),
                "webp".to_string(),
                "svg".to_string(),
                "ico".to_string(),
                "heic".to_string(),
                "heif".to_string(),
            ],
            categories: vec!["image".to_string()],
            ..Default::default()
        }
    }

    pub fn videos() -> Self {
        Self {
            extensions: vec![
                "mp4".to_string(),
                "avi".to_string(),
                "mkv".to_string(),
                "mov".to_string(),
                "wmv".to_string(),
                "flv".to_string(),
                "webm".to_string(),
                "m4v".to_string(),
                "mpeg".to_string(),
                "mpg".to_string(),
            ],
            categories: vec!["video".to_string()],
            ..Default::default()
        }
    }

    pub fn documents() -> Self {
        Self {
            extensions: vec![
                "doc".to_string(),
                "docx".to_string(),
                "xls".to_string(),
                "xlsx".to_string(),
                "ppt".to_string(),
                "pptx".to_string(),
                "pdf".to_string(),
                "txt".to_string(),
                "rtf".to_string(),
                "odt".to_string(),
                "ods".to_string(),
                "odp".to_string(),
            ],
            categories: vec!["document".to_string()],
            ..Default::default()
        }
    }

    pub fn archives() -> Self {
        Self {
            extensions: vec![
                "zip".to_string(),
                "rar".to_string(),
                "7z".to_string(),
                "tar".to_string(),
                "gz".to_string(),
                "bz2".to_string(),
                "xz".to_string(),
                "iso".to_string(),
            ],
            ..Default::default()
        }
    }

    pub fn encrypted() -> Self {
        Self {
            entropy_min: Some(7.8),
            size_min: Some(64),
            size_max: Some(100 * 1024 * 1024),
            ..Default::default()
        }
    }
}

use std::time::{SystemTime, UNIX_EPOCH};

pub struct TriagePresetManager {
    presets: HashMap<String, TriagePreset>,
}

impl TriagePresetManager {
    pub fn new() -> Self {
        let mut manager = Self {
            presets: HashMap::new(),
        };
        manager.init_default_presets();
        manager
    }

    fn init_default_presets(&mut self) {
        self.presets.insert(
            "quick".to_string(),
            TriagePreset {
                id: "quick".to_string(),
                name: "Quick Scan".to_string(),
                description: "Quick scan for common executable types".to_string(),
                category: TriagePresetCategory::Quick,
                filters: TriageFilter::quick(),
                is_system: true,
                is_default: true,
            },
        );

        self.presets.insert(
            "malware".to_string(),
            TriagePreset {
                id: "malware".to_string(),
                name: "Malware Hunt".to_string(),
                description: "Scan for potential malware and suspicious files".to_string(),
                category: TriagePresetCategory::Malware,
                filters: TriageFilter::malware(),
                is_system: true,
                is_default: false,
            },
        );

        self.presets.insert(
            "user-activity".to_string(),
            TriagePreset {
                id: "user-activity".to_string(),
                name: "User Activity".to_string(),
                description: "Recent user activity and documents".to_string(),
                category: TriagePresetCategory::UserActivity,
                filters: TriageFilter::user_activity(),
                is_system: true,
                is_default: false,
            },
        );

        self.presets.insert(
            "system".to_string(),
            TriagePreset {
                id: "system".to_string(),
                name: "System Files".to_string(),
                description: "Windows system files and configuration".to_string(),
                category: TriagePresetCategory::System,
                filters: TriageFilter::system(),
                is_system: true,
                is_default: false,
            },
        );

        self.presets.insert(
            "network".to_string(),
            TriagePreset {
                id: "network".to_string(),
                name: "Network Activity".to_string(),
                description: "Network logs, captures, and browser data".to_string(),
                category: TriagePresetCategory::Network,
                filters: TriageFilter::network(),
                is_system: true,
                is_default: false,
            },
        );

        self.presets.insert(
            "suspicious".to_string(),
            TriagePreset {
                id: "suspicious".to_string(),
                name: "Suspicious Files".to_string(),
                description: "High entropy files in unusual locations".to_string(),
                category: TriagePresetCategory::Malware,
                filters: TriageFilter::suspicious(),
                is_system: true,
                is_default: false,
            },
        );

        self.presets.insert(
            "large".to_string(),
            TriagePreset {
                id: "large".to_string(),
                name: "Large Files".to_string(),
                description: "Files larger than 100MB".to_string(),
                category: TriagePresetCategory::Custom,
                filters: TriageFilter::large_files(),
                is_system: true,
                is_default: false,
            },
        );

        self.presets.insert(
            "images".to_string(),
            TriagePreset {
                id: "images".to_string(),
                name: "Images".to_string(),
                description: "Image and photo files".to_string(),
                category: TriagePresetCategory::Custom,
                filters: TriageFilter::images(),
                is_system: true,
                is_default: false,
            },
        );

        self.presets.insert(
            "videos".to_string(),
            TriagePreset {
                id: "videos".to_string(),
                name: "Videos".to_string(),
                description: "Video files".to_string(),
                category: TriagePresetCategory::Custom,
                filters: TriageFilter::videos(),
                is_system: true,
                is_default: false,
            },
        );

        self.presets.insert(
            "documents".to_string(),
            TriagePreset {
                id: "documents".to_string(),
                name: "Documents".to_string(),
                description: "Office documents and PDFs".to_string(),
                category: TriagePresetCategory::Custom,
                filters: TriageFilter::documents(),
                is_system: true,
                is_default: false,
            },
        );

        self.presets.insert(
            "archives".to_string(),
            TriagePreset {
                id: "archives".to_string(),
                name: "Archives".to_string(),
                description: "Compressed archives".to_string(),
                category: TriagePresetCategory::Custom,
                filters: TriageFilter::archives(),
                is_system: true,
                is_default: false,
            },
        );

        self.presets.insert(
            "encrypted".to_string(),
            TriagePreset {
                id: "encrypted".to_string(),
                name: "Potentially Encrypted".to_string(),
                description: "High entropy files (possibly encrypted)".to_string(),
                category: TriagePresetCategory::Custom,
                filters: TriageFilter::encrypted(),
                is_system: true,
                is_default: false,
            },
        );
    }

    pub fn get_preset(&self, id: &str) -> Option<&TriagePreset> {
        self.presets.get(id)
    }

    pub fn list_presets(&self) -> Vec<&TriagePreset> {
        self.presets.values().collect()
    }

    pub fn list_presets_by_category(&self, category: TriagePresetCategory) -> Vec<&TriagePreset> {
        self.presets
            .values()
            .filter(|p| p.category == category)
            .collect()
    }

    pub fn list_default_presets(&self) -> Vec<&TriagePreset> {
        self.presets.values().filter(|p| p.is_default).collect()
    }

    pub fn list_system_presets(&self) -> Vec<&TriagePreset> {
        self.presets.values().filter(|p| p.is_system).collect()
    }

    pub fn add_custom_preset(&mut self, preset: TriagePreset) {
        self.presets.insert(preset.id.clone(), preset);
    }

    pub fn remove_custom_preset(&mut self, id: &str) -> bool {
        if let Some(preset) = self.presets.get(id) {
            if !preset.is_system {
                return self.presets.remove(id).is_some();
            }
        }
        false
    }
}

impl Default for TriagePresetManager {
    fn default() -> Self {
        Self::new()
    }
}
