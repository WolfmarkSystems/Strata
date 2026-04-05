use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct AndroidFullParser;

impl AndroidFullParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidDeviceFull {
    pub device_id: Option<String>,
    pub serial_number: Option<String>,
    pub model: Option<String>,
    pub manufacturer: Option<String>,
    pub brand: Option<String>,
    pub device: Option<String>,
    pub product: Option<String>,
    pub hardware: Option<String>,
    pub board: Option<String>,
    pub os_version: Option<String>,
    pub sdk_int: Option<i32>,
    pub security_patch: Option<String>,
    pub build_id: Option<String>,
    pub build_fingerprint: Option<String>,
    pub boot_loader: Option<String>,
    pub radio_version: Option<String>,
    pub bootloader_unlocked: bool,
    pub root_access: bool,
    pub selinux_enforcing: bool,
    pub encryption_status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidAppFull {
    pub package_name: Option<String>,
    pub app_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    pub install_time: Option<i64>,
    pub update_time: Option<i64>,
    pub data_dir: Option<String>,
    pub source_dir: Option<String>,
    pub apk_size: i64,
    pub signature: Option<String>,
    pub is_system_app: bool,
    pub is_enabled: bool,
    pub is_debuggable: bool,
    pub requested_permissions: Vec<String>,
    pub manifest: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidCallLogFull {
    pub id: Option<i64>,
    pub number: Option<String>,
    pub date: Option<i64>,
    pub duration: i32,
    pub type_: Option<String>,
    pub name: Option<String>,
    pub photo_id: Option<String>,
    pub cached_name: Option<String>,
    pub cached_number_type: Option<i32>,
    pub cached_number_label: Option<String>,
    pub geocode: Option<String>,
    pub phone_account_id: Option<String>,
    pub phone_account_component: Option<String>,
    pub is_read: bool,
    pub duration_formatted: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidSmsFull {
    pub id: Option<i64>,
    pub thread_id: Option<i64>,
    pub address: Option<String>,
    pub person: Option<String>,
    pub date: Option<i64>,
    pub date_sent: Option<i64>,
    pub protocol: Option<i32>,
    pub read: bool,
    pub status: Option<i32>,
    pub type_: Option<i32>,
    pub reply_path_present: bool,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub teleservice: Option<String>,
    pub service_center: Option<String>,
    pub locked: bool,
    pub error_code: Option<i32>,
    pub seen: bool,
    pub spam: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidLocationFull {
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub altitude: Option<f64>,
    pub accuracy: Option<f64>,
    pub speed: Option<f64>,
    pub bearing: Option<f64>,
    pub timestamp: Option<i64>,
    pub provider: Option<String>,
    pub activity: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidWifiFull {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub capabilities: Option<String>,
    pub frequency: Option<i32>,
    pub channel_width: Option<i32>,
    pub rssi: Option<i32>,
    pub link_speed: Option<i32>,
    pub last_connected: Option<i64>,
    pub is_secure: bool,
    pub is_known_network: bool,
}

impl Default for AndroidFullParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for AndroidFullParser {
    fn name(&self) -> &str {
        "Android Full"
    }

    fn artifact_type(&self) -> &str {
        "mobile"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["android", "data/data", "Android/data", "adb"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = AndroidAppFull {
                package_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                app_name: None,
                version_name: None,
                version_code: None,
                install_time: None,
                update_time: None,
                data_dir: None,
                source_dir: Some(path.to_string_lossy().to_string()),
                apk_size: data.len() as i64,
                signature: None,
                is_system_app: false,
                is_enabled: true,
                is_debuggable: false,
                requested_permissions: vec![],
                manifest: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "mobile".to_string(),
                description: "Android application".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}
