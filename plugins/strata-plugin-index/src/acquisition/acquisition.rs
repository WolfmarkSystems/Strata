use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AcquisitionParser;

impl AcquisitionParser {
    pub fn new() -> Self {
        Self
    }

    pub fn calculate_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    pub fn generate_chain_of_custody(evidence_path: &Path, data: &[u8]) -> ChainOfCustody {
        let hash = Self::calculate_hash(data);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        ChainOfCustody {
            evidence_path: evidence_path.to_string_lossy().to_string(),
            sha256_hash: hash,
            timestamp,
            acquired_by: "ForensicSuite".to_string(),
            tool_version: Some("1.3.0".to_string()),
            platform: std::env::consts::OS.to_string(),
            verified: false,
        }
    }

    pub fn verify_chain_of_custody(
        _evidence_path: &Path,
        data: &[u8],
        expected_hash: &str,
    ) -> bool {
        let current_hash = Self::calculate_hash(data);
        current_hash == expected_hash
    }

    pub fn create_adb_acquisition_config() -> AdbAcquisitionConfig {
        AdbAcquisitionConfig {
            target_device: None,
            acquisition_type: AdbAcquisitionType::Logical,
            include_data: true,
            include_system: false,
            include_sdcard: false,
            backup_apps: vec![],
            pull_paths: vec![
                "/data/data".to_string(),
                "/sdcard".to_string(),
                "/storage/emulated/0".to_string(),
            ],
            compressed: true,
            output_path: None,
        }
    }

    pub fn create_ios_acquisition_config() -> IosAcquisitionConfig {
        IosAcquisitionConfig {
            target_device: None,
            acquisition_type: IosAcquisitionType::Logical,
            jailbreak_required: false,
            checkm8_available: false,
            backup_password: None,
            include_keychain: true,
            include_photos: true,
            include_messages: true,
            include_location: true,
            include_health: true,
            output_path: None,
        }
    }

    pub fn create_graph_collection_config() -> GraphCollectionConfig {
        GraphCollectionConfig {
            tenant_id: None,
            client_id: None,
            use_device_code_flow: true,
            scopes: vec![
                "AuditLog.Read.All".to_string(),
                "Mail.Read".to_string(),
                "MailboxSettings.Read".to_string(),
                "ChannelMessage.Read.All".to_string(),
                "Directory.Read.All".to_string(),
            ],
            endpoints: vec![
                "/auditLogs/signIns".to_string(),
                "/users/{id}/mailFolders/inbox/messageRules".to_string(),
                "/users/{id}/mailboxSettings".to_string(),
                "/users/{id}/chats".to_string(),
            ],
            output_path: None,
        }
    }

    pub fn parse_acquisition_report(path: &Path) -> Result<AcquisitionReport, ParserError> {
        let data = std::fs::read(path)?;

        if let Ok(report) = serde_json::from_slice::<AcquisitionReport>(&data) {
            return Ok(report);
        }

        if let Ok(report) = serde_yaml::from_slice::<AcquisitionReport>(&data) {
            return Ok(report);
        }

        Ok(AcquisitionReport {
            case_number: path.file_name().map(|n| n.to_string_lossy().to_string()),
            examiner: None,
            evidence_number: None,
            description: None,
            acquisitions: vec![],
            total_size: 0,
            total_files: 0,
            total_partitions: 0,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustody {
    pub evidence_path: String,
    pub sha256_hash: String,
    pub timestamp: i64,
    pub acquired_by: String,
    pub tool_version: Option<String>,
    pub platform: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdbAcquisitionConfig {
    pub target_device: Option<String>,
    pub acquisition_type: AdbAcquisitionType,
    pub include_data: bool,
    pub include_system: bool,
    pub include_sdcard: bool,
    pub backup_apps: Vec<String>,
    pub pull_paths: Vec<String>,
    pub compressed: bool,
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdbAcquisitionType {
    Logical,
    Physical,
    Root,
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosAcquisitionConfig {
    pub target_device: Option<String>,
    pub acquisition_type: IosAcquisitionType,
    pub jailbreak_required: bool,
    pub checkm8_available: bool,
    pub backup_password: Option<String>,
    pub include_keychain: bool,
    pub include_photos: bool,
    pub include_messages: bool,
    pub include_location: bool,
    pub include_health: bool,
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphCollectionConfig {
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub use_device_code_flow: bool,
    pub scopes: Vec<String>,
    pub endpoints: Vec<String>,
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IosAcquisitionType {
    Logical,
    Physical,
    Cloud,
    Checkm8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionProgress {
    pub phase: String,
    pub progress_percent: f32,
    pub current_item: Option<String>,
    pub items_processed: i64,
    pub total_items: i64,
    pub bytes_transferred: i64,
    pub total_bytes: i64,
    pub started_at: i64,
    pub estimated_completion: Option<i64>,
}

impl Default for AcquisitionProgress {
    fn default() -> Self {
        Self {
            phase: "Initializing".to_string(),
            progress_percent: 0.0,
            current_item: None,
            items_processed: 0,
            total_items: 0,
            bytes_transferred: 0,
            total_bytes: 0,
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            estimated_completion: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiskImage {
    pub image_path: Option<String>,
    pub image_type: Option<String>,
    pub tool: Option<String>,
    pub size: i64,
    pub sector_size: Option<i32>,
    pub hash_md5: Option<String>,
    pub hash_sha1: Option<String>,
    pub hash_sha256: Option<String>,
    pub is_compressed: bool,
    pub is_encrypted: bool,
    pub is_split: bool,
    pub split_count: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LiveAcquisition {
    pub target: Option<String>,
    pub target_type: Option<String>,
    pub memory_dump: bool,
    pub pagefile: bool,
    pub hiberfil: bool,
    pub registry: bool,
    pub process_dump: bool,
    pub network_capture: bool,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub tool: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub container_type: Option<String>,
    pub contains: Vec<String>,
    pub partition_count: i32,
    pub volume_count: i32,
    pub file_system: Option<String>,
    pub offset: Option<i64>,
    pub size: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcquisitionReport {
    pub case_number: Option<String>,
    pub examiner: Option<String>,
    pub evidence_number: Option<String>,
    pub description: Option<String>,
    pub acquisitions: Vec<AcquisitionEntry>,
    pub total_size: i64,
    pub total_files: i64,
    pub total_partitions: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcquisitionEntry {
    pub source: Option<String>,
    pub destination: Option<String>,
    pub acquisition_type: Option<String>,
    pub status: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub size: i64,
    pub hash: Option<String>,
}

impl Default for AcquisitionParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for AcquisitionParser {
    fn name(&self) -> &str {
        "Acquisition"
    }

    fn artifact_type(&self) -> &str {
        "acquisition"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            ".e01",
            ".aff",
            ".vmdk",
            ".vhd",
            ".vhdx",
            "acquisition",
            "evidence",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() > 0 {
            let container_type = if path.to_string_lossy().ends_with(".e01") {
                Some("E01".to_string())
            } else if path.to_string_lossy().ends_with(".aff") {
                Some("AFF".to_string())
            } else if path.to_string_lossy().ends_with(".vmdk") {
                Some("VMDK".to_string())
            } else if path.to_string_lossy().ends_with(".vhd")
                || path.to_string_lossy().ends_with(".vhdx")
            {
                Some("VHD".to_string())
            } else {
                Some("Unknown".to_string())
            };

            let container = ContainerInfo {
                container_type,
                contains: vec![],
                partition_count: 0,
                volume_count: 0,
                file_system: None,
                offset: None,
                size: data.len() as i64,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "acquisition".to_string(),
                description: "Disk/container acquisition".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&container).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}
