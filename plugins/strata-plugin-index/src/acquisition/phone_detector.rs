use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct PhoneImageDetector;

impl PhoneImageDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect_format(&self, path: &Path, data: &[u8]) -> PhoneImageFormat {
        let path_str = path.to_string_lossy().to_lowercase();
        let _file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let mut format = PhoneImageFormat {
            format_type: None,
            tool: None,
            version: None,
            is_encrypted: path_str.contains("encrypted"),
            is_compressed: false,
            confidence: 0.0,
            detection_markers: Vec::new(),
        };

        if self.detect_encase(&path_str, data, &mut format) {
            return format;
        }
        if self.detect_ftk(&path_str, data, &mut format) {
            return format;
        }
        if self.detect_ewf(&path_str, data, &mut format) {
            return format;
        }
        if self.detect_graykey(&path_str, data, &mut format) {
            return format;
        }
        if self.detect_cellebrite(&path_str, data, &mut format) {
            return format;
        }
        if self.detect_itunes(&path_str, data, &mut format) {
            return format;
        }
        if self.detect_adb(&path_str, data, &mut format) {
            return format;
        }
        if self.detect_magnet(&path_str, data, &mut format) {
            return format;
        }

        format.format_type = Some("Unknown".to_string());
        format.confidence = 0.3;
        format
    }

    fn detect_encase(&self, path_str: &str, _data: &[u8], format: &mut PhoneImageFormat) -> bool {
        if path_str.contains("encase") || path_str.contains(".e01") || path_str.contains(".ewf") {
            format.format_type = Some("EnCase".to_string());
            format.tool = Some("EnCase".to_string());
            format.confidence = 0.95;
            format
                .detection_markers
                .push("EnCase/EWF signature".to_string());
            if path_str.contains(".e01") {
                format.detection_markers.push("E01 format".to_string());
            }
            return true;
        }
        false
    }

    fn detect_ftk(&self, path_str: &str, _data: &[u8], format: &mut PhoneImageFormat) -> bool {
        if path_str.contains("ftk")
            || path_str.contains("forensic toolkit")
            || path_str.contains(".ad1")
        {
            format.format_type = Some("FTK".to_string());
            format.tool = Some("Forensic Toolkit".to_string());
            format.confidence = 0.90;
            format.detection_markers.push("FTK signature".to_string());
            if path_str.contains(".ad1") {
                format
                    .detection_markers
                    .push("AD1 compressed archive".to_string());
            }
            return true;
        }
        false
    }

    fn detect_ewf(&self, path_str: &str, data: &[u8], format: &mut PhoneImageFormat) -> bool {
        if path_str.ends_with(".ewf")
            || path_str.ends_with(".e01")
            || path_str.contains("expert witness")
        {
            if data.len() >= 12 {
                let header = &data[..12];
                if header.starts_with(b"EVF") || header.starts_with(b"FTK") {
                    format.format_type = Some("EWF".to_string());
                    format.tool = Some("Expert Witness Format".to_string());
                    format.confidence = 0.98;
                    format.detection_markers.push("EWF header".to_string());
                    return true;
                }
            }
        }
        false
    }

    fn detect_graykey(&self, path_str: &str, _data: &[u8], format: &mut PhoneImageFormat) -> bool {
        if path_str.contains("graykey")
            || path_str.contains("gray key")
            || path_str.contains("grayshift")
        {
            format.format_type = Some("GrayKey".to_string());
            format.tool = Some("GrayKey".to_string());
            format.version = Some("4.x".to_string());
            format.confidence = 0.95;
            format
                .detection_markers
                .push("GrayKey extraction".to_string());

            if path_str.ends_with(".tar")
                || path_str.ends_with(".tar.gz")
                || path_str.ends_with(".tgz")
            {
                format.is_compressed = true;
                format.detection_markers.push("TAR archive".to_string());
            } else if path_str.ends_with(".zip") {
                format.is_compressed = true;
                format.detection_markers.push("ZIP archive".to_string());
            }
            return true;
        }
        false
    }

    fn detect_cellebrite(
        &self,
        path_str: &str,
        _data: &[u8],
        format: &mut PhoneImageFormat,
    ) -> bool {
        if path_str.contains("cellebrite") || path_str.contains("ufed") || path_str.contains("ufdr")
        {
            format.format_type = Some("Cellebrite UFED".to_string());
            format.tool = Some("Cellebrite UFED".to_string());
            format.version = Some("8.x".to_string());
            format.confidence = 0.95;
            format.detection_markers.push("Cellebrite UFED".to_string());

            if path_str.contains("physical") {
                format
                    .detection_markers
                    .push("Physical acquisition".to_string());
            } else if path_str.contains("logical") {
                format
                    .detection_markers
                    .push("Logical acquisition".to_string());
            } else if path_str.contains("cloud") {
                format
                    .detection_markers
                    .push("Cloud acquisition".to_string());
            }

            if path_str.ends_with(".zip") || path_str.ends_with(".ufdr.zip") {
                format.is_compressed = true;
                format.detection_markers.push("UFDR ZIP".to_string());
            }
            return true;
        }
        false
    }

    fn detect_itunes(&self, path_str: &str, _data: &[u8], format: &mut PhoneImageFormat) -> bool {
        if path_str.contains("itunes")
            || path_str.contains("iphone backup")
            || path_str.contains("ios backup")
            || path_str.contains("icloud")
            || path_str.contains("manifest.db")
        {
            format.format_type = Some("iTunes/iCloud Backup".to_string());
            format.tool = Some("Apple iTunes/iCloud".to_string());
            format.confidence = 0.90;
            format.detection_markers.push("iOS backup".to_string());

            if path_str.contains("manifest.plist") || path_str.contains("manifest.db") {
                format.detection_markers.push("Manifest file".to_string());
            }
            if path_str.contains("encrypted") || path_str.contains(".key") {
                format.is_encrypted = true;
                format
                    .detection_markers
                    .push("Encrypted backup".to_string());
            }
            return true;
        }
        false
    }

    fn detect_adb(&self, path_str: &str, _data: &[u8], format: &mut PhoneImageFormat) -> bool {
        if path_str.contains("adb")
            || path_str.contains("android backup")
            || path_str.contains("android data")
            || path_str.contains(".ab")
            || path_str.contains("data/data")
            || path_str.contains("data/user")
        {
            format.format_type = Some("Android ADB".to_string());
            format.tool = Some("Android Debug Bridge".to_string());
            format.confidence = 0.85;
            format.detection_markers.push("Android ADB".to_string());

            if path_str.contains("physical")
                || path_str.contains("system")
                || path_str.contains("data/data")
            {
                format
                    .detection_markers
                    .push("Physical acquisition".to_string());
            } else {
                format.detection_markers.push("Logical backup".to_string());
            }

            if path_str.ends_with(".ab") || path_str.ends_with(".zip") {
                format.is_compressed = true;
                format
                    .detection_markers
                    .push("Android Backup format".to_string());
            } else if path_str.ends_with(".tar")
                || path_str.ends_with(".tar.gz")
                || path_str.ends_with(".tgz")
            {
                format.is_compressed = true;
                format.detection_markers.push("TAR archive".to_string());
            }
            return true;
        }
        false
    }

    fn detect_magnet(&self, path_str: &str, _data: &[u8], format: &mut PhoneImageFormat) -> bool {
        if path_str.contains("magnet")
            || path_str.contains("axiom")
            || path_str.contains(".axiuiex")
        {
            format.format_type = Some("Magnet AXIOM".to_string());
            format.tool = Some("Magnet AXIOM".to_string());
            format.confidence = 0.90;
            format.detection_markers.push("Magnet AXIOM".to_string());

            if path_str.ends_with(".axiuiex") {
                format
                    .detection_markers
                    .push("AXIOM export file".to_string());
            }
            return true;
        }
        false
    }

    pub fn get_parser_pipeline(&self, format: &PhoneImageFormat) -> Vec<String> {
        let format_type = format.format_type.as_deref().unwrap_or("");

        match format_type {
            "GrayKey" => vec![
                "graykey".to_string(),
                "graykey_tar".to_string(),
                "keychain".to_string(),
                "ios_backup".to_string(),
                "ios_messages".to_string(),
                "ios_contacts".to_string(),
                "ios_location".to_string(),
            ],
            "Cellebrite UFED" => vec![
                "cellebrite".to_string(),
                "ufed".to_string(),
                "cellebrite_ufdr".to_string(),
                "ios_backup".to_string(),
                "ios_messages".to_string(),
                "android_backup".to_string(),
            ],
            "iTunes/iCloud Backup" => vec![
                "ios_backup".to_string(),
                "ios_messages".to_string(),
                "ios_contacts".to_string(),
                "ios_photos".to_string(),
                "ios_safari".to_string(),
                "ios_location".to_string(),
                "ios_health".to_string(),
            ],
            "Android ADB" => vec![
                "android".to_string(),
                "android_backup".to_string(),
                "adb".to_string(),
                "android_messages".to_string(),
                "android_contacts".to_string(),
                "whatsapp".to_string(),
                "signal".to_string(),
            ],
            "Magnet AXIOM" => vec![
                "axiom".to_string(),
                "magnet".to_string(),
                "phone_acquisition".to_string(),
                "ios_backup".to_string(),
                "android_backup".to_string(),
            ],
            "EnCase" | "EWF" => vec![
                "disk_image".to_string(),
                "partition".to_string(),
                "filesystem".to_string(),
                "carving".to_string(),
            ],
            "FTK" => vec![
                "ftk".to_string(),
                "ad1".to_string(),
                "disk_image".to_string(),
            ],
            _ => vec!["generic".to_string()],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhoneImageFormat {
    pub format_type: Option<String>,
    pub tool: Option<String>,
    pub version: Option<String>,
    pub is_encrypted: bool,
    pub is_compressed: bool,
    pub confidence: f32,
    pub detection_markers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionResult {
    pub format: PhoneImageFormat,
    pub device_info: Option<DeviceInfo>,
    pub extraction_info: Option<ExtractionInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_type: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub model: Option<String>,
    pub manufacturer: Option<String>,
    pub serial: Option<String>,
    pub imei: Option<String>,
    pub meid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractionInfo {
    pub extraction_type: Option<String>,
    pub extraction_time: Option<i64>,
    pub extractor_version: Option<String>,
    pub is_rooted: bool,
    pub is_jailbroken: bool,
    pub partition_count: i32,
}

impl Default for PhoneImageDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for PhoneImageDetector {
    fn name(&self) -> &str {
        "Phone Image Detector"
    }

    fn artifact_type(&self) -> &str {
        "acquisition"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "graykey",
            "grayshift",
            "cellebrite",
            "ufed",
            "ufdr",
            "itunes",
            "itunes backup",
            "iphone backup",
            "icloud",
            "adb",
            "android backup",
            "android data",
            "magnet",
            "axiom",
            ".axiuiex",
            ".e01",
            ".ewf",
            ".ad1",
            "encase",
            "ftk",
            "forensic toolkit",
            ".tar",
            ".tgz",
            ".zip",
            ".ab",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let format = self.detect_format(path, data);
        let pipeline = self.get_parser_pipeline(&format);

        let result = DetectionResult {
            format,
            device_info: None,
            extraction_info: None,
        };

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "acquisition".to_string(),
            description: format!(
                "Universal detection: {} (confidence: {:.0}%)",
                result.format.format_type.as_deref().unwrap_or("Unknown"),
                result.format.confidence * 100.0
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "detection": result,
                "parser_pipeline": pipeline,
            }),
        });

        Ok(artifacts)
    }
}
