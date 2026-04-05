use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Windows ESE (Extensible Storage Engine) Database Parser
///
/// ESE (Jet Blue) is the database engine used by:
///   - Windows Search Index (Windows.edb)
///   - SRUM (SRU/SRUDB.dat)
///   - BITS job queue (qmgr0.dat, qmgr1.dat)
///   - Internet Explorer WebCache (WebCacheV01.dat)
///   - Exchange Server (priv1.edb, pub1.edb)
///   - Active Directory (ntds.dit)
///   - Windows Mail (WindowsMail.edb)
///   - Cortana (CortanaCoreDb.dat)
///
/// Format: Binary database with pages, B-tree indices, tagged data columns.
/// Header starts at offset 0 with "magic" and database signature.
///
/// Forensic value: ESE databases contain critical evidence:
///   - Windows.edb: Full-text content of files, emails, messages — even after deletion
///   - SRUM: Complete application usage and network data
///   - WebCache: IE/Edge browsing data with timestamps
///   - ntds.dit: Active Directory domain password hashes
pub struct EseParser;

impl Default for EseParser {
    fn default() -> Self {
        Self::new()
    }
}

impl EseParser {
    pub fn new() -> Self {
        Self
    }
}

/// ESE database signature at offset 4
const ESE_SIGNATURE: u32 = 0x89ABCDEF;

/// ESE header magic bytes
const _ESE_MAGIC_OFFSET: usize = 4;

#[derive(Debug, Serialize, Deserialize)]
pub struct EseDatabaseInfo {
    pub database_type: String,
    pub file_size: usize,
    pub page_size: Option<u32>,
    pub database_state: Option<String>,
    pub creation_time: Option<i64>,
    pub signature: Option<String>,
    pub version: Option<u32>,
    pub table_count_estimate: Option<usize>,
    pub forensic_note: String,
}

impl ArtifactParser for EseParser {
    fn name(&self) -> &str {
        "Windows ESE Database Parser"
    }

    fn artifact_type(&self) -> &str {
        "ese_database"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "Windows.edb",
            "WebCacheV01.dat",
            "WebCacheV24.dat",
            "spartan.edb",
            "CortanaCoreDb.dat",
            "ntds.dit",
            "WindowsMail.edb",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let filename_lower = filename.to_lowercase();

        if data.len() < 668 {
            return Ok(artifacts);
        }

        // Validate ESE header
        // ESE database header format:
        // Offset 0: checksum (4 bytes)
        // Offset 4: signature (4 bytes) — typically 0x89ABCDEF
        // Offset 8: file format version (4 bytes)
        // Offset 236: page size (4 bytes)
        // Offset 344: database state (4 bytes)
        // Offset 588: creation time FILETIME (8 bytes)

        let signature = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        // ESE databases also have a "magic" at specific offset patterns
        let is_ese = signature == ESE_SIGNATURE
            || (data.len() > 4096 && &data[4..8] != b"\x00\x00\x00\x00")
            || filename_lower.ends_with(".edb")
            || filename_lower == "ntds.dit"
            || filename_lower.contains("webcache");

        if !is_ese {
            return Ok(artifacts);
        }

        let page_size = if data.len() > 240 {
            Some(u32::from_le_bytes([data[236], data[237], data[238], data[239]]))
        } else {
            None
        };

        let db_state_code = if data.len() > 348 {
            Some(u32::from_le_bytes([data[344], data[345], data[346], data[347]]))
        } else {
            None
        };

        let database_state = db_state_code.map(|code| {
            match code {
                1 => "JustCreated",
                2 => "DirtyShutdown",
                3 => "CleanShutdown",
                4 => "BeingConverted",
                5 => "ForceDetach",
                _ => "Unknown",
            }
            .to_string()
        });

        let version = if data.len() > 12 {
            Some(u32::from_le_bytes([data[8], data[9], data[10], data[11]]))
        } else {
            None
        };

        // Determine database purpose from filename
        let (database_type, forensic_note) = match filename_lower.as_str() {
            s if s.contains("windows.edb") => (
                "Windows Search Index".to_string(),
                "Contains full-text search data for files, emails, and messages. \
                 Content persists even after source files are deleted. \
                 Critical for recovering deleted evidence."
                    .to_string(),
            ),
            s if s.contains("webcache") => (
                "Internet Explorer/Edge WebCache".to_string(),
                "Contains browsing history, cookies, download records, and DOM storage \
                 for Internet Explorer and legacy Edge. Timestamps and URL data."
                    .to_string(),
            ),
            "ntds.dit" => (
                "Active Directory Database".to_string(),
                "Contains Active Directory objects including user accounts and password hashes. \
                 CRITICAL: Password hashes can be extracted with tools like secretsdump. \
                 Access to this file indicates potential domain compromise (T1003.003)."
                    .to_string(),
            ),
            s if s.contains("cortana") => (
                "Cortana Database".to_string(),
                "Contains Cortana queries, reminders, and interaction history.".to_string(),
            ),
            s if s.contains("spartan") => (
                "Edge Browser Database".to_string(),
                "Microsoft Edge (Spartan) browsing data.".to_string(),
            ),
            s if s.contains("windowsmail") => (
                "Windows Mail Database".to_string(),
                "Contains Windows Mail/Calendar data.".to_string(),
            ),
            _ => (
                "ESE Database".to_string(),
                "Extensible Storage Engine database detected.".to_string(),
            ),
        };

        let info = EseDatabaseInfo {
            database_type: database_type.clone(),
            file_size: data.len(),
            page_size,
            database_state: database_state.clone(),
            creation_time: None,
            signature: Some(format!("0x{:08X}", signature)),
            version,
            table_count_estimate: page_size
                .filter(|&ps| ps > 0)
                .map(|ps| data.len() / ps as usize),
            forensic_note: forensic_note.clone(),
        };

        let mut desc = format!(
            "ESE Database: {} ({}, {} bytes, state: {})",
            database_type,
            filename,
            data.len(),
            database_state.as_deref().unwrap_or("unknown"),
        );

        if filename_lower == "ntds.dit" {
            desc.push_str(" [CRITICAL — Active Directory password hashes (T1003.003)]");
        }
        if filename_lower.contains("windows.edb") {
            desc.push_str(" [Contains searchable content from deleted files]");
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ese_database".to_string(),
            description: desc,
            source_path: source.clone(),
            json_data: serde_json::to_value(&info).unwrap_or_default(),
        });

        // For Windows.edb, scan for table names in the page data
        if filename_lower.contains("windows.edb") || filename_lower.contains("webcache") {
            let tables = scan_for_table_names(data);
            if !tables.is_empty() {
                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "ese_tables".to_string(),
                    description: format!(
                        "ESE Tables [{}]: {}",
                        database_type,
                        tables.join(", "),
                    ),
                    source_path: source,
                    json_data: serde_json::json!({
                        "tables": tables,
                        "table_count": tables.len(),
                    }),
                });
            }
        }

        Ok(artifacts)
    }
}

/// Scan ESE database pages for table catalog entries
fn scan_for_table_names(data: &[u8]) -> Vec<String> {
    let mut tables = Vec::new();
    let known_tables = [
        "SystemIndex_Gthr",
        "SystemIndex_GthrPth",
        "SystemIndex_PropertyStore",
        "SystemIndex_PropertyStore_Hash",
        "MSysObjects",
        "MSysObjectsShadow",
        "Containers",
        "Container_",
        "HstsEntries",
        "AppRuntime",
        "AppTimeline",
        "NetworkUsage",
        "NetworkConnections",
        "EnergyUsage",
        "SruDbIdMapTable",
    ];

    let text = String::from_utf8_lossy(data);
    for table_name in &known_tables {
        if text.contains(table_name) && !tables.contains(&table_name.to_string()) {
            tables.push(table_name.to_string());
        }
    }

    tables
}
