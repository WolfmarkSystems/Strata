use crate::classification::mftparse::{parse_mft_records_from_path, MftRecord};
use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// MFT Timestomp Detection Parser
///
/// Compares $STANDARD_INFORMATION timestamps against $FILE_NAME timestamps
/// in MFT records to detect timestamp manipulation (timestomping).
///
/// Forensic value: Timestomping is MITRE ATT&CK T1070.006. Attackers use
/// tools like Timestomp.exe, SetMACE, or PowerShell to modify timestamps
/// and blend malicious files with legitimate system files. Detecting $SI/$FN
/// discrepancies is the primary method for identifying this anti-forensic
/// technique.
///
/// Detection logic:
///   - $SI modified < $FN modified: File was timestomped backward
///   - $SI created > $SI modified: Creation after modification (impossible normally)
///   - $SI timestamps all identical: Bulk timestomp tool artifact
///   - $FN modified << $SI modified: Significant discrepancy flags manipulation
pub struct MftTimestompParser;

impl Default for MftTimestompParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MftTimestompParser {
    pub fn new() -> Self {
        Self
    }
}

/// Threshold for timestamp discrepancy (seconds) — 1 hour
const TIMESTOMP_THRESHOLD_SECS: i64 = 3600;

/// Threshold for "far future" detection — 2 years from 2026
const FAR_FUTURE_EPOCH: i64 = 1_798_761_600; // ~2027-01-01

/// Threshold for "ancient" timestamps — before Windows NT era
const ANCIENT_EPOCH: i64 = 631_152_000; // 1990-01-01

#[derive(Debug, Serialize, Deserialize)]
pub struct TimestompAnomaly {
    pub record_number: u64,
    pub file_name: Option<String>,
    pub anomaly_type: String,
    pub severity: String,
    pub description: String,
    pub si_created: Option<i64>,
    pub si_modified: Option<i64>,
    pub si_mft_modified: Option<i64>,
    pub si_accessed: Option<i64>,
    pub fn_created: Option<i64>,
    pub fn_modified: Option<i64>,
    pub fn_mft_modified: Option<i64>,
    pub fn_accessed: Option<i64>,
    pub delta_seconds: Option<i64>,
    pub mitre_technique: String,
    pub is_deleted: bool,
    pub parent_record: Option<u64>,
}

impl ArtifactParser for MftTimestompParser {
    fn name(&self) -> &str {
        "MFT Timestomp Detector"
    }

    fn artifact_type(&self) -> &str {
        "anti_forensics"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["$MFT", "$mft", "MFT", "mft_dump", "mft.bin", "mft.raw"]
    }

    fn parse_file(&self, path: &Path, _data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        // Use the existing MFT parser to get records
        let records = parse_mft_records_from_path(path, 100_000);

        if records.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "anti_forensics".to_string(),
                description: format!(
                    "MFT Timestomp Analysis: No records parsed from {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                source_path: source,
                json_data: serde_json::json!({
                    "note": "MFT file detected but no records could be parsed for timestomp analysis."
                }),
            });
            return Ok(artifacts);
        }

        let total_records = records.len();
        let mut anomaly_count = 0;

        for record in &records {
            let anomalies = detect_timestomp_anomalies(record);
            for anomaly in anomalies {
                anomaly_count += 1;
                let severity_prefix = match anomaly.severity.as_str() {
                    "CRITICAL" => "[CRITICAL] ",
                    "HIGH" => "[HIGH] ",
                    "MEDIUM" => "[MEDIUM] ",
                    _ => "",
                };

                artifacts.push(ParsedArtifact {
                    timestamp: record.modified_time,
                    artifact_type: "timestomp_anomaly".to_string(),
                    description: format!(
                        "{}Timestomp: {} — {} (T1070.006)",
                        severity_prefix,
                        record.file_name.as_deref().unwrap_or("unknown"),
                        anomaly.description,
                    ),
                    source_path: source.clone(),
                    json_data: serde_json::to_value(&anomaly).unwrap_or_default(),
                });
            }
        }

        // Summary artifact
        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "timestomp_summary".to_string(),
            description: format!(
                "MFT Timestomp Analysis: {} anomalies in {} records",
                anomaly_count, total_records,
            ),
            source_path: source,
            json_data: serde_json::json!({
                "total_records_analyzed": total_records,
                "anomalies_detected": anomaly_count,
                "mitre_technique": "T1070.006",
                "technique_name": "Indicator Removal: Timestomp",
            }),
        });

        Ok(artifacts)
    }
}

fn detect_timestomp_anomalies(record: &MftRecord) -> Vec<TimestompAnomaly> {
    let mut anomalies = Vec::new();

    // Skip system files (records 0-26 are MFT metadata)
    if record.record_number <= 26 {
        return anomalies;
    }

    // First: use existing timestamp_conflicts from the MFT parser
    for conflict in &record.timestamp_conflicts {
        anomalies.push(TimestompAnomaly {
            record_number: record.record_number,
            file_name: record.file_name.clone(),
            anomaly_type: "si_fn_mismatch".to_string(),
            severity: "HIGH".to_string(),
            description: format!("$SI/$FN mismatch on {}", conflict),
            si_created: record.created_time,
            si_modified: record.modified_time,
            si_mft_modified: record.mft_modified_time,
            si_accessed: record.accessed_time,
            fn_created: None,
            fn_modified: None,
            fn_mft_modified: None,
            fn_accessed: None,
            delta_seconds: None,
            mitre_technique: "T1070.006".to_string(),
            is_deleted: record.deleted,
            parent_record: record.parent_record_number,
        });
    }

    // Additional detection: creation time after modification time
    if let (Some(created), Some(modified)) = (record.created_time, record.modified_time) {
        if created > modified + TIMESTOMP_THRESHOLD_SECS {
            anomalies.push(TimestompAnomaly {
                record_number: record.record_number,
                file_name: record.file_name.clone(),
                anomaly_type: "created_after_modified".to_string(),
                severity: "CRITICAL".to_string(),
                description: format!(
                    "Created ({}) after Modified ({}) — impossible without manipulation",
                    created, modified
                ),
                si_created: Some(created),
                si_modified: Some(modified),
                si_mft_modified: record.mft_modified_time,
                si_accessed: record.accessed_time,
                fn_created: None,
                fn_modified: None,
                fn_mft_modified: None,
                fn_accessed: None,
                delta_seconds: Some(created - modified),
                mitre_technique: "T1070.006".to_string(),
                is_deleted: record.deleted,
                parent_record: record.parent_record_number,
            });
        }
    }

    // Detection: all four $SI timestamps identical (bulk timestomp artifact)
    if let (Some(c), Some(m), Some(mft), Some(a)) = (
        record.created_time,
        record.modified_time,
        record.mft_modified_time,
        record.accessed_time,
    ) {
        if c == m && m == mft && mft == a && c != 0 {
            anomalies.push(TimestompAnomaly {
                record_number: record.record_number,
                file_name: record.file_name.clone(),
                anomaly_type: "all_timestamps_identical".to_string(),
                severity: "MEDIUM".to_string(),
                description: "All four $SI timestamps identical — bulk timestomp tool signature"
                    .to_string(),
                si_created: Some(c),
                si_modified: Some(m),
                si_mft_modified: Some(mft),
                si_accessed: Some(a),
                fn_created: None,
                fn_modified: None,
                fn_mft_modified: None,
                fn_accessed: None,
                delta_seconds: Some(0),
                mitre_technique: "T1070.006".to_string(),
                is_deleted: record.deleted,
                parent_record: record.parent_record_number,
            });
        }
    }

    // Detection: far future timestamps
    for (ts, name) in [
        (record.created_time, "created"),
        (record.modified_time, "modified"),
        (record.accessed_time, "accessed"),
    ] {
        if let Some(t) = ts {
            if t > FAR_FUTURE_EPOCH {
                anomalies.push(TimestompAnomaly {
                    record_number: record.record_number,
                    file_name: record.file_name.clone(),
                    anomaly_type: "future_timestamp".to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("{} timestamp is in the far future (epoch {})", name, t),
                    si_created: record.created_time,
                    si_modified: record.modified_time,
                    si_mft_modified: record.mft_modified_time,
                    si_accessed: record.accessed_time,
                    fn_created: None,
                    fn_modified: None,
                    fn_mft_modified: None,
                    fn_accessed: None,
                    delta_seconds: None,
                    mitre_technique: "T1070.006".to_string(),
                    is_deleted: record.deleted,
                    parent_record: record.parent_record_number,
                });
            }
        }
    }

    // Detection: pre-NT era timestamps on non-system files
    if let Some(created) = record.created_time {
        if created > 0 && created < ANCIENT_EPOCH && record.record_number > 26 {
            anomalies.push(TimestompAnomaly {
                record_number: record.record_number,
                file_name: record.file_name.clone(),
                anomaly_type: "ancient_timestamp".to_string(),
                severity: "MEDIUM".to_string(),
                description: format!(
                    "Created timestamp predates Windows NT era (epoch {})",
                    created
                ),
                si_created: Some(created),
                si_modified: record.modified_time,
                si_mft_modified: record.mft_modified_time,
                si_accessed: record.accessed_time,
                fn_created: None,
                fn_modified: None,
                fn_mft_modified: None,
                fn_accessed: None,
                delta_seconds: None,
                mitre_technique: "T1070.006".to_string(),
                is_deleted: record.deleted,
                parent_record: record.parent_record_number,
            });
        }
    }

    anomalies
}
