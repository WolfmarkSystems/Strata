use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// macOS Core Data epoch: 2001-01-01 00:00:00 UTC
const COREDATA_EPOCH_OFFSET: f64 = 978307200.0;

pub struct MacosKnowledgecParser;

impl MacosKnowledgecParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KnowledgecEntry {
    pub timestamp: Option<i64>,
    pub end_timestamp: Option<i64>,
    pub bundle_id: Option<String>,
    pub value: Option<String>,
    pub stream_name: Option<String>,
    pub duration: Option<i64>,
    pub device_id: Option<String>,
    pub uuid: Option<String>,
    pub entry_creation: Option<i64>,
}

impl Default for MacosKnowledgecParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Categorize KnowledgeC stream names into forensic categories
fn stream_to_artifact_type(stream: &str) -> &str {
    match stream {
        s if s.contains("/app/inFocus") || s.contains("/app/usage") => "application_usage",
        s if s.contains("/display") || s.contains("/device/isLocked") => "device_activity",
        s if s.contains("/safari") || s.contains("/webUsage") => "browser_activity",
        s if s.contains("/audio") || s.contains("/media") => "media_usage",
        s if s.contains("/location") => "location_activity",
        s if s.contains("/notification") => "notification",
        s if s.contains("/intent") || s.contains("/siri") => "user_interaction",
        s if s.contains("/pluggedIn") || s.contains("/battery") => "power_event",
        _ => "application_usage",
    }
}

/// Classify forensic significance of a stream name
fn stream_forensic_note(stream: &str) -> Option<&str> {
    match stream {
        s if s.contains("/app/inFocus") => Some("App in foreground — proves user interaction"),
        s if s.contains("/device/isLocked") => Some("Device lock/unlock — proves physical access"),
        s if s.contains("/safari/history") => Some("Safari browsing — user web activity timeline"),
        s if s.contains("/app/install") => Some("App installation event"),
        s if s.contains("/location/visit") => Some("Location visit — places user at location"),
        _ => None,
    }
}

impl ArtifactParser for MacosKnowledgecParser {
    fn name(&self) -> &str {
        "macOS KnowledgeC"
    }

    fn artifact_type(&self) -> &str {
        "application_usage"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["knowledgeC.db", "knowledgeC.db-wal"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();
            if table_exists(conn, "ZOBJECT") {
                // Primary query: full KnowledgeC extraction with device and source correlation
                let mut stmt = conn
                    .prepare(
                        "SELECT
                            ZOBJECT.ZSTARTDATE,
                            ZOBJECT.ZENDDATE,
                            ZOBJECT.ZVALUESTRING,
                            ZSOURCE.ZBUNDLEID,
                            ZOBJECT.ZSTREAMNAME,
                            ZOBJECT.ZENDDATE - ZOBJECT.ZSTARTDATE,
                            ZSOURCE.ZDEVICEID,
                            ZOBJECT.ZUUID,
                            ZOBJECT.ZCREATIONDATE
                         FROM ZOBJECT
                         LEFT JOIN ZSOURCE ON ZOBJECT.ZSOURCE = ZSOURCE.Z_PK
                         WHERE ZOBJECT.ZSTARTDATE IS NOT NULL
                         ORDER BY ZOBJECT.ZSTARTDATE DESC
                         LIMIT 10000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok(KnowledgecEntry {
                            timestamp: row
                                .get::<_, f64>(0)
                                .ok()
                                .map(|d| (d + COREDATA_EPOCH_OFFSET) as i64),
                            end_timestamp: row
                                .get::<_, f64>(1)
                                .ok()
                                .map(|d| (d + COREDATA_EPOCH_OFFSET) as i64),
                            value: row.get(2).ok(),
                            bundle_id: row.get(3).ok(),
                            stream_name: row.get(4).ok(),
                            duration: row.get::<_, f64>(5).ok().map(|d| d as i64),
                            device_id: row.get(6).ok(),
                            uuid: row.get(7).ok(),
                            entry_creation: row
                                .get::<_, f64>(8)
                                .ok()
                                .map(|d| (d + COREDATA_EPOCH_OFFSET) as i64),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let stream = row.stream_name.as_deref().unwrap_or("unknown");
                    let artifact_type = stream_to_artifact_type(stream).to_string();
                    let forensic_note = stream_forensic_note(stream);

                    let mut desc = format!(
                        "KnowledgeC: {} [{}]",
                        row.bundle_id.as_deref().unwrap_or("unknown"),
                        stream,
                    );
                    if let Some(val) = &row.value {
                        if !val.is_empty() {
                            desc.push_str(&format!(" = {}", val));
                        }
                    }
                    if let Some(dur) = row.duration {
                        if dur > 0 {
                            desc.push_str(&format!(" ({}s)", dur));
                        }
                    }
                    if let Some(note) = forensic_note {
                        desc.push_str(&format!(" [{}]", note));
                    }

                    let mut json = serde_json::to_value(&row).unwrap_or_default();
                    if let Some(note) = forensic_note {
                        json["forensic_note"] = serde_json::Value::String(note.to_string());
                    }

                    entries.push(ParsedArtifact {
                        timestamp: row.timestamp,
                        artifact_type,
                        description: desc,
                        source_path: path.to_string_lossy().to_string(),
                        json_data: json,
                    });
                }
            }
            Ok(entries)
        });

        if let Ok(mut entries) = sqlite_result {
            artifacts.append(&mut entries);
        }

        Ok(artifacts)
    }
}
