use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{
    list_tables, quote_identifier, table_columns, with_sqlite_connection,
};
use regex::Regex;
use rusqlite::types::ValueRef;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

pub struct UsageStatsParser;

impl UsageStatsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidUsageStatsEntry {
    pub source_kind: String,
    pub package_name: Option<String>,
    pub timestamp: Option<i64>,
    pub duration_ms: Option<i64>,
    pub event_type: Option<String>,
    pub standby_bucket: Option<i32>,
    pub details: Option<String>,
}

impl Default for UsageStatsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for UsageStatsParser {
    fn name(&self) -> &str {
        "Android UsageStats & Digital Wellbeing"
    }

    fn artifact_type(&self) -> &str {
        "android_usagestats"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "usagestats",
            "wellbeing",
            "digitalwellbeing",
            "app_usage",
            "app_timer",
            "usagehistory",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        if data.is_empty() {
            return Ok(artifacts);
        }

        let path_lower = path.to_string_lossy().to_ascii_lowercase();
        let likely_usage_file = path_lower.contains("usagestats")
            || path_lower.contains("wellbeing")
            || path_lower.contains("digitalwellbeing")
            || path_lower.contains("usage")
            || path_lower.contains("app_timer");

        if likely_usage_file {
            parse_usagestats_xml(path, data, &mut artifacts);
            parse_usagestats_binary(path, data, &mut artifacts);
        }

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut parsed = Vec::new();
            parse_digital_wellbeing_sqlite(conn, path, &mut parsed);
            Ok(parsed)
        });
        if let Ok(mut parsed) = sqlite_result {
            artifacts.append(&mut parsed);
        }

        dedupe_artifacts(&mut artifacts);
        Ok(artifacts)
    }
}

fn parse_usagestats_xml(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let text = String::from_utf8_lossy(data);
    if !(text.contains("<packages") || text.contains("<event") || text.contains("<usagestats")) {
        return;
    }

    for line in text.lines().take(200_000) {
        let trimmed = line.trim();
        if trimmed.starts_with("<package") {
            let package_name = extract_attr_any(trimmed, &["package", "name"]);
            let duration_ms = extract_attr_any(
                trimmed,
                &[
                    "timeActive",
                    "time_active",
                    "timeInForeground",
                    "totalTimeActive",
                ],
            )
            .and_then(|v| v.parse::<i64>().ok());
            let timestamp = extract_attr_any(
                trimmed,
                &[
                    "lastTimeActive",
                    "lastTimeUsed",
                    "last_time_used",
                    "timestamp",
                    "timeStamp",
                ],
            )
            .and_then(|v| v.parse::<i64>().ok())
            .map(normalize_epoch_to_secs);

            if package_name.is_none() && duration_ms.is_none() && timestamp.is_none() {
                continue;
            }

            let entry = AndroidUsageStatsEntry {
                source_kind: "usagestats_xml".to_string(),
                package_name: package_name.clone(),
                timestamp,
                duration_ms,
                event_type: Some("package_usage".to_string()),
                standby_bucket: extract_attr_any(trimmed, &["standbyBucket"])
                    .and_then(|v| v.parse::<i32>().ok()),
                details: None,
            };

            out.push(ParsedArtifact {
                timestamp: entry.timestamp,
                artifact_type: "android_usagestats".to_string(),
                description: format!(
                    "UsageStats package {}",
                    package_name.unwrap_or_else(|| "unknown".to_string())
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        } else if trimmed.starts_with("<event") {
            let package_name = extract_attr_any(trimmed, &["package", "name"]);
            let timestamp = extract_attr_any(trimmed, &["time", "timestamp", "timeStamp"])
                .and_then(|v| v.parse::<i64>().ok())
                .map(normalize_epoch_to_secs);
            let event_type = extract_attr_any(trimmed, &["type", "eventType"]);

            let entry = AndroidUsageStatsEntry {
                source_kind: "usagestats_xml".to_string(),
                package_name: package_name.clone(),
                timestamp,
                duration_ms: None,
                event_type: event_type.clone(),
                standby_bucket: None,
                details: None,
            };

            if entry.package_name.is_none() && entry.event_type.is_none() {
                continue;
            }

            out.push(ParsedArtifact {
                timestamp: entry.timestamp,
                artifact_type: "android_usagestats".to_string(),
                description: format!(
                    "UsageStats event {}",
                    package_name.unwrap_or_else(|| "unknown".to_string())
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }
    }
}

fn parse_usagestats_binary(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let regex = match Regex::new(r"(?:com|org|net|io)\.[A-Za-z0-9_][A-Za-z0-9._]{2,120}") {
        Ok(r) => r,
        Err(_) => return,
    };
    let text = String::from_utf8_lossy(data);
    let mut seen = HashSet::new();
    let file_ts = path
        .file_name()
        .and_then(|v| v.to_str())
        .and_then(extract_numeric_timestamp)
        .map(normalize_epoch_to_secs);

    for capture in regex.find_iter(&text).take(500) {
        let pkg = capture.as_str().to_string();
        if !seen.insert(pkg.clone()) {
            continue;
        }
        let entry = AndroidUsageStatsEntry {
            source_kind: "usagestats_protobuf_like".to_string(),
            package_name: Some(pkg.clone()),
            timestamp: file_ts,
            duration_ms: None,
            event_type: Some("package_reference".to_string()),
            standby_bucket: None,
            details: Some("Recovered from binary UsageStats payload".to_string()),
        };
        out.push(ParsedArtifact {
            timestamp: entry.timestamp,
            artifact_type: "android_usagestats".to_string(),
            description: format!("UsageStats protobuf package {}", pkg),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_digital_wellbeing_sqlite(
    conn: &rusqlite::Connection,
    path: &Path,
    out: &mut Vec<ParsedArtifact>,
) {
    for table in list_tables(conn) {
        let lower_table = table.to_ascii_lowercase();
        if !["usage", "wellbeing", "app", "event", "screen"]
            .iter()
            .any(|needle| lower_table.contains(needle))
        {
            continue;
        }

        let columns = table_columns(conn, &table);
        if columns.is_empty() {
            continue;
        }

        let package_col = find_column(
            &columns,
            &[
                "package_name",
                "package",
                "pkg",
                "app_package",
                "application",
                "app",
            ],
        );
        let ts_col = find_column(
            &columns,
            &[
                "timestamp",
                "time",
                "event_time",
                "last_time_used",
                "date",
                "start_time",
                "end_time",
                "day",
            ],
        );
        let duration_col = find_column(
            &columns,
            &[
                "total_time_foreground",
                "time_in_foreground",
                "duration",
                "screen_time",
                "usage_time",
                "total_time",
                "time_active",
            ],
        );
        let event_col = find_column(
            &columns,
            &["event_type", "event", "action", "state", "reason", "type"],
        );

        if package_col.is_none() && ts_col.is_none() && duration_col.is_none() {
            continue;
        }

        let mut selected = vec![format!("rowid as {}", quote_identifier("__rowid"))];
        if let Some(col) = &package_col {
            selected.push(quote_identifier(col));
        }
        if let Some(col) = &ts_col {
            selected.push(quote_identifier(col));
        }
        if let Some(col) = &duration_col {
            selected.push(quote_identifier(col));
        }
        if let Some(col) = &event_col {
            selected.push(quote_identifier(col));
        }

        let query = format!(
            "SELECT {} FROM {} LIMIT 5000",
            selected.join(", "),
            quote_identifier(&table)
        );
        let mut stmt = match conn.prepare(&query) {
            Ok(stmt) => stmt,
            Err(_) => continue,
        };

        let rows = stmt.query_map([], |row| {
            let mut idx = 1usize;
            let package_name = if package_col.is_some() {
                let v = row.get_ref(idx).ok().and_then(value_to_string);
                idx += 1;
                v
            } else {
                None
            };
            let timestamp = if ts_col.is_some() {
                let v = row
                    .get_ref(idx)
                    .ok()
                    .and_then(value_to_i64)
                    .map(normalize_epoch_to_secs);
                idx += 1;
                v
            } else {
                None
            };
            let duration_ms = if duration_col.is_some() {
                let v = row.get_ref(idx).ok().and_then(value_to_i64);
                idx += 1;
                v
            } else {
                None
            };
            let event_type = if event_col.is_some() {
                row.get_ref(idx).ok().and_then(value_to_string)
            } else {
                None
            };

            Ok(AndroidUsageStatsEntry {
                source_kind: "digital_wellbeing_sqlite".to_string(),
                package_name,
                timestamp,
                duration_ms,
                event_type,
                standby_bucket: None,
                details: Some(format!("table={table}")),
            })
        });

        let Ok(rows) = rows else {
            continue;
        };

        for entry in rows.flatten() {
            out.push(ParsedArtifact {
                timestamp: entry.timestamp,
                artifact_type: "android_usagestats".to_string(),
                description: format!(
                    "Digital Wellbeing {}",
                    entry
                        .package_name
                        .clone()
                        .unwrap_or_else(|| "entry".to_string())
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }
    }
}

fn extract_attr_any(line: &str, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(v) = extract_attr(line, key) {
            return Some(v);
        }
    }
    None
}

fn extract_attr(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = line.find(&needle)?;
    let rest = &line[start + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn find_column(columns: &[String], hints: &[&str]) -> Option<String> {
    for hint in hints {
        if let Some(found) = columns
            .iter()
            .find(|c| c.eq_ignore_ascii_case(hint) || c.to_ascii_lowercase().contains(hint))
        {
            return Some(found.clone());
        }
    }
    None
}

fn value_to_string(value: ValueRef<'_>) -> Option<String> {
    match value {
        ValueRef::Null => None,
        ValueRef::Text(v) => Some(String::from_utf8_lossy(v).to_string()),
        ValueRef::Integer(v) => Some(v.to_string()),
        ValueRef::Real(v) => Some(v.to_string()),
        ValueRef::Blob(v) => Some(format!("blob:{}bytes", v.len())),
    }
}

fn value_to_i64(value: ValueRef<'_>) -> Option<i64> {
    match value {
        ValueRef::Null => None,
        ValueRef::Integer(v) => Some(v),
        ValueRef::Real(v) => Some(v as i64),
        ValueRef::Text(v) => String::from_utf8_lossy(v).parse::<i64>().ok(),
        ValueRef::Blob(_) => None,
    }
}

fn extract_numeric_timestamp(value: &str) -> Option<i64> {
    let mut digits = String::new();
    for c in value.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        }
    }
    if digits.len() < 10 {
        return None;
    }
    digits.parse::<i64>().ok()
}

fn normalize_epoch_to_secs(value: i64) -> i64 {
    if value > 1_000_000_000_000_000_000 {
        value / 1_000_000_000
    } else if value > 10_000_000_000_000_000 {
        value / 1_000_000
    } else if value > 10_000_000_000 {
        value / 1_000
    } else {
        value
    }
}

fn dedupe_artifacts(artifacts: &mut Vec<ParsedArtifact>) {
    let mut seen = HashSet::new();
    artifacts.retain(|artifact| {
        let key = format!(
            "{}|{}|{}",
            artifact.artifact_type, artifact.description, artifact.source_path
        );
        seen.insert(key)
    });
}
