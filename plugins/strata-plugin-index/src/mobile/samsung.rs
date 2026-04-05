use crate::sqlite_utils::{list_tables, quote_identifier, table_columns, with_sqlite_connection};
use rusqlite::types::ValueRef;
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct SamsungParser;

impl SamsungParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SamsungRubidiumEntry {
    pub table: String,
    pub package_name: Option<String>,
    pub event: Option<String>,
    pub timestamp: Option<i64>,
    pub confidence: Option<f64>,
    pub details: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SamsungHealthEntry {
    pub table: String,
    pub metric_type: String,
    pub timestamp: Option<i64>,
    pub end_timestamp: Option<i64>,
    pub value: Option<f64>,
    pub unit: Option<String>,
    pub source: Option<String>,
}

impl Default for SamsungParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SamsungParser {
    fn name(&self) -> &str {
        "Samsung Artifacts (Rubidium + Health)"
    }

    fn artifact_type(&self) -> &str {
        "android_samsung"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "rubidium",
            "shealth",
            "samsunghealth",
            "health",
            "com.samsung.android",
            "com.sec.android",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        if data.is_empty() {
            return Ok(artifacts);
        }

        let path_lower = path.to_string_lossy().to_ascii_lowercase();
        let looks_relevant = path_lower.contains("samsung")
            || path_lower.contains("shealth")
            || path_lower.contains("health")
            || path_lower.contains("rubidium")
            || path_lower.contains("com.sec")
            || path_lower.ends_with(".db");
        if !looks_relevant {
            return Ok(artifacts);
        }

        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut parsed = Vec::new();
            parse_rubidium(conn, path, &mut parsed);
            parse_samsung_health(conn, path, &mut parsed);
            Ok(parsed)
        });
        if let Ok(mut parsed) = sqlite_result {
            artifacts.append(&mut parsed);
        }

        Ok(artifacts)
    }
}

fn parse_rubidium(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    for table in list_tables(conn) {
        let table_lower = table.to_ascii_lowercase();
        if !["rubidium", "interaction", "predict", "telemetry", "event"]
            .iter()
            .any(|needle| table_lower.contains(needle))
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
                "app_pkg",
                "app_package",
                "app",
            ],
        );
        let event_col = find_column(
            &columns,
            &[
                "event",
                "action",
                "event_type",
                "state",
                "prediction",
                "label",
            ],
        );
        let ts_col = find_column(
            &columns,
            &["timestamp", "time", "event_time", "ts", "date", "created"],
        );
        let confidence_col =
            find_column(&columns, &["confidence", "score", "probability", "weight"]);

        if package_col.is_none() && event_col.is_none() {
            continue;
        }

        let mut select_cols = vec![format!("rowid as {}", quote_identifier("__rowid"))];
        if let Some(col) = &package_col {
            select_cols.push(quote_identifier(col));
        }
        if let Some(col) = &event_col {
            select_cols.push(quote_identifier(col));
        }
        if let Some(col) = &ts_col {
            select_cols.push(quote_identifier(col));
        }
        if let Some(col) = &confidence_col {
            select_cols.push(quote_identifier(col));
        }

        let sql = format!(
            "SELECT {} FROM {} LIMIT 5000",
            select_cols.join(", "),
            quote_identifier(&table)
        );

        let mut stmt = match conn.prepare(&sql) {
            Ok(stmt) => stmt,
            Err(_) => continue,
        };
        let rows = stmt.query_map([], |row: &rusqlite::Row| {
            let mut idx = 1usize;
            let package_name = if package_col.is_some() {
                let v = row.get_ref(idx).ok().and_then(value_to_string);
                idx += 1;
                v
            } else {
                None
            };
            let event = if event_col.is_some() {
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
            let confidence = if confidence_col.is_some() {
                row.get_ref(idx).ok().and_then(value_to_f64)
            } else {
                None
            };

            Ok(SamsungRubidiumEntry {
                table: table.clone(),
                package_name,
                event,
                timestamp,
                confidence,
                details: Some("Samsung Rubidium telemetry".to_string()),
            })
        });

        let Ok(rows) = rows else {
            continue;
        };

        for entry in rows.flatten() {
            out.push(ParsedArtifact {
                timestamp: entry.timestamp,
                artifact_type: "android_samsung".to_string(),
                description: format!(
                    "Samsung Rubidium {}",
                    entry.event.clone().unwrap_or_else(|| "event".to_string())
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }
    }
}

fn parse_samsung_health(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    for table in list_tables(conn) {
        let table_lower = table.to_ascii_lowercase();
        if !["health", "step", "pedometer", "heart", "sleep", "exercise"]
            .iter()
            .any(|needle| table_lower.contains(needle))
        {
            continue;
        }

        let columns = table_columns(conn, &table);
        if columns.is_empty() {
            continue;
        }

        let ts_col = find_column(
            &columns,
            &[
                "timestamp",
                "time",
                "start_time",
                "start",
                "date",
                "created_at",
                "day",
            ],
        );
        let end_col = find_column(&columns, &["end_time", "end", "stop_time", "finish_time"]);
        let value_col = find_column(
            &columns,
            &[
                "step_count",
                "steps",
                "count",
                "heart_rate",
                "bpm",
                "distance",
                "calorie",
                "duration",
                "value",
            ],
        );
        let unit_col = find_column(&columns, &["unit", "metric_unit"]);
        let source_col = find_column(&columns, &["source", "device", "origin", "tracker"]);

        if ts_col.is_none() && value_col.is_none() {
            continue;
        }

        let metric_type = if table_lower.contains("step") || table_lower.contains("pedometer") {
            "steps"
        } else if table_lower.contains("heart") {
            "heart_rate"
        } else if table_lower.contains("sleep") {
            "sleep"
        } else if table_lower.contains("exercise") {
            "exercise"
        } else {
            "health_metric"
        };

        let mut select_cols = vec![format!("rowid as {}", quote_identifier("__rowid"))];
        if let Some(col) = &ts_col {
            select_cols.push(quote_identifier(col));
        }
        if let Some(col) = &end_col {
            select_cols.push(quote_identifier(col));
        }
        if let Some(col) = &value_col {
            select_cols.push(quote_identifier(col));
        }
        if let Some(col) = &unit_col {
            select_cols.push(quote_identifier(col));
        }
        if let Some(col) = &source_col {
            select_cols.push(quote_identifier(col));
        }

        let sql = format!(
            "SELECT {} FROM {} LIMIT 5000",
            select_cols.join(", "),
            quote_identifier(&table)
        );

        let mut stmt = match conn.prepare(&sql) {
            Ok(stmt) => stmt,
            Err(_) => continue,
        };
        let rows = stmt.query_map([], |row: &rusqlite::Row| {
            let mut idx = 1usize;
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
            let end_timestamp = if end_col.is_some() {
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
            let value = if value_col.is_some() {
                let v = row.get_ref(idx).ok().and_then(value_to_f64);
                idx += 1;
                v
            } else {
                None
            };
            let unit = if unit_col.is_some() {
                let v = row.get_ref(idx).ok().and_then(value_to_string);
                idx += 1;
                v
            } else {
                None
            };
            let source = if source_col.is_some() {
                row.get_ref(idx).ok().and_then(value_to_string)
            } else {
                None
            };

            Ok(SamsungHealthEntry {
                table: table.clone(),
                metric_type: metric_type.to_string(),
                timestamp,
                end_timestamp,
                value,
                unit,
                source,
            })
        });

        let Ok(rows) = rows else {
            continue;
        };

        for entry in rows.flatten() {
            out.push(ParsedArtifact {
                timestamp: entry.timestamp,
                artifact_type: "android_samsung".to_string(),
                description: format!("Samsung Health {}", entry.metric_type),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }
    }
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

fn value_to_f64(value: ValueRef<'_>) -> Option<f64> {
    match value {
        ValueRef::Null => None,
        ValueRef::Integer(v) => Some(v as f64),
        ValueRef::Real(v) => Some(v),
        ValueRef::Text(v) => String::from_utf8_lossy(v).parse::<f64>().ok(),
        ValueRef::Blob(_) => None,
    }
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
