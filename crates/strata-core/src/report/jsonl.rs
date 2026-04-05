use crate::timeline::TimelineEntry;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonlExportConfig {
    pub timesketch_compatible: bool,
    pub include_json_data: bool,
    pub max_entries: Option<usize>,
}

impl Default for JsonlExportConfig {
    fn default() -> Self {
        Self {
            timesketch_compatible: true,
            include_json_data: true,
            max_entries: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimesketchEntry {
    pub datetime: String,
    pub timestamp: i64,
    pub timestamp_desc: String,
    pub source: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_data: Option<serde_json::Value>,
}

pub struct JsonlExporter {
    config: JsonlExportConfig,
}

impl JsonlExporter {
    pub fn new(config: JsonlExportConfig) -> Self {
        Self { config }
    }

    pub fn export_timeline_jsonl(
        &self,
        timeline_db_path: &Path,
        output_path: &Path,
    ) -> anyhow::Result<usize> {
        use rusqlite::Connection;

        let conn = Connection::open(timeline_db_path)?;

        let output_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(output_path)?;

        let mut writer = BufWriter::new(output_file);

        let mut query = "SELECT id, timestamp, artifact_type, description, source_path, json_data, created_utc FROM timeline".to_string();
        if let Some(max) = self.config.max_entries {
            query.push_str(&format!(" ORDER BY id DESC LIMIT {}", max));
        } else {
            query.push_str(" ORDER BY id");
        }

        let mut stmt = conn.prepare(&query)?;
        let entries = stmt.query_map([], |row| {
            let json_str: String = row.get(5).unwrap_or_default();
            let json_data: serde_json::Value =
                serde_json::from_str(&json_str).unwrap_or(serde_json::json!({}));

            Ok(TimelineEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                artifact_type: row.get(2)?,
                description: row.get(3)?,
                source_path: row.get(4)?,
                json_data,
                created_utc: row.get(6)?,
            })
        })?;

        let mut count = 0;
        for entry_result in entries {
            let entry = entry_result?;

            if self.config.timesketch_compatible {
                let timesketch_entry = self.to_timesketch_entry(&entry);
                let json_line = serde_json::to_string(&timesketch_entry)?;
                writeln!(writer, "{}", json_line)?;
            } else {
                let json_line = serde_json::to_string(&entry)?;
                writeln!(writer, "{}", json_line)?;
            }

            count += 1;
        }

        writer.flush()?;
        Ok(count)
    }

    fn to_timesketch_entry(&self, entry: &TimelineEntry) -> TimesketchEntry {
        let datetime = entry
            .timestamp
            .map(|ts| {
                chrono::DateTime::from_timestamp_millis(ts)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| "".to_string())
            })
            .unwrap_or_default();

        let timestamp = entry.timestamp.unwrap_or(0);

        TimesketchEntry {
            datetime,
            timestamp,
            timestamp_desc: entry.artifact_type.clone(),
            source: "ForensicSuite".to_string(),
            message: entry.description.clone(),
            path: if entry.source_path.is_empty() {
                None
            } else {
                Some(entry.source_path.clone())
            },
            extra_data: if self.config.include_json_data && !entry.json_data.is_null() {
                Some(entry.json_data.clone())
            } else {
                None
            },
        }
    }

    pub fn stream_timeline_entries(
        &self,
        timeline_db_path: &Path,
        mut callback: impl FnMut(&TimelineEntry) -> bool,
    ) -> anyhow::Result<usize> {
        use rusqlite::Connection;

        let conn = Connection::open(timeline_db_path)?;

        let mut stmt = conn.prepare(
            "SELECT id, timestamp, artifact_type, description, source_path, json_data, created_utc FROM timeline ORDER BY id"
        )?;

        let entries = stmt.query_map([], |row| {
            let json_str: String = row.get(5).unwrap_or_default();
            let json_data: serde_json::Value =
                serde_json::from_str(&json_str).unwrap_or(serde_json::json!({}));

            Ok(TimelineEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                artifact_type: row.get(2)?,
                description: row.get(3)?,
                source_path: row.get(4)?,
                json_data,
                created_utc: row.get(6)?,
            })
        })?;

        let mut count = 0;
        for entry_result in entries {
            let entry = entry_result?;
            if !callback(&entry) {
                break;
            }
            count += 1;
        }

        Ok(count)
    }
}

pub fn export_timeline_jsonl(timeline_db_path: &Path, output_path: &Path) -> anyhow::Result<usize> {
    let exporter = JsonlExporter::new(JsonlExportConfig::default());
    exporter.export_timeline_jsonl(timeline_db_path, output_path)
}
