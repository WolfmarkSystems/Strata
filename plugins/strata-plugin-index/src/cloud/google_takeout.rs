use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct GoogleTakeoutParser;

impl GoogleTakeoutParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleTakeoutEntry {
    pub service: Option<String>,
    pub activity_type: Option<String>,
    pub actor: Option<String>,
    pub event_time: Option<i64>,
    pub title: Option<String>,
    pub details: Option<String>,
    pub source_file: Option<String>,
}

impl Default for GoogleTakeoutParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for GoogleTakeoutParser {
    fn name(&self) -> &str {
        "Google Takeout"
    }

    fn artifact_type(&self) -> &str {
        "cloud_export"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "takeout",
            "Takeout",
            "My Activity",
            "myactivity",
            "Google Takeout",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        parse_takeout_json(path, data, &mut artifacts);
        if artifacts.is_empty() {
            parse_takeout_csv(path, data, &mut artifacts);
        }

        if artifacts.is_empty() && !data.is_empty() {
            let entry = GoogleTakeoutEntry {
                service: Some(infer_service(path)),
                activity_type: None,
                actor: None,
                event_time: None,
                title: path.file_name().map(|v| v.to_string_lossy().to_string()),
                details: Some("Google Takeout artifact file".to_string()),
                source_file: Some(path.to_string_lossy().to_string()),
            };
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_export".to_string(),
                description: "Google Takeout artifact".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_takeout_json(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    if parse_location_history(path, &value, out) {
        return;
    }

    if let Some(entries) = value.as_array() {
        for entry in entries.iter().take(20000) {
            if let Some(artifact) = build_artifact_from_json(path, entry) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(items) = value.get("items").and_then(|v| v.as_array()) {
        for item in items.iter().take(20000) {
            if let Some(artifact) = build_artifact_from_json(path, item) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(artifact) = build_artifact_from_json(path, &value) {
        out.push(artifact);
    }
}

fn parse_location_history(
    path: &Path,
    value: &serde_json::Value,
    out: &mut Vec<ParsedArtifact>,
) -> bool {
    let is_location_file = path
        .to_string_lossy()
        .to_ascii_lowercase()
        .contains("records.json")
        || path
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("location history");

    let locations = value
        .get("locations")
        .and_then(|v| v.as_array())
        .or_else(|| value.get("Records").and_then(|v| v.as_array()));
    if let Some(locations) = locations {
        for loc in locations.iter().take(50000) {
            let lat = loc
                .get("latitudeE7")
                .and_then(|v| v.as_i64())
                .map(|v| v as f64 / 10_000_000.0);
            let lon = loc
                .get("longitudeE7")
                .and_then(|v| v.as_i64())
                .map(|v| v as f64 / 10_000_000.0);
            let ts = loc
                .get("timestampMs")
                .or_else(|| loc.get("timestamp"))
                .and_then(parse_iso_or_numeric_ts);
            let semantic = loc
                .get("activity")
                .or_else(|| loc.get("deviceTag"))
                .and_then(|v| v.as_str())
                .map(|v| v.to_string());

            let entry = GoogleTakeoutEntry {
                service: Some("Google Location History".to_string()),
                activity_type: Some("raw_location".to_string()),
                actor: None,
                event_time: ts,
                title: Some("Location ping".to_string()),
                details: Some(format!(
                    "lat={:?}, lon={:?}, semantic={:?}",
                    lat, lon, semantic
                )),
                source_file: Some(path.to_string_lossy().to_string()),
            };
            out.push(ParsedArtifact {
                timestamp: entry.event_time,
                artifact_type: "cloud_export".to_string(),
                description: "Google Takeout location record".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }
        return true;
    }

    if let Some(timeline) = value.get("timelineObjects").and_then(|v| v.as_array()) {
        for obj in timeline.iter().take(50000) {
            if let Some(place) = obj.get("placeVisit") {
                let loc = place.get("location");
                let lat = loc
                    .and_then(|v| v.get("latitudeE7"))
                    .and_then(|v| v.as_i64())
                    .map(|v| v as f64 / 10_000_000.0);
                let lon = loc
                    .and_then(|v| v.get("longitudeE7"))
                    .and_then(|v| v.as_i64())
                    .map(|v| v as f64 / 10_000_000.0);
                let ts = place
                    .get("duration")
                    .and_then(|v| v.get("startTimestamp"))
                    .and_then(parse_iso_or_numeric_ts);
                let entry = GoogleTakeoutEntry {
                    service: Some("Google Location History".to_string()),
                    activity_type: Some("semantic_place_visit".to_string()),
                    actor: None,
                    event_time: ts,
                    title: Some("Place Visit".to_string()),
                    details: Some(format!("lat={:?}, lon={:?}", lat, lon)),
                    source_file: Some(path.to_string_lossy().to_string()),
                };
                out.push(ParsedArtifact {
                    timestamp: entry.event_time,
                    artifact_type: "cloud_export".to_string(),
                    description: "Google semantic location (place visit)".to_string(),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(entry).unwrap_or_default(),
                });
            } else if let Some(activity) = obj.get("activitySegment") {
                let ts = activity
                    .get("duration")
                    .and_then(|v| v.get("startTimestamp"))
                    .and_then(parse_iso_or_numeric_ts);
                let entry = GoogleTakeoutEntry {
                    service: Some("Google Location History".to_string()),
                    activity_type: Some("semantic_activity_segment".to_string()),
                    actor: None,
                    event_time: ts,
                    title: Some("Activity Segment".to_string()),
                    details: Some(activity.to_string()),
                    source_file: Some(path.to_string_lossy().to_string()),
                };
                out.push(ParsedArtifact {
                    timestamp: entry.event_time,
                    artifact_type: "cloud_export".to_string(),
                    description: "Google semantic location (activity segment)".to_string(),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(entry).unwrap_or_default(),
                });
            }
        }
        return true;
    }

    is_location_file && !out.is_empty()
}

fn build_artifact_from_json(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let title = value
        .get("title")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .or_else(|| {
            value
                .get("header")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string())
        });
    let event_time = value
        .get("time")
        .and_then(parse_iso_or_numeric_ts)
        .or_else(|| value.get("eventTime").and_then(parse_iso_or_numeric_ts))
        .or_else(|| value.get("timestamp").and_then(parse_iso_or_numeric_ts));

    if title.is_none() && event_time.is_none() {
        return None;
    }

    let details = value
        .get("titleUrl")
        .and_then(|v| v.as_str())
        .map(|v| format!("titleUrl={v}"))
        .or_else(|| {
            value
                .get("description")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string())
        });

    let entry = GoogleTakeoutEntry {
        service: value
            .get("product")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string())
            .or_else(|| Some(infer_service(path))),
        activity_type: value
            .get("activityType")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        actor: value
            .get("actor")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        event_time,
        title: title.clone(),
        details,
        source_file: Some(path.to_string_lossy().to_string()),
    };

    Some(ParsedArtifact {
        timestamp: entry.event_time,
        artifact_type: "cloud_export".to_string(),
        description: format!(
            "Google Takeout {}",
            title.unwrap_or_else(|| "event".to_string())
        ),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    })
}

fn parse_takeout_csv(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut lines = text.lines();
    let Some(header_line) = lines.next() else {
        return;
    };

    let headers: Vec<String> = header_line
        .split(',')
        .map(|v| v.trim().trim_matches('"').to_ascii_lowercase())
        .collect();
    if headers.is_empty() {
        return;
    }

    let title_idx = headers
        .iter()
        .position(|h| h == "title" || h == "event")
        .unwrap_or(0);
    let time_idx = headers
        .iter()
        .position(|h| h == "time" || h == "eventtime" || h == "timestamp");
    let actor_idx = headers
        .iter()
        .position(|h| h == "actor" || h == "email" || h == "account");

    for line in lines.take(20000) {
        let cols: Vec<&str> = line.split(',').collect();
        if cols.is_empty() {
            continue;
        }
        let title = cols
            .get(title_idx)
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty());
        let event_time = time_idx
            .and_then(|idx| cols.get(idx).copied())
            .and_then(|v| parse_iso_or_numeric_text(v.trim().trim_matches('"')));
        let actor = actor_idx
            .and_then(|idx| cols.get(idx).copied())
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty());

        if title.is_none() && event_time.is_none() {
            continue;
        }

        let entry = GoogleTakeoutEntry {
            service: Some(infer_service(path)),
            activity_type: Some("csv".to_string()),
            actor,
            event_time,
            title: title.clone(),
            details: None,
            source_file: Some(path.to_string_lossy().to_string()),
        };

        out.push(ParsedArtifact {
            timestamp: entry.event_time,
            artifact_type: "cloud_export".to_string(),
            description: format!(
                "Google Takeout {}",
                title.unwrap_or_else(|| "event".to_string())
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn infer_service(path: &Path) -> String {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.contains("youtube") {
        "YouTube".to_string()
    } else if lower.contains("gmail") || lower.contains("mail") {
        "Gmail".to_string()
    } else if lower.contains("drive") {
        "Google Drive".to_string()
    } else if lower.contains("photos") {
        "Google Photos".to_string()
    } else if lower.contains("my activity") || lower.contains("myactivity") {
        "My Activity".to_string()
    } else {
        "Google".to_string()
    }
}

fn parse_iso_or_numeric_ts(value: &serde_json::Value) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        return Some(v);
    }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v).ok();
    }
    if let Some(v) = value.as_str() {
        return parse_iso_or_numeric_text(v);
    }
    None
}

fn parse_iso_or_numeric_text(value: &str) -> Option<i64> {
    if let Ok(num) = value.parse::<i64>() {
        return Some(num);
    }
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.timestamp())
}
