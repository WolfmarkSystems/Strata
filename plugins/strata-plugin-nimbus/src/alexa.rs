//! IOT-1 — Amazon Alexa ecosystem artifacts.
//!
//! Parses data the Amazon Alexa mobile app (iOS `com.amazon.echo` /
//! Android `com.amazon.dee.app`) leaves on phones: interaction
//! history JSON caches, paired-device inventories, and enabled-skill
//! lists. The real Alexa API surface is cloud-only, so the on-device
//! artifacts are whatever the app chose to cache — which is still a
//! great deal.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlexaArtifact {
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub utterance_text: Option<String>,
    pub response_text: Option<String>,
    pub audio_reference: Option<String>,
    pub user_speaker: Option<String>,
    pub device_location: Option<String>,
    pub account_email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlexaDevice {
    pub device_name: String,
    pub device_type: String,
    pub room: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlexaSkill {
    pub skill_name: String,
    pub enabled_at: Option<DateTime<Utc>>,
    pub vendor: Option<String>,
}

/// Parse an interaction-history JSON payload as cached by the mobile
/// app. Unknown shapes return empty.
pub fn parse_interaction_history(json: &str, account_email: Option<&str>) -> Vec<AlexaArtifact> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = match v.get("activities").and_then(|x| x.as_array()) {
        Some(a) => a,
        None => match v.as_array() {
            Some(a) => a,
            None => return Vec::new(),
        },
    };
    let mut out = Vec::new();
    for entry in arr {
        let ts_ms = entry
            .get("creationTimestamp")
            .or_else(|| entry.get("timestamp"))
            .and_then(|x| x.as_i64())
            .unwrap_or(0);
        let timestamp = Utc
            .timestamp_opt(ts_ms / 1000, 0)
            .single()
            .unwrap_or_else(unix_epoch);
        out.push(AlexaArtifact {
            artifact_type: entry
                .get("activityType")
                .and_then(|x| x.as_str())
                .unwrap_or("Interaction")
                .into(),
            timestamp,
            device_name: entry
                .get("sourceDeviceName")
                .and_then(|x| x.as_str())
                .map(String::from),
            device_type: entry
                .get("sourceDeviceType")
                .and_then(|x| x.as_str())
                .map(String::from),
            utterance_text: entry
                .get("description")
                .and_then(|x| x.get("summary"))
                .and_then(|x| x.as_str())
                .or_else(|| entry.get("utterance").and_then(|x| x.as_str()))
                .map(String::from),
            response_text: entry
                .get("responseText")
                .and_then(|x| x.as_str())
                .map(String::from),
            audio_reference: entry
                .get("audioReference")
                .and_then(|x| x.as_str())
                .map(String::from),
            user_speaker: entry
                .get("recognizedSpeaker")
                .and_then(|x| x.as_str())
                .map(String::from),
            device_location: entry.get("room").and_then(|x| x.as_str()).map(String::from),
            account_email: account_email.map(String::from),
        });
    }
    out
}

fn unix_epoch() -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::UNIX_EPOCH)
}

/// Parse the device-inventory SQLite cache. Schema probe-based so it
/// tolerates the Android-vs-iOS column-naming drift.
pub fn parse_device_inventory(conn: &Connection) -> Vec<AlexaDevice> {
    let Some(table) = first_table(conn, &["devices", "echo_devices", "paired_devices"]) else {
        return Vec::new();
    };
    let cols = col_names(conn, &table);
    let name =
        pick(&cols, &["name", "device_name", "account_name"]).unwrap_or_else(|| "name".into());
    let kind = pick(&cols, &["device_type", "type"]).unwrap_or_else(|| "device_type".into());
    let room = pick(&cols, &["room", "location"]);
    let serial = pick(&cols, &["serial_number", "serial", "dsn"]);
    let sql = format!(
        "SELECT {}, {}, {}, {} FROM {}",
        name,
        kind,
        room.clone().unwrap_or_else(|| "NULL".into()),
        serial.clone().unwrap_or_else(|| "NULL".into()),
        table
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Option<String>>(0)
                .unwrap_or(None)
                .unwrap_or_default(),
            r.get::<_, Option<String>>(1)
                .unwrap_or(None)
                .unwrap_or_default(),
            r.get::<_, Option<String>>(2).unwrap_or(None),
            r.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    rows.flatten()
        .map(|(name, kind, room, serial)| AlexaDevice {
            device_name: name,
            device_type: kind,
            room,
            serial_number: serial,
        })
        .collect()
}

pub fn parse_enabled_skills(json: &str) -> Vec<AlexaSkill> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = match v.get("skills").and_then(|x| x.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };
    arr.iter()
        .map(|s| AlexaSkill {
            skill_name: s.get("name").and_then(|x| x.as_str()).unwrap_or("").into(),
            enabled_at: s
                .get("enabledAt")
                .and_then(|x| x.as_str())
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|d| d.with_timezone(&Utc)),
            vendor: s
                .get("vendorName")
                .and_then(|x| x.as_str())
                .map(String::from),
        })
        .collect()
}

fn first_table(conn: &Connection, candidates: &[&str]) -> Option<String> {
    for t in candidates {
        let sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?1";
        if conn.query_row(sql, [t], |r| r.get::<_, String>(0)).is_ok() {
            return Some((*t).into());
        }
    }
    None
}

fn col_names(conn: &Connection, table: &str) -> Vec<String> {
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    stmt.query_map([], |r| r.get::<_, String>(1))
        .ok()
        .map(|r| r.flatten().collect())
        .unwrap_or_default()
}

fn pick(cols: &[String], candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if cols.iter().any(|x| x.eq_ignore_ascii_case(c)) {
            return Some((*c).into());
        }
    }
    None
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_interaction_history_entries() {
        let json = r#"{
            "activities":[
                {"activityType":"VoiceCommand",
                 "creationTimestamp":1700000000000,
                 "sourceDeviceName":"Kitchen Echo",
                 "sourceDeviceType":"EchoDot",
                 "description":{"summary":"play rain sounds"},
                 "responseText":"Playing Rain Sounds on Amazon Music.",
                 "recognizedSpeaker":"korbyn"}
            ]
        }"#;
        let arts = parse_interaction_history(json, Some("korbyn@example.com"));
        assert_eq!(arts.len(), 1);
        assert_eq!(arts[0].device_name.as_deref(), Some("Kitchen Echo"));
        assert_eq!(arts[0].utterance_text.as_deref(), Some("play rain sounds"));
        assert_eq!(arts[0].user_speaker.as_deref(), Some("korbyn"));
        assert_eq!(arts[0].account_email.as_deref(), Some("korbyn@example.com"));
    }

    #[test]
    fn malformed_json_returns_empty() {
        assert!(parse_interaction_history("not-json", None).is_empty());
        assert!(parse_interaction_history("{}", None).is_empty());
    }

    #[test]
    fn parses_device_inventory_from_sqlite() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE devices (name TEXT, device_type TEXT, room TEXT, serial_number TEXT);",
        )
        .expect("s");
        c.execute(
            "INSERT INTO devices VALUES ('Bedroom Dot', 'EchoDot', 'Bedroom', 'SN-1234')",
            [],
        )
        .expect("ins");
        let devs = parse_device_inventory(&c);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].room.as_deref(), Some("Bedroom"));
    }

    #[test]
    fn parses_enabled_skills() {
        let json = r#"{"skills":[
            {"name":"Weather","enabledAt":"2024-05-01T10:00:00Z","vendorName":"Amazon"},
            {"name":"MyBank","enabledAt":"2024-06-15T12:00:00Z","vendorName":"BigBank Inc"}
        ]}"#;
        let s = parse_enabled_skills(json);
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].skill_name, "MyBank");
        assert!(s[0].enabled_at.is_some());
    }

    #[test]
    fn missing_tables_return_empty() {
        let c = Connection::open_in_memory().expect("open");
        assert!(parse_device_inventory(&c).is_empty());
    }
}
