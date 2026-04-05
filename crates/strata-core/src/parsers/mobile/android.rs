use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct AndroidParser;

impl AndroidParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidBackupEntry {
    pub backup_type: String,
    pub category: String,
    pub path: String,
    pub size: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidDbEntry {
    pub table: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidAppEntry {
    pub package_name: Option<String>,
    pub app_name: Option<String>,
    pub version: Option<String>,
    pub install_time: Option<i64>,
    pub update_time: Option<i64>,
    pub data_dir: Option<String>,
    pub apk_path: Option<String>,
    pub is_system_app: bool,
    pub is_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidCallLogEntry {
    pub number: Option<String>,
    pub duration: i32,
    pub date: Option<i64>,
    pub type_: Option<String>,
    pub name: Option<String>,
    pub cached_number_type: Option<i32>,
    pub geocode: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidSmsEntry {
    pub address: Option<String>,
    pub body: Option<String>,
    pub date: Option<i64>,
    pub type_: Option<String>,
    pub read: bool,
    pub seen: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidMmsEntry {
    pub id: Option<i64>,
    pub date: Option<i64>,
    pub message_box: Option<i32>,
    pub message_type: Option<i32>,
    pub subject: Option<String>,
    pub read: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidDeviceEntry {
    pub android_id: Option<String>,
    pub model: Option<String>,
    pub manufacturer: Option<String>,
    pub brand: Option<String>,
    pub device: Option<String>,
    pub product: Option<String>,
    pub os_version: Option<String>,
    pub sdk_version: Option<i32>,
    pub security_patch: Option<String>,
    pub build_id: Option<String>,
}

impl Default for AndroidParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for AndroidParser {
    fn name(&self) -> &str {
        "Android"
    }

    fn artifact_type(&self) -> &str {
        "mobile"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "android",
            "data/data",
            "Android/data",
            "mmssms.db",
            "sms.db",
            "calllog.db",
            "calls.db",
            "contacts2.db",
            "com.android.providers.telephony",
            "com.android.providers.contacts",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let mut parsed_sqlite = false;

        if !data.is_empty() {
            let sqlite_result = with_sqlite_connection(path, data, |conn| {
                let mut local = Vec::new();
                parse_sms_table(conn, path, &mut local);
                parse_mms_table(conn, path, &mut local);
                parse_calllog_table(conn, path, &mut local);
                Ok(local)
            });

            if let Ok(mut parsed) = sqlite_result {
                if !parsed.is_empty() {
                    parsed_sqlite = true;
                    artifacts.append(&mut parsed);
                }
            }
        }

        if !parsed_sqlite && !data.is_empty() {
            let entry = AndroidAppEntry {
                package_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                app_name: None,
                version: None,
                install_time: None,
                update_time: None,
                data_dir: None,
                apk_path: Some(path.to_string_lossy().to_string()),
                is_system_app: false,
                is_enabled: true,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "mobile".to_string(),
                description: "Android application".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_sms_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "sms") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT _id, address, body, date, type, read, seen FROM sms ORDER BY date DESC LIMIT 5000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        let type_code: Option<i32> = row.get(4).ok();
        let type_name = type_code.map(map_sms_type);
        Ok(AndroidSmsEntry {
            address: row.get(1).ok(),
            body: row.get(2).ok(),
            date: row.get(3).ok(),
            type_: type_name,
            read: row.get::<_, i32>(5).unwrap_or(0) != 0,
            seen: row.get::<_, i32>(6).unwrap_or(0) != 0,
        })
    });

    let Ok(rows) = rows else {
        return;
    };

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.date,
            artifact_type: "mobile_sms".to_string(),
            description: format!(
                "Android SMS {}",
                entry
                    .address
                    .as_deref()
                    .filter(|v| !v.is_empty())
                    .unwrap_or("unknown")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_mms_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "pdu") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT _id, date, msg_box, m_type, sub, read FROM pdu ORDER BY date DESC LIMIT 3000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        Ok(AndroidMmsEntry {
            id: row.get(0).ok(),
            date: row.get(1).ok(),
            message_box: row.get(2).ok(),
            message_type: row.get(3).ok(),
            subject: row.get(4).ok(),
            read: row.get::<_, i32>(5).unwrap_or(0) != 0,
        })
    });

    let Ok(rows) = rows else {
        return;
    };

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.date,
            artifact_type: "mobile_mms".to_string(),
            description: format!("Android MMS id={}", entry.id.unwrap_or_default()),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_calllog_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "calls") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT number, duration, date, type, name, cached_number_type, geocoded_location FROM calls ORDER BY date DESC LIMIT 5000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        let type_code: Option<i32> = row.get(3).ok();
        let type_name = type_code.map(map_call_type);
        Ok(AndroidCallLogEntry {
            number: row.get(0).ok(),
            duration: row.get::<_, i32>(1).unwrap_or(0),
            date: row.get(2).ok(),
            type_: type_name,
            name: row.get(4).ok(),
            cached_number_type: row.get(5).ok(),
            geocode: row.get(6).ok(),
        })
    });

    let Ok(rows) = rows else {
        return;
    };

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.date,
            artifact_type: "mobile_call_log".to_string(),
            description: format!(
                "Android call {} ({})",
                entry
                    .number
                    .as_deref()
                    .filter(|v| !v.is_empty())
                    .unwrap_or("unknown"),
                entry.type_.clone().unwrap_or_else(|| "unknown".to_string())
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn map_sms_type(value: i32) -> String {
    match value {
        1 => "inbox",
        2 => "sent",
        3 => "draft",
        4 => "outbox",
        5 => "failed",
        6 => "queued",
        _ => "unknown",
    }
    .to_string()
}

fn map_call_type(value: i32) -> String {
    match value {
        1 => "incoming",
        2 => "outgoing",
        3 => "missed",
        4 => "voicemail",
        5 => "rejected",
        6 => "blocked",
        _ => "unknown",
    }
    .to_string()
}
