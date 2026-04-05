use crate::sqlite_utils::{list_tables, quote_identifier, table_columns, with_sqlite_connection};
use rusqlite::types::ValueRef;
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct ThirdPartyMobileAppsParser;

impl ThirdPartyMobileAppsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThirdPartyMessageEntry {
    pub app: String,
    pub conversation_id: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub text: Option<String>,
    pub timestamp: Option<i64>,
    pub media_path: Option<String>,
    pub source_kind: String,
}

impl Default for ThirdPartyMobileAppsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for ThirdPartyMobileAppsParser {
    fn name(&self) -> &str {
        "Mobile Third-Party Apps (Snapchat/TikTok/IG/Messenger/Threema/Wickr)"
    }

    fn artifact_type(&self) -> &str {
        "mobile_app_chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "snapchat",
            "tiktok",
            "instagram",
            "messenger",
            "threema",
            "wickr",
            "leveldb",
            "chat",
            "message",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        if data.is_empty() {
            return Ok(artifacts);
        }

        let app = detect_app(path);
        if app == "unknown" {
            return Ok(artifacts);
        }

        parse_json(path, app, data, &mut artifacts);
        parse_leveldb_like(path, app, data, &mut artifacts);

        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut parsed = Vec::new();
            parse_sqlite(conn, path, app, &mut parsed);
            Ok(parsed)
        });
        if let Ok(mut parsed) = sqlite_result {
            artifacts.append(&mut parsed);
        }

        Ok(artifacts)
    }
}

fn detect_app(path: &Path) -> &'static str {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.contains("snapchat") || lower.contains("com.snapchat") {
        "snapchat"
    } else if lower.contains("tiktok") || lower.contains("musically") {
        "tiktok"
    } else if lower.contains("instagram") || lower.contains("com.instagram") {
        "instagram"
    } else if lower.contains("messenger") || lower.contains("com.facebook.orca") {
        "messenger"
    } else if lower.contains("threema") {
        "threema"
    } else if lower.contains("wickr") {
        "wickr"
    } else {
        "unknown"
    }
}

fn parse_json(path: &Path, app: &str, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    if let Some(items) = value.as_array() {
        for item in items.iter().take(20_000) {
            if let Some(artifact) = message_from_json(path, app, item) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(messages) = value.get("messages").and_then(|v| v.as_array()) {
        for msg in messages.iter().take(20_000) {
            if let Some(artifact) = message_from_json(path, app, msg) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(artifact) = message_from_json(path, app, &value) {
        out.push(artifact);
    }
}

fn parse_leveldb_like(path: &Path, app: &str, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let text = String::from_utf8_lossy(data);
    let mut emitted = 0usize;
    for line in text.lines().take(50_000) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !(trimmed.contains("message")
            || trimmed.contains("chat")
            || trimmed.contains("sender")
            || trimmed.contains("recipient"))
        {
            continue;
        }
        let entry = ThirdPartyMessageEntry {
            app: app.to_string(),
            conversation_id: None,
            sender: None,
            recipient: None,
            text: Some(trimmed.chars().take(500).collect()),
            timestamp: None,
            media_path: None,
            source_kind: "leveldb_text".to_string(),
        };
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "mobile_app_chat".to_string(),
            description: format!("{} chat fragment", app),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
        emitted += 1;
        if emitted >= 1000 {
            break;
        }
    }
}

fn parse_sqlite(
    conn: &rusqlite::Connection,
    path: &Path,
    app: &str,
    out: &mut Vec<ParsedArtifact>,
) {
    for table in list_tables(conn) {
        let table_lower = table.to_ascii_lowercase();
        if !["message", "chat", "conversation", "thread", "event"]
            .iter()
            .any(|needle| table_lower.contains(needle))
        {
            continue;
        }

        let cols = table_columns(conn, &table);
        if cols.is_empty() {
            continue;
        }

        let conv_col = find_column(
            &cols,
            &["conversation_id", "chat_id", "thread_id", "dialog_id"],
        );
        let sender_col = find_column(&cols, &["sender", "from", "author", "user_id"]);
        let recipient_col = find_column(&cols, &["recipient", "to", "peer_id"]);
        let text_col = find_column(&cols, &["text", "body", "message", "content", "caption"]);
        let ts_col = find_column(&cols, &["timestamp", "time", "date", "created", "sent_at"]);
        let media_col = find_column(
            &cols,
            &[
                "media",
                "attachment",
                "file",
                "image",
                "video",
                "uri",
                "path",
            ],
        );

        if text_col.is_none() && media_col.is_none() {
            continue;
        }

        let mut select_cols = vec![format!("rowid as {}", quote_identifier("__rowid"))];
        if let Some(c) = &conv_col {
            select_cols.push(quote_identifier(c));
        }
        if let Some(c) = &sender_col {
            select_cols.push(quote_identifier(c));
        }
        if let Some(c) = &recipient_col {
            select_cols.push(quote_identifier(c));
        }
        if let Some(c) = &text_col {
            select_cols.push(quote_identifier(c));
        }
        if let Some(c) = &ts_col {
            select_cols.push(quote_identifier(c));
        }
        if let Some(c) = &media_col {
            select_cols.push(quote_identifier(c));
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
            let conversation_id = if conv_col.is_some() {
                let v = row.get_ref(idx).ok().and_then(value_to_string);
                idx += 1;
                v
            } else {
                None
            };
            let sender = if sender_col.is_some() {
                let v = row.get_ref(idx).ok().and_then(value_to_string);
                idx += 1;
                v
            } else {
                None
            };
            let recipient = if recipient_col.is_some() {
                let v = row.get_ref(idx).ok().and_then(value_to_string);
                idx += 1;
                v
            } else {
                None
            };
            let text = if text_col.is_some() {
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
            let media_path = if media_col.is_some() {
                row.get_ref(idx).ok().and_then(value_to_string)
            } else {
                None
            };

            Ok(ThirdPartyMessageEntry {
                app: app.to_string(),
                conversation_id,
                sender,
                recipient,
                text,
                timestamp,
                media_path,
                source_kind: format!("sqlite:{}", table),
            })
        });
        let Ok(rows) = rows else {
            continue;
        };

        for entry in rows.flatten() {
            out.push(ParsedArtifact {
                timestamp: entry.timestamp,
                artifact_type: "mobile_app_chat".to_string(),
                description: format!("{} message", app),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }
    }
}

fn message_from_json(path: &Path, app: &str, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let text = value
        .get("text")
        .or_else(|| value.get("body"))
        .or_else(|| value.get("message"))
        .or_else(|| value.get("content"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let media_path = value
        .get("media")
        .or_else(|| value.get("attachment"))
        .or_else(|| value.get("file"))
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                Some(s.to_string())
            } else {
                v.get("path")
                    .and_then(|x| x.as_str())
                    .map(|x| x.to_string())
            }
        });
    if text.is_none() && media_path.is_none() {
        return None;
    }
    let entry = ThirdPartyMessageEntry {
        app: app.to_string(),
        conversation_id: value
            .get("conversation_id")
            .or_else(|| value.get("chat_id"))
            .and_then(value_to_json_string),
        sender: value
            .get("sender")
            .or_else(|| value.get("from"))
            .and_then(value_to_json_string),
        recipient: value
            .get("recipient")
            .or_else(|| value.get("to"))
            .and_then(value_to_json_string),
        text,
        timestamp: value
            .get("timestamp")
            .or_else(|| value.get("time"))
            .and_then(value_to_json_i64)
            .map(normalize_epoch_to_secs),
        media_path,
        source_kind: "json".to_string(),
    };
    Some(ParsedArtifact {
        timestamp: entry.timestamp,
        artifact_type: "mobile_app_chat".to_string(),
        description: format!("{} message", app),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    })
}

fn find_column(cols: &[String], hints: &[&str]) -> Option<String> {
    for hint in hints {
        if let Some(c) = cols
            .iter()
            .find(|c| c.eq_ignore_ascii_case(hint) || c.to_ascii_lowercase().contains(hint))
        {
            return Some(c.clone());
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

fn value_to_json_string(value: &serde_json::Value) -> Option<String> {
    if let Some(v) = value.as_str() {
        return Some(v.to_string());
    }
    if let Some(v) = value.as_i64() {
        return Some(v.to_string());
    }
    if let Some(v) = value.as_u64() {
        return Some(v.to_string());
    }
    None
}

fn value_to_json_i64(value: &serde_json::Value) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        return Some(v);
    }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v).ok();
    }
    value.as_str().and_then(|v| v.parse::<i64>().ok())
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
