use crate::sqlite_utils::{table_columns, table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::warn;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct WhatsAppFullParser;

impl WhatsAppFullParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatsAppMessageEntry {
    pub message_id: Option<String>,
    pub key_remote_jid: Option<String>,
    pub key_from_me: bool,
    pub key_id: Option<String>,
    pub sender: Option<String>,
    pub message: Option<String>,
    pub timestamp: Option<i64>,
    pub media_url: Option<String>,
    pub media_mime_type: Option<String>,
    pub media_size: Option<i64>,
    pub media_hash: Option<String>,
    pub thumb_image: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub status: Option<String>,
    pub readable_date: Option<String>,
    pub push_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatsAppChatEntry {
    pub jid: Option<String>,
    pub display_name: Option<String>,
    pub last_message: Option<String>,
    pub last_message_time: Option<i64>,
    pub unread_count: i32,
    pub is_archived: bool,
    pub is_muted: bool,
    pub mute_expiry: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatsAppContactEntry {
    pub jid: Option<String>,
    pub display_name: Option<String>,
    pub push_name: Option<String>,
    pub status: Option<String>,
    pub photo_id: Option<String>,
    pub is_blocked: bool,
}

impl Default for WhatsAppFullParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for WhatsAppFullParser {
    fn name(&self) -> &str {
        "WhatsApp Full"
    }

    fn artifact_type(&self) -> &str {
        "mobile_whatsapp_message"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["whatsapp", "msgstore", "wa.db", "com.whatsapp"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        match with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut artifacts = Vec::new();
            let mut handled_schema = false;

            handled_schema |= parse_whatsapp_messages_table(conn, path, &mut artifacts);
            handled_schema |= parse_whatsapp_message_table(conn, path, &mut artifacts);
            handled_schema |= parse_whatsapp_generic_messages_table(conn, path, &mut artifacts);

            if !handled_schema {
                warn!(
                    "[parser::whatsapp] no supported message schema found in {}",
                    path.display()
                );
            }

            Ok(artifacts)
        }) {
            Ok(artifacts) => Ok(artifacts),
            Err(e) => {
                warn!(
                    "[parser::whatsapp] sqlite parse failed for {}: {}",
                    path.display(),
                    e
                );
                Ok(Vec::new())
            }
        }
    }
}

fn parse_whatsapp_messages_table(
    conn: &rusqlite::Connection,
    path: &Path,
    out: &mut Vec<ParsedArtifact>,
) -> bool {
    if !table_exists(conn, "messages") {
        return false;
    }

    let current_required = [
        "key_id",
        "key_remote_jid",
        "key_from_me",
        "data",
        "timestamp",
        "media_url",
        "media_mime_type",
        "media_size",
        "media_hash",
        "latitude",
        "longitude",
        "status",
        "remote_resource",
    ];

    if has_columns(conn, "messages", &current_required) {
        let mut stmt = match conn.prepare(
            "SELECT key_id, key_remote_jid, key_from_me, data, timestamp, media_url, media_mime_type, media_size, media_hash, latitude, longitude, status, remote_resource FROM messages ORDER BY timestamp DESC LIMIT 10000",
        ) {
            Ok(stmt) => stmt,
            Err(e) => {
                warn!(
                    "[parser::whatsapp] failed preparing messages query for {}: {}",
                    path.display(),
                    e
                );
                return true;
            }
        };

        let rows = match stmt.query_map([], |row: &rusqlite::Row| {
            Ok(WhatsAppMessageEntry {
                message_id: row.get::<_, String>(0).ok(),
                key_remote_jid: row.get(1).ok(),
                key_from_me: row.get::<_, i32>(2).unwrap_or(0) != 0,
                key_id: row.get(0).ok(),
                sender: row.get(12).ok(),
                message: row.get(3).ok(),
                timestamp: row.get(4).ok(),
                media_url: row.get(5).ok(),
                media_mime_type: row.get(6).ok(),
                media_size: row.get(7).ok(),
                media_hash: row.get(8).ok(),
                thumb_image: None,
                latitude: row.get(9).ok(),
                longitude: row.get(10).ok(),
                status: row.get::<_, i32>(11).ok().map(map_status),
                readable_date: None,
                push_name: None,
            })
        }) {
            Ok(rows) => rows,
            Err(e) => {
                warn!(
                    "[parser::whatsapp] failed querying messages rows for {}: {}",
                    path.display(),
                    e
                );
                return true;
            }
        };

        for entry in rows.flatten() {
            out.push(build_whatsapp_artifact(path, entry));
        }

        return true;
    }

    let generic_required = ["id", "address", "date", "body", "type"];
    if !has_columns(conn, "messages", &generic_required) {
        warn!(
            "[parser::whatsapp] messages table in {} is missing required columns {:?}",
            path.display(),
            generic_required
        );
        return true;
    }

    let mut stmt = match conn.prepare(
        "SELECT id, address, date, body, type FROM messages ORDER BY date DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            warn!(
                "[parser::whatsapp] failed preparing generic messages query for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    let rows = match stmt.query_map([], |row: &rusqlite::Row| {
        Ok(WhatsAppMessageEntry {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            key_remote_jid: row.get::<_, String>(1).ok(),
            key_from_me: matches!(row.get::<_, i64>(4).ok(), Some(2)),
            key_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            sender: row.get::<_, String>(1).ok(),
            message: row.get(3).ok(),
            timestamp: row.get(2).ok(),
            media_url: None,
            media_mime_type: None,
            media_size: None,
            media_hash: None,
            thumb_image: None,
            latitude: None,
            longitude: None,
            status: row.get::<_, i64>(4).ok().map(|v| v.to_string()),
            readable_date: None,
            push_name: None,
        })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            warn!(
                "[parser::whatsapp] failed querying generic messages rows for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    for entry in rows.flatten() {
        out.push(build_whatsapp_artifact(path, entry));
    }

    true
}

fn parse_whatsapp_message_table(
    conn: &rusqlite::Connection,
    path: &Path,
    out: &mut Vec<ParsedArtifact>,
) -> bool {
    if !table_exists(conn, "message") {
        return false;
    }

    let required = [
        "_id",
        "chat_row_id",
        "from_me",
        "text_data",
        "timestamp",
        "media_wa_type",
    ];
    if !has_columns(conn, "message", &required) {
        warn!(
            "[parser::whatsapp] message table in {} is missing required columns {:?}",
            path.display(),
            required
        );
        return true;
    }

    let mut stmt = match conn.prepare(
        "SELECT _id, chat_row_id, from_me, text_data, timestamp, media_wa_type FROM message ORDER BY timestamp DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            warn!(
                "[parser::whatsapp] failed preparing legacy message query for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    let rows = match stmt.query_map([], |row: &rusqlite::Row| {
        Ok(WhatsAppMessageEntry {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            key_remote_jid: row.get::<_, i64>(1).ok().map(|v| v.to_string()),
            key_from_me: row.get::<_, i32>(2).unwrap_or(0) != 0,
            key_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            sender: None,
            message: row.get(3).ok(),
            timestamp: row.get(4).ok(),
            media_url: None,
            media_mime_type: row.get::<_, i32>(5).ok().map(|v| v.to_string()),
            media_size: None,
            media_hash: None,
            thumb_image: None,
            latitude: None,
            longitude: None,
            status: None,
            readable_date: None,
            push_name: None,
        })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            warn!(
                "[parser::whatsapp] failed querying legacy message rows for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    for entry in rows.flatten() {
        out.push(build_whatsapp_artifact(path, entry));
    }

    true
}

fn parse_whatsapp_generic_messages_table(
    conn: &rusqlite::Connection,
    path: &Path,
    out: &mut Vec<ParsedArtifact>,
) -> bool {
    if !table_exists(conn, "Messages") {
        return false;
    }

    let required = ["id", "address", "date", "body", "type"];
    if !has_columns(conn, "Messages", &required) {
        warn!(
            "[parser::whatsapp] Messages table in {} is missing required columns {:?}",
            path.display(),
            required
        );
        return true;
    }

    let mut stmt = match conn.prepare(
        "SELECT id, address, date, body, type FROM Messages ORDER BY date DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            warn!(
                "[parser::whatsapp] failed preparing uppercase Messages query for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    let rows = match stmt.query_map([], |row: &rusqlite::Row| {
        Ok(WhatsAppMessageEntry {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            key_remote_jid: row.get::<_, String>(1).ok(),
            key_from_me: matches!(row.get::<_, i64>(4).ok(), Some(2)),
            key_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            sender: row.get::<_, String>(1).ok(),
            message: row.get(3).ok(),
            timestamp: row.get(2).ok(),
            media_url: None,
            media_mime_type: None,
            media_size: None,
            media_hash: None,
            thumb_image: None,
            latitude: None,
            longitude: None,
            status: row.get::<_, i64>(4).ok().map(|v| v.to_string()),
            readable_date: None,
            push_name: None,
        })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            warn!(
                "[parser::whatsapp] failed querying uppercase Messages rows for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    for entry in rows.flatten() {
        out.push(build_whatsapp_artifact(path, entry));
    }

    true
}

fn has_columns(conn: &rusqlite::Connection, table: &str, required: &[&str]) -> bool {
    let available = table_columns(conn, table)
        .into_iter()
        .map(|column| column.to_lowercase())
        .collect::<std::collections::HashSet<_>>();

    required
        .iter()
        .all(|column| available.contains(&column.to_lowercase()))
}

fn build_whatsapp_artifact(path: &Path, entry: WhatsAppMessageEntry) -> ParsedArtifact {
    let preview = entry
        .message
        .as_deref()
        .unwrap_or("")
        .chars()
        .take(80)
        .collect::<String>();
    let description = if preview.is_empty() {
        "WhatsApp message".to_string()
    } else {
        format!("WhatsApp message: {}", preview)
    };

    ParsedArtifact {
        timestamp: entry.timestamp,
        artifact_type: "mobile_whatsapp_message".to_string(),
        description,
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    }
}

fn map_status(status: i32) -> String {
    match status {
        0 => "received",
        4 => "waiting",
        5 => "server-ack",
        6 => "device-ack",
        8 => "read",
        _ => "unknown",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_zero_row_whatsapp_fixture_as_empty() {
        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("apps")
            .join("shield")
            .join("fixtures")
            .join("parsers")
            .join("mobile")
            .join("whatsapp_empty.db");
        let data = std::fs::read(&fixture_path).expect("fixture bytes");

        let artifacts = WhatsAppFullParser::new()
            .parse_file(&fixture_path, &data)
            .expect("whatsapp fixture parse should succeed");

        assert!(artifacts.is_empty());
    }
}
