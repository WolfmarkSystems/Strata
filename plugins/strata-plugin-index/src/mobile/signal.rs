use crate::sqlite_utils::{table_columns, table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};
use tracing::warn;

pub struct SignalParser;

impl SignalParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalMessageEntry {
    pub message_id: Option<String>,
    pub conversation_id: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub body: Option<String>,
    pub timestamp: Option<i64>,
    pub received_timestamp: Option<i64>,
    pub is_read: bool,
    pub is_delivered: bool,
    pub is_sent: bool,
    pub is_successful: bool,
    pub attachments: Vec<String>,
    pub mentions: Vec<String>,
    pub quote: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalContactEntry {
    pub uuid: Option<String>,
    pub phone_number: Option<String>,
    pub name: Option<String>,
    pub avatar_path: Option<String>,
    pub color: Option<String>,
    pub is_blocked: bool,
    pub mute_until: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalGroupEntry {
    pub group_id: Option<String>,
    pub title: Option<String>,
    pub members: Vec<String>,
    pub avatar_path: Option<String>,
    pub timestamp: Option<i64>,
    pub is_archived: bool,
}

impl Default for SignalParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SignalParser {
    fn name(&self) -> &str {
        "Signal"
    }

    fn artifact_type(&self) -> &str {
        "mobile_signal_message"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "signal",
            "org.thoughtcrime.securesms",
            "signal.db",
            "db.sqlite",
            "signalbackup",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        match with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut artifacts = Vec::new();
            let mut handled_schema = false;

            handled_schema |= parse_signal_message_table(conn, path, &mut artifacts);
            handled_schema |= parse_signal_sms_table(conn, path, &mut artifacts);
            handled_schema |= parse_signal_generic_messages_table(conn, path, &mut artifacts);

            if !handled_schema {
                warn!(
                    "[parser::signal] no supported message schema found in {}",
                    path.display()
                );
            }

            Ok(artifacts)
        }) {
            Ok(artifacts) => Ok(artifacts),
            Err(e) => {
                warn!(
                    "[parser::signal] sqlite parse failed for {}: {}",
                    path.display(),
                    e
                );
                Ok(Vec::new())
            }
        }
    }
}

fn parse_signal_message_table(
    conn: &rusqlite::Connection,
    path: &Path,
    out: &mut Vec<ParsedArtifact>,
) -> bool {
    if !table_exists(conn, "message") {
        return false;
    }

    let required = [
        "_id",
        "thread_id",
        "body",
        "date_sent",
        "date_received",
        "type",
        "read",
    ];
    if !has_columns(conn, "message", &required) {
        warn!(
            "[parser::signal] message table in {} is missing required columns {:?}",
            path.display(),
            required
        );
        return true;
    }

    let mut stmt = match conn.prepare(
        "SELECT _id, thread_id, body, date_sent, date_received, type, read FROM message ORDER BY date_sent DESC LIMIT 5000",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            warn!(
                "[parser::signal] failed preparing message query for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    let rows = match stmt.query_map([], |row: &rusqlite::Row| {
        let msg_type = row.get::<_, i32>(5).unwrap_or(0);
        Ok(SignalMessageEntry {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            conversation_id: row.get::<_, i64>(1).ok().map(|v| v.to_string()),
            sender: None,
            recipient: None,
            body: row.get(2).ok(),
            timestamp: row.get(3).ok(),
            received_timestamp: row.get(4).ok(),
            is_read: row.get::<_, i32>(6).unwrap_or(0) != 0,
            is_delivered: matches!(msg_type, 4 | 5),
            is_sent: matches!(msg_type, 2..=5),
            is_successful: matches!(msg_type, 2 | 4 | 5),
            attachments: vec![],
            mentions: vec![],
            quote: None,
        })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            warn!(
                "[parser::signal] failed querying message rows for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    for entry in rows.flatten() {
        out.push(build_signal_artifact(path, entry));
    }

    true
}

fn parse_signal_sms_table(
    conn: &rusqlite::Connection,
    path: &Path,
    out: &mut Vec<ParsedArtifact>,
) -> bool {
    if !table_exists(conn, "sms") {
        return false;
    }

    let required = [
        "_id",
        "thread_id",
        "address",
        "body",
        "date",
        "read",
        "type",
    ];
    if !has_columns(conn, "sms", &required) {
        warn!(
            "[parser::signal] sms table in {} is missing required columns {:?}",
            path.display(),
            required
        );
        return true;
    }

    let mut stmt = match conn.prepare(
        "SELECT _id, thread_id, address, body, date, read, type FROM sms ORDER BY date DESC LIMIT 5000",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            warn!(
                "[parser::signal] failed preparing sms query for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    let rows = match stmt.query_map([], |row: &rusqlite::Row| {
        let msg_type = row.get::<_, i32>(6).unwrap_or(0);
        Ok(SignalMessageEntry {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            conversation_id: row.get::<_, i64>(1).ok().map(|v| v.to_string()),
            sender: row.get(2).ok(),
            recipient: None,
            body: row.get(3).ok(),
            timestamp: row.get(4).ok(),
            received_timestamp: None,
            is_read: row.get::<_, i32>(5).unwrap_or(0) != 0,
            is_delivered: msg_type == 2,
            is_sent: msg_type == 2,
            is_successful: msg_type == 2,
            attachments: vec![],
            mentions: vec![],
            quote: None,
        })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            warn!(
                "[parser::signal] failed querying sms rows for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    for entry in rows.flatten() {
        out.push(build_signal_artifact(path, entry));
    }

    true
}

fn parse_signal_generic_messages_table(
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
            "[parser::signal] Messages table in {} is missing required columns {:?}",
            path.display(),
            required
        );
        return true;
    }

    let mut stmt = match conn
        .prepare("SELECT id, address, date, body, type FROM Messages ORDER BY date DESC LIMIT 5000")
    {
        Ok(stmt) => stmt,
        Err(e) => {
            warn!(
                "[parser::signal] failed preparing generic Messages query for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    let rows = match stmt.query_map([], |row: &rusqlite::Row| {
        let msg_type = row.get::<_, i64>(4).ok();
        Ok(SignalMessageEntry {
            message_id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            conversation_id: row.get::<_, String>(1).ok(),
            sender: row.get::<_, String>(1).ok(),
            recipient: None,
            body: row.get(3).ok(),
            timestamp: row.get(2).ok(),
            received_timestamp: None,
            is_read: false,
            is_delivered: matches!(msg_type, Some(4 | 5)),
            is_sent: matches!(msg_type, Some(2..=5)),
            is_successful: matches!(msg_type, Some(2 | 4 | 5)),
            attachments: vec![],
            mentions: vec![],
            quote: None,
        })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            warn!(
                "[parser::signal] failed querying generic Messages rows for {}: {}",
                path.display(),
                e
            );
            return true;
        }
    };

    for entry in rows.flatten() {
        out.push(build_signal_artifact(path, entry));
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

fn build_signal_artifact(path: &Path, entry: SignalMessageEntry) -> ParsedArtifact {
    let preview = entry
        .body
        .as_deref()
        .unwrap_or("")
        .chars()
        .take(80)
        .collect::<String>();
    let description = if preview.is_empty() {
        "Signal message".to_string()
    } else {
        format!("Signal message: {}", preview)
    };

    ParsedArtifact {
        timestamp: entry.timestamp.or(entry.received_timestamp),
        artifact_type: "mobile_signal_message".to_string(),
        description,
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_zero_row_signal_fixture_as_empty() {
        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("apps")
            .join("shield")
            .join("fixtures")
            .join("parsers")
            .join("mobile")
            .join("signal_empty.db");
        let data = std::fs::read(&fixture_path).expect("fixture bytes");

        let artifacts = SignalParser::new()
            .parse_file(&fixture_path, &data)
            .expect("signal fixture parse should succeed");

        assert!(artifacts.is_empty());
    }
}
