//! AI assistant desktop + mobile artifacts (PULSE-14).
//!
//! MITRE: T1005 (data from local system), T1552.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiAppArtifact {
    pub app_name: String,
    pub platform: String,
    pub artifact_type: String,
    pub conversation_title: Option<String>,
    pub message_count: Option<u64>,
    pub created_at: Option<DateTime<Utc>>,
    pub content_accessible: bool,
    pub keyword_flagged: bool,
}

const SENSITIVE_KEYWORDS: &[&str] = &[
    "password", "hack", "exploit", "bomb", "weapon", "drug", "csam",
];

pub fn identify_ai_app(path: &Path) -> Option<&'static str> {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if lower.contains("/chatgpt/") || lower.contains("com.openai.chatgpt") {
        return Some("ChatGPT");
    }
    if lower.contains("/copilot/") || lower.contains("microsoftcopilot") {
        return Some("Copilot");
    }
    if lower.contains("/gemini/") || lower.contains("com.google.android.apps.bard") {
        return Some("Gemini");
    }
    if lower.contains("/claude/") || lower.contains("com.anthropic.claude") {
        return Some("Claude");
    }
    None
}

pub fn platform_from_path(path: &Path) -> &'static str {
    let lower = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    if lower.contains("/data/data/") || lower.contains(".apk") {
        "Android"
    } else if lower.contains("/private/var/mobile") || lower.contains("/bundle.app/") {
        "iOS"
    } else {
        "Windows"
    }
}

pub fn has_sensitive_keyword(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SENSITIVE_KEYWORDS.iter().any(|k| lower.contains(k))
}

pub fn parse_conversations(path: &Path, app_name: &str) -> Vec<AiAppArtifact> {
    let Some(conn) = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok() else {
        return Vec::new();
    };
    // PRAGMA check.
    if conn
        .pragma_query_value(None, "schema_version", |_| Ok(()))
        .is_err()
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, title, created_at, \
                (SELECT COUNT(*) FROM messages WHERE conversation_id = conversations.id) \
         FROM conversations ORDER BY created_at ASC",
    ) {
        let rows = stmt.query_map([], |row| {
            let _id: Option<i64> = row.get(0)?;
            let title: Option<String> = row.get(1)?;
            let created_at: Option<i64> = row.get(2)?;
            let msg_count: Option<i64> = row.get(3)?;
            Ok((title, created_at, msg_count))
        });
        if let Ok(rows) = rows {
            let platform = platform_from_path(path);
            for (title, created_at, msg_count) in rows.flatten() {
                let ts = created_at.and_then(|v| {
                    // Try seconds then ms.
                    if v > 100_000_000_000 {
                        DateTime::<Utc>::from_timestamp(v / 1000, 0)
                    } else {
                        DateTime::<Utc>::from_timestamp(v, 0)
                    }
                });
                let keyword_flagged = title.as_deref().map(has_sensitive_keyword).unwrap_or(false);
                out.push(AiAppArtifact {
                    app_name: app_name.to_string(),
                    platform: platform.to_string(),
                    artifact_type: "Conversation".to_string(),
                    conversation_title: title,
                    message_count: msg_count.map(|n| n.max(0) as u64),
                    created_at: ts,
                    content_accessible: true,
                    keyword_flagged,
                });
            }
        }
    }
    out
}

pub fn scan(path: &Path) -> Vec<AiAppArtifact> {
    let Some(app) = identify_ai_app(path) else {
        return Vec::new();
    };
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.ends_with(".db") || name.ends_with(".sqlite") {
        let parsed = parse_conversations(path, app);
        if !parsed.is_empty() {
            return parsed;
        }
        // Unparseable — record install presence.
        return vec![AiAppArtifact {
            app_name: app.to_string(),
            platform: platform_from_path(path).to_string(),
            artifact_type: "InstallRecord".to_string(),
            conversation_title: None,
            message_count: None,
            created_at: None,
            content_accessible: false,
            keyword_flagged: false,
        }];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn identify_ai_app_recognises_paths() {
        assert_eq!(
            identify_ai_app(Path::new(
                "C:\\Users\\a\\AppData\\Roaming\\ChatGPT\\config.json"
            )),
            Some("ChatGPT")
        );
        assert_eq!(
            identify_ai_app(Path::new("/data/data/com.openai.chatgpt/databases/chatgpt.db")),
            Some("ChatGPT")
        );
        assert!(identify_ai_app(Path::new("/tmp/random")).is_none());
    }

    #[test]
    fn has_sensitive_keyword_flags_terms() {
        assert!(has_sensitive_keyword("How to hack a router"));
        assert!(has_sensitive_keyword("My API password"));
        assert!(!has_sensitive_keyword("Dinner recipes"));
    }

    #[test]
    fn parse_conversations_extracts_titles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("chatgpt.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE conversations (id INTEGER, title TEXT, created_at INTEGER); \
             CREATE TABLE messages (conversation_id INTEGER, role TEXT, content TEXT);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO conversations VALUES (1, 'How to hack a system', 1717243200)",
            [],
        )
        .expect("c");
        conn.execute(
            "INSERT INTO messages VALUES (1, 'user', 'hi')",
            [],
        )
        .expect("m");
        conn.execute(
            "INSERT INTO messages VALUES (1, 'assistant', 'hello')",
            [],
        )
        .expect("m2");
        drop(conn);
        let out = parse_conversations(&path, "ChatGPT");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].message_count, Some(2));
        assert!(out[0].keyword_flagged);
    }

    #[test]
    fn scan_falls_back_to_install_record_for_encrypted_db() {
        let dir = tempfile::tempdir().expect("tempdir");
        let chatgpt = dir.path().join("ChatGPT");
        std::fs::create_dir_all(&chatgpt).expect("mkdirs");
        let path = chatgpt.join("chatgpt.db");
        std::fs::write(&path, b"not-sqlite").expect("w");
        let out = scan(&path);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].artifact_type, "InstallRecord");
        assert!(!out[0].content_accessible);
    }

    #[test]
    fn platform_from_path_detects_android() {
        assert_eq!(
            platform_from_path(Path::new("/data/data/com.openai.chatgpt/databases/x.db")),
            "Android"
        );
    }
}
