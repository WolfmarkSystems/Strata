//! WIN25H2-2 — Click to Do + Semantic Indexing + Copilot interaction
//! artifacts.
//!
//! Windows 11 25H2 on Copilot+ PCs logs AI interactions in three
//! distinct stores: Click to Do events (per-interaction text / image
//! action records), the Semantic Index (AI-indexed document tags and
//! search queries), and Copilot assistant logs. This module owns the
//! canonical records and a pair of structured-log parsers; wiring
//! to %LOCALAPPDATA% paths lives in the chronicle plugin dispatch.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClickToDoEvent {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub target_content_type: String,
    pub target_content_preview: Option<String>,
    pub action_taken: String,
    pub source_application: Option<String>,
    pub source_document: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticIndexEntry {
    pub file_path: String,
    pub indexed_date: DateTime<Utc>,
    pub extracted_topics: Vec<String>,
    pub document_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CopilotInteraction {
    pub timestamp: DateTime<Utc>,
    pub query: String,
    pub response_preview: Option<String>,
    pub action_taken: Option<String>,
}

/// Parse a JSONL-style Click to Do log line.
pub fn parse_click_to_do_line(line: &str) -> Option<ClickToDoEvent> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let ts = v.get("timestamp")?.as_str()?;
    let timestamp = DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&Utc);
    Some(ClickToDoEvent {
        event_type: v
            .get("event")
            .and_then(|x| x.as_str())
            .unwrap_or("click_to_do")
            .into(),
        timestamp,
        target_content_type: v
            .get("content_type")
            .and_then(|x| x.as_str())
            .unwrap_or("Unknown")
            .into(),
        target_content_preview: v
            .get("content_preview")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        action_taken: v
            .get("action")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .into(),
        source_application: v.get("app").and_then(|x| x.as_str()).map(|s| s.to_string()),
        source_document: v
            .get("document")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
    })
}

/// Parse a semantic-index JSONL record.
pub fn parse_semantic_index_line(line: &str) -> Option<SemanticIndexEntry> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let ts = v.get("indexed_at")?.as_str()?;
    let indexed_date = DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&Utc);
    Some(SemanticIndexEntry {
        file_path: v.get("path")?.as_str()?.to_string(),
        indexed_date,
        extracted_topics: v
            .get("topics")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        document_summary: v
            .get("summary")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
    })
}

/// Parse a copilot-interaction log line.
pub fn parse_copilot_line(line: &str) -> Option<CopilotInteraction> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let ts = v.get("timestamp")?.as_str()?;
    let timestamp = DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&Utc);
    Some(CopilotInteraction {
        timestamp,
        query: v.get("query")?.as_str()?.to_string(),
        response_preview: v
            .get("response_preview")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        action_taken: v
            .get("action")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
    })
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_click_to_do_event() {
        let line = r#"{"timestamp":"2026-04-17T12:00:00Z","event":"click_to_do","content_type":"Text","content_preview":"meeting at 3pm","action":"Summarize","app":"Outlook","document":"mail#42"}"#;
        let e = parse_click_to_do_line(line).expect("parsed");
        assert_eq!(e.action_taken, "Summarize");
        assert_eq!(e.source_application.as_deref(), Some("Outlook"));
    }

    #[test]
    fn parses_semantic_index_entry() {
        let line = r#"{"indexed_at":"2026-04-17T12:00:00Z","path":"C:\\docs\\report.pdf","topics":["finance","Q2"],"summary":"Q2 financial results"}"#;
        let e = parse_semantic_index_line(line).expect("parsed");
        assert_eq!(e.file_path, "C:\\docs\\report.pdf");
        assert_eq!(e.extracted_topics, vec!["finance", "Q2"]);
    }

    #[test]
    fn parses_copilot_interaction() {
        let line = r#"{"timestamp":"2026-04-17T12:00:00Z","query":"summarize my inbox","response_preview":"Your inbox has 17 unread..."}"#;
        let c = parse_copilot_line(line).expect("parsed");
        assert_eq!(c.query, "summarize my inbox");
    }

    #[test]
    fn garbage_returns_none() {
        assert!(parse_click_to_do_line("{}").is_none());
        assert!(parse_semantic_index_line("not-json").is_none());
        assert!(parse_copilot_line("").is_none());
    }

    #[test]
    fn missing_topics_yields_empty_vec() {
        let line = r#"{"indexed_at":"2026-04-17T12:00:00Z","path":"C:\\x"}"#;
        let e = parse_semantic_index_line(line).expect("parsed");
        assert!(e.extracted_topics.is_empty());
    }
}
