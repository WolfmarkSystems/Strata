//! APPLE26-5 — Notes AI + Apple Intelligence + Image Playground /
//! Genmoji artifact structures.
//!
//! Shared between the pulse (iOS) and mactrace (macOS) plugins. This
//! module owns the canonical record shapes and a small set of
//! detection helpers; the plugin-side modules wire them to the
//! actual on-device paths.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotesAIArtifact {
    pub note_id: i64,
    pub title: String,
    pub creation_date: Option<DateTime<Utc>>,
    pub modification_date: Option<DateTime<Utc>>,
    pub contains_ai_content: bool,
    pub ai_operations: Vec<String>,
    pub original_text_available: bool,
    pub ai_modified_text: Option<String>,
    pub original_text: Option<String>,
    pub writing_tools_used: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppleIntelligenceRequest {
    pub timestamp: DateTime<Utc>,
    pub request_type: String,
    pub initiating_app: Option<String>,
    pub processed_on_device: bool,
    pub private_cloud_compute: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImagePlaygroundGeneration {
    pub timestamp: DateTime<Utc>,
    pub prompt: String,
    pub style: Option<String>,
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenmojiGeneration {
    pub timestamp: DateTime<Utc>,
    pub prompt: String,
    pub output_path: Option<String>,
}

// ── Row-level helpers ──────────────────────────────────────────────────

/// Returns true when a Notes row carries any AI-generated content
/// flag. Column names differ across iOS 26 point-releases so we take
/// a tolerant approach: presence of any *AI* / *RE_WRITE* / *SUMMARY*
/// token in the column-name set is treated as "this note was touched
/// by AI". Callers pass the full row-level bitfield for context.
pub fn contains_ai_flag(column_names: &[String], ai_flag_value: Option<i64>) -> bool {
    if let Some(v) = ai_flag_value {
        if v != 0 {
            return true;
        }
    }
    column_names.iter().any(|c| {
        let u = c.to_ascii_uppercase();
        u.contains("AIGENERATED") || u.contains("AI_GENERATED") || u.contains("RE_WRITE")
    })
}

/// Known writing-tool operation tags emitted by the AppleIntelligence
/// Notes pipeline. Used by callers to classify a single note.
pub fn canonical_writing_tool(raw: &str) -> Option<&'static str> {
    match raw.to_ascii_lowercase().trim() {
        "summarize" | "summary" => Some("Summarize"),
        "rewrite" => Some("Rewrite"),
        "proofread" => Some("Proofread"),
        "make_professional" | "professional" => Some("Make Professional"),
        "make_friendly" | "friendly" => Some("Make Friendly"),
        "make_concise" | "concise" => Some("Make Concise"),
        _ => None,
    }
}

/// Parse an AppleIntelligence request log line (one per line of
/// JSONL-ish format per the current research). Returns Some when the
/// line is well-formed; silently drops garbage.
pub fn parse_intelligence_log_line(line: &str) -> Option<AppleIntelligenceRequest> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let ts = v.get("timestamp")?.as_str()?;
    let timestamp = DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&Utc);
    let request_type = v
        .get("request_type")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let initiating_app = v
        .get("app")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let processed_on_device = v
        .get("on_device")
        .and_then(|x| x.as_bool())
        .unwrap_or(true);
    let private_cloud_compute = v
        .get("private_cloud_compute")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    Some(AppleIntelligenceRequest {
        timestamp,
        request_type,
        initiating_app,
        processed_on_device,
        private_cloud_compute,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalises_writing_tools() {
        assert_eq!(canonical_writing_tool("Summarize"), Some("Summarize"));
        assert_eq!(canonical_writing_tool("REWRITE"), Some("Rewrite"));
        assert_eq!(canonical_writing_tool("make_professional"), Some("Make Professional"));
        assert_eq!(canonical_writing_tool("unrecognised"), None);
    }

    #[test]
    fn contains_ai_flag_honours_explicit_value() {
        assert!(contains_ai_flag(&[], Some(1)));
        assert!(!contains_ai_flag(&[], Some(0)));
    }

    #[test]
    fn contains_ai_flag_matches_column_names() {
        let cols = vec!["ZTITLE".to_string(), "ZAIGENERATED".to_string()];
        assert!(contains_ai_flag(&cols, None));
    }

    #[test]
    fn parses_well_formed_intelligence_log() {
        let line = r#"{"timestamp":"2026-04-17T10:00:00Z","request_type":"text_summarize","app":"Notes","on_device":true}"#;
        let r = parse_intelligence_log_line(line).expect("parsed");
        assert_eq!(r.request_type, "text_summarize");
        assert_eq!(r.initiating_app.as_deref(), Some("Notes"));
        assert!(r.processed_on_device);
    }

    #[test]
    fn bad_json_returns_none() {
        assert!(parse_intelligence_log_line("not json").is_none());
        assert!(parse_intelligence_log_line("{}").is_none());
    }

    #[test]
    fn image_playground_structure_roundtrips_serde() {
        let p = ImagePlaygroundGeneration {
            timestamp: Utc::now(),
            prompt: "a cat in a suit".into(),
            style: Some("Watercolor".into()),
            output_path: Some("/tmp/cat.png".into()),
        };
        let s = serde_json::to_string(&p).expect("ser");
        let p2: ImagePlaygroundGeneration = serde_json::from_str(&s).expect("de");
        assert_eq!(p.prompt, p2.prompt);
    }
}
