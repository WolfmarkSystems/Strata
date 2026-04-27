//! Terminal / shell history parser for macOS.
//!
//! Complements the existing `MacosShellHistoryParser` (which handles plain
//! `.zsh_history` / `.bash_history` files) with the *additional* macOS-specific
//! sources that mac_apt enumerates:
//!
//!   * `~/.zsh_sessions/<uuid>.history` — per-session zsh history
//!   * `~/.zsh_sessions/<uuid>.session` — session marker (start time)
//!   * `~/.zhistory` — alternate zsh location
//!   * `~/.local/share/fish/fish_history` — fish shell YAML log
//!   * `~/.bash_sessions/*.historynew` — Apple's per-session bash history
//!   * `~/.lesshst` — less command history
//!   * `~/.python_history` — Python REPL history
//!   * `~/.node_repl_history` — Node REPL history
//!   * `~/.psql_history` — PostgreSQL CLI history
//!
//! Forensic value:
//! Per-session shell history files are commonly missed by tools that only
//! grep for `.zsh_history`, but on modern macOS the `.zsh_sessions` directory
//! often contains the most recent commands the user typed.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAX_LINES: usize = 50_000;

pub struct MacosTerminalHistoryParser;

impl MacosTerminalHistoryParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosTerminalHistoryParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TerminalHistoryEntry {
    pub source: String,
    pub timestamp: Option<i64>,
    pub command: String,
}

impl ArtifactParser for MacosTerminalHistoryParser {
    fn name(&self) -> &str {
        "macOS Terminal History"
    }

    fn artifact_type(&self) -> &str {
        "user_activity"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            ".history",
            ".zhistory",
            ".historynew",
            "fish_history",
            ".lesshst",
            ".python_history",
            ".node_repl_history",
            ".psql_history",
            ".zsh_sessions",
            ".bash_sessions",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let path_str = path.to_string_lossy().to_lowercase();
        let lc_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Hard exclusion: the existing MacosShellHistoryParser already covers
        // these top-level files, so we skip them to avoid duplicate emit.
        if matches!(
            lc_name.as_str(),
            ".zsh_history" | ".bash_history" | ".sh_history"
        ) {
            return Ok(Vec::new());
        }

        let source = classify_source(&lc_name, &path_str);
        if source == "unknown" {
            return Ok(Vec::new());
        }

        if source == "fish_history" {
            return Ok(parse_fish_history(path, data));
        }
        if source == "zsh_session" {
            return Ok(parse_zsh_history_lines(path, data, source));
        }
        if source == "lesshst" {
            return Ok(parse_lesshst(path, data));
        }

        // Generic line-based history files (.python_history, .node_repl_history,
        // .psql_history, .zhistory, .historynew, generic .history).
        Ok(parse_plain_history(path, data, source))
    }
}

fn classify_source(lc_name: &str, lc_path: &str) -> &'static str {
    if lc_path.contains("/.zsh_sessions/") {
        return "zsh_session";
    }
    if lc_path.contains("/.bash_sessions/") {
        return "bash_session";
    }
    match lc_name {
        ".zhistory" => "zhistory",
        ".historynew" => "bash_session",
        "fish_history" => "fish_history",
        ".lesshst" => "lesshst",
        ".python_history" => "python_history",
        ".node_repl_history" => "node_repl_history",
        ".psql_history" => "psql_history",
        // The generic ".history" file (zsh writes here on some installs).
        ".history" => "zhistory",
        _ => "unknown",
    }
}

fn parse_plain_history(path: &Path, data: &[u8], source: &str) -> Vec<ParsedArtifact> {
    let text = String::from_utf8_lossy(data);
    text.lines()
        .take(MAX_LINES)
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let cmd = line.trim().to_string();
            ParsedArtifact {
                timestamp: None,
                artifact_type: "user_activity".to_string(),
                description: format!("{} command: {}", source, cmd),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(TerminalHistoryEntry {
                    source: source.to_string(),
                    timestamp: None,
                    command: cmd,
                })
                .unwrap_or_default(),
            }
        })
        .collect()
}

/// Parse zsh history lines that may carry an extended `: <ts>:0;cmd` prefix.
fn parse_zsh_history_lines(path: &Path, data: &[u8], source: &str) -> Vec<ParsedArtifact> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    for line in text.lines().take(MAX_LINES) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut timestamp = None;
        let mut command = trimmed.to_string();
        if trimmed.starts_with(':') || trimmed.starts_with(": ") {
            if let Some(semi) = trimmed.find(';') {
                let metadata = trimmed[1..semi].trim();
                if let Some(colon) = metadata.find(':') {
                    if let Ok(ts) = metadata[..colon].parse::<i64>() {
                        timestamp = Some(ts);
                    }
                }
                command = trimmed[semi + 1..].to_string();
            }
        }
        out.push(ParsedArtifact {
            timestamp,
            artifact_type: "user_activity".to_string(),
            description: format!("{} command: {}", source, command),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(TerminalHistoryEntry {
                source: source.to_string(),
                timestamp,
                command,
            })
            .unwrap_or_default(),
        });
    }
    out
}

/// Fish history is a YAML stream of `- cmd: ... \n  when: <epoch>` blocks.
fn parse_fish_history(path: &Path, data: &[u8]) -> Vec<ParsedArtifact> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    let mut current_cmd: Option<String> = None;
    let mut current_when: Option<i64> = None;

    for line in text.lines().take(MAX_LINES * 2) {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("- cmd:") {
            // Flush previous if any
            if let Some(cmd) = current_cmd.take() {
                out.push(ParsedArtifact {
                    timestamp: current_when.take(),
                    artifact_type: "user_activity".to_string(),
                    description: format!("fish command: {}", cmd),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(TerminalHistoryEntry {
                        source: "fish_history".to_string(),
                        timestamp: current_when,
                        command: cmd,
                    })
                    .unwrap_or_default(),
                });
            }
            current_cmd = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("when:") {
            current_when = rest.trim().parse::<i64>().ok();
        }
    }
    // Flush trailing entry
    if let Some(cmd) = current_cmd.take() {
        out.push(ParsedArtifact {
            timestamp: current_when,
            artifact_type: "user_activity".to_string(),
            description: format!("fish command: {}", cmd),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(TerminalHistoryEntry {
                source: "fish_history".to_string(),
                timestamp: current_when,
                command: cmd,
            })
            .unwrap_or_default(),
        });
    }
    out
}

/// `~/.lesshst` stores `.search` and `.shell` sections, each followed by
/// "\u{0}" prefixed entries — a hand-rolled escape format. We surface every
/// non-marker line as a command-or-search artifact.
fn parse_lesshst(path: &Path, data: &[u8]) -> Vec<ParsedArtifact> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    let mut section = "less";
    for line in text.lines().take(MAX_LINES) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == ".done" {
            continue;
        }
        if let Some(stripped) = trimmed.strip_prefix('.') {
            section = match stripped {
                "search" => "less.search",
                "shell" => "less.shell",
                "mark" => "less.mark",
                _ => "less",
            };
            continue;
        }
        let cmd = trimmed.trim_start_matches('"').to_string();
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "user_activity".to_string(),
            description: format!("{} entry: {}", section, cmd),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(TerminalHistoryEntry {
                source: section.to_string(),
                timestamp: None,
                command: cmd,
            })
            .unwrap_or_default(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parses_zsh_session_history_with_timestamps() {
        let parser = MacosTerminalHistoryParser::new();
        let path = PathBuf::from("/Users/test/.zsh_sessions/abc123.history");
        let body = ": 1700000000:0;ls -la\n: 1700000060:0;cd /Users/test\n";
        let out = parser.parse_file(&path, body.as_bytes()).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].timestamp, Some(1_700_000_000));
        assert!(out[0].description.contains("ls -la"));
    }

    #[test]
    fn parses_fish_history_yaml() {
        let parser = MacosTerminalHistoryParser::new();
        let path = PathBuf::from("/Users/test/.local/share/fish/fish_history");
        let body = "- cmd: echo hi\n  when: 1700000000\n- cmd: pwd\n  when: 1700000100\n";
        let out = parser.parse_file(&path, body.as_bytes()).unwrap();
        assert_eq!(out.len(), 2);
        let cmds: Vec<String> = out
            .iter()
            .filter_map(|a| {
                a.json_data
                    .get("command")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .collect();
        assert_eq!(cmds, vec!["echo hi", "pwd"]);
    }

    #[test]
    fn parses_python_history() {
        let parser = MacosTerminalHistoryParser::new();
        let path = PathBuf::from("/Users/test/.python_history");
        let body = "import os\nos.listdir('.')\n";
        let out = parser.parse_file(&path, body.as_bytes()).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out[0].description.contains("python_history"));
    }

    #[test]
    fn skips_top_level_zsh_history_to_avoid_duplicate() {
        let parser = MacosTerminalHistoryParser::new();
        let path = PathBuf::from("/Users/test/.zsh_history");
        let out = parser.parse_file(&path, b": 1700000000:0;ls").unwrap();
        assert!(
            out.is_empty(),
            "shell_history covers .zsh_history exclusively"
        );
    }

    #[test]
    fn parses_lesshst_sections() {
        let parser = MacosTerminalHistoryParser::new();
        let path = PathBuf::from("/Users/test/.lesshst");
        let body = ".search\n\"hello\n\"world\n.shell\n\"ls -la\n.done\n";
        let out = parser.parse_file(&path, body.as_bytes()).unwrap();
        assert!(out.iter().any(|a| a.description.contains("less.search")));
        assert!(out.iter().any(|a| a.description.contains("less.shell")));
    }
}
