use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::scalpel::{
    read_prefix, read_text_prefix, DEFAULT_BINARY_MAX_BYTES, DEFAULT_TEXT_MAX_BYTES,
};
use crate::errors::ForensicError;

#[derive(Debug, Clone, Default)]
pub struct TerminalProfile {
    pub name: String,
    pub command_line: String,
    pub starting_directory: String,
    pub icon: String,
    pub color_scheme: String,
    pub cursor_style: String,
    pub font: String,
}

pub fn get_windows_terminal_profiles() -> Result<Vec<TerminalProfile>, ForensicError> {
    let Some(json) = load_settings_json() else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    let profiles = json
        .get("profiles")
        .and_then(|v| v.get("list"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for profile in profiles {
        out.push(TerminalProfile {
            name: profile
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            command_line: profile
                .get("commandline")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            starting_directory: profile
                .get("startingDirectory")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            icon: profile
                .get("icon")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            color_scheme: profile
                .get("colorScheme")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            cursor_style: profile
                .get("cursorShape")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            font: profile
                .get("font")
                .and_then(|v| v.get("face"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }

    Ok(out)
}

pub fn get_terminal_settings() -> Result<TerminalSettings, ForensicError> {
    let Some(json) = load_settings_json() else {
        return Ok(TerminalSettings {
            default_profile: "".to_string(),
            theme: "dark".to_string(),
            ..Default::default()
        });
    };

    Ok(TerminalSettings {
        default_profile: json
            .get("defaultProfile")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        theme: json
            .get("theme")
            .and_then(Value::as_str)
            .unwrap_or("system")
            .to_string(),
        show_scrollbar: json
            .get("showScrollbar")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        copy_on_select: json
            .get("copyOnSelect")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        word_delimiters: json
            .get("wordDelimiters")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct TerminalSettings {
    pub default_profile: String,
    pub theme: String,
    pub show_scrollbar: bool,
    pub copy_on_select: bool,
    pub word_delimiters: String,
}

pub fn get_terminal_tab_history() -> Result<Vec<TabHistory>, ForensicError> {
    Ok(parse_terminal_tab_history(&tab_history_path()))
}

#[derive(Debug, Clone, Default)]
pub struct TabHistory {
    pub id: u32,
    pub title: String,
    pub command_count: u32,
    pub last_activity: u64,
}

fn parse_terminal_tab_history(path: &Path) -> Vec<TabHistory> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = if trimmed.contains('|') {
            trimmed.split('|').collect()
        } else {
            trimmed.split(',').collect()
        };
        if parts.len() < 4 {
            continue;
        }
        out.push(TabHistory {
            id: parts[0].trim().parse::<u32>().unwrap_or(0),
            title: parts[1].trim().to_string(),
            command_count: parts[2].trim().parse::<u32>().unwrap_or(0),
            last_activity: parts[3].trim().parse::<u64>().unwrap_or(0),
        });
    }
    out
}

fn load_settings_json() -> Option<Value> {
    for path in terminal_settings_candidates() {
        let Ok(data) = read_prefix(&path, DEFAULT_BINARY_MAX_BYTES) else {
            continue;
        };
        if let Ok(json) = serde_json::from_slice::<Value>(&data) {
            return Some(json);
        }
    }
    None
}

fn terminal_settings_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_TERMINAL_SETTINGS") {
        return vec![PathBuf::from(path)];
    }

    let mut out = vec![PathBuf::from("artifacts")
        .join("terminal")
        .join("settings.json")];

    if let Ok(user_profile) = env::var("USERPROFILE") {
        out.push(
            PathBuf::from(&user_profile)
                .join("AppData")
                .join("Local")
                .join("Packages")
                .join("Microsoft.WindowsTerminal_8wekyb3d8bbwe")
                .join("LocalState")
                .join("settings.json"),
        );
        out.push(
            PathBuf::from(user_profile)
                .join("AppData")
                .join("Local")
                .join("Packages")
                .join("Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe")
                .join("LocalState")
                .join("settings.json"),
        );
    }
    out
}

fn tab_history_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_TERMINAL_TAB_HISTORY") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("terminal")
        .join("tab_history.log")
}
