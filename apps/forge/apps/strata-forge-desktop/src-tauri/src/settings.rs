use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Forge application settings, persisted to %APPDATA%\Strata\forge-settings.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeSettings {
    pub llm_base_url: String,
    pub llm_model: String,
    pub llm_timeout_secs: u64,
    pub context_server_port: u16,
    pub stream_responses: bool,
    pub max_conversation_history: usize,
    pub font_size: u8,
    pub save_conversation_history: bool,
    pub examiner_name: String,
}

impl Default for ForgeSettings {
    fn default() -> Self {
        Self {
            llm_base_url: "http://localhost:11434".to_string(),
            llm_model: "llama3.2".to_string(),
            llm_timeout_secs: 120,
            context_server_port: 7842,
            stream_responses: true,
            max_conversation_history: 20,
            font_size: 14,
            save_conversation_history: true,
            examiner_name: String::new(),
        }
    }
}

impl ForgeSettings {
    /// Path to the settings file.
    pub fn settings_path() -> PathBuf {
        let base = std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| dirs_fallback());
        base.join("Strata").join("forge-settings.json")
    }

    /// Path to the conversation history directory.
    pub fn history_dir() -> PathBuf {
        let base = std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| dirs_fallback());
        base.join("Strata").join("forge-history")
    }

    /// Load settings from disk, or return defaults if file doesn't exist.
    pub fn load() -> Self {
        let path = Self::settings_path();
        match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save settings to disk. Creates parent directories if needed.
    pub fn save(&self) -> Result<(), String> {
        let path = Self::settings_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create settings dir: {}", e))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize settings: {}", e))?;
        std::fs::write(&path, json).map_err(|e| format!("Failed to write settings: {}", e))?;
        Ok(())
    }

    /// Check if this is the first run (no settings file exists).
    pub fn is_first_run() -> bool {
        !Self::settings_path().exists()
    }
}

fn dirs_fallback() -> PathBuf {
    // Unix fallback
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".config"))
        .unwrap_or_else(|_| PathBuf::from("."))
}
