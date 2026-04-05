use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_xbox_gamebar_captures() -> Vec<GameBarCapture> {
    let Some(items) = load(path("FORENSIC_GAMEBAR_CAPTURES", "captures.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| GameBarCapture {
            capture_type: s(&v, &["capture_type", "type"]),
            file_path: s(&v, &["file_path", "path"]),
            game: s(&v, &["game"]),
            duration: n(&v, &["duration", "duration_seconds"]) as u32,
            created: n(&v, &["created", "timestamp"]),
            size: n(&v, &["size"]),
        })
        .filter(|x| !x.file_path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct GameBarCapture {
    pub capture_type: String,
    pub file_path: String,
    pub game: String,
    pub duration: u32,
    pub created: u64,
    pub size: u64,
}

pub fn get_xbox_gamebar_settings() -> Vec<GameBarSettings> {
    let Some(items) = load(path("FORENSIC_GAMEBAR_SETTINGS", "settings.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| GameBarSettings {
            key: s(&v, &["key", "name"]),
            value: s(&v, &["value"]),
        })
        .filter(|x| !x.key.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct GameBarSettings {
    pub key: String,
    pub value: String,
}

pub fn get_xbox_gamepass() -> Vec<GamePassGame> {
    let Some(items) = load(path("FORENSIC_GAMEPASS_GAMES", "gamepass_games.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| GamePassGame {
            game_id: s(&v, &["game_id", "id"]),
            name: s(&v, &["name", "title"]),
            last_played: n(&v, &["last_played"]),
            play_time: n(&v, &["play_time", "play_time_seconds"]),
        })
        .filter(|x| !x.game_id.is_empty() || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct GamePassGame {
    pub game_id: String,
    pub name: String,
    pub last_played: u64,
    pub play_time: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("xbox_gamebar").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}
