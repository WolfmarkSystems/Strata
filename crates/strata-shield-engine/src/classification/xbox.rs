use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_xbox_activity() -> Vec<XboxActivity> {
    let Some(items) = load(path("FORENSIC_XBOX_ACTIVITY", "xbox_activity.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| XboxActivity {
            game_name: s(&v, &["game_name", "title"]),
            app_id: s(&v, &["app_id", "game_id"]),
            last_played: n(&v, &["last_played"]),
            total_time: n(&v, &["total_time", "play_time"]),
        })
        .filter(|x| !x.game_name.is_empty() || !x.app_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct XboxActivity {
    pub game_name: String,
    pub app_id: String,
    pub last_played: u64,
    pub total_time: u64,
}

pub fn get_xbox_clips() -> Vec<XboxClip> {
    let Some(items) = load(path("FORENSIC_XBOX_CLIPS", "xbox_clips.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| XboxClip {
            game_id: s(&v, &["game_id", "app_id"]),
            clip_path: s(&v, &["clip_path", "path"]),
            duration: n(&v, &["duration", "duration_seconds"]) as u32,
            thumbnail_path: s(&v, &["thumbnail_path", "thumbnail"]),
            created: n(&v, &["created", "timestamp"]),
        })
        .filter(|x| !x.clip_path.is_empty() || !x.game_id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct XboxClip {
    pub game_id: String,
    pub clip_path: String,
    pub duration: u32,
    pub thumbnail_path: String,
    pub created: u64,
}

pub fn get_xbox_achievements() -> Vec<XboxAchievement> {
    let Some(items) = load(path("FORENSIC_XBOX_ACHIEVEMENTS", "xbox_achievements.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| XboxAchievement {
            game_id: s(&v, &["game_id", "app_id"]),
            achievement_id: s(&v, &["achievement_id", "id"]),
            name: s(&v, &["name", "title"]),
            unlocked_at: n(&v, &["unlocked_at", "timestamp"]),
        })
        .filter(|x| !x.achievement_id.is_empty() || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct XboxAchievement {
    pub game_id: String,
    pub achievement_id: String,
    pub name: String,
    pub unlocked_at: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("xbox").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let json: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = json.as_array() {
        Some(items.clone())
    } else if json.is_object() {
        Some(vec![json])
    } else {
        None
    }
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
