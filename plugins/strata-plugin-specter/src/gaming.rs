//! GAME-1/2/3 — PlayStation / Xbox / Nintendo companion-app
//! artifact parsers.
//!
//! All three share the same JSON-shape on their respective mobile
//! apps (activities list, friend roster, message log, trophy /
//! achievement / play-time history). The module owns one unified
//! record type per platform plus per-platform JSON parsers.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── PlayStation ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlayStationArtifact {
    pub psn_id: String,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub game_title: Option<String>,
    pub friends_involved: Vec<String>,
    pub message_content: Option<String>,
    pub trophy_data: Option<TrophyData>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrophyData {
    pub trophy_name: String,
    pub trophy_rarity: String,
    pub earned_timestamp: DateTime<Utc>,
    pub game_title: String,
}

pub fn parse_playstation(json: &str, psn_id: &str) -> Vec<PlayStationArtifact> {
    parse_generic::<_, PlayStationArtifact>(json, |entry| {
        let timestamp = parse_ts(&entry)?;
        let trophy = entry.get("trophy").and_then(|t| {
            Some(TrophyData {
                trophy_name: t.get("name")?.as_str()?.to_string(),
                trophy_rarity: t
                    .get("rarity")
                    .and_then(|x| x.as_str())
                    .unwrap_or("common")
                    .into(),
                earned_timestamp: t
                    .get("earned_at")
                    .and_then(|x| x.as_str())
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now),
                game_title: t
                    .get("game")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        });
        Some(PlayStationArtifact {
            psn_id: psn_id.to_string(),
            artifact_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Event")
                .to_string(),
            timestamp,
            game_title: entry
                .get("game")
                .and_then(|x| x.as_str())
                .map(String::from),
            friends_involved: entry
                .get("friends")
                .and_then(|x| x.as_array())
                .map(|arr| arr.iter().filter_map(|e| e.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            message_content: entry.get("message").and_then(|x| x.as_str()).map(String::from),
            trophy_data: trophy,
        })
    })
}

// ── Xbox ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XboxArtifact {
    pub gamertag: String,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub game_title: Option<String>,
    pub clip_or_screenshot_path: Option<String>,
    pub message_content: Option<String>,
    pub party_members: Vec<String>,
    pub club_name: Option<String>,
}

pub fn parse_xbox(json: &str, gamertag: &str) -> Vec<XboxArtifact> {
    parse_generic::<_, XboxArtifact>(json, |entry| {
        Some(XboxArtifact {
            gamertag: gamertag.to_string(),
            artifact_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Event")
                .to_string(),
            timestamp: parse_ts(&entry)?,
            game_title: entry.get("game").and_then(|x| x.as_str()).map(String::from),
            clip_or_screenshot_path: entry
                .get("clip_path")
                .and_then(|x| x.as_str())
                .map(String::from),
            message_content: entry.get("message").and_then(|x| x.as_str()).map(String::from),
            party_members: entry
                .get("party")
                .and_then(|x| x.as_array())
                .map(|arr| arr.iter().filter_map(|e| e.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            club_name: entry.get("club").and_then(|x| x.as_str()).map(String::from),
        })
    })
}

// ── Nintendo ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NintendoArtifact {
    pub nintendo_account: String,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub game_title: Option<String>,
    pub play_duration_minutes: Option<u32>,
    pub friend_interactions: Vec<String>,
    pub screenshot_path: Option<String>,
}

pub fn parse_nintendo(json: &str, nintendo_account: &str) -> Vec<NintendoArtifact> {
    parse_generic::<_, NintendoArtifact>(json, |entry| {
        Some(NintendoArtifact {
            nintendo_account: nintendo_account.to_string(),
            artifact_type: entry
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("Event")
                .to_string(),
            timestamp: parse_ts(&entry)?,
            game_title: entry.get("game").and_then(|x| x.as_str()).map(String::from),
            play_duration_minutes: entry
                .get("duration_minutes")
                .and_then(|x| x.as_u64())
                .map(|u| u as u32),
            friend_interactions: entry
                .get("friends")
                .and_then(|x| x.as_array())
                .map(|arr| arr.iter().filter_map(|e| e.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            screenshot_path: entry
                .get("screenshot")
                .and_then(|x| x.as_str())
                .map(String::from),
        })
    })
}

// ── Shared helpers ─────────────────────────────────────────────────────

fn parse_ts(entry: &serde_json::Value) -> Option<DateTime<Utc>> {
    entry
        .get("timestamp")
        .and_then(|x| x.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
}

fn parse_generic<F, T>(json: &str, make: F) -> Vec<T>
where
    F: Fn(serde_json::Value) -> Option<T>,
{
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v
        .get("activities")
        .and_then(|x| x.as_array())
        .or_else(|| v.as_array())
        .cloned()
        .unwrap_or_default();
    arr.into_iter().filter_map(make).collect()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_playstation_message_event() {
        let json = r#"[{"type":"Message","timestamp":"2026-04-10T15:00:00Z",
            "friends":["FriendPSN"],"message":"gg"}]"#;
        let a = parse_playstation(json, "MyPSN");
        assert_eq!(a[0].message_content.as_deref(), Some("gg"));
        assert_eq!(a[0].friends_involved, vec!["FriendPSN"]);
    }

    #[test]
    fn parses_playstation_trophy_entry() {
        let json = r#"[{"type":"Trophy","timestamp":"2026-04-10T16:00:00Z",
            "game":"Horizon","trophy":{"name":"Master Hunter","rarity":"gold",
            "earned_at":"2026-04-10T16:00:00Z","game":"Horizon"}}]"#;
        let a = parse_playstation(json, "MyPSN");
        let t = a[0].trophy_data.as_ref().expect("trophy");
        assert_eq!(t.trophy_rarity, "gold");
    }

    #[test]
    fn parses_xbox_party_chat_entry() {
        let json = r#"[{"type":"PartyChat","timestamp":"2026-04-10T18:00:00Z",
            "game":"Halo","party":["Alice","Bob","Charlie"]}]"#;
        let a = parse_xbox(json, "GamertagX");
        assert_eq!(a[0].party_members.len(), 3);
    }

    #[test]
    fn parses_xbox_clip_path() {
        let json = r#"[{"type":"Clip","timestamp":"2026-04-10T19:00:00Z",
            "game":"COD","clip_path":"/DCIM/clip1.mp4"}]"#;
        let a = parse_xbox(json, "GamertagX");
        assert_eq!(a[0].clip_or_screenshot_path.as_deref(), Some("/DCIM/clip1.mp4"));
    }

    #[test]
    fn parses_nintendo_play_duration() {
        let json = r#"[{"type":"PlaySession","timestamp":"2026-04-10T20:00:00Z",
            "game":"Mario Kart","duration_minutes":45}]"#;
        let a = parse_nintendo(json, "Switch-User");
        assert_eq!(a[0].play_duration_minutes, Some(45));
    }

    #[test]
    fn empty_on_bad_input() {
        assert!(parse_playstation("nope", "").is_empty());
        assert!(parse_xbox("{}", "").is_empty());
        assert!(parse_nintendo("", "").is_empty());
    }
}
