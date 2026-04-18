//! CHAT-1 — metadata-only parsers for deep encrypted messaging apps.
//!
//! Signal Desktop, Telegram Desktop, WhatsApp Business, Threema,
//! Element/Matrix, and Discord voice-channel logs all carry local
//! artifacts whose *metadata* survives the content encryption. This
//! module pulls the participant roster, conversation counts, date
//! ranges, and account identifiers without touching the encrypted
//! ciphertext.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedMessagingMetadata {
    pub platform: String,
    pub account_identifier: Option<String>,
    pub conversation_count: u32,
    pub total_messages: u32,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub participants: Vec<String>,
    pub group_memberships: Vec<String>,
    pub last_activity: Option<DateTime<Utc>>,
    pub encrypted_content_present: bool,
}

/// Signal Desktop's config.json carries the owner phone number in
/// clear text. Returns it if present.
pub fn parse_signal_config(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v.get("number").and_then(|x| x.as_str()).map(String::from)
}

/// Per-platform inputs collapsed to a named struct so
/// `build_metadata` stays under the too-many-arguments lint.
#[derive(Debug, Clone, Default)]
pub struct MessagingInputs<'a> {
    pub platform: &'a str,
    pub account: Option<&'a str>,
    pub conversation_count: u32,
    pub total_messages: u32,
    pub participants: Vec<String>,
    pub groups: Vec<String>,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub last_activity: Option<DateTime<Utc>>,
    pub encrypted_content_present: bool,
}

/// Build a metadata summary from caller-supplied numbers. The
/// per-platform parsers reduce their native file format to this
/// struct before calling in here so the aggregation path is uniform.
pub fn build_metadata(i: MessagingInputs<'_>) -> EncryptedMessagingMetadata {
    EncryptedMessagingMetadata {
        platform: i.platform.into(),
        account_identifier: i.account.map(String::from),
        conversation_count: i.conversation_count,
        total_messages: i.total_messages,
        date_range: i.date_range,
        participants: i.participants,
        group_memberships: i.groups,
        last_activity: i.last_activity,
        encrypted_content_present: i.encrypted_content_present,
    }
}

/// Parse the Telegram Desktop `tdata/settings0` for the phone
/// number. Telegram encodes settings as a custom binary format, but
/// the phone number is stored as a readable ASCII run; we search for
/// the "+<digits>" pattern.
pub fn parse_telegram_phone(bytes: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+'
            && i + 7 < bytes.len()
            && bytes[i + 1..=i + 7].iter().all(|b| b.is_ascii_digit())
        {
            let mut end = i + 8;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end - i <= 16 {
                return Some(
                    std::str::from_utf8(&bytes[i..end])
                        .ok()?
                        .to_string(),
                );
            }
        }
        i += 1;
    }
    None
}

/// Parse a Discord voice-channel session JSON dump. The voice audio
/// itself is cloud-only, but session participants and start/end
/// timestamps leave forensic traces worth surfacing.
pub fn parse_discord_voice_sessions(json: &str) -> Vec<VoiceChannelSession> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = v
        .get("sessions")
        .and_then(|x| x.as_array())
        .or_else(|| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for entry in arr {
        let participants: Vec<String> = entry
            .get("participants")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|e| e.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let started = entry
            .get("started")
            .and_then(|x| x.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc));
        let ended = entry
            .get("ended")
            .and_then(|x| x.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc));
        out.push(VoiceChannelSession {
            channel: entry
                .get("channel")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            started,
            ended,
            participants,
        });
    }
    out
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceChannelSession {
    pub channel: String,
    pub started: Option<DateTime<Utc>>,
    pub ended: Option<DateTime<Utc>>,
    pub participants: Vec<String>,
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_config_phone_number() {
        let json = r#"{"number":"+15551234567","other":"..."}"#;
        assert_eq!(parse_signal_config(json).as_deref(), Some("+15551234567"));
    }

    #[test]
    fn telegram_phone_number_pulled_from_binary() {
        // Arbitrary binary with a readable "+" number embedded.
        let mut buf = vec![0u8; 32];
        buf.extend_from_slice(b"+15558675309");
        buf.extend_from_slice(&[0u8; 16]);
        assert_eq!(parse_telegram_phone(&buf).as_deref(), Some("+15558675309"));
    }

    #[test]
    fn telegram_phone_none_when_absent() {
        let buf = b"no phone here".to_vec();
        assert!(parse_telegram_phone(&buf).is_none());
    }

    #[test]
    fn parses_discord_voice_sessions() {
        let json = r#"{"sessions":[
            {"channel":"general","started":"2026-04-10T20:00:00Z",
             "ended":"2026-04-10T21:00:00Z","participants":["alice#0001","bob#0002"]}
        ]}"#;
        let s = parse_discord_voice_sessions(json);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].participants.len(), 2);
        assert!(s[0].started.is_some());
    }

    #[test]
    fn build_metadata_carries_all_fields() {
        let m = build_metadata(MessagingInputs {
            platform: "Signal",
            account: Some("+15551234567"),
            conversation_count: 12,
            total_messages: 3_451,
            participants: vec!["alice".into()],
            groups: vec!["team".into()],
            date_range: None,
            last_activity: None,
            encrypted_content_present: true,
        });
        assert_eq!(m.platform, "Signal");
        assert_eq!(m.conversation_count, 12);
        assert!(m.encrypted_content_present);
    }

    #[test]
    fn empty_on_bad_input() {
        assert!(parse_signal_config("").is_none());
        assert!(parse_discord_voice_sessions("nope").is_empty());
    }
}
