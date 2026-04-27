//! LEGACY-IOS-3 — iOS 17+ message retention settings analysis.
//!
//! The `com.apple.MobileSMS.plist` KeepMessageForDays key disappears
//! when the setting is "Forever" (iOS 17+ default). Examiners
//! looking for deletion evidence have to distinguish between:
//!   * messages aged out of a short retention window (normal),
//!   * messages missing under Forever retention (possible deletion),
//!   * a retention setting changed from Forever → short immediately
//!     before a legal event (likely intentional evidence destruction).
//!
//! This module owns the analysis: given the current setting, the
//! thread's message count and age, and any historical-retention
//! evidence, produce a MessageRetentionSetting record with
//! examiner-ready wording.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageRetention {
    Forever,
    OneYear,
    ThirtyDays,
    Unknown,
}

impl MessageRetention {
    pub fn retention_days(&self) -> Option<u64> {
        match self {
            Self::Forever => None,
            Self::OneYear => Some(365),
            Self::ThirtyDays => Some(30),
            Self::Unknown => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Forever => "Forever",
            Self::OneYear => "1 Year",
            Self::ThirtyDays => "30 Days",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoricalRetention {
    pub setting: MessageRetention,
    pub detected_at: DateTime<Utc>,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageRetentionSetting {
    pub current_setting: MessageRetention,
    pub setting_has_changed: bool,
    pub historical_settings: Vec<HistoricalRetention>,
    pub messages_expected_present: Option<u64>,
    pub messages_actually_present: u64,
    pub gap_detected: bool,
    pub gap_explanation: String,
}

/// Parse the KeepMessageForDays value out of a plist-loaded map.
/// iOS stores the setting as a string ("-1" / "365" / "30") in
/// modern releases, but some older builds used integers.
pub fn parse_keep_message_for_days(raw: Option<&plist::Value>) -> MessageRetention {
    let Some(v) = raw else {
        // Missing key = Forever (default on iOS 17+).
        return MessageRetention::Forever;
    };
    let days = match v {
        plist::Value::Integer(i) => i.as_signed().unwrap_or(0),
        plist::Value::String(s) => s.trim().parse::<i64>().unwrap_or(0),
        _ => return MessageRetention::Unknown,
    };
    match days {
        i if i <= 0 => MessageRetention::Forever,
        30 => MessageRetention::ThirtyDays,
        365 => MessageRetention::OneYear,
        _ => MessageRetention::Unknown,
    }
}

/// Gap analysis: given a current setting, the thread's age, and the
/// observed message count, produce a MessageRetentionSetting with
/// the examiner-ready explanation filled in.
pub fn analyse(
    current_setting: MessageRetention,
    thread_age_days: u64,
    messages_actually_present: u64,
    expected_if_full_retention: u64,
    historical: Vec<HistoricalRetention>,
) -> MessageRetentionSetting {
    let setting_has_changed = historical.iter().any(|h| h.setting != current_setting);

    let messages_expected_present = match current_setting {
        MessageRetention::Forever => Some(expected_if_full_retention),
        MessageRetention::OneYear if thread_age_days <= 365 => Some(expected_if_full_retention),
        MessageRetention::ThirtyDays if thread_age_days <= 30 => Some(expected_if_full_retention),
        _ => None, // older than retention → older messages purged
    };

    let recent_downgrade = changed_to_shorter_recently(&historical, current_setting);

    let (gap_detected, explanation) = if recent_downgrade {
        (
            true,
            "ALERT: Message retention setting was changed from 'Forever' to a shorter period. \
             Older messages were purged as a result of that change. If the change occurred \
             close to a legal event or investigation trigger, this action may constitute \
             intentional evidence destruction."
                .to_string(),
        )
    } else if let Some(expected) = messages_expected_present {
        if messages_actually_present < expected {
            (
                true,
                "Messages are missing beneath the expected count for this retention setting. \
                 Investigate deletion events in the per-message audit."
                    .to_string(),
            )
        } else {
            (false, String::new())
        }
    } else {
        (
            false,
            "Retention setting would purge older messages; gap is expected, not suspicious.".into(),
        )
    };

    MessageRetentionSetting {
        current_setting,
        setting_has_changed,
        historical_settings: historical,
        messages_expected_present,
        messages_actually_present,
        gap_detected,
        gap_explanation: explanation,
    }
}

fn changed_to_shorter_recently(history: &[HistoricalRetention], current: MessageRetention) -> bool {
    // "Recently" = any historical record within the last 180 days.
    let cutoff = Utc::now() - Duration::days(180);
    history.iter().any(|h| {
        h.detected_at > cutoff
            && (h.setting == MessageRetention::Forever)
            && current != MessageRetention::Forever
    })
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_plist_key_means_forever() {
        assert_eq!(parse_keep_message_for_days(None), MessageRetention::Forever);
    }

    #[test]
    fn explicit_thirty_days_parses() {
        let v = plist::Value::String("30".into());
        assert_eq!(
            parse_keep_message_for_days(Some(&v)),
            MessageRetention::ThirtyDays
        );
    }

    #[test]
    fn integer_negative_one_means_forever() {
        let v = plist::Value::Integer(plist::Integer::from(-1i64));
        assert_eq!(
            parse_keep_message_for_days(Some(&v)),
            MessageRetention::Forever
        );
    }

    #[test]
    fn analyse_flags_gap_under_forever_setting() {
        let result = analyse(MessageRetention::Forever, 730, 10, 100, Vec::new());
        assert!(result.gap_detected);
        assert!(result.gap_explanation.contains("Messages are missing"));
    }

    #[test]
    fn analyse_no_gap_when_counts_match() {
        let result = analyse(MessageRetention::Forever, 730, 100, 100, Vec::new());
        assert!(!result.gap_detected);
    }

    #[test]
    fn analyse_flags_intentional_destruction_after_recent_downgrade() {
        let history = vec![HistoricalRetention {
            setting: MessageRetention::Forever,
            detected_at: Utc::now() - Duration::days(30),
            source: "plist_backup".into(),
        }];
        let result = analyse(MessageRetention::ThirtyDays, 90, 1, 10, history);
        assert!(result.gap_detected);
        assert!(result.gap_explanation.contains("ALERT"));
    }

    #[test]
    fn retention_days_accessor_covers_cases() {
        assert_eq!(MessageRetention::ThirtyDays.retention_days(), Some(30));
        assert_eq!(MessageRetention::Forever.retention_days(), None);
    }
}
