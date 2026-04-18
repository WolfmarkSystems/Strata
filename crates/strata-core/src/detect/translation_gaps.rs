//! APPLE26-2 — Live Translation evidence-gap detector.
//!
//! iOS 26 / macOS Tahoe 26 Live Translation runs on-device and in
//! many cases does not preserve the pre-translation source text or
//! source audio. That creates a forensic gap the examiner must be
//! warned about in court-ready output. This module catalogues the
//! five gap-types documented in the Apple 26 forensics research and
//! emits a structured `TranslationGap` per instance.
//!
//! The detector is pure — it operates over caller-supplied fact
//! tuples (translated-message flag, device-locale, FaceTime-
//! translation flag, system-preference map). Wiring to actual iOS 26
//! artifacts is done in the pulse / mactrace plugins; this crate
//! provides the canonical gap taxonomy and examiner-warning text so
//! both plugins produce consistent case-report wording.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TranslationGapType {
    MessageTranslatedBeforeSend,
    MessageTranslatedOnReceive,
    FaceTimeLiveTranslation,
    PhoneCallLiveTranslation,
    SystemWideTranslationEnabled,
}

impl TranslationGapType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::MessageTranslatedBeforeSend => "Message translated before send",
            Self::MessageTranslatedOnReceive => "Message translated on receive",
            Self::FaceTimeLiveTranslation => "FaceTime Live Translation (audio lost)",
            Self::PhoneCallLiveTranslation => "Phone call Live Translation (audio lost)",
            Self::SystemWideTranslationEnabled => "System-wide translation enabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TranslationGap {
    pub artifact_path: String,
    pub gap_type: TranslationGapType,
    pub what_is_present: String,
    pub what_is_missing: String,
    pub examiner_warning: String,
    pub confidence: f64,
}

/// Caller-supplied facts about a single message / call that feed the
/// detector. All fields are optional — pass the subset the plugin
/// actually parsed out of the device.
#[derive(Debug, Clone, Default)]
pub struct MessageTranslationFacts<'a> {
    pub artifact_path: &'a str,
    pub is_translated_flag: bool,
    pub source_language: Option<&'a str>,
    pub target_language: Option<&'a str>,
    pub showed_original: bool,
    pub device_locale: Option<&'a str>,
}

#[derive(Debug, Clone, Default)]
pub struct CallTranslationFacts<'a> {
    pub artifact_path: &'a str,
    pub kind: CallKind,
    pub live_translation_used: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum CallKind {
    #[default]
    FaceTime,
    Phone,
}

/// Given a single message's translation facts, return the gap (if
/// any). `None` means no evidence loss was inferred.
pub fn gap_from_message(m: &MessageTranslationFacts) -> Option<TranslationGap> {
    if !m.is_translated_flag {
        // A language mismatch alone is low-confidence signal — flag
        // it, but at reduced confidence so reporting can sort.
        let mismatch = match (m.source_language, m.device_locale) {
            (Some(src), Some(locale))
                if !src.is_empty()
                    && !locale.is_empty()
                    && !locale.to_ascii_lowercase().starts_with(&src.to_ascii_lowercase()[..src.len().min(2)]) =>
            {
                true
            }
            _ => false,
        };
        if !mismatch {
            return None;
        }
        return Some(TranslationGap {
            artifact_path: m.artifact_path.into(),
            gap_type: TranslationGapType::MessageTranslatedBeforeSend,
            what_is_present: "translated message text".into(),
            what_is_missing: "original source-language text".into(),
            examiner_warning: examiner_warning(TranslationGapType::MessageTranslatedBeforeSend),
            confidence: 0.45,
        });
    }
    let gap_type = if m.showed_original {
        TranslationGapType::MessageTranslatedOnReceive
    } else {
        TranslationGapType::MessageTranslatedBeforeSend
    };
    Some(TranslationGap {
        artifact_path: m.artifact_path.into(),
        gap_type: gap_type.clone(),
        what_is_present: "translated text + language metadata".into(),
        what_is_missing: match gap_type {
            TranslationGapType::MessageTranslatedBeforeSend => "original pre-translation text".into(),
            _ => "none — original retained on recipient side".into(),
        },
        examiner_warning: examiner_warning(gap_type),
        confidence: if m.showed_original { 0.55 } else { 0.85 },
    })
}

pub fn gap_from_call(c: &CallTranslationFacts) -> Option<TranslationGap> {
    if !c.live_translation_used {
        return None;
    }
    let gap_type = match c.kind {
        CallKind::FaceTime => TranslationGapType::FaceTimeLiveTranslation,
        CallKind::Phone => TranslationGapType::PhoneCallLiveTranslation,
    };
    Some(TranslationGap {
        artifact_path: c.artifact_path.into(),
        gap_type: gap_type.clone(),
        what_is_present: "call metadata (participants, duration, timestamps)".into(),
        what_is_missing: "call audio + real-time translated transcript".into(),
        examiner_warning: examiner_warning(gap_type),
        confidence: 0.9,
    })
}

/// Returns a gap entry if the device-wide Translation feature toggle
/// is on — coarse but honest.
pub fn gap_from_system_flag(artifact_path: &str, translation_enabled: bool) -> Option<TranslationGap> {
    if !translation_enabled {
        return None;
    }
    Some(TranslationGap {
        artifact_path: artifact_path.into(),
        gap_type: TranslationGapType::SystemWideTranslationEnabled,
        what_is_present: "confirmation that Live Translation feature was enabled".into(),
        what_is_missing:
            "no direct evidence of which specific messages / calls were translated"
                .into(),
        examiner_warning: examiner_warning(TranslationGapType::SystemWideTranslationEnabled),
        confidence: 0.35,
    })
}

/// Canonical examiner-warning text per gap type. Kept as a single
/// function so the CLI, the expert-witness report template, and the
/// Tauri UI render the same sentence.
pub fn examiner_warning(kind: TranslationGapType) -> String {
    match kind {
        TranslationGapType::MessageTranslatedBeforeSend => {
            "TRANSLATION EVIDENCE GAP: This message was processed by Live Translation before \
             being sent. The translated version displayed to the user is preserved, but the \
             original language input may not have been stored on device. Investigators \
             attempting to verify original message content, intent, or linguistic context \
             should be aware that pre-translation text may be unavailable. Forensic \
             confidence in message attribution reduced for this artifact."
                .into()
        }
        TranslationGapType::MessageTranslatedOnReceive => {
            "TRANSLATION EVIDENCE NOTE: This message was translated upon receipt. The \
             original language text is typically retained alongside the translated version. \
             Verify both fields are present in the source database."
                .into()
        }
        TranslationGapType::FaceTimeLiveTranslation => {
            "TRANSLATION EVIDENCE GAP: FaceTime Live Translation was enabled for this call. \
             Audio content is processed in real time on-device and is typically not retained \
             after the call ends. The actual words spoken — in either language — may be \
             unrecoverable. Examiners should treat the call's translated transcript (if any) \
             as secondary evidence."
                .into()
        }
        TranslationGapType::PhoneCallLiveTranslation => {
            "TRANSLATION EVIDENCE GAP: Phone Live Translation was enabled for this call. \
             Audio content is processed in real time on-device and is typically not retained. \
             The actual words spoken may be unrecoverable."
                .into()
        }
        TranslationGapType::SystemWideTranslationEnabled => {
            "TRANSLATION SCOPE NOTE: The system-wide Live Translation preference was enabled \
             on this device. The scope of translation — which messages, which calls — cannot \
             be reconstructed from this flag alone. Examine per-message and per-call \
             translation artifacts for specific instances."
                .into()
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translated_flag_before_send_yields_high_confidence() {
        let m = MessageTranslationFacts {
            artifact_path: "/chat.db#7",
            is_translated_flag: true,
            source_language: Some("es"),
            target_language: Some("en"),
            showed_original: false,
            device_locale: Some("en-US"),
        };
        let g = gap_from_message(&m).expect("gap");
        assert_eq!(g.gap_type, TranslationGapType::MessageTranslatedBeforeSend);
        assert!(g.confidence >= 0.8);
    }

    #[test]
    fn translated_flag_showed_original_yields_on_receive() {
        let m = MessageTranslationFacts {
            artifact_path: "/chat.db#8",
            is_translated_flag: true,
            source_language: Some("en"),
            target_language: Some("es"),
            showed_original: true,
            ..Default::default()
        };
        let g = gap_from_message(&m).expect("gap");
        assert_eq!(g.gap_type, TranslationGapType::MessageTranslatedOnReceive);
    }

    #[test]
    fn locale_mismatch_without_flag_yields_low_confidence_gap() {
        let m = MessageTranslationFacts {
            artifact_path: "/chat.db#9",
            is_translated_flag: false,
            source_language: Some("ru"),
            device_locale: Some("en-US"),
            ..Default::default()
        };
        let g = gap_from_message(&m).expect("gap");
        assert_eq!(g.gap_type, TranslationGapType::MessageTranslatedBeforeSend);
        assert!(g.confidence < 0.6);
    }

    #[test]
    fn matching_locale_no_flag_returns_none() {
        let m = MessageTranslationFacts {
            is_translated_flag: false,
            source_language: Some("en"),
            device_locale: Some("en-US"),
            ..Default::default()
        };
        assert!(gap_from_message(&m).is_none());
    }

    #[test]
    fn facetime_live_translation_call_flagged() {
        let c = CallTranslationFacts {
            artifact_path: "/facetime#42",
            kind: CallKind::FaceTime,
            live_translation_used: true,
        };
        let g = gap_from_call(&c).expect("gap");
        assert_eq!(g.gap_type, TranslationGapType::FaceTimeLiveTranslation);
        assert!(g.examiner_warning.contains("Audio content"));
    }

    #[test]
    fn system_wide_flag_emits_coarse_gap() {
        let g = gap_from_system_flag("/defaults.plist", true).expect("gap");
        assert_eq!(g.gap_type, TranslationGapType::SystemWideTranslationEnabled);
    }

    #[test]
    fn examiner_warning_text_is_stable() {
        let w1 = examiner_warning(TranslationGapType::MessageTranslatedBeforeSend);
        let w2 = examiner_warning(TranslationGapType::MessageTranslatedBeforeSend);
        assert_eq!(w1, w2);
        assert!(w1.contains("TRANSLATION"));
    }
}
