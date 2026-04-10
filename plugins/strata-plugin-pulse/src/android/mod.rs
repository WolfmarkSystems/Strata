//! Android parsers — ALEAPP-compatible schema extractors.
//!
//! Each submodule exports a single `parse(path: &Path) -> Vec<ArtifactRecord>`
//! plus a `MATCHES` list of lower-cased path fragments used to decide
//! whether the parser should be invoked for a given candidate file.
//! The top-level `PulsePlugin` walks the evidence tree and dispatches
//! matching files to every parser in [`ALL_PARSERS`].

use std::path::Path;
use strata_plugin_sdk::ArtifactRecord;

pub mod helpers;
pub mod walker;

// Individual parsers — one module per ALEAPP-equivalent artifact.
pub mod accounts_google;
pub mod app_usage;
pub mod browser_history;
pub mod call_logs;
pub mod contacts;
pub mod gmail;
pub mod google_chrome;
pub mod google_maps;
pub mod google_photos;
pub mod sms;

/// A single Android parser binding — name, matcher, and runner.
pub struct ParserEntry {
    /// Short slug used in log messages.
    pub name: &'static str,
    /// Lower-case path substrings; if any match the candidate path
    /// (`path.to_string_lossy().to_lowercase()`) this parser runs.
    pub matches_any: &'static [&'static str],
    /// Parse callback — accepts the absolute on-disk path of the
    /// candidate file.
    pub run: fn(&Path) -> Vec<ArtifactRecord>,
}

impl ParserEntry {
    /// Check if this parser should run for the given candidate path.
    pub fn matches(&self, path: &Path) -> bool {
        let p = path.to_string_lossy().to_lowercase();
        self.matches_any.iter().any(|needle| p.contains(needle))
    }
}

/// All Android parsers, in dispatch order.
///
/// Order matters only in that parsers listed earlier get first shot at
/// any candidate file, but every match is tried — a single path can
/// be consumed by multiple parsers (e.g. Chrome's `History` is probed
/// by both `google_chrome` and `browser_history`).
pub const ALL_PARSERS: &[ParserEntry] = &[
    ParserEntry {
        name: "accounts_google",
        matches_any: accounts_google::MATCHES,
        run: accounts_google::parse,
    },
    ParserEntry {
        name: "app_usage",
        matches_any: app_usage::MATCHES,
        run: app_usage::parse,
    },
    ParserEntry {
        name: "call_logs",
        matches_any: call_logs::MATCHES,
        run: call_logs::parse,
    },
    ParserEntry {
        name: "sms",
        matches_any: sms::MATCHES,
        run: sms::parse,
    },
    ParserEntry {
        name: "contacts",
        matches_any: contacts::MATCHES,
        run: contacts::parse,
    },
    ParserEntry {
        name: "browser_history",
        matches_any: browser_history::MATCHES,
        run: browser_history::parse,
    },
    ParserEntry {
        name: "google_photos",
        matches_any: google_photos::MATCHES,
        run: google_photos::parse,
    },
    ParserEntry {
        name: "gmail",
        matches_any: gmail::MATCHES,
        run: gmail::parse,
    },
    ParserEntry {
        name: "google_maps",
        matches_any: google_maps::MATCHES,
        run: google_maps::parse,
    },
    ParserEntry {
        name: "google_chrome",
        matches_any: google_chrome::MATCHES,
        run: google_chrome::parse,
    },
];
