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
pub mod bluetooth;
pub mod browser_history;
pub mod calendar;
pub mod call_logs;
pub mod chrome_cookies;
pub mod chrome_downloads;
pub mod chrome_login_data;
pub mod chrome_top_sites;
pub mod clipboard;
pub mod contacts;
pub mod device_info;
pub mod discord;
pub mod facebook_messenger;
pub mod gmail;
pub mod google_chrome;
pub mod google_maps;
pub mod google_photos;
pub mod google_play;
pub mod imo_messenger;
pub mod installed_apps;
pub mod keyboard_cache;
pub mod line_messenger;
pub mod location_history;
pub mod notifications;
pub mod skype;
pub mod sms;
pub mod snapchat;
pub mod telegram;
pub mod textnow;
pub mod viber;
pub mod whatsapp;
pub mod wifi_profiles;

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
    ParserEntry {
        name: "wifi_profiles",
        matches_any: wifi_profiles::MATCHES,
        run: wifi_profiles::parse,
    },
    ParserEntry {
        name: "bluetooth",
        matches_any: bluetooth::MATCHES,
        run: bluetooth::parse,
    },
    ParserEntry {
        name: "installed_apps",
        matches_any: installed_apps::MATCHES,
        run: installed_apps::parse,
    },
    ParserEntry {
        name: "clipboard",
        matches_any: clipboard::MATCHES,
        run: clipboard::parse,
    },
    ParserEntry {
        name: "chrome_downloads",
        matches_any: chrome_downloads::MATCHES,
        run: chrome_downloads::parse,
    },
    ParserEntry {
        name: "calendar",
        matches_any: calendar::MATCHES,
        run: calendar::parse,
    },
    ParserEntry {
        name: "notifications",
        matches_any: notifications::MATCHES,
        run: notifications::parse,
    },
    ParserEntry {
        name: "keyboard_cache",
        matches_any: keyboard_cache::MATCHES,
        run: keyboard_cache::parse,
    },
    ParserEntry {
        name: "location_history",
        matches_any: location_history::MATCHES,
        run: location_history::parse,
    },
    ParserEntry {
        name: "device_info",
        matches_any: device_info::MATCHES,
        run: device_info::parse,
    },
    ParserEntry {
        name: "chrome_cookies",
        matches_any: chrome_cookies::MATCHES,
        run: chrome_cookies::parse,
    },
    ParserEntry {
        name: "chrome_login_data",
        matches_any: chrome_login_data::MATCHES,
        run: chrome_login_data::parse,
    },
    ParserEntry {
        name: "chrome_top_sites",
        matches_any: chrome_top_sites::MATCHES,
        run: chrome_top_sites::parse,
    },
    ParserEntry {
        name: "google_play",
        matches_any: google_play::MATCHES,
        run: google_play::parse,
    },
    ParserEntry {
        name: "whatsapp",
        matches_any: whatsapp::MATCHES,
        run: whatsapp::parse,
    },
    ParserEntry {
        name: "facebook_messenger",
        matches_any: facebook_messenger::MATCHES,
        run: facebook_messenger::parse,
    },
    ParserEntry {
        name: "discord",
        matches_any: discord::MATCHES,
        run: discord::parse,
    },
    ParserEntry {
        name: "snapchat",
        matches_any: snapchat::MATCHES,
        run: snapchat::parse,
    },
    ParserEntry {
        name: "telegram",
        matches_any: telegram::MATCHES,
        run: telegram::parse,
    },
    ParserEntry {
        name: "skype",
        matches_any: skype::MATCHES,
        run: skype::parse,
    },
    ParserEntry {
        name: "textnow",
        matches_any: textnow::MATCHES,
        run: textnow::parse,
    },
    ParserEntry {
        name: "viber",
        matches_any: viber::MATCHES,
        run: viber::parse,
    },
    ParserEntry {
        name: "line_messenger",
        matches_any: line_messenger::MATCHES,
        run: line_messenger::parse,
    },
    ParserEntry {
        name: "imo_messenger",
        matches_any: imo_messenger::MATCHES,
        run: imo_messenger::parse,
    },
];
