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
pub mod adidas_running;
pub mod app_usage;
pub mod bluetooth;
pub mod browser_history;
pub mod calendar;
pub mod call_logs;
pub mod cash_app;
pub mod chrome_autofill;
pub mod chrome_bookmarks;
pub mod chrome_cookies;
pub mod chrome_downloads;
pub mod chrome_login_data;
pub mod chrome_media_history;
pub mod chrome_top_sites;
pub mod clipboard;
pub mod contacts;
pub mod device_info;
pub mod discord;
pub mod facebook_messenger;
pub mod factory_reset;
pub mod firefox;
pub mod firefox_cookies;
pub mod fitbit;
pub mod garmin_activities;
pub mod garmin_dailies;
pub mod garmin_sleep;
pub mod gmail;
pub mod google_calendar_events;
pub mod google_chrome;
pub mod google_keep;
pub mod google_maps;
pub mod google_messages;
pub mod google_photos;
pub mod google_play;
pub mod imo_messenger;
pub mod installed_apps;
pub mod keyboard_cache;
pub mod line_messenger;
pub mod location_history;
pub mod nike_activities;
pub mod nike_moments;
pub mod notifications;
pub mod permissions;
pub mod puma_trac;
pub mod recent_activity;
pub mod runkeeper;
pub mod samsung_notes;
pub mod sim_info;
pub mod skype;
pub mod sms;
pub mod snapchat;
pub mod strava;
pub mod telegram;
pub mod textnow;
pub mod tiktok;
pub mod twitter;
pub mod usage_stats;
pub mod viber;
pub mod vlc_media;
pub mod waze;
pub mod wellbeing;
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
    ParserEntry {
        name: "firefox",
        matches_any: firefox::MATCHES,
        run: firefox::parse,
    },
    ParserEntry {
        name: "firefox_cookies",
        matches_any: firefox_cookies::MATCHES,
        run: firefox_cookies::parse,
    },
    ParserEntry {
        name: "chrome_autofill",
        matches_any: chrome_autofill::MATCHES,
        run: chrome_autofill::parse,
    },
    ParserEntry {
        name: "chrome_bookmarks",
        matches_any: chrome_bookmarks::MATCHES,
        run: chrome_bookmarks::parse,
    },
    ParserEntry {
        name: "chrome_media_history",
        matches_any: chrome_media_history::MATCHES,
        run: chrome_media_history::parse,
    },
    ParserEntry {
        name: "waze",
        matches_any: waze::MATCHES,
        run: waze::parse,
    },
    ParserEntry {
        name: "cash_app",
        matches_any: cash_app::MATCHES,
        run: cash_app::parse,
    },
    ParserEntry {
        name: "google_keep",
        matches_any: google_keep::MATCHES,
        run: google_keep::parse,
    },
    ParserEntry {
        name: "google_calendar_events",
        matches_any: google_calendar_events::MATCHES,
        run: google_calendar_events::parse,
    },
    ParserEntry {
        name: "google_messages",
        matches_any: google_messages::MATCHES,
        run: google_messages::parse,
    },
    ParserEntry {
        name: "sim_info",
        matches_any: sim_info::MATCHES,
        run: sim_info::parse,
    },
    ParserEntry {
        name: "wellbeing",
        matches_any: wellbeing::MATCHES,
        run: wellbeing::parse,
    },
    ParserEntry {
        name: "usage_stats",
        matches_any: usage_stats::MATCHES,
        run: usage_stats::parse,
    },
    ParserEntry {
        name: "samsung_notes",
        matches_any: samsung_notes::MATCHES,
        run: samsung_notes::parse,
    },
    ParserEntry {
        name: "recent_activity",
        matches_any: recent_activity::MATCHES,
        run: recent_activity::parse,
    },
    ParserEntry {
        name: "tiktok",
        matches_any: tiktok::MATCHES,
        run: tiktok::parse,
    },
    ParserEntry {
        name: "permissions",
        matches_any: permissions::MATCHES,
        run: permissions::parse,
    },
    ParserEntry {
        name: "factory_reset",
        matches_any: factory_reset::MATCHES,
        run: factory_reset::parse,
    },
    ParserEntry {
        name: "vlc_media",
        matches_any: vlc_media::MATCHES,
        run: vlc_media::parse,
    },
    ParserEntry {
        name: "twitter",
        matches_any: twitter::MATCHES,
        run: twitter::parse,
    },
    ParserEntry {
        name: "garmin_activities",
        matches_any: garmin_activities::MATCHES,
        run: garmin_activities::parse,
    },
    ParserEntry {
        name: "garmin_dailies",
        matches_any: garmin_dailies::MATCHES,
        run: garmin_dailies::parse,
    },
    ParserEntry {
        name: "garmin_sleep",
        matches_any: garmin_sleep::MATCHES,
        run: garmin_sleep::parse,
    },
    ParserEntry {
        name: "nike_activities",
        matches_any: nike_activities::MATCHES,
        run: nike_activities::parse,
    },
    ParserEntry {
        name: "nike_moments",
        matches_any: nike_moments::MATCHES,
        run: nike_moments::parse,
    },
    ParserEntry {
        name: "strava",
        matches_any: strava::MATCHES,
        run: strava::parse,
    },
    ParserEntry {
        name: "adidas_running",
        matches_any: adidas_running::MATCHES,
        run: adidas_running::parse,
    },
    ParserEntry {
        name: "puma_trac",
        matches_any: puma_trac::MATCHES,
        run: puma_trac::parse,
    },
    ParserEntry {
        name: "runkeeper",
        matches_any: runkeeper::MATCHES,
        run: runkeeper::parse,
    },
    ParserEntry {
        name: "fitbit",
        matches_any: fitbit::MATCHES,
        run: fitbit::parse,
    },
];
