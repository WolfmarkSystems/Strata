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
pub mod amazon_shopping;
pub mod app_usage;
pub mod badoo;
pub mod bereal;
pub mod bitcoin_wallet;
pub mod bluetooth;
pub mod browser_history;
pub mod bumble;
pub mod calendar;
pub mod call_logs;
pub mod cash_app;
pub mod chess_com;
pub mod chess_with_friends;
pub mod citymapper;
pub mod chrome_autofill;
pub mod chrome_bookmarks;
pub mod chrome_cookies;
pub mod chrome_downloads;
pub mod chrome_login_data;
pub mod chrome_media_history;
pub mod chrome_top_sites;
pub mod clipboard;
pub mod coinbase;
pub mod contacts;
pub mod device_info;
pub mod discord;
pub mod dji_flight;
pub mod doordash;
pub mod ebay;
pub mod facebook_messenger;
pub mod factory_reset;
pub mod firefox;
pub mod firefox_cookies;
pub mod fitbit;
pub mod garmin_activities;
pub mod garmin_dailies;
pub mod garmin_sleep;
pub mod garmin_weight;
pub mod gmail;
pub mod google_calendar_events;
pub mod google_chrome;
pub mod google_keep;
pub mod google_maps;
pub mod google_messages;
pub mod google_photos;
pub mod google_play;
pub mod grubhub;
pub mod imo_messenger;
pub mod installed_apps;
pub mod instacart;
pub mod keyboard_cache;
pub mod life360;
pub mod line_messenger;
pub mod linkedin;
pub mod location_history;
pub mod lyft;
pub mod mapmywalk;
pub mod meetme;
pub mod mega_chat;
pub mod metamask;
pub mod miui_gallery;
pub mod miui_security;
pub mod nike_activities;
pub mod nike_moments;
pub mod notifications;
pub mod oruxmaps;
pub mod permissions;
pub mod pinterest;
pub mod puma_trac;
pub mod randochat;
pub mod recent_activity;
pub mod reddit;
pub mod robinhood;
pub mod romeo;
pub mod runkeeper;
pub mod samsung_health;
pub mod samsung_notes;
pub mod samsung_pay;
pub mod sim_info;
pub mod skout;
pub mod skype;
pub mod slopes;
pub mod smartthings;
pub mod sms;
pub mod snapchat;
pub mod snapchat_memories;
pub mod snapchat_stories;
pub mod speedtest;
pub mod strava;
pub mod telegram;
pub mod telegram_channels;
pub mod textnow;
pub mod tiktok;
pub mod tiktok_live;
pub mod tiktok_search;
pub mod trust_wallet;
pub mod twitch;
pub mod twitter;
pub mod twitter_spaces;
pub mod uber;
pub mod uber_eats;
pub mod usage_stats;
pub mod venmo;
pub mod viber;
pub mod vlc_media;
pub mod waze;
pub mod wellbeing;
pub mod whatsapp;
pub mod wifi_profiles;
pub mod withings;
pub mod words_with_friends;
pub mod zepp_life;

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
    ParserEntry {
        name: "badoo",
        matches_any: badoo::MATCHES,
        run: badoo::parse,
    },
    ParserEntry {
        name: "bumble",
        matches_any: bumble::MATCHES,
        run: bumble::parse,
    },
    ParserEntry {
        name: "meetme",
        matches_any: meetme::MATCHES,
        run: meetme::parse,
    },
    ParserEntry {
        name: "skout",
        matches_any: skout::MATCHES,
        run: skout::parse,
    },
    ParserEntry {
        name: "romeo",
        matches_any: romeo::MATCHES,
        run: romeo::parse,
    },
    ParserEntry {
        name: "chess_com",
        matches_any: chess_com::MATCHES,
        run: chess_com::parse,
    },
    ParserEntry {
        name: "chess_with_friends",
        matches_any: chess_with_friends::MATCHES,
        run: chess_with_friends::parse,
    },
    ParserEntry {
        name: "words_with_friends",
        matches_any: words_with_friends::MATCHES,
        run: words_with_friends::parse,
    },
    ParserEntry {
        name: "randochat",
        matches_any: randochat::MATCHES,
        run: randochat::parse,
    },
    ParserEntry {
        name: "mega_chat",
        matches_any: mega_chat::MATCHES,
        run: mega_chat::parse,
    },
    ParserEntry {
        name: "life360",
        matches_any: life360::MATCHES,
        run: life360::parse,
    },
    ParserEntry {
        name: "withings",
        matches_any: withings::MATCHES,
        run: withings::parse,
    },
    ParserEntry {
        name: "zepp_life",
        matches_any: zepp_life::MATCHES,
        run: zepp_life::parse,
    },
    ParserEntry {
        name: "oruxmaps",
        matches_any: oruxmaps::MATCHES,
        run: oruxmaps::parse,
    },
    ParserEntry {
        name: "slopes",
        matches_any: slopes::MATCHES,
        run: slopes::parse,
    },
    ParserEntry {
        name: "speedtest",
        matches_any: speedtest::MATCHES,
        run: speedtest::parse,
    },
    ParserEntry {
        name: "mapmywalk",
        matches_any: mapmywalk::MATCHES,
        run: mapmywalk::parse,
    },
    ParserEntry {
        name: "citymapper",
        matches_any: citymapper::MATCHES,
        run: citymapper::parse,
    },
    ParserEntry {
        name: "garmin_weight",
        matches_any: garmin_weight::MATCHES,
        run: garmin_weight::parse,
    },
    ParserEntry {
        name: "linkedin",
        matches_any: linkedin::MATCHES,
        run: linkedin::parse,
    },
    ParserEntry {
        name: "samsung_health",
        matches_any: samsung_health::MATCHES,
        run: samsung_health::parse,
    },
    ParserEntry {
        name: "samsung_pay",
        matches_any: samsung_pay::MATCHES,
        run: samsung_pay::parse,
    },
    ParserEntry {
        name: "smartthings",
        matches_any: smartthings::MATCHES,
        run: smartthings::parse,
    },
    ParserEntry {
        name: "miui_security",
        matches_any: miui_security::MATCHES,
        run: miui_security::parse,
    },
    ParserEntry {
        name: "miui_gallery",
        matches_any: miui_gallery::MATCHES,
        run: miui_gallery::parse,
    },
    ParserEntry {
        name: "bitcoin_wallet",
        matches_any: bitcoin_wallet::MATCHES,
        run: bitcoin_wallet::parse,
    },
    ParserEntry {
        name: "coinbase",
        matches_any: coinbase::MATCHES,
        run: coinbase::parse,
    },
    ParserEntry {
        name: "trust_wallet",
        matches_any: trust_wallet::MATCHES,
        run: trust_wallet::parse,
    },
    ParserEntry {
        name: "metamask",
        matches_any: metamask::MATCHES,
        run: metamask::parse,
    },
    ParserEntry {
        name: "dji_flight",
        matches_any: dji_flight::MATCHES,
        run: dji_flight::parse,
    },
    ParserEntry {
        name: "amazon_shopping",
        matches_any: amazon_shopping::MATCHES,
        run: amazon_shopping::parse,
    },
    ParserEntry {
        name: "ebay",
        matches_any: ebay::MATCHES,
        run: ebay::parse,
    },
    ParserEntry {
        name: "uber",
        matches_any: uber::MATCHES,
        run: uber::parse,
    },
    ParserEntry {
        name: "uber_eats",
        matches_any: uber_eats::MATCHES,
        run: uber_eats::parse,
    },
    ParserEntry {
        name: "doordash",
        matches_any: doordash::MATCHES,
        run: doordash::parse,
    },
    ParserEntry {
        name: "lyft",
        matches_any: lyft::MATCHES,
        run: lyft::parse,
    },
    ParserEntry {
        name: "grubhub",
        matches_any: grubhub::MATCHES,
        run: grubhub::parse,
    },
    ParserEntry {
        name: "venmo",
        matches_any: venmo::MATCHES,
        run: venmo::parse,
    },
    ParserEntry {
        name: "robinhood",
        matches_any: robinhood::MATCHES,
        run: robinhood::parse,
    },
    ParserEntry {
        name: "instacart",
        matches_any: instacart::MATCHES,
        run: instacart::parse,
    },
    ParserEntry {
        name: "snapchat_stories",
        matches_any: snapchat_stories::MATCHES,
        run: snapchat_stories::parse,
    },
    ParserEntry {
        name: "snapchat_memories",
        matches_any: snapchat_memories::MATCHES,
        run: snapchat_memories::parse,
    },
    ParserEntry {
        name: "bereal",
        matches_any: bereal::MATCHES,
        run: bereal::parse,
    },
    ParserEntry {
        name: "telegram_channels",
        matches_any: telegram_channels::MATCHES,
        run: telegram_channels::parse,
    },
    ParserEntry {
        name: "tiktok_search",
        matches_any: tiktok_search::MATCHES,
        run: tiktok_search::parse,
    },
    ParserEntry {
        name: "tiktok_live",
        matches_any: tiktok_live::MATCHES,
        run: tiktok_live::parse,
    },
    ParserEntry {
        name: "reddit",
        matches_any: reddit::MATCHES,
        run: reddit::parse,
    },
    ParserEntry {
        name: "twitter_spaces",
        matches_any: twitter_spaces::MATCHES,
        run: twitter_spaces::parse,
    },
    ParserEntry {
        name: "pinterest",
        matches_any: pinterest::MATCHES,
        run: pinterest::parse,
    },
    ParserEntry {
        name: "twitch",
        matches_any: twitch::MATCHES,
        run: twitch::parse,
    },
];
