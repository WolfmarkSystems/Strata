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
pub mod airbnb;
pub mod amazon_alexa;
pub mod amazon_shopping;
pub mod american_airlines;
pub mod android_auto;
pub mod anydo;
pub mod app_usage;
pub mod army_mobile;
pub mod authy;
pub mod badoo;
pub mod bank_of_america;
pub mod bereal;
pub mod betterhelp;
pub mod bitcoin_wallet;
pub mod bitwarden;
pub mod blackboard;
pub mod blockchain_wallet;
pub mod blood_pressure_app;
pub mod bluetooth;
pub mod booking_com;
pub mod browser_history;
pub mod bumble;
pub mod calendar;
pub mod call_logs;
pub mod calm_app;
pub mod canvas_lms;
pub mod capital_one;
pub mod cash_app;
pub mod chase_bank;
pub mod chess_com;
pub mod chess_with_friends;
pub mod chrome_autofill;
pub mod chrome_bookmarks;
pub mod chrome_cookies;
pub mod chrome_downloads;
pub mod chrome_login_data;
pub mod chrome_media_history;
pub mod chrome_top_sites;
pub mod citizen_app;
pub mod citymapper;
pub mod clipboard;
pub mod coffee_meets_bagel;
pub mod coinbase;
pub mod coinomi;
pub mod contacts;
pub mod costco;
pub mod dailymotion;
pub mod delta_airlines;
pub mod device_info;
pub mod dexcom_cgm;
pub mod discord;
pub mod discord_voice;
pub mod dji_flight;
pub mod dmv_app;
pub mod doordash;
pub mod duolingo;
pub mod ebay;
pub mod electrum_wallet;
pub mod evernote;
pub mod exodus_wallet;
pub mod expedia;
pub mod facebook_messenger;
pub mod factory_reset;
pub mod fb_marketplace;
pub mod find_my_kids;
pub mod firefox;
pub mod firefox_cookies;
pub mod fitbit;
pub mod fordpass;
pub mod garmin_activities;
pub mod garmin_dailies;
pub mod garmin_sleep;
pub mod garmin_weight;
pub mod gm_onstar;
pub mod gmail;
pub mod google_authenticator;
pub mod google_calendar_events;
pub mod google_chrome;
pub mod google_family_link;
pub mod google_flights;
pub mod google_home;
pub mod google_keep;
pub mod google_maps;
pub mod google_messages;
pub mod google_photos;
pub mod google_play;
pub mod google_tasks;
pub mod govx;
pub mod grindr;
pub mod groupme;
pub mod grubhub;
pub mod headspace;
pub mod here_maps;
pub mod hinge;
pub mod hotels_com;
pub mod imo_messenger;
pub mod indeed;
pub mod instacart;
pub mod installed_apps;
pub mod irs2go;
pub mod keyboard_cache;
pub mod lastpass;
pub mod lexisnexis;
pub mod libre_cgm;
pub mod life360;
pub mod life360_deep;
pub mod line_messenger;
pub mod linkedin;
pub mod linkedin_jobs;
pub mod location_history;
pub mod lyft;
pub mod mapmywalk;
pub mod maps_me;
pub mod marco_polo;
pub mod medicare;
pub mod meetme;
pub mod mega_chat;
pub mod metamask;
pub mod miui_gallery;
pub mod miui_security;
pub mod mychart;
pub mod myfitnesspal;
pub mod mysugr;
pub mod navy_federal;
pub mod nest;
pub mod nextdoor;
pub mod nike_activities;
pub mod nike_moments;
pub mod notifications;
pub mod notion;
pub mod offerup;
pub mod okcupid;
pub mod onenote;
pub mod onepassword;
pub mod oruxmaps;
pub mod osmand;
pub mod oura;
pub mod pacer;
pub mod pandora;
pub mod parkwhiz;
pub mod peloton;
pub mod permissions;
pub mod philips_hue;
pub mod pillow_sleep;
pub mod pinterest;
pub mod plenty_of_fish;
pub mod pluto_tv;
pub mod protonmail;
pub mod puma_trac;
pub mod randochat;
pub mod realtor_com;
pub mod recent_activity;
pub mod reddit;
pub mod redfin;
pub mod ring_doorbell;
pub mod robinhood;
pub mod romeo;
pub mod rumble;
pub mod runkeeper;
pub mod samsung_health;
pub mod samsung_notes;
pub mod samsung_pay;
pub mod signal_attachments;
pub mod sim_info;
pub mod skout;
pub mod skype;
pub mod slack_deep;
pub mod sleep_cycle;
pub mod slopes;
pub mod smartthings;
pub mod smartthings_events;
pub mod sms;
pub mod snapchat;
pub mod snapchat_memories;
pub mod snapchat_spotlight;
pub mod snapchat_stories;
pub mod soundcloud;
pub mod southwest_airlines;
pub mod speedtest;
pub mod spothero;
pub mod spotify_deep;
pub mod strava;
pub mod target_app;
pub mod teams_deep;
pub mod telegram;
pub mod telegram_channels;
pub mod tesla_app;
pub mod textnow;
pub mod tiktok;
pub mod tiktok_live;
pub mod tiktok_search;
pub mod tinder;
pub mod todoist;
pub mod trust_wallet;
pub mod tsa_precheck;
pub mod tubi;
pub mod twitch;
pub mod twitter;
pub mod twitter_spaces;
pub mod uber;
pub mod uber_eats;
pub mod united_airlines;
pub mod united_healthcare;
pub mod usaa;
pub mod usage_stats;
pub mod venmo;
pub mod viber;
pub mod vlc_media;
pub mod voxer;
pub mod vrbo;
pub mod walmart;
pub mod waze;
pub mod wellbeing;
pub mod wells_fargo;
pub mod westlaw;
pub mod whatsapp;
pub mod whoop;
pub mod wifi_profiles;
pub mod withings;
pub mod words_with_friends;
pub mod youtube_music;
pub mod zelle;
pub mod zello;
pub mod zepp_life;
pub mod zillow;
pub mod ziprecruiter;
pub mod zoom_deep;

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
        name: "airbnb",
        matches_any: airbnb::MATCHES,
        run: airbnb::parse,
    },
    ParserEntry {
        name: "american_airlines",
        matches_any: american_airlines::MATCHES,
        run: american_airlines::parse,
    },
    ParserEntry {
        name: "booking_com",
        matches_any: booking_com::MATCHES,
        run: booking_com::parse,
    },
    ParserEntry {
        name: "delta_airlines",
        matches_any: delta_airlines::MATCHES,
        run: delta_airlines::parse,
    },
    ParserEntry {
        name: "expedia",
        matches_any: expedia::MATCHES,
        run: expedia::parse,
    },
    ParserEntry {
        name: "google_flights",
        matches_any: google_flights::MATCHES,
        run: google_flights::parse,
    },
    ParserEntry {
        name: "hotels_com",
        matches_any: hotels_com::MATCHES,
        run: hotels_com::parse,
    },
    ParserEntry {
        name: "southwest_airlines",
        matches_any: southwest_airlines::MATCHES,
        run: southwest_airlines::parse,
    },
    ParserEntry {
        name: "united_airlines",
        matches_any: united_airlines::MATCHES,
        run: united_airlines::parse,
    },
    ParserEntry {
        name: "vrbo",
        matches_any: vrbo::MATCHES,
        run: vrbo::parse,
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
    ParserEntry {
        name: "chase_bank",
        matches_any: chase_bank::MATCHES,
        run: chase_bank::parse,
    },
    ParserEntry {
        name: "bank_of_america",
        matches_any: bank_of_america::MATCHES,
        run: bank_of_america::parse,
    },
    ParserEntry {
        name: "wells_fargo",
        matches_any: wells_fargo::MATCHES,
        run: wells_fargo::parse,
    },
    ParserEntry {
        name: "capital_one",
        matches_any: capital_one::MATCHES,
        run: capital_one::parse,
    },
    ParserEntry {
        name: "zelle",
        matches_any: zelle::MATCHES,
        run: zelle::parse,
    },
    ParserEntry {
        name: "united_healthcare",
        matches_any: united_healthcare::MATCHES,
        run: united_healthcare::parse,
    },
    ParserEntry {
        name: "irs2go",
        matches_any: irs2go::MATCHES,
        run: irs2go::parse,
    },
    ParserEntry {
        name: "mychart",
        matches_any: mychart::MATCHES,
        run: mychart::parse,
    },
    ParserEntry {
        name: "medicare",
        matches_any: medicare::MATCHES,
        run: medicare::parse,
    },
    ParserEntry {
        name: "dmv_app",
        matches_any: dmv_app::MATCHES,
        run: dmv_app::parse,
    },
    ParserEntry {
        name: "signal_attachments",
        matches_any: signal_attachments::MATCHES,
        run: signal_attachments::parse,
    },
    ParserEntry {
        name: "linkedin_jobs",
        matches_any: linkedin_jobs::MATCHES,
        run: linkedin_jobs::parse,
    },
    ParserEntry {
        name: "discord_voice",
        matches_any: discord_voice::MATCHES,
        run: discord_voice::parse,
    },
    ParserEntry {
        name: "tinder",
        matches_any: tinder::MATCHES,
        run: tinder::parse,
    },
    ParserEntry {
        name: "hinge",
        matches_any: hinge::MATCHES,
        run: hinge::parse,
    },
    ParserEntry {
        name: "google_home",
        matches_any: google_home::MATCHES,
        run: google_home::parse,
    },
    ParserEntry {
        name: "amazon_alexa",
        matches_any: amazon_alexa::MATCHES,
        run: amazon_alexa::parse,
    },
    ParserEntry {
        name: "smartthings_events",
        matches_any: smartthings_events::MATCHES,
        run: smartthings_events::parse,
    },
    ParserEntry {
        name: "ring_doorbell",
        matches_any: ring_doorbell::MATCHES,
        run: ring_doorbell::parse,
    },
    ParserEntry {
        name: "nest",
        matches_any: nest::MATCHES,
        run: nest::parse,
    },
    ParserEntry {
        name: "philips_hue",
        matches_any: philips_hue::MATCHES,
        run: philips_hue::parse,
    },
    ParserEntry {
        name: "android_auto",
        matches_any: android_auto::MATCHES,
        run: android_auto::parse,
    },
    ParserEntry {
        name: "tesla_app",
        matches_any: tesla_app::MATCHES,
        run: tesla_app::parse,
    },
    ParserEntry {
        name: "fordpass",
        matches_any: fordpass::MATCHES,
        run: fordpass::parse,
    },
    ParserEntry {
        name: "gm_onstar",
        matches_any: gm_onstar::MATCHES,
        run: gm_onstar::parse,
    },
    ParserEntry {
        name: "dexcom_cgm",
        matches_any: dexcom_cgm::MATCHES,
        run: dexcom_cgm::parse,
    },
    ParserEntry {
        name: "libre_cgm",
        matches_any: libre_cgm::MATCHES,
        run: libre_cgm::parse,
    },
    ParserEntry {
        name: "mysugr",
        matches_any: mysugr::MATCHES,
        run: mysugr::parse,
    },
    ParserEntry {
        name: "betterhelp",
        matches_any: betterhelp::MATCHES,
        run: betterhelp::parse,
    },
    ParserEntry {
        name: "calm_app",
        matches_any: calm_app::MATCHES,
        run: calm_app::parse,
    },
    ParserEntry {
        name: "headspace",
        matches_any: headspace::MATCHES,
        run: headspace::parse,
    },
    ParserEntry {
        name: "myfitnesspal",
        matches_any: myfitnesspal::MATCHES,
        run: myfitnesspal::parse,
    },
    ParserEntry {
        name: "peloton",
        matches_any: peloton::MATCHES,
        run: peloton::parse,
    },
    ParserEntry {
        name: "whoop",
        matches_any: whoop::MATCHES,
        run: whoop::parse,
    },
    ParserEntry {
        name: "oura",
        matches_any: oura::MATCHES,
        run: oura::parse,
    },
    ParserEntry {
        name: "duolingo",
        matches_any: duolingo::MATCHES,
        run: duolingo::parse,
    },
    ParserEntry {
        name: "canvas_lms",
        matches_any: canvas_lms::MATCHES,
        run: canvas_lms::parse,
    },
    ParserEntry {
        name: "blackboard",
        matches_any: blackboard::MATCHES,
        run: blackboard::parse,
    },
    ParserEntry {
        name: "spotify_deep",
        matches_any: spotify_deep::MATCHES,
        run: spotify_deep::parse,
    },
    ParserEntry {
        name: "pandora",
        matches_any: pandora::MATCHES,
        run: pandora::parse,
    },
    ParserEntry {
        name: "lexisnexis",
        matches_any: lexisnexis::MATCHES,
        run: lexisnexis::parse,
    },
    ParserEntry {
        name: "westlaw",
        matches_any: westlaw::MATCHES,
        run: westlaw::parse,
    },
    ParserEntry {
        name: "pacer",
        matches_any: pacer::MATCHES,
        run: pacer::parse,
    },
    ParserEntry {
        name: "army_mobile",
        matches_any: army_mobile::MATCHES,
        run: army_mobile::parse,
    },
    ParserEntry {
        name: "govx",
        matches_any: govx::MATCHES,
        run: govx::parse,
    },
    ParserEntry {
        name: "usaa",
        matches_any: usaa::MATCHES,
        run: usaa::parse,
    },
    ParserEntry {
        name: "navy_federal",
        matches_any: navy_federal::MATCHES,
        run: navy_federal::parse,
    },
    ParserEntry {
        name: "tsa_precheck",
        matches_any: tsa_precheck::MATCHES,
        run: tsa_precheck::parse,
    },
    ParserEntry {
        name: "google_authenticator",
        matches_any: google_authenticator::MATCHES,
        run: google_authenticator::parse,
    },
    ParserEntry {
        name: "protonmail",
        matches_any: protonmail::MATCHES,
        run: protonmail::parse,
    },
    ParserEntry {
        name: "zillow",
        matches_any: zillow::MATCHES,
        run: zillow::parse,
    },
    ParserEntry {
        name: "realtor_com",
        matches_any: realtor_com::MATCHES,
        run: realtor_com::parse,
    },
    ParserEntry {
        name: "redfin",
        matches_any: redfin::MATCHES,
        run: redfin::parse,
    },
    ParserEntry {
        name: "indeed",
        matches_any: indeed::MATCHES,
        run: indeed::parse,
    },
    ParserEntry {
        name: "ziprecruiter",
        matches_any: ziprecruiter::MATCHES,
        run: ziprecruiter::parse,
    },
    ParserEntry {
        name: "notion",
        matches_any: notion::MATCHES,
        run: notion::parse,
    },
    ParserEntry {
        name: "evernote",
        matches_any: evernote::MATCHES,
        run: evernote::parse,
    },
    ParserEntry {
        name: "onenote",
        matches_any: onenote::MATCHES,
        run: onenote::parse,
    },
    ParserEntry {
        name: "todoist",
        matches_any: todoist::MATCHES,
        run: todoist::parse,
    },
    ParserEntry {
        name: "anydo",
        matches_any: anydo::MATCHES,
        run: anydo::parse,
    },
    ParserEntry {
        name: "google_tasks",
        matches_any: google_tasks::MATCHES,
        run: google_tasks::parse,
    },
    ParserEntry {
        name: "lastpass",
        matches_any: lastpass::MATCHES,
        run: lastpass::parse,
    },
    ParserEntry {
        name: "onepassword",
        matches_any: onepassword::MATCHES,
        run: onepassword::parse,
    },
    ParserEntry {
        name: "bitwarden",
        matches_any: bitwarden::MATCHES,
        run: bitwarden::parse,
    },
    ParserEntry {
        name: "authy",
        matches_any: authy::MATCHES,
        run: authy::parse,
    },
    ParserEntry {
        name: "soundcloud",
        matches_any: soundcloud::MATCHES,
        run: soundcloud::parse,
    },
    ParserEntry {
        name: "youtube_music",
        matches_any: youtube_music::MATCHES,
        run: youtube_music::parse,
    },
    ParserEntry {
        name: "groupme",
        matches_any: groupme::MATCHES,
        run: groupme::parse,
    },
    ParserEntry {
        name: "here_maps",
        matches_any: here_maps::MATCHES,
        run: here_maps::parse,
    },
    ParserEntry {
        name: "maps_me",
        matches_any: maps_me::MATCHES,
        run: maps_me::parse,
    },
    ParserEntry {
        name: "osmand",
        matches_any: osmand::MATCHES,
        run: osmand::parse,
    },
    ParserEntry {
        name: "walmart",
        matches_any: walmart::MATCHES,
        run: walmart::parse,
    },
    ParserEntry {
        name: "target_app",
        matches_any: target_app::MATCHES,
        run: target_app::parse,
    },
    ParserEntry {
        name: "costco",
        matches_any: costco::MATCHES,
        run: costco::parse,
    },
    ParserEntry {
        name: "offerup",
        matches_any: offerup::MATCHES,
        run: offerup::parse,
    },
    ParserEntry {
        name: "fb_marketplace",
        matches_any: fb_marketplace::MATCHES,
        run: fb_marketplace::parse,
    },
    ParserEntry {
        name: "marco_polo",
        matches_any: marco_polo::MATCHES,
        run: marco_polo::parse,
    },
    ParserEntry {
        name: "voxer",
        matches_any: voxer::MATCHES,
        run: voxer::parse,
    },
    ParserEntry {
        name: "zello",
        matches_any: zello::MATCHES,
        run: zello::parse,
    },
    ParserEntry {
        name: "snapchat_spotlight",
        matches_any: snapchat_spotlight::MATCHES,
        run: snapchat_spotlight::parse,
    },
    ParserEntry {
        name: "rumble",
        matches_any: rumble::MATCHES,
        run: rumble::parse,
    },
    ParserEntry {
        name: "dailymotion",
        matches_any: dailymotion::MATCHES,
        run: dailymotion::parse,
    },
    ParserEntry {
        name: "pluto_tv",
        matches_any: pluto_tv::MATCHES,
        run: pluto_tv::parse,
    },
    ParserEntry {
        name: "tubi",
        matches_any: tubi::MATCHES,
        run: tubi::parse,
    },
    ParserEntry {
        name: "grindr",
        matches_any: grindr::MATCHES,
        run: grindr::parse,
    },
    ParserEntry {
        name: "coffee_meets_bagel",
        matches_any: coffee_meets_bagel::MATCHES,
        run: coffee_meets_bagel::parse,
    },
    ParserEntry {
        name: "plenty_of_fish",
        matches_any: plenty_of_fish::MATCHES,
        run: plenty_of_fish::parse,
    },
    ParserEntry {
        name: "okcupid",
        matches_any: okcupid::MATCHES,
        run: okcupid::parse,
    },
    ParserEntry {
        name: "citizen_app",
        matches_any: citizen_app::MATCHES,
        run: citizen_app::parse,
    },
    ParserEntry {
        name: "nextdoor",
        matches_any: nextdoor::MATCHES,
        run: nextdoor::parse,
    },
    ParserEntry {
        name: "exodus_wallet",
        matches_any: exodus_wallet::MATCHES,
        run: exodus_wallet::parse,
    },
    ParserEntry {
        name: "electrum_wallet",
        matches_any: electrum_wallet::MATCHES,
        run: electrum_wallet::parse,
    },
    ParserEntry {
        name: "coinomi",
        matches_any: coinomi::MATCHES,
        run: coinomi::parse,
    },
    ParserEntry {
        name: "blockchain_wallet",
        matches_any: blockchain_wallet::MATCHES,
        run: blockchain_wallet::parse,
    },
    ParserEntry {
        name: "parkwhiz",
        matches_any: parkwhiz::MATCHES,
        run: parkwhiz::parse,
    },
    ParserEntry {
        name: "spothero",
        matches_any: spothero::MATCHES,
        run: spothero::parse,
    },
    ParserEntry {
        name: "sleep_cycle",
        matches_any: sleep_cycle::MATCHES,
        run: sleep_cycle::parse,
    },
    ParserEntry {
        name: "blood_pressure_app",
        matches_any: blood_pressure_app::MATCHES,
        run: blood_pressure_app::parse,
    },
    ParserEntry {
        name: "google_family_link",
        matches_any: google_family_link::MATCHES,
        run: google_family_link::parse,
    },
    ParserEntry {
        name: "find_my_kids",
        matches_any: find_my_kids::MATCHES,
        run: find_my_kids::parse,
    },
    ParserEntry {
        name: "life360_deep",
        matches_any: life360_deep::MATCHES,
        run: life360_deep::parse,
    },
    ParserEntry {
        name: "pillow_sleep",
        matches_any: pillow_sleep::MATCHES,
        run: pillow_sleep::parse,
    },
    ParserEntry {
        name: "slack_deep",
        matches_any: slack_deep::MATCHES,
        run: slack_deep::parse,
    },
    ParserEntry {
        name: "teams_deep",
        matches_any: teams_deep::MATCHES,
        run: teams_deep::parse,
    },
    ParserEntry {
        name: "zoom_deep",
        matches_any: zoom_deep::MATCHES,
        run: zoom_deep::parse,
    },
];
