//! iOS artifact parsers.
//!
//! Each parser is a small, self-contained module with `matches()` and
//! `parse()` entry points and its own tests. [`dispatch`] runs every parser
//! that claims ownership of the given path and flattens their output.

use std::path::Path;

use strata_plugin_sdk::ArtifactRecord;

pub mod util;

pub mod accessibility;
pub mod accounts;
pub mod aggregate;
pub mod airdrop;
pub mod alltrails;
pub mod appinstall;
pub mod appletv;
pub mod apppermissions;
pub mod appstate;
pub mod biome;
pub mod bluetooth;
pub mod bumble;
pub mod calendar;
pub mod candycrush;
pub mod cashapp;
pub mod clashofclans;
pub mod coinbase;
pub mod cellular;
pub mod cloudkit;
pub mod chrome;
pub mod crashlogs;
pub mod callhistory;
pub mod carplay;
pub mod containermanager;
pub mod crashreporterdeep;
pub mod contacts;
pub mod cookies;
pub mod datausage;
pub mod deviceinfo;
pub mod dhcpleases;
pub mod disneyplus;
pub mod duetactivity;
pub mod discord;
pub mod emergencysos;
pub mod facebook;
pub mod facetimedeep;
pub mod fileprovider;
pub mod findmy;
pub mod findmynetwork;
pub mod firefox;
pub mod fitbit;
pub mod focusmode;
pub mod googlemaps;
pub mod health;
pub mod healthsamples;
pub mod healthsources;
pub mod healthworkouts;
pub mod hinge;
pub mod homekit;
pub mod hulu;
pub mod icloudbackup;
pub mod imessageattach;
pub mod instagram;
pub mod interactionc;
pub mod itunesstore;
pub mod keyboard;
pub mod kik;
pub mod knowledgec;
pub mod line;
pub mod linkedin;
pub mod location;
pub mod lyft;
pub mod mail;
pub mod medialibrary;
pub mod maps;
pub mod mobileactivation;
pub mod mobilebackup;
pub mod netflix;
pub mod notes;
pub mod notifications;
pub mod amazonprime;
pub mod photoanalysis;
pub mod photos;
pub mod pinterest;
pub mod pokemongo;
pub mod protonmail;
pub mod podcasts;
pub mod powerlog;
pub mod reddit;
pub mod reminders;
pub mod restrictions;
pub mod robinhood;
pub mod safari;
pub mod safaritabs;
pub mod screenrecording;
pub mod screentime;
pub mod shortcuts;
pub mod siminfo;
pub mod spotlight;
pub mod spotify;
pub mod strava;
pub mod shutdownlog;
pub mod signal;
pub mod skype;
pub mod slack;
pub mod sms;
pub mod snapchat;
pub mod telegram;
pub mod tiktok;
pub mod tinder;
pub mod tcc;
pub mod teams;
pub mod textreplacement;
pub mod threema;
pub mod twitch;
pub mod twitter;
pub mod viber;
pub mod uber;
pub mod venmo;
pub mod voicememos;
pub mod voicemail;
pub mod wallet;
pub mod webclips;
pub mod waze;
pub mod wechat;
pub mod whatsapp;
pub mod wifi;
pub mod youtube;
pub mod zoom;

/// Run every registered parser against a single path. Parsers whose
/// `matches()` returns `false` are skipped. Parsers that match but find
/// nothing extractable return an empty vector and contribute nothing.
pub fn dispatch(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    if knowledgec::matches(path) {
        out.extend(knowledgec::parse(path));
    }
    if sms::matches(path) {
        out.extend(sms::parse(path));
    }
    if callhistory::matches(path) {
        out.extend(callhistory::parse(path));
    }
    if contacts::matches(path) {
        out.extend(contacts::parse(path));
    }
    if safari::matches(path) {
        out.extend(safari::parse(path));
    }
    if photos::matches(path) {
        out.extend(photos::parse(path));
    }
    if health::matches(path) {
        out.extend(health::parse(path));
    }
    if location::matches(path) {
        out.extend(location::parse(path));
    }
    if appinstall::matches(path) {
        out.extend(appinstall::parse(path));
    }
    if notes::matches(path) {
        out.extend(notes::parse(path));
    }
    if notifications::matches(path) {
        out.extend(notifications::parse(path));
    }
    if screentime::matches(path) {
        out.extend(screentime::parse(path));
    }
    if wifi::matches(path) {
        out.extend(wifi::parse(path));
    }
    if calendar::matches(path) {
        out.extend(calendar::parse(path));
    }
    if voicemail::matches(path) {
        out.extend(voicemail::parse(path));
    }
    if reminders::matches(path) {
        out.extend(reminders::parse(path));
    }
    if wallet::matches(path) {
        out.extend(wallet::parse(path));
    }
    if maps::matches(path) {
        out.extend(maps::parse(path));
    }
    if accounts::matches(path) {
        out.extend(accounts::parse(path));
    }
    if keyboard::matches(path) {
        out.extend(keyboard::parse(path));
    }
    if icloudbackup::matches(path) {
        out.extend(icloudbackup::parse(path));
    }
    if powerlog::matches(path) {
        out.extend(powerlog::parse(path));
    }
    if whatsapp::matches(path) {
        out.extend(whatsapp::parse(path));
    }
    if signal::matches(path) {
        out.extend(signal::parse(path));
    }
    if telegram::matches(path) {
        out.extend(telegram::parse(path));
    }
    if mail::matches(path) {
        out.extend(mail::parse(path));
    }
    if findmy::matches(path) {
        out.extend(findmy::parse(path));
    }
    if bluetooth::matches(path) {
        out.extend(bluetooth::parse(path));
    }
    if discord::matches(path) {
        out.extend(discord::parse(path));
    }
    if biome::matches(path) {
        out.extend(biome::parse(path));
    }
    if cellular::matches(path) {
        out.extend(cellular::parse(path));
    }
    if chrome::matches(path) {
        out.extend(chrome::parse(path));
    }
    if snapchat::matches(path) {
        out.extend(snapchat::parse(path));
    }
    if crashlogs::matches(path) {
        out.extend(crashlogs::parse(path));
    }
    if tiktok::matches(path) {
        out.extend(tiktok::parse(path));
    }
    if instagram::matches(path) {
        out.extend(instagram::parse(path));
    }
    if facebook::matches(path) {
        out.extend(facebook::parse(path));
    }
    if twitter::matches(path) {
        out.extend(twitter::parse(path));
    }
    if reddit::matches(path) {
        out.extend(reddit::parse(path));
    }
    if kik::matches(path) {
        out.extend(kik::parse(path));
    }
    if wechat::matches(path) {
        out.extend(wechat::parse(path));
    }
    if line::matches(path) {
        out.extend(line::parse(path));
    }
    if viber::matches(path) {
        out.extend(viber::parse(path));
    }
    if tinder::matches(path) {
        out.extend(tinder::parse(path));
    }
    if tcc::matches(path) {
        out.extend(tcc::parse(path));
    }
    if appstate::matches(path) {
        out.extend(appstate::parse(path));
    }
    if deviceinfo::matches(path) {
        out.extend(deviceinfo::parse(path));
    }
    if siminfo::matches(path) {
        out.extend(siminfo::parse(path));
    }
    if safaritabs::matches(path) {
        out.extend(safaritabs::parse(path));
    }
    if podcasts::matches(path) {
        out.extend(podcasts::parse(path));
    }
    if spotify::matches(path) {
        out.extend(spotify::parse(path));
    }
    if youtube::matches(path) {
        out.extend(youtube::parse(path));
    }
    if medialibrary::matches(path) {
        out.extend(medialibrary::parse(path));
    }
    if cookies::matches(path) {
        out.extend(cookies::parse(path));
    }
    if uber::matches(path) {
        out.extend(uber::parse(path));
    }
    if cashapp::matches(path) {
        out.extend(cashapp::parse(path));
    }
    if venmo::matches(path) {
        out.extend(venmo::parse(path));
    }
    if googlemaps::matches(path) {
        out.extend(googlemaps::parse(path));
    }
    if waze::matches(path) {
        out.extend(waze::parse(path));
    }
    if netflix::matches(path) {
        out.extend(netflix::parse(path));
    }
    if interactionc::matches(path) {
        out.extend(interactionc::parse(path));
    }
    if airdrop::matches(path) {
        out.extend(airdrop::parse(path));
    }
    if spotlight::matches(path) {
        out.extend(spotlight::parse(path));
    }
    if aggregate::matches(path) {
        out.extend(aggregate::parse(path));
    }
    if containermanager::matches(path) {
        out.extend(containermanager::parse(path));
    }
    if voicememos::matches(path) {
        out.extend(voicememos::parse(path));
    }
    if webclips::matches(path) {
        out.extend(webclips::parse(path));
    }
    if textreplacement::matches(path) {
        out.extend(textreplacement::parse(path));
    }
    if duetactivity::matches(path) {
        out.extend(duetactivity::parse(path));
    }
    if apppermissions::matches(path) {
        out.extend(apppermissions::parse(path));
    }
    if dhcpleases::matches(path) {
        out.extend(dhcpleases::parse(path));
    }
    if shutdownlog::matches(path) {
        out.extend(shutdownlog::parse(path));
    }
    if accessibility::matches(path) {
        out.extend(accessibility::parse(path));
    }
    if photoanalysis::matches(path) {
        out.extend(photoanalysis::parse(path));
    }
    if fileprovider::matches(path) {
        out.extend(fileprovider::parse(path));
    }
    if cloudkit::matches(path) {
        out.extend(cloudkit::parse(path));
    }
    if mobileactivation::matches(path) {
        out.extend(mobileactivation::parse(path));
    }
    if restrictions::matches(path) {
        out.extend(restrictions::parse(path));
    }
    if itunesstore::matches(path) {
        out.extend(itunesstore::parse(path));
    }
    if mobilebackup::matches(path) {
        out.extend(mobilebackup::parse(path));
    }
    if healthworkouts::matches(path) {
        out.extend(healthworkouts::parse(path));
    }
    if datausage::matches(path) {
        out.extend(datausage::parse(path));
    }
    if bumble::matches(path) {
        out.extend(bumble::parse(path));
    }
    if hinge::matches(path) {
        out.extend(hinge::parse(path));
    }
    if slack::matches(path) {
        out.extend(slack::parse(path));
    }
    if teams::matches(path) {
        out.extend(teams::parse(path));
    }
    if zoom::matches(path) {
        out.extend(zoom::parse(path));
    }
    if linkedin::matches(path) {
        out.extend(linkedin::parse(path));
    }
    if skype::matches(path) {
        out.extend(skype::parse(path));
    }
    if threema::matches(path) {
        out.extend(threema::parse(path));
    }
    if protonmail::matches(path) {
        out.extend(protonmail::parse(path));
    }
    if pokemongo::matches(path) {
        out.extend(pokemongo::parse(path));
    }
    if clashofclans::matches(path) {
        out.extend(clashofclans::parse(path));
    }
    if candycrush::matches(path) {
        out.extend(candycrush::parse(path));
    }
    if robinhood::matches(path) {
        out.extend(robinhood::parse(path));
    }
    if coinbase::matches(path) {
        out.extend(coinbase::parse(path));
    }
    if hulu::matches(path) {
        out.extend(hulu::parse(path));
    }
    if disneyplus::matches(path) {
        out.extend(disneyplus::parse(path));
    }
    if amazonprime::matches(path) {
        out.extend(amazonprime::parse(path));
    }
    if twitch::matches(path) {
        out.extend(twitch::parse(path));
    }
    if healthsamples::matches(path) {
        out.extend(healthsamples::parse(path));
    }
    if healthsources::matches(path) {
        out.extend(healthsources::parse(path));
    }
    if fitbit::matches(path) {
        out.extend(fitbit::parse(path));
    }
    if strava::matches(path) {
        out.extend(strava::parse(path));
    }
    if alltrails::matches(path) {
        out.extend(alltrails::parse(path));
    }
    if appletv::matches(path) {
        out.extend(appletv::parse(path));
    }
    if lyft::matches(path) {
        out.extend(lyft::parse(path));
    }
    if pinterest::matches(path) {
        out.extend(pinterest::parse(path));
    }
    if firefox::matches(path) {
        out.extend(firefox::parse(path));
    }
    if carplay::matches(path) {
        out.extend(carplay::parse(path));
    }
    if homekit::matches(path) {
        out.extend(homekit::parse(path));
    }
    if shortcuts::matches(path) {
        out.extend(shortcuts::parse(path));
    }
    if screenrecording::matches(path) {
        out.extend(screenrecording::parse(path));
    }
    if focusmode::matches(path) {
        out.extend(focusmode::parse(path));
    }
    if emergencysos::matches(path) {
        out.extend(emergencysos::parse(path));
    }
    if crashreporterdeep::matches(path) {
        out.extend(crashreporterdeep::parse(path));
    }
    if imessageattach::matches(path) {
        out.extend(imessageattach::parse(path));
    }
    if facetimedeep::matches(path) {
        out.extend(facetimedeep::parse(path));
    }
    if findmynetwork::matches(path) {
        out.extend(findmynetwork::parse(path));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn dispatch_ignores_unknown_files() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("random.txt");
        std::fs::write(&p, b"nothing to see").unwrap();
        let records = dispatch(&p);
        assert!(records.is_empty());
    }

    #[test]
    fn dispatch_returns_vec_for_nonexistent_path() {
        let records = dispatch(Path::new("/does/not/exist/sms.db"));
        assert!(records.is_empty());
    }
}
