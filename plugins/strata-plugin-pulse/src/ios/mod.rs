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
pub mod airbnb;
pub mod airdrop;
pub mod airpods;
pub mod alarms;
pub mod airprint;
pub mod alltrails;
pub mod appinstall;
pub mod appgroupcontainers;
pub mod applepay;
pub mod applenews;
pub mod appclips;
pub mod appletv;
pub mod apppermissions;
pub mod appstate;
pub mod authkit;
pub mod backgroundtasks;
pub mod bear;
pub mod biome;
pub mod biometrickit;
pub mod bluetooth;
pub mod books;
pub mod bumble;
pub mod calendar;
pub mod candycrush;
pub mod cashapp;
pub mod clashofclans;
pub mod coinbase;
pub mod cellular;
pub mod cloudkit;
pub mod cloudkitsync;
pub mod chrome;
pub mod compass;
pub mod continuity;
pub mod corespotlightindex;
pub mod crashlogs;
pub mod callhistory;
pub mod carekit;
pub mod carplay;
pub mod chase;
pub mod commlimits;
pub mod containermanager;
pub mod corelocationhist;
pub mod crashreporterdeep;
pub mod contacts;
pub mod cookies;
pub mod datadetectors;
pub mod datausage;
pub mod deletedapps;
pub mod deviceinfo;
pub mod devicelock;
pub mod diskusage;
pub mod dhcpleases;
pub mod disneyplus;
pub mod duetactivity;
pub mod discord;
pub mod emergencysos;
pub mod encryptednotes;
pub mod expedia;
pub mod facebook;
pub mod facetimedeep;
pub mod falldetection;
pub mod fileprovider;
pub mod findmy;
pub mod findmynetwork;
pub mod firefox;
pub mod fitbit;
pub mod focusfilters;
pub mod focusmode;
pub mod freeform;
pub mod gamecenter;
pub mod goodnotes;
pub mod googlemaps;
pub mod handoff;
pub mod health;
pub mod hearinghealth;
pub mod healthsamples;
pub mod healthsources;
pub mod healthecg;
pub mod healthworkouts;
pub mod hinge;
pub mod homekit;
pub mod hulu;
pub mod icloudbackup;
pub mod icloudkeyvalue;
pub mod icloudtabs;
pub mod biome_versions;
pub mod imessage_ios26;
pub mod imessageattach;
pub mod ios16_features;
pub mod message_retention;
pub mod shared_photo_library;
pub mod instagram;
pub mod interactionc;
pub mod itunesstore;
pub mod journal;
pub mod keychainmeta;
pub mod keyboard;
pub mod kik;
pub mod knowledgec;
pub mod line;
pub mod linkedin;
pub mod liveactivities;
pub mod location;
pub mod lyft;
pub mod magnifier;
pub mod mail;
pub mod mailattach;
pub mod managedconfig;
pub mod measure;
pub mod medialibrary;
pub mod maps;
pub mod minecraft;
pub mod mediaremote;
pub mod mobileasset;
pub mod mobileactivation;
pub mod mobilebackup;
pub mod nanotimekit;
pub mod nearbyinteraction;
pub mod netflix;
pub mod notes;
pub mod notion;
pub mod nsuserdefaults;
pub mod notifications;
pub mod obsidian;
pub mod amazonprime;
pub mod photoanalysis;
pub mod passkit;
pub mod photos;
pub mod pinterest;
pub mod pokemongo;
pub mod protonmail;
pub mod podcasts;
pub mod powerlog;
pub mod reddit;
pub mod reminders;
pub mod researchkit;
pub mod restrictions;
pub mod roblox;
pub mod robinhood;
pub mod safari;
pub mod safarisearches;
pub mod safaritabs;
pub mod screenrecording;
pub mod screentime;
pub mod screentimeapps;
pub mod sharinghistory;
pub mod shortcuts;
pub mod simtoolkit;
pub mod siri;
pub mod siminfo;
pub mod springboardarrange;
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
pub mod translate;
pub mod truststore;
pub mod threema;
pub mod twitch;
pub mod twitter;
pub mod viber;
pub mod uber;
pub mod uberdeep;
pub mod universalclipboard;
pub mod venmo;
pub mod venmoreceipts;
pub mod visionhealth;
pub mod voicememos;
pub mod vpnconfig;
pub mod vrbo;
pub mod voicemail;
pub mod wallet;
pub mod webclips;
pub mod watchconnectivity;
pub mod waze;
pub mod weather;
pub mod wechat;
pub mod wellsfargo;
pub mod whatsapp;
pub mod amongus;
pub mod wordle;
pub mod widgetkit;
pub mod wifi;
pub mod wifigeo;
pub mod workoutroutes;
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
    if siri::matches(path) {
        out.extend(siri::parse(path));
    }
    if wifigeo::matches(path) {
        out.extend(wifigeo::parse(path));
    }
    if safarisearches::matches(path) {
        out.extend(safarisearches::parse(path));
    }
    if icloudtabs::matches(path) {
        out.extend(icloudtabs::parse(path));
    }
    if healthecg::matches(path) {
        out.extend(healthecg::parse(path));
    }
    if managedconfig::matches(path) {
        out.extend(managedconfig::parse(path));
    }
    if devicelock::matches(path) {
        out.extend(devicelock::parse(path));
    }
    if mailattach::matches(path) {
        out.extend(mailattach::parse(path));
    }
    if appclips::matches(path) {
        out.extend(appclips::parse(path));
    }
    if widgetkit::matches(path) {
        out.extend(widgetkit::parse(path));
    }
    if backgroundtasks::matches(path) {
        out.extend(backgroundtasks::parse(path));
    }
    if workoutroutes::matches(path) {
        out.extend(workoutroutes::parse(path));
    }
    if falldetection::matches(path) {
        out.extend(falldetection::parse(path));
    }
    if airpods::matches(path) {
        out.extend(airpods::parse(path));
    }
    if applepay::matches(path) {
        out.extend(applepay::parse(path));
    }
    if passkit::matches(path) {
        out.extend(passkit::parse(path));
    }
    if corelocationhist::matches(path) {
        out.extend(corelocationhist::parse(path));
    }
    if gamecenter::matches(path) {
        out.extend(gamecenter::parse(path));
    }
    if screentimeapps::matches(path) {
        out.extend(screentimeapps::parse(path));
    }
    if commlimits::matches(path) {
        out.extend(commlimits::parse(path));
    }
    if nsuserdefaults::matches(path) {
        out.extend(nsuserdefaults::parse(path));
    }
    if cloudkitsync::matches(path) {
        out.extend(cloudkitsync::parse(path));
    }
    if watchconnectivity::matches(path) {
        out.extend(watchconnectivity::parse(path));
    }
    if applenews::matches(path) {
        out.extend(applenews::parse(path));
    }
    if books::matches(path) {
        out.extend(books::parse(path));
    }
    if translate::matches(path) {
        out.extend(translate::parse(path));
    }
    if weather::matches(path) {
        out.extend(weather::parse(path));
    }
    if compass::matches(path) {
        out.extend(compass::parse(path));
    }
    if measure::matches(path) {
        out.extend(measure::parse(path));
    }
    if magnifier::matches(path) {
        out.extend(magnifier::parse(path));
    }
    if airprint::matches(path) {
        out.extend(airprint::parse(path));
    }
    if handoff::matches(path) {
        out.extend(handoff::parse(path));
    }
    if universalclipboard::matches(path) {
        out.extend(universalclipboard::parse(path));
    }
    if continuity::matches(path) {
        out.extend(continuity::parse(path));
    }
    if truststore::matches(path) {
        out.extend(truststore::parse(path));
    }
    if mobileasset::matches(path) {
        out.extend(mobileasset::parse(path));
    }
    if biometrickit::matches(path) {
        out.extend(biometrickit::parse(path));
    }
    if authkit::matches(path) {
        out.extend(authkit::parse(path));
    }
    if corespotlightindex::matches(path) {
        out.extend(corespotlightindex::parse(path));
    }
    if nanotimekit::matches(path) {
        out.extend(nanotimekit::parse(path));
    }
    if datadetectors::matches(path) {
        out.extend(datadetectors::parse(path));
    }
    if springboardarrange::matches(path) {
        out.extend(springboardarrange::parse(path));
    }
    if encryptednotes::matches(path) {
        out.extend(encryptednotes::parse(path));
    }
    if deletedapps::matches(path) {
        out.extend(deletedapps::parse(path));
    }
    if simtoolkit::matches(path) {
        out.extend(simtoolkit::parse(path));
    }
    if vpnconfig::matches(path) {
        out.extend(vpnconfig::parse(path));
    }
    if alarms::matches(path) {
        out.extend(alarms::parse(path));
    }
    if keychainmeta::matches(path) {
        out.extend(keychainmeta::parse(path));
    }
    if diskusage::matches(path) {
        out.extend(diskusage::parse(path));
    }
    if appgroupcontainers::matches(path) {
        out.extend(appgroupcontainers::parse(path));
    }
    if icloudkeyvalue::matches(path) {
        out.extend(icloudkeyvalue::parse(path));
    }
    if sharinghistory::matches(path) {
        out.extend(sharinghistory::parse(path));
    }
    if mediaremote::matches(path) {
        out.extend(mediaremote::parse(path));
    }
    if nearbyinteraction::matches(path) {
        out.extend(nearbyinteraction::parse(path));
    }
    if freeform::matches(path) {
        out.extend(freeform::parse(path));
    }
    if journal::matches(path) {
        out.extend(journal::parse(path));
    }
    if focusfilters::matches(path) {
        out.extend(focusfilters::parse(path));
    }
    if liveactivities::matches(path) {
        out.extend(liveactivities::parse(path));
    }
    if airbnb::matches(path) {
        out.extend(airbnb::parse(path));
    }
    if expedia::matches(path) {
        out.extend(expedia::parse(path));
    }
    if researchkit::matches(path) {
        out.extend(researchkit::parse(path));
    }
    if carekit::matches(path) {
        out.extend(carekit::parse(path));
    }
    if hearinghealth::matches(path) {
        out.extend(hearinghealth::parse(path));
    }
    if chase::matches(path) {
        out.extend(chase::parse(path));
    }
    if wellsfargo::matches(path) {
        out.extend(wellsfargo::parse(path));
    }
    if roblox::matches(path) {
        out.extend(roblox::parse(path));
    }
    if minecraft::matches(path) {
        out.extend(minecraft::parse(path));
    }
    if amongus::matches(path) {
        out.extend(amongus::parse(path));
    }
    if wordle::matches(path) {
        out.extend(wordle::parse(path));
    }
    if notion::matches(path) {
        out.extend(notion::parse(path));
    }
    if obsidian::matches(path) {
        out.extend(obsidian::parse(path));
    }
    if bear::matches(path) {
        out.extend(bear::parse(path));
    }
    if goodnotes::matches(path) {
        out.extend(goodnotes::parse(path));
    }
    if vrbo::matches(path) {
        out.extend(vrbo::parse(path));
    }
    if visionhealth::matches(path) {
        out.extend(visionhealth::parse(path));
    }
    if uberdeep::matches(path) {
        out.extend(uberdeep::parse(path));
    }
    if venmoreceipts::matches(path) {
        out.extend(venmoreceipts::parse(path));
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
