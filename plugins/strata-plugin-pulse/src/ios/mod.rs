//! iOS artifact parsers.
//!
//! Each parser is a small, self-contained module with `matches()` and
//! `parse()` entry points and its own tests. [`dispatch`] runs every parser
//! that claims ownership of the given path and flattens their output.

use std::path::Path;

use strata_plugin_sdk::ArtifactRecord;

pub mod util;

pub mod accounts;
pub mod appinstall;
pub mod biome;
pub mod bluetooth;
pub mod calendar;
pub mod callhistory;
pub mod contacts;
pub mod discord;
pub mod findmy;
pub mod health;
pub mod icloudbackup;
pub mod keyboard;
pub mod knowledgec;
pub mod location;
pub mod mail;
pub mod maps;
pub mod notes;
pub mod notifications;
pub mod photos;
pub mod powerlog;
pub mod reminders;
pub mod safari;
pub mod screentime;
pub mod signal;
pub mod sms;
pub mod telegram;
pub mod voicemail;
pub mod wallet;
pub mod whatsapp;
pub mod wifi;

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
