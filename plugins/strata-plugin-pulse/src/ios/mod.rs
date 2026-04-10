//! iOS artifact parsers.
//!
//! Each parser is a small, self-contained module with `matches()` and
//! `parse()` entry points and its own tests. [`dispatch`] runs every parser
//! that claims ownership of the given path and flattens their output.

use std::path::Path;

use strata_plugin_sdk::ArtifactRecord;

pub mod util;

pub mod appinstall;
pub mod callhistory;
pub mod contacts;
pub mod health;
pub mod knowledgec;
pub mod location;
pub mod notes;
pub mod photos;
pub mod safari;
pub mod sms;

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
