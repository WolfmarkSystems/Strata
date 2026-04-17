//! Rosetta 2 translation-cache artifacts (MAC-8).
//!
//! On Apple Silicon, Rosetta caches translated x86_64 binaries under
//! `~/Library/Application Support/com.apple.dt.Rosetta/` and
//! `/var/db/oah/`. A cache entry whose original binary no longer
//! exists is strong evidence that a deleted x86_64 binary executed.
//!
//! MITRE: T1070 (indicator removal), T1027.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosettaArtifact {
    pub cache_path: String,
    pub binary_hash: String,
    pub cache_size: u64,
    pub created: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub original_binary_exists: bool,
    pub original_binary_path: Option<String>,
}

pub fn is_rosetta_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.contains("com.apple.dt.rosetta") || lower.contains("/var/db/oah/")
}

pub fn binary_hash_from_filename(name: &str) -> String {
    // Rosetta cache filenames look like `{hex-hash}.aot`. Strip the
    // extension and return whatever remains.
    let stripped = name
        .rsplit_once('.')
        .map(|(l, _)| l.to_string())
        .unwrap_or_else(|| name.to_string());
    stripped
}

pub fn scan(path: &Path, search_roots: &[&Path]) -> Option<RosettaArtifact> {
    if !is_rosetta_path(path) {
        return None;
    }
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let name = path.file_name()?.to_str()?.to_string();
    let hash = binary_hash_from_filename(&name);
    let cache_size = meta.len();
    let created = meta.created().ok().map(DateTime::<Utc>::from);
    let last_used = meta.modified().ok().map(DateTime::<Utc>::from);
    let (original_binary_path, original_binary_exists) = find_original_binary(&hash, search_roots);
    Some(RosettaArtifact {
        cache_path: path.to_string_lossy().to_string(),
        binary_hash: hash,
        cache_size,
        created,
        last_used,
        original_binary_path: original_binary_path.map(|p| p.to_string_lossy().to_string()),
        original_binary_exists,
    })
}

fn find_original_binary(hash: &str, search_roots: &[&Path]) -> (Option<PathBuf>, bool) {
    for root in search_roots {
        if let Some(found) = walk_and_match(root, hash) {
            return (Some(found), true);
        }
    }
    (None, false)
}

fn walk_and_match(dir: &Path, hash: &str) -> Option<PathBuf> {
    let read = fs::read_dir(dir).ok()?;
    for entry in read.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if let Some(found) = walk_and_match(&p, hash) {
                return Some(found);
            }
        } else if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if name.contains(hash) {
                return Some(p);
            }
        }
    }
    None
}

pub fn check_suspicion(art: &RosettaArtifact) -> Option<String> {
    if !art.original_binary_exists {
        return Some(format!(
            "Rosetta cache exists but original x86_64 binary is missing (hash {})",
            art.binary_hash
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_rosetta_path_matches_rosetta_and_oah() {
        assert!(is_rosetta_path(Path::new(
            "/Users/me/Library/Application Support/com.apple.dt.Rosetta/ABC.aot"
        )));
        assert!(is_rosetta_path(Path::new("/var/db/oah/translation.bin")));
        assert!(!is_rosetta_path(Path::new("/tmp/other")));
    }

    #[test]
    fn binary_hash_from_filename_strips_extension() {
        assert_eq!(binary_hash_from_filename("DEADBEEFCAFE.aot"), "DEADBEEFCAFE");
        assert_eq!(binary_hash_from_filename("nohex"), "nohex");
    }

    #[test]
    fn scan_reports_missing_original_binary_as_suspicious() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rosetta = dir
            .path()
            .join("Library")
            .join("Application Support")
            .join("com.apple.dt.Rosetta");
        std::fs::create_dir_all(&rosetta).expect("mkdirs");
        let cache_path = rosetta.join("FAKEHASH.aot");
        std::fs::write(&cache_path, b"cache-contents").expect("w");
        let search_root = dir.path().join("elsewhere");
        std::fs::create_dir_all(&search_root).expect("mkdirs");
        let art = scan(&cache_path, &[&search_root]).expect("some");
        assert!(!art.original_binary_exists);
        assert!(check_suspicion(&art).is_some());
    }

    #[test]
    fn scan_finds_original_binary_in_search_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rosetta = dir.path().join("com.apple.dt.Rosetta");
        std::fs::create_dir_all(&rosetta).expect("mkdirs");
        let cache_path = rosetta.join("HASHABC.aot");
        std::fs::write(&cache_path, b"c").expect("w");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("mkdirs");
        let orig = bin_dir.join("HASHABC");
        std::fs::write(&orig, b"binary").expect("w");
        let art = scan(&cache_path, &[&bin_dir]).expect("some");
        assert!(art.original_binary_exists);
        assert!(check_suspicion(&art).is_none());
    }

    #[test]
    fn scan_returns_none_for_non_rosetta_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("unrelated.bin");
        std::fs::write(&path, b"x").expect("w");
        assert!(scan(&path, &[]).is_none());
    }
}
