//! ADB `.ab` backup parser (AND-4).
//!
//! Parses only the plain-text header — never attempts to decrypt or
//! decompress the tar stream. Extracts version, encryption state,
//! compression flag, and app package names when the stream is
//! unencrypted + uncompressed enough to scan byte-wise.
//!
//! MITRE: T1005, T1119.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::fs;
use std::io::Read;
use std::path::Path;
use strata_plugin_sdk::Artifact;

const AB_MAGIC: &[u8; 14] = b"ANDROID BACKUP";
const HEADER_SCAN_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbBackup {
    pub backup_path: String,
    pub version: u8,
    pub encrypted: bool,
    pub compressed: bool,
    pub encryption_algo: Option<String>,
    pub included_apps: Vec<String>,
    pub database_count: usize,
    pub total_file_count: usize,
    pub file_mtime: Option<DateTime<Utc>>,
}

pub fn is_ab_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.eq_ignore_ascii_case("ab"))
        .unwrap_or(false)
}

pub fn parse(path: &Path) -> Option<AdbBackup> {
    if !is_ab_path(path) {
        return None;
    }
    let mut f = fs::File::open(path).ok()?;
    let mut head = vec![0u8; HEADER_SCAN_BYTES.min(64 * 1024)];
    let n = f.read(&mut head).ok()?;
    head.truncate(n);
    if head.len() < AB_MAGIC.len() || !head.starts_with(AB_MAGIC) {
        return None;
    }
    // Header is exactly 4 newline-terminated plain-text lines; the
    // body after line 4 is the raw data stream (TAR or encrypted
    // blob). Read exactly 4 lines and stop.
    let mut lines: Vec<String> = Vec::new();
    let mut cursor = 0usize;
    let mut header_lines = 4usize;
    loop {
        if header_lines == 0 || cursor >= head.len() {
            break;
        }
        let remaining = &head[cursor..];
        let Some(nl) = remaining.iter().position(|b| *b == b'\n') else {
            break;
        };
        let line = String::from_utf8_lossy(&remaining[..nl]).to_string();
        lines.push(line);
        cursor += nl + 1;
        header_lines -= 1;
    }
    if lines.is_empty() {
        return None;
    }
    let version = lines
        .get(1)
        .and_then(|s| s.trim().parse::<u8>().ok())
        .unwrap_or(1);
    let compressed = lines
        .get(2)
        .and_then(|s| s.trim().parse::<u8>().ok())
        .map(|n| n != 0)
        .unwrap_or(false);
    let encryption_algo = lines.get(3).map(|s| s.trim().to_string());
    let encrypted = encryption_algo
        .as_deref()
        .map(|a| !a.eq_ignore_ascii_case("none"))
        .unwrap_or(false);
    let mtime = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(DateTime::<Utc>::from);
    let mut included_apps: Vec<String> = Vec::new();
    let mut database_count = 0usize;
    let mut total_file_count = 0usize;
    // If unencrypted + uncompressed, scan remaining bytes for tar
    // headers — tar entries contain the filename in ASCII.
    if !encrypted && !compressed {
        let remainder = &head[cursor..];
        let ascii_runs = extract_ascii_runs(remainder, 8);
        for run in ascii_runs {
            if let Some(pkg) = extract_apps_segment(&run) {
                if !included_apps.contains(&pkg) {
                    included_apps.push(pkg);
                }
            }
            if run.contains("_db/") || run.ends_with(".db") {
                database_count += 1;
            }
            total_file_count += 1;
        }
    }
    Some(AdbBackup {
        backup_path: path.to_string_lossy().to_string(),
        version,
        encrypted,
        compressed,
        encryption_algo,
        included_apps,
        database_count,
        total_file_count,
        file_mtime: mtime,
    })
}

fn extract_ascii_runs(bytes: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for &b in bytes {
        if (0x20..=0x7E).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min {
                if let Ok(s) = std::str::from_utf8(&current) {
                    out.push(s.to_string());
                }
            }
            current.clear();
        }
    }
    if current.len() >= min {
        if let Ok(s) = std::str::from_utf8(&current) {
            out.push(s.to_string());
        }
    }
    out
}

fn extract_apps_segment(s: &str) -> Option<String> {
    let pos = s.find("apps/")?;
    let rest = &s[pos + 5..];
    let end = rest.find('/').unwrap_or(rest.len());
    let pkg = rest[..end].trim();
    if pkg.is_empty() || !pkg.contains('.') {
        return None;
    }
    Some(pkg.to_string())
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let Some(backup) = parse(path) else {
        return Vec::new();
    };
    let mut a = if backup.encrypted {
        Artifact::new("ADB Backup Encrypted", &backup.backup_path)
    } else {
        Artifact::new("ADB Backup", &backup.backup_path)
    };
    a.timestamp = backup.file_mtime.map(|d| d.timestamp() as u64);
    a.add_field(
        "title",
        &format!(
            "ADB backup v{} ({}, {})",
            backup.version,
            if backup.encrypted { "encrypted" } else { "plaintext" },
            if backup.compressed { "compressed" } else { "uncompressed" }
        ),
    );
    a.add_field(
        "detail",
        &format!(
            "Version: {} | Encrypted: {} | Compressed: {} | Encryption: {} | Apps: {} | DBs: {} | Files: {}",
            backup.version,
            backup.encrypted,
            backup.compressed,
            backup.encryption_algo.as_deref().unwrap_or("-"),
            backup.included_apps.len(),
            backup.database_count,
            backup.total_file_count,
        ),
    );
    a.add_field(
        "file_type",
        if backup.encrypted {
            "ADB Backup Encrypted"
        } else {
            "ADB Backup"
        },
    );
    a.add_field("version", &backup.version.to_string());
    a.add_field("encrypted", if backup.encrypted { "true" } else { "false" });
    a.add_field("compressed", if backup.compressed { "true" } else { "false" });
    if let Some(e) = &backup.encryption_algo {
        a.add_field("encryption_algo", e);
    }
    for pkg in &backup.included_apps {
        a.add_field("app_package", pkg);
    }
    a.add_field("db_count", &backup.database_count.to_string());
    a.add_field("file_count", &backup.total_file_count.to_string());
    a.add_field("mitre", "T1005");
    a.add_field("mitre_secondary", "T1119");
    a.add_field("forensic_value", "High");
    vec![a]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_ab(dir: &tempfile::TempDir, lines: &[&str], body: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join("backup.ab");
        let mut bytes = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                bytes.push(b'\n');
            }
            bytes.extend_from_slice(line.as_bytes());
        }
        bytes.push(b'\n');
        bytes.extend_from_slice(body);
        fs::write(&path, &bytes).expect("w");
        path
    }

    #[test]
    fn is_ab_path_matches_extension_case_insensitive() {
        assert!(is_ab_path(Path::new("/x/y.ab")));
        assert!(is_ab_path(Path::new("/x/y.AB")));
        assert!(!is_ab_path(Path::new("/x/y.tar")));
    }

    #[test]
    fn parse_plaintext_header_extracts_version_flags() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_ab(
            &dir,
            &["ANDROID BACKUP", "3", "1", "none"],
            b"apps/com.example.app/_manifest stuff",
        );
        let backup = parse(&path).expect("parsed");
        assert_eq!(backup.version, 3);
        assert!(backup.compressed);
        assert!(!backup.encrypted);
    }

    #[test]
    fn parse_encrypted_marks_encrypted_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_ab(
            &dir,
            &["ANDROID BACKUP", "5", "1", "AES-256", "deadbeef", "cafebabe", "10000", "hash"],
            b"encrypted-stream-bytes",
        );
        let backup = parse(&path).expect("parsed");
        assert_eq!(backup.version, 5);
        assert!(backup.encrypted);
        assert_eq!(backup.encryption_algo.as_deref(), Some("AES-256"));
    }

    #[test]
    fn parse_unencrypted_uncompressed_enumerates_app_packages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = b"apps/com.example.alpha/files/data\napps/com.example.beta/_db/main.db\napps/com.example.alpha/files/again\n";
        let path = write_ab(
            &dir,
            &["ANDROID BACKUP", "1", "0", "none"],
            body,
        );
        let backup = parse(&path).expect("parsed");
        assert!(backup.included_apps.contains(&"com.example.alpha".to_string()));
        assert!(backup.included_apps.contains(&"com.example.beta".to_string()));
        assert!(backup.database_count >= 1);
    }

    #[test]
    fn parse_rejects_non_ab_magic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("notanab.ab");
        std::fs::write(&path, b"not-an-ab-file").expect("w");
        assert!(parse(&path).is_none());
    }
}
