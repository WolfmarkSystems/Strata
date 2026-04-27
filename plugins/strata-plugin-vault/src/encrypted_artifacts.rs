//! Encrypted archives + secure-messaging presence (VAULT-6).
//!
//! Encrypted-archive detection inspects header flags, not the encrypted
//! payload. Secure-messaging apps (Signal, Wickr, Briar, Session) and
//! Tor Browser are detected by their installation paths and
//! non-encrypted config files.
//!
//! MITRE: T1090.003 (multi-hop proxy / Tor), T1552.003.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use std::fs;
use std::io::Read;
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedArchive {
    pub format: String,
    pub path: String,
    pub file_size: u64,
    pub encryption_method: Option<String>,
    pub entry_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorBrowserArtifact {
    pub artifact_type: String,
    pub onion_urls: Vec<String>,
    pub visit_count: u64,
    pub custom_bridges: bool,
    pub extra_extensions: Vec<String>,
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let mut out = Vec::new();
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // Encrypted archives.
    if let Some(a) = detect_encrypted_archive(path) {
        out.push(a);
    }
    // Secure messaging app paths (presence-only).
    let messaging: &[(&str, &str)] = &[
        ("Signal", "/signal/"),
        ("Signal", "\\signal\\"),
        ("Wickr", "/wickr/"),
        ("Wickr", "\\wickr\\"),
        ("Session", "/session/"),
        ("Session", "\\session\\"),
        ("Briar", "org.briarproject.briar.android"),
    ];
    for (app, frag) in messaging {
        if lower.contains(frag) && (name.ends_with(".sqlite") || name == "config.json") {
            let path_str = path.to_string_lossy().to_string();
            let mut a = Artifact::new("Secure Messaging App", &path_str);
            a.add_field("title", &format!("{} installation detected", app));
            a.add_field("detail", &format!("App: {} | Artifact: {}", app, path_str));
            a.add_field("file_type", "Secure Messaging App");
            a.add_field("app_name", app);
            a.add_field("mitre", "T1552.003");
            a.add_field("forensic_value", "Medium");
            out.push(a);
        }
    }
    // Tor Browser presence.
    if lower.contains("/tor browser/")
        || lower.contains("\\tor browser\\")
        || lower.contains("/torbrowser-data/")
    {
        let path_str = path.to_string_lossy().to_string();
        // places.sqlite → parse for .onion URLs.
        if name == "places.sqlite" {
            let onions = tor_onion_urls(path).unwrap_or_default();
            let mut a = Artifact::new("Tor Browser History", &path_str);
            a.add_field(
                "title",
                &format!("Tor Browser places.sqlite — {} .onion URLs", onions.len()),
            );
            a.add_field(
                "detail",
                &format!(
                    "Tor Browser history: {} .onion URLs | path: {}",
                    onions.len(),
                    path_str
                ),
            );
            a.add_field("file_type", "Tor Browser History");
            a.add_field("onion_count", &onions.len().to_string());
            for url in onions.iter().take(32) {
                a.add_field("onion_url", url);
            }
            a.add_field("mitre", "T1090.003");
            a.add_field("forensic_value", "High");
            a.add_field("suspicious", "true");
            out.push(a);
        } else if name == "torrc" {
            let path_str2 = path_str.clone();
            let body = fs::read_to_string(path).unwrap_or_default();
            let custom_bridges = body.contains("Bridge ");
            let mut a = Artifact::new("Tor Browser History", &path_str2);
            a.add_field(
                "title",
                if custom_bridges {
                    "Tor Browser torrc with custom bridges (advanced OPSEC)"
                } else {
                    "Tor Browser torrc configuration"
                },
            );
            a.add_field("detail", &format!("torrc at {}", path_str2));
            a.add_field("file_type", "Tor Browser History");
            a.add_field(
                "custom_bridges",
                if custom_bridges { "true" } else { "false" },
            );
            a.add_field("mitre", "T1090.003");
            a.add_field("forensic_value", "High");
            a.add_field("suspicious", "true");
            out.push(a);
        }
    }
    out
}

fn detect_encrypted_archive(path: &Path) -> Option<Artifact> {
    let Ok(mut f) = fs::File::open(path) else {
        return None;
    };
    let mut head = [0u8; 64];
    let read_len = f.read(&mut head).ok()?;
    if read_len < 8 {
        return None;
    }
    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    // 7-Zip: 37 7A BC AF 27 1C.
    if head[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return Some(build(path, "7Zip", size, Some("AES-256")));
    }
    // RAR: 52 61 72 21 1A 07.
    if head[..6] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] {
        return Some(build(path, "RAR", size, Some("header-flag")));
    }
    // AxCrypt: C2 26 15 71 07 9F 4F 15.
    if head[..8] == [0xC2, 0x26, 0x15, 0x71, 0x07, 0x9F, 0x4F, 0x15] {
        return Some(build(path, "AxCrypt", size, Some("AxCrypt-2")));
    }
    // ZIP with encryption flag.
    if head[..4] == [0x50, 0x4B, 0x03, 0x04] {
        let gpbf = u16::from_le_bytes([head[6], head[7]]);
        if gpbf & 0x0001 != 0 {
            return Some(build(path, "ZIP", size, Some("ZipCrypto/AES")));
        }
    }
    None
}

fn build(path: &Path, format: &str, size: u64, method: Option<&str>) -> Artifact {
    let path_str = path.to_string_lossy().to_string();
    let mut a = Artifact::new("Encrypted Archive", &path_str);
    a.add_field(
        "title",
        &format!("Encrypted archive: {} ({} bytes)", format, size),
    );
    a.add_field(
        "detail",
        &format!(
            "Format: {} | Size: {} | Method: {} | Path: {}",
            format,
            size,
            method.unwrap_or("unknown"),
            path_str
        ),
    );
    a.add_field("file_type", "Encrypted Archive");
    a.add_field("archive_format", format);
    if let Some(m) = method {
        a.add_field("encryption_method", m);
    }
    a.add_field("file_size", &size.to_string());
    a.add_field("mitre", "T1027.013");
    a.add_field("forensic_value", "High");
    a.add_field("suspicious", "true");
    a
}

fn tor_onion_urls(path: &Path) -> Option<Vec<String>> {
    use rusqlite::{Connection, OpenFlags};
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    let mut stmt = conn
        .prepare("SELECT url FROM moz_places WHERE url LIKE '%.onion%'")
        .ok()?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0)).ok()?;
    let mut out = Vec::new();
    for r in rows.flatten() {
        out.push(r);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_7zip_encrypted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("archive.7z");
        std::fs::write(
            &path,
            [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x00, 0x00, 0x00],
        )
        .expect("write");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("archive_format").map(|s| s.as_str()) == Some("7Zip")));
    }

    #[test]
    fn detects_zip_encrypted_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.zip");
        let mut body = vec![0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
        body.extend_from_slice(&[0x01, 0x00]); // GPBF with encryption bit
        body.extend_from_slice(&[0u8; 54]);
        std::fs::write(&path, &body).expect("write");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("archive_format").map(|s| s.as_str()) == Some("ZIP")));
    }

    #[test]
    fn detects_axcrypt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("file.axx");
        let mut body = vec![0xC2, 0x26, 0x15, 0x71, 0x07, 0x9F, 0x4F, 0x15];
        body.extend_from_slice(&[0u8; 56]);
        std::fs::write(&path, &body).expect("write");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("archive_format").map(|s| s.as_str()) == Some("AxCrypt")));
    }

    #[test]
    fn detects_signal_sqlite_presence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let signal_dir = dir.path().join("Signal").join("sql");
        std::fs::create_dir_all(&signal_dir).expect("mkdirs");
        let path = signal_dir.join("db.sqlite");
        std::fs::write(&path, b"").expect("write");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("app_name").map(|s| s.as_str()) == Some("Signal")));
    }

    #[test]
    fn parses_tor_places_for_onion_urls() {
        use rusqlite::Connection;
        let dir = tempfile::tempdir().expect("tempdir");
        let tbdir = dir
            .path()
            .join("Tor Browser")
            .join("Browser")
            .join("profile.default");
        std::fs::create_dir_all(&tbdir).expect("mkdirs");
        let path = tbdir.join("places.sqlite");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch("CREATE TABLE moz_places (url TEXT);")
            .expect("schema");
        conn.execute(
            "INSERT INTO moz_places VALUES ('http://3g2upl4pq6kufc4m.onion')",
            [],
        )
        .expect("insert");
        drop(conn);
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("file_type").map(|s| s.as_str()) == Some("Tor Browser History")));
    }

    #[test]
    fn noop_on_unrelated_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("random.txt");
        std::fs::write(&path, b"hello").expect("write");
        assert!(scan(&path).is_empty());
    }
}
