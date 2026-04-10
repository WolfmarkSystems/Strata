//! iOS Bluetooth pairings — `com.apple.MobileBluetooth.devices.plist`,
//! `com.apple.MobileBluetooth.ledevices.other.db`.
//!
//! iOS persists every paired Bluetooth peripheral (BR/EDR + LE) in
//! one of these files. Per-device fields include the device name, MAC
//! address, vendor ID, and last seen time.
//!
//! Pulse v1.0 reports presence + size for the plist and a row count
//! for the SQLite store.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    n == "com.apple.mobilebluetooth.devices.plist"
        || n == "com.apple.mobilebluetooth.ledevices.other.db"
        || n == "com.apple.mobilebluetooth.ledevices.paired.db"
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if name.ends_with(".db") {
        if let Some(conn) = util::open_sqlite_ro(path) {
            let table_names: Vec<String> = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                .and_then(|mut s| {
                    let r = s.query_map([], |row| row.get::<_, String>(0))?;
                    Ok(r.flatten().collect::<Vec<_>>())
                })
                .unwrap_or_default();
            let mut total = 0_i64;
            for t in &table_names {
                total += util::count_rows(&conn, t);
            }
            out.push(ArtifactRecord {
                category: ArtifactCategory::NetworkArtifacts,
                subcategory: "Bluetooth devices".to_string(),
                timestamp: None,
                title: "iOS Bluetooth paired devices".to_string(),
                detail: format!(
                    "{} total rows across {} table(s) in {}",
                    total,
                    table_names.len(),
                    name
                ),
                source_path: source,
                forensic_value: ForensicValue::High,
                mitre_technique: Some("T1011".to_string()),
                is_suspicious: false,
                raw_data: None,
            });
            return out;
        }
    }

    out.push(ArtifactRecord {
        category: ArtifactCategory::NetworkArtifacts,
        subcategory: "Bluetooth devices".to_string(),
        timestamp: None,
        title: "iOS Bluetooth paired devices plist".to_string(),
        detail: format!(
            "Bluetooth pairings file present at {} ({} bytes)",
            source, size
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1011".to_string()),
        is_suspicious: false,
        raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_known_filenames() {
        assert!(matches(Path::new(
            "/var/wireless/Library/Preferences/com.apple.MobileBluetooth.devices.plist"
        )));
        assert!(matches(Path::new(
            "/var/wireless/Library/Databases/com.apple.MobileBluetooth.ledevices.other.db"
        )));
        assert!(!matches(Path::new("/var/wireless/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_plist_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.MobileBluetooth.devices.plist");
        std::fs::write(&p, b"bplist00fake").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("bytes"));
    }

    #[test]
    fn parses_db_table_counts() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.MobileBluetooth.ledevices.other.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE leperipherals (Uuid TEXT, Name TEXT)", []).unwrap();
        c.execute("INSERT INTO leperipherals VALUES ('uuid1', 'AirPods')", []).unwrap();
        c.execute("INSERT INTO leperipherals VALUES ('uuid2', 'Apple Watch')", []).unwrap();
        let recs = parse(&p);
        let r = recs.iter().find(|r| r.subcategory == "Bluetooth devices").unwrap();
        assert!(r.detail.contains("2 total rows"));
    }

    #[test]
    fn empty_file_returns_no_records() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.MobileBluetooth.devices.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
