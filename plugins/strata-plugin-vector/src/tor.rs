//! Tor, I2P, proxy-chain, and VPN artifact detection.

use chrono::{NaiveDateTime, TimeZone, Utc};
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorHistoryEntry {
    pub url: String,
    pub title: Option<String>,
    pub visit_date: i64,
    pub is_onion: bool,
    pub onion_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorStateFile {
    pub last_written: Option<i64>,
    pub entry_guards: Vec<String>,
    pub bw_read_total_kb: Option<u64>,
    pub bw_write_total_kb: Option<u64>,
}

pub fn is_onion_url(url: &str) -> bool {
    url.to_ascii_lowercase().contains(".onion")
}

pub fn onion_address(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();
    let pos = lower.find(".onion")?;
    let before = &url[..pos];
    let start = before
        .rfind(|c: char| !c.is_ascii_alphanumeric())
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let host = url.get(start..pos + ".onion".len())?;
    (!host.is_empty()).then(|| host.to_string())
}

pub fn parse_tor_state(content: &str) -> TorStateFile {
    let mut last_written = None;
    let mut entry_guards = Vec::new();
    let mut bw_read_total_kb = None;
    let mut bw_write_total_kb = None;

    for line in content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("LastWritten ") {
            last_written = parse_tor_datetime(rest.trim());
        } else if t.starts_with("EntryGuard ") || t.starts_with("Guard ") {
            entry_guards.push(t.to_string());
        } else if let Some(rest) = t.strip_prefix("BWHistoryReadValues ") {
            bw_read_total_kb = Some(sum_csv_u64(rest));
        } else if let Some(rest) = t.strip_prefix("BWHistoryWriteValues ") {
            bw_write_total_kb = Some(sum_csv_u64(rest));
        }
    }

    TorStateFile {
        last_written,
        entry_guards,
        bw_read_total_kb,
        bw_write_total_kb,
    }
}

pub fn dark_web_advisory(onion_urls: &[String], source: &str) -> Option<Artifact> {
    if onion_urls.is_empty() {
        return None;
    }
    let mut a = Artifact::new("Tor Dark Web Advisory", source);
    a.add_field("title", "DARK WEB ACCESS CONFIRMED");
    a.add_field(
        "detail",
        &format!(
            "Tor Browser history contains {} .onion URL(s). Examiner review required.",
            onion_urls.len()
        ),
    );
    a.add_field("file_type", "Tor Dark Web Advisory");
    a.add_field(
        "advisory_notice",
        "DARK WEB ACCESS confirmed by Tor Browser .onion history.",
    );
    a.add_field("onion_count", &onion_urls.len().to_string());
    for url in onion_urls.iter().take(32) {
        a.add_field("onion_url", url);
    }
    a.add_field("mitre", "T1090.003");
    a.add_field("forensic_value", "Critical");
    a.add_field("suspicious", "true");
    Some(a)
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut out = Vec::new();

    if is_tor_profile_path(&lower) {
        if name == "places.sqlite" {
            let onions = tor_places_onion_urls(path);
            if let Some(a) = dark_web_advisory(&onions, &path.to_string_lossy()) {
                out.push(a);
            }
        } else if matches!(
            name.as_str(),
            "torrc" | "cached-microdesc-consensus" | "cached-certs" | "key4.db" | "logins.json"
        ) {
            out.push(presence_artifact(
                "Tor Browser Artifact",
                "Tor Browser profile artifact",
                path,
            ));
        } else if name == "state" {
            if let Ok(content) = std::fs::read_to_string(path) {
                let state = parse_tor_state(&content);
                let mut a = presence_artifact("Tor State File", "Tor state file parsed", path);
                if let Some(ts) = state.last_written {
                    a.timestamp = Some(ts as u64);
                    a.add_field("last_written_unix", &ts.to_string());
                }
                a.add_field("entry_guard_count", &state.entry_guards.len().to_string());
                if let Some(kb) = state.bw_read_total_kb {
                    a.add_field("bw_read_total_kb", &kb.to_string());
                }
                if let Some(kb) = state.bw_write_total_kb {
                    a.add_field("bw_write_total_kb", &kb.to_string());
                }
                out.push(a);
            }
        }
    }

    if (lower.contains("/.i2p/") || lower.contains("/i2p/") || lower.contains("\\i2p\\"))
        && (matches!(name.as_str(), "router.config" | "wrapper.log")
            || lower.contains("/addressbook/"))
    {
        out.push(presence_artifact(
            "I2P Artifact",
            "I2P installation artifact",
            path,
        ));
    }

    if name == "proxychains.conf" || lower.contains("/.proxychains/") {
        out.push(presence_artifact(
            "ProxyChains Configuration",
            "ProxyChains anonymization configuration",
            path,
        ));
    }

    if lower.contains("openvpn")
        || lower.contains("nordvpn")
        || lower.contains("protonvpn")
        || lower.contains("mullvad vpn")
        || name.ends_with(".ovpn")
    {
        out.push(presence_artifact(
            "VPN Artifact",
            "VPN client/configuration artifact",
            path,
        ));
    }

    out
}

fn is_tor_profile_path(lower: &str) -> bool {
    lower.contains("/tor browser/")
        || lower.contains("/torbrowser-data/")
        || lower.contains("/browser/torbrowser/data/browser/")
        || lower.ends_with("/tor")
        || lower.ends_with("/tor.exe")
        || lower.ends_with("/torrc")
}

fn presence_artifact(file_type: &str, detail: &str, path: &Path) -> Artifact {
    let mut a = Artifact::new(file_type, &path.to_string_lossy());
    a.add_field("title", file_type);
    a.add_field("detail", detail);
    a.add_field("file_type", file_type);
    a.add_field("mitre", "T1090.003");
    a.add_field("forensic_value", "High");
    a.add_field("suspicious", "true");
    a
}

fn tor_places_onion_urls(path: &Path) -> Vec<String> {
    use rusqlite::{Connection, OpenFlags};
    let Ok(conn) = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return Vec::new();
    };
    let Ok(mut stmt) = conn.prepare("SELECT url FROM moz_places WHERE url LIKE '%.onion%'") else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) else {
        return Vec::new();
    };
    rows.flatten().collect()
}

fn parse_tor_datetime(value: &str) -> Option<i64> {
    let ndt = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").ok()?;
    Some(Utc.from_utc_datetime(&ndt).timestamp())
}

fn sum_csv_u64(value: &str) -> u64 {
    value
        .split(',')
        .filter_map(|part| part.trim().parse::<u64>().ok())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_url_detected() {
        assert!(is_onion_url(
            "http://facebookwkhpilnemxj7ascrwwwi72yxv7zntv5srhd6j4zmgg3pryd.onion/"
        ));
        assert!(!is_onion_url("https://facebook.com/"));
    }

    #[test]
    fn tor_state_last_written_parsed() {
        let content = "LastWritten 2025-11-25 09:00:00\nEntryGuard node1 key\n";
        let state = parse_tor_state(content);
        assert!(state.last_written.is_some());
        assert_eq!(state.entry_guards.len(), 1);
    }

    #[test]
    fn tor_state_bandwidth_parsed() {
        let content = "BWHistoryReadValues 1024,2048,512\nBWHistoryWriteValues 512,1024,256\n";
        let state = parse_tor_state(content);
        assert_eq!(state.bw_read_total_kb, Some(3584));
        assert_eq!(state.bw_write_total_kb, Some(1792));
    }

    #[test]
    fn dark_web_critical_advisory_emitted() {
        let urls = vec!["http://abc123.onion/login".to_string()];
        let art = dark_web_advisory(&urls, "/case/places.sqlite").expect("advisory");
        assert_eq!(
            art.data.get("forensic_value").map(String::as_str),
            Some("Critical")
        );
        assert!(art
            .data
            .get("advisory_notice")
            .map(|s| s.contains("DARK WEB ACCESS"))
            .unwrap_or(false));
    }

    #[test]
    fn vector_tor_module_detects_onion_url() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "strata_tor_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let profile = root.join("TorBrowser-Data/Browser/profile.default");
        std::fs::create_dir_all(&profile)?;
        let db_path = profile.join("places.sqlite");
        {
            let conn = rusqlite::Connection::open(&db_path)?;
            conn.execute("CREATE TABLE moz_places (url TEXT)", [])?;
            conn.execute(
                "INSERT INTO moz_places (url) VALUES (?1)",
                ["http://examplehiddenservice.onion/login"],
            )?;
        }

        let artifacts = scan(&db_path);
        std::fs::remove_dir_all(&root)?;

        assert!(artifacts.iter().any(|artifact| {
            artifact
                .data
                .get("title")
                .map(|title| title == "DARK WEB ACCESS CONFIRMED")
                .unwrap_or(false)
        }));
        Ok(())
    }
}
