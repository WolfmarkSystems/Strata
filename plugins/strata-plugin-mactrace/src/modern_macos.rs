//! Modern macOS (Ventura 13 through Tahoe 26) artifact parsers.
//!
//! Four high-value artifacts that are either new in macOS 13+ or take a
//! different form on modern versions:
//!
//! | Filename                                                | Variant                                     |
//! |---------------------------------------------------------|---------------------------------------------|
//! | `BackgroundItems-v8.db`                                 | [`ModernMacosRecord::BackgroundTask`]       |
//! | `RMAdminStore-Local.sqlite` (Screen Time)               | [`ModernMacosRecord::ScreenTime`]           |
//! | `InstallHistory.plist`                                  | [`ModernMacosRecord::InstallHistory`]       |
//! | `netusage.sqlite`                                       | [`ModernMacosRecord::NetworkUsage`]         |
//!
//! ## MITRE ATT&CK
//! * **T1547.011** — Background Task Management persistence.
//! * **T1059** — Screen Time app-usage evidence (post-execution).
//! * **T1072** — Install History (software deployment tooling).
//! * **T1071** — Network Usage (application-layer protocol telemetry).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use plist::Value;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// CoreData / Mach absolute-time epoch offset from Unix epoch (seconds).
const APPLE_EPOCH_OFFSET: i64 = 978_307_200;

/// Hard cap on rows materialised per database.
const MAX_RECORDS: usize = 500_000;

/// Which flavour of modern-macOS artifact a record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModernMacosArtifactType {
    /// `BackgroundItems-v8.db` — macOS 13+ Background Task Management.
    BackgroundTask,
    /// `RMAdminStore-Local.sqlite` — Screen Time per-app usage totals.
    ScreenTime,
    /// `/Library/Receipts/InstallHistory.plist` — software install log.
    InstallHistory,
    /// `netusage.sqlite` — per-process WiFi / Ethernet byte counters.
    NetworkUsage,
}

impl ModernMacosArtifactType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModernMacosArtifactType::BackgroundTask => "BackgroundTask",
            ModernMacosArtifactType::ScreenTime => "ScreenTime",
            ModernMacosArtifactType::InstallHistory => "InstallHistory",
            ModernMacosArtifactType::NetworkUsage => "NetworkUsage",
        }
    }

    pub fn mitre(&self) -> &'static str {
        match self {
            ModernMacosArtifactType::BackgroundTask => "T1547.011",
            ModernMacosArtifactType::ScreenTime => "T1059",
            ModernMacosArtifactType::InstallHistory => "T1072",
            ModernMacosArtifactType::NetworkUsage => "T1071",
        }
    }

    /// Default forensic value tier. Callers may override — a BackgroundTask
    /// record for a non-Apple unapproved entry is upgraded to `"High"`.
    pub fn forensic_value(&self) -> &'static str {
        match self {
            ModernMacosArtifactType::BackgroundTask | ModernMacosArtifactType::NetworkUsage => {
                "High"
            }
            _ => "Medium",
        }
    }

    /// Classify a file path to a modern-macOS artifact type. Returns
    /// `None` for paths we do not handle.
    pub fn from_path(path: &Path) -> Option<ModernMacosArtifactType> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let full = path.to_string_lossy().to_ascii_lowercase();
        if name.starts_with("backgrounditems-v") && name.ends_with(".db") {
            return Some(ModernMacosArtifactType::BackgroundTask);
        }
        if name == "rmadminstore-local.sqlite" {
            return Some(ModernMacosArtifactType::ScreenTime);
        }
        if name == "installhistory.plist" {
            return Some(ModernMacosArtifactType::InstallHistory);
        }
        if name == "netusage.sqlite"
            || (name.starts_with("netusage") && full.contains("/networkd/"))
        {
            return Some(ModernMacosArtifactType::NetworkUsage);
        }
        None
    }
}

/// One record extracted from a modern-macOS artifact source. The
/// variant-shaped payload keeps each flavour's fields fully typed.
#[derive(Debug, Clone, PartialEq)]
pub enum ModernMacosRecord {
    BackgroundTask(BackgroundTaskEntry),
    ScreenTime(ScreenTimeEntry),
    InstallHistory(InstallHistoryEntry),
    NetworkUsage(NetworkUsageEntry),
}

impl ModernMacosRecord {
    pub fn artifact_type(&self) -> ModernMacosArtifactType {
        match self {
            ModernMacosRecord::BackgroundTask(_) => ModernMacosArtifactType::BackgroundTask,
            ModernMacosRecord::ScreenTime(_) => ModernMacosArtifactType::ScreenTime,
            ModernMacosRecord::InstallHistory(_) => ModernMacosArtifactType::InstallHistory,
            ModernMacosRecord::NetworkUsage(_) => ModernMacosArtifactType::NetworkUsage,
        }
    }

    /// Best-effort event timestamp for timeline placement.
    pub fn timestamp(&self) -> Option<DateTime<Utc>> {
        match self {
            ModernMacosRecord::BackgroundTask(e) => e.created_at,
            ModernMacosRecord::ScreenTime(e) => Some(e.date),
            ModernMacosRecord::InstallHistory(e) => Some(e.install_date),
            ModernMacosRecord::NetworkUsage(e) => Some(e.timestamp),
        }
    }
}

/// Background Task Management (`BackgroundItems-v8.db`) entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackgroundTaskEntry {
    /// Bundle identifier of the app registered for background execution.
    pub app_identifier: String,
    /// Full filesystem path to the executable or app bundle.
    pub app_path: String,
    /// Developer name from the code signature (empty when unsigned).
    pub developer_name: String,
    /// True if this is a legacy LaunchAgent / LaunchDaemon converted to BTM.
    pub is_legacy: bool,
    /// True if the user explicitly approved background execution.
    pub user_approved: bool,
    /// Unix-timestamp seconds when this entry was first created, as UTC.
    /// `None` when the stored value failed to decode.
    pub created_at: Option<DateTime<Utc>>,
}

/// Screen Time usage record (`RMAdminStore-Local.sqlite`,
/// `ZUSAGETIMEDITEM` table).
#[derive(Debug, Clone, PartialEq)]
pub struct ScreenTimeEntry {
    /// macOS bundle identifier of the tracked app.
    pub bundle_id: String,
    /// Total usage time in seconds.
    pub total_time_secs: f64,
    /// Date of usage, decoded from CoreData epoch.
    pub date: DateTime<Utc>,
}

impl Eq for ScreenTimeEntry {}

/// `InstallHistory.plist` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallHistoryEntry {
    /// Human-readable name of the installed software.
    pub display_name: String,
    /// Declared version string (may be empty).
    pub display_version: String,
    /// Install completion time in UTC.
    pub install_date: DateTime<Utc>,
    /// Package identifier (reverse-DNS form, may be empty for GUI installs).
    pub package_identifier: String,
    /// Name of the process that performed the install (`"Installer"`,
    /// `"softwareupdated"`, etc.).
    pub process_name: String,
}

/// `netusage.sqlite` per-process byte-counter record (`PLProcessNetStats`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkUsageEntry {
    /// Process basename, no leading path.
    pub process_name: String,
    /// Bytes received on Wi-Fi interfaces.
    pub wifi_in: u64,
    /// Bytes transmitted on Wi-Fi interfaces.
    pub wifi_out: u64,
    /// Bytes received on wired Ethernet interfaces.
    pub wired_in: u64,
    /// Bytes transmitted on wired Ethernet interfaces.
    pub wired_out: u64,
    /// Measurement timestamp in UTC.
    pub timestamp: DateTime<Utc>,
}

/// Dispatch on the file-path classifier and parse every record found.
/// Empty vec for unknown paths, unreadable files, or malformed content.
pub fn parse(path: &Path) -> Vec<ModernMacosRecord> {
    match ModernMacosArtifactType::from_path(path) {
        Some(ModernMacosArtifactType::BackgroundTask) => parse_background_tasks(path),
        Some(ModernMacosArtifactType::ScreenTime) => parse_screen_time(path),
        Some(ModernMacosArtifactType::InstallHistory) => parse_install_history(path),
        Some(ModernMacosArtifactType::NetworkUsage) => parse_network_usage(path),
        None => Vec::new(),
    }
}

fn open_readonly(path: &Path) -> Option<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()
}

fn parse_background_tasks(path: &Path) -> Vec<ModernMacosRecord> {
    let Some(conn) = open_readonly(path) else {
        return Vec::new();
    };
    let sql = "SELECT app_identifier, app_path, developer_name, \
                      is_legacy, user_approved, created_at \
               FROM BTMEntry \
               ORDER BY created_at ASC";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        Ok(BackgroundTaskEntry {
            app_identifier: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
            app_path: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            developer_name: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            is_legacy: row.get::<_, Option<i64>>(3)?.unwrap_or(0) != 0,
            user_approved: row.get::<_, Option<i64>>(4)?.unwrap_or(0) != 0,
            created_at: row
                .get::<_, Option<i64>>(5)?
                .and_then(|s| DateTime::<Utc>::from_timestamp(s, 0)),
        })
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for row in rows {
        if out.len() >= MAX_RECORDS {
            break;
        }
        if let Ok(entry) = row {
            out.push(ModernMacosRecord::BackgroundTask(entry));
        }
    }
    out
}

fn parse_screen_time(path: &Path) -> Vec<ModernMacosRecord> {
    let Some(conn) = open_readonly(path) else {
        return Vec::new();
    };
    let sql = "SELECT ZBUNDLEID, ZTOTALTIME, ZDATE \
               FROM ZUSAGETIMEDITEM \
               ORDER BY ZDATE ASC";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        let bundle_id: Option<String> = row.get(0)?;
        let total_time: Option<f64> = row.get(1)?;
        let date_raw: Option<f64> = row.get(2)?;
        Ok((bundle_id, total_time, date_raw))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for row in rows {
        if out.len() >= MAX_RECORDS {
            break;
        }
        let Ok((bundle_id, total_time, date_raw)) = row else {
            continue;
        };
        let Some(date) = date_raw.and_then(apple_epoch_to_utc) else {
            continue;
        };
        out.push(ModernMacosRecord::ScreenTime(ScreenTimeEntry {
            bundle_id: bundle_id.unwrap_or_default(),
            total_time_secs: total_time.unwrap_or(0.0),
            date,
        }));
    }
    out
}

fn parse_install_history(path: &Path) -> Vec<ModernMacosRecord> {
    let Ok(value) = Value::from_file(path) else {
        return Vec::new();
    };
    let Some(arr) = value.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in arr {
        if out.len() >= MAX_RECORDS {
            break;
        }
        let Some(dict) = entry.as_dictionary() else {
            continue;
        };
        let Some(date) = dict.get("date").and_then(plist_date_to_utc) else {
            continue;
        };
        let display_name = dict
            .get("displayName")
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let display_version = dict
            .get("displayVersion")
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let process_name = dict
            .get("processName")
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let package_identifier = dict
            .get("packageIdentifiers")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_string())
            .or_else(|| dict.get("packageIdentifier").and_then(|v| v.as_string()))
            .unwrap_or("")
            .to_string();
        out.push(ModernMacosRecord::InstallHistory(InstallHistoryEntry {
            display_name,
            display_version,
            install_date: date,
            package_identifier,
            process_name,
        }));
    }
    out
}

fn parse_network_usage(path: &Path) -> Vec<ModernMacosRecord> {
    let Some(conn) = open_readonly(path) else {
        return Vec::new();
    };
    let sql = "SELECT pBaseName, wifiIn, wifiOut, wiredIn, wiredOut, ztimestamp \
               FROM PLProcessNetStats \
               ORDER BY ztimestamp ASC";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        let name: Option<String> = row.get(0)?;
        let wifi_in: Option<i64> = row.get(1)?;
        let wifi_out: Option<i64> = row.get(2)?;
        let wired_in: Option<i64> = row.get(3)?;
        let wired_out: Option<i64> = row.get(4)?;
        let ts: Option<i64> = row.get(5)?;
        Ok((name, wifi_in, wifi_out, wired_in, wired_out, ts))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for row in rows {
        if out.len() >= MAX_RECORDS {
            break;
        }
        let Ok((name, wifi_in, wifi_out, wired_in, wired_out, ts)) = row else {
            continue;
        };
        let Some(timestamp) = ts.and_then(|s| DateTime::<Utc>::from_timestamp(s, 0)) else {
            continue;
        };
        out.push(ModernMacosRecord::NetworkUsage(NetworkUsageEntry {
            process_name: name.unwrap_or_default(),
            wifi_in: wifi_in.unwrap_or(0).max(0) as u64,
            wifi_out: wifi_out.unwrap_or(0).max(0) as u64,
            wired_in: wired_in.unwrap_or(0).max(0) as u64,
            wired_out: wired_out.unwrap_or(0).max(0) as u64,
            timestamp,
        }));
    }
    out
}

fn apple_epoch_to_utc(apple_secs: f64) -> Option<DateTime<Utc>> {
    if !apple_secs.is_finite() {
        return None;
    }
    let secs = apple_secs.trunc() as i64;
    let nanos = ((apple_secs - apple_secs.trunc()) * 1_000_000_000.0) as u32;
    DateTime::<Utc>::from_timestamp(secs.saturating_add(APPLE_EPOCH_OFFSET), nanos)
}

fn plist_date_to_utc(v: &Value) -> Option<DateTime<Utc>> {
    let d = v.as_date()?;
    let sys: std::time::SystemTime = d.into();
    Some(sys.into())
}

/// True when a BackgroundTask entry should be flagged `suspicious`: a
/// non-Apple developer whose entry is not user-approved.
pub fn is_suspicious_background_task(entry: &BackgroundTaskEntry) -> bool {
    let is_apple = entry.app_identifier.starts_with("com.apple.")
        || entry.developer_name.eq_ignore_ascii_case("Apple")
        || entry.developer_name.contains("Apple Inc");
    !is_apple && !entry.user_approved
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Value;
    use rusqlite::Connection;

    #[test]
    fn from_path_classifies_known_filenames() {
        assert_eq!(
            ModernMacosArtifactType::from_path(Path::new(
                "/Library/Application Support/com.apple.backgroundtaskmanagementd/BackgroundItems-v8.db"
            )),
            Some(ModernMacosArtifactType::BackgroundTask)
        );
        assert_eq!(
            ModernMacosArtifactType::from_path(Path::new(
                "/Users/a/Library/Application Support/com.apple.ScreenTime/RMAdminStore-Local.sqlite"
            )),
            Some(ModernMacosArtifactType::ScreenTime)
        );
        assert_eq!(
            ModernMacosArtifactType::from_path(Path::new("/Library/Receipts/InstallHistory.plist")),
            Some(ModernMacosArtifactType::InstallHistory)
        );
        assert_eq!(
            ModernMacosArtifactType::from_path(Path::new(
                "/private/var/networkd/db/netusage.sqlite"
            )),
            Some(ModernMacosArtifactType::NetworkUsage)
        );
        assert!(ModernMacosArtifactType::from_path(Path::new("/nope")).is_none());
    }

    #[test]
    fn parse_unknown_path_returns_empty() {
        assert!(parse(Path::new("/nonexistent/whatever.plist")).is_empty());
    }

    #[test]
    fn parse_background_tasks_captures_approval_flags() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("BackgroundItems-v8.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE BTMEntry ( \
                 app_identifier TEXT, app_path TEXT, developer_name TEXT, \
                 is_legacy INTEGER, user_approved INTEGER, created_at INTEGER \
             );",
        )
        .expect("create");
        conn.execute(
            "INSERT INTO BTMEntry VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "com.evil.helper",
                "/Applications/Evil.app/Contents/MacOS/Helper",
                "Malicious LLC",
                0_i64,
                0_i64,
                1_717_243_200_i64
            ],
        )
        .expect("insert");
        drop(conn);
        let records = parse(&path);
        assert_eq!(records.len(), 1);
        let ModernMacosRecord::BackgroundTask(e) = &records[0] else {
            panic!("expected BackgroundTask");
        };
        assert_eq!(e.app_identifier, "com.evil.helper");
        assert!(!e.user_approved);
        assert_eq!(e.created_at.map(|d| d.timestamp()), Some(1_717_243_200));
        assert!(is_suspicious_background_task(e));
    }

    #[test]
    fn parse_screen_time_converts_apple_epoch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("RMAdminStore-Local.sqlite");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE ZUSAGETIMEDITEM ( \
                 Z_PK INTEGER PRIMARY KEY, ZBUNDLEID TEXT, ZTOTALTIME REAL, ZDATE REAL \
             );",
        )
        .expect("create");
        // CoreData 738_936_000 == Unix 1_717_243_200
        conn.execute(
            "INSERT INTO ZUSAGETIMEDITEM VALUES (NULL, ?1, ?2, ?3)",
            rusqlite::params!["com.apple.Safari", 3600.0_f64, 738_936_000.0_f64],
        )
        .expect("insert");
        drop(conn);
        let records = parse(&path);
        assert_eq!(records.len(), 1);
        let ModernMacosRecord::ScreenTime(e) = &records[0] else {
            panic!("expected ScreenTime");
        };
        assert_eq!(e.bundle_id, "com.apple.Safari");
        assert_eq!(e.total_time_secs as i64, 3600);
        assert_eq!(e.date.timestamp(), 1_717_243_200);
    }

    #[test]
    fn parse_install_history_reads_plist_array() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("InstallHistory.plist");
        // Build an array of one install dict.
        let mut entry = plist::Dictionary::new();
        entry.insert("displayName".into(), Value::String("Xcode".into()));
        entry.insert("displayVersion".into(), Value::String("15.0".into()));
        entry.insert(
            "processName".into(),
            Value::String("softwareupdated".into()),
        );
        entry.insert(
            "packageIdentifiers".into(),
            Value::Array(vec![Value::String("com.apple.pkg.Xcode".into())]),
        );
        let sys_time =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_717_243_200);
        entry.insert("date".into(), Value::Date(sys_time.into()));
        let root = Value::Array(vec![Value::Dictionary(entry)]);
        root.to_file_xml(&path).expect("write plist");

        let records = parse(&path);
        assert_eq!(records.len(), 1);
        let ModernMacosRecord::InstallHistory(e) = &records[0] else {
            panic!("expected InstallHistory");
        };
        assert_eq!(e.display_name, "Xcode");
        assert_eq!(e.display_version, "15.0");
        assert_eq!(e.process_name, "softwareupdated");
        assert_eq!(e.package_identifier, "com.apple.pkg.Xcode");
        assert_eq!(e.install_date.timestamp(), 1_717_243_200);
    }

    #[test]
    fn parse_network_usage_reads_process_stats() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("netusage.sqlite");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE PLProcessNetStats ( \
                 pBaseName TEXT, wifiIn INTEGER, wifiOut INTEGER, \
                 wiredIn INTEGER, wiredOut INTEGER, ztimestamp INTEGER \
             );",
        )
        .expect("create");
        conn.execute(
            "INSERT INTO PLProcessNetStats VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "curl",
                1_000_000_i64,
                500_000_i64,
                0_i64,
                0_i64,
                1_717_243_200_i64
            ],
        )
        .expect("insert");
        drop(conn);
        let records = parse(&path);
        assert_eq!(records.len(), 1);
        let ModernMacosRecord::NetworkUsage(e) = &records[0] else {
            panic!("expected NetworkUsage");
        };
        assert_eq!(e.process_name, "curl");
        assert_eq!(e.wifi_in, 1_000_000);
        assert_eq!(e.wifi_out, 500_000);
        assert_eq!(e.timestamp.timestamp(), 1_717_243_200);
    }

    #[test]
    fn mitre_and_severity_map_per_type() {
        assert_eq!(ModernMacosArtifactType::BackgroundTask.mitre(), "T1547.011");
        assert_eq!(ModernMacosArtifactType::ScreenTime.mitre(), "T1059");
        assert_eq!(ModernMacosArtifactType::InstallHistory.mitre(), "T1072");
        assert_eq!(ModernMacosArtifactType::NetworkUsage.mitre(), "T1071");
        assert_eq!(
            ModernMacosArtifactType::BackgroundTask.forensic_value(),
            "High"
        );
        assert_eq!(
            ModernMacosArtifactType::ScreenTime.forensic_value(),
            "Medium"
        );
    }

    #[test]
    fn suspicious_flag_respects_apple_and_approval() {
        let apple = BackgroundTaskEntry {
            app_identifier: "com.apple.something".to_string(),
            app_path: "/System/Library/Foo".to_string(),
            developer_name: "Apple Inc.".to_string(),
            is_legacy: false,
            user_approved: false,
            created_at: None,
        };
        assert!(!is_suspicious_background_task(&apple));

        let approved_third_party = BackgroundTaskEntry {
            app_identifier: "com.thirdparty.agent".to_string(),
            app_path: "/Applications/Agent.app".to_string(),
            developer_name: "Third Party".to_string(),
            is_legacy: false,
            user_approved: true,
            created_at: None,
        };
        assert!(!is_suspicious_background_task(&approved_third_party));

        let unapproved_third_party = BackgroundTaskEntry {
            app_identifier: "com.evil.helper".to_string(),
            app_path: "/tmp/helper".to_string(),
            developer_name: "Malicious LLC".to_string(),
            is_legacy: false,
            user_approved: false,
            created_at: None,
        };
        assert!(is_suspicious_background_task(&unapproved_third_party));
    }
}
