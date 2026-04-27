//! Capability Access Manager database (CHRON-2).
//!
//! Windows 11 23H2+ adds a SQLite CAM database at
//! `%ProgramData%\Microsoft\Windows\CapabilityAccessManager\
//! CapabilityAccessManager.db`. This module reads the Capabilities
//! table and surfaces mic/camera/location/screencapture access.
//!
//! Privacy-investigation gold: stalkerware, SAPR, corporate espionage.
//!
//! MITRE: T1123 (audio), T1125 (video), T1430 (location).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

const FILETIME_EPOCH_DELTA: i64 = 11_644_473_600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CamRecord {
    pub capability: String,
    pub app_name: String,
    pub last_used: Option<DateTime<Utc>>,
    pub access_granted: bool,
    pub user_decision: String,
    pub source: String,
}

pub fn is_cam_db_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.eq_ignore_ascii_case("CapabilityAccessManager.db"))
        .unwrap_or(false)
}

pub fn parse(path: &Path) -> Vec<CamRecord> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = Connection::open_with_flags(path, flags) else {
        return Vec::new();
    };
    query(&conn).unwrap_or_default()
}

fn query(conn: &Connection) -> rusqlite::Result<Vec<CamRecord>> {
    let mut stmt = conn.prepare(
        "SELECT CapabilityName, PackageName, LastUsed, AccessGranted, UserDecision \
         FROM Capabilities",
    )?;
    let rows = stmt.query_map([], |row| {
        let cap: String = row.get::<_, Option<String>>(0)?.unwrap_or_default();
        let pkg: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
        let ts: Option<i64> = row.get(2)?;
        let granted: Option<i64> = row.get(3)?;
        let decision: Option<i64> = row.get(4)?;
        Ok((cap, pkg, ts, granted, decision))
    })?;
    let mut out = Vec::new();
    for r in rows.flatten() {
        let (cap, pkg, ts, granted, decision) = r;
        let last_used = ts.and_then(decode_timestamp);
        out.push(CamRecord {
            capability: cap,
            app_name: pkg,
            last_used,
            access_granted: granted.unwrap_or(0) != 0,
            user_decision: decision_to_str(decision.unwrap_or(0)).to_string(),
            source: "Database".to_string(),
        });
    }
    Ok(out)
}

fn decision_to_str(v: i64) -> &'static str {
    match v {
        1 => "Allowed",
        2 => "Denied",
        _ => "NotDecided",
    }
}

/// CAM timestamps may be FILETIME or Unix seconds — try FILETIME first.
fn decode_timestamp(v: i64) -> Option<DateTime<Utc>> {
    if v > 100_000_000_000_000 {
        let secs = (v / 10_000_000).saturating_sub(FILETIME_EPOCH_DELTA);
        return DateTime::<Utc>::from_timestamp(secs, 0);
    }
    if v > 1_000_000_000 {
        return DateTime::<Utc>::from_timestamp(v, 0);
    }
    None
}

const SYSTEM_PACKAGES: &[&str] = &[
    "microsoft.windows",
    "microsoft.aad.brokerplugin",
    "microsoft.bing",
    "microsoft.people",
    "microsoft.accountscontrol",
];

/// Returns a suspicion reason when the access should be flagged.
pub fn check_suspicion(rec: &CamRecord) -> Option<String> {
    let cap = rec.capability.to_ascii_lowercase();
    let pkg = rec.app_name.to_ascii_lowercase();
    let is_system = SYSTEM_PACKAGES.iter().any(|p| pkg.starts_with(p));
    let is_sensitive = matches!(
        cap.as_str(),
        "microphone" | "camera" | "location" | "screencapture"
    );
    if !is_sensitive {
        return None;
    }
    if is_system {
        return None;
    }
    if cap == "screencapture" {
        return Some(format!(
            "Screen capture by non-system app '{}'",
            rec.app_name
        ));
    }
    Some(format!(
        "{} access by non-system app '{}'",
        rec.capability, rec.app_name
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn build_db() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("CapabilityAccessManager.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE Capabilities (CapabilityName TEXT, PackageName TEXT, \
                                        LastUsed INTEGER, AccessGranted INTEGER, \
                                        UserDecision INTEGER);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO Capabilities VALUES ('microphone', 'com.suspicious.app', 1717243200, 1, 1)",
            [],
        )
        .expect("i1");
        conn.execute(
            "INSERT INTO Capabilities VALUES ('camera', 'microsoft.windows.camera', 1717243200, 1, 1)",
            [],
        )
        .expect("i2");
        drop(conn);
        dir
    }

    #[test]
    fn parse_returns_records() {
        let dir = build_db();
        let path = dir.path().join("CapabilityAccessManager.db");
        let recs = parse(&path);
        assert_eq!(recs.len(), 2);
        assert!(recs.iter().any(|r| r.capability == "microphone"));
    }

    #[test]
    fn check_suspicion_flags_non_system_mic_access() {
        let r = CamRecord {
            capability: "microphone".into(),
            app_name: "com.suspicious.app".into(),
            last_used: None,
            access_granted: true,
            user_decision: "Allowed".into(),
            source: "Database".into(),
        };
        assert!(check_suspicion(&r).is_some());
    }

    #[test]
    fn check_suspicion_ignores_system_packages() {
        let r = CamRecord {
            capability: "camera".into(),
            app_name: "microsoft.windows.camera".into(),
            last_used: None,
            access_granted: true,
            user_decision: "Allowed".into(),
            source: "Database".into(),
        };
        assert!(check_suspicion(&r).is_none());
    }

    #[test]
    fn is_cam_db_path_matches_filename() {
        assert!(is_cam_db_path(Path::new("/x/CapabilityAccessManager.db")));
        assert!(!is_cam_db_path(Path::new("/x/other.db")));
    }

    #[test]
    fn decode_timestamp_handles_both_encodings() {
        let unix = decode_timestamp(1_717_243_200).expect("unix");
        assert_eq!(unix.timestamp(), 1_717_243_200);
        // FILETIME for the same instant.
        let filetime = (1_717_243_200_i64 + FILETIME_EPOCH_DELTA) * 10_000_000;
        let ft = decode_timestamp(filetime).expect("filetime");
        assert_eq!(ft.timestamp(), 1_717_243_200);
    }
}
