//! iOS TCC (Transparency, Consent, and Control) — `TCC.db`.
//!
//! `TCC.db` records every per-app privacy permission grant/deny for
//! camera, microphone, photos, contacts, location, etc. iLEAPP keys
//! off the `access` table with columns `service`, `client`
//! (bundle ID), `auth_value`, `auth_reason`, `last_modified`.
//!
//! Extremely high forensic value — shows which apps had camera/mic
//! access and when the user granted it.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["tcc.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "access") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let total = util::count_rows(&conn, "access");

    // Per-service breakdown
    let by_service = conn
        .prepare("SELECT service, auth_value, COUNT(*) FROM access GROUP BY service, auth_value ORDER BY COUNT(*) DESC")
        .and_then(|mut s| {
            let r = s.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)))?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "TCC permissions".to_string(),
        timestamp: None,
        title: "iOS privacy permissions (TCC)".to_string(),
        detail: format!(
            "{} access rows (per-app camera/mic/photos/contacts/location grants)",
            total
        ),
        source_path: source.clone(),
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });

    for (service, auth, count) in by_service {
        let auth_label = match auth {
            0 => "denied",
            2 => "allowed",
            3 => "limited",
            _ => "other",
        };
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: format!("TCC {} {}", service, auth_label),
            timestamp: None,
            title: format!("{}: {} ({})", service, auth_label, count),
            detail: format!("{} apps {} for {}", count, auth_label, service),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_tcc(rows: &[(&str, &str, i64)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE access (service TEXT, client TEXT, auth_value INTEGER, auth_reason INTEGER, last_modified INTEGER)", []).unwrap();
        for (svc, client, auth) in rows {
            c.execute(
                "INSERT INTO access VALUES (?1, ?2, ?3, 4, 1700000000)",
                rusqlite::params![*svc, *client, *auth],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_tcc_db() {
        assert!(matches(Path::new("/var/mobile/Library/TCC/TCC.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_summary_and_service_breakdown() {
        let tmp = make_tcc(&[
            ("kTCCServiceCamera", "com.app.a", 2),
            ("kTCCServiceCamera", "com.app.b", 0),
            ("kTCCServiceMicrophone", "com.app.a", 2),
        ]);
        let recs = parse(tmp.path());
        let summary = recs
            .iter()
            .find(|r| r.subcategory == "TCC permissions")
            .unwrap();
        assert!(summary.detail.contains("3 access rows"));
        assert!(recs
            .iter()
            .any(|r| r.subcategory.contains("Camera") && r.subcategory.contains("allowed")));
        assert!(recs
            .iter()
            .any(|r| r.subcategory.contains("Camera") && r.subcategory.contains("denied")));
    }

    #[test]
    fn missing_access_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
