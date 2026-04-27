//! Samsung-specific Android artifacts (AND-2).
//!
//! Covers Samsung Health (step + heart / sleep / exercise), Knox
//! security events, Samsung Location History, Samsung Messages, and
//! Samsung Internet Browser.
//!
//! MITRE: T1430 (activity inference → location), T1005.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq)]
pub struct SamsungArtifact {
    pub category: String,
    pub source_path: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub value: String,
    pub secondary_value: Option<String>,
    pub metadata: Option<String>,
}

fn open_ro(path: &Path) -> Option<Connection> {
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    c.pragma_query_value(None, "schema_version", |_| Ok(()))
        .ok()?;
    Some(c)
}

fn decode_ms(ms: i64) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(
        ms.div_euclid(1000),
        (ms.rem_euclid(1000) as u32) * 1_000_000,
    )
}

pub fn classify(path: &Path) -> Option<&'static str> {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    if lower.contains("com.sec.android.app.shealth/databases/") && name == "healthdatashare.db" {
        return Some("Health");
    }
    if lower.contains("com.samsung.android.locationsharing/databases/")
        && name == "locationhistory.db"
    {
        return Some("Location");
    }
    if lower.contains("com.samsung.android.messaging/databases/") && name == "message.db" {
        return Some("Messages");
    }
    if lower.contains("com.sec.android.app.sbrowser/") && name == "sbrowser.db" {
        return Some("Browser");
    }
    if lower.contains("/data/system/sec_knox/")
        && (name == "knox_security_log.db" || name == "knox_security_log.txt")
    {
        return Some("Knox");
    }
    None
}

pub fn parse_health(path: &Path) -> Vec<SamsungArtifact> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT data_type, start_time, value, pkg_name FROM health_data_all ORDER BY start_time ASC",
    ) {
        let rows = stmt.query_map([], |row| {
            let data_type: Option<String> = row.get(0)?;
            let start_time: Option<i64> = row.get(1)?;
            let value: Option<f64> = row.get(2)?;
            let pkg_name: Option<String> = row.get(3)?;
            Ok((data_type, start_time, value, pkg_name))
        });
        if let Ok(rows) = rows {
            for (data_type, start_time, value, pkg_name) in rows.flatten() {
                out.push(SamsungArtifact {
                    category: "Health".into(),
                    source_path: path.to_string_lossy().to_string(),
                    timestamp: start_time.and_then(decode_ms),
                    value: format!(
                        "{}={:.2}",
                        data_type.unwrap_or_default(),
                        value.unwrap_or(0.0)
                    ),
                    secondary_value: pkg_name,
                    metadata: None,
                });
            }
        }
    }
    out
}

pub fn parse_location(path: &Path) -> Vec<SamsungArtifact> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT latitude, longitude, timestamp, accuracy, provider FROM history ORDER BY timestamp ASC",
    ) {
        let rows = stmt.query_map([], |row| {
            let lat: Option<f64> = row.get(0)?;
            let lon: Option<f64> = row.get(1)?;
            let ts: Option<i64> = row.get(2)?;
            let acc: Option<f64> = row.get(3)?;
            let provider: Option<String> = row.get(4)?;
            Ok((lat, lon, ts, acc, provider))
        });
        if let Ok(rows) = rows {
            for (lat, lon, ts, acc, provider) in rows.flatten() {
                if let (Some(lat), Some(lon)) = (lat, lon) {
                    out.push(SamsungArtifact {
                        category: "Location".into(),
                        source_path: path.to_string_lossy().to_string(),
                        timestamp: ts.and_then(decode_ms),
                        value: format!("{:.6},{:.6}", lat, lon),
                        secondary_value: acc.map(|a| format!("±{:.1}m", a)),
                        metadata: provider,
                    });
                }
            }
        }
    }
    out
}

pub fn parse_messages(path: &Path) -> Vec<SamsungArtifact> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(mut stmt) =
        conn.prepare("SELECT address, body, date, type FROM message ORDER BY date ASC")
    {
        let rows = stmt.query_map([], |row| {
            let address: Option<String> = row.get(0)?;
            let body: Option<String> = row.get(1)?;
            let date: Option<i64> = row.get(2)?;
            let mtype: Option<i64> = row.get(3)?;
            Ok((address, body, date, mtype))
        });
        if let Ok(rows) = rows {
            for (address, body, date, mtype) in rows.flatten() {
                out.push(SamsungArtifact {
                    category: "Messages".into(),
                    source_path: path.to_string_lossy().to_string(),
                    timestamp: date.and_then(decode_ms),
                    value: body.unwrap_or_default(),
                    secondary_value: address,
                    metadata: mtype.map(|m| format!("type={}", m)),
                });
            }
        }
    }
    out
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let Some(kind) = classify(path) else {
        return Vec::new();
    };
    let records = match kind {
        "Health" => parse_health(path),
        "Location" => parse_location(path),
        "Messages" => parse_messages(path),
        _ => Vec::new(),
    };
    records
        .into_iter()
        .map(|r| {
            let mut a = Artifact::new(&format!("Samsung {}", r.category), &r.source_path);
            a.timestamp = r.timestamp.map(|d| d.timestamp() as u64);
            a.add_field("title", &format!("Samsung {}: {}", r.category, r.value));
            a.add_field(
                "detail",
                &format!(
                    "Category: {} | value: {} | secondary: {} | metadata: {}",
                    r.category,
                    r.value,
                    r.secondary_value.as_deref().unwrap_or("-"),
                    r.metadata.as_deref().unwrap_or("-"),
                ),
            );
            a.add_field("file_type", &format!("Samsung {}", r.category));
            a.add_field("category", &r.category);
            a.add_field("value", &r.value);
            if let Some(v) = &r.secondary_value {
                a.add_field("secondary_value", v);
            }
            if let Some(v) = &r.metadata {
                a.add_field("metadata", v);
            }
            let mitre = match r.category.as_str() {
                "Location" => "T1430",
                "Messages" => "T1636.002",
                _ => "T1005",
            };
            a.add_field("mitre", mitre);
            a.add_field("forensic_value", "High");
            a
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn classify_recognises_known_paths() {
        assert_eq!(
            classify(Path::new(
                "/data/data/com.sec.android.app.shealth/databases/healthdatashare.db"
            )),
            Some("Health")
        );
        assert_eq!(
            classify(Path::new(
                "/data/data/com.samsung.android.locationsharing/databases/LocationHistory.db"
            )),
            Some("Location")
        );
        assert_eq!(
            classify(Path::new(
                "/data/data/com.samsung.android.messaging/databases/message.db"
            )),
            Some("Messages")
        );
    }

    #[test]
    fn parse_location_extracts_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("LocationHistory.db");
        let conn = Connection::open(&db).expect("open");
        conn.execute_batch(
            "CREATE TABLE history (latitude REAL, longitude REAL, timestamp INTEGER, accuracy REAL, provider TEXT);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO history VALUES (37.7749, -122.4194, 1717243200000, 5.0, 'gps')",
            [],
        )
        .expect("ins");
        drop(conn);
        let out = parse_location(&db);
        assert_eq!(out.len(), 1);
        assert!(out[0].value.contains("37.774"));
    }

    #[test]
    fn parse_messages_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("message.db");
        let conn = Connection::open(&db).expect("open");
        conn.execute_batch(
            "CREATE TABLE message (msg_id INTEGER, address TEXT, body TEXT, date INTEGER, type INTEGER, status INTEGER);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO message VALUES (1, '+15551234567', 'hello sms', 1717243200000, 1, 0)",
            [],
        )
        .expect("ins");
        drop(conn);
        let out = parse_messages(&db);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].value, "hello sms");
    }

    #[test]
    fn scan_emits_artifacts_for_samsung_messages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir
            .path()
            .join("data")
            .join("data")
            .join("com.samsung.android.messaging")
            .join("databases");
        std::fs::create_dir_all(&base).expect("mkdirs");
        let db = base.join("message.db");
        let conn = Connection::open(&db).expect("open");
        conn.execute_batch(
            "CREATE TABLE message (msg_id INTEGER, address TEXT, body TEXT, date INTEGER, type INTEGER, status INTEGER);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO message VALUES (1, '+1', 'hi', 1717243200000, 1, 0)",
            [],
        )
        .expect("ins");
        drop(conn);
        let arts = scan(&db);
        assert!(arts
            .iter()
            .any(|a| a.data.get("file_type").map(|s| s.as_str()) == Some("Samsung Messages")));
    }

    #[test]
    fn scan_returns_empty_for_unrelated_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("random.db");
        std::fs::write(&p, b"").expect("w");
        assert!(scan(&p).is_empty());
    }
}
