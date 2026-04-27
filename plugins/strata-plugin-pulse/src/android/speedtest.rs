//! Speedtest by Ookla — network speed test history.
//!
//! ALEAPP reference: `scripts/artifacts/speedtest.py`. Source path:
//! `/data/data/org.zwanoo.android.speedtest/databases/AmplifyDatastore.db`.
//!
//! Key table: `UnivSpeedTestResult`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "org.zwanoo.android.speedtest/databases/amplifydatastore.db",
    "org.zwanoo.android.speedtest/databases/speedtest",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "UnivSpeedTestResult") {
        return Vec::new();
    }
    read_results(&conn, path)
}

fn read_results(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT date, connectionType, ssid, \
               userLatitude, userLongitude, externalIp, internalIp, \
               downloadKbps, uploadKbps \
               FROM UnivSpeedTestResult \
               ORDER BY date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
            row.get::<_, Option<i64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (date_ms, conn_type, ssid, lat, lon, ext_ip, int_ip, dl, ul) in rows.flatten() {
        let conn_type = conn_type.unwrap_or_else(|| "unknown".to_string());
        let ssid = ssid.unwrap_or_default();
        let ext_ip = ext_ip.unwrap_or_default();
        let int_ip = int_ip.unwrap_or_default();
        let dl_mbps = dl.unwrap_or(0) as f64 / 1000.0;
        let ul_mbps = ul.unwrap_or(0) as f64 / 1000.0;
        let ts = date_ms.and_then(unix_ms_to_i64);
        let title = format!(
            "Speedtest {} ↓{:.1}/↑{:.1} Mbps",
            conn_type, dl_mbps, ul_mbps
        );
        let mut detail = format!(
            "Speedtest connection='{}' download={:.1}Mbps upload={:.1}Mbps",
            conn_type, dl_mbps, ul_mbps
        );
        if !ssid.is_empty() {
            detail.push_str(&format!(" ssid='{}'", ssid));
        }
        if !ext_ip.is_empty() {
            detail.push_str(&format!(" external_ip='{}'", ext_ip));
        }
        if !int_ip.is_empty() {
            detail.push_str(&format!(" internal_ip='{}'", int_ip));
        }
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::NetworkArtifacts,
            "Speedtest Result",
            title,
            detail,
            path,
            ts,
            ForensicValue::High,
            false,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE UnivSpeedTestResult (
                date INTEGER,
                connectionType TEXT,
                ssid TEXT,
                userLatitude REAL,
                userLongitude REAL,
                externalIp TEXT,
                internalIp TEXT,
                downloadKbps INTEGER,
                uploadKbps INTEGER
            );
            INSERT INTO UnivSpeedTestResult VALUES(1609459200000,'WIFI','HomeWiFi',37.7749,-122.4194,'203.0.113.42','192.168.1.100',200000,50000);
            INSERT INTO UnivSpeedTestResult VALUES(1609459300000,'Cellular',NULL,37.7700,-122.4000,'198.51.100.7','10.0.0.50',30000,10000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_results() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Speedtest Result"));
    }

    #[test]
    fn external_and_internal_ip() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("external_ip='203.0.113.42'")
                && a.detail.contains("internal_ip='192.168.1.100'")));
    }

    #[test]
    fn mbps_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("200.0") && a.title.contains("50.0")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
