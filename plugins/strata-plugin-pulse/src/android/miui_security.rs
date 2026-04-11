//! MIUI Security Center — antivirus scan and threat logs.
//!
//! Source path: `/data/data/com.miui.securitycenter/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Parser uses plausible MIUI
//! Security Center schema patterns. MIUI stores scan history in
//! `scan_history` and threat detections in `threat`. Column names vary
//! across MIUI versions.

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.miui.securitycenter/databases/",
    "com.miui.securityadd/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["scan_history", "virus_scan_history", "av_scan"] {
        if table_exists(&conn, table) {
            out.extend(read_scans(&conn, path, table));
        }
    }
    for table in &["threat", "virus", "malware_record"] {
        if table_exists(&conn, table) {
            out.extend(read_threats(&conn, path, table));
        }
    }
    out
}

fn read_scans(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let ts_col = if column_exists(conn, table, "scan_time") {
        "scan_time"
    } else {
        "time"
    };
    let sql = format!(
        "SELECT {ts_col}, result, scanned_count, threat_count \
         FROM \"{table}\" ORDER BY {ts_col} DESC LIMIT 1000",
        ts_col = ts_col,
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, result, scanned, threats) in rows.flatten() {
        let result = result.unwrap_or_else(|| "unknown".to_string());
        let scanned = scanned.unwrap_or(0);
        let threats = threats.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("MIUI scan: {} ({} threats)", result, threats);
        let detail = format!(
            "MIUI security scan result='{}' scanned={} threats={}",
            result, scanned, threats
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "MIUI Security Scan",
            title,
            detail,
            path,
            ts,
            if threats > 0 { ForensicValue::Critical } else { ForensicValue::Low },
            threats > 0,
        ));
    }
    out
}

fn read_threats(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT name, package_name, threat_type, file_path, detect_time \
         FROM \"{table}\" ORDER BY detect_time DESC LIMIT 1000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, package, threat_type, file_path, ts_ms) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let package = package.unwrap_or_default();
        let threat_type = threat_type.unwrap_or_default();
        let file_path = file_path.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("MIUI threat: {} ({})", name, threat_type);
        let mut detail = format!(
            "MIUI security threat name='{}' type='{}'",
            name, threat_type
        );
        if !package.is_empty() {
            detail.push_str(&format!(" package='{}'", package));
        }
        if !file_path.is_empty() {
            detail.push_str(&format!(" file='{}'", file_path));
        }
        out.push(build_record(
            ArtifactCategory::ExecutionHistory,
            "MIUI Threat",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            true,
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
            CREATE TABLE scan_history (
                scan_time INTEGER,
                result TEXT,
                scanned_count INTEGER,
                threat_count INTEGER
            );
            INSERT INTO scan_history VALUES(1609459200000,'clean',150,0);
            INSERT INTO scan_history VALUES(1609545600000,'threats_found',200,2);
            CREATE TABLE threat (
                name TEXT,
                package_name TEXT,
                threat_type TEXT,
                file_path TEXT,
                detect_time INTEGER
            );
            INSERT INTO threat VALUES('Android.Trojan.XYZ','com.evil.app','trojan','/data/app/evil.apk',1609545600000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_scans_and_threats() {
        let db = make_db();
        let r = parse(db.path());
        let scans: Vec<_> = r.iter().filter(|a| a.subcategory == "MIUI Security Scan").collect();
        let threats: Vec<_> = r.iter().filter(|a| a.subcategory == "MIUI Threat").collect();
        assert_eq!(scans.len(), 2);
        assert_eq!(threats.len(), 1);
    }

    #[test]
    fn threat_scan_flagged_critical() {
        let db = make_db();
        let r = parse(db.path());
        let threat_scan = r.iter().find(|a| a.detail.contains("threats=2")).unwrap();
        assert!(threat_scan.is_suspicious);
        assert!(matches!(threat_scan.forensic_value, ForensicValue::Critical));
    }

    #[test]
    fn threat_details_captured() {
        let db = make_db();
        let r = parse(db.path());
        let t = r.iter().find(|a| a.subcategory == "MIUI Threat").unwrap();
        assert!(t.detail.contains("package='com.evil.app'"));
        assert!(t.detail.contains("file='/data/app/evil.apk'"));
        assert!(t.is_suspicious);
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
