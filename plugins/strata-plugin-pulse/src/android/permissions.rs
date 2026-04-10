//! Permissions — Android runtime permission grants.
//!
//! ALEAPP reference: `scripts/artifacts/permissions.py`. Source path:
//! `/data/system/packages.xml` (XML) or `/data/system/runtime-permissions.xml`.
//!
//! We parse the SQLite-based variant used by newer Android versions
//! in `/data/misc_de/*/apexdata/com.android.permission/runtime-permissions.db`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "runtime-permissions.db",
    "runtime-permissions/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if table_exists(&conn, "runtime_permissions") {
        read_permissions(&conn, path)
    } else if table_exists(&conn, "permissions") {
        read_permissions_legacy(&conn, path)
    } else {
        Vec::new()
    }
}

/// Dangerous permissions that warrant forensic attention.
const DANGEROUS_PERMS: &[&str] = &[
    "camera",
    "record_audio",
    "access_fine_location",
    "access_coarse_location",
    "read_contacts",
    "read_sms",
    "read_call_log",
    "read_external_storage",
    "write_external_storage",
    "access_media_location",
];

fn is_dangerous(perm: &str) -> bool {
    let lower = perm.to_lowercase();
    DANGEROUS_PERMS.iter().any(|d| lower.contains(d))
}

fn read_permissions(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT package_name, permission_name, is_granted \
               FROM runtime_permissions \
               WHERE is_granted = 1 \
               ORDER BY package_name LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (package, permission) in rows.flatten() {
        let package = package.unwrap_or_else(|| "(unknown)".to_string());
        let perm = permission.unwrap_or_else(|| "(unknown)".to_string());
        let dangerous = is_dangerous(&perm);
        let title = format!("Permission: {} → {}", package, perm);
        let detail = format!(
            "Android permission package='{}' permission='{}' granted=true dangerous={}",
            package, perm, dangerous
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Runtime Permission",
            title,
            detail,
            path,
            None,
            if dangerous { ForensicValue::High } else { ForensicValue::Low },
            dangerous,
        ));
    }
    out
}

fn read_permissions_legacy(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT package_name, name, granted \
               FROM permissions \
               WHERE granted = 1 \
               ORDER BY package_name LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (package, name) in rows.flatten() {
        let package = package.unwrap_or_else(|| "(unknown)".to_string());
        let perm = name.unwrap_or_else(|| "(unknown)".to_string());
        let dangerous = is_dangerous(&perm);
        let title = format!("Permission: {} → {}", package, perm);
        let detail = format!(
            "Android permission package='{}' permission='{}' granted=true dangerous={}",
            package, perm, dangerous
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Runtime Permission",
            title,
            detail,
            path,
            None,
            if dangerous { ForensicValue::High } else { ForensicValue::Low },
            dangerous,
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
            CREATE TABLE runtime_permissions (
                package_name TEXT,
                permission_name TEXT,
                is_granted INTEGER
            );
            INSERT INTO runtime_permissions VALUES('com.whatsapp','android.permission.CAMERA',1);
            INSERT INTO runtime_permissions VALUES('com.whatsapp','android.permission.RECORD_AUDIO',1);
            INSERT INTO runtime_permissions VALUES('com.whatsapp','android.permission.INTERNET',1);
            INSERT INTO runtime_permissions VALUES('com.evil.app','android.permission.ACCESS_FINE_LOCATION',1);
            INSERT INTO runtime_permissions VALUES('com.safe.app','android.permission.VIBRATE',0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_granted_only() {
        let db = make_db();
        let r = parse(db.path());
        // 4 granted, 1 not granted
        assert_eq!(r.len(), 4);
    }

    #[test]
    fn dangerous_perms_flagged() {
        let db = make_db();
        let r = parse(db.path());
        let camera = r.iter().find(|a| a.detail.contains("CAMERA")).unwrap();
        assert!(camera.is_suspicious);
        assert!(camera.detail.contains("dangerous=true"));
    }

    #[test]
    fn safe_perm_not_suspicious() {
        let db = make_db();
        let r = parse(db.path());
        let internet = r.iter().find(|a| a.detail.contains("INTERNET")).unwrap();
        assert!(!internet.is_suspicious);
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
