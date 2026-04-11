//! MIUI Gallery — Xiaomi photo gallery trash and cloud state.
//!
//! Source path: `/data/data/com.miui.gallery/databases/gallery.db`.
//!
//! Schema note: not in ALEAPP upstream. MIUI Gallery uses tables
//! `garbage` (trash/recycle bin) and `cloud` (synced cloud photos).
//! Key forensic interest: deleted photos in `garbage` may still be
//! recoverable after user "deletion".

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.miui.gallery/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "garbage") {
        out.extend(read_trash(&conn, path));
    }
    if table_exists(&conn, "cloud") {
        out.extend(read_cloud(&conn, path));
    }
    out
}

fn read_trash(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_delete_time = column_exists(conn, "garbage", "delete_time");
    let ts_col = if has_delete_time { "delete_time" } else { "date_modified" };
    let sql = format!(
        "SELECT fileName, localPath, size, {ts_col}, sha1 \
         FROM garbage ORDER BY {ts_col} DESC LIMIT 10000",
        ts_col = ts_col
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, local_path, size, ts_ms, sha1) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let local_path = local_path.unwrap_or_default();
        let size = size.unwrap_or(0);
        let sha1 = sha1.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("MIUI trash: {}", name);
        let mut detail = format!(
            "MIUI Gallery trash file='{}' size={} local_path='{}'",
            name, size, local_path
        );
        if !sha1.is_empty() {
            detail.push_str(&format!(" sha1='{}'", sha1));
        }
        out.push(build_record(
            ArtifactCategory::DeletedRecovered,
            "MIUI Gallery Trash",
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

fn read_cloud(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT fileName, localPath, serverPath, size, dateModified \
               FROM cloud ORDER BY dateModified DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, local_path, server_path, size, ts_ms) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let local_path = local_path.unwrap_or_default();
        let server_path = server_path.unwrap_or_default();
        let size = size.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("MIUI cloud: {}", name);
        let detail = format!(
            "MIUI Gallery cloud file='{}' local='{}' server='{}' size={}",
            name, local_path, server_path, size
        );
        out.push(build_record(
            ArtifactCategory::CloudSync,
            "MIUI Gallery Cloud",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
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
            CREATE TABLE garbage (
                fileName TEXT,
                localPath TEXT,
                size INTEGER,
                delete_time INTEGER,
                sha1 TEXT
            );
            INSERT INTO garbage VALUES('IMG_001.jpg','/sdcard/DCIM/IMG_001.jpg',1234567,1609459200000,'abc123def456');
            INSERT INTO garbage VALUES('secret.jpg','/sdcard/Pictures/secret.jpg',987654,1609545600000,'deadbeef');
            CREATE TABLE cloud (
                fileName TEXT,
                localPath TEXT,
                serverPath TEXT,
                size INTEGER,
                dateModified INTEGER
            );
            INSERT INTO cloud VALUES('backup.jpg','/sdcard/DCIM/backup.jpg','https://cloud.mi.com/backup.jpg',500000,1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_trash_and_cloud() {
        let db = make_db();
        let r = parse(db.path());
        let trash: Vec<_> = r.iter().filter(|a| a.subcategory == "MIUI Gallery Trash").collect();
        let cloud: Vec<_> = r.iter().filter(|a| a.subcategory == "MIUI Gallery Cloud").collect();
        assert_eq!(trash.len(), 2);
        assert_eq!(cloud.len(), 1);
    }

    #[test]
    fn trash_is_suspicious_and_critical() {
        let db = make_db();
        let r = parse(db.path());
        let secret = r.iter().find(|a| a.title.contains("secret.jpg")).unwrap();
        assert!(secret.is_suspicious);
        assert!(matches!(secret.forensic_value, ForensicValue::Critical));
    }

    #[test]
    fn sha1_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("sha1='abc123def456'")));
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
