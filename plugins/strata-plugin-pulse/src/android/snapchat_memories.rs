//! Snapchat Memories — saved snaps and cloud backups.
//!
//! Source path: `/data/data/com.snapchat.android/databases/memories.db`.
//!
//! Schema note: ALEAPP's `snapchat.py` touches memory tables briefly;
//! this parser focuses deeply on `memories_entry`, `memories_snap`,
//! and `memories_meo_confidential` (which contains the passcode-protected
//! "My Eyes Only" vault metadata).

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.snapchat.android/databases/memories.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "memories_entry") {
        out.extend(read_entries(&conn, path));
    }
    if table_exists(&conn, "memories_snap") {
        out.extend(read_snaps(&conn, path));
    }
    if table_exists(&conn, "memories_meo_confidential") {
        out.extend(read_meo(&conn, path));
    }
    out
}

fn read_entries(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT _id, create_time, is_private, snap_ids, \
               cached_servlet_media_formats \
               FROM memories_entry ORDER BY create_time DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, create_ms, is_private, snap_ids, formats) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let ts = create_ms.and_then(unix_ms_to_i64);
        let is_private = is_private.unwrap_or(0) != 0;
        let snap_ids = snap_ids.unwrap_or_default();
        let formats = formats.unwrap_or_default();
        let title = format!("Snapchat memory {} ({})", id, if is_private { "private" } else { "normal" });
        let detail = format!(
            "Snapchat memories_entry id='{}' private={} snap_ids='{}' formats='{}'",
            id, is_private, snap_ids, formats
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Snapchat Memory",
            title,
            detail,
            path,
            ts,
            if is_private { ForensicValue::Critical } else { ForensicValue::High },
            is_private,
        ));
    }
    out
}

fn read_snaps(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT _id, create_time, media_id, width, height, duration, \
               has_location, latitude, longitude, front_facing \
               FROM memories_snap ORDER BY create_time DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
            row.get::<_, Option<i64>>(9).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, create_ms, media_id, width, height, duration, has_loc, lat, lon, front) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let media_id = media_id.unwrap_or_default();
        let width = width.unwrap_or(0);
        let height = height.unwrap_or(0);
        let duration = duration.unwrap_or(0);
        let has_location = has_loc.unwrap_or(0) != 0;
        let front_facing = front.unwrap_or(0) != 0;
        let ts = create_ms.and_then(unix_ms_to_i64);
        let title = format!("Snapchat memory snap {} ({}x{})", id, width, height);
        let mut detail = format!(
            "Snapchat memories_snap id='{}' media_id='{}' dimensions={}x{} duration={} front_facing={}",
            id, media_id, width, height, duration, front_facing
        );
        if has_location {
            if let (Some(la), Some(lo)) = (lat, lon) {
                detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
            }
        }
        out.push(build_record(
            ArtifactCategory::Media,
            "Snapchat Memory Snap",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn read_meo(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT user_id, hashed_passcode, master_key, master_key_iv \
               FROM memories_meo_confidential LIMIT 10";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (user_id, passcode, key, iv) in rows.flatten() {
        let user_id = user_id.unwrap_or_else(|| "(unknown)".to_string());
        let passcode = passcode.unwrap_or_default();
        let key = key.unwrap_or_default();
        let iv = iv.unwrap_or_default();
        let title = format!("Snapchat 'My Eyes Only' vault: {}", user_id);
        let detail = format!(
            "Snapchat memories MEO (My Eyes Only) user_id='{}' hashed_passcode='{}' has_master_key={} has_iv={}",
            user_id,
            passcode,
            !key.is_empty(),
            !iv.is_empty()
        );
        out.push(build_record(
            ArtifactCategory::EncryptionKeyMaterial,
            "Snapchat MEO Vault",
            title,
            detail,
            path,
            None,
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
            CREATE TABLE memories_entry (
                _id TEXT,
                create_time INTEGER,
                is_private INTEGER,
                snap_ids TEXT,
                cached_servlet_media_formats TEXT
            );
            INSERT INTO memories_entry VALUES('e1',1609459200000,0,'s1,s2','image/jpeg');
            INSERT INTO memories_entry VALUES('e2',1609545600000,1,'s3','video/mp4');
            CREATE TABLE memories_snap (
                _id TEXT,
                create_time INTEGER,
                media_id TEXT,
                width INTEGER,
                height INTEGER,
                duration INTEGER,
                has_location INTEGER,
                latitude REAL,
                longitude REAL,
                front_facing INTEGER
            );
            INSERT INTO memories_snap VALUES('s1',1609459200000,'m1',1080,1920,0,1,37.7749,-122.4194,1);
            CREATE TABLE memories_meo_confidential (
                user_id TEXT,
                hashed_passcode TEXT,
                master_key TEXT,
                master_key_iv TEXT
            );
            INSERT INTO memories_meo_confidential VALUES('user_x','hash_abc','key_data','iv_data');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_entries_snaps_meo() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Snapchat Memory"));
        assert!(r.iter().any(|a| a.subcategory == "Snapchat Memory Snap"));
        assert!(r.iter().any(|a| a.subcategory == "Snapchat MEO Vault"));
    }

    #[test]
    fn private_entry_flagged_suspicious() {
        let db = make_db();
        let r = parse(db.path());
        let private = r.iter().find(|a| a.detail.contains("private=true")).unwrap();
        assert!(private.is_suspicious);
    }

    #[test]
    fn snap_gps_captured() {
        let db = make_db();
        let r = parse(db.path());
        let snap = r.iter().find(|a| a.subcategory == "Snapchat Memory Snap").unwrap();
        assert!(snap.detail.contains("lat=37.774900"));
        assert!(snap.detail.contains("front_facing=true"));
    }

    #[test]
    fn meo_vault_flagged_critical() {
        let db = make_db();
        let r = parse(db.path());
        let meo = r.iter().find(|a| a.subcategory == "Snapchat MEO Vault").unwrap();
        assert!(meo.is_suspicious);
        assert!(meo.detail.contains("has_master_key=true"));
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
