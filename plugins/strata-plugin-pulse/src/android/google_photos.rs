//! Google Photos — media metadata from the Google Photos app.
//!
//! ALEAPP reference: `scripts/artifacts/googlePhotos.py`. Source DB:
//! `/data/data/com.google.android.apps.photos/databases/gphotos0.db`
//! with the `local_media` and `remote_media` tables.
//!
//! The forensically interesting columns are:
//!
//! - `local_media.filename` + `local_media.dateTakenMs` — where the
//!   image was taken from the device camera.
//! - `local_media.latitude`, `local_media.longitude` — EXIF geo that
//!   Photos extracted and cached.
//! - `remote_media.media_key` + `remote_media.timestamp` — cloud
//!   backups, including whether this item was uploaded.

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["gphotos0.db", "gphotos.db", "localtrash.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "local_media") {
        read_local_media(&conn, path, &mut out);
    }
    if table_exists(&conn, "remote_media") {
        read_remote_media(&conn, path, &mut out);
    }
    out
}

fn read_local_media(conn: &Connection, path: &Path, out: &mut Vec<ArtifactRecord>) {
    let has_lat = column_exists(conn, "local_media", "latitude");
    let has_lon = column_exists(conn, "local_media", "longitude");
    let mut sql = String::from("SELECT filename, dateTakenMs");
    if has_lat {
        sql.push_str(", latitude");
    } else {
        sql.push_str(", NULL");
    }
    if has_lon {
        sql.push_str(", longitude");
    } else {
        sql.push_str(", NULL");
    }
    sql.push_str(" FROM local_media ORDER BY dateTakenMs DESC LIMIT 20000");

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return;
    };
    for (filename, taken_ms, lat, lon) in rows.flatten() {
        let filename = filename.unwrap_or_else(|| "(unnamed)".to_string());
        let ts = taken_ms.and_then(unix_ms_to_i64);
        let mut detail = format!("Google Photos local_media file='{}'", filename);
        if let (Some(la), Some(lo)) = (lat, lon) {
            if la != 0.0 || lo != 0.0 {
                detail.push_str(&format!(" geo=({:.6},{:.6})", la, lo));
            }
        }
        out.push(build_record(
            ArtifactCategory::Media,
            "Android Google Photos (local)",
            format!("Photo: {}", filename),
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
}

fn read_remote_media(conn: &Connection, path: &Path, out: &mut Vec<ArtifactRecord>) {
    let sql = "SELECT media_key, timestamp FROM remote_media ORDER BY timestamp DESC LIMIT 20000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return;
    };
    for (media_key, ts_ms) in rows.flatten() {
        let key = media_key.unwrap_or_else(|| "(no key)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        out.push(build_record(
            ArtifactCategory::CloudSync,
            "Android Google Photos (remote)",
            format!("Cloud Photo: {}", key),
            format!(
                "Google Photos remote_media key='{}' — uploaded to cloud",
                key
            ),
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
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
            CREATE TABLE local_media (
                id INTEGER PRIMARY KEY,
                filename TEXT,
                dateTakenMs INTEGER,
                latitude REAL,
                longitude REAL
            );
            CREATE TABLE remote_media (
                id INTEGER PRIMARY KEY,
                media_key TEXT,
                timestamp INTEGER
            );
            INSERT INTO local_media VALUES(1,'IMG_001.jpg',1609459200000,37.4219,-122.0840);
            INSERT INTO local_media VALUES(2,'IMG_002.jpg',1609459300000,0,0);
            INSERT INTO remote_media VALUES(1,'abc123',1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn reads_local_and_remote() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn local_geo_appears_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let img1 = r.iter().find(|x| x.title.contains("IMG_001.jpg")).unwrap();
        assert!(img1.detail.contains("geo=(37.421900,-122.084000)"));
    }

    #[test]
    fn zero_geo_is_dropped() {
        let db = make_db();
        let r = parse(db.path());
        let img2 = r.iter().find(|x| x.title.contains("IMG_002.jpg")).unwrap();
        assert!(!img2.detail.contains("geo="));
    }

    #[test]
    fn remote_records_categorized_cloudsync() {
        let db = make_db();
        let r = parse(db.path());
        let remote = r
            .iter()
            .find(|x| x.subcategory == "Android Google Photos (remote)")
            .unwrap();
        assert_eq!(remote.category, ArtifactCategory::CloudSync);
    }
}
