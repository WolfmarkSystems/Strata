//! BeReal — dual-camera social post extraction.
//!
//! Source path: `/data/data/com.bereal.ft/databases/*` or cache.
//!
//! Schema note: not in ALEAPP upstream. BeReal is a RN app that stores
//! posts in `post` or `bereal_post` tables, friends in `friend`. Key
//! forensic fields include dual-camera image paths (front + back),
//! location, and retake count (how many times the user retook the photo
//! before posting — proxy for authenticity concerns).

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.bereal.ft/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["post", "bereal_post", "posts"] {
        if table_exists(&conn, table) {
            out.extend(read_posts(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "friend") {
        out.extend(read_friends(&conn, path));
    }
    out
}

fn read_posts(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, user_id, taken_at, front_image, back_image, \
         caption, location, latitude, longitude, retake_count, is_late \
         FROM \"{table}\" ORDER BY taken_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
            row.get::<_, Option<i64>>(9).unwrap_or(None),
            row.get::<_, Option<i64>>(10).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, user_id, taken_ms, front, back, caption, location, lat, lon, retakes, is_late) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let user_id = user_id.unwrap_or_else(|| "(unknown)".to_string());
        let front = front.unwrap_or_default();
        let back = back.unwrap_or_default();
        let caption = caption.unwrap_or_default();
        let location = location.unwrap_or_default();
        let retakes = retakes.unwrap_or(0);
        let is_late = is_late.unwrap_or(0) != 0;
        let ts = taken_ms.and_then(unix_ms_to_i64);
        let title = format!("BeReal post: {} ({} retakes)", user_id, retakes);
        let mut detail = format!(
            "BeReal post id='{}' user_id='{}' front_image='{}' back_image='{}' retake_count={} is_late={}",
            id, user_id, front, back, retakes, is_late
        );
        if !caption.is_empty() {
            detail.push_str(&format!(" caption='{}'", caption));
        }
        if !location.is_empty() {
            detail.push_str(&format!(" location='{}'", location));
        }
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "BeReal Post",
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

fn read_friends(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, username, full_name, profile_picture \
               FROM friend LIMIT 5000";
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
    for (id, username, full_name, profile_pic) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let username = username.unwrap_or_else(|| "(unknown)".to_string());
        let full_name = full_name.unwrap_or_default();
        let profile_pic = profile_pic.unwrap_or_default();
        let title = format!("BeReal friend: {} ({})", full_name, username);
        let detail = format!(
            "BeReal friend id='{}' username='{}' full_name='{}' profile_picture='{}'",
            id, username, full_name, profile_pic
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "BeReal Friend",
            title,
            detail,
            path,
            None,
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
            CREATE TABLE post (
                id TEXT,
                user_id TEXT,
                taken_at INTEGER,
                front_image TEXT,
                back_image TEXT,
                caption TEXT,
                location TEXT,
                latitude REAL,
                longitude REAL,
                retake_count INTEGER,
                is_late INTEGER
            );
            INSERT INTO post VALUES('p1','u1',1609459200000,'/cache/front1.jpg','/cache/back1.jpg','Morning coffee','San Francisco',37.7749,-122.4194,0,0);
            INSERT INTO post VALUES('p2','u1',1609545600000,'/cache/front2.jpg','/cache/back2.jpg','',NULL,NULL,NULL,5,1);
            CREATE TABLE friend (
                id TEXT,
                username TEXT,
                full_name TEXT,
                profile_picture TEXT
            );
            INSERT INTO friend VALUES('u2','alice_br','Alice','http://pic.jpg');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_posts_and_friends() {
        let db = make_db();
        let r = parse(db.path());
        let posts: Vec<_> = r.iter().filter(|a| a.subcategory == "BeReal Post").collect();
        let friends: Vec<_> = r.iter().filter(|a| a.subcategory == "BeReal Friend").collect();
        assert_eq!(posts.len(), 2);
        assert_eq!(friends.len(), 1);
    }

    #[test]
    fn retake_count_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("retake_count=5") && a.detail.contains("is_late=true")));
    }

    #[test]
    fn dual_camera_images_captured() {
        let db = make_db();
        let r = parse(db.path());
        let p1 = r.iter().find(|a| a.detail.contains("p1")).unwrap();
        assert!(p1.detail.contains("front_image='/cache/front1.jpg'"));
        assert!(p1.detail.contains("back_image='/cache/back1.jpg'"));
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
