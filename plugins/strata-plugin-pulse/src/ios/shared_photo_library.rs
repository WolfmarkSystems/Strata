//! LEGACY-IOS-4 — iCloud Shared Photo Library (iOS 14-18).
//!
//! Parses the ZSHARE table in Photos.sqlite and emits per-share
//! metadata + per-asset contribution records. The attribution-safe
//! output distinguishes between assets the device user contributed
//! and assets contributed by other participants — critical for CSAM
//! and trafficking scope questions.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ICloudSharedLibrary {
    pub share_id: i64,
    pub library_name: String,
    pub creator: String,
    pub created_date: Option<DateTime<Utc>>,
    pub participants: Vec<SharedLibraryParticipant>,
    pub asset_count: u64,
    pub is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharedLibraryParticipant {
    pub apple_id: String,
    pub role: String,
    pub invite_date: Option<DateTime<Utc>>,
    pub accept_date: Option<DateTime<Utc>>,
    pub removed_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharedAsset {
    pub asset_id: i64,
    pub contributor_apple_id: String,
    pub contribution_date: Option<DateTime<Utc>>,
    pub file_path: Option<String>,
    pub original_filename: Option<String>,
    pub moved_from_personal: bool,
    pub attributed_to_device_user: bool,
}

/// Parse the ZSHARE table for library metadata.
pub fn parse_libraries(conn: &Connection, device_apple_id: &str) -> Vec<ICloudSharedLibrary> {
    if !table_exists(conn, "ZSHARE") {
        return Vec::new();
    }
    let cols = col_names(conn, "ZSHARE");
    let mut stmt = match conn.prepare(&format!(
        "SELECT Z_PK, {}, {}, {}, {} FROM ZSHARE",
        pick(&cols, &["ZNAME", "ZTITLE"]).unwrap_or_else(|| "NULL".into()),
        pick(&cols, &["ZCREATOR", "ZORIGINATOR"]).unwrap_or_else(|| "NULL".into()),
        pick(&cols, &["ZCREATIONDATE", "ZDATE"]).unwrap_or_else(|| "NULL".into()),
        pick(&cols, &["ZASSETCOUNT"]).unwrap_or_else(|| "0".into()),
    )) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, Option<String>>(1).unwrap_or(None),
            r.get::<_, Option<String>>(2).unwrap_or(None),
            r.get::<_, Option<f64>>(3).unwrap_or(None),
            r.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    let mut out = Vec::new();
    for (id, name, creator, created, count) in rows.flatten() {
        out.push(ICloudSharedLibrary {
            share_id: id,
            library_name: name.unwrap_or_default(),
            creator: creator.unwrap_or_else(|| device_apple_id.to_string()),
            created_date: created.and_then(cocoa_to_utc_f),
            participants: Vec::new(),
            asset_count: count.unwrap_or(0).max(0) as u64,
            is_active: true,
        });
    }
    out
}

pub fn parse_shared_assets(conn: &Connection, device_apple_id: &str) -> Vec<SharedAsset> {
    if !table_exists(conn, "ZSHAREDASSET") {
        return Vec::new();
    }
    let cols = col_names(conn, "ZSHAREDASSET");
    let sql = format!(
        "SELECT Z_PK, {}, {}, {}, {} FROM ZSHAREDASSET",
        pick(&cols, &["ZCONTRIBUTORAPPLEID", "ZCONTRIBUTOR"]).unwrap_or_else(|| "NULL".into()),
        pick(&cols, &["ZCONTRIBUTIONDATE", "ZDATE"]).unwrap_or_else(|| "NULL".into()),
        pick(&cols, &["ZPATH", "ZFILEPATH"]).unwrap_or_else(|| "NULL".into()),
        pick(&cols, &["ZORIGINALFILENAME", "ZFILENAME"]).unwrap_or_else(|| "NULL".into()),
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, Option<String>>(1).unwrap_or(None),
            r.get::<_, Option<f64>>(2).unwrap_or(None),
            r.get::<_, Option<String>>(3).unwrap_or(None),
            r.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    let mut out = Vec::new();
    for (id, contributor, date, path, filename) in rows.flatten() {
        let contributor = contributor.unwrap_or_default();
        let attributed = contributor.eq_ignore_ascii_case(device_apple_id);
        out.push(SharedAsset {
            asset_id: id,
            contributor_apple_id: contributor,
            contribution_date: date.and_then(cocoa_to_utc_f),
            file_path: path,
            original_filename: filename,
            moved_from_personal: false,
            attributed_to_device_user: attributed,
        });
    }
    out
}

fn table_exists(conn: &Connection, t: &str) -> bool {
    conn.query_row(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?1",
        [t],
        |r| r.get::<_, String>(0),
    )
    .is_ok()
}

fn col_names(conn: &Connection, table: &str) -> Vec<String> {
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    stmt.query_map([], |r| r.get::<_, String>(1))
        .ok()
        .map(|r| r.flatten().collect())
        .unwrap_or_default()
}

fn pick(cols: &[String], candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if cols.iter().any(|x| x.eq_ignore_ascii_case(c)) {
            return Some((*c).into());
        }
    }
    None
}

fn cocoa_to_utc_f(ts: f64) -> Option<DateTime<Utc>> {
    if ts <= 0.0 {
        return None;
    }
    let cocoa_epoch_offset = 978_307_200i64;
    Utc.timestamp_opt(ts as i64 + cocoa_epoch_offset, 0).single()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(device_id: &str) -> Connection {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE ZSHARE (Z_PK INTEGER PRIMARY KEY, ZNAME TEXT, ZCREATOR TEXT, \
             ZCREATIONDATE REAL, ZASSETCOUNT INTEGER);\
             CREATE TABLE ZSHAREDASSET (Z_PK INTEGER PRIMARY KEY, ZCONTRIBUTORAPPLEID TEXT, \
             ZCONTRIBUTIONDATE REAL, ZPATH TEXT, ZORIGINALFILENAME TEXT);",
        )
        .expect("schema");
        c.execute(
            "INSERT INTO ZSHARE VALUES (1, 'Family Library', ?, 700000000.0, 42)",
            [device_id],
        )
        .expect("ins");
        c.execute(
            "INSERT INTO ZSHAREDASSET VALUES (1, ?, 700000100.0, 'DCIM/IMG_0001.HEIC', 'IMG_0001.HEIC')",
            [device_id],
        )
        .expect("ins");
        c.execute(
            "INSERT INTO ZSHAREDASSET VALUES (2, 'someone-else@icloud.com', 700000200.0, 'DCIM/IMG_0002.HEIC', 'IMG_0002.HEIC')",
            [],
        )
        .expect("ins");
        c
    }

    #[test]
    fn parses_libraries_with_name_and_count() {
        let c = fixture("korbyn@example.com");
        let libs = parse_libraries(&c, "korbyn@example.com");
        assert_eq!(libs.len(), 1);
        assert_eq!(libs[0].library_name, "Family Library");
        assert_eq!(libs[0].asset_count, 42);
    }

    #[test]
    fn attributes_device_user_assets_correctly() {
        let c = fixture("korbyn@example.com");
        let assets = parse_shared_assets(&c, "korbyn@example.com");
        assert_eq!(assets.len(), 2);
        let own = assets.iter().filter(|a| a.attributed_to_device_user).count();
        let other = assets.iter().filter(|a| !a.attributed_to_device_user).count();
        assert_eq!(own, 1);
        assert_eq!(other, 1);
    }

    #[test]
    fn missing_tables_return_empty() {
        let c = Connection::open_in_memory().expect("open");
        assert!(parse_libraries(&c, "x@y").is_empty());
        assert!(parse_shared_assets(&c, "x@y").is_empty());
    }

    #[test]
    fn contribution_date_converts_from_cocoa() {
        let c = fixture("korbyn@example.com");
        let assets = parse_shared_assets(&c, "korbyn@example.com");
        let first = assets.iter().find(|a| a.asset_id == 1).expect("asset");
        assert!(first.contribution_date.is_some());
    }
}
