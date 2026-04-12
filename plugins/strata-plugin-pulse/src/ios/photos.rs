//! iOS `Photos.sqlite` — PhotosLibrary metadata.
//!
//! **Image bytes are never read.** This parser opens the metadata
//! database read-only, counts assets and albums, and emits the date
//! range. Image content is the responsibility of the CSAM module via
//! the Sentinel plugin — Pulse never embeds or hashes pixel data.
//!
//! The schema iLEAPP keys off varies between iOS versions:
//!   * iOS 13+: `ZASSET` (`ZDATECREATED`, `ZFILENAME`, `ZUNIFORMTYPEIDENTIFIER`)
//!   * iOS 12 :  `ZGENERICASSET` (same fields)
//!   * `ZGENERICALBUM` — album rows
//!
//! Pulse v1.0 emits one summary record per detected asset table plus
//! one record for the album count, all metadata-only.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["photos.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    // Probe both schema variants — most modern iOS uses ZASSET, but
    // legacy backups still ship ZGENERICASSET.
    for table in ["ZASSET", "ZGENERICASSET"] {
        if !util::table_exists(&conn, table) {
            continue;
        }
        let count = util::count_rows(&conn, table);
        let (first, last) = conn
            .prepare(&format!(
                "SELECT MIN(ZDATECREATED), MAX(ZDATECREATED) FROM {} \
                 WHERE ZDATECREATED IS NOT NULL",
                table
            ))
            .and_then(|mut s| {
                s.query_row([], |row| {
                    Ok((row.get::<_, Option<f64>>(0)?, row.get::<_, Option<f64>>(1)?))
                })
            })
            .unwrap_or((None, None));
        let first_unix = first.and_then(util::cf_absolute_to_unix);
        let last_unix = last.and_then(util::cf_absolute_to_unix);

        out.push(ArtifactRecord {
            category: ArtifactCategory::Media,
            subcategory: format!("Photos {}", table),
            timestamp: first_unix,
            title: "iOS Photos library".to_string(),
            detail: format!(
                "{} {} rows (image bytes NOT read), date range {:?}..{:?} Unix",
                count, table, first_unix, last_unix
            ),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }

    if util::table_exists(&conn, "ZGENERICALBUM") {
        let count = util::count_rows(&conn, "ZGENERICALBUM");
        out.push(ArtifactRecord {
            category: ArtifactCategory::Media,
            subcategory: "Photos albums".to_string(),
            timestamp: None,
            title: "Photos albums".to_string(),
            detail: format!("{} ZGENERICALBUM rows", count),
            source_path: source.clone(),
            forensic_value: ForensicValue::Medium,
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

    fn make_photos_db(asset_table: &str, asset_rows: usize, albums: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            &format!(
                "CREATE TABLE {} (\
                    Z_PK INTEGER PRIMARY KEY, \
                    ZDATECREATED DOUBLE, \
                    ZFILENAME TEXT, \
                    ZUNIFORMTYPEIDENTIFIER TEXT \
                 )",
                asset_table
            ),
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE ZGENERICALBUM (Z_PK INTEGER PRIMARY KEY, ZTITLE TEXT)",
            [],
        )
        .unwrap();
        for i in 0..asset_rows {
            c.execute(
                &format!(
                    "INSERT INTO {} (ZDATECREATED, ZFILENAME, ZUNIFORMTYPEIDENTIFIER) \
                     VALUES (?1, ?2, 'public.jpeg')",
                    asset_table
                ),
                rusqlite::params![700_000_000.0_f64 + i as f64, format!("IMG_{:04}.JPG", i)],
            )
            .unwrap();
        }
        for i in 0..albums {
            c.execute(
                "INSERT INTO ZGENERICALBUM (ZTITLE) VALUES (?1)",
                rusqlite::params![format!("Album {}", i)],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_photos_sqlite() {
        assert!(matches(Path::new(
            "/private/var/mobile/Media/PhotoData/Photos.sqlite"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/Safari/History.db")));
    }

    #[test]
    fn parses_modern_zasset_schema() {
        let tmp = make_photos_db("ZASSET", 4, 2);
        let records = parse(tmp.path());
        let asset = records
            .iter()
            .find(|r| r.subcategory == "Photos ZASSET")
            .expect("zasset record");
        assert!(asset.detail.contains("4 ZASSET"));
        assert!(asset.detail.contains("image bytes NOT read"));
        let albums = records
            .iter()
            .find(|r| r.subcategory == "Photos albums")
            .expect("albums record");
        assert!(albums.detail.contains("2 ZGENERICALBUM"));
    }

    #[test]
    fn parses_legacy_zgenericasset_schema() {
        let tmp = make_photos_db("ZGENERICASSET", 3, 0);
        let records = parse(tmp.path());
        assert!(records
            .iter()
            .any(|r| r.subcategory == "Photos ZGENERICASSET"));
    }

    #[test]
    fn parser_never_emits_image_bytes() {
        let tmp = make_photos_db("ZASSET", 1, 0);
        let records = parse(tmp.path());
        for r in records {
            assert!(r.raw_data.is_none(), "raw_data must stay None for Photos");
            assert!(!r.detail.to_lowercase().contains("base64"));
            assert!(!r.detail.to_lowercase().contains("payload"));
        }
    }

    #[test]
    fn empty_db_returns_no_records() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        let records = parse(tmp.path());
        assert!(records.is_empty());
    }
}
