//! iOS Photo Analysis — `ZCOMPUTEDASSETATTRIBUTES` in `Photos.sqlite`.
//!
//! Apple's on-device ML classifies every photo: face count, body count,
//! scene type, activity. This is a *separate* parser from `photos.rs`
//! because it targets the ML classification tables, not the asset
//! inventory. Reveals photo content without viewing image bytes.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    // Same file as photos.rs but we produce different records
    util::name_is(path, &["photos.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "ZCOMPUTEDASSETATTRIBUTES") { return out; }
    let source = path.to_string_lossy().to_string();
    let count = util::count_rows(&conn, "ZCOMPUTEDASSETATTRIBUTES");

    // Count photos with detected faces/bodies
    let faces: i64 = conn
        .prepare("SELECT COUNT(*) FROM ZCOMPUTEDASSETATTRIBUTES WHERE ZFACECOUNT > 0")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .unwrap_or(0);
    let bodies: i64 = conn
        .prepare("SELECT COUNT(*) FROM ZCOMPUTEDASSETATTRIBUTES WHERE ZBODYCOUNT > 0")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .unwrap_or(0);

    out.push(ArtifactRecord {
        category: ArtifactCategory::Media,
        subcategory: "Photo Analysis ML".to_string(),
        timestamp: None,
        title: "iOS Photo ML classification".to_string(),
        detail: format!(
            "{} classified assets — {} with faces, {} with bodies (no image bytes read)",
            count, faces, bodies
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_analysis_db(rows: &[(i64, i64)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZCOMPUTEDASSETATTRIBUTES (Z_PK INTEGER PRIMARY KEY, ZFACECOUNT INTEGER, ZBODYCOUNT INTEGER)", []).unwrap();
        for (fc, bc) in rows {
            c.execute("INSERT INTO ZCOMPUTEDASSETATTRIBUTES (ZFACECOUNT, ZBODYCOUNT) VALUES (?1, ?2)", rusqlite::params![*fc, *bc]).unwrap();
        }
        tmp
    }

    #[test]
    fn parses_face_and_body_counts() {
        let tmp = make_analysis_db(&[(2, 1), (0, 0), (1, 0)]);
        let recs = parse(tmp.path());
        let r = recs.iter().find(|r| r.subcategory == "Photo Analysis ML").unwrap();
        assert!(r.detail.contains("3 classified"));
        assert!(r.detail.contains("2 with faces"));
        assert!(r.detail.contains("1 with bodies"));
        assert!(r.detail.contains("no image bytes"));
    }

    #[test]
    fn missing_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn matches_photos_sqlite() {
        assert!(matches(Path::new("/var/mobile/Media/PhotoData/Photos.sqlite")));
    }
}
