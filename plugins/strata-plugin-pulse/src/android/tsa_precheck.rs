//! TSA PreCheck / myTSA — travel security enrollment and status.
//!
//! Source path: `/data/data/gov.dhs.tsa.mytsa/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. TSA app caches Known Traveler
//! Number (KTN), wait times, airport info, and flight status lookups.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["gov.dhs.tsa.mytsa/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "traveler_profile") {
        out.extend(read_profile(&conn, path));
    }
    for table in &["airport_search", "wait_time_lookup"] {
        if table_exists(&conn, table) {
            out.extend(read_searches(&conn, path, table));
            break;
        }
    }
    out
}

fn read_profile(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT ktn, first_name, last_name, date_of_birth, \
               membership_type, expiration_date \
               FROM traveler_profile LIMIT 10";
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ktn, first, last, dob, membership_type, expiration) in rows.flatten() {
        let ktn = ktn.unwrap_or_default();
        let first = first.unwrap_or_default();
        let last = last.unwrap_or_default();
        let dob = dob.unwrap_or_default();
        let membership_type = membership_type.unwrap_or_default();
        let expiration = expiration.unwrap_or_default();
        let title = format!("TSA PreCheck: {} {} ({})", first, last, membership_type);
        let detail = format!(
            "TSA PreCheck traveler ktn='{}' name='{} {}' dob='{}' membership='{}' expiration='{}'",
            ktn, first, last, dob, membership_type, expiration
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "TSA PreCheck",
            title,
            detail,
            path,
            None,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn read_searches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT airport_code, airport_name, searched_at, wait_time_minutes \
         FROM \"{table}\" ORDER BY searched_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (airport_code, airport_name, ts_ms, wait_time) in rows.flatten() {
        let airport_code = airport_code.unwrap_or_default();
        let airport_name = airport_name.unwrap_or_default();
        let wait_time = wait_time.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("TSA lookup: {} ({} min wait)", airport_code, wait_time);
        let detail = format!(
            "TSA airport lookup airport_code='{}' airport_name='{}' wait_time_minutes={}",
            airport_code, airport_name, wait_time
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "TSA Airport Lookup",
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
            CREATE TABLE traveler_profile (ktn TEXT, first_name TEXT, last_name TEXT, date_of_birth TEXT, membership_type TEXT, expiration_date TEXT);
            INSERT INTO traveler_profile VALUES('TT1234567','Jane','Doe','1985-03-15','TSA PreCheck','2028-01-01');
            CREATE TABLE airport_search (airport_code TEXT, airport_name TEXT, searched_at INTEGER, wait_time_minutes INTEGER);
            INSERT INTO airport_search VALUES('BWI','Baltimore/Washington International',1609459200000,12);
            INSERT INTO airport_search VALUES('DCA','Ronald Reagan National',1609459300000,8);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_profile_and_searches() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "TSA PreCheck"));
        assert!(r.iter().any(|a| a.subcategory == "TSA Airport Lookup"));
    }

    #[test]
    fn ktn_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("ktn='TT1234567'")));
    }

    #[test]
    fn airport_code_and_wait_time() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("BWI") && a.title.contains("12 min wait")));
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
