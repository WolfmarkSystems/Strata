//! Google Flights — Android searched flights and saved trip extraction.
//!
//! Source path: `/data/data/com.google.android.apps.travel/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Google Flights stores search history
//! in tables like `flight_searches` and saved trips in `saved_trips`. Search
//! history reveals travel intentions and destination research, which can be
//! significant in establishing motive or alibi.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.google.android.apps.travel/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_searches(&conn, path));
    out.extend(parse_saved_trips(&conn, path));
    out
}

fn parse_searches(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "flight_searches") {
        "flight_searches"
    } else if table_exists(conn, "searches") {
        "searches"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT search_id, origin, destination, depart_date, return_date, \
         passengers, cabin_class, searched_at \
         FROM \"{t}\" ORDER BY searched_at DESC LIMIT 5000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (search_id, origin, dest, depart, ret, pax, cabin, searched_ms) in rows.flatten() {
        let search_id = search_id.unwrap_or_default();
        let origin = origin.unwrap_or_default();
        let dest = dest.unwrap_or_else(|| "(unknown)".to_string());
        let depart = depart.unwrap_or_default();
        let ret = ret.unwrap_or_default();
        let pax = pax.unwrap_or(1);
        let cabin = cabin.unwrap_or_default();
        let ts = searched_ms.and_then(unix_ms_to_i64);
        let title = format!("Google Flights search: {} → {}", origin, dest);
        let detail = format!(
            "Google Flights search id='{}' origin='{}' destination='{}' \
             depart_date='{}' return_date='{}' passengers={} cabin='{}' searched_at='{}'",
            search_id,
            origin,
            dest,
            depart,
            ret,
            pax,
            cabin,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Google Flights Search",
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

fn parse_saved_trips(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "saved_trips") {
        "saved_trips"
    } else if table_exists(conn, "tracked_flights") {
        "tracked_flights"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT trip_id, origin, destination, depart_date, return_date, saved_at \
         FROM \"{t}\" ORDER BY saved_at DESC LIMIT 2000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (trip_id, origin, dest, depart, ret, saved_ms) in rows.flatten() {
        let trip_id = trip_id.unwrap_or_default();
        let origin = origin.unwrap_or_default();
        let dest = dest.unwrap_or_else(|| "(unknown)".to_string());
        let depart = depart.unwrap_or_default();
        let ret = ret.unwrap_or_default();
        let ts = saved_ms.and_then(unix_ms_to_i64);
        let title = format!("Google Flights saved trip: {} → {}", origin, dest);
        let detail = format!(
            "Google Flights saved_trip id='{}' origin='{}' destination='{}' \
             depart_date='{}' return_date='{}' saved_at='{}'",
            trip_id,
            origin,
            dest,
            depart,
            ret,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Google Flights Saved Trip",
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
            CREATE TABLE flight_searches (
                search_id TEXT,
                origin TEXT,
                destination TEXT,
                depart_date TEXT,
                return_date TEXT,
                passengers INTEGER,
                cabin_class TEXT,
                searched_at INTEGER
            );
            INSERT INTO flight_searches VALUES('s-1','JFK','CDG','2024-12-01','2024-12-10',2,'economy',1700000000000);
            INSERT INTO flight_searches VALUES('s-2','LAX','NRT','2024-11-15',NULL,1,'business',1699900000000);
            CREATE TABLE saved_trips (
                trip_id TEXT,
                origin TEXT,
                destination TEXT,
                depart_date TEXT,
                return_date TEXT,
                saved_at INTEGER
            );
            INSERT INTO saved_trips VALUES('trp-1','BOS','MIA','2024-12-20','2024-12-27',1699800000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_searches() {
        let db = make_db();
        let r = parse(db.path());
        let searches: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Google Flights Search")
            .collect();
        assert_eq!(searches.len(), 2);
    }

    #[test]
    fn parses_saved_trip() {
        let db = make_db();
        let r = parse(db.path());
        let saved: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Google Flights Saved Trip")
            .collect();
        assert_eq!(saved.len(), 1);
        assert!(saved[0].detail.contains("destination='MIA'"));
    }

    #[test]
    fn search_origin_destination_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("JFK") && a.title.contains("CDG")));
    }

    #[test]
    fn missing_tables_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
