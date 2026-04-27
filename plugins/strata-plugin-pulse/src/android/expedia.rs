//! Expedia — Android trip segment extraction (flights, hotels, car rentals).
//!
//! Source path: `/data/data/com.expedia.bookings/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Expedia stores itinerary data in
//! Room databases with tables like `trips` and `trip_segments`. A single
//! itinerary may contain multiple segments (flight, hotel, car). Key forensic
//! fields: segment_type, confirmation, traveler names, origin/destination.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.expedia.bookings/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_trips(&conn, path));
    out.extend(parse_segments(&conn, path));
    out
}

fn parse_trips(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "trips") {
        "trips"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT trip_id, title, start_date, end_date, travelers \
         FROM \"{t}\" ORDER BY start_date DESC LIMIT 2000",
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (trip_id, title, start_ms, end_ms, travelers) in rows.flatten() {
        let trip_id = trip_id.unwrap_or_default();
        let title = title.unwrap_or_else(|| "(unknown trip)".to_string());
        let travelers = travelers.unwrap_or_default();
        let ts = start_ms.and_then(unix_ms_to_i64);
        let record_title = format!("Expedia trip: {}", title);
        let detail = format!(
            "Expedia trip id='{}' title='{}' start='{}' end='{}' travelers='{}'",
            trip_id,
            title,
            fmt_ts(start_ms.and_then(unix_ms_to_i64)),
            fmt_ts(end_ms.and_then(unix_ms_to_i64)),
            travelers
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Expedia Trip",
            record_title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn parse_segments(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "trip_segments") {
        "trip_segments"
    } else if table_exists(conn, "itinerary_items") {
        "itinerary_items"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT segment_id, trip_id, segment_type, confirmation_code, \
         origin, destination, departure_time, arrival_time, travelers \
         FROM \"{t}\" ORDER BY departure_time DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (seg_id, trip_id, seg_type, confirm, origin, dest, dep_ms, arr_ms, travelers) in
        rows.flatten()
    {
        let seg_id = seg_id.unwrap_or_default();
        let trip_id = trip_id.unwrap_or_default();
        let seg_type = seg_type.unwrap_or_else(|| "unknown".to_string());
        let confirm = confirm.unwrap_or_default();
        let origin = origin.unwrap_or_default();
        let dest = dest.unwrap_or_default();
        let travelers = travelers.unwrap_or_default();
        let ts = dep_ms.and_then(unix_ms_to_i64);
        let title = format!("Expedia {}: {} → {}", seg_type, origin, dest);
        let detail = format!(
            "Expedia segment id='{}' trip='{}' type='{}' confirmation='{}' \
             origin='{}' destination='{}' departure='{}' arrival='{}' travelers='{}'",
            seg_id,
            trip_id,
            seg_type,
            confirm,
            origin,
            dest,
            fmt_ts(dep_ms.and_then(unix_ms_to_i64)),
            fmt_ts(arr_ms.and_then(unix_ms_to_i64)),
            travelers
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Expedia Segment",
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE trips (
                trip_id TEXT,
                title TEXT,
                start_date INTEGER,
                end_date INTEGER,
                travelers TEXT
            );
            INSERT INTO trips VALUES('trp-1','New York Business Trip',1700000000000,1700432000000,'John Doe');
            CREATE TABLE trip_segments (
                segment_id TEXT,
                trip_id TEXT,
                segment_type TEXT,
                confirmation_code TEXT,
                origin TEXT,
                destination TEXT,
                departure_time INTEGER,
                arrival_time INTEGER,
                travelers TEXT
            );
            INSERT INTO trip_segments VALUES(
                'seg-1','trp-1','flight','EXP-7712','LAX','JFK',
                1700000000000,1700018000000,'John Doe'
            );
            INSERT INTO trip_segments VALUES(
                'seg-2','trp-1','hotel','EXP-7713','JFK','JFK',
                1700018000000,1700432000000,'John Doe'
            );
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_trip_and_segments() {
        let db = make_db();
        let r = parse(db.path());
        let trips: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Expedia Trip")
            .collect();
        let segs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Expedia Segment")
            .collect();
        assert_eq!(trips.len(), 1);
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn flight_segment_has_confirmation() {
        let db = make_db();
        let r = parse(db.path());
        let segs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Expedia Segment")
            .collect();
        assert!(segs
            .iter()
            .any(|a| a.detail.contains("confirmation='EXP-7712'")));
    }

    #[test]
    fn segment_origin_destination_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("LAX") && a.title.contains("JFK")));
    }

    #[test]
    fn missing_tables_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
