//! Realtor.com — Android property search, saved property, and open house RSVP extraction.
//!
//! Source path: `/data/data/com.move.realtor/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Realtor.com uses Room databases with
//! tables like `property_searches`, `saved_properties`, `open_house_rsvps`.
//! Open house RSVPs establish planned physical presence at a specific address
//! and are classified Critical.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.move.realtor/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_searches(&conn, path));
    out.extend(parse_saved_properties(&conn, path));
    out.extend(parse_open_house_rsvps(&conn, path));
    out
}

fn parse_searches(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "property_searches") {
        "property_searches"
    } else if table_exists(conn, "search_history") {
        "search_history"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT query, location, price_min, price_max, beds_min, baths_min, searched_at \
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (query, location, price_min, price_max, beds, baths, searched_ms) in rows.flatten() {
        let query = query.unwrap_or_else(|| "(unknown)".to_string());
        let location = location.unwrap_or_default();
        let ts = searched_ms.and_then(unix_ms_to_i64);
        let title = format!("Realtor.com search: {} in {}", query, location);
        let detail = format!(
            "Realtor.com property_search query='{}' location='{}' price_min={} \
             price_max={} beds_min={} baths_min={} searched_at='{}'",
            query,
            location,
            price_min.unwrap_or(0),
            price_max.unwrap_or(0),
            beds.unwrap_or(0),
            baths.unwrap_or(0),
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Realtor.com Property Search",
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

fn parse_saved_properties(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "saved_properties") {
        "saved_properties"
    } else if table_exists(conn, "favorites") {
        "favorites"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT property_id, address, price, beds, baths, sqft, saved_at \
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (property_id, address, price, beds, baths, sqft, saved_ms) in rows.flatten() {
        let property_id = property_id.unwrap_or_default();
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let ts = saved_ms.and_then(unix_ms_to_i64);
        let title = format!("Realtor.com saved: {}", address);
        let detail = format!(
            "Realtor.com saved_property id='{}' address='{}' price={} beds={} \
             baths={} sqft={} saved_at='{}'",
            property_id,
            address,
            price.unwrap_or(0),
            beds.unwrap_or(0),
            baths.unwrap_or(0),
            sqft.unwrap_or(0),
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Realtor.com Saved Property",
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

fn parse_open_house_rsvps(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "open_house_rsvps") {
        "open_house_rsvps"
    } else if table_exists(conn, "open_house_registrations") {
        "open_house_registrations"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT property_id, address, event_date, agent_name, rsvp_status, rsvped_at \
         FROM \"{t}\" ORDER BY rsvped_at DESC LIMIT 2000",
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (property_id, address, event_ms, agent, status, rsvped_ms) in rows.flatten() {
        let property_id = property_id.unwrap_or_default();
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let agent = agent.unwrap_or_default();
        let status = status.unwrap_or_default();
        let event_ts = event_ms.and_then(unix_ms_to_i64);
        let ts = rsvped_ms.and_then(unix_ms_to_i64);
        let title = format!("Realtor.com open house RSVP: {}", address);
        let detail = format!(
            "Realtor.com open_house_rsvp id='{}' address='{}' event_date='{}' \
             agent='{}' status='{}' rsvped_at='{}'",
            property_id,
            address,
            fmt_ts(event_ts),
            agent,
            status,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Realtor.com Open House RSVP",
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
            CREATE TABLE property_searches (
                query TEXT,
                location TEXT,
                price_min INTEGER,
                price_max INTEGER,
                beds_min INTEGER,
                baths_min INTEGER,
                searched_at INTEGER
            );
            INSERT INTO property_searches VALUES('3br house','Denver, CO',400000,700000,3,2,1700000000000);
            CREATE TABLE saved_properties (
                property_id TEXT,
                address TEXT,
                price INTEGER,
                beds INTEGER,
                baths INTEGER,
                sqft INTEGER,
                saved_at INTEGER
            );
            INSERT INTO saved_properties VALUES('rdc-001','789 Oak Ave, Denver, CO',550000,3,2,1950,1700100000000);
            CREATE TABLE open_house_rsvps (
                property_id TEXT,
                address TEXT,
                event_date INTEGER,
                agent_name TEXT,
                rsvp_status TEXT,
                rsvped_at INTEGER
            );
            INSERT INTO open_house_rsvps VALUES('rdc-001','789 Oak Ave, Denver, CO',1700200000000,'Sarah K','confirmed',1700150000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_search_saved_and_rsvp() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Realtor.com Property Search"));
        assert!(r.iter().any(|a| a.subcategory == "Realtor.com Saved Property"));
        assert!(r.iter().any(|a| a.subcategory == "Realtor.com Open House RSVP"));
    }

    #[test]
    fn rsvp_is_critical() {
        let db = make_db();
        let r = parse(db.path());
        let rsvps: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Realtor.com Open House RSVP")
            .collect();
        assert_eq!(rsvps.len(), 1);
        assert_eq!(rsvps[0].forensic_value, ForensicValue::Critical);
        assert!(rsvps[0].detail.contains("agent='Sarah K'"));
        assert!(rsvps[0].detail.contains("status='confirmed'"));
    }

    #[test]
    fn search_captures_location_filters() {
        let db = make_db();
        let r = parse(db.path());
        let searches: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Realtor.com Property Search")
            .collect();
        assert!(searches[0].detail.contains("location='Denver, CO'"));
        assert!(searches[0].detail.contains("beds_min=3"));
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
