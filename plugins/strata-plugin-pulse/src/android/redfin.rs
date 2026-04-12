//! Redfin — Android property search, saved home, and tour schedule extraction.
//!
//! Source path: `/data/data/com.redfin.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Redfin uses Room databases with
//! tables like `property_searches`, `saved_homes`, `tour_schedules`. Tour
//! schedules record planned physical presence at a specific address (date,
//! time, agent) and are classified Critical.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.redfin.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_searches(&conn, path));
    out.extend(parse_saved_homes(&conn, path));
    out.extend(parse_tour_schedules(&conn, path));
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
        let title = format!("Redfin search: {} in {}", query, location);
        let detail = format!(
            "Redfin property_search query='{}' location='{}' price_min={} \
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
            "Redfin Property Search",
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

fn parse_saved_homes(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "saved_homes") {
        "saved_homes"
    } else if table_exists(conn, "favorites") {
        "favorites"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT home_id, address, price, beds, baths, sqft, saved_at \
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
    for (home_id, address, price, beds, baths, sqft, saved_ms) in rows.flatten() {
        let home_id = home_id.unwrap_or_default();
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let ts = saved_ms.and_then(unix_ms_to_i64);
        let title = format!("Redfin saved home: {}", address);
        let detail = format!(
            "Redfin saved_home id='{}' address='{}' price={} beds={} baths={} \
             sqft={} saved_at='{}'",
            home_id,
            address,
            price.unwrap_or(0),
            beds.unwrap_or(0),
            baths.unwrap_or(0),
            sqft.unwrap_or(0),
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Redfin Saved Home",
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

fn parse_tour_schedules(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "tour_schedules") {
        "tour_schedules"
    } else if table_exists(conn, "scheduled_tours") {
        "scheduled_tours"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT home_id, address, tour_date, tour_time, agent_name, tour_status, scheduled_at \
         FROM \"{t}\" ORDER BY scheduled_at DESC LIMIT 2000",
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
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (home_id, address, tour_date_ms, tour_time, agent, status, scheduled_ms) in rows.flatten()
    {
        let home_id = home_id.unwrap_or_default();
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let tour_time = tour_time.unwrap_or_default();
        let agent = agent.unwrap_or_default();
        let status = status.unwrap_or_default();
        let tour_ts = tour_date_ms.and_then(unix_ms_to_i64);
        let ts = scheduled_ms.and_then(unix_ms_to_i64);
        let title = format!("Redfin tour scheduled: {}", address);
        let detail = format!(
            "Redfin tour_schedule id='{}' address='{}' tour_date='{}' tour_time='{}' \
             agent='{}' status='{}' scheduled_at='{}'",
            home_id,
            address,
            fmt_ts(tour_ts),
            tour_time,
            agent,
            status,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Redfin Tour Schedule",
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
            INSERT INTO property_searches VALUES('condo','Seattle, WA',350000,600000,2,1,1700000000000);
            CREATE TABLE saved_homes (
                home_id TEXT,
                address TEXT,
                price INTEGER,
                beds INTEGER,
                baths INTEGER,
                sqft INTEGER,
                saved_at INTEGER
            );
            INSERT INTO saved_homes VALUES('rf-9001','321 Pine St, Seattle, WA',520000,2,2,1100,1700050000000);
            CREATE TABLE tour_schedules (
                home_id TEXT,
                address TEXT,
                tour_date INTEGER,
                tour_time TEXT,
                agent_name TEXT,
                tour_status TEXT,
                scheduled_at INTEGER
            );
            INSERT INTO tour_schedules VALUES('rf-9001','321 Pine St, Seattle, WA',1700250000000,'10:00 AM','Alex R','scheduled',1700200000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_search_saved_and_tour() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Redfin Property Search"));
        assert!(r.iter().any(|a| a.subcategory == "Redfin Saved Home"));
        assert!(r.iter().any(|a| a.subcategory == "Redfin Tour Schedule"));
    }

    #[test]
    fn tour_is_critical_with_agent() {
        let db = make_db();
        let r = parse(db.path());
        let tours: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Redfin Tour Schedule")
            .collect();
        assert_eq!(tours.len(), 1);
        assert_eq!(tours[0].forensic_value, ForensicValue::Critical);
        assert!(tours[0].detail.contains("agent='Alex R'"));
        assert!(tours[0].detail.contains("tour_time='10:00 AM'"));
    }

    #[test]
    fn search_captures_location_and_price() {
        let db = make_db();
        let r = parse(db.path());
        let searches: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Redfin Property Search")
            .collect();
        assert!(searches[0].detail.contains("location='Seattle, WA'"));
        assert!(searches[0].detail.contains("price_min=350000"));
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
