//! Delta Airlines — Android boarding pass and SkyMiles frequent flyer extraction.
//!
//! Source path: `/data/data/com.delta.mobile.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Delta uses Room databases with tables
//! like `boarding_passes` and `skymiles_account`. Boarding pass data (flight
//! number, departure, arrival, seat, gate, PNR) establishes travel patterns
//! and is treated as Critical forensic value.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.delta.mobile.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_boarding_passes(&conn, path));
    out.extend(parse_skymiles(&conn, path));
    out
}

fn parse_boarding_passes(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "boarding_passes") {
        "boarding_passes"
    } else if table_exists(conn, "boardingpass") {
        "boardingpass"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT flight_number, departure_airport, arrival_airport, \
         departure_time, seat, gate, pnr, passenger_name, status \
         FROM \"{t}\" ORDER BY departure_time DESC LIMIT 2000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (flight_num, dep, arr, dep_ms, seat, gate, pnr, passenger, status) in rows.flatten() {
        let flight_num = flight_num.unwrap_or_else(|| "(unknown)".to_string());
        let dep = dep.unwrap_or_default();
        let arr = arr.unwrap_or_default();
        let seat = seat.unwrap_or_default();
        let gate = gate.unwrap_or_default();
        let pnr = pnr.unwrap_or_default();
        let passenger = passenger.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = dep_ms.and_then(unix_ms_to_i64);
        let title = format!("DL {} boarding pass: {} → {}", flight_num, dep, arr);
        let detail = format!(
            "Delta boarding_pass flight='{}' departure='{}' arrival='{}' \
             departure_time='{}' seat='{}' gate='{}' pnr='{}' passenger='{}' status='{}'",
            flight_num,
            dep,
            arr,
            fmt_ts(dep_ms.and_then(unix_ms_to_i64)),
            seat,
            gate,
            pnr,
            passenger,
            status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Delta Boarding Pass",
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

fn parse_skymiles(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "skymiles_account") {
        "skymiles_account"
    } else if table_exists(conn, "frequent_flyer") {
        "frequent_flyer"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT account_number, status_level, miles_balance, member_name, updated_at \
         FROM \"{t}\" LIMIT 10",
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (acct_num, status, miles, member, updated_ms) in rows.flatten() {
        let acct_num = acct_num.unwrap_or_else(|| "(unknown)".to_string());
        let status = status.unwrap_or_default();
        let miles = miles.unwrap_or(0);
        let member = member.unwrap_or_default();
        let ts = updated_ms.and_then(unix_ms_to_i64);
        let title = format!("SkyMiles account: {}", acct_num);
        let detail = format!(
            "SkyMiles account='{}' member='{}' status='{}' miles={} updated='{}'",
            acct_num,
            member,
            status,
            miles,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "SkyMiles Account",
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
            CREATE TABLE boarding_passes (
                flight_number TEXT,
                departure_airport TEXT,
                arrival_airport TEXT,
                departure_time INTEGER,
                seat TEXT,
                gate TEXT,
                pnr TEXT,
                passenger_name TEXT,
                status TEXT
            );
            INSERT INTO boarding_passes VALUES(
                'DL411','ATL','SEA',1700000000000,'22F','D14','ZRWT1Q','JANE DOE','boarded'
            );
            CREATE TABLE skymiles_account (
                account_number TEXT,
                status_level TEXT,
                miles_balance INTEGER,
                member_name TEXT,
                updated_at INTEGER
            );
            INSERT INTO skymiles_account VALUES('DL87654321','Platinum',112000,'JANE DOE',1700000100000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_boarding_pass() {
        let db = make_db();
        let r = parse(db.path());
        let bp: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Delta Boarding Pass")
            .collect();
        assert_eq!(bp.len(), 1);
        assert!(bp[0].detail.contains("pnr='ZRWT1Q'"));
        assert!(bp[0].detail.contains("gate='D14'"));
    }

    #[test]
    fn parses_skymiles_account() {
        let db = make_db();
        let r = parse(db.path());
        let ff: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "SkyMiles Account")
            .collect();
        assert_eq!(ff.len(), 1);
        assert!(ff[0].detail.contains("miles=112000"));
        assert!(ff[0].detail.contains("status='Platinum'"));
    }

    #[test]
    fn boarding_pass_forensic_value_is_critical() {
        let db = make_db();
        let r = parse(db.path());
        let bp: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Delta Boarding Pass")
            .collect();
        assert!(bp
            .iter()
            .all(|a| a.forensic_value == ForensicValue::Critical));
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
