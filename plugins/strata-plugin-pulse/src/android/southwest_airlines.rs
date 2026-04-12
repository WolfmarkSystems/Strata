//! Southwest Airlines — Android boarding pass and Rapid Rewards extraction.
//!
//! Source path: `/data/data/com.southwestairlines.mobile/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Southwest uses Room databases with
//! tables like `boarding_passes` and `rapid_rewards_account`. Southwest does
//! not assign seats — seat column may be empty or contain open-seating group
//! (e.g. "A32"). Boarding position and boarding group are key fields.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.southwestairlines.mobile/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_boarding_passes(&conn, path));
    out.extend(parse_rapid_rewards(&conn, path));
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
         departure_time, boarding_position, gate, pnr, passenger_name, status \
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
    for (flight_num, dep, arr, dep_ms, boarding_pos, gate, pnr, passenger, status) in rows.flatten()
    {
        let flight_num = flight_num.unwrap_or_else(|| "(unknown)".to_string());
        let dep = dep.unwrap_or_default();
        let arr = arr.unwrap_or_default();
        let boarding_pos = boarding_pos.unwrap_or_default();
        let gate = gate.unwrap_or_default();
        let pnr = pnr.unwrap_or_default();
        let passenger = passenger.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = dep_ms.and_then(unix_ms_to_i64);
        let title = format!("WN {} boarding pass: {} → {}", flight_num, dep, arr);
        let detail = format!(
            "Southwest boarding_pass flight='{}' departure='{}' arrival='{}' \
             departure_time='{}' boarding_position='{}' gate='{}' pnr='{}' \
             passenger='{}' status='{}'",
            flight_num,
            dep,
            arr,
            fmt_ts(dep_ms.and_then(unix_ms_to_i64)),
            boarding_pos,
            gate,
            pnr,
            passenger,
            status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Southwest Boarding Pass",
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

fn parse_rapid_rewards(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "rapid_rewards_account") {
        "rapid_rewards_account"
    } else if table_exists(conn, "rapid_rewards") {
        "rapid_rewards"
    } else if table_exists(conn, "frequent_flyer") {
        "frequent_flyer"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT account_number, status_level, points_balance, member_name, updated_at \
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
    for (acct_num, status, points, member, updated_ms) in rows.flatten() {
        let acct_num = acct_num.unwrap_or_else(|| "(unknown)".to_string());
        let status = status.unwrap_or_default();
        let points = points.unwrap_or(0);
        let member = member.unwrap_or_default();
        let ts = updated_ms.and_then(unix_ms_to_i64);
        let title = format!("Rapid Rewards account: {}", acct_num);
        let detail = format!(
            "RapidRewards account='{}' member='{}' status='{}' points={} updated='{}'",
            acct_num,
            member,
            status,
            points,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Rapid Rewards Account",
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
                boarding_position TEXT,
                gate TEXT,
                pnr TEXT,
                passenger_name TEXT,
                status TEXT
            );
            INSERT INTO boarding_passes VALUES(
                'WN1024','DAL','MCO',1700000000000,'A32','Gate 7','QPLM8X','BOB JONES','boarded'
            );
            CREATE TABLE rapid_rewards_account (
                account_number TEXT,
                status_level TEXT,
                points_balance INTEGER,
                member_name TEXT,
                updated_at INTEGER
            );
            INSERT INTO rapid_rewards_account VALUES('WN99001122','A-List',34000,'BOB JONES',1700000300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_boarding_pass() {
        let db = make_db();
        let r = parse(db.path());
        let bp: Vec<_> = r.iter().filter(|a| a.subcategory == "Southwest Boarding Pass").collect();
        assert_eq!(bp.len(), 1);
        assert!(bp[0].detail.contains("pnr='QPLM8X'"));
        assert!(bp[0].detail.contains("boarding_position='A32'"));
    }

    #[test]
    fn parses_rapid_rewards() {
        let db = make_db();
        let r = parse(db.path());
        let rr: Vec<_> = r.iter().filter(|a| a.subcategory == "Rapid Rewards Account").collect();
        assert_eq!(rr.len(), 1);
        assert!(rr[0].detail.contains("points=34000"));
        assert!(rr[0].detail.contains("status='A-List'"));
    }

    #[test]
    fn boarding_pass_forensic_value_is_critical() {
        let db = make_db();
        let r = parse(db.path());
        let bp: Vec<_> = r.iter().filter(|a| a.subcategory == "Southwest Boarding Pass").collect();
        assert!(bp.iter().all(|a| a.forensic_value == ForensicValue::Critical));
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
