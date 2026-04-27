//! Army/DoD Mobile — Army Mobile, MyPay, AKO, and related mil apps.
//!
//! Source paths:
//! - `/data/data/com.army.armymobile/databases/*.db`
//! - `/data/data/mil.dfas.mypay/databases/*.db`
//! - `/data/data/mil.army.ako/databases/*.db`
//!
//! Schema note: not in ALEAPP upstream. Military apps cache user
//! profile data (rank, unit, installation), MyPay leave/pay stubs,
//! and AKO message history. High forensic value for CI investigations.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.army.armymobile/databases/",
    "mil.dfas.mypay/databases/",
    "mil.army.ako/databases/",
    "mil.dod.cac/databases/",
    "gov.army/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "user_profile") {
        out.extend(read_profile(&conn, path));
    }
    for table in &["pay_stub", "les", "pay_history"] {
        if table_exists(&conn, table) {
            out.extend(read_pay(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "message") {
        out.extend(read_messages(&conn, path));
    }
    for table in &["notification", "alert_history"] {
        if table_exists(&conn, table) {
            out.extend(read_notifications(&conn, path, table));
            break;
        }
    }
    out
}

fn read_profile(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT dodid, rank, last_name, first_name, unit, \
               installation, branch, component, mos \
               FROM user_profile LIMIT 10";
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
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (dodid, rank, last_name, first_name, unit, installation, branch, component, mos) in
        rows.flatten()
    {
        let dodid = dodid.unwrap_or_default();
        let rank = rank.unwrap_or_default();
        let last_name = last_name.unwrap_or_default();
        let first_name = first_name.unwrap_or_default();
        let unit = unit.unwrap_or_default();
        let installation = installation.unwrap_or_default();
        let branch = branch.unwrap_or_default();
        let component = component.unwrap_or_default();
        let mos = mos.unwrap_or_default();
        let title = format!("Army profile: {} {} {}", rank, first_name, last_name);
        let detail = format!(
            "Army Mobile profile dodid='{}' rank='{}' name='{} {}' unit='{}' installation='{}' branch='{}' component='{}' mos='{}'",
            dodid, rank, first_name, last_name, unit, installation, branch, component, mos
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Army Profile",
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

fn read_pay(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, pay_date, gross_pay, net_pay, entitlements, \
         deductions, allotments \
         FROM \"{table}\" ORDER BY pay_date DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, pay_date_ms, gross, net, entitlements, deductions, allotments) in rows.flatten() {
        let id = id.unwrap_or_default();
        let gross = gross.unwrap_or_default();
        let net = net.unwrap_or_default();
        let entitlements = entitlements.unwrap_or_default();
        let deductions = deductions.unwrap_or_default();
        let allotments = allotments.unwrap_or_default();
        let ts = pay_date_ms.and_then(unix_ms_to_i64);
        let title = format!("MyPay LES: gross={} net={}", gross, net);
        let detail = format!(
            "MyPay pay stub id='{}' gross_pay='{}' net_pay='{}' entitlements='{}' deductions='{}' allotments='{}'",
            id, gross, net, entitlements, deductions, allotments
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "MyPay LES",
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

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, sender, subject, body, received_at, is_read \
               FROM message ORDER BY received_at DESC LIMIT 5000";
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, sender, subject, body, ts_ms, is_read) in rows.flatten() {
        let id = id.unwrap_or_default();
        let sender = sender.unwrap_or_default();
        let subject = subject.unwrap_or_default();
        let body = body.unwrap_or_default();
        let is_read = is_read.unwrap_or(0) != 0;
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("AKO message: {} — {}", sender, subject);
        let detail = format!(
            "Army/AKO message id='{}' sender='{}' subject='{}' body='{}' is_read={}",
            id, sender, subject, body, is_read
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Army Message",
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

fn read_notifications(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, title, body, received_at, category \
         FROM \"{table}\" ORDER BY received_at DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, notif_title, body, ts_ms, category) in rows.flatten() {
        let id = id.unwrap_or_default();
        let notif_title = notif_title.unwrap_or_default();
        let body = body.unwrap_or_default();
        let category = category.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Army notification: {}", notif_title);
        let detail = format!(
            "Army notification id='{}' title='{}' body='{}' category='{}'",
            id, notif_title, body, category
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Army Notification",
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
            CREATE TABLE user_profile (dodid TEXT, rank TEXT, last_name TEXT, first_name TEXT, unit TEXT, installation TEXT, branch TEXT, component TEXT, mos TEXT);
            INSERT INTO user_profile VALUES('1234567890','SFC','Smith','John','3rd MI BN','Fort Meade','Army','Active Duty','35L');
            CREATE TABLE pay_stub (id TEXT, pay_date INTEGER, gross_pay TEXT, net_pay TEXT, entitlements TEXT, deductions TEXT, allotments TEXT);
            INSERT INTO pay_stub VALUES('les1',1609459200000,'$4,500.00','$3,200.00','BAH,BAS','SGLI,TSGLI','$500');
            CREATE TABLE message (id TEXT, sender TEXT, subject TEXT, body TEXT, received_at INTEGER, is_read INTEGER);
            INSERT INTO message VALUES('m1','HQ','Mandatory Training','Complete annual training NLT 15JAN',1609459300000,0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_profile_pay_messages() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Army Profile"));
        assert!(r.iter().any(|a| a.subcategory == "MyPay LES"));
        assert!(r.iter().any(|a| a.subcategory == "Army Message"));
    }

    #[test]
    fn dodid_and_mos_captured() {
        let db = make_db();
        let r = parse(db.path());
        let p = r.iter().find(|a| a.subcategory == "Army Profile").unwrap();
        assert!(p.detail.contains("dodid='1234567890'"));
        assert!(p.detail.contains("mos='35L'"));
        assert!(p.detail.contains("unit='3rd MI BN'"));
    }

    #[test]
    fn les_amounts_captured() {
        let db = make_db();
        let r = parse(db.path());
        let les = r.iter().find(|a| a.subcategory == "MyPay LES").unwrap();
        assert!(les.detail.contains("gross_pay='$4,500.00'"));
        assert!(les.detail.contains("entitlements='BAH,BAS'"));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
