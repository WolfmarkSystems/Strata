//! DMV Apps — state DMV/DOT mobile license and vehicle data.
//!
//! Source path: various state-specific packages, e.g.
//! `/data/data/gov.ca.dmv.wallet/databases/*.db`,
//! `/data/data/gov.ny.dmv/databases/*.db`,
//! `/data/data/com.flhsmv.mobile/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Parser covers common table
//! patterns used across state DMV apps for mobile driver's license
//! (mDL) data, vehicle registrations, and citations.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "gov.ca.dmv.wallet/databases/",
    "gov.ny.dmv/databases/",
    "com.flhsmv.mobile/databases/",
    "gov.tx.dps/databases/",
    "dmv_mobile/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["driver_license", "mdl", "mobile_drivers_license"] {
        if table_exists(&conn, table) {
            out.extend(read_license(&conn, path, table));
            break;
        }
    }
    for table in &["vehicle", "vehicle_registration"] {
        if table_exists(&conn, table) {
            out.extend(read_vehicles(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "citation") {
        out.extend(read_citations(&conn, path));
    }
    out
}

fn read_license(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT license_number, first_name, last_name, dob, \
         address, state, expiration_date, class, restrictions \
         FROM \"{table}\" LIMIT 10",
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (license_number, first, last, dob, address, state, exp_ms, class, restrictions) in rows.flatten() {
        let license_number = license_number.unwrap_or_else(|| "(unknown)".to_string());
        let first = first.unwrap_or_default();
        let last = last.unwrap_or_default();
        let dob = dob.unwrap_or_default();
        let address = address.unwrap_or_default();
        let state = state.unwrap_or_default();
        let class = class.unwrap_or_default();
        let restrictions = restrictions.unwrap_or_default();
        let ts = exp_ms.and_then(unix_ms_to_i64);
        let title = format!("DMV mDL: {} {} ({})", first, last, state);
        let detail = format!(
            "DMV mobile driver's license number='{}' name='{} {}' dob='{}' address='{}' state='{}' class='{}' restrictions='{}'",
            license_number, first, last, dob, address, state, class, restrictions
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "DMV Driver License",
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

fn read_vehicles(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT plate, vin, make, model, year, registration_expires, \
         registered_owner FROM \"{table}\" LIMIT 100",
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (plate, vin, make, model, year, exp_ms, owner) in rows.flatten() {
        let plate = plate.unwrap_or_else(|| "(unknown)".to_string());
        let vin = vin.unwrap_or_default();
        let make = make.unwrap_or_default();
        let model = model.unwrap_or_default();
        let year = year.unwrap_or(0);
        let owner = owner.unwrap_or_default();
        let ts = exp_ms.and_then(unix_ms_to_i64);
        let title = format!("DMV vehicle: {} {} {} ({})", year, make, model, plate);
        let detail = format!(
            "DMV vehicle plate='{}' vin='{}' make='{}' model='{}' year={} owner='{}'",
            plate, vin, make, model, year, owner
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "DMV Vehicle",
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

fn read_citations(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT citation_number, issued_date, violation_code, \
               violation_description, fine_amount, status \
               FROM citation ORDER BY issued_date DESC LIMIT 1000";
    let mut stmt = match conn.prepare(sql) {
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (citation_number, issued_ms, code, description, fine, status) in rows.flatten() {
        let citation_number = citation_number.unwrap_or_else(|| "(unknown)".to_string());
        let code = code.unwrap_or_default();
        let description = description.unwrap_or_default();
        let fine = fine.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = issued_ms.and_then(unix_ms_to_i64);
        let title = format!("DMV citation: {} ({})", code, description);
        let detail = format!(
            "DMV citation number='{}' code='{}' description='{}' fine='{}' status='{}'",
            citation_number, code, description, fine, status
        );
        out.push(build_record(
            ArtifactCategory::ExecutionHistory,
            "DMV Citation",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            true,
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
            CREATE TABLE driver_license (
                license_number TEXT,
                first_name TEXT,
                last_name TEXT,
                dob TEXT,
                address TEXT,
                state TEXT,
                expiration_date INTEGER,
                class TEXT,
                restrictions TEXT
            );
            INSERT INTO driver_license VALUES('D1234567','Jane','Doe','1985-05-15','123 Main St','CA',2000000000000,'C','NONE');
            CREATE TABLE vehicle (
                plate TEXT,
                vin TEXT,
                make TEXT,
                model TEXT,
                year INTEGER,
                registration_expires INTEGER,
                registered_owner TEXT
            );
            INSERT INTO vehicle VALUES('ABC123','1HGBH41JXMN109186','Honda','Civic',2019,2000000000000,'Jane Doe');
            CREATE TABLE citation (
                citation_number TEXT,
                issued_date INTEGER,
                violation_code TEXT,
                violation_description TEXT,
                fine_amount TEXT,
                status TEXT
            );
            INSERT INTO citation VALUES('C001',1609459200000,'22350','Unsafe speed','$238.00','paid');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_license_vehicle_citation() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "DMV Driver License"));
        assert!(r.iter().any(|a| a.subcategory == "DMV Vehicle"));
        assert!(r.iter().any(|a| a.subcategory == "DMV Citation"));
    }

    #[test]
    fn vehicle_vin_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("vin='1HGBH41JXMN109186'")));
    }

    #[test]
    fn citation_flagged_suspicious() {
        let db = make_db();
        let r = parse(db.path());
        let citation = r.iter().find(|a| a.subcategory == "DMV Citation").unwrap();
        assert!(citation.is_suspicious);
        assert!(citation.detail.contains("fine='$238.00'"));
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
