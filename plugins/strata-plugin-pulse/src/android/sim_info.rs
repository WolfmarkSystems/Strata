//! SIM Info — Android SIM card identity extraction.
//!
//! ALEAPP reference: `scripts/artifacts/siminfo.py`. Source path:
//! `/data/user_de/*/com.android.providers.telephony/databases/telephony.db`.
//!
//! Key table: `siminfo` — IMSI, ICCID, carrier, phone number.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["providers.telephony/databases/telephony.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "siminfo") {
        return Vec::new();
    }
    read_siminfo(&conn, path)
}

fn read_siminfo(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT number, display_name, carrier_name, \
               iso_country_code, icc_id \
               FROM siminfo LIMIT 100";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (number, display, carrier, country, iccid) in rows.flatten() {
        let number = number.unwrap_or_else(|| "(unknown)".to_string());
        let display = display.unwrap_or_else(|| "(unknown)".to_string());
        let carrier = carrier.unwrap_or_else(|| "(unknown)".to_string());
        let country = country.unwrap_or_default();
        let iccid = iccid.unwrap_or_default();
        let title = format!("SIM: {} — {} ({})", display, carrier, number);
        let mut detail = format!(
            "SIM info number='{}' display='{}' carrier='{}'",
            number, display, carrier
        );
        if !country.is_empty() {
            detail.push_str(&format!(" country='{}'", country));
        }
        if !iccid.is_empty() {
            detail.push_str(&format!(" iccid='{}'", iccid));
        }
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "SIM Info",
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE siminfo (
                _id INTEGER PRIMARY KEY,
                number TEXT,
                display_name TEXT,
                carrier_name TEXT,
                iso_country_code TEXT,
                icc_id TEXT
            );
            INSERT INTO siminfo VALUES(1,'+15551234567','Personal SIM','Verizon','us','89014103271234567890');
            INSERT INTO siminfo VALUES(2,'+447700900123','UK SIM','Vodafone','gb','89440000001234567890');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_sims() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "SIM Info"));
    }

    #[test]
    fn carrier_and_number_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("carrier='Verizon'")));
        assert!(r.iter().any(|a| a.detail.contains("number='+15551234567'")));
    }

    #[test]
    fn iccid_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let sim = r.iter().find(|a| a.detail.contains("Verizon")).unwrap();
        assert!(sim.detail.contains("iccid='89014103271234567890'"));
    }

    #[test]
    fn forensic_value_is_critical() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .all(|a| matches!(a.forensic_value, ForensicValue::Critical)));
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
