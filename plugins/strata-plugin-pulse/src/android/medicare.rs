//! Medicare — Medicare.gov mobile app claim and Part D drug data.
//!
//! Source path: `/data/data/gov.medicare.mymedicare/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Medicare.gov app stores claim
//! history, Part D drug list, and enrollment info.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["gov.medicare.mymedicare/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "claim") {
        out.extend(read_claims(&conn, path));
    }
    if table_exists(&conn, "prescription") {
        out.extend(read_prescriptions(&conn, path));
    }
    out
}

fn read_claims(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT claim_id, service_date, provider, claim_type, \
               amount_charged, amount_paid, claim_status \
               FROM claim ORDER BY service_date DESC LIMIT 5000";
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
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (claim_id, service_ms, provider, claim_type, charged, paid, status) in rows.flatten() {
        let claim_id = claim_id.unwrap_or_else(|| "(unknown)".to_string());
        let provider = provider.unwrap_or_default();
        let claim_type = claim_type.unwrap_or_default();
        let charged = charged.unwrap_or_default();
        let paid = paid.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = service_ms.and_then(unix_ms_to_i64);
        let title = format!("Medicare claim: {} ({})", provider, claim_type);
        let detail = format!(
            "Medicare claim id='{}' provider='{}' type='{}' charged='{}' paid='{}' status='{}'",
            claim_id, provider, claim_type, charged, paid, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Medicare Claim",
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

fn read_prescriptions(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT drug_name, ndc, fill_date, pharmacy, \
               cost, quantity FROM prescription \
               ORDER BY fill_date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (drug_name, ndc, fill_ms, pharmacy, cost, quantity) in rows.flatten() {
        let drug_name = drug_name.unwrap_or_else(|| "(unknown)".to_string());
        let ndc = ndc.unwrap_or_default();
        let pharmacy = pharmacy.unwrap_or_default();
        let cost = cost.unwrap_or_default();
        let quantity = quantity.unwrap_or_default();
        let ts = fill_ms.and_then(unix_ms_to_i64);
        let title = format!("Medicare Rx: {}", drug_name);
        let detail = format!(
            "Medicare prescription drug_name='{}' ndc='{}' pharmacy='{}' cost='{}' quantity='{}'",
            drug_name, ndc, pharmacy, cost, quantity
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Medicare Prescription",
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
            CREATE TABLE claim (
                claim_id TEXT,
                service_date INTEGER,
                provider TEXT,
                claim_type TEXT,
                amount_charged TEXT,
                amount_paid TEXT,
                claim_status TEXT
            );
            INSERT INTO claim VALUES('c1',1609459200000,'City Hospital','Part A','$5000','$4500','paid');
            CREATE TABLE prescription (
                drug_name TEXT,
                ndc TEXT,
                fill_date INTEGER,
                pharmacy TEXT,
                cost TEXT,
                quantity TEXT
            );
            INSERT INTO prescription VALUES('Metformin','00093-1074-01',1609459300000,'CVS #1234','$15.00','60');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_claims_and_prescriptions() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Medicare Claim"));
        assert!(r.iter().any(|a| a.subcategory == "Medicare Prescription"));
    }

    #[test]
    fn claim_type_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Part A")));
    }

    #[test]
    fn ndc_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("ndc='00093-1074-01'")));
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
