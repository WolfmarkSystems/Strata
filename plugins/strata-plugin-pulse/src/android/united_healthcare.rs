//! UnitedHealthcare — health insurance app claim/member extraction.
//!
//! Source path: `/data/data/com.uhc.mobile/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Health insurance apps typically
//! store claim history, member info, and provider searches in Room
//! databases. Column names and tables vary by version.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.uhc.mobile/databases/", "com.optum.mobile/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["claim", "claims", "claim_history"] {
        if table_exists(&conn, table) {
            out.extend(read_claims(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "member") {
        out.extend(read_member(&conn, path));
    }
    out
}

fn read_claims(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT claim_id, service_date, provider_name, diagnosis_code, \
         amount_billed, amount_paid, status \
         FROM \"{table}\" ORDER BY service_date DESC LIMIT 5000",
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
    for (claim_id, service_ms, provider, diagnosis, billed, paid, status) in rows.flatten() {
        let claim_id = claim_id.unwrap_or_else(|| "(unknown)".to_string());
        let provider = provider.unwrap_or_else(|| "(unknown)".to_string());
        let diagnosis = diagnosis.unwrap_or_default();
        let billed = billed.unwrap_or_default();
        let paid = paid.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = service_ms.and_then(unix_ms_to_i64);
        let title = format!("UHC claim: {} ({})", provider, status);
        let detail = format!(
            "UnitedHealthcare claim id='{}' provider='{}' diagnosis='{}' billed='{}' paid='{}' status='{}'",
            claim_id, provider, diagnosis, billed, paid, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "UHC Claim",
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

fn read_member(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT member_id, first_name, last_name, dob, \
               plan_name, group_number \
               FROM member LIMIT 10";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (member_id, first, last, dob, plan, group) in rows.flatten() {
        let member_id = member_id.unwrap_or_default();
        let first = first.unwrap_or_default();
        let last = last.unwrap_or_default();
        let dob = dob.unwrap_or_default();
        let plan = plan.unwrap_or_default();
        let group = group.unwrap_or_default();
        let title = format!("UHC member: {} {}", first, last);
        let detail = format!(
            "UnitedHealthcare member id='{}' first_name='{}' last_name='{}' dob='{}' plan='{}' group='{}'",
            member_id, first, last, dob, plan, group
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "UHC Member",
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
            CREATE TABLE claim (
                claim_id TEXT,
                service_date INTEGER,
                provider_name TEXT,
                diagnosis_code TEXT,
                amount_billed TEXT,
                amount_paid TEXT,
                status TEXT
            );
            INSERT INTO claim VALUES('c1',1609459200000,'Dr. Smith MD','J11.1','$350.00','$280.00','paid');
            CREATE TABLE member (
                member_id TEXT,
                first_name TEXT,
                last_name TEXT,
                dob TEXT,
                plan_name TEXT,
                group_number TEXT
            );
            INSERT INTO member VALUES('m1','Jane','Doe','1985-05-15','PPO Gold','G12345');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_claims_and_member() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "UHC Claim"));
        assert!(r.iter().any(|a| a.subcategory == "UHC Member"));
    }

    #[test]
    fn diagnosis_code_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("diagnosis='J11.1'")));
    }

    #[test]
    fn member_dob_and_plan() {
        let db = make_db();
        let r = parse(db.path());
        let m = r.iter().find(|a| a.subcategory == "UHC Member").unwrap();
        assert!(m.detail.contains("dob='1985-05-15'"));
        assert!(m.detail.contains("plan='PPO Gold'"));
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
