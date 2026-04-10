//! Chrome Autofill — Android Chrome saved form data.
//!
//! ALEAPP reference: `scripts/artifacts/chromeAutofill.py`. Source path:
//! `/data/data/com.android.chrome/app_chrome/Default/Web Data`.
//!
//! Key tables: `autofill`, `autofill_profiles`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "app_chrome/default/web data",
    "app_sbrowser/default/web data",
    "app_opera/web data",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "autofill") {
        out.extend(read_autofill(&conn, path));
    }
    if table_exists(&conn, "autofill_profiles") {
        out.extend(read_profiles(&conn, path));
    }
    out
}

fn read_autofill(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT name, value, date_created, date_last_used, count \
               FROM autofill ORDER BY date_last_used DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, value, created, last_used, count) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let value = value.unwrap_or_default();
        // date_created and date_last_used are Unix epoch seconds
        let ts = last_used.or(created);
        let count = count.unwrap_or(0);
        let preview: String = value.chars().take(80).collect();
        let title = format!("Chrome autofill {}: {}", name, preview);
        let detail = format!(
            "Chrome autofill field='{}' value='{}' use_count={}",
            name, value, count
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Chrome Autofill",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_profiles(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT first_name, last_name, email, number, \
               company_name, street_address, city, state, zipcode, \
               date_modified \
               FROM autofill_profiles ORDER BY date_modified DESC LIMIT 1000";
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
            row.get::<_, Option<i64>>(9).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (first, last, email, phone, company, street, city, state, zip, modified) in rows.flatten() {
        let name = format!(
            "{} {}",
            first.unwrap_or_default(),
            last.unwrap_or_default()
        ).trim().to_string();
        let name_display = if name.is_empty() { "(unnamed)".to_string() } else { name.clone() };
        let title = format!("Chrome autofill profile: {}", name_display);
        let mut detail = format!("Chrome autofill profile name='{}'", name_display);
        if let Some(e) = email.filter(|e| !e.is_empty()) {
            detail.push_str(&format!(" email='{}'", e));
        }
        if let Some(p) = phone.filter(|p| !p.is_empty()) {
            detail.push_str(&format!(" phone='{}'", p));
        }
        if let Some(c) = company.filter(|c| !c.is_empty()) {
            detail.push_str(&format!(" company='{}'", c));
        }
        let mut addr_parts = Vec::new();
        if let Some(s) = street.filter(|s| !s.is_empty()) { addr_parts.push(s); }
        if let Some(c) = city.filter(|c| !c.is_empty()) { addr_parts.push(c); }
        if let Some(s) = state.filter(|s| !s.is_empty()) { addr_parts.push(s); }
        if let Some(z) = zip.filter(|z| !z.is_empty()) { addr_parts.push(z); }
        if !addr_parts.is_empty() {
            detail.push_str(&format!(" address='{}'", addr_parts.join(", ")));
        }
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Chrome Autofill Profile",
            title,
            detail,
            path,
            modified,
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
            CREATE TABLE autofill (
                name TEXT,
                value TEXT,
                date_created INTEGER,
                date_last_used INTEGER,
                count INTEGER
            );
            INSERT INTO autofill VALUES('email','user@example.com',1609459200,1609459300,5);
            INSERT INTO autofill VALUES('username','jsmith',1609459200,1609459400,3);
            CREATE TABLE autofill_profiles (
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                number TEXT,
                company_name TEXT,
                street_address TEXT,
                city TEXT,
                state TEXT,
                zipcode TEXT,
                date_modified INTEGER
            );
            INSERT INTO autofill_profiles VALUES('John','Smith','john@example.com','+15551234567','Acme Corp','123 Main St','Springfield','IL','62704',1609459500);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_autofill_and_profiles() {
        let db = make_db();
        let r = parse(db.path());
        let fills: Vec<_> = r.iter().filter(|a| a.subcategory == "Chrome Autofill").collect();
        let profs: Vec<_> = r.iter().filter(|a| a.subcategory == "Chrome Autofill Profile").collect();
        assert_eq!(fills.len(), 2);
        assert_eq!(profs.len(), 1);
    }

    #[test]
    fn profile_includes_address() {
        let db = make_db();
        let r = parse(db.path());
        let prof = r.iter().find(|a| a.subcategory == "Chrome Autofill Profile").unwrap();
        assert!(prof.detail.contains("address='123 Main St, Springfield, IL, 62704'"));
    }

    #[test]
    fn autofill_count_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let email = r.iter().find(|a| a.detail.contains("user@example.com")).unwrap();
        assert!(email.detail.contains("use_count=5"));
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
