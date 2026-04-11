//! MyChart — Epic patient portal medical record extraction.
//!
//! Source path: `/data/data/epic.mychart.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. MyChart stores appointments,
//! medications, test results, and messages in Room databases. Column
//! names vary by Epic deployment.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["epic.mychart.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "appointment") {
        out.extend(read_appointments(&conn, path));
    }
    if table_exists(&conn, "medication") {
        out.extend(read_medications(&conn, path));
    }
    if table_exists(&conn, "message") {
        out.extend(read_messages(&conn, path));
    }
    out
}

fn read_appointments(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, scheduled_date, provider_name, department, \
               reason, status \
               FROM appointment ORDER BY scheduled_date DESC LIMIT 5000";
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
    for (id, scheduled_ms, provider, department, reason, status) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let provider = provider.unwrap_or_default();
        let department = department.unwrap_or_default();
        let reason = reason.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = scheduled_ms.and_then(unix_ms_to_i64);
        let title = format!("MyChart appt: {} ({})", provider, status);
        let detail = format!(
            "MyChart appointment id='{}' provider='{}' department='{}' reason='{}' status='{}'",
            id, provider, department, reason, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "MyChart Appointment",
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

fn read_medications(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT name, dosage, frequency, prescribed_by, \
               start_date, status \
               FROM medication LIMIT 5000";
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
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, dosage, frequency, prescribed_by, start_ms, status) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let dosage = dosage.unwrap_or_default();
        let frequency = frequency.unwrap_or_default();
        let prescribed_by = prescribed_by.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = start_ms.and_then(unix_ms_to_i64);
        let title = format!("MyChart med: {} {}", name, dosage);
        let detail = format!(
            "MyChart medication name='{}' dosage='{}' frequency='{}' prescribed_by='{}' status='{}'",
            name, dosage, frequency, prescribed_by, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "MyChart Medication",
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
    let sql = "SELECT id, sender_name, subject, body, sent_at, is_read \
               FROM message ORDER BY sent_at DESC LIMIT 5000";
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
    for (id, sender, subject, body, sent_ms, is_read) in rows.flatten() {
        let id = id.unwrap_or_default();
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let subject = subject.unwrap_or_default();
        let body = body.unwrap_or_default();
        let is_read = is_read.unwrap_or(0) != 0;
        let ts = sent_ms.and_then(unix_ms_to_i64);
        let title = format!("MyChart msg: {} — {}", sender, subject);
        let detail = format!(
            "MyChart message id='{}' sender='{}' subject='{}' body='{}' read={}",
            id, sender, subject, body, is_read
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "MyChart Message",
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
            CREATE TABLE appointment (
                id TEXT,
                scheduled_date INTEGER,
                provider_name TEXT,
                department TEXT,
                reason TEXT,
                status TEXT
            );
            INSERT INTO appointment VALUES('a1',1609459200000,'Dr. Wilson','Cardiology','Annual checkup','confirmed');
            CREATE TABLE medication (
                name TEXT,
                dosage TEXT,
                frequency TEXT,
                prescribed_by TEXT,
                start_date INTEGER,
                status TEXT
            );
            INSERT INTO medication VALUES('Lisinopril','10mg','once daily','Dr. Wilson',1609459200000,'active');
            CREATE TABLE message (
                id TEXT,
                sender_name TEXT,
                subject TEXT,
                body TEXT,
                sent_at INTEGER,
                is_read INTEGER
            );
            INSERT INTO message VALUES('m1','Dr. Wilson','Test results ready','Your labs are back',1609459300000,1);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_appt_med_msg() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "MyChart Appointment"));
        assert!(r.iter().any(|a| a.subcategory == "MyChart Medication"));
        assert!(r.iter().any(|a| a.subcategory == "MyChart Message"));
    }

    #[test]
    fn medication_dosage_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Lisinopril 10mg")));
    }

    #[test]
    fn appointment_provider_captured() {
        let db = make_db();
        let r = parse(db.path());
        let appt = r.iter().find(|a| a.subcategory == "MyChart Appointment").unwrap();
        assert!(appt.detail.contains("provider='Dr. Wilson'"));
        assert!(appt.detail.contains("department='Cardiology'"));
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
