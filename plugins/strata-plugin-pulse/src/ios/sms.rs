//! iOS `sms.db` — SMS + iMessage messages.
//!
//! The schema iLEAPP keys off is:
//!   * `message` — text body, sender/receiver, date (Cocoa seconds or
//!     nanoseconds depending on iOS version)
//!   * `handle`  — mapping from ROWID to `id` (phone number or Apple
//!     ID)
//!   * `chat`    — chat room metadata
//!   * `attachment` / `message_attachment_join` — attachments
//!
//! iOS 13 switched `message.date` from whole-second Cocoa doubles to
//! nanosecond integers. Both variants show up in the wild, so the
//! parser probes the first non-null `date` value and picks the right
//! converter.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["sms.db", "chat.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "message") {
        return out;
    }

    let source = path.to_string_lossy().to_string();

    // Total row count — always available.
    let total = util::count_rows(&conn, "message");

    // Count messages by service (iMessage, SMS, RCS on iOS 18+).
    let services = conn
        .prepare(
            "SELECT COALESCE(service, '(unknown)'), COUNT(*) FROM message \
             GROUP BY service ORDER BY COUNT(*) DESC",
        )
        .and_then(|mut s| {
            let rows = s.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?;
            Ok(rows.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    // Earliest/latest date — probe for the nanosecond vs seconds format.
    let (first_ts, last_ts) = probe_date_range(&conn);

    let range_str = match (first_ts, last_ts) {
        (Some(a), Some(b)) => format!("range {}..{} Unix", a, b),
        _ => "no usable timestamps".to_string(),
    };

    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "SMS/iMessage".to_string(),
        timestamp: first_ts,
        title: "SMS / iMessage database".to_string(),
        detail: format!("{} total messages, {}", total, range_str),
        source_path: source.clone(),
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
    });

    for (service, count) in services {
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: format!("SMS/iMessage service: {}", service),
            timestamp: None,
            title: format!("{} messages", service),
            detail: format!("{} rows routed through service {}", count, service),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
        });
    }

    // Handle (participant) count — useful for showing the panel even
    // when the message table is empty after a wipe.
    if util::table_exists(&conn, "handle") {
        let handle_count = util::count_rows(&conn, "handle");
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "SMS/iMessage handles".to_string(),
            timestamp: None,
            title: "Message participants".to_string(),
            detail: format!("{} unique handles (phone numbers / Apple IDs)", handle_count),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
        });
    }

    // Attachment count.
    if util::table_exists(&conn, "attachment") {
        let att = util::count_rows(&conn, "attachment");
        if att > 0 {
            out.push(ArtifactRecord {
                category: ArtifactCategory::Media,
                subcategory: "SMS/iMessage attachments".to_string(),
                timestamp: None,
                title: "Message attachments".to_string(),
                detail: format!("{} attachment rows (images, videos, audio)", att),
                source_path: source.clone(),
                forensic_value: ForensicValue::High,
                mitre_technique: None,
                is_suspicious: false,
                raw_data: None,
            });
        }
    }

    out
}

/// Probe a representative `date` value and decide whether iOS is
/// writing whole-second Cocoa doubles or nanosecond integers. Returns
/// `(first, last)` unix seconds.
fn probe_date_range(conn: &rusqlite::Connection) -> (Option<i64>, Option<i64>) {
    let Ok(mut stmt) = conn.prepare(
        "SELECT MIN(date), MAX(date) FROM message WHERE date IS NOT NULL AND date != 0",
    ) else {
        return (None, None);
    };
    let (min, max): (Option<i64>, Option<i64>) = stmt
        .query_row([], |row| {
            Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?))
        })
        .unwrap_or((None, None));
    let min = min.and_then(convert_message_date);
    let max = max.and_then(convert_message_date);
    (min, max)
}

/// iOS <13 stores `message.date` as Cocoa seconds (roughly 10 digits).
/// iOS >=13 stores it as Cocoa nanoseconds (roughly 18+ digits). Use a
/// magnitude check since the two ranges are 9 orders apart.
fn convert_message_date(raw: i64) -> Option<i64> {
    if raw <= 0 {
        return None;
    }
    if raw > 1_000_000_000_000 {
        util::cf_nanos_to_unix(raw)
    } else {
        util::cf_absolute_to_unix(raw as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_sms_db(date_is_nanos: bool, rows: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE message (\
                ROWID INTEGER PRIMARY KEY, \
                text TEXT, \
                service TEXT, \
                date INTEGER \
             )",
            [],
        )
        .unwrap();
        c.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)", [])
            .unwrap();
        c.execute(
            "CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY, filename TEXT)",
            [],
        )
        .unwrap();

        // Insert messages with alternating services so the grouping
        // branch exercises multiple rows.
        for i in 0..rows {
            let service = if i % 2 == 0 { "iMessage" } else { "SMS" };
            let date: i64 = if date_is_nanos {
                700_000_000_i64 * 1_000_000_000 + i as i64
            } else {
                700_000_000_i64 + i as i64
            };
            c.execute(
                "INSERT INTO message (text, service, date) VALUES (?1, ?2, ?3)",
                rusqlite::params![format!("msg {}", i), service, date],
            )
            .unwrap();
        }
        c.execute("INSERT INTO handle (id) VALUES ('+15551234567')", [])
            .unwrap();
        c.execute("INSERT INTO attachment (filename) VALUES ('/var/mobile/a.jpg')", [])
            .unwrap();
        tmp
    }

    #[test]
    fn matches_sms_and_chat_db() {
        assert!(matches(Path::new("/private/var/mobile/Library/SMS/sms.db")));
        assert!(matches(Path::new("/Users/me/Library/Messages/chat.db")));
        assert!(!matches(Path::new("/Users/me/Library/Safari/History.db")));
    }

    #[test]
    fn parses_summary_attachments_and_handles() {
        let tmp = make_sms_db(false, 4);
        let records = parse(tmp.path());

        let summary = records
            .iter()
            .find(|r| r.subcategory == "SMS/iMessage")
            .expect("summary record");
        assert!(summary.detail.contains("4 total messages"));
        assert_eq!(summary.forensic_value, ForensicValue::Critical);

        let handles = records
            .iter()
            .find(|r| r.subcategory == "SMS/iMessage handles")
            .expect("handle record");
        assert!(handles.detail.contains("1 unique handles"));

        let att = records
            .iter()
            .find(|r| r.subcategory == "SMS/iMessage attachments")
            .expect("attachment record");
        assert!(att.detail.contains("1 attachment"));

        // Per-service breakdown.
        assert!(records
            .iter()
            .any(|r| r.subcategory == "SMS/iMessage service: iMessage"));
        assert!(records
            .iter()
            .any(|r| r.subcategory == "SMS/iMessage service: SMS"));
    }

    #[test]
    fn handles_both_date_encodings() {
        let seconds_tmp = make_sms_db(false, 1);
        let nanos_tmp = make_sms_db(true, 1);

        let seconds = parse(seconds_tmp.path());
        let nanos = parse(nanos_tmp.path());

        let expect_unix = 700_000_000_i64 + util::APPLE_EPOCH_OFFSET;

        let seconds_summary = seconds
            .iter()
            .find(|r| r.subcategory == "SMS/iMessage")
            .unwrap();
        let nanos_summary = nanos.iter().find(|r| r.subcategory == "SMS/iMessage").unwrap();
        assert_eq!(seconds_summary.timestamp, Some(expect_unix));
        assert_eq!(nanos_summary.timestamp, Some(expect_unix));
    }

    #[test]
    fn empty_message_table_still_emits_summary() {
        let tmp = make_sms_db(false, 0);
        let records = parse(tmp.path());
        let summary = records
            .iter()
            .find(|r| r.subcategory == "SMS/iMessage")
            .expect("summary record even when empty");
        assert!(summary.detail.contains("0 total messages"));
    }

    #[test]
    fn convert_message_date_rejects_zero_and_negative() {
        assert!(convert_message_date(0).is_none());
        assert!(convert_message_date(-1).is_none());
    }
}
