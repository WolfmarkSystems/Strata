//! KnowledgeC parser — macOS 10.x through macOS 12 user-activity store.
//!
//! `knowledgeC.db` is Apple's SQLite-backed activity timeline maintained by
//! the CoreDuet framework at `/private/var/db/CoreDuet/Knowledge/knowledgeC.db`
//! (system-wide) and `~/Library/Application Support/Knowledge/knowledgeC.db`
//! (per-user). It records foreground app focus, app sessions, lock state,
//! display backlight state, Safari history, and app-level web usage.
//!
//! ## Deprecation
//! On macOS 13 (Ventura) and later, Apple Biome supersedes this database as
//! the primary user-activity store. Parse Biome (see `crate::biome`) on
//! modern systems; KnowledgeC is still worth harvesting on 10.13–12.x images
//! and on any Mac that has not yet migrated.
//!
//! ## Schema
//! Records live in the `ZOBJECT` table. Key columns we consume:
//!
//! | Column              | Type    | Meaning                                             |
//! |---------------------|---------|-----------------------------------------------------|
//! | `ZSTREAMNAME`       | TEXT    | Stream identifier (e.g. `/app/inFocus`)             |
//! | `ZSTARTDATE`        | REAL    | Event start, CoreData epoch seconds                 |
//! | `ZENDDATE`          | REAL    | Event end, CoreData epoch seconds                   |
//! | `ZVALUEINTEGER`     | INTEGER | Varies by stream (lock bool, backlight bool, …)     |
//! | `ZVALUESTRING`      | TEXT    | Varies by stream (bundle id, URL, …)                |
//! | `ZVALUEDOUBLE`      | REAL    | Varies by stream (rarely used by our schemas)       |
//! | `ZSECONDSSTARTDATE` | REAL    | Alternate start timestamp (synthetic streams)       |
//! | `ZDEVICEID`         | TEXT    | CoreDuet device UUID (continuity attribution)       |
//!
//! ## CoreData epoch
//! CoreData / Mach absolute-time encodes timestamps as seconds since
//! 2001-01-01 00:00:00 UTC. Add `978_307_200` to convert to the Unix epoch.
//!
//! ## Streams decoded
//! * `/app/inFocus` — bundle_id from `ZVALUESTRING`.
//! * `/app/webUsage` — url from `ZVALUESTRING`.
//! * `/device/isLocked` — locked bool from `ZVALUEINTEGER`.
//! * `/safari/history` — url from `ZVALUESTRING`.
//! * `/user/appSession` — bundle_id + duration from `ZENDDATE - ZSTARTDATE`.
//! * `/display/isBacklit` — backlit bool from `ZVALUEINTEGER`.
//!
//! ## MITRE ATT&CK
//! * **T1217** (Browser Information Discovery) — `safari/history` and
//!   `app/webUsage`.
//! * **T1059** (Command and Scripting Interpreter) — `app/inFocus` and
//!   `user/appSession` (canonical post-execution signal on macOS).
//! * **T1083** (File and Directory Discovery) — device lock / backlight and
//!   any other stream routed through this parser.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Offset from the Unix epoch to the CoreData / Mach absolute-time epoch
/// (2001-01-01 00:00:00 UTC expressed as Unix seconds).
const APPLE_EPOCH_OFFSET: i64 = 978_307_200;

/// Plausibility window used when filtering decoded timestamps. Anything
/// before 2000-01-01 or after 2100-01-01 is discarded as a corrupt value
/// (CoreData epoch seconds for those bounds).
const MIN_APPLE_EPOCH: f64 = -31_622_400.0;
const MAX_APPLE_EPOCH: f64 = 3_124_137_600.0;

/// Hard cap on rows materialised per database to keep runaway parses
/// bounded. KnowledgeC on a busy machine can exceed 10M rows; callers that
/// need everything should stream directly against SQLite.
const MAX_RECORDS: usize = 500_000;

/// A single typed record extracted from `ZOBJECT`.
///
/// Forensic interpretation depends on `stream_name`; the per-stream
/// meaning of each optional field is documented on the field.
///
/// **Deprecated on macOS 13+**: Apple Biome (see [`crate::biome`])
/// supersedes this database. Both parsers are retained because forensic
/// images frequently contain legacy volumes or multi-user machines that
/// have not migrated.
#[derive(Debug, Clone, PartialEq)]
pub struct KnowledgeCRecord {
    /// KnowledgeC stream identifier verbatim from `ZOBJECT.ZSTREAMNAME`
    /// (for example `"/app/inFocus"`, `"/safari/history"`). Drives how
    /// consumers should interpret the remaining fields.
    pub stream_name: String,

    /// Event start converted from CoreData-epoch seconds
    /// (`ZOBJECT.ZSTARTDATE`) to UTC. For instantaneous streams such as
    /// `/device/isLocked` this is the moment the state changed; for
    /// duration streams such as `/user/appSession` this is when the
    /// session began.
    pub start_time: DateTime<Utc>,

    /// Event end converted from CoreData-epoch seconds
    /// (`ZOBJECT.ZENDDATE`) to UTC. `None` when absent or when the record
    /// represents a point-in-time event rather than an interval.
    pub end_time: Option<DateTime<Utc>>,

    /// macOS / iOS bundle identifier (for example `"com.apple.Safari"`)
    /// sourced from `ZVALUESTRING`. Populated for `/app/inFocus` and
    /// `/user/appSession`; `None` otherwise.
    pub bundle_id: Option<String>,

    /// URL sourced from `ZVALUESTRING`. Populated for `/safari/history`
    /// and `/app/webUsage`; `None` otherwise. Includes entries that may
    /// never have been written to Safari's `History.db` (for example when
    /// an app renders a web view that logs to webUsage only).
    pub url: Option<String>,

    /// Raw `ZVALUEINTEGER` payload. Interpretation is stream-specific:
    /// for `/device/isLocked` and `/display/isBacklit` a non-zero value
    /// is the "on" state. Preserved as a signed integer so consumers can
    /// disambiguate streams we do not decode explicitly.
    pub value_integer: Option<i64>,

    /// CoreDuet device UUID from `ZDEVICEID`. When Continuity sync is
    /// active this can identify activity that originated on a paired
    /// device (iPhone / iPad) rather than the host Mac.
    pub device_id: Option<String>,
}

/// Parse `knowledgeC.db` at `path` and return every typed record found.
///
/// Opens the database read-only. Returns an empty vector (not an error)
/// when the file is missing, corrupt, or lacks the expected `ZOBJECT`
/// table. Never panics.
pub fn parse(path: &Path) -> Vec<KnowledgeCRecord> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = Connection::open_with_flags(path, flags) else {
        return Vec::new();
    };
    query_records(&conn).unwrap_or_default()
}

fn query_records(conn: &Connection) -> rusqlite::Result<Vec<KnowledgeCRecord>> {
    let sql = "SELECT ZSTREAMNAME, ZSTARTDATE, ZENDDATE, \
                      ZVALUEINTEGER, ZVALUESTRING, ZDEVICEID \
               FROM ZOBJECT \
               WHERE ZSTREAMNAME IN ( \
                   '/app/inFocus', '/app/webUsage', '/device/isLocked', \
                   '/safari/history', '/user/appSession', '/display/isBacklit' \
               ) \
               ORDER BY ZSTARTDATE ASC";
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| {
        let stream_name: String = row.get(0)?;
        let start_raw: Option<f64> = row.get(1)?;
        let end_raw: Option<f64> = row.get(2)?;
        let value_integer: Option<i64> = row.get(3)?;
        let value_string: Option<String> = row.get(4)?;
        let device_id: Option<String> = row.get(5)?;
        Ok((stream_name, start_raw, end_raw, value_integer, value_string, device_id))
    })?;

    let mut out = Vec::new();
    for row in rows {
        if out.len() >= MAX_RECORDS {
            break;
        }
        let Ok((stream_name, start_raw, end_raw, value_integer, value_string, device_id)) = row
        else {
            continue;
        };
        let Some(start_time) = start_raw.and_then(decode_apple_timestamp) else {
            continue;
        };
        let end_time = end_raw.and_then(decode_apple_timestamp);
        let (bundle_id, url) = split_value_string(&stream_name, value_string);
        out.push(KnowledgeCRecord {
            stream_name,
            start_time,
            end_time,
            bundle_id,
            url,
            value_integer,
            device_id,
        });
    }
    Ok(out)
}

fn split_value_string(
    stream_name: &str,
    value_string: Option<String>,
) -> (Option<String>, Option<String>) {
    match (stream_name, value_string) {
        ("/app/inFocus", Some(s)) | ("/user/appSession", Some(s)) => (Some(s), None),
        ("/app/webUsage", Some(s)) | ("/safari/history", Some(s)) => (None, Some(s)),
        _ => (None, None),
    }
}

/// Convert a CoreData-epoch `f64` (seconds since 2001-01-01 UTC) to UTC.
/// Returns `None` for non-finite or out-of-window values.
pub(crate) fn decode_apple_timestamp(apple_secs: f64) -> Option<DateTime<Utc>> {
    if !apple_secs.is_finite() {
        return None;
    }
    if !(MIN_APPLE_EPOCH..MAX_APPLE_EPOCH).contains(&apple_secs) {
        return None;
    }
    let secs = apple_secs.trunc() as i64;
    let frac = apple_secs - apple_secs.trunc();
    let nanos = (frac * 1_000_000_000.0) as u32;
    DateTime::<Utc>::from_timestamp(secs.saturating_add(APPLE_EPOCH_OFFSET), nanos)
}

/// Session duration in whole seconds for a record, computed as
/// `end_time - start_time`. Returns `None` when `end_time` is absent.
pub fn session_duration_secs(record: &KnowledgeCRecord) -> Option<i64> {
    record
        .end_time
        .map(|end| end.timestamp() - record.start_time.timestamp())
}

/// Heuristic suggesting a MITRE ATT&CK technique for a stream name.
pub fn mitre_for_stream(stream_name: &str) -> &'static str {
    match stream_name {
        "/safari/history" | "/app/webUsage" => "T1217",
        "/app/inFocus" | "/user/appSession" => "T1059",
        _ => "T1083",
    }
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    type FixtureRow<'a> = (
        &'a str,
        f64,
        Option<f64>,
        Option<i64>,
        Option<&'a str>,
        Option<&'a str>,
    );

    fn build_fixture(rows: &[FixtureRow<'_>]) -> NamedTempFile {
        let file = NamedTempFile::new().expect("tempfile");
        let conn = Connection::open(file.path()).expect("open fixture db");
        conn.execute_batch(
            "CREATE TABLE ZOBJECT ( \
                 ZSTREAMNAME TEXT, \
                 ZSTARTDATE REAL, \
                 ZENDDATE REAL, \
                 ZVALUEINTEGER INTEGER, \
                 ZVALUESTRING TEXT, \
                 ZVALUEDOUBLE REAL, \
                 ZSECONDSSTARTDATE REAL, \
                 ZDEVICEID TEXT \
             );",
        )
        .expect("create table");
        for (stream, start, end, vi, vs, did) in rows {
            conn.execute(
                "INSERT INTO ZOBJECT ( \
                     ZSTREAMNAME, ZSTARTDATE, ZENDDATE, \
                     ZVALUEINTEGER, ZVALUESTRING, ZDEVICEID \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![stream, start, end, vi, vs, did],
            )
            .expect("insert row");
        }
        drop(conn);
        file
    }

    #[test]
    fn parse_returns_empty_when_file_missing() {
        let records = parse(Path::new("/definitely/not/a/real/knowledgeC.db"));
        assert!(records.is_empty());
    }

    #[test]
    fn parse_returns_empty_when_table_absent() {
        let file = NamedTempFile::new().expect("tempfile");
        let conn = Connection::open(file.path()).expect("open empty db");
        conn.execute_batch("CREATE TABLE UNRELATED (x INTEGER);")
            .expect("create unrelated");
        drop(conn);
        assert!(parse(file.path()).is_empty());
    }

    #[test]
    fn parse_decodes_in_focus_record() {
        // 2024-06-01 12:00:00 UTC == Unix 1_717_243_200
        // CoreData epoch == 1_717_243_200 - 978_307_200 = 738_936_000
        let start = 738_936_000.0;
        let end = 738_936_060.0;
        let file = build_fixture(&[(
            "/app/inFocus",
            start,
            Some(end),
            None,
            Some("com.apple.Safari"),
            Some("DEVICE-UUID-1"),
        )]);
        let records = parse(file.path());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.stream_name, "/app/inFocus");
        assert_eq!(r.bundle_id.as_deref(), Some("com.apple.Safari"));
        assert!(r.url.is_none());
        assert_eq!(r.start_time.timestamp(), 1_717_243_200);
        assert_eq!(r.end_time.map(|t| t.timestamp()), Some(1_717_243_260));
        assert_eq!(r.device_id.as_deref(), Some("DEVICE-UUID-1"));
        assert_eq!(session_duration_secs(r), Some(60));
    }

    #[test]
    fn parse_decodes_safari_history_and_lock_streams() {
        let file = build_fixture(&[
            (
                "/safari/history",
                738_936_100.0,
                None,
                None,
                Some("https://example.com/"),
                None,
            ),
            (
                "/device/isLocked",
                738_936_200.0,
                Some(738_936_260.0),
                Some(1),
                None,
                None,
            ),
            (
                "/display/isBacklit",
                738_936_300.0,
                Some(738_936_360.0),
                Some(0),
                None,
                None,
            ),
        ]);
        let records = parse(file.path());
        assert_eq!(records.len(), 3);

        let safari = records
            .iter()
            .find(|r| r.stream_name == "/safari/history")
            .expect("safari row");
        assert_eq!(safari.url.as_deref(), Some("https://example.com/"));
        assert!(safari.bundle_id.is_none());

        let locked = records
            .iter()
            .find(|r| r.stream_name == "/device/isLocked")
            .expect("locked row");
        assert_eq!(locked.value_integer, Some(1));

        let backlit = records
            .iter()
            .find(|r| r.stream_name == "/display/isBacklit")
            .expect("backlit row");
        assert_eq!(backlit.value_integer, Some(0));
    }

    #[test]
    fn parse_skips_unsupported_streams_and_bad_timestamps() {
        let file = build_fixture(&[
            (
                "/not/a/tracked/stream",
                738_936_000.0,
                None,
                None,
                Some("ignored"),
                None,
            ),
            (
                "/app/inFocus",
                f64::NAN,
                None,
                None,
                Some("com.apple.Terminal"),
                None,
            ),
            (
                "/user/appSession",
                738_936_500.0,
                Some(738_940_100.0),
                None,
                Some("com.apple.Terminal"),
                None,
            ),
        ]);
        let records = parse(file.path());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].stream_name, "/user/appSession");
        assert_eq!(records[0].bundle_id.as_deref(), Some("com.apple.Terminal"));
        assert_eq!(session_duration_secs(&records[0]), Some(3600));
    }

    #[test]
    fn mitre_for_stream_maps_known_streams() {
        assert_eq!(mitre_for_stream("/safari/history"), "T1217");
        assert_eq!(mitre_for_stream("/app/webUsage"), "T1217");
        assert_eq!(mitre_for_stream("/app/inFocus"), "T1059");
        assert_eq!(mitre_for_stream("/user/appSession"), "T1059");
        assert_eq!(mitre_for_stream("/device/isLocked"), "T1083");
        assert_eq!(mitre_for_stream("/display/isBacklit"), "T1083");
        assert_eq!(mitre_for_stream("/anything/else"), "T1083");
    }

    #[test]
    fn decode_apple_timestamp_rejects_nonfinite_and_out_of_range() {
        assert!(decode_apple_timestamp(f64::NAN).is_none());
        assert!(decode_apple_timestamp(f64::INFINITY).is_none());
        assert!(decode_apple_timestamp(-1.0e12).is_none());
        assert!(decode_apple_timestamp(1.0e12).is_none());
        let ok = decode_apple_timestamp(738_936_000.0).expect("finite");
        assert_eq!(ok.timestamp(), 1_717_243_200);
    }
}
