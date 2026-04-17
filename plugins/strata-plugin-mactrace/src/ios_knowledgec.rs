//! iOS KnowledgeC parser — shares schema with [`crate::knowledgec`].
//!
//! `/private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db`.
//!
//! iOS adds streams that don't exist on macOS:
//!
//! * `/device/isPluggedIn` — charging bool (`ZVALUEINTEGER`).
//! * `/device/batteryPercentage` — 0.0..1.0 (`ZVALUEDOUBLE`).
//! * `/media/nowPlaying` — title / artist (`ZVALUESTRING`).
//! * `/safariHistory` — iOS variant of Safari history (URL in
//!   `ZVALUESTRING`).
//! * `/com.apple.messages.count` — per-interval message count
//!   (`ZVALUEINTEGER`).
//! * `/location/significant` — same stream as iOS Biome; retained for
//!   backwards compatibility on iOS 15 and earlier.
//!
//! Shared with macOS: `/app/inFocus`, `/safari/history`,
//! `/user/appSession`.
//!
//! ## Deprecated on iOS 16+
//! iOS 16 deprecates most KnowledgeC streams in favour of Biome
//! (`streams/…`). Parse Biome on modern devices; this module still
//! recovers data from iOS 10–15 images and any device that hasn't
//! migrated.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Unix offset for the CoreData epoch (2001-01-01 UTC).
const APPLE_EPOCH_OFFSET: i64 = 978_307_200;
const MAX_RECORDS: usize = 500_000;

/// Streams this parser understands.
pub const IOS_STREAMS: &[&str] = &[
    "/app/inFocus",
    "/device/isPluggedIn",
    "/device/batteryPercentage",
    "/media/nowPlaying",
    "/safari/history",
    "/safariHistory",
    "/user/appSession",
    "/com.apple.messages.count",
    "/location/significant",
];

/// A row from iOS `ZOBJECT`.
///
/// **Deprecated on iOS 16+**: Apple Biome (see [`crate::ios_biome`])
/// supersedes most of these streams. Both parsers ship so forensic
/// images of mixed iOS versions can be processed uniformly.
#[derive(Debug, Clone, PartialEq)]
pub struct IosKnowledgeCRecord {
    /// `ZSTREAMNAME` verbatim.
    pub stream_name: String,
    /// `ZSTARTDATE` decoded to UTC.
    pub start_time: DateTime<Utc>,
    /// `ZENDDATE` decoded to UTC when present.
    pub end_time: Option<DateTime<Utc>>,
    /// Bundle identifier for app streams (`inFocus`, `appSession`).
    pub bundle_id: Option<String>,
    /// URL for Safari-history streams.
    pub url: Option<String>,
    /// Media title for the `nowPlaying` stream.
    pub media_title: Option<String>,
    /// Integer payload — charging bool, message count, etc.
    pub value_integer: Option<i64>,
    /// Double payload — battery percentage (0.0..1.0).
    pub value_double: Option<f64>,
    /// Device UUID from `ZDEVICEID`.
    pub device_id: Option<String>,
}

pub fn parse(path: &Path) -> Vec<IosKnowledgeCRecord> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = Connection::open_with_flags(path, flags) else {
        return Vec::new();
    };
    query_rows(&conn).unwrap_or_default()
}

fn query_rows(conn: &Connection) -> rusqlite::Result<Vec<IosKnowledgeCRecord>> {
    // Build the IN clause dynamically so adding/removing iOS streams
    // lives entirely in IOS_STREAMS.
    let placeholders = IOS_STREAMS
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT ZSTREAMNAME, ZSTARTDATE, ZENDDATE, ZVALUEINTEGER, ZVALUESTRING, \
                ZVALUEDOUBLE, ZDEVICEID \
         FROM ZOBJECT \
         WHERE ZSTREAMNAME IN ({}) \
         ORDER BY ZSTARTDATE ASC",
        placeholders
    );
    let mut stmt = conn.prepare(&sql)?;
    let params: Vec<&dyn rusqlite::ToSql> = IOS_STREAMS
        .iter()
        .map(|s| s as &dyn rusqlite::ToSql)
        .collect();
    let rows = stmt.query_map(params.as_slice(), |row| {
        let stream_name: String = row.get(0)?;
        let start_raw: Option<f64> = row.get(1)?;
        let end_raw: Option<f64> = row.get(2)?;
        let value_integer: Option<i64> = row.get(3)?;
        let value_string: Option<String> = row.get(4)?;
        let value_double: Option<f64> = row.get(5)?;
        let device_id: Option<String> = row.get(6)?;
        Ok((
            stream_name,
            start_raw,
            end_raw,
            value_integer,
            value_string,
            value_double,
            device_id,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        if out.len() >= MAX_RECORDS {
            break;
        }
        let Ok((stream_name, start_raw, end_raw, vi, vs, vd, did)) = row else {
            continue;
        };
        let Some(start_time) = start_raw.and_then(decode_apple_epoch) else {
            continue;
        };
        let (bundle_id, url, media_title) = split_value_string(&stream_name, vs);
        out.push(IosKnowledgeCRecord {
            stream_name,
            start_time,
            end_time: end_raw.and_then(decode_apple_epoch),
            bundle_id,
            url,
            media_title,
            value_integer: vi,
            value_double: vd,
            device_id: did,
        });
    }
    Ok(out)
}

fn decode_apple_epoch(secs: f64) -> Option<DateTime<Utc>> {
    if !secs.is_finite() {
        return None;
    }
    let whole = secs.trunc() as i64;
    let nanos = ((secs - secs.trunc()) * 1_000_000_000.0) as u32;
    DateTime::<Utc>::from_timestamp(whole.saturating_add(APPLE_EPOCH_OFFSET), nanos)
}

fn split_value_string(
    stream: &str,
    vs: Option<String>,
) -> (Option<String>, Option<String>, Option<String>) {
    match (stream, vs) {
        ("/app/inFocus", Some(s)) | ("/user/appSession", Some(s)) => (Some(s), None, None),
        ("/safari/history", Some(s)) | ("/safariHistory", Some(s)) => (None, Some(s), None),
        ("/media/nowPlaying", Some(s)) => (None, None, Some(s)),
        _ => (None, None, None),
    }
}

/// True when `path` lies under the iOS CoreDuet location.
pub fn is_ios_knowledgec_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.contains("mobile/library/coreduet")
        && path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.eq_ignore_ascii_case("knowledgeC.db"))
            .unwrap_or(false)
}

pub fn mitre_for_stream(stream: &str) -> &'static str {
    match stream {
        "/safari/history" | "/safariHistory" => "T1217",
        "/com.apple.messages.count" => "T1636.002",
        "/location/significant" => "T1430",
        "/media/nowPlaying" => "T1005",
        "/app/inFocus" | "/user/appSession" => "T1059",
        _ => "T1083",
    }
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    type FixtureRow<'a> = (
        &'a str,
        f64,
        Option<f64>,
        Option<i64>,
        Option<&'a str>,
        Option<f64>,
    );

    fn build_fixture(rows: &[FixtureRow<'_>]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("knowledgeC.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE ZOBJECT ( \
                 ZSTREAMNAME TEXT, ZSTARTDATE REAL, ZENDDATE REAL, \
                 ZVALUEINTEGER INTEGER, ZVALUESTRING TEXT, ZVALUEDOUBLE REAL, \
                 ZDEVICEID TEXT \
             );",
        )
        .expect("create");
        for (stream, start, end, vi, vs, vd) in rows {
            conn.execute(
                "INSERT INTO ZOBJECT VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                rusqlite::params![stream, start, end, vi, vs, vd],
            )
            .expect("insert");
        }
        drop(conn);
        dir
    }

    #[test]
    fn parse_returns_empty_on_missing_file() {
        assert!(parse(Path::new("/no/such/knowledgeC.db")).is_empty());
    }

    #[test]
    fn parse_returns_empty_on_missing_table() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("knowledgeC.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch("CREATE TABLE UNRELATED(x INTEGER);")
            .expect("create");
        drop(conn);
        assert!(parse(&path).is_empty());
    }

    #[test]
    fn parse_plugged_in_and_battery() {
        let dir = build_fixture(&[
            (
                "/device/isPluggedIn",
                738_936_000.0,
                None,
                Some(1),
                None,
                None,
            ),
            (
                "/device/batteryPercentage",
                738_936_100.0,
                None,
                None,
                None,
                Some(0.55),
            ),
        ]);
        let recs = parse(&dir.path().join("knowledgeC.db"));
        assert_eq!(recs.len(), 2);
        let plugged = recs
            .iter()
            .find(|r| r.stream_name == "/device/isPluggedIn")
            .expect("plugged");
        assert_eq!(plugged.value_integer, Some(1));
        let bat = recs
            .iter()
            .find(|r| r.stream_name == "/device/batteryPercentage")
            .expect("bat");
        assert_eq!(bat.value_double, Some(0.55));
    }

    #[test]
    fn parse_media_now_playing_and_messages() {
        let dir = build_fixture(&[
            (
                "/media/nowPlaying",
                738_936_000.0,
                Some(738_936_180.0),
                None,
                Some("Album - Song"),
                None,
            ),
            (
                "/com.apple.messages.count",
                738_936_500.0,
                Some(738_940_100.0),
                Some(42),
                None,
                None,
            ),
        ]);
        let recs = parse(&dir.path().join("knowledgeC.db"));
        assert_eq!(recs.len(), 2);
        let media = recs
            .iter()
            .find(|r| r.stream_name == "/media/nowPlaying")
            .expect("media");
        assert_eq!(media.media_title.as_deref(), Some("Album - Song"));
        let msg = recs
            .iter()
            .find(|r| r.stream_name == "/com.apple.messages.count")
            .expect("messages");
        assert_eq!(msg.value_integer, Some(42));
    }

    #[test]
    fn parse_skips_unknown_streams_and_bad_timestamps() {
        let dir = build_fixture(&[
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
                Some("com.apple.Safari"),
                None,
            ),
            (
                "/app/inFocus",
                738_936_400.0,
                Some(738_936_460.0),
                None,
                Some("com.apple.mobilesafari"),
                None,
            ),
        ]);
        let recs = parse(&dir.path().join("knowledgeC.db"));
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].bundle_id.as_deref(), Some("com.apple.mobilesafari"));
    }

    #[test]
    fn is_ios_knowledgec_path_matches_canonical_location() {
        assert!(is_ios_knowledgec_path(Path::new(
            "/private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db"
        )));
        assert!(!is_ios_knowledgec_path(Path::new(
            "/private/var/db/CoreDuet/Knowledge/knowledgeC.db"
        )));
    }

    #[test]
    fn mitre_maps_per_stream() {
        assert_eq!(mitre_for_stream("/safariHistory"), "T1217");
        assert_eq!(mitre_for_stream("/location/significant"), "T1430");
        assert_eq!(mitre_for_stream("/com.apple.messages.count"), "T1636.002");
        assert_eq!(mitre_for_stream("/app/inFocus"), "T1059");
        assert_eq!(mitre_for_stream("/media/nowPlaying"), "T1005");
    }
}
