//! Browser history artifact parsing helpers.

use chrono::{DateTime, Duration, TimeZone, Utc};
use rusqlite::Connection;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct BrowserHistoryEntry {
    pub url: String,
    pub title: Option<String>,
    pub visit_time: DateTime<Utc>,
    pub visit_count: u32,
    pub browser: String,
    pub profile: Option<String>,
    pub typed_count: u32,
    pub transition: String,
}

#[derive(Debug, Clone)]
pub struct BrowserDownload {
    pub url: String,
    pub target_path: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub total_bytes: u64,
    pub state: String,
}

#[derive(Debug, Clone, Default)]
pub struct BrowserArtifactBundle {
    pub history: Vec<BrowserHistoryEntry>,
    pub downloads: Vec<BrowserDownload>,
}

pub fn parse_browser_db_bytes(
    path_hint: &str,
    bytes: &[u8],
) -> Result<BrowserArtifactBundle, String> {
    let db_type = detect_browser_type(path_hint);
    if db_type == BrowserType::Unknown {
        return Err("Unsupported browser database path".to_string());
    }
    let profile = detect_profile_name(path_hint);

    let temp_path = temp_db_path(path_hint);
    std::fs::write(&temp_path, bytes).map_err(|e| format!("temp write failed: {}", e))?;

    let parse_result = parse_browser_db_file(&temp_path, db_type, profile.as_deref());
    let _ = std::fs::remove_file(&temp_path);
    parse_result
}

fn parse_browser_db_file(
    path: &Path,
    db_type: BrowserType,
    profile: Option<&str>,
) -> Result<BrowserArtifactBundle, String> {
    let conn = Connection::open(path).map_err(|e| format!("sqlite open failed: {}", e))?;
    match db_type {
        BrowserType::Chrome => parse_chromium(&conn, "Chrome", profile),
        BrowserType::Edge => parse_chromium(&conn, "Edge", profile),
        BrowserType::Firefox => parse_firefox(&conn, profile),
        BrowserType::Unknown => Err("unknown browser database type".to_string()),
    }
}

fn parse_chromium(
    conn: &Connection,
    browser_name: &str,
    profile: Option<&str>,
) -> Result<BrowserArtifactBundle, String> {
    let mut out = BrowserArtifactBundle::default();

    let mut stmt = conn
        .prepare(
            "SELECT urls.url, urls.title, urls.visit_count, urls.typed_count, visits.visit_time, visits.transition
             FROM visits
             JOIN urls ON visits.url = urls.id
             ORDER BY visits.visit_time DESC
             LIMIT 5000",
        )
        .map_err(|e| format!("history query prepare failed: {}", e))?;

    let rows = stmt
        .query_map([], |row| {
            let raw_visit_time: i64 = row.get(4)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2).unwrap_or(0),
                row.get::<_, i64>(3).unwrap_or(0),
                raw_visit_time,
                row.get::<_, i64>(5).unwrap_or(0),
            ))
        })
        .map_err(|e| format!("history query failed: {}", e))?;

    for row in rows {
        let Ok((url, title, visit_count, typed_count, raw_visit_time, transition)) = row else {
            continue;
        };
        let Some(visit_time) = chrome_time_to_utc(raw_visit_time) else {
            continue;
        };
        out.history.push(BrowserHistoryEntry {
            url,
            title,
            visit_time,
            visit_count: visit_count.max(0) as u32,
            browser: browser_name.to_string(),
            profile: profile.map(|s| s.to_string()),
            typed_count: typed_count.max(0) as u32,
            transition: chromium_transition_label(transition),
        });
    }

    if let Ok(mut dstmt) = conn.prepare(
        "SELECT tab_url, target_path, start_time, end_time, received_bytes, state
         FROM downloads
         ORDER BY start_time DESC
         LIMIT 2000",
    ) {
        if let Ok(rows) = dstmt.query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2).unwrap_or(0),
                row.get::<_, Option<i64>>(3).ok().flatten(),
                row.get::<_, i64>(4).unwrap_or(0),
                row.get::<_, i64>(5).unwrap_or(0),
            ))
        }) {
            for row in rows {
                let Ok((url, target_path, start_time_raw, end_time_raw, total_bytes, state)) = row
                else {
                    continue;
                };
                let Some(start_time) = chrome_time_to_utc(start_time_raw) else {
                    continue;
                };
                out.downloads.push(BrowserDownload {
                    url: url.unwrap_or_default(),
                    target_path: target_path.unwrap_or_default(),
                    start_time,
                    end_time: end_time_raw.and_then(chrome_time_to_utc),
                    total_bytes: total_bytes.max(0) as u64,
                    state: chromium_download_state(state),
                });
            }
        }
    }

    Ok(out)
}

fn parse_firefox(
    conn: &Connection,
    profile: Option<&str>,
) -> Result<BrowserArtifactBundle, String> {
    let mut out = BrowserArtifactBundle::default();

    let mut stmt = conn
        .prepare(
            "SELECT p.url, p.title, p.visit_count, h.visit_date
             FROM moz_historyvisits h
             JOIN moz_places p ON h.place_id = p.id
             ORDER BY h.visit_date DESC
             LIMIT 5000",
        )
        .map_err(|e| format!("firefox history query prepare failed: {}", e))?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2).unwrap_or(0),
                row.get::<_, i64>(3).unwrap_or(0),
            ))
        })
        .map_err(|e| format!("firefox history query failed: {}", e))?;

    for row in rows {
        let Ok((url, title, visit_count, visit_date_raw)) = row else {
            continue;
        };
        let Some(visit_time) = firefox_time_to_utc(visit_date_raw) else {
            continue;
        };
        out.history.push(BrowserHistoryEntry {
            url,
            title,
            visit_time,
            visit_count: visit_count.max(0) as u32,
            browser: "Firefox".to_string(),
            profile: profile.map(|s| s.to_string()),
            typed_count: 0,
            transition: "visit".to_string(),
        });
    }

    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserType {
    Chrome,
    Edge,
    Firefox,
    Unknown,
}

fn detect_browser_type(path_hint: &str) -> BrowserType {
    let p = path_hint.replace('\\', "/").to_lowercase();
    if p.contains("/appdata/local/google/chrome/user data/") {
        BrowserType::Chrome
    } else if p.contains("/appdata/local/microsoft/edge/user data/") {
        BrowserType::Edge
    } else if p.contains("/appdata/roaming/mozilla/firefox/profiles/") {
        BrowserType::Firefox
    } else {
        BrowserType::Unknown
    }
}

fn detect_profile_name(path_hint: &str) -> Option<String> {
    let normalized = path_hint.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').collect();
    if let Some(idx) = parts
        .iter()
        .position(|p| p.eq_ignore_ascii_case("profiles") || p.eq_ignore_ascii_case("user data"))
    {
        let next = parts.get(idx + 1).copied().unwrap_or_default().trim();
        if !next.is_empty() {
            return Some(next.to_string());
        }
    }
    None
}

fn temp_db_path(path_hint: &str) -> std::path::PathBuf {
    let mut safe = path_hint.replace([':', '\\', '/', ' '], "_");
    if safe.len() > 80 {
        safe.truncate(80);
    }
    std::env::temp_dir().join(format!("strata_browser_{}_{}.db", std::process::id(), safe))
}

fn chrome_time_to_utc(micros_since_1601: i64) -> Option<DateTime<Utc>> {
    if micros_since_1601 <= 0 {
        return None;
    }
    let base = Utc.with_ymd_and_hms(1601, 1, 1, 0, 0, 0).single()?;
    base.checked_add_signed(Duration::microseconds(micros_since_1601))
}

fn firefox_time_to_utc(micros_since_unix: i64) -> Option<DateTime<Utc>> {
    if micros_since_unix <= 0 {
        return None;
    }
    Utc.timestamp_micros(micros_since_unix).single()
}

fn chromium_transition_label(value: i64) -> String {
    match value & 0xff {
        0 => "link".to_string(),
        1 => "typed".to_string(),
        2 => "auto_bookmark".to_string(),
        3 => "auto_subframe".to_string(),
        4 => "manual_subframe".to_string(),
        5 => "generated".to_string(),
        6 => "start_page".to_string(),
        7 => "form_submit".to_string(),
        8 => "reload".to_string(),
        _ => "other".to_string(),
    }
}

fn chromium_download_state(value: i64) -> String {
    match value {
        0 => "in_progress".to_string(),
        1 => "complete".to_string(),
        2 => "interrupted".to_string(),
        3 => "cancelled".to_string(),
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_browser_type_matches_known_paths() {
        assert_eq!(
            detect_browser_type("C:/Users/A/AppData/Local/Google/Chrome/User Data/Default/History"),
            BrowserType::Chrome
        );
        assert_eq!(
            detect_browser_type(
                "C:/Users/A/AppData/Local/Microsoft/Edge/User Data/Default/History"
            ),
            BrowserType::Edge
        );
        assert_eq!(
            detect_browser_type(
                "C:/Users/A/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/places.sqlite"
            ),
            BrowserType::Firefox
        );
    }

    #[test]
    fn detect_profile_name_extracts_segment() {
        let p = detect_profile_name(
            "C:/Users/A/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default-release/places.sqlite",
        );
        assert_eq!(p.as_deref(), Some("abc.default-release"));
    }

    #[test]
    fn chromium_transition_labels_are_stable() {
        assert_eq!(chromium_transition_label(1), "typed");
        assert_eq!(chromium_transition_label(8), "reload");
        assert_eq!(chromium_transition_label(255), "other");
    }

    #[test]
    fn chromium_download_states_are_stable() {
        assert_eq!(chromium_download_state(0), "in_progress");
        assert_eq!(chromium_download_state(1), "complete");
        assert_eq!(chromium_download_state(2), "interrupted");
        assert_eq!(chromium_download_state(99), "unknown");
    }
}
