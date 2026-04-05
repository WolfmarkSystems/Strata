use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct BrowserHistoryEntry {
    pub url: String,
    pub title: Option<String>,
    pub timestamp: i64,
    pub browser: BrowserType,
    pub visit_count: u32,
}

#[derive(Debug, Clone)]
pub struct BrowserForensicsRecord {
    pub url: String,
    pub title: Option<String>,
    pub browser: Option<String>,
    pub timestamp_unix: Option<i64>,
    pub timestamp_utc: Option<String>,
    pub timestamp_precision: String,
    pub user_sid: Option<String>,
    pub username: Option<String>,
    pub profile_path: Option<String>,
    pub process_path: Option<String>,
    pub visit_count: Option<u32>,
    pub source_path: Option<String>,
    pub source_record_id: Option<String>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum BrowserType {
    Chrome,
    Firefox,
    Edge,
    Safari,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserInputShape {
    Missing,
    Empty,
    Directory,
    Sqlite,
    JsonArray,
    JsonObject,
    CsvText,
    LineText,
    Unknown,
}

impl BrowserInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::Directory => "directory",
            Self::Sqlite => "sqlite",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::CsvText => "csv-text",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_browser_forensics_input_shape(path: &Path) -> BrowserInputShape {
    if !path.exists() {
        return BrowserInputShape::Missing;
    }
    if path.is_dir() {
        return BrowserInputShape::Directory;
    }
    if path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.eq_ignore_ascii_case("sqlite") || v.eq_ignore_ascii_case("db"))
        .unwrap_or(false)
    {
        return BrowserInputShape::Sqlite;
    }

    let Ok(bytes) = std::fs::read(path) else {
        return BrowserInputShape::Unknown;
    };
    if bytes.is_empty() {
        return BrowserInputShape::Empty;
    }
    if bytes.len() >= 16 && &bytes[0..16] == b"SQLite format 3\0" {
        return BrowserInputShape::Sqlite;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return BrowserInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return BrowserInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return BrowserInputShape::JsonObject;
    }
    let first = trimmed
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first.contains("url")
        || first.contains("title")
        || first.contains("visit")
        || first.contains("browser")
    {
        return BrowserInputShape::CsvText;
    }
    BrowserInputShape::LineText
}

pub fn parse_browser_records_from_path(path: &Path, limit: usize) -> Vec<BrowserForensicsRecord> {
    if !path.exists() || limit == 0 {
        return Vec::new();
    }

    let mut rows = if path.is_dir() {
        parse_browser_dir(path, limit)
    } else {
        parse_browser_file(path)
    };

    if rows.is_empty() {
        rows = parse_browser_text_fallback(path);
    }

    let mut seen = BTreeSet::<String>::new();
    rows.retain(|row| {
        let key = format!(
            "{}|{}|{}|{}|{}",
            row.url,
            row.browser.clone().unwrap_or_default(),
            row.timestamp_unix
                .map(|v| v.to_string())
                .unwrap_or_default(),
            row.user_sid.clone().unwrap_or_default(),
            row.profile_path.clone().unwrap_or_default()
        );
        seen.insert(key)
    });

    rows.sort_by(|a, b| {
        b.timestamp_unix
            .is_some()
            .cmp(&a.timestamp_unix.is_some())
            .then_with(|| {
                b.timestamp_unix
                    .unwrap_or_default()
                    .cmp(&a.timestamp_unix.unwrap_or_default())
            })
            .then_with(|| {
                a.browser
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(b.browser.as_deref().unwrap_or_default())
            })
            .then_with(|| a.url.cmp(&b.url))
    });
    rows.truncate(limit);
    rows
}

pub fn parse_browser_text_fallback(path: &Path) -> Vec<BrowserForensicsRecord> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_browser_csv_or_lines(&content)
}

fn parse_browser_dir(path: &Path, limit: usize) -> Vec<BrowserForensicsRecord> {
    let mut rows = Vec::new();
    let Ok(entries) = strata_fs::read_dir(path) else {
        return rows;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let remaining = limit.saturating_sub(rows.len());
            if remaining == 0 {
                break;
            }
            let mut nested = parse_browser_dir(&p, remaining);
            rows.append(&mut nested);
            continue;
        }

        let mut parsed = parse_browser_file(&p);
        rows.append(&mut parsed);
        if rows.len() >= limit {
            break;
        }
    }
    rows
}

fn parse_browser_file(path: &Path) -> Vec<BrowserForensicsRecord> {
    if let Ok(bytes) = strata_fs::read(path) {
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            return parse_browser_rows_json_value(&value);
        }

        let text = String::from_utf8_lossy(&bytes);
        let mut rows = parse_browser_csv_or_lines(&text);
        if rows.is_empty()
            && matches!(
                detect_browser_forensics_input_shape(path),
                BrowserInputShape::Sqlite
            )
        {
            rows = parse_browser_sqlite_fallback(path);
        }
        return rows;
    }
    Vec::new()
}

fn parse_browser_sqlite_fallback(path: &Path) -> Vec<BrowserForensicsRecord> {
    let mut rows = Vec::new();

    if let Ok(chrome) = parse_chrome_history(path) {
        rows.extend(chrome.into_iter().map(|row| {
            let ts = normalize_epochish_timestamp(Some(row.timestamp));
            BrowserForensicsRecord {
                url: row.url,
                title: row.title,
                browser: Some(browser_type_name(&row.browser).to_string()),
                timestamp_unix: ts.0,
                timestamp_utc: ts.1,
                timestamp_precision: ts.2,
                user_sid: None,
                username: None,
                profile_path: None,
                process_path: Some("chrome.exe".to_string()),
                visit_count: Some(row.visit_count),
                source_path: Some(path.to_string_lossy().to_string()),
                source_record_id: None,
            }
        }));
    }
    if rows.is_empty() {
        if let Ok(firefox) = parse_firefox_history(path) {
            rows.extend(firefox.into_iter().map(|row| {
                let ts = normalize_epochish_timestamp(Some(row.timestamp));
                BrowserForensicsRecord {
                    url: row.url,
                    title: row.title,
                    browser: Some(browser_type_name(&row.browser).to_string()),
                    timestamp_unix: ts.0,
                    timestamp_utc: ts.1,
                    timestamp_precision: ts.2,
                    user_sid: None,
                    username: None,
                    profile_path: None,
                    process_path: Some("firefox.exe".to_string()),
                    visit_count: Some(row.visit_count),
                    source_path: Some(path.to_string_lossy().to_string()),
                    source_record_id: None,
                }
            }));
        }
    }

    rows
}

fn parse_browser_rows_json_value(value: &Value) -> Vec<BrowserForensicsRecord> {
    let rows = if let Some(arr) = value.as_array() {
        arr.clone()
    } else if let Some(obj) = value.as_object() {
        obj.get("records")
            .and_then(|v| v.as_array())
            .or_else(|| obj.get("entries").and_then(|v| v.as_array()))
            .or_else(|| obj.get("history").and_then(|v| v.as_array()))
            .or_else(|| obj.get("data").and_then(|v| v.as_array()))
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut out = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else {
            continue;
        };
        let url = obj
            .get("url")
            .and_then(|v| v.as_str())
            .or_else(|| obj.get("uri").and_then(|v| v.as_str()))
            .or_else(|| obj.get("link").and_then(|v| v.as_str()))
            .unwrap_or_default()
            .trim()
            .to_string();
        if url.is_empty() {
            continue;
        }
        let browser = obj
            .get("browser")
            .and_then(|v| v.as_str())
            .or_else(|| obj.get("browser_name").and_then(|v| v.as_str()))
            .map(normalize_browser_name);
        let (timestamp_unix, timestamp_utc, timestamp_precision) = normalize_timestamp_fields(
            obj.get("timestamp_unix")
                .or_else(|| obj.get("timestamp"))
                .or_else(|| obj.get("visit_time"))
                .or_else(|| obj.get("last_visit_time"))
                .or_else(|| obj.get("occurred_utc"))
                .or_else(|| obj.get("timestamp_utc")),
        );
        out.push(BrowserForensicsRecord {
            url,
            title: obj
                .get("title")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("page_title").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            browser,
            timestamp_unix,
            timestamp_utc,
            timestamp_precision,
            user_sid: obj
                .get("user_sid")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("sid").and_then(|v| v.as_str()))
                .map(normalize_sid),
            username: obj
                .get("username")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("user").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            profile_path: obj
                .get("profile_path")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("profile").and_then(|v| v.as_str()))
                .map(normalize_path),
            process_path: obj
                .get("process_path")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("process").and_then(|v| v.as_str()))
                .map(normalize_path),
            visit_count: obj
                .get("visit_count")
                .and_then(value_to_u32)
                .or_else(|| obj.get("count").and_then(value_to_u32)),
            source_path: obj
                .get("source_path")
                .and_then(|v| v.as_str())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            source_record_id: obj
                .get("source_record_id")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("record_id").and_then(|v| v.as_str()))
                .or_else(|| obj.get("id").and_then(|v| v.as_str()))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
        });
    }
    out
}

fn parse_browser_csv_or_lines(content: &str) -> Vec<BrowserForensicsRecord> {
    let mut out = Vec::new();
    let mut lines = content.lines();
    let first = lines.next().unwrap_or_default();
    let first_lc = first.to_ascii_lowercase();

    if first.contains(',')
        && (first_lc.contains("url")
            || first_lc.contains("browser")
            || first_lc.contains("timestamp"))
    {
        let headers = first
            .split(',')
            .map(|v| v.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let cols = trimmed.split(',').map(|v| v.trim()).collect::<Vec<_>>();
            if cols.is_empty() {
                continue;
            }
            let get_col = |name: &str| -> Option<&str> {
                headers
                    .iter()
                    .position(|h| h == name)
                    .and_then(|idx| cols.get(idx).copied())
            };
            let url = get_col("url")
                .or_else(|| get_col("uri"))
                .or_else(|| cols.first().copied())
                .unwrap_or_default()
                .trim()
                .to_string();
            if url.is_empty() {
                continue;
            }
            let ts_raw = get_col("timestamp_unix")
                .or_else(|| get_col("timestamp"))
                .or_else(|| get_col("occurred_utc"));
            let (timestamp_unix, timestamp_utc, timestamp_precision) =
                normalize_timestamp_str(ts_raw.unwrap_or_default());
            out.push(BrowserForensicsRecord {
                url,
                title: get_col("title")
                    .or_else(|| get_col("page_title"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                browser: get_col("browser").map(normalize_browser_name),
                timestamp_unix,
                timestamp_utc,
                timestamp_precision,
                user_sid: get_col("user_sid")
                    .or_else(|| get_col("sid"))
                    .map(normalize_sid),
                username: get_col("username")
                    .or_else(|| get_col("user"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                profile_path: get_col("profile_path")
                    .or_else(|| get_col("profile"))
                    .map(normalize_path),
                process_path: get_col("process_path")
                    .or_else(|| get_col("process"))
                    .map(normalize_path),
                visit_count: get_col("visit_count").and_then(|v| v.parse::<u32>().ok()),
                source_path: get_col("source_path")
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                source_record_id: get_col("source_record_id")
                    .or_else(|| get_col("record_id"))
                    .or_else(|| get_col("id"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
            });
        }
        return out;
    }

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((url_part, rest)) = trimmed.split_once('|') {
            let url = url_part.trim().to_string();
            if url.is_empty() {
                continue;
            }
            let (timestamp_unix, timestamp_utc, timestamp_precision) =
                normalize_timestamp_str(rest);
            out.push(BrowserForensicsRecord {
                url,
                title: None,
                browser: None,
                timestamp_unix,
                timestamp_utc,
                timestamp_precision,
                user_sid: None,
                username: None,
                profile_path: None,
                process_path: None,
                visit_count: None,
                source_path: None,
                source_record_id: None,
            });
            continue;
        }
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            out.push(BrowserForensicsRecord {
                url: trimmed.to_string(),
                title: None,
                browser: None,
                timestamp_unix: None,
                timestamp_utc: None,
                timestamp_precision: "none".to_string(),
                user_sid: None,
                username: None,
                profile_path: None,
                process_path: None,
                visit_count: None,
                source_path: None,
                source_record_id: None,
            });
        }
    }

    out
}

fn normalize_browser_name(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "chrome" | "google chrome" | "chrome.exe" => "chrome".to_string(),
        "edge" | "microsoft edge" | "msedge" | "msedge.exe" => "edge".to_string(),
        "firefox" | "mozilla firefox" | "firefox.exe" => "firefox".to_string(),
        "safari" | "safari.exe" => "safari".to_string(),
        v => v.to_string(),
    }
}

fn normalize_sid(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn normalize_path(value: &str) -> String {
    value
        .trim()
        .replace('/', "\\")
        .replace("\\\\?\\", "")
        .trim_end_matches('\\')
        .to_string()
}

fn value_to_u32(value: &Value) -> Option<u32> {
    if let Some(v) = value.as_u64() {
        return u32::try_from(v).ok();
    }
    if let Some(v) = value.as_i64() {
        return u32::try_from(v).ok();
    }
    value.as_str().and_then(|v| v.trim().parse::<u32>().ok())
}

fn normalize_timestamp_fields(value: Option<&Value>) -> (Option<i64>, Option<String>, String) {
    let Some(v) = value else {
        return (None, None, "none".to_string());
    };
    if let Some(num) = v.as_i64() {
        return normalize_epochish_timestamp(Some(num));
    }
    if let Some(num) = v.as_u64() {
        let signed = i64::try_from(num).unwrap_or(i64::MAX);
        return normalize_epochish_timestamp(Some(signed));
    }
    if let Some(s) = v.as_str() {
        return normalize_timestamp_str(s);
    }
    (None, None, "none".to_string())
}

fn normalize_timestamp_str(value: &str) -> (Option<i64>, Option<String>, String) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return (None, None, "none".to_string());
    }
    if let Ok(v) = trimmed.parse::<i64>() {
        return normalize_epochish_timestamp(Some(v));
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        let ts = dt.timestamp();
        return (Some(ts), Some(ts_to_utc(ts)), "seconds".to_string());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        let ts = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc)
            .timestamp();
        return (Some(ts), Some(ts_to_utc(ts)), "seconds".to_string());
    }
    (None, None, "none".to_string())
}

fn normalize_epochish_timestamp(value: Option<i64>) -> (Option<i64>, Option<String>, String) {
    let Some(raw) = value else {
        return (None, None, "none".to_string());
    };
    if raw <= 0 {
        return (None, None, "none".to_string());
    }

    let (unix, precision) = if raw > 100_000_000_000_000 {
        // WebKit microseconds since 1601-01-01.
        let unix = raw / 1_000_000 - 11_644_473_600;
        (unix, "microseconds".to_string())
    } else if raw > 10_000_000_000 {
        (raw / 1_000, "milliseconds".to_string())
    } else {
        (raw, "seconds".to_string())
    };

    if unix <= 0 {
        return (None, None, "none".to_string());
    }
    (Some(unix), Some(ts_to_utc(unix)), precision)
}

fn ts_to_utc(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

fn browser_type_name(value: &BrowserType) -> &'static str {
    match value {
        BrowserType::Chrome => "chrome",
        BrowserType::Firefox => "firefox",
        BrowserType::Edge => "edge",
        BrowserType::Safari => "safari",
        BrowserType::Unknown => "unknown",
    }
}

pub fn parse_chrome_history(path: &Path) -> Result<Vec<BrowserHistoryEntry>, std::io::Error> {
    let mut entries = Vec::new();

    if !path.exists() {
        return Ok(entries);
    }

    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)?;

    if data.len() < 16 {
        return Ok(entries);
    }

    let mut pos = 0;
    while pos + 16 <= data.len() {
        let record_type = data[pos];
        let record_length =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);

        if record_type == 1 && record_length > 20 {
            let url_start = pos + 8;
            let url_end = url_start + (record_length as usize - 8).min(2048);

            if url_end <= data.len() {
                let url_bytes = &data[url_start..url_end];
                if let Ok(url) = String::from_utf8(url_bytes.to_vec()) {
                    let url = url.trim_end_matches('\0').to_string();
                    if !url.is_empty() && url.starts_with("http") {
                        let timestamp = u64::from_le_bytes([
                            data[pos + 8 + 8],
                            data[pos + 8 + 9],
                            data[pos + 8 + 10],
                            data[pos + 8 + 11],
                            data[pos + 8 + 12],
                            data[pos + 8 + 13],
                            data[pos + 8 + 14],
                            data[pos + 8 + 15],
                        ]);

                        entries.push(BrowserHistoryEntry {
                            url,
                            title: None,
                            timestamp: timestamp as i64,
                            browser: BrowserType::Chrome,
                            visit_count: 1,
                        });
                    }
                }
            }
        }

        if record_length == 0 {
            break;
        }
        pos += record_length as usize;
    }

    Ok(entries)
}

pub fn parse_firefox_history(path: &Path) -> Result<Vec<BrowserHistoryEntry>, std::io::Error> {
    let mut entries = Vec::new();

    if !path.exists() {
        return Ok(entries);
    }

    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)?;

    let search_string = b"http".to_vec();
    let mut pos = 0;

    while let Some(found) = data[pos..].iter().position(|&b| b == search_string[0]) {
        pos += found;

        if pos + 10 < data.len() && &data[pos..pos + 4] == b"http" {
            let end = data[pos..].iter().position(|&b| b == 0).unwrap_or(1000);
            if end < 2048 {
                let url_bytes = &data[pos..pos + end];
                if let Ok(url) = String::from_utf8(url_bytes.to_vec()) {
                    if url.starts_with("http") {
                        entries.push(BrowserHistoryEntry {
                            url,
                            title: None,
                            timestamp: 0,
                            browser: BrowserType::Firefox,
                            visit_count: 1,
                        });
                    }
                }
            }
        }

        pos += 1;
        if pos > data.len().saturating_sub(100) {
            break;
        }
    }

    Ok(entries)
}

pub fn detect_browser_history_paths(
    base_path: &Path,
) -> std::collections::HashMap<BrowserType, Vec<std::path::PathBuf>> {
    use std::collections::HashMap;
    let mut paths = HashMap::new();

    let chrome_path = base_path.join("Google/Chrome/User Data/Default/History");
    if chrome_path.exists() {
        paths
            .entry(BrowserType::Chrome)
            .or_insert_with(Vec::new)
            .push(chrome_path);
    }

    let firefox_path = base_path.join("Mozilla/Firefox/Profiles");
    if firefox_path.exists() {
        if let Ok(entries) = std::fs::read_dir(&firefox_path) {
            for entry in entries.flatten() {
                let places = entry.path().join("places.sqlite");
                if places.exists() {
                    paths
                        .entry(BrowserType::Firefox)
                        .or_insert_with(Vec::new)
                        .push(places);
                }
            }
        }
    }

    let edge_path = base_path.join("Microsoft/Edge/User Data/Default/History");
    if edge_path.exists() {
        paths
            .entry(BrowserType::Edge)
            .or_insert_with(Vec::new)
            .push(edge_path);
    }

    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_browser_forensics_input_shape_supports_sqlite_json_csv() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("browser");
        let sqlite = temp.path().join("History");
        let json = temp.path().join("history.json");
        let csv = temp.path().join("history.csv");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(&sqlite, b"SQLite format 3\0.....").expect("sqlite");
        std::fs::write(
            &json,
            r#"[{"url":"https://example.com","timestamp":1700001000,"browser":"chrome"}]"#,
        )
        .expect("json");
        std::fs::write(
            &csv,
            "url,title,timestamp,browser\nhttps://example.com,Example,1700001000,chrome\n",
        )
        .expect("csv");

        assert_eq!(
            detect_browser_forensics_input_shape(&dir),
            BrowserInputShape::Directory
        );
        assert_eq!(
            detect_browser_forensics_input_shape(&sqlite),
            BrowserInputShape::Sqlite
        );
        assert_eq!(
            detect_browser_forensics_input_shape(&json),
            BrowserInputShape::JsonArray
        );
        assert_eq!(
            detect_browser_forensics_input_shape(&csv),
            BrowserInputShape::CsvText
        );
    }

    #[test]
    fn parse_browser_records_from_path_parses_json_rows() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("browser.json");
        std::fs::write(
            &path,
            r#"[{"url":"https://example.test","title":"Example","timestamp":1700033001,"browser":"Chrome","user_sid":"s-1-5-21","profile_path":"C:/Users/test/AppData/Local/Google/Chrome/User Data/Default"}]"#,
        )
        .expect("write");

        let rows = parse_browser_records_from_path(&path, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].url, "https://example.test");
        assert_eq!(rows[0].browser.as_deref(), Some("chrome"));
        assert_eq!(rows[0].timestamp_unix, Some(1_700_033_001));
        assert_eq!(rows[0].user_sid.as_deref(), Some("S-1-5-21"));
        assert!(rows[0]
            .profile_path
            .as_deref()
            .unwrap_or_default()
            .contains("Users\\test\\AppData"));
    }

    #[test]
    fn parse_browser_text_fallback_handles_partial_rows() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("browser.txt");
        std::fs::write(
            &path,
            "url,timestamp,browser\nhttps://one.test,1700033002,edge\nhttps://two.test|\nhttps://three.test\n",
        )
        .expect("write");

        let rows = parse_browser_text_fallback(&path);
        assert!(rows.len() >= 2);
        assert!(rows.iter().any(|r| r.url == "https://one.test"));
        assert!(rows.iter().any(|r| r.url == "https://three.test"));
    }
}
