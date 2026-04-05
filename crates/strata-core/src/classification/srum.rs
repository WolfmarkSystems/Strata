use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrumInputShape {
    Json,
    Csv,
    RawEse,
    Unknown,
}

impl SrumInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::RawEse => "raw_ese",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SrumRecord {
    pub record_id: Option<u64>,
    pub provider: Option<String>,
    pub record_type: Option<String>,
    pub timestamp_utc: Option<String>,
    pub timestamp_unix: Option<i64>,
    pub timestamp_precision: Option<String>,
    pub app_id: Option<String>,
    pub app_name: Option<String>,
    pub exe_path: Option<String>,
    pub user_sid: Option<String>,
    pub network_interface: Option<String>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub packets_in: Option<u64>,
    pub packets_out: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SrumParseMetadata {
    pub input_shape: String,
    pub parser_mode: String,
    pub fallback_used: bool,
    pub parsed_count: usize,
    pub deduped_count: usize,
    pub quality_flags: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SrumParseResult {
    pub records: Vec<SrumRecord>,
    pub metadata: SrumParseMetadata,
}

pub fn detect_srum_input_shape(data: &[u8]) -> SrumInputShape {
    if data.is_empty() {
        return SrumInputShape::Unknown;
    }

    // ESE/Jet database signature (0x89ABCDEF) at offset 4 in little endian.
    if data.len() >= 8 && data[4..8] == [0xEF, 0xCD, 0xAB, 0x89] {
        return SrumInputShape::RawEse;
    }

    let text = String::from_utf8_lossy(data);
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return SrumInputShape::Json;
    }

    if looks_csv_like(trimmed) {
        return SrumInputShape::Csv;
    }

    SrumInputShape::Unknown
}

pub fn parse_srum_records(data: &[u8]) -> Vec<SrumRecord> {
    parse_srum_records_with_metadata(data).records
}

pub fn parse_srum_records_with_metadata(data: &[u8]) -> SrumParseResult {
    let shape = detect_srum_input_shape(data);
    let mut metadata = SrumParseMetadata {
        input_shape: shape.as_str().to_string(),
        parser_mode: "none".to_string(),
        fallback_used: false,
        parsed_count: 0,
        deduped_count: 0,
        quality_flags: Vec::new(),
    };

    if data.is_empty() {
        metadata.quality_flags.push("empty_input".to_string());
        return SrumParseResult {
            records: Vec::new(),
            metadata,
        };
    }

    let mut rows: Vec<SrumRecord> = Vec::new();
    let mut attempted_json = false;

    if matches!(shape, SrumInputShape::Json | SrumInputShape::Unknown) {
        attempted_json = true;
        if let Ok(value) = serde_json::from_slice::<Value>(data) {
            rows = parse_json_records(&value);
            if !rows.is_empty() {
                metadata.parser_mode = "json".to_string();
            }
        }
    }

    if rows.is_empty() {
        let text = String::from_utf8_lossy(data);
        let csv_rows = parse_csv_records(text.as_ref());
        if !csv_rows.is_empty() {
            rows = csv_rows;
            metadata.parser_mode = "csv".to_string();
            metadata.fallback_used = attempted_json;
        }
    }

    if metadata.parser_mode == "none" {
        metadata.parser_mode = "none".to_string();
    }

    if shape == SrumInputShape::RawEse {
        metadata
            .quality_flags
            .push("raw_ese_direct_decode_not_implemented".to_string());
    }

    for row in &mut rows {
        normalize_record(row);
    }

    let pre_dedupe = rows.len();
    rows = dedupe_records(rows);
    metadata.deduped_count = pre_dedupe.saturating_sub(rows.len());
    if metadata.deduped_count > 0 {
        metadata
            .quality_flags
            .push("dedupe_applied_exact_key".to_string());
    }

    sort_records_newest_first(&mut rows);
    metadata.parsed_count = rows.len();

    if rows.is_empty() {
        metadata.quality_flags.push("no_records_parsed".to_string());
    }
    if rows.iter().all(|r| r.timestamp_unix.is_none()) {
        metadata
            .quality_flags
            .push("no_valid_timestamps".to_string());
    }
    if rows.iter().all(|r| r.user_sid.is_none()) {
        metadata.quality_flags.push("no_user_sid".to_string());
    }
    if rows.iter().all(|r| r.exe_path.is_none()) {
        metadata.quality_flags.push("no_exe_path".to_string());
    }

    SrumParseResult {
        records: rows,
        metadata,
    }
}

fn looks_csv_like(text: &str) -> bool {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let Some(first) = lines.next() else {
        return false;
    };
    (first.contains(',') || first.contains('|')) && first.chars().any(|c| c.is_ascii_alphabetic())
}

fn parse_json_records(value: &Value) -> Vec<SrumRecord> {
    if let Some(rows) = value.as_array() {
        return rows.iter().filter_map(parse_json_row).collect();
    }

    if let Some(obj) = value.as_object() {
        for key in ["records", "entries", "rows", "items", "data"] {
            if let Some(rows) = obj.get(key).and_then(Value::as_array) {
                return rows.iter().filter_map(parse_json_row).collect();
            }
        }
        if let Some(data_obj) = obj.get("data").and_then(Value::as_object) {
            for key in ["records", "entries", "rows", "items", "events", "results"] {
                if let Some(rows) = data_obj.get(key).and_then(Value::as_array) {
                    return rows.iter().filter_map(parse_json_row).collect();
                }
            }
        }

        if let Some(row) = parse_json_row(value) {
            return vec![row];
        }
    }

    Vec::new()
}

fn parse_json_row(row: &Value) -> Option<SrumRecord> {
    let obj = row.as_object()?;

    let (timestamp_utc, timestamp_unix, timestamp_precision) = parse_timestamp_value(
        obj.get("timestamp_utc")
            .or_else(|| obj.get("timestamp"))
            .or_else(|| obj.get("event_time"))
            .or_else(|| obj.get("occurred_utc"))
            .or_else(|| obj.get("time_created"))
            .or_else(|| obj.get("time_unix"))
            .or_else(|| obj.get("time"))
            .or_else(|| obj.get("timestamp_unix"))
            .or_else(|| obj.get("last_updated")),
    );

    Some(SrumRecord {
        record_id: get_u64(obj, &["record_id", "recordid", "id", "RecordId"]),
        provider: get_string(
            obj,
            &[
                "provider",
                "provider_name",
                "table",
                "source",
                "source_provider",
                "provider_id",
                "providerid",
            ],
        ),
        record_type: get_string(
            obj,
            &[
                "record_type",
                "type",
                "category",
                "event_type",
                "usage_type",
                "event_category",
            ],
        ),
        timestamp_utc,
        timestamp_unix,
        timestamp_precision,
        app_id: get_string(obj, &["app_id", "appid", "application_id", "app_guid"]),
        app_name: get_string(
            obj,
            &[
                "app_name",
                "application_name",
                "image_name",
                "process_name",
                "name",
                "application",
            ],
        ),
        exe_path: get_string(
            obj,
            &["exe_path", "path", "image_path", "full_path", "fullpath"],
        ),
        user_sid: get_string(obj, &["user_sid", "sid", "user", "usersid", "user_id"]),
        network_interface: get_string(
            obj,
            &[
                "network_interface",
                "interface",
                "interface_luid",
                "luid",
                "interface_name",
            ],
        ),
        bytes_in: get_u64(
            obj,
            &[
                "bytes_in",
                "in_bytes",
                "bytesrecv",
                "recv_bytes",
                "rx_bytes",
                "download_bytes",
            ],
        ),
        bytes_out: get_u64(
            obj,
            &[
                "bytes_out",
                "out_bytes",
                "bytessent",
                "sent_bytes",
                "tx_bytes",
                "upload_bytes",
            ],
        ),
        packets_in: get_u64(
            obj,
            &["packets_in", "in_packets", "packetsrecv", "rx_packets"],
        ),
        packets_out: get_u64(
            obj,
            &["packets_out", "out_packets", "packetssent", "tx_packets"],
        ),
    })
}

fn parse_csv_records(text: &str) -> Vec<SrumRecord> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Vec::new();
    }

    let header = lines.remove(0);
    let delimiter = if header.contains('|') && !header.contains(',') {
        '|'
    } else {
        ','
    };
    let header_parts = split_delimited_line(header, delimiter);
    let normalized_header: Vec<String> = header_parts
        .iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .collect();

    let record_id_index = header_index(&normalized_header, &["record_id", "recordid", "id"]);
    let provider_index = header_index(
        &normalized_header,
        &["provider", "provider_name", "table", "source"],
    );
    let record_type_index = header_index(
        &normalized_header,
        &[
            "record_type",
            "type",
            "category",
            "event_type",
            "usage_type",
        ],
    );
    let timestamp_index = header_index(
        &normalized_header,
        &[
            "timestamp_utc",
            "timestamp",
            "event_time",
            "occurred_utc",
            "time_created",
            "time",
            "time_unix",
            "timestamp_unix",
            "last_updated",
        ],
    );
    let app_id_index = header_index(
        &normalized_header,
        &["app_id", "appid", "application_id", "app_guid"],
    );
    let app_name_index = header_index(
        &normalized_header,
        &[
            "app_name",
            "application_name",
            "image_name",
            "process_name",
            "name",
            "application",
        ],
    );
    let exe_path_index = header_index(
        &normalized_header,
        &["exe_path", "path", "image_path", "full_path", "fullpath"],
    );
    let user_sid_index = header_index(
        &normalized_header,
        &["user_sid", "sid", "user", "usersid", "user_id"],
    );
    let interface_index = header_index(
        &normalized_header,
        &[
            "network_interface",
            "interface",
            "interface_luid",
            "luid",
            "interface_name",
        ],
    );
    let bytes_in_index = header_index(
        &normalized_header,
        &[
            "bytes_in",
            "in_bytes",
            "bytesrecv",
            "recv_bytes",
            "rx_bytes",
            "download_bytes",
        ],
    );
    let bytes_out_index = header_index(
        &normalized_header,
        &[
            "bytes_out",
            "out_bytes",
            "bytessent",
            "sent_bytes",
            "tx_bytes",
            "upload_bytes",
        ],
    );
    let packets_in_index = header_index(
        &normalized_header,
        &["packets_in", "in_packets", "packetsrecv", "rx_packets"],
    );
    let packets_out_index = header_index(
        &normalized_header,
        &["packets_out", "out_packets", "packetssent", "tx_packets"],
    );

    let mut out = Vec::new();
    for line in lines {
        let cols = split_delimited_line(line, delimiter);
        let (timestamp_utc, timestamp_unix, timestamp_precision) =
            parse_timestamp_str(get_col(&cols, timestamp_index));
        out.push(SrumRecord {
            record_id: get_col(&cols, record_id_index).and_then(parse_u64_text),
            provider: get_col(&cols, provider_index).map(ToString::to_string),
            record_type: get_col(&cols, record_type_index).map(ToString::to_string),
            timestamp_utc,
            timestamp_unix,
            timestamp_precision,
            app_id: get_col(&cols, app_id_index).map(ToString::to_string),
            app_name: get_col(&cols, app_name_index).map(ToString::to_string),
            exe_path: get_col(&cols, exe_path_index).map(ToString::to_string),
            user_sid: get_col(&cols, user_sid_index).map(ToString::to_string),
            network_interface: get_col(&cols, interface_index).map(ToString::to_string),
            bytes_in: get_col(&cols, bytes_in_index).and_then(parse_u64_text),
            bytes_out: get_col(&cols, bytes_out_index).and_then(parse_u64_text),
            packets_in: get_col(&cols, packets_in_index).and_then(parse_u64_text),
            packets_out: get_col(&cols, packets_out_index).and_then(parse_u64_text),
        });
    }

    out
}

fn split_delimited_line(line: &str, delimiter: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cell = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cell.push('"');
                    let _ = chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            _ if ch == delimiter && !in_quotes => {
                out.push(cell.trim().to_string());
                cell.clear();
            }
            _ => cell.push(ch),
        }
    }
    out.push(cell.trim().to_string());
    out
}

fn header_index(headers: &[String], names: &[&str]) -> Option<usize> {
    headers.iter().position(|h| names.iter().any(|n| h == n))
}

fn get_col(cols: &[String], index: Option<usize>) -> Option<&str> {
    cols.get(index?).map(|v| v.trim()).filter(|v| !v.is_empty())
}

fn get_u64(map: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(value) = map.get(*key).and_then(parse_numeric_value_u64) {
            return Some(value);
        }
        if let Some((_, value)) = map.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
            if let Some(parsed) = parse_numeric_value_u64(value) {
                return Some(parsed);
            }
        }
    }
    None
}

fn get_string(map: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = map.get(*key).or_else(|| {
            map.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v)
        }) {
            let normalized = match value {
                Value::String(s) => Some(s.to_string()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            };
            if let Some(v) = normalized {
                return Some(v);
            }
        }
    }
    None
}

fn parse_numeric_value_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64().or_else(|| n.as_i64().map(|v| v.max(0) as u64)),
        Value::String(s) => parse_u64_text(s),
        _ => None,
    }
}

fn parse_u64_text(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    trimmed.replace(',', "").parse::<u64>().ok()
}

fn parse_timestamp_value(value: Option<&Value>) -> (Option<String>, Option<i64>, Option<String>) {
    match value {
        Some(Value::Number(n)) => {
            if let Some(v) = n.as_i64() {
                timestamp_from_numeric(v)
            } else if let Some(v) = n.as_u64() {
                timestamp_from_numeric(v as i64)
            } else {
                (None, None, None)
            }
        }
        Some(Value::String(s)) => parse_timestamp_str(Some(s)),
        _ => (None, None, None),
    }
}

fn parse_timestamp_str(value: Option<&str>) -> (Option<String>, Option<i64>, Option<String>) {
    let Some(raw) = value else {
        return (None, None, None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (None, None, None);
    }

    if let Ok(v) = trimmed.parse::<i64>() {
        return timestamp_from_numeric(v);
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        let utc = dt.with_timezone(&Utc).to_rfc3339();
        return (Some(utc), Some(dt.timestamp()), Some("rfc3339".to_string()));
    }

    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, fmt) {
            let utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
            return (
                Some(utc.to_rfc3339()),
                Some(utc.timestamp()),
                Some("naive_utc".to_string()),
            );
        }
    }

    (None, None, None)
}

fn timestamp_from_numeric(raw: i64) -> (Option<String>, Option<i64>, Option<String>) {
    let (unix, precision) = if (116_444_736_000_000_000..400_000_000_000_000_000).contains(&raw) {
        (
            (raw / 10_000_000) - 11_644_473_600,
            Some("filetime_100ns".to_string()),
        )
    } else if raw > 1_000_000_000_000_000_000 {
        (raw / 1_000_000_000, Some("unix_nanos".to_string()))
    } else if raw > 1_000_000_000_000_000 {
        (raw / 1_000_000, Some("unix_micros".to_string()))
    } else if raw > 4_000_000_000 {
        (raw / 1000, Some("unix_millis".to_string()))
    } else {
        (raw, Some("unix_seconds".to_string()))
    };

    if let Some(dt) = DateTime::<Utc>::from_timestamp(unix, 0) {
        (Some(dt.to_rfc3339()), Some(unix), precision)
    } else {
        (None, None, None)
    }
}

fn normalize_record(row: &mut SrumRecord) {
    row.provider = normalize_token(row.provider.take());
    row.record_type = normalize_token(row.record_type.take());
    row.app_id = normalize_token(row.app_id.take());
    row.app_name = normalize_token(row.app_name.take());
    row.network_interface = normalize_token(row.network_interface.take());
    row.user_sid = normalize_sid(row.user_sid.take());
    row.exe_path = normalize_windows_path(row.exe_path.take());

    if row.timestamp_utc.is_none() {
        if let Some(unix) = row.timestamp_unix {
            if let Some(dt) = DateTime::<Utc>::from_timestamp(unix, 0) {
                row.timestamp_utc = Some(dt.to_rfc3339());
            }
        }
    }
}

fn normalize_token(value: Option<String>) -> Option<String> {
    let v = value?;
    let trimmed = v.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_sid(value: Option<String>) -> Option<String> {
    let sid = normalize_token(value)?;
    if sid.to_ascii_lowercase().starts_with("s-") {
        Some(sid.to_ascii_uppercase())
    } else {
        Some(sid)
    }
}

fn normalize_windows_path(value: Option<String>) -> Option<String> {
    let path = normalize_token(value)?;
    let normalized = path.replace('/', "\\").trim_matches('"').to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn dedupe_records(rows: Vec<SrumRecord>) -> Vec<SrumRecord> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let key = dedupe_key(&row);
        if seen.insert(key) {
            out.push(row);
        }
    }
    out
}

fn dedupe_key(row: &SrumRecord) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        row.record_id
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        row.provider.as_deref().unwrap_or("-"),
        row.record_type.as_deref().unwrap_or("-"),
        row.timestamp_unix
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        row.app_id.as_deref().unwrap_or("-"),
        row.app_name.as_deref().unwrap_or("-"),
        row.exe_path.as_deref().unwrap_or("-"),
        row.user_sid.as_deref().unwrap_or("-"),
        row.bytes_in
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        row.bytes_out
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string())
    )
}

fn sort_records_newest_first(rows: &mut [SrumRecord]) {
    rows.sort_by(|a, b| {
        b.timestamp_unix
            .unwrap_or(i64::MIN)
            .cmp(&a.timestamp_unix.unwrap_or(i64::MIN))
            .then_with(|| a.record_id.cmp(&b.record_id))
            .then_with(|| a.app_name.cmp(&b.app_name))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_shape_identifies_raw_ese_signature() {
        let mut data = vec![0u8; 64];
        data[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
        assert_eq!(detect_srum_input_shape(&data), SrumInputShape::RawEse);
    }

    #[test]
    fn parse_srum_json_records_newest_first() {
        let data = br#"{
            "records": [
                {
                    "record_id": 41,
                    "provider_name": "network",
                    "usage_type": "network-usage",
                    "timestamp_utc": "2026-03-10T02:00:00Z",
                    "app_name": "chrome.exe",
                    "exe_path": "C:/Program Files/Google/Chrome/Application/chrome.exe",
                    "user_sid": "s-1-5-21-1000",
                    "bytes_in": 512,
                    "bytes_out": 1024
                },
                {
                    "record_id": 42,
                    "provider_name": "network",
                    "usage_type": "network-usage",
                    "timestamp_unix": 1773111600,
                    "app_name": "teams.exe",
                    "bytes_in": 2048,
                    "bytes_out": 4096
                }
            ]
        }"#;

        let parsed = parse_srum_records_with_metadata(data);
        let rows = parsed.records;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].record_id, Some(42));
        assert_eq!(rows[0].app_name.as_deref(), Some("teams.exe"));
        assert_eq!(rows[1].record_id, Some(41));
        assert_eq!(rows[1].bytes_out, Some(1024));
        assert_eq!(
            rows[1].exe_path.as_deref(),
            Some("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
        );
        assert_eq!(rows[1].user_sid.as_deref(), Some("S-1-5-21-1000"));
        assert_eq!(parsed.metadata.input_shape, "json");
        assert_eq!(parsed.metadata.parser_mode, "json");
    }

    #[test]
    fn parse_srum_csv_records() {
        let data =
            b"record_id,timestamp_utc,provider,record_type,app_name,user_sid,bytes_in,bytes_out\n\
41,2026-03-10T01:00:00Z,network,network-usage,chrome.exe,S-1-5-21-1000,12,34\n";

        let parsed = parse_srum_records_with_metadata(data);
        let rows = parsed.records;
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.record_id, Some(41));
        assert_eq!(row.provider.as_deref(), Some("network"));
        assert_eq!(row.record_type.as_deref(), Some("network-usage"));
        assert_eq!(row.app_name.as_deref(), Some("chrome.exe"));
        assert_eq!(row.bytes_in, Some(12));
        assert_eq!(row.bytes_out, Some(34));
        assert_eq!(row.user_sid.as_deref(), Some("S-1-5-21-1000"));
        assert_eq!(parsed.metadata.input_shape, "csv");
        assert_eq!(parsed.metadata.parser_mode, "csv");
    }

    #[test]
    fn parse_srum_json_nested_data_rows_with_aliases() {
        let data = br#"{
            "data": {
                "results": [
                    {
                        "RecordId": "0x2A",
                        "provider_id": "SRU-NET",
                        "event_category": "network",
                        "occurred_utc": "2026-03-11T10:30:00Z",
                        "app_guid": "APP-1",
                        "application": "edge.exe",
                        "fullpath": "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
                        "usersid": "s-1-5-21-1001",
                        "interface_name": "Wi-Fi",
                        "rx_bytes": "1,024",
                        "tx_bytes": "2048",
                        "rx_packets": 8,
                        "tx_packets": 9
                    }
                ]
            }
        }"#;

        let parsed = parse_srum_records_with_metadata(data);
        assert_eq!(parsed.records.len(), 1);
        let row = &parsed.records[0];
        assert_eq!(row.record_id, Some(42));
        assert_eq!(row.provider.as_deref(), Some("SRU-NET"));
        assert_eq!(row.record_type.as_deref(), Some("network"));
        assert_eq!(row.app_id.as_deref(), Some("APP-1"));
        assert_eq!(row.app_name.as_deref(), Some("edge.exe"));
        assert_eq!(
            row.exe_path.as_deref(),
            Some("C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe")
        );
        assert_eq!(row.user_sid.as_deref(), Some("S-1-5-21-1001"));
        assert_eq!(row.network_interface.as_deref(), Some("Wi-Fi"));
        assert_eq!(row.bytes_in, Some(1024));
        assert_eq!(row.bytes_out, Some(2048));
        assert_eq!(row.packets_in, Some(8));
        assert_eq!(row.packets_out, Some(9));
        assert_eq!(parsed.metadata.parser_mode, "json");
    }

    #[test]
    fn parse_srum_csv_supports_pipe_and_quoted_commas() {
        let data = b"record_id|timestamp|provider|record_type|app_name|exe_path|bytes_in|bytes_out\n\
0x2A|2026-03-11 10:30:00|network|usage|edge.exe|\"C:/Users/Analyst/My, Folder/edge.exe\"|1024|2048\n";

        let parsed = parse_srum_records_with_metadata(data);
        assert_eq!(parsed.records.len(), 1);
        let row = &parsed.records[0];
        assert_eq!(row.record_id, Some(42));
        assert_eq!(row.provider.as_deref(), Some("network"));
        assert_eq!(
            row.exe_path.as_deref(),
            Some("C:\\Users\\Analyst\\My, Folder\\edge.exe")
        );
        assert_eq!(row.bytes_in, Some(1024));
        assert_eq!(row.bytes_out, Some(2048));
        assert!(row.timestamp_unix.is_some());
    }

    #[test]
    fn parse_srum_timestamps_handle_micro_and_nano_inputs() {
        let data = br#"[
            {"record_id": 1, "timestamp_unix": 1773111600000000, "app_name": "a.exe"},
            {"record_id": 2, "time_unix": 1773111600000000000, "app_name": "b.exe"}
        ]"#;

        let parsed = parse_srum_records_with_metadata(data);
        assert_eq!(parsed.records.len(), 2);
        assert!(parsed
            .records
            .iter()
            .all(|row| row.timestamp_unix == Some(1_773_111_600)));
        assert!(parsed
            .records
            .iter()
            .any(|row| row.timestamp_precision.as_deref() == Some("unix_micros")));
        assert!(parsed
            .records
            .iter()
            .any(|row| row.timestamp_precision.as_deref() == Some("unix_nanos")));
    }

    #[test]
    fn parse_srum_dedupe_collapses_duplicate_rows() {
        let data = br#"{
            "records": [
                {"record_id": 1, "timestamp_unix": 100, "app_name": "a.exe", "bytes_in": 10, "bytes_out": 20},
                {"record_id": 1, "timestamp_unix": 100, "app_name": "a.exe", "bytes_in": 10, "bytes_out": 20}
            ]
        }"#;
        let parsed = parse_srum_records_with_metadata(data);
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.metadata.deduped_count, 1);
    }

    #[test]
    fn parse_srum_invalid_input_returns_empty() {
        let parsed = parse_srum_records_with_metadata(b"\x00\x01\xffnot-json-not-csv");
        assert!(parsed.records.is_empty());
        assert!(parsed
            .metadata
            .quality_flags
            .iter()
            .any(|f| f == "no_records_parsed"));
    }
}
