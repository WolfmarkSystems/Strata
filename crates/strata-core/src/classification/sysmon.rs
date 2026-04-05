use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use std::env;
use std::path::PathBuf;

pub fn get_sysmon_logs() -> Vec<SysmonEvent> {
    let path = env::var("FORENSIC_SYSMON_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("logs").join("sysmon.log"));
    let content = match read_text_prefix(&path, DEFAULT_TEXT_MAX_BYTES * 2) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    parse_sysmon_log_lines(&content)
}

pub fn parse_sysmon_log_lines(content: &str) -> Vec<SysmonEvent> {
    let mut out = Vec::new();
    let mut current_event_id: Option<u32> = None;
    let mut current_ts: Option<u64> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if let (Some(event_id), Some(timestamp)) = (current_event_id.take(), current_ts.take())
            {
                out.push(SysmonEvent {
                    event_id,
                    timestamp,
                });
            }
            continue;
        }

        if let Some(v) = parse_sysmon_event_id(trimmed) {
            current_event_id = Some(v);
        }
        if let Some(v) = parse_sysmon_timestamp(trimmed) {
            current_ts = Some(v);
        }

        // Pipe/comma one-line fallback: event_id|timestamp
        if trimmed.contains('|') || trimmed.contains(',') {
            let parts: Vec<&str> = if trimmed.contains('|') {
                trimmed.split('|').collect()
            } else {
                trimmed.split(',').collect()
            };
            if parts.len() >= 2 {
                if let (Ok(event_id), Ok(timestamp)) = (
                    parts[0].trim().parse::<u32>(),
                    parts[1].trim().parse::<u64>(),
                ) {
                    out.push(SysmonEvent {
                        event_id,
                        timestamp,
                    });
                }
            }
        }
    }

    if let (Some(event_id), Some(timestamp)) = (current_event_id, current_ts) {
        out.push(SysmonEvent {
            event_id,
            timestamp,
        });
    }

    out
}

fn parse_sysmon_event_id(line: &str) -> Option<u32> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("event id") {
        if let Some((_, rhs)) = line.split_once(':') {
            return rhs.trim().parse::<u32>().ok();
        }
    }
    if lower.contains("\"eventid\"") {
        return extract_number_token(line).and_then(|v| v.parse::<u32>().ok());
    }
    None
}

fn parse_sysmon_timestamp(line: &str) -> Option<u64> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("utc time") || lower.contains("utctime") || lower.contains("timestamp") {
        if let Some((_, rhs)) = line.split_once(':') {
            return parse_unix_or_iso(rhs.trim());
        }
    }
    if lower.contains("\"utctime\"") || lower.contains("\"timestamp\"") {
        return extract_quoted_or_number(line).and_then(parse_unix_or_iso);
    }
    None
}

fn parse_unix_or_iso(value: &str) -> Option<u64> {
    value
        .trim_matches('"')
        .parse::<u64>()
        .ok()
        .or_else(|| parse_iso8601_to_unix(value.trim_matches('"')))
}

fn extract_number_token(line: &str) -> Option<String> {
    line.split(|c: char| !c.is_ascii_digit())
        .find(|p| !p.is_empty())
        .map(|s| s.to_string())
}

fn extract_quoted_or_number(line: &str) -> Option<&str> {
    if let Some(start) = line.find('"') {
        let rest = &line[start + 1..];
        if let Some(end) = rest.find('"') {
            let s = &rest[..end];
            if !s.is_empty() && s.chars().next().unwrap_or(' ').is_ascii_digit() {
                return Some(s);
            }
        }
    }
    line.split(|c: char| c.is_whitespace() || c == ':' || c == ',')
        .find(|p| !p.is_empty() && p.chars().next().unwrap_or(' ').is_ascii_digit())
}

fn parse_iso8601_to_unix(raw: &str) -> Option<u64> {
    let normalized = raw.trim().trim_end_matches('Z').replace('T', " ");
    let mut it = normalized.split(' ');
    let date = it.next()?;
    let time = it.next()?;
    let d: Vec<&str> = date.split('-').collect();
    let t: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || t.len() < 2 {
        return None;
    }
    let year = d[0].parse::<i32>().ok()?;
    let month = d[1].parse::<u32>().ok()?;
    let day = d[2].parse::<u32>().ok()?;
    let hour = t[0].parse::<u32>().ok()?;
    let minute = t[1].parse::<u32>().ok()?;
    let second = t.get(2).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    unix_from_ymd_hms(year, month, day, hour, minute, second)
}

fn unix_from_ymd_hms(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u64> {
    if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let y = year - ((month <= 2) as i32);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i32;
    let d = day as i32;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days as i64 * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64;
    if secs < 0 {
        None
    } else {
        Some(secs as u64)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SysmonEvent {
    pub event_id: u32,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_sysmon_block() {
        let content = r#"
Event ID: 1
UtcTime: 2026-03-08T01:02:03Z

Event ID: 3
UtcTime: 1710000000
"#;
        let rows = parse_sysmon_log_lines(content);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].event_id, 1);
        assert_eq!(rows[1].event_id, 3);
    }
}
