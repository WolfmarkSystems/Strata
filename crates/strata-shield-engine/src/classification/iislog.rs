use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use std::env;
use std::path::PathBuf;

pub fn get_iis_logs() -> Vec<IisLog> {
    let path = env::var("FORENSIC_IIS_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("iis").join("u_ex.log"));
    let content = match read_text_prefix(&path, DEFAULT_TEXT_MAX_BYTES * 2) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    parse_iis_log_text(&content)
}

pub fn parse_iis_log_text(content: &str) -> Vec<IisLog> {
    let mut fields: Vec<String> = Vec::new();
    let mut out = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("#Fields:") {
            fields = trimmed
                .trim_start_matches("#Fields:")
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            continue;
        }
        if trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let ts = parse_w3c_time(&fields, &parts).unwrap_or(0);
        let client_ip = extract_field(&fields, &parts, "c-ip").unwrap_or_default();
        let stem = extract_field(&fields, &parts, "cs-uri-stem").unwrap_or_default();
        let query = extract_field(&fields, &parts, "cs-uri-query").unwrap_or_default();
        let uri = if !query.is_empty() && query != "-" {
            format!("{stem}?{query}")
        } else {
            stem
        };

        out.push(IisLog {
            timestamp: ts,
            client_ip,
            uri,
        });
    }

    out
}

fn extract_field(fields: &[String], parts: &[&str], key: &str) -> Option<String> {
    let idx = fields.iter().position(|f| f.eq_ignore_ascii_case(key))?;
    Some(parts.get(idx)?.to_string())
}

fn parse_w3c_time(fields: &[String], parts: &[&str]) -> Option<u64> {
    let date = extract_field(fields, parts, "date")?;
    let time = extract_field(fields, parts, "time")?;
    let d: Vec<&str> = date.split('-').collect();
    let t: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || t.len() != 3 {
        return None;
    }
    let year = d[0].parse::<i32>().ok()?;
    let month = d[1].parse::<u32>().ok()?;
    let day = d[2].parse::<u32>().ok()?;
    let hour = t[0].parse::<u32>().ok()?;
    let minute = t[1].parse::<u32>().ok()?;
    let second = t[2].parse::<u32>().ok()?;
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
pub struct IisLog {
    pub timestamp: u64,
    pub client_ip: String,
    pub uri: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_w3c_iis_line() {
        let data = r#"
#Fields: date time c-ip cs-uri-stem cs-uri-query
2026-03-08 12:00:01 10.0.0.5 /owa/auth/logon.aspx -
"#;
        let rows = parse_iis_log_text(data);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].client_ip, "10.0.0.5");
        assert!(rows[0].uri.contains("/owa/auth/logon.aspx"));
    }
}
