use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_powershell_transcript_paths() -> Vec<String> {
    let path = path("FORENSIC_POWERSHELL_TRANSCRIPTS", "transcripts.json");
    let data = match super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    if let Some(items) = json.as_array() {
        return items
            .iter()
            .filter_map(|x| {
                if let Some(s) = x.as_str() {
                    Some(s.to_string())
                } else {
                    x.get("path")
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                }
            })
            .collect();
    }
    Vec::new()
}

pub fn parse_powershell_events() -> Vec<PowerShellEvent> {
    parse_powershell_events_file(&path("FORENSIC_POWERSHELL_EVENTS", "ps_events.json"))
}

pub fn parse_powershell_events_file(path: &std::path::Path) -> Vec<PowerShellEvent> {
    let mut events = if let Some(items) = load(path.to_path_buf()) {
        items
            .into_iter()
            .map(|v| PowerShellEvent {
                timestamp: n(&v, &["timestamp", "time_created", "occurred_utc"]),
                script: s(&v, &["script", "command", "script_block_text"]),
            })
            .filter(|x| x.timestamp > 0 || !x.script.is_empty())
            .collect::<Vec<_>>()
    } else {
        parse_line_fallback(path)
    };
    events.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| a.script.cmp(&b.script))
    });
    events
}

#[derive(Debug, Clone, Default)]
pub struct PowerShellEvent {
    pub timestamp: u64,
    pub script: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("powershell").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let json: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = json.as_array() {
        Some(items.clone())
    } else if let Some(items) = json.get("records").and_then(Value::as_array) {
        Some(items.clone())
    } else if let Some(items) = json.get("events").and_then(Value::as_array) {
        Some(items.clone())
    } else if let Some(items) = json.get("items").and_then(Value::as_array) {
        Some(items.clone())
    } else if json.is_object() {
        Some(vec![json])
    } else {
        None
    }
}

fn parse_line_fallback(path: &std::path::Path) -> Vec<PowerShellEvent> {
    let Ok(content) =
        super::scalpel::read_text_prefix(path, super::scalpel::DEFAULT_TEXT_MAX_BYTES)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = if trimmed.contains('|') {
            trimmed.split('|').collect()
        } else {
            trimmed.split(',').collect()
        };
        let timestamp = parts
            .first()
            .copied()
            .map(parse_timestamp)
            .unwrap_or_default();
        let script = if parts.len() >= 2 {
            parts[1..].join("|").trim().to_string()
        } else {
            trimmed.to_string()
        };
        if timestamp > 0 || !script.is_empty() {
            out.push(PowerShellEvent { timestamp, script });
        }
    }
    out
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            let parsed = parse_timestamp(x);
            if parsed > 0 {
                return parsed;
            }
        }
    }
    0
}

fn parse_timestamp(value: &str) -> u64 {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return 0;
    }
    if let Ok(n) = trimmed.parse::<u64>() {
        return n;
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        let unix = dt.timestamp();
        if unix > 0 {
            return unix as u64;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::parse_powershell_events_file;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("forensic_suite_{name}_{unique}"))
    }

    #[test]
    fn parse_events_json_records_shape_and_rfc3339() {
        let root = temp_dir("ps_events_json");
        strata_fs::create_dir_all(&root).unwrap();
        let input = root.join("ps_events.json");
        strata_fs::write(
            &input,
            r#"{"records":[{"occurred_utc":"2026-03-11T14:00:00Z","script":"powershell.exe -enc AAAA"}]}"#,
        )
        .unwrap();

        let rows = parse_powershell_events_file(&input);
        assert_eq!(rows.len(), 1, "expected one parsed row");
        assert!(
            rows[0].timestamp > 0,
            "rfc3339 timestamps should normalize to unix"
        );
        assert!(rows[0].script.contains("powershell.exe"));

        let _ = strata_fs::remove_dir_all(root);
    }

    #[test]
    fn parse_events_line_fallback_accepts_pipe_format() {
        let root = temp_dir("ps_events_fallback");
        strata_fs::create_dir_all(&root).unwrap();
        let input = root.join("ps_events.log");
        strata_fs::write(
            &input,
            "1700000000|C:\\Windows\\System32\\cmd.exe /c whoami\n",
        )
        .unwrap();

        let rows = parse_powershell_events_file(&input);
        assert_eq!(rows.len(), 1, "expected one fallback row");
        assert_eq!(rows[0].timestamp, 1_700_000_000);
        assert!(rows[0].script.contains("whoami"));

        let _ = strata_fs::remove_dir_all(root);
    }
}
