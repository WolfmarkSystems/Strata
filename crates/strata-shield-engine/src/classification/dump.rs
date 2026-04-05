use crate::errors::ForensicError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct DumpFile {
    pub dump_type: DumpType,
    pub process_id: Option<u32>,
    pub timestamp: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Default)]
pub enum DumpType {
    #[default]
    Full,
    Mini,
    Kernel,
    Active,
}

pub fn detect_dump_file(data: &[u8]) -> Option<DumpType> {
    if data.starts_with(b"PAGE") {
        return Some(DumpType::Kernel);
    }
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        let t = s(&v, &["dump_type", "type"]);
        return Some(dump_type_enum(t));
    }
    None
}

pub fn parse_dump_header(data: &[u8]) -> Result<DumpHeader, ForensicError> {
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        return Ok(DumpHeader {
            dump_type: dump_type_enum(s(&v, &["dump_type", "type"])),
            machine_type: n(&v, &["machine_type"]) as u16,
            timestamp: n(&v, &["timestamp", "time"]),
            flags: n(&v, &["flags"]) as u32,
        });
    }
    Ok(DumpHeader {
        dump_type: detect_dump_file(data).unwrap_or(DumpType::Mini),
        machine_type: 0,
        timestamp: 0,
        flags: 0,
    })
}

#[derive(Debug, Clone, Default)]
pub struct DumpHeader {
    pub dump_type: DumpType,
    pub machine_type: u16,
    pub timestamp: u64,
    pub flags: u32,
}

pub fn extract_dump_processes(data: &[u8]) -> Result<Vec<DumpProcess>, ForensicError> {
    let Ok(v) = serde_json::from_slice::<Value>(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("processes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| DumpProcess {
            name: s(&x, &["name"]),
            pid: n(&x, &["pid"]) as u32,
            threads: n(&x, &["threads", "thread_count"]) as u32,
        })
        .filter(|x| !x.name.is_empty() || x.pid > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct DumpProcess {
    pub name: String,
    pub pid: u32,
    pub threads: u32,
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
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return x as u64;
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

fn dump_type_enum(value: String) -> DumpType {
    match value.to_ascii_lowercase().as_str() {
        "full" => DumpType::Full,
        "kernel" => DumpType::Kernel,
        "active" => DumpType::Active,
        _ => DumpType::Mini,
    }
}
