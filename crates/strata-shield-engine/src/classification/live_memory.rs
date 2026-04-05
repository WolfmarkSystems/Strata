use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_memory_regions() -> Vec<MemoryRegion> {
    let Some(items) = load(path("FORENSIC_LIVE_MEMORY_REGIONS", "memory_regions.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| MemoryRegion {
            pid: n(&v, &["pid"]) as u32,
            start: n(&v, &["start", "start_address"]),
            end: n(&v, &["end", "end_address"]),
            protection: s(&v, &["protection"]),
            type_: s(&v, &["type_", "type"]),
        })
        .filter(|x| x.pid > 0 || x.start > 0 || x.end > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct MemoryRegion {
    pub pid: u32,
    pub start: u64,
    pub end: u64,
    pub protection: String,
    pub type_: String,
}

pub fn scan_memory_patterns() -> Vec<MemoryPattern> {
    let Some(items) = load(path(
        "FORENSIC_LIVE_MEMORY_PATTERNS",
        "memory_patterns.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| MemoryPattern {
            pid: n(&v, &["pid"]) as u32,
            address: n(&v, &["address"]),
            pattern: bytes(&v, &["pattern", "bytes"]),
            context: s(&v, &["context"]),
        })
        .filter(|x| x.pid > 0 || x.address > 0 || !x.pattern.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct MemoryPattern {
    pub pid: u32,
    pub address: u64,
    pub pattern: Vec<u8>,
    pub context: String,
}

pub fn extract_memory_strings() -> Vec<MemoryString> {
    let Some(items) = load(path("FORENSIC_LIVE_MEMORY_STRINGS", "memory_strings.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| MemoryString {
            pid: n(&v, &["pid"]) as u32,
            address: n(&v, &["address"]),
            string: s(&v, &["string", "value"]),
            encoding: s(&v, &["encoding"]),
        })
        .filter(|x| !x.string.is_empty() || x.address > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct MemoryString {
    pub pid: u32,
    pub address: u64,
    pub string: String,
    pub encoding: String,
}

pub fn find_injected_code() -> Vec<InjectedCode> {
    let Some(items) = load(path("FORENSIC_LIVE_INJECTED_CODE", "injected_code.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| InjectedCode {
            pid: n(&v, &["pid"]) as u32,
            address: n(&v, &["address"]),
            size: n(&v, &["size"]),
            code_type: s(&v, &["code_type", "type"]),
        })
        .filter(|x| x.pid > 0 || x.address > 0 || x.size > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct InjectedCode {
    pub pid: u32,
    pub address: u64,
    pub size: u64,
    pub code_type: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("live").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
}

fn bytes(v: &Value, keys: &[&str]) -> Vec<u8> {
    for k in keys {
        if let Some(items) = v.get(*k).and_then(Value::as_array) {
            return items
                .iter()
                .filter_map(Value::as_u64)
                .filter_map(|n| u8::try_from(n).ok())
                .collect();
        }
    }
    Vec::new()
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
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}
