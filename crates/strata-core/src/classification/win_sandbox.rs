use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_sandbox_state() -> Vec<SandboxState> {
    let Some(items) = load(path("FORENSIC_SANDBOX_STATE", "state.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SandboxState {
            started: n(&v, &["started", "started_at"]),
            user: s(&v, &["user"]),
            memory_limit: n(&v, &["memory_limit", "memory_mb"]),
            networking: s(&v, &["networking"]),
        })
        .filter(|x| x.started > 0 || !x.user.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SandboxState {
    pub started: u64,
    pub user: String,
    pub memory_limit: u64,
    pub networking: String,
}

pub fn get_sandbox_files() -> Vec<SandboxFile> {
    let Some(items) = load(path("FORENSIC_SANDBOX_FILES", "files.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SandboxFile {
            path: s(&v, &["path"]),
            size: n(&v, &["size"]),
            shared_from_host: b(&v, &["shared_from_host", "from_host"]),
        })
        .filter(|x| !x.path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SandboxFile {
    pub path: String,
    pub size: u64,
    pub shared_from_host: bool,
}

pub fn get_sandbox_processes() -> Vec<SandboxProcess> {
    let Some(items) = load(path("FORENSIC_SANDBOX_PROCESSES", "processes.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SandboxProcess {
            pid: n(&v, &["pid"]) as u32,
            name: s(&v, &["name", "process_name"]),
            parent_pid: n(&v, &["parent_pid", "ppid"]) as u32,
            start_time: n(&v, &["start_time", "started"]),
        })
        .filter(|x| x.pid > 0 || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SandboxProcess {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub start_time: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("win_sandbox").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data)
        .ok()?
        .as_array()
        .cloned()
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

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}
