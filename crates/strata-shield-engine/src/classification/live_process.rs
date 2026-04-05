use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_running_processes() -> Vec<LiveProcess> {
    let Some(items) = load(path("FORENSIC_LIVE_PROCESSES", "processes.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| LiveProcess {
            pid: n(&v, &["pid"]) as u32,
            name: s(&v, &["name", "process_name"]),
            path: s(&v, &["path", "image_path"]),
            command_line: s(&v, &["command_line", "cmdline"]),
            start_time: n(&v, &["start_time", "started"]),
            parent_pid: n(&v, &["parent_pid", "ppid"]) as u32,
            user: s(&v, &["user", "username"]),
        })
        .filter(|x| x.pid > 0 || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LiveProcess {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub start_time: u64,
    pub parent_pid: u32,
    pub user: String,
}

pub fn get_network_connections() -> Vec<NetworkConnection> {
    let Some(items) = load(path(
        "FORENSIC_LIVE_NET_CONNECTIONS",
        "net_connections.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| NetworkConnection {
            pid: n(&v, &["pid"]) as u32,
            protocol: s(&v, &["protocol"]),
            local_addr: s(&v, &["local_addr", "local_address"]),
            remote_addr: s(&v, &["remote_addr", "remote_address"]),
            state: s(&v, &["state"]),
        })
        .filter(|x| x.pid > 0 || !x.local_addr.is_empty() || !x.remote_addr.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct NetworkConnection {
    pub pid: u32,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
}

pub fn get_loaded_dlls() -> Vec<LoadedDll> {
    let Some(items) = load(path("FORENSIC_LIVE_LOADED_DLLS", "loaded_dlls.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| LoadedDll {
            pid: n(&v, &["pid"]) as u32,
            name: s(&v, &["name", "dll_name"]),
            path: s(&v, &["path", "dll_path"]),
            base_address: n(&v, &["base_address", "address"]),
        })
        .filter(|x| !x.name.is_empty() || !x.path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct LoadedDll {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub base_address: u64,
}

pub fn get_open_handles() -> Vec<OpenHandle> {
    let Some(items) = load(path("FORENSIC_LIVE_OPEN_HANDLES", "open_handles.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| OpenHandle {
            pid: n(&v, &["pid"]) as u32,
            handle_type: s(&v, &["handle_type", "type"]),
            name: s(&v, &["name", "object_name"]),
        })
        .filter(|x| x.pid > 0 || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct OpenHandle {
    pub pid: u32,
    pub handle_type: String,
    pub name: String,
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
