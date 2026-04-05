use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_sccm_clients() -> Vec<SccmClient> {
    let Some(items) = load(path("FORENSIC_SCCM_CLIENTS", "sccm_clients.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SccmClient {
            hostname: s(&v, &["hostname", "name"]),
            client_id: s(&v, &["client_id", "id"]),
            last_heartbeat: n(&v, &["last_heartbeat"]),
            site_code: s(&v, &["site_code"]),
            active: b(&v, &["active"]),
        })
        .filter(|x| !x.client_id.is_empty() || !x.hostname.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SccmClient {
    pub hostname: String,
    pub client_id: String,
    pub last_heartbeat: u64,
    pub site_code: String,
    pub active: bool,
}

pub fn get_sccm_software_deployments() -> Vec<SoftwareDeployment> {
    let Some(items) = load(path(
        "FORENSIC_SCCM_DEPLOYMENTS",
        "sccm_software_deployments.json",
    )) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SoftwareDeployment {
            package_id: s(&v, &["package_id"]),
            package_name: s(&v, &["package_name", "name"]),
            target_machines: sa(&v, &["target_machines", "targets"]),
            status: s(&v, &["status"]),
            start_time: n(&v, &["start_time"]),
        })
        .filter(|x| !x.package_id.is_empty() || !x.package_name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SoftwareDeployment {
    pub package_id: String,
    pub package_name: String,
    pub target_machines: Vec<String>,
    pub status: String,
    pub start_time: u64,
}

pub fn get_sccm_collections() -> Vec<SccmCollection> {
    let Some(items) = load(path("FORENSIC_SCCM_COLLECTIONS", "sccm_collections.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SccmCollection {
            collection_id: s(&v, &["collection_id", "id"]),
            name: s(&v, &["name"]),
            member_count: n(&v, &["member_count", "count"]) as u32,
            collection_type: s(&v, &["collection_type", "type"]),
        })
        .filter(|x| !x.collection_id.is_empty() || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SccmCollection {
    pub collection_id: String,
    pub name: String,
    pub member_count: u32,
    pub collection_type: String,
}

pub fn get_sccm_task_sequence() -> Vec<TaskSequence> {
    let Some(items) = load(path("FORENSIC_SCCM_TASKSEQ", "sccm_task_sequence.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| TaskSequence {
            package_id: s(&v, &["package_id"]),
            name: s(&v, &["name"]),
            steps: sa(&v, &["steps"]),
        })
        .filter(|x| !x.package_id.is_empty() || !x.name.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TaskSequence {
    pub package_id: String,
    pub name: String,
    pub steps: Vec<String>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("sccm").join(file))
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
fn sa(v: &Value, keys: &[&str]) -> Vec<String> {
    for k in keys {
        if let Some(arr) = v.get(*k).and_then(Value::as_array) {
            return arr
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
        }
    }
    Vec::new()
}
