use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_vscode_workspaces() -> Vec<VscodeWorkspace> {
    let Some(items) = load(path("FORENSIC_VSCODE_WORKSPACES", "vscode_workspaces.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| VscodeWorkspace {
            path: s(&v, &["path"]),
            name: s(&v, &["name"]),
            last_opened: n(&v, &["last_opened"]),
            files_opened: n(&v, &["files_opened"]) as u32,
        })
        .filter(|x| !x.path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct VscodeWorkspace {
    pub path: String,
    pub name: String,
    pub last_opened: u64,
    pub files_opened: u32,
}

pub fn get_vscode_extensions() -> Vec<VscodeExtension> {
    let Some(items) = load(path("FORENSIC_VSCODE_EXTENSIONS", "vscode_extensions.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| VscodeExtension {
            id: s(&v, &["id"]),
            name: s(&v, &["name"]),
            version: s(&v, &["version"]),
            installed: n(&v, &["installed"]),
            enabled: b(&v, &["enabled"]),
        })
        .filter(|x| !x.id.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct VscodeExtension {
    pub id: String,
    pub name: String,
    pub version: String,
    pub installed: u64,
    pub enabled: bool,
}

pub fn get_vscode_settings() -> Vec<VscodeSettings> {
    let Some(items) = load(path("FORENSIC_VSCODE_SETTINGS", "vscode_settings.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| VscodeSettings {
            key: s(&v, &["key"]),
            value: s(&v, &["value"]),
            source: s(&v, &["source"]),
        })
        .filter(|x| !x.key.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct VscodeSettings {
    pub key: String,
    pub value: String,
    pub source: String,
}

pub fn get_vscode_sync() -> Vec<VscodeSync> {
    let Some(items) = load(path("FORENSIC_VSCODE_SYNC", "vscode_sync.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| VscodeSync {
            setting: s(&v, &["setting", "key"]),
            synced: n(&v, &["synced", "timestamp"]),
            synced_from: s(&v, &["synced_from", "source"]),
        })
        .filter(|x| !x.setting.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct VscodeSync {
    pub setting: String,
    pub synced: u64,
    pub synced_from: String,
}

pub fn get_vscode_terminals() -> Vec<VscodeTerminal> {
    let Some(items) = load(path("FORENSIC_VSCODE_TERMINALS", "vscode_terminals.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| VscodeTerminal {
            workspace: s(&v, &["workspace"]),
            shell: s(&v, &["shell"]),
            commands: sa(&v, &["commands"]),
        })
        .filter(|x| !x.workspace.is_empty() || !x.shell.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct VscodeTerminal {
    pub workspace: String,
    pub shell: String,
    pub commands: Vec<String>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("vscode").join(file))
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
