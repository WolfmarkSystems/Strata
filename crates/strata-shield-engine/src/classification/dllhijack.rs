use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_dll_hijacking() -> Vec<DllHijack> {
    let Some(items) = load(path("FORENSIC_DLL_HIJACK", "dll_hijack.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| DllHijack {
            process: s(&v, &["process", "process_name"]),
            path: s(&v, &["path", "dll_path"]),
        })
        .filter(|x| !x.process.is_empty() || !x.path.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DllHijack {
    pub process: String,
    pub path: String,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("execution").join(file))
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
