use std::path::{Path, PathBuf};

use serde_json::Value;

use super::scalpel::{
    read_prefix, read_text_prefix, DEFAULT_BINARY_MAX_BYTES, DEFAULT_TEXT_MAX_BYTES,
};
use super::scheduledtasks;
use crate::errors::ForensicError;

pub fn get_scheduled_tasks_xml(path: &str) -> Result<Vec<TaskXml>, ForensicError> {
    let task_path = PathBuf::from(path);
    if path.trim().is_empty() || !task_path.exists() {
        return Ok(Vec::new());
    }

    if task_path.is_dir() {
        let tasks = scheduledtasks::parse_scheduled_tasks_xml(&task_path)?;
        return Ok(tasks
            .into_iter()
            .map(|t| TaskXml {
                name: t.name,
                action: format_action(&t.actions),
            })
            .collect());
    }

    if is_json(&task_path) {
        return Ok(parse_json_taskxml(&task_path));
    }

    if is_xml(&task_path) {
        return Ok(parse_single_xml_task(&task_path));
    }

    Ok(Vec::new())
}

#[derive(Debug, Clone, Default)]
pub struct TaskXml {
    pub name: String,
    pub action: String,
}

fn is_xml(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("xml"))
        .unwrap_or(false)
}

fn is_json(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}

fn parse_json_taskxml(path: &Path) -> Vec<TaskXml> {
    let data = match read_prefix(path, DEFAULT_BINARY_MAX_BYTES) {
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
            .map(|v| TaskXml {
                name: s(v, &["name", "task_name"]),
                action: s(v, &["action", "command"]),
            })
            .filter(|x| !x.name.is_empty() || !x.action.is_empty())
            .collect();
    }
    if json.is_object() {
        let row = TaskXml {
            name: s(&json, &["name", "task_name"]),
            action: s(&json, &["action", "command"]),
        };
        if !row.name.is_empty() || !row.action.is_empty() {
            return vec![row];
        }
    }
    Vec::new()
}

fn parse_single_xml_task(path: &Path) -> Vec<TaskXml> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let name = path
        .file_stem()
        .and_then(|n| n.to_str())
        .map(ToString::to_string)
        .unwrap_or_default();

    let action = extract_tag(&content, "Command")
        .or_else(|| extract_tag(&content, "ComObject"))
        .or_else(|| extract_tag(&content, "Arguments"))
        .unwrap_or_default();

    if name.is_empty() && action.is_empty() {
        Vec::new()
    } else {
        vec![TaskXml { name, action }]
    }
}

fn extract_tag(content: &str, tag: &str) -> Option<String> {
    let start = format!("<{}>", tag);
    let end = format!("</{}>", tag);
    let from = content.find(&start)? + start.len();
    let to = content[from..].find(&end)? + from;
    Some(content[from..to].trim().to_string())
}

fn format_action(actions: &[scheduledtasks::TaskAction]) -> String {
    let mut out = Vec::new();
    for action in actions {
        match action.action_type {
            scheduledtasks::ActionType::Execute => {
                let path = action.path.clone().unwrap_or_default();
                let args = action.arguments.clone().unwrap_or_default();
                let combined = if args.is_empty() {
                    path
                } else if path.is_empty() {
                    args
                } else {
                    format!("{} {}", path, args)
                };
                if !combined.is_empty() {
                    out.push(combined);
                }
            }
            scheduledtasks::ActionType::ComObject => {
                if let Some(path) = &action.path {
                    out.push(format!("COM:{}", path));
                }
            }
            scheduledtasks::ActionType::Unknown => {}
        }
    }
    out.join(" | ")
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}
