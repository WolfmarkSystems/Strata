use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct TroubleshootingHistory {
    pub troublehooter_name: String,
    pub description: String,
    pub run_date: u64,
    pub result: TroubleshootingResult,
    pub log_path: String,
}

#[derive(Debug, Clone, Default)]
pub enum TroubleshootingResult {
    #[default]
    Unknown,
    NotResolved,
    Resolved,
    ResolvedWithRestart,
    ResolvedProgram,
    Unresolved,
}

pub fn get_troubleshooting_history() -> Result<Vec<TroubleshootingHistory>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_TROUBLESHOOTING_HISTORY",
        "troubleshooting_history.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| TroubleshootingHistory {
            troublehooter_name: s(&v, &["troublehooter_name", "name"]),
            description: s(&v, &["description"]),
            run_date: n(&v, &["run_date", "timestamp"]),
            result: result_enum(s(&v, &["result", "status"])),
            log_path: s(&v, &["log_path", "path"]),
        })
        .filter(|x| !x.troublehooter_name.is_empty() || x.run_date > 0)
        .collect())
}

pub fn get_diagnostic_logs() -> Result<Vec<DiagnosticLog>, ForensicError> {
    let Some(items) = load(path("FORENSIC_DIAGNOSTIC_LOGS", "diagnostic_logs.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| DiagnosticLog {
            name: s(&v, &["name"]),
            path: s(&v, &["path"]),
            size: n(&v, &["size"]),
            last_modified: n(&v, &["last_modified", "modified"]),
        })
        .filter(|x| !x.name.is_empty() || !x.path.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct DiagnosticLog {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub last_modified: u64,
}

pub fn get_reliability_records() -> Result<Vec<ReliabilityRecord>, ForensicError> {
    let Some(items) = load(path(
        "FORENSIC_DIAGNOSTIC_RELIABILITY",
        "diagnostic_reliability.json",
    )) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| ReliabilityRecord {
            timestamp: n(&v, &["timestamp", "time"]),
            event_id: n(&v, &["event_id", "id"]) as u32,
            level: s(&v, &["level"]),
            source: s(&v, &["source"]),
            description: s(&v, &["description", "message"]),
        })
        .filter(|x| x.timestamp > 0 || x.event_id > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct ReliabilityRecord {
    pub timestamp: u64,
    pub event_id: u32,
    pub level: String,
    pub source: String,
    pub description: String,
}

pub fn get_problem_reports() -> Result<Vec<ProblemReport>, ForensicError> {
    let Some(items) = load(path("FORENSIC_PROBLEM_REPORTS", "problem_reports.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| ProblemReport {
            report_id: s(&v, &["report_id", "id"]),
            problem_name: s(&v, &["problem_name", "name"]),
            submitted_time: n(&v, &["submitted_time", "timestamp"]),
            status: s(&v, &["status"]),
            bucket_id: s(&v, &["bucket_id"]),
        })
        .filter(|x| !x.report_id.is_empty() || !x.problem_name.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct ProblemReport {
    pub report_id: String,
    pub problem_name: String,
    pub submitted_time: u64,
    pub status: String,
    pub bucket_id: String,
}

pub fn get_hip_diagnostics() -> Result<Vec<HipDiagnostic>, ForensicError> {
    let Some(items) = load(path("FORENSIC_HIP_DIAGNOSTICS", "hip_diagnostics.json")) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| HipDiagnostic {
            name: s(&v, &["name"]),
            category: s(&v, &["category"]),
            enabled: b(&v, &["enabled"]),
            last_run: opt_n(&v, &["last_run", "timestamp"]),
        })
        .filter(|x| !x.name.is_empty() || !x.category.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct HipDiagnostic {
    pub name: String,
    pub category: String,
    pub enabled: bool,
    pub last_run: Option<u64>,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("diagnostics").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let json: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = json.as_array() {
        Some(items.clone())
    } else if json.is_object() {
        Some(vec![json])
    } else {
        None
    }
}

fn result_enum(value: String) -> TroubleshootingResult {
    match value.to_ascii_lowercase().as_str() {
        "notresolved" | "not_resolved" => TroubleshootingResult::NotResolved,
        "resolved" => TroubleshootingResult::Resolved,
        "resolvedwithrestart" | "resolved_with_restart" => {
            TroubleshootingResult::ResolvedWithRestart
        }
        "resolvedprogram" | "resolved_program" => TroubleshootingResult::ResolvedProgram,
        "unresolved" => TroubleshootingResult::Unresolved,
        _ => TroubleshootingResult::Unknown,
    }
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
    opt_n(v, keys).unwrap_or(0)
}

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}
