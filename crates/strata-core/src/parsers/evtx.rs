//! Windows EVTX parser.
//!
//! v1.3.0: switched from a stub (filename-only detection) to a real
//! per-event parser backed by the pure-Rust `evtx` crate, which works
//! cross-platform. Each high-value event becomes its own `ParsedArtifact`
//! with `artifact_type = "EVTX-<EventID>"` so the Sigma correlation
//! engine can match Hayabusa-inspired rules against real data.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::evtx_structured;
use evtx::EvtxParser as InnerEvtxParser;
use serde_json::Value;
use std::path::Path;

pub struct EvtxParser;

impl Default for EvtxParser {
    fn default() -> Self {
        Self::new()
    }
}

impl EvtxParser {
    pub fn new() -> Self {
        Self
    }
}

/// Event IDs we care about, keyed by source channel. Anything not in this
/// set gets folded into a single "other" bucket to keep artifact counts sane.
///
/// Inspired by Hayabusa rule categories and SANS FOR508 high-value events.
fn is_high_value_event(channel: &str, event_id: u32) -> bool {
    match channel {
        // Security log
        "Security" => matches!(
            event_id,
            4624  // logon
            | 4625  // failed logon
            | 4634  // logoff
            | 4648  // explicit-creds logon
            | 4672  // special privileges assigned
            | 4697  // service install (Win10+)
            | 4698  // scheduled task created
            | 4699  // scheduled task deleted
            | 4700  // scheduled task enabled
            | 4702  // scheduled task updated
            | 4719  // audit policy changed
            | 4720  // user account created
            | 4722  // user account enabled
            | 4724  // password reset attempt
            | 4725  // user account disabled
            | 4726  // user account deleted
            | 4728  // member added to global group
            | 4732  // member added to local group
            | 4738  // user account changed
            | 4740  // user account locked out
            | 4768  // Kerberos TGT requested
            | 4769  // Kerberos service ticket requested
            | 4771  // Kerberos pre-auth failed
            | 4776  // NTLM logon validation
            | 4781  // account name changed
            | 1102 // audit log cleared
        ),
        // System log
        "System" => matches!(
            event_id,
            7045  // service install
            | 7034  // service terminated unexpectedly
            | 7036  // service state change
            | 104   // system log cleared
            | 6005  // event log service started
            | 6006 // event log service stopped
        ),
        // PowerShell operational
        s if s.eq_ignore_ascii_case("Microsoft-Windows-PowerShell/Operational") => {
            matches!(event_id, 4103..=4106)
        }
        // Sysmon
        s if s.eq_ignore_ascii_case("Microsoft-Windows-Sysmon/Operational") => {
            matches!(
                event_id,
                1 // process create
                | 3  // network connect
                | 7  // image loaded
                | 8  // CreateRemoteThread
                | 10 // ProcessAccess (LSASS)
                | 11 // FileCreate
                | 12 // RegistryObject
                | 13 // RegistryEvent (SetValue)
                | 17 // PipeEvent
                | 19 | 20 | 21 // WmiEvent
                | 22 // DnsQuery
                | 25 // ProcessTampering
            )
        }
        // Task Scheduler operational
        s if s.eq_ignore_ascii_case("Microsoft-Windows-TaskScheduler/Operational") => {
            matches!(event_id, 106 | 140 | 141 | 200 | 201)
        }
        // WinRM
        s if s.eq_ignore_ascii_case("Microsoft-Windows-WinRM/Operational") => {
            matches!(event_id, 6 | 169)
        }
        // Windows Defender operational
        s if s.eq_ignore_ascii_case("Microsoft-Windows-Windows Defender/Operational") => {
            matches!(
                event_id,
                1006 | 1007 | 1008 | 1116 | 1117 | 5001 | 5007 | 5010
            )
        }
        _ => false,
    }
}

/// Pull a string field from an `evtx` JSON record. The `evtx` crate emits
/// records as `Event.EventData.<Field>` or `Event.UserData.<Field>`.
fn event_data_str(root: &Value, key: &str) -> Option<String> {
    let event = root.get("Event")?;
    for section in ["EventData", "UserData"] {
        if let Some(data) = event.get(section) {
            if let Some(v) = data.get(key) {
                return Some(match v {
                    Value::String(s) => s.clone(),
                    _ => v.to_string(),
                });
            }
        }
    }
    None
}

fn system_u32(root: &Value, path: &[&str]) -> Option<u32> {
    let mut cur = root.get("Event")?.get("System")?;
    for p in path {
        cur = cur.get(*p)?;
    }
    match cur {
        Value::Number(n) => n.as_u64().map(|v| v as u32),
        Value::String(s) => s.parse().ok(),
        Value::Object(o) => o
            .get("#text")
            .or_else(|| o.get("Value"))
            .and_then(|v| match v {
                Value::Number(n) => n.as_u64().map(|v| v as u32),
                Value::String(s) => s.parse().ok(),
                _ => None,
            }),
        _ => None,
    }
}

fn system_str(root: &Value, path: &[&str]) -> Option<String> {
    let mut cur = root.get("Event")?.get("System")?;
    for p in path {
        cur = cur.get(*p)?;
    }
    match cur {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => o
            .get("#text")
            .or_else(|| o.get("Name"))
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                _ => None,
            }),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn timecreated_unix(root: &Value) -> Option<i64> {
    // Event.System.TimeCreated.#attributes.SystemTime (ISO-8601 string).
    let sys = root.get("Event")?.get("System")?;
    let tc = sys.get("TimeCreated")?;
    let iso = tc
        .get("#attributes")
        .and_then(|a| a.get("SystemTime"))
        .or_else(|| tc.get("SystemTime"))
        .and_then(|v| v.as_str())?;
    chrono::DateTime::parse_from_rfc3339(iso)
        .map(|d| d.timestamp())
        .ok()
}

impl ArtifactParser for EvtxParser {
    fn name(&self) -> &str {
        "Windows EVTX Parser (evtx crate)"
    }

    fn artifact_type(&self) -> &str {
        "eventlog"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".evtx"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_string();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let log_name = filename.trim_end_matches(".evtx").to_string();

        let mut parser = match InnerEvtxParser::from_buffer(data.to_vec()) {
            Ok(p) => p,
            Err(e) => {
                return Err(ParserError::Parse(format!(
                    "evtx parse init failed on {}: {}",
                    filename, e
                )));
            }
        };

        let mut total = 0usize;
        let mut high_value = 0usize;
        let mut per_event_cap = 2500usize; // hard cap per log file

        for record in parser.records_json_value() {
            if per_event_cap == 0 {
                break;
            }
            let record = match record {
                Ok(r) => r,
                Err(_) => continue,
            };
            total += 1;

            let root = &record.data;
            let Some(event_id) = system_u32(root, &["EventID"]) else {
                continue;
            };
            let channel = system_str(root, &["Channel"]).unwrap_or_else(|| log_name.clone());

            if !is_high_value_event(&channel, event_id) {
                continue;
            }
            high_value += 1;
            per_event_cap -= 1;

            let ts = timecreated_unix(root);
            let computer = system_str(root, &["Computer"]);
            let provider = system_str(root, &["Provider"]).unwrap_or_default();

            // Common event-data fields we want surfaced to the UI + Sigma plugin.
            let target_user = event_data_str(root, "TargetUserName");
            let subject_user = event_data_str(root, "SubjectUserName");
            let source_ip = event_data_str(root, "IpAddress")
                .or_else(|| event_data_str(root, "SourceNetworkAddress"));
            let logon_type = event_data_str(root, "LogonType");
            let process_name =
                event_data_str(root, "ProcessName").or_else(|| event_data_str(root, "Image"));
            let command_line = event_data_str(root, "CommandLine")
                .or_else(|| event_data_str(root, "ScriptBlockText"));
            let parent_image = event_data_str(root, "ParentImage");
            let service_name = event_data_str(root, "ServiceName");
            let target_filename = event_data_str(root, "TargetFilename");

            let description = match event_id {
                4624 => format!(
                    "Logon success — user={} type={} from={}",
                    target_user.clone().unwrap_or_default(),
                    logon_type.clone().unwrap_or_default(),
                    source_ip.clone().unwrap_or_default()
                ),
                4625 => format!(
                    "Logon failed — user={} from={}",
                    target_user.clone().unwrap_or_default(),
                    source_ip.clone().unwrap_or_default()
                ),
                4688 => format!(
                    "Process create — {}",
                    process_name.clone().unwrap_or_default()
                ),
                4698 => format!(
                    "Scheduled task created — {}",
                    event_data_str(root, "TaskName").unwrap_or_default()
                ),
                4720 => format!(
                    "User account created — {}",
                    target_user.clone().unwrap_or_default()
                ),
                4732 => format!(
                    "Member added to local group — {}",
                    target_user.clone().unwrap_or_default()
                ),
                4769 => format!(
                    "Kerberos ticket requested — user={} svc={}",
                    target_user.clone().unwrap_or_default(),
                    event_data_str(root, "ServiceName").unwrap_or_default()
                ),
                1102 => "Security audit log cleared".to_string(),
                104 => "System log cleared".to_string(),
                7045 => format!(
                    "Service install — {}",
                    service_name.clone().unwrap_or_default()
                ),
                4104 => format!(
                    "PowerShell script block — {}",
                    command_line
                        .as_deref()
                        .map(|s| &s[..s.len().min(120)])
                        .unwrap_or("")
                ),
                1 => format!(
                    "Sysmon process create — {}",
                    process_name.clone().unwrap_or_default()
                ),
                3 => format!(
                    "Sysmon network connect — {}",
                    process_name.clone().unwrap_or_default()
                ),
                10 => format!(
                    "Sysmon ProcessAccess — target={}",
                    event_data_str(root, "TargetImage").unwrap_or_default()
                ),
                22 => format!(
                    "Sysmon DnsQuery — {}",
                    event_data_str(root, "QueryName").unwrap_or_default()
                ),
                _ => format!("{} event {}", channel, event_id),
            };

            let mut data_obj = serde_json::Map::new();
            data_obj.insert("event_id".into(), Value::from(event_id));
            data_obj.insert("channel".into(), Value::from(channel.clone()));
            data_obj.insert("provider".into(), Value::from(provider.clone()));
            data_obj.insert("log_name".into(), Value::from(log_name.clone()));
            if let Some(v) = computer {
                data_obj.insert("computer".into(), Value::from(v));
            }
            if let Some(v) = target_user {
                data_obj.insert("target_user".into(), Value::from(v));
            }
            if let Some(v) = subject_user {
                data_obj.insert("subject_user".into(), Value::from(v));
            }
            if let Some(v) = source_ip {
                data_obj.insert("source_ip".into(), Value::from(v));
            }
            if let Some(v) = logon_type {
                data_obj.insert("logon_type".into(), Value::from(v));
            }
            if let Some(v) = process_name {
                data_obj.insert("process_name".into(), Value::from(v));
            }
            if let Some(v) = command_line {
                data_obj.insert("command_line".into(), Value::from(v));
            }
            if let Some(v) = parent_image {
                data_obj.insert("parent_image".into(), Value::from(v));
            }
            if let Some(v) = service_name {
                data_obj.insert("service_name".into(), Value::from(v));
            }
            if let Some(v) = target_filename {
                data_obj.insert("target_filename".into(), Value::from(v));
            }

            // Typed structured-event extraction for the 9 high-value IDs
            // documented in `parsers::evtx_structured`. Adds:
            //   * `artifact_subcategory = "Windows Event"`
            //   * `mitre` mapped per the user-specified table (overrides
            //     the generic per-channel default)
            //   * `forensic_value = "High"` for the structured set
            //   * `structured` — the typed Win<EID>* struct, serialized
            if let Some(structured) = evtx_structured::extract_event(event_id, root) {
                data_obj.insert("artifact_subcategory".into(), Value::from("Windows Event"));
                if let Some(mitre) = evtx_structured::mitre_for_event_id(event_id) {
                    data_obj.insert("mitre".into(), Value::from(mitre));
                }
                data_obj.insert(
                    "forensic_value".into(),
                    Value::from(evtx_structured::forensic_value_for_event_id(event_id)),
                );
                if let Ok(v) = serde_json::to_value(&structured) {
                    data_obj.insert("structured".into(), v);
                }
            }

            artifacts.push(ParsedArtifact {
                timestamp: ts,
                artifact_type: format!("EVTX-{}", event_id),
                description,
                source_path: path_str.clone(),
                json_data: Value::Object(data_obj),
            });
        }

        // Always emit a summary artifact so the UI shows the file even when
        // no high-value events fired.
        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "eventlog".to_string(),
            description: format!(
                "Event Log: {} ({} records, {} high-value)",
                log_name, total, high_value
            ),
            source_path: path_str,
            json_data: serde_json::json!({
                "log_name": log_name,
                "filename": filename,
                "size_bytes": data.len(),
                "total_records": total,
                "high_value_events": high_value,
            }),
        });

        Ok(artifacts)
    }
}
