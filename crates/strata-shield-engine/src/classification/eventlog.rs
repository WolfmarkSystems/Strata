use crate::errors::ForensicError;
use chrono::DateTime;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use super::scalpel::{read_prefix, DEFAULT_BINARY_MAX_BYTES};

const FILETIME_UNIX_EPOCH_OFFSET: u64 = 11_644_473_600;
const MAX_XML_SCAN_BYTES: usize = DEFAULT_BINARY_MAX_BYTES * 16;

#[derive(Debug, Clone)]
pub struct EventLogEntry {
    pub event_id: u32,
    pub level: u8,
    pub level_name: Option<String>,
    pub timestamp: Option<i64>,
    pub source: String,
    pub channel: Option<String>,
    pub record_id: Option<u64>,
    pub task: Option<u32>,
    pub opcode: Option<u32>,
    pub keywords: Option<String>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub event_data: BTreeMap<String, String>,
    pub semantic_category: Option<String>,
    pub semantic_summary: Option<String>,
    pub message: Option<String>,
    pub computer: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityLogSummary {
    pub logon_events: u32,
    pub privilege_escalation: u32,
    pub account_changes: u32,
    pub failed_logons: u32,
    pub entries: Vec<EventLogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventLogInputShape {
    RawEvtx,
    XmlExport,
    Utf16XmlExport,
    RawEvt,
    Unknown,
}

impl EventLogInputShape {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RawEvtx => "raw_evtx",
            Self::XmlExport => "xml_export",
            Self::Utf16XmlExport => "utf16_xml_export",
            Self::RawEvt => "raw_evt",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventLogParseMetadata {
    pub input_shape: EventLogInputShape,
    pub parser_mode: String,
    pub fallback_used: bool,
    pub deduped_count: usize,
    pub quality_flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityLogParseResult {
    pub summary: SecurityLogSummary,
    pub metadata: EventLogParseMetadata,
}

#[derive(Debug, Clone)]
pub struct EventLogEntriesParseResult {
    pub entries: Vec<EventLogEntry>,
    pub metadata: EventLogParseMetadata,
}

pub fn detect_eventlog_input_shape(data: &[u8]) -> EventLogInputShape {
    if data.len() >= 8 && &data[..7] == b"ElfFile" {
        return EventLogInputShape::RawEvtx;
    }
    if data.windows(4).any(|w| w == b"LfLe") {
        return EventLogInputShape::RawEvt;
    }
    if data.windows(6).any(|w| w == b"<Event") {
        return EventLogInputShape::XmlExport;
    }

    // "<Event" encoded in UTF-16LE bytes.
    const UTF16_EVENT: [u8; 12] = [b'<', 0, b'E', 0, b'v', 0, b'e', 0, b'n', 0, b't', 0];
    if data.windows(UTF16_EVENT.len()).any(|w| w == UTF16_EVENT) {
        return EventLogInputShape::Utf16XmlExport;
    }

    EventLogInputShape::Unknown
}

pub fn parse_security_log(path: &Path) -> Result<SecurityLogSummary, ForensicError> {
    let parsed = parse_security_log_with_metadata(path)?;
    Ok(parsed.summary)
}

pub fn parse_security_log_with_metadata(
    path: &Path,
) -> Result<SecurityLogParseResult, ForensicError> {
    let (entries, metadata) = parse_event_log_entries_with_metadata(path)?;
    let mut summary = SecurityLogSummary {
        logon_events: 0,
        privilege_escalation: 0,
        account_changes: 0,
        failed_logons: 0,
        entries,
    };

    for entry in &summary.entries {
        match entry.event_id {
            4624 | 4634 | 4647 => summary.logon_events += 1,
            4672 => summary.privilege_escalation += 1,
            4720 | 4722 | 4723 | 4724 | 4725 | 4726 | 4738 | 4741 | 4742 | 4743 => {
                summary.account_changes += 1
            }
            4625 => summary.failed_logons += 1,
            4776 => {
                if first_data_value(&entry.event_data, &["Status", "ErrorCode", "FailureCode"])
                    .map(is_non_success_status)
                    .unwrap_or(false)
                {
                    summary.failed_logons += 1;
                }
            }
            _ => {}
        }
    }

    Ok(SecurityLogParseResult { summary, metadata })
}

pub fn parse_system_log(path: &Path) -> Result<Vec<EventLogEntry>, ForensicError> {
    parse_event_log_entries(path)
}

pub fn parse_system_log_with_metadata(
    path: &Path,
) -> Result<EventLogEntriesParseResult, ForensicError> {
    let (entries, metadata) = parse_event_log_entries_with_metadata(path)?;
    Ok(EventLogEntriesParseResult { entries, metadata })
}

pub fn parse_application_log(path: &Path) -> Result<Vec<EventLogEntry>, ForensicError> {
    parse_event_log_entries(path)
}

// Extended security-event catalog used for truthful fallback classification when
// we have a known event ID but no richer field-level semantic formatter yet.
const EXTENDED_SECURITY_EVENT_IDS: &[u32] = &[
    4608, 4609, 4610, 4611, 4612, 4614, 4621, 4622, 4627, 4649, 4656, 4658, 4660, 4661, 4662, 4663,
    4664, 4665, 4666, 4667, 4670, 4671, 4675, 4688, 4689, 4690, 4691, 4692, 4693, 4694, 4695, 4696,
    4700, 4701, 4703, 4704, 4705, 4706, 4707, 4713, 4714, 4715, 4716, 4717, 4718, 4721, 4727, 4730,
    4731, 4734, 4735, 4737, 4739, 4744, 4745, 4746, 4747, 4748, 4749, 4750, 4751, 4752, 4753, 4754,
    4755, 4758, 4760, 4761, 4762, 4763, 4764, 4765, 4766, 4770, 4771, 4772, 4773, 4774, 4775, 4780,
    4781, 4793, 4794, 4797, 4798, 4799, 4800, 4801, 4802, 4803, 4816, 4817, 4825, 4826, 4886, 4887,
    4888, 4890, 4891, 4892, 4902, 4904, 4905, 4906, 4907, 4908, 4909, 4910, 4911, 4912, 4928, 4929,
    4930, 4931, 4932, 4933, 4934, 4935, 4936, 4937, 4944, 4945, 4946, 4947, 4948, 4950, 4951, 4952,
    4953, 4954, 4956, 4957, 4958, 4960, 4961, 4962, 4963, 4964, 4965, 4966, 4967, 4985, 5024, 5025,
    5031, 5032, 5033, 5034, 5035, 5037, 5038, 5039, 5040, 5041, 5042, 5043, 5044, 5045, 5046, 5047,
    5048, 5056, 5057, 5058, 5059, 5060, 5061, 5062, 5063, 5064, 5065, 5066, 5067, 5068, 5069, 5070,
    5071, 5120, 5121, 5122, 5123, 5124, 5140, 5142, 5143, 5144, 5145, 5146, 5147, 5148, 5149, 5150,
    5151, 5152, 5153, 5154, 5155, 5157, 5159, 5168,
];

const EXTENDED_SECURITY_EVENT_EXTRA_RANGE_START: u32 = 5200;
const EXTENDED_SECURITY_EVENT_EXTRA_RANGE_END: u32 = 9099;

#[cfg(test)]
fn extended_security_event_catalog_size() -> usize {
    EXTENDED_SECURITY_EVENT_IDS.len()
        + (EXTENDED_SECURITY_EVENT_EXTRA_RANGE_END - EXTENDED_SECURITY_EVENT_EXTRA_RANGE_START + 1)
            as usize
}

fn is_extended_security_event_id(event_id: u32) -> bool {
    EXTENDED_SECURITY_EVENT_IDS.binary_search(&event_id).is_ok()
        || (EXTENDED_SECURITY_EVENT_EXTRA_RANGE_START..=EXTENDED_SECURITY_EVENT_EXTRA_RANGE_END)
            .contains(&event_id)
}

pub fn get_known_security_event_description(event_id: u32) -> &'static str {
    match event_id {
        4624 => "Successful logon",
        4625 => "Failed logon",
        4627 => "Group membership information",
        4634 => "Logoff",
        4649 => "Replay attack detected",
        4648 => "Logon attempted with explicit credentials",
        4657 => "Registry value modified",
        4647 => "User initiated logoff",
        4616 => "System time changed",
        4672 => "Special privileges assigned",
        4673 => "Sensitive privilege use attempted",
        4674 => "Operation attempted on privileged object",
        4697 => "Service installed in system",
        4698 => "Scheduled task created",
        4699 => "Scheduled task deleted",
        4702 => "Scheduled task updated",
        4713 => "Kerberos policy changed",
        4719 => "System audit policy changed",
        4720 => "User account created",
        4722 => "User account enabled",
        4723 => "Password change attempt",
        4724 => "Password reset attempt",
        4725 => "User account disabled",
        4726 => "User account deleted",
        4728 => "Member added to security-enabled global group",
        4729 => "Member removed from security-enabled global group",
        4738 => "User account changed",
        4732 => "Member added to security-enabled local group",
        4733 => "Member removed from security-enabled local group",
        4735 => "Security-enabled local group changed",
        4737 => "Security-enabled global group changed",
        4741 => "Computer account created",
        4742 => "Computer account changed",
        4743 => "Computer account deleted",
        4754 => "Security-enabled universal group created",
        4755 => "Security-enabled universal group changed",
        4756 => "Member added to security-enabled universal group",
        4757 => "Member removed from security-enabled universal group",
        4740 => "User account locked out",
        4765 => "SID History added to account",
        4766 => "SID History add attempt failed",
        4767 => "Account unlocked",
        4768 => "Kerberos TGT requested",
        4769 => "Kerberos service ticket requested",
        4774 => "Account mapped for logon",
        4776 => "NTLM authentication",
        4778 => "Session reconnected",
        4779 => "Session disconnected",
        4798 => "User local group membership enumerated",
        4799 => "Security-enabled local group membership enumerated",
        4825 => "CrashOnAuditFail value changed",
        4826 => "Boot Configuration Data loaded",
        4964 => "Special groups assigned to new logon",
        5146 => "Detailed file share access denied",
        5147 => "Detailed file share access granted",
        5148 => "Detailed file share access check",
        5149 => "Detailed file share object checked",
        5150 => "Windows Filtering Platform blocked packet",
        5151 => "Windows Filtering Platform blocked packet",
        5152 => "Windows Filtering Platform dropped packet",
        5153 => "Windows Filtering Platform dropped packet",
        5154 => "Windows Filtering Platform allowed bind/listen",
        5155 => "Windows Filtering Platform blocked bind/listen",
        7034 => "Service terminated unexpectedly",
        7036 => "Service entered state",
        7040 => "Service start type changed",
        1074 => "System shutdown/restart initiated",
        _ if is_extended_security_event_id(event_id) => "Extended security auditing event",
        _ => "Unknown event",
    }
}

fn parse_event_log_entries(path: &Path) -> Result<Vec<EventLogEntry>, ForensicError> {
    let (entries, _) = parse_event_log_entries_with_metadata(path)?;
    Ok(entries)
}

fn parse_event_log_entries_with_metadata(
    path: &Path,
) -> Result<(Vec<EventLogEntry>, EventLogParseMetadata), ForensicError> {
    if !path.exists() {
        return Ok((
            Vec::new(),
            EventLogParseMetadata {
                input_shape: EventLogInputShape::Unknown,
                parser_mode: "none".to_string(),
                fallback_used: false,
                deduped_count: 0,
                quality_flags: vec!["input_missing".to_string()],
            },
        ));
    }

    let data = read_prefix(path, MAX_XML_SCAN_BYTES)?;
    let input_shape = detect_eventlog_input_shape(&data);
    let (mut entries, deduped_count) = parse_evtx_xml_entries_with_stats(&data);
    let mut parser_mode = "evtx_xml".to_string();
    let mut fallback_used = false;
    let mut quality_flags = Vec::new();

    if entries.is_empty() {
        fallback_used = true;
        parser_mode = "legacy_evt".to_string();
        entries = parse_legacy_evt_records(&data);
    }

    if entries.is_empty() {
        parser_mode = "none".to_string();
        quality_flags.push("no_records_parsed".to_string());
    }
    if entries.iter().all(|e| e.timestamp.is_none()) && !entries.is_empty() {
        quality_flags.push("no_valid_timestamps".to_string());
    }

    let metadata = EventLogParseMetadata {
        input_shape,
        parser_mode,
        fallback_used,
        deduped_count,
        quality_flags,
    };
    Ok((entries, metadata))
}

#[cfg(test)]
fn parse_evtx_xml_entries(data: &[u8]) -> Vec<EventLogEntry> {
    let (entries, _) = parse_evtx_xml_entries_with_stats(data);
    entries
}

fn parse_evtx_xml_entries_with_stats(data: &[u8]) -> (Vec<EventLogEntry>, usize) {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut deduped_count = 0usize;

    for xml in extract_event_xml_fragments_ascii(data) {
        if let Some(entry) = parse_event_xml(&xml) {
            let dedupe_key = (
                entry.event_id,
                entry.timestamp.unwrap_or_default(),
                entry.source.clone(),
                entry.computer.clone().unwrap_or_default(),
                entry.record_id.unwrap_or_default(),
            );
            if seen.insert(dedupe_key) {
                entries.push(entry);
            } else {
                deduped_count += 1;
            }
        }
    }

    for xml in extract_event_xml_fragments_utf16(data) {
        if let Some(entry) = parse_event_xml(&xml) {
            let dedupe_key = (
                entry.event_id,
                entry.timestamp.unwrap_or_default(),
                entry.source.clone(),
                entry.computer.clone().unwrap_or_default(),
                entry.record_id.unwrap_or_default(),
            );
            if seen.insert(dedupe_key) {
                entries.push(entry);
            } else {
                deduped_count += 1;
            }
        }
    }

    entries.sort_by(|a, b| {
        b.timestamp
            .unwrap_or_default()
            .cmp(&a.timestamp.unwrap_or_default())
    });
    (entries, deduped_count)
}

fn parse_legacy_evt_records(data: &[u8]) -> Vec<EventLogEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset + 96 <= data.len() {
        if &data[offset..offset + 4] != b"LfLe" {
            offset += 1;
            continue;
        }

        let record_size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;
        if record_size < 96 || offset + record_size > data.len() {
            break;
        }

        let timestamp_filetime = u64::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        let timestamp = filetime_to_unix(timestamp_filetime).map(|v| v as i64);
        let event_id = u32::from_le_bytes([
            data[offset + 24],
            data[offset + 25],
            data[offset + 26],
            data[offset + 27],
        ]);
        let level = data[offset + 28];
        let source = extract_null_terminated_ascii(data, offset + 48, 64).unwrap_or_default();

        entries.push(EventLogEntry {
            event_id,
            level,
            level_name: level_name(level),
            timestamp,
            source,
            channel: None,
            record_id: None,
            task: None,
            opcode: None,
            keywords: None,
            process_id: None,
            thread_id: None,
            event_data: BTreeMap::new(),
            semantic_category: None,
            semantic_summary: None,
            message: None,
            computer: None,
            user: None,
        });

        offset += record_size;
    }

    entries
}

fn parse_event_xml(xml: &str) -> Option<EventLogEntry> {
    let event_id = extract_event_id(xml)?;
    let level = extract_tag_text(xml, "Level")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0);
    let source = extract_provider_name(xml).unwrap_or_else(|| "unknown".to_string());
    let channel = extract_tag_text(xml, "Channel").map(|v| v.trim().to_string());
    let record_id = extract_tag_text(xml, "EventRecordID").and_then(|v| v.trim().parse().ok());
    let task = extract_tag_text(xml, "Task").and_then(|v| v.trim().parse().ok());
    let opcode = extract_tag_text(xml, "Opcode").and_then(|v| v.trim().parse().ok());
    let keywords = extract_tag_text(xml, "Keywords")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let process_id = extract_attr_from_element(xml, "Execution", "ProcessID")
        .and_then(|v| v.trim().parse().ok());
    let thread_id =
        extract_attr_from_element(xml, "Execution", "ThreadID").and_then(|v| v.trim().parse().ok());
    let mut event_data = extract_event_data_fields(xml);
    normalize_event_data_fields(&mut event_data);
    let timestamp = extract_system_time(xml)
        .or_else(|| extract_tag_text(xml, "TimeCreated"))
        .and_then(|v| parse_timestamp_to_unix(&v));
    let computer = normalize_computer_name(extract_tag_text(xml, "Computer"));
    let user = normalize_user_identity(
        extract_security_user(xml).or_else(|| extract_user_from_event_data(&event_data)),
    );
    let message = extract_message(xml, &event_data);
    let (semantic_category, semantic_summary) =
        build_semantic_summary(event_id, &source, &event_data, message.as_deref());

    Some(EventLogEntry {
        event_id,
        level,
        level_name: level_name(level),
        timestamp,
        source,
        channel,
        record_id,
        task,
        opcode,
        keywords,
        process_id,
        thread_id,
        event_data,
        semantic_category,
        semantic_summary,
        message,
        computer,
        user,
    })
}

fn normalize_user_identity(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim().trim_matches('"');
        if trimmed.is_empty() {
            return None;
        }
        if let Some(sid) = normalize_sid(trimmed) {
            return Some(sid);
        }
        Some(trimmed.to_string())
    })
}

fn normalize_computer_name(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim().trim_matches('"');
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_ascii_uppercase())
        }
    })
}

fn normalize_sid(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"');
    if trimmed.to_ascii_lowercase().starts_with("s-") {
        Some(trimmed.to_ascii_uppercase())
    } else {
        None
    }
}

fn normalize_windows_path(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.replace('/', "\\"))
    }
}

fn normalize_event_data_fields(event_data: &mut BTreeMap<String, String>) {
    for (key, value) in event_data.iter_mut() {
        let normalized = if key.eq_ignore_ascii_case("ProcessName")
            || key.eq_ignore_ascii_case("NewProcessName")
            || key.eq_ignore_ascii_case("ParentProcessName")
            || key.eq_ignore_ascii_case("Image")
            || key.eq_ignore_ascii_case("ApplicationName")
            || key.eq_ignore_ascii_case("Path")
            || key.eq_ignore_ascii_case("ExecutablePath")
        {
            normalize_windows_path(value)
        } else if key.to_ascii_lowercase().contains("sid") {
            normalize_sid(value)
        } else {
            let trimmed = value.trim().trim_matches('"');
            if trimmed.is_empty() {
                None
            } else {
                // Keep event data bounded so malformed or oversized payloads
                // cannot flood summaries or downstream JSON envelopes.
                Some(truncate(trimmed, 2048))
            }
        };
        if let Some(updated) = normalized {
            *value = updated;
        }
    }
}

fn extract_event_id(xml: &str) -> Option<u32> {
    extract_tag_text(xml, "EventID").and_then(|v| v.trim().parse::<u32>().ok())
}

fn extract_provider_name(xml: &str) -> Option<String> {
    extract_attr_from_element(xml, "Provider", "Name")
}

fn extract_system_time(xml: &str) -> Option<String> {
    extract_attr_from_element(xml, "TimeCreated", "SystemTime")
}

fn extract_security_user(xml: &str) -> Option<String> {
    extract_attr_from_element(xml, "Security", "UserID")
}

fn extract_message(xml: &str, event_data: &BTreeMap<String, String>) -> Option<String> {
    if let Some(msg) = extract_tag_text(xml, "Message") {
        let trimmed = msg.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(msg) = event_data.get("Message") {
        let trimmed = msg.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(msg) = event_data.values().next() {
        let trimmed = msg.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    extract_first_data_value(xml)
}

fn extract_user_from_event_data(event_data: &BTreeMap<String, String>) -> Option<String> {
    first_data_value(
        event_data,
        &[
            "TargetUserName",
            "SubjectUserName",
            "AccountName",
            "User",
            "UserName",
            "TargetSid",
            "SubjectUserSid",
        ],
    )
    .map(ToString::to_string)
}

fn extract_event_data_fields(xml: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut start = 0usize;
    let mut ordinal = 1usize;
    while let Some(idx) = xml[start..].find("<Data") {
        let abs = start + idx;
        let Some(close_idx) = xml[abs..].find('>') else {
            break;
        };
        let header_end = abs + close_idx;
        let header = &xml[abs..=header_end];
        let content_start = header_end + 1;
        let Some(end_idx) = xml[content_start..].find("</Data>") else {
            break;
        };

        let key = extract_attr_from_snippet(header, "Name")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| format!("data_{}", ordinal));
        let value = decode_xml_entities(xml[content_start..content_start + end_idx].trim());
        if !value.is_empty() {
            insert_event_data_value(&mut out, key, value);
        }

        start = content_start + end_idx + 7;
        ordinal += 1;
    }
    out
}

fn extract_first_data_value(xml: &str) -> Option<String> {
    let mut start = 0usize;
    while let Some(idx) = xml[start..].find("<Data") {
        let abs = start + idx;
        let Some(close_idx) = xml[abs..].find('>') else {
            break;
        };
        let content_start = abs + close_idx + 1;
        let Some(end_idx) = xml[content_start..].find("</Data>") else {
            break;
        };
        let value = decode_xml_entities(xml[content_start..content_start + end_idx].trim());
        if !value.is_empty() {
            return Some(value);
        }
        start = content_start + end_idx + 7;
    }
    None
}

fn extract_tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)?;
    let after_open = xml[start..].find('>')? + start + 1;
    let end = xml[after_open..].find(&close)? + after_open;
    Some(decode_xml_entities(&xml[after_open..end]))
}

fn extract_attr_from_element(xml: &str, element: &str, attr: &str) -> Option<String> {
    let open = format!("<{}", element);
    let start = xml.find(&open)?;
    let end = xml[start..].find('>')? + start;
    let snippet = &xml[start..=end];
    extract_attr_from_snippet(snippet, attr)
}

fn extract_attr_from_snippet(snippet: &str, attr: &str) -> Option<String> {
    let p1 = format!(r#"{}=""#, attr);
    if let Some(idx) = snippet.find(&p1) {
        let val_start = idx + p1.len();
        if let Some(val_end) = snippet[val_start..].find('"') {
            return Some(decode_xml_entities(
                &snippet[val_start..val_start + val_end],
            ));
        }
    }

    let p2 = format!(r#"{}='"#, attr);
    if let Some(idx) = snippet.find(&p2) {
        let val_start = idx + p2.len();
        if let Some(val_end) = snippet[val_start..].find('\'') {
            return Some(decode_xml_entities(
                &snippet[val_start..val_start + val_end],
            ));
        }
    }

    None
}

fn insert_event_data_value(out: &mut BTreeMap<String, String>, key: String, value: String) {
    if let std::collections::btree_map::Entry::Vacant(v) = out.entry(key.clone()) {
        v.insert(value);
        return;
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{}_{}", key, suffix);
        if let std::collections::btree_map::Entry::Vacant(v) = out.entry(candidate) {
            v.insert(value);
            return;
        }
        suffix += 1;
    }
}

fn decode_xml_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }

        let mut j = i + 1;
        while j < bytes.len() && j.saturating_sub(i) <= 12 {
            if bytes[j] == b';' {
                break;
            }
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b';' {
            out.push('&');
            i += 1;
            continue;
        }

        let ent = &value[i + 1..j];
        let decoded = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => {
                if let Some(hex) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                    u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                } else if let Some(dec) = ent.strip_prefix('#') {
                    dec.parse::<u32>().ok().and_then(char::from_u32)
                } else {
                    None
                }
            }
        };

        if let Some(ch) = decoded {
            out.push(ch);
        } else {
            out.push_str(&value[i..=j]);
        }
        i = j + 1;
    }
    out
}

fn parse_timestamp_to_unix(value: &str) -> Option<i64> {
    let dt: DateTime<chrono::FixedOffset> = DateTime::parse_from_rfc3339(value).ok()?;
    Some(dt.timestamp())
}

fn level_name(level: u8) -> Option<String> {
    let name = match level {
        1 => "critical",
        2 => "error",
        3 => "warning",
        4 => "information",
        5 => "verbose",
        _ => return None,
    };
    Some(name.to_string())
}

fn first_data_value<'a>(data: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(v) = data.get(*key) {
            let t = v.trim();
            if !t.is_empty() && t != "-" {
                return Some(t);
            }
        }
        // Fall back to case-insensitive matching for real-world exports where
        // field casing is inconsistent.
        if let Some((_, v)) = data.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
            let t = v.trim();
            if !t.is_empty() && t != "-" {
                return Some(t);
            }
        }
    }
    None
}

fn parse_u32_token(value: &str) -> Option<u32> {
    let t = value.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u32>().ok()
    }
}

fn describe_logon_type(value: &str) -> Option<&'static str> {
    match parse_u32_token(value)? {
        2 => Some("interactive"),
        3 => Some("network"),
        4 => Some("batch"),
        5 => Some("service"),
        7 => Some("unlock"),
        8 => Some("network-cleartext"),
        9 => Some("new-credentials"),
        10 => Some("remote-interactive"),
        11 => Some("cached-interactive"),
        12 => Some("cached-remote-interactive"),
        13 => Some("cached-unlock"),
        _ => None,
    }
}

fn describe_kerberos_encryption_type(value: &str) -> Option<&'static str> {
    match parse_u32_token(value)? {
        0x01 => Some("des-cbc-crc"),
        0x03 => Some("des-cbc-md5"),
        0x11 => Some("aes128-cts-hmac-sha1-96"),
        0x12 => Some("aes256-cts-hmac-sha1-96"),
        0x17 => Some("rc4-hmac"),
        0x18 => Some("rc4-hmac-exp"),
        _ => None,
    }
}

fn describe_nt_status(value: &str) -> Option<&'static str> {
    match parse_u32_token(value)? {
        0x0 => Some("success"),
        0xC000005E => Some("no-logon-servers"),
        0xC000006D => Some("logon-failure"),
        0xC0000064 => Some("unknown-user"),
        0xC000006A => Some("bad-password"),
        0xC000006E => Some("account-restriction"),
        0xC000006F => Some("invalid-logon-hours"),
        0xC0000070 => Some("invalid-workstation"),
        0xC0000071 => Some("password-expired"),
        0xC0000072 => Some("account-disabled"),
        0xC000018C => Some("trust-relationship-failure"),
        0xC0000133 => Some("time-skew"),
        0xC000015B => Some("logon-type-not-granted"),
        0xC0000192 => Some("netlogon-service-not-started"),
        0xC0000193 => Some("account-expired"),
        0xC0000224 => Some("password-must-change"),
        0xC0000234 => Some("account-locked"),
        0xC0000413 => Some("authentication-firewall-failure"),
        _ => None,
    }
}

fn describe_token_elevation_type(value: &str) -> Option<&'static str> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("yes") || trimmed == "1" {
        return Some("elevated");
    }
    if trimmed.eq_ignore_ascii_case("no") || trimmed == "0" {
        return Some("not-elevated");
    }
    match trimmed {
        "%%1936" => Some("default"),
        "%%1937" => Some("full"),
        "%%1938" => Some("limited"),
        _ => None,
    }
}

fn format_token_elevation(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(label) = describe_token_elevation_type(trimmed) {
        label.to_string()
    } else {
        truncate(trimmed, 64)
    }
}

fn format_pid_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u64>().ok()
    };
    parsed.map(|n| format!("{} (0x{:X})", n, n))
}

fn normalize_failure_reason_text(value: &str) -> String {
    let mut reason = value.trim().to_string();
    if reason.eq_ignore_ascii_case("unknown user name or bad password.") {
        return "unknown-user-or-bad-password".to_string();
    }
    if reason.starts_with("%%") {
        return truncate(&reason, 120);
    }
    while reason.ends_with('.') {
        reason.pop();
    }
    truncate(&reason, 120)
}

fn format_status_with_name(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(name) = describe_nt_status(trimmed) {
        format!("{}:{}", trimmed, name)
    } else {
        truncate(trimmed, 48)
    }
}

fn is_non_success_status(value: &str) -> bool {
    parse_u32_token(value).map(|v| v != 0).unwrap_or(true)
}

fn build_semantic_summary(
    event_id: u32,
    source: &str,
    data: &BTreeMap<String, String>,
    message: Option<&str>,
) -> (Option<String>, Option<String>) {
    let source_lc = source.to_ascii_lowercase();
    let is_sysmon = source_lc.contains("sysmon");
    let is_eventlog_source = source_lc.contains("eventlog");
    let is_system_source = source_lc.contains("service control manager")
        || source_lc.contains("kernel-power")
        || source_lc.contains("eventlog")
        || source_lc == "system";

    match event_id {
        4624 => {
            let user = first_data_value(data, &["TargetUserName", "SubjectUserName"]);
            let ip = first_data_value(data, &["IpAddress", "WorkstationName"]);
            let logon_type = first_data_value(data, &["LogonType", "Logon_Type"]);
            let auth_pkg = first_data_value(
                data,
                &[
                    "AuthenticationPackageName",
                    "AuthenticationPackage",
                    "PackageName",
                ],
            );
            let logon_proc = first_data_value(data, &["LogonProcessName", "LogonProcess"]);
            let mut s = "Successful logon".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", u));
            }
            if let Some(ipv) = ip {
                s.push_str(&format!(" from {}", ipv));
            }
            if let Some(lt) = logon_type {
                if let Some(name) = describe_logon_type(lt) {
                    s.push_str(&format!(" [type {}]", name));
                }
            }
            if let Some(pkg) = auth_pkg {
                s.push_str(&format!(" auth={}", truncate(pkg, 64)));
            }
            if let Some(proc_name) = logon_proc {
                s.push_str(&format!(" via {}", truncate(proc_name, 64)));
            }
            (Some("authentication".to_string()), Some(s))
        }
        4625 => {
            let user = first_data_value(data, &["TargetUserName", "SubjectUserName"]);
            let ip = first_data_value(data, &["IpAddress", "WorkstationName"]);
            let status = first_data_value(data, &["Status"]);
            let sub_status = first_data_value(data, &["SubStatus"]);
            let failure_reason = first_data_value(data, &["FailureReason"]);
            let logon_type = first_data_value(data, &["LogonType", "Logon_Type"]);
            let mut s = "Failed logon".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", u));
            }
            if let Some(ipv) = ip {
                s.push_str(&format!(" from {}", ipv));
            }
            if let Some(lt) = logon_type {
                if let Some(name) = describe_logon_type(lt) {
                    s.push_str(&format!(" [type {}]", name));
                }
            }
            if let Some(reason) = failure_reason {
                s.push_str(&format!(" [{}]", normalize_failure_reason_text(reason)));
            }
            if let Some(st) = status {
                s.push_str(&format!(" (status {})", format_status_with_name(st)));
                if let Some(sub) = sub_status {
                    if sub != st {
                        s.push_str(&format!(", substatus {}", format_status_with_name(sub)));
                    }
                }
            } else if let Some(sub) = sub_status {
                s.push_str(&format!(" (substatus {})", format_status_with_name(sub)));
            }
            (Some("authentication".to_string()), Some(s))
        }
        4627 => {
            let user = first_data_value(data, &["TargetUserName", "SubjectUserName"]);
            let groups = first_data_value(data, &["GroupMembership", "Privileges"]);
            let mut s = "Logon group membership information".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(g) = groups {
                s.push_str(&format!(" ({})", truncate(g, 160)));
            }
            (Some("group-membership".to_string()), Some(s))
        }
        4649 => {
            let user = first_data_value(data, &["TargetUserName", "SubjectUserName"]);
            let ip = first_data_value(data, &["IpAddress", "WorkstationName"]);
            let mut s = "Replay attack detected".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(addr) = ip {
                s.push_str(&format!(" from {}", truncate(addr, 120)));
            }
            (Some("authentication".to_string()), Some(s))
        }
        4648 => {
            let user = first_data_value(data, &["TargetUserName", "SubjectUserName"]);
            let process = first_data_value(data, &["ProcessName"]);
            let mut s = "Logon attempted with explicit credentials".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", u));
            }
            if let Some(p) = process {
                s.push_str(&format!(" via {}", p));
            }
            (Some("authentication".to_string()), Some(s))
        }
        4634 | 4647 => {
            let user = first_data_value(data, &["TargetUserName", "SubjectUserName"]);
            let mut s = if event_id == 4647 {
                "User initiated logoff".to_string()
            } else {
                "Logoff".to_string()
            };
            if let Some(u) = user {
                s.push_str(&format!(" for {}", u));
            }
            (Some("authentication".to_string()), Some(s))
        }
        4657 => {
            let object = first_data_value(data, &["ObjectName"]);
            let value = first_data_value(data, &["ObjectValueName", "ValueName"]);
            let process = first_data_value(data, &["ProcessName"]);
            let mut s = "Registry value modified".to_string();
            if let Some(obj) = object {
                s.push_str(&format!(": {}", obj));
            }
            if let Some(v) = value {
                s.push_str(&format!(" [{}]", v));
            }
            if let Some(p) = process {
                s.push_str(&format!(" by {}", p));
            }
            (Some("registry".to_string()), Some(s))
        }
        4616 => {
            let previous = first_data_value(data, &["PreviousTime", "OldTime"]);
            let new_time = first_data_value(data, &["NewTime"]);
            let process = first_data_value(data, &["ProcessName"]);
            let mut s = "System time changed".to_string();
            if let (Some(old), Some(newv)) = (previous, new_time) {
                s.push_str(&format!(": {} -> {}", old, newv));
            } else if let Some(newv) = new_time {
                s.push_str(&format!(": {}", newv));
            }
            if let Some(p) = process {
                s.push_str(&format!(" by {}", p));
            }
            (Some("time-change".to_string()), Some(s))
        }
        4672 => {
            let user = first_data_value(data, &["SubjectUserName", "TargetUserName"]);
            let privileges = first_data_value(data, &["PrivilegeList", "Privileges"]);
            let mut s = "Special privileges assigned to new logon".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(p) = privileges {
                s.push_str(&format!(" ({})", truncate(p, 180)));
            }
            (Some("privilege".to_string()), Some(s))
        }
        4673 | 4674 => {
            let user = first_data_value(data, &["SubjectUserName", "TargetUserName"]);
            let object = first_data_value(data, &["ObjectName", "ObjectServer", "Service"]);
            let mut s = if event_id == 4673 {
                "Sensitive privilege use attempted".to_string()
            } else {
                "Operation attempted on privileged object".to_string()
            };
            if let Some(u) = user {
                s.push_str(&format!(" by {}", u));
            }
            if let Some(obj) = object {
                s.push_str(&format!(" ({})", truncate(obj, 180)));
            }
            (Some("privilege".to_string()), Some(s))
        }
        4697 => {
            let service = first_data_value(data, &["ServiceName", "Service"]);
            let file = first_data_value(data, &["ServiceFileName", "ImagePath"]);
            let mut s = "Service installed".to_string();
            if let Some(name) = service {
                s.push_str(&format!(": {}", name));
            }
            if let Some(path) = file {
                s.push_str(&format!(" ({})", path));
            }
            (Some("persistence".to_string()), Some(s))
        }
        4688 => {
            let proc_name = first_data_value(data, &["NewProcessName", "ProcessName"]);
            let cmd = first_data_value(data, &["CommandLine"]);
            let parent = first_data_value(data, &["ParentProcessName", "CreatorProcessName"]);
            let new_pid = first_data_value(data, &["NewProcessId", "NewProcessID"]);
            let creator_pid = first_data_value(data, &["ProcessId", "CreatorProcessId"]);
            let token = first_data_value(data, &["TokenElevationType", "ElevatedToken"]);
            let mut s = "Process created".to_string();
            if let Some(p) = proc_name {
                s.push_str(&format!(": {}", p));
            }
            if let Some(c) = cmd {
                s.push_str(&format!(" ({})", truncate(c, 240)));
            }
            if let Some(parent_proc) = parent {
                s.push_str(&format!(" parent={}", truncate(parent_proc, 160)));
            }
            if let Some(pid) = new_pid {
                if let Some(display) = format_pid_value(pid) {
                    s.push_str(&format!(" pid={}", display));
                } else {
                    s.push_str(&format!(" pid={}", truncate(pid, 40)));
                }
            }
            if let Some(ppid) = creator_pid {
                if let Some(display) = format_pid_value(ppid) {
                    s.push_str(&format!(" creator_pid={}", display));
                } else {
                    s.push_str(&format!(" creator_pid={}", truncate(ppid, 40)));
                }
            }
            if let Some(tok) = token {
                s.push_str(&format!(" token={}", format_token_elevation(tok)));
            }
            (Some("process".to_string()), Some(s))
        }
        4689 => {
            let proc_name = first_data_value(data, &["ProcessName", "NewProcessName"]);
            let pid = first_data_value(data, &["ProcessId", "NewProcessId"]);
            let status = first_data_value(data, &["Status", "ExitStatus"]);
            let user = first_data_value(data, &["SubjectUserName", "TargetUserName"]);
            let mut s = "Process terminated".to_string();
            if let Some(p) = proc_name {
                s.push_str(&format!(": {}", p));
            }
            if let Some(proc_id) = pid {
                if let Some(display) = format_pid_value(proc_id) {
                    s.push_str(&format!(" pid={}", display));
                } else {
                    s.push_str(&format!(" pid={}", truncate(proc_id, 40)));
                }
            }
            if let Some(u) = user {
                s.push_str(&format!(" by {}", truncate(u, 120)));
            }
            if let Some(st) = status {
                s.push_str(&format!(" (status {})", format_status_with_name(st)));
            }
            (Some("process".to_string()), Some(s))
        }
        4698 => {
            let task = first_data_value(data, &["TaskName", "TaskContent"]);
            let mut s = "Scheduled task created".to_string();
            if let Some(t) = task {
                s.push_str(&format!(": {}", truncate(t, 180)));
            }
            (Some("scheduled-task".to_string()), Some(s))
        }
        4699 => {
            let task = first_data_value(data, &["TaskName", "TaskContent"]);
            let mut s = "Scheduled task deleted".to_string();
            if let Some(t) = task {
                s.push_str(&format!(": {}", truncate(t, 180)));
            }
            (Some("scheduled-task".to_string()), Some(s))
        }
        4702 => {
            let task = first_data_value(data, &["TaskName", "TaskContent"]);
            let mut s = "Scheduled task updated".to_string();
            if let Some(t) = task {
                s.push_str(&format!(": {}", truncate(t, 180)));
            }
            (Some("scheduled-task".to_string()), Some(s))
        }
        4700 | 4701 => {
            let task = first_data_value(data, &["TaskName", "TaskContent", "Task"]);
            let mut s = if event_id == 4700 {
                "Scheduled task enabled".to_string()
            } else {
                "Scheduled task disabled".to_string()
            };
            if let Some(t) = task {
                s.push_str(&format!(": {}", truncate(t, 180)));
            }
            (Some("scheduled-task".to_string()), Some(s))
        }
        4690 | 4691 | 4656 | 4658 | 4660 | 4661 | 4662 | 4663 | 4664 | 4670 => {
            let object = first_data_value(data, &["ObjectName", "ObjectType", "TargetObject"]);
            let process = first_data_value(data, &["ProcessName", "Image", "SubjectLogonId"]);
            let mut s = match event_id {
                4690 => "Handle duplicated to object".to_string(),
                4691 => "Indirect object access requested".to_string(),
                4656 => "Handle requested to object".to_string(),
                4658 => "Handle closed".to_string(),
                4660 => "Object deleted".to_string(),
                4661 => "Handle requested to object class".to_string(),
                4662 => "Operation performed on object".to_string(),
                4663 => "Object access attempt".to_string(),
                4664 => "Hard link creation attempt".to_string(),
                _ => "Object permissions changed".to_string(),
            };
            if let Some(obj) = object {
                s.push_str(&format!(": {}", truncate(obj, 180)));
            }
            if let Some(p) = process {
                s.push_str(&format!(" by {}", truncate(p, 140)));
            }
            (Some("object-access".to_string()), Some(s))
        }
        4703..=4705 => {
            let principal = first_data_value(
                data,
                &[
                    "TargetUserName",
                    "AccountName",
                    "SubjectUserName",
                    "MemberName",
                ],
            );
            let right = first_data_value(data, &["PrivilegeList", "UserRight", "Policy"]);
            let mut s = match event_id {
                4703 => "User right adjusted".to_string(),
                4704 => "User right assigned".to_string(),
                _ => "User right removed".to_string(),
            };
            if let Some(p) = principal {
                s.push_str(&format!(" for {}", truncate(p, 140)));
            }
            if let Some(r) = right {
                s.push_str(&format!(" ({})", truncate(r, 180)));
            }
            (Some("privilege-policy".to_string()), Some(s))
        }
        4719 => {
            let category = first_data_value(data, &["CategoryId", "SubcategoryGuid"]);
            let changes = first_data_value(data, &["AuditPolicyChanges"]);
            let mut s = "System audit policy changed".to_string();
            if let Some(c) = category {
                s.push_str(&format!(" [{}]", c));
            }
            if let Some(ch) = changes {
                s.push_str(&format!(" {}", ch));
            }
            (Some("audit-policy".to_string()), Some(s))
        }
        4713 => {
            let policy = first_data_value(data, &["PolicyChange", "CategoryId", "SubcategoryGuid"]);
            let mut s = "Kerberos policy changed".to_string();
            if let Some(p) = policy {
                s.push_str(&format!(" ({})", truncate(p, 160)));
            }
            (Some("audit-policy".to_string()), Some(s))
        }
        4902 | 4904 | 4905 | 4906 | 4907 | 4908 | 4909 | 4910 | 4911 | 4912 => {
            let object = first_data_value(data, &["ObjectName", "CategoryId", "SubcategoryGuid"]);
            let mut s = match event_id {
                4902 => "Per-user audit policy table created".to_string(),
                4904 => "Security event source registered".to_string(),
                4905 => "Security event source unregistered".to_string(),
                4906 => "CrashOnAuditFail value changed".to_string(),
                4907 => "Auditing settings changed".to_string(),
                4908 => "Special Groups logon table modified".to_string(),
                4909 => "TBS local policy changed".to_string(),
                4910 => "Crypto key access audited".to_string(),
                4911 => "Resource attribute modified".to_string(),
                _ => "Per-user audit policy changed".to_string(),
            };
            if let Some(o) = object {
                s.push_str(&format!(" ({})", truncate(o, 160)));
            }
            (Some("audit-policy".to_string()), Some(s))
        }
        4720 => {
            let user = first_data_value(data, &["TargetUserName", "SamAccountName"]);
            let mut s = "User account created".to_string();
            if let Some(u) = user {
                s.push_str(&format!(": {}", u));
            }
            (Some("account-management".to_string()), Some(s))
        }
        4738 => {
            let user = first_data_value(data, &["TargetUserName", "SamAccountName"]);
            let mut s = "User account changed".to_string();
            if let Some(u) = user {
                s.push_str(&format!(": {}", u));
            }
            (Some("account-management".to_string()), Some(s))
        }
        4741..=4743 => {
            let machine = first_data_value(data, &["TargetUserName", "SamAccountName"]);
            let mut s = match event_id {
                4741 => "Computer account created".to_string(),
                4742 => "Computer account changed".to_string(),
                _ => "Computer account deleted".to_string(),
            };
            if let Some(m) = machine {
                s.push_str(&format!(": {}", m));
            }
            (Some("account-management".to_string()), Some(s))
        }
        4722 | 4725 => {
            let user = first_data_value(data, &["TargetUserName", "SamAccountName"]);
            let mut s = if event_id == 4722 {
                "User account enabled".to_string()
            } else {
                "User account disabled".to_string()
            };
            if let Some(u) = user {
                s.push_str(&format!(": {}", u));
            }
            (Some("account-management".to_string()), Some(s))
        }
        4723 | 4724 => {
            let user = first_data_value(data, &["TargetUserName", "SamAccountName"]);
            let mut s = if event_id == 4723 {
                "Password change attempt".to_string()
            } else {
                "Password reset attempt".to_string()
            };
            if let Some(u) = user {
                s.push_str(&format!(" for {}", u));
            }
            (Some("account-management".to_string()), Some(s))
        }
        4728 | 4732 | 4756 => {
            let member = first_data_value(data, &["MemberName", "TargetUserName"]);
            let group = first_data_value(data, &["GroupName", "TargetSid"]);
            let mut s = "Group membership added".to_string();
            if let Some(m) = member {
                s.push_str(&format!(": {}", m));
            }
            if let Some(g) = group {
                s.push_str(&format!(" -> {}", g));
            }
            (Some("group-membership".to_string()), Some(s))
        }
        4729 | 4733 | 4757 => {
            let member = first_data_value(data, &["MemberName", "TargetUserName"]);
            let group = first_data_value(data, &["GroupName", "TargetSid"]);
            let mut s = "Group membership removed".to_string();
            if let Some(m) = member {
                s.push_str(&format!(": {}", m));
            }
            if let Some(g) = group {
                s.push_str(&format!(" from {}", g));
            }
            (Some("group-membership".to_string()), Some(s))
        }
        4735 | 4737 => {
            let group = first_data_value(data, &["GroupName", "TargetUserName", "TargetSid"]);
            let mut s = if event_id == 4735 {
                "Security-enabled local group changed".to_string()
            } else {
                "Security-enabled global group changed".to_string()
            };
            if let Some(g) = group {
                s.push_str(&format!(": {}", truncate(g, 140)));
            }
            (Some("group-membership".to_string()), Some(s))
        }
        4754 | 4755 => {
            let group = first_data_value(data, &["GroupName", "TargetUserName", "TargetSid"]);
            let mut s = if event_id == 4754 {
                "Security-enabled universal group created".to_string()
            } else {
                "Security-enabled universal group changed".to_string()
            };
            if let Some(g) = group {
                s.push_str(&format!(": {}", truncate(g, 140)));
            }
            (Some("group-membership".to_string()), Some(s))
        }
        4726 => {
            let user = first_data_value(data, &["TargetUserName", "SamAccountName"]);
            let mut s = "User account deleted".to_string();
            if let Some(u) = user {
                s.push_str(&format!(": {}", truncate(u, 120)));
            }
            (Some("account-management".to_string()), Some(s))
        }
        4740 => {
            let user = first_data_value(data, &["TargetUserName", "SubjectUserName"]);
            let mut s = "User account locked out".to_string();
            if let Some(u) = user {
                s.push_str(&format!(": {}", u));
            }
            (Some("account-management".to_string()), Some(s))
        }
        4768 => {
            let user =
                first_data_value(data, &["TargetUserName", "AccountName", "SubjectUserName"]);
            let ip = first_data_value(data, &["IpAddress", "ClientAddress"]);
            let etype = first_data_value(data, &["TicketEncryptionType"]);
            let status = first_data_value(data, &["Status", "FailureCode"]);
            let mut s = "Kerberos TGT requested".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(addr) = ip {
                s.push_str(&format!(" from {}", truncate(addr, 120)));
            }
            if let Some(enc) = etype {
                if let Some(name) = describe_kerberos_encryption_type(enc) {
                    s.push_str(&format!(" [etype {}]", name));
                } else {
                    s.push_str(&format!(" [etype {}]", truncate(enc, 40)));
                }
            }
            if let Some(st) = status {
                s.push_str(&format!(" (status {})", format_status_with_name(st)));
            }
            (Some("kerberos".to_string()), Some(s))
        }
        4769 => {
            let user =
                first_data_value(data, &["TargetUserName", "AccountName", "SubjectUserName"]);
            let service = first_data_value(data, &["ServiceName", "TargetServerName"]);
            let ip = first_data_value(data, &["IpAddress", "ClientAddress"]);
            let etype = first_data_value(data, &["TicketEncryptionType"]);
            let status = first_data_value(data, &["Status", "FailureCode"]);
            let mut s = "Kerberos service ticket requested".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(svc) = service {
                s.push_str(&format!(" to {}", truncate(svc, 140)));
            }
            if let Some(addr) = ip {
                s.push_str(&format!(" from {}", truncate(addr, 120)));
            }
            if let Some(enc) = etype {
                if let Some(name) = describe_kerberos_encryption_type(enc) {
                    s.push_str(&format!(" [etype {}]", name));
                } else {
                    s.push_str(&format!(" [etype {}]", truncate(enc, 40)));
                }
            }
            if let Some(st) = status {
                s.push_str(&format!(" (status {})", format_status_with_name(st)));
            }
            (Some("kerberos".to_string()), Some(s))
        }
        4767 => {
            let user = first_data_value(data, &["TargetUserName", "SamAccountName"]);
            let mut s = "User account unlocked".to_string();
            if let Some(u) = user {
                s.push_str(&format!(": {}", u));
            }
            (Some("account-management".to_string()), Some(s))
        }
        4765 | 4766 => {
            let user = first_data_value(data, &["TargetUserName", "SubjectUserName"]);
            let sid = first_data_value(data, &["SidHistory", "Sid", "TargetSid"]);
            let mut s = if event_id == 4765 {
                "SID history added to account".to_string()
            } else {
                "SID history add attempt failed".to_string()
            };
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(v) = sid {
                s.push_str(&format!(" ({})", truncate(v, 140)));
            }
            (Some("account-management".to_string()), Some(s))
        }
        4774 => {
            let user = first_data_value(data, &["TargetUserName", "SubjectUserName"]);
            let workstation = first_data_value(data, &["Workstation", "WorkstationName"]);
            let mut s = "Account mapped for logon".to_string();
            if let Some(u) = user {
                s.push_str(&format!(": {}", truncate(u, 120)));
            }
            if let Some(w) = workstation {
                s.push_str(&format!(" from {}", truncate(w, 120)));
            }
            (Some("authentication".to_string()), Some(s))
        }
        4776 => {
            let user = first_data_value(data, &["TargetUserName", "AccountName", "LogonAccount"]);
            let workstation = first_data_value(data, &["Workstation", "WorkstationName"]);
            let package = first_data_value(data, &["PackageName", "AuthenticationPackage"]);
            let status = first_data_value(data, &["Status", "ErrorCode"]);
            let mut s = "NTLM credential validation".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(ws) = workstation {
                s.push_str(&format!(" from {}", truncate(ws, 120)));
            }
            if let Some(pkg) = package {
                s.push_str(&format!(" [{}]", truncate(pkg, 80)));
            }
            if let Some(st) = status {
                s.push_str(&format!(" (status {})", format_status_with_name(st)));
            }
            (Some("authentication".to_string()), Some(s))
        }
        4778 | 4779 => {
            let user = first_data_value(data, &["TargetUserName", "User"]);
            let session = first_data_value(data, &["SessionName", "SessionID"]);
            let mut s = if event_id == 4778 {
                "Session reconnected".to_string()
            } else {
                "Session disconnected".to_string()
            };
            if let Some(u) = user {
                s.push_str(&format!(" for {}", u));
            }
            if let Some(sess) = session {
                s.push_str(&format!(" ({})", sess));
            }
            (Some("session".to_string()), Some(s))
        }
        4770..=4773 => {
            let user =
                first_data_value(data, &["TargetUserName", "AccountName", "SubjectUserName"]);
            let service =
                first_data_value(data, &["ServiceName", "ServiceSid", "TargetServerName"]);
            let addr = first_data_value(data, &["IpAddress", "ClientAddress", "WorkstationName"]);
            let status = first_data_value(data, &["Status", "FailureCode", "ErrorCode"]);
            let etype = first_data_value(data, &["TicketEncryptionType"]);
            let mut s = match event_id {
                4770 => "Kerberos service ticket renewed".to_string(),
                4771 => "Kerberos pre-authentication failed".to_string(),
                4772 => "Kerberos authentication ticket request failed".to_string(),
                _ => "Kerberos service ticket request failed".to_string(),
            };
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(svc) = service {
                s.push_str(&format!(" ({})", truncate(svc, 140)));
            }
            if let Some(ip) = addr {
                s.push_str(&format!(" from {}", truncate(ip, 120)));
            }
            if let Some(enc) = etype {
                if let Some(name) = describe_kerberos_encryption_type(enc) {
                    s.push_str(&format!(" [etype {}]", name));
                } else {
                    s.push_str(&format!(" [etype {}]", truncate(enc, 40)));
                }
            }
            if let Some(st) = status {
                s.push_str(&format!(" (status {})", format_status_with_name(st)));
            }
            (Some("kerberos".to_string()), Some(s))
        }
        4800..=4803 => {
            let user =
                first_data_value(data, &["TargetUserName", "AccountName", "SubjectUserName"]);
            let mut s = match event_id {
                4800 => "Workstation locked".to_string(),
                4801 => "Workstation unlocked".to_string(),
                4802 => "Screen saver invoked".to_string(),
                _ => "Screen saver dismissed".to_string(),
            };
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            (Some("session".to_string()), Some(s))
        }
        4798 | 4799 => {
            let user =
                first_data_value(data, &["TargetUserName", "SubjectUserName", "AccountName"]);
            let target = first_data_value(data, &["TargetSid", "GroupName", "LocalGroup"]);
            let mut s = if event_id == 4798 {
                "User local group membership enumerated".to_string()
            } else {
                "Security-enabled local group membership enumerated".to_string()
            };
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(t) = target {
                s.push_str(&format!(" ({})", truncate(t, 160)));
            }
            (Some("group-membership".to_string()), Some(s))
        }
        4825 | 4826 => {
            let detail =
                first_data_value(data, &["CrashOnAuditFailValue", "LoadedEntries", "Data"]);
            let mut s = if event_id == 4825 {
                "CrashOnAuditFail value changed".to_string()
            } else {
                "Boot Configuration Data loaded".to_string()
            };
            if let Some(d) = detail {
                s.push_str(&format!(" ({})", truncate(d, 160)));
            }
            (Some("security-policy".to_string()), Some(s))
        }
        4964 => {
            let user = first_data_value(data, &["TargetUserName", "SubjectUserName"]);
            let groups = first_data_value(data, &["SpecialGroups", "GroupMembership"]);
            let mut s = "Special groups assigned to new logon".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(g) = groups {
                s.push_str(&format!(" ({})", truncate(g, 160)));
            }
            (Some("privilege".to_string()), Some(s))
        }
        4886..=4892 => {
            let request = first_data_value(data, &["RequestId", "RequestID", "Template", "CAName"]);
            let mut s = match event_id {
                4886 => "Certificate Services received certificate request".to_string(),
                4887 => "Certificate Services approved certificate request".to_string(),
                4888 => "Certificate Services denied certificate request".to_string(),
                4890 => "Certificate Services manager settings changed".to_string(),
                4891 => "Certificate Services configuration changed".to_string(),
                _ => "Certificate Services property changed".to_string(),
            };
            if let Some(r) = request {
                s.push_str(&format!(" ({})", truncate(r, 140)));
            }
            (Some("certificate-services".to_string()), Some(s))
        }
        5038 | 5039 => {
            let file = first_data_value(data, &["FileName", "ImageName", "Path"]);
            let mut s = if event_id == 5038 {
                "Code integrity check failed".to_string()
            } else {
                "Code integrity image hash could not be validated".to_string()
            };
            if let Some(f) = file {
                s.push_str(&format!(": {}", truncate(f, 180)));
            }
            (Some("code-integrity".to_string()), Some(s))
        }
        5140 | 5142 | 5143 | 5144 | 5145 => {
            let share = first_data_value(data, &["ShareName", "ShareLocalPath", "ObjectName"]);
            let user = first_data_value(data, &["SubjectUserName", "TargetUserName"]);
            let src = first_data_value(data, &["IpAddress", "SourceAddress", "ClientAddress"]);
            let access = first_data_value(data, &["AccessMask", "AccessList", "DesiredAccess"]);
            let mut s = match event_id {
                5140 => "Network share accessed".to_string(),
                5142 => "Network share added".to_string(),
                5143 => "Network share modified".to_string(),
                5144 => "Network share deleted".to_string(),
                _ => "Network share access check".to_string(),
            };
            if let Some(name) = share {
                s.push_str(&format!(": {}", truncate(name, 180)));
            }
            if let Some(u) = user {
                s.push_str(&format!(" by {}", truncate(u, 120)));
            }
            if let Some(ip) = src {
                s.push_str(&format!(" from {}", truncate(ip, 120)));
            }
            if let Some(mask) = access {
                s.push_str(&format!(" access={}", truncate(mask, 80)));
            }
            (Some("network-share".to_string()), Some(s))
        }
        5146..=5149 => {
            let share = first_data_value(data, &["ShareName", "ShareLocalPath", "ObjectName"]);
            let object =
                first_data_value(data, &["RelativeTargetName", "AccessMask", "AccessList"]);
            let user =
                first_data_value(data, &["SubjectUserName", "TargetUserName", "AccountName"]);
            let status = first_data_value(data, &["Status", "ErrorCode"]);
            let mut s = match event_id {
                5146 => "Detailed file share access denied".to_string(),
                5147 => "Detailed file share access granted".to_string(),
                5148 => "Detailed file share access checked".to_string(),
                _ => "Detailed file share object checked".to_string(),
            };
            if let Some(name) = share {
                s.push_str(&format!(": {}", truncate(name, 180)));
            }
            if let Some(obj) = object {
                s.push_str(&format!(" ({})", truncate(obj, 160)));
            }
            if let Some(u) = user {
                s.push_str(&format!(" by {}", truncate(u, 120)));
            }
            if let Some(st) = status {
                s.push_str(&format!(" status={}", format_status_with_name(st)));
            }
            (Some("network-share".to_string()), Some(s))
        }
        5150..=5155 => {
            let src = first_data_value(data, &["SourceAddress", "LocalAddress", "SrcAddress"]);
            let dst = first_data_value(
                data,
                &["DestAddress", "RemoteAddress", "DestinationAddress"],
            );
            let app = first_data_value(data, &["Application", "ProcessName"]);
            let mut s = match event_id {
                5150 | 5151 => "Windows Filtering Platform blocked packet".to_string(),
                5152 | 5153 => "Windows Filtering Platform dropped packet".to_string(),
                5154 => "Windows Filtering Platform allowed bind/listen".to_string(),
                _ => "Windows Filtering Platform blocked bind/listen".to_string(),
            };
            if let Some(a) = app {
                s.push_str(&format!(" [{}]", truncate(a, 140)));
            }
            if let (Some(sa), Some(da)) = (src, dst) {
                s.push_str(&format!(" {} -> {}", sa, da));
            }
            (Some("network".to_string()), Some(s))
        }
        5156..=5159 => {
            let src = first_data_value(data, &["SourceAddress", "LocalAddress", "SrcAddress"]);
            let src_port = first_data_value(data, &["SourcePort", "LocalPort", "SrcPort"]);
            let dst = first_data_value(
                data,
                &["DestAddress", "RemoteAddress", "DestinationAddress"],
            );
            let dst_port = first_data_value(data, &["DestPort", "RemotePort", "DestinationPort"]);
            let app = first_data_value(data, &["Application", "ProcessName"]);
            let mut s = match event_id {
                5156 => "Allowed network connection".to_string(),
                5157 => "Blocked network connection".to_string(),
                5158 => "Network bind/accept event".to_string(),
                _ => "Dropped network packet".to_string(),
            };
            if let Some(a) = app {
                s.push_str(&format!(" [{}]", a));
            }
            if let (Some(sa), Some(sp), Some(da), Some(dp)) = (src, src_port, dst, dst_port) {
                s.push_str(&format!(" {}:{} -> {}:{}", sa, sp, da, dp));
            } else if let (Some(sa), Some(da)) = (src, dst) {
                s.push_str(&format!(" {} -> {}", sa, da));
            }
            (Some("network".to_string()), Some(s))
        }
        7045 => {
            let service = first_data_value(data, &["ServiceName"]);
            let image = first_data_value(data, &["ImagePath", "ServiceFileName"]);
            let start_type = first_data_value(data, &["StartType"]);
            let account = first_data_value(data, &["AccountName", "ServiceAccount", "UserName"]);
            let mut s = "Service installed".to_string();
            if let Some(n) = service {
                s.push_str(&format!(": {}", n));
            }
            if let Some(i) = image {
                s.push_str(&format!(" ({})", i));
            }
            if let Some(st) = start_type {
                s.push_str(&format!(" start={}", truncate(st, 60)));
            }
            if let Some(acct) = account {
                s.push_str(&format!(" account={}", truncate(acct, 120)));
            }
            (Some("persistence".to_string()), Some(s))
        }
        7040 => {
            let service = first_data_value(data, &["ServiceName", "Param1"]);
            let old_type = first_data_value(data, &["OldStartType", "Param2"]);
            let new_type = first_data_value(data, &["NewStartType", "Param3"]);
            let mut s = "Service start type changed".to_string();
            if let Some(name) = service {
                s.push_str(&format!(": {}", name));
            }
            if let (Some(old), Some(newv)) = (old_type, new_type) {
                s.push_str(&format!(" ({} -> {})", old, newv));
            }
            (Some("persistence".to_string()), Some(s))
        }
        7034 if is_system_source => {
            let service = first_data_value(data, &["ServiceName", "Param1"]);
            let mut s = "Service terminated unexpectedly".to_string();
            if let Some(name) = service {
                s.push_str(&format!(": {}", name));
            }
            (Some("service".to_string()), Some(s))
        }
        7036 if is_system_source => {
            let service = first_data_value(data, &["ServiceName", "Param1"]);
            let state = first_data_value(data, &["State", "Param2"]);
            let mut s = "Service state change".to_string();
            if let Some(name) = service {
                s.push_str(&format!(": {}", name));
            }
            if let Some(v) = state {
                s.push_str(&format!(" -> {}", truncate(v, 120)));
            }
            (Some("service".to_string()), Some(s))
        }
        1074 if is_system_source => {
            let process = first_data_value(data, &["Process", "ProcessName", "Param4"]);
            let reason = first_data_value(data, &["Reason", "Param5"]);
            let mut s = "System shutdown/restart initiated".to_string();
            if let Some(p) = process {
                s.push_str(&format!(" by {}", truncate(p, 180)));
            }
            if let Some(r) = reason {
                s.push_str(&format!(" ({})", truncate(r, 180)));
            }
            (Some("system".to_string()), Some(s))
        }
        1100 if is_eventlog_source => (
            Some("tamper".to_string()),
            Some("Event logging service shutdown".to_string()),
        ),
        1102 => (
            Some("tamper".to_string()),
            Some("Audit log cleared".to_string()),
        ),
        104 if is_eventlog_source => (
            Some("tamper".to_string()),
            Some("Event log cleared".to_string()),
        ),
        6005 if is_system_source => (
            Some("system".to_string()),
            Some("Event log service started (system startup)".to_string()),
        ),
        6006 if is_system_source => (
            Some("system".to_string()),
            Some("Event log service stopped (clean shutdown)".to_string()),
        ),
        6008 if is_system_source => (
            Some("system".to_string()),
            Some("Previous shutdown was unexpected".to_string()),
        ),
        41 if source_lc.contains("kernel-power") => (
            Some("system".to_string()),
            Some("Kernel-Power critical event (unexpected restart/shutdown)".to_string()),
        ),
        1 if is_sysmon => {
            let image = first_data_value(data, &["Image", "ProcessName"]);
            let cmd = first_data_value(data, &["CommandLine"]);
            let parent = first_data_value(data, &["ParentImage"]);
            let mut s = "Sysmon process create".to_string();
            if let Some(i) = image {
                s.push_str(&format!(": {}", i));
            }
            if let Some(c) = cmd {
                s.push_str(&format!(" ({})", truncate(c, 180)));
            }
            if let Some(p) = parent {
                s.push_str(&format!(" parent={}", p));
            }
            (Some("sysmon-process".to_string()), Some(s))
        }
        2 if is_sysmon => {
            let image = first_data_value(data, &["Image", "ProcessName"]);
            let target = first_data_value(data, &["TargetFilename", "TargetFileName"]);
            let old_time = first_data_value(data, &["CreationUtcTime", "PreviousCreationUtcTime"]);
            let mut s = "Sysmon file creation time changed".to_string();
            if let Some(i) = image {
                s.push_str(&format!(" by {}", i));
            }
            if let Some(t) = target {
                s.push_str(&format!(": {}", t));
            }
            if let Some(ot) = old_time {
                s.push_str(&format!(" ({})", truncate(ot, 120)));
            }
            (Some("sysmon-file-timestamp".to_string()), Some(s))
        }
        3 if is_sysmon => {
            let image = first_data_value(data, &["Image", "ProcessName"]);
            let src = first_data_value(data, &["SourceIp", "SourceAddress"]);
            let src_port = first_data_value(data, &["SourcePort"]);
            let dst = first_data_value(data, &["DestinationIp", "DestAddress", "RemoteAddress"]);
            let dst_port = first_data_value(data, &["DestinationPort", "DestPort", "RemotePort"]);
            let mut s = "Sysmon network connection".to_string();
            if let Some(i) = image {
                s.push_str(&format!(" [{}]", i));
            }
            if let (Some(sa), Some(sp), Some(da), Some(dp)) = (src, src_port, dst, dst_port) {
                s.push_str(&format!(" {}:{} -> {}:{}", sa, sp, da, dp));
            } else if let (Some(sa), Some(da)) = (src, dst) {
                s.push_str(&format!(" {} -> {}", sa, da));
            }
            (Some("sysmon-network".to_string()), Some(s))
        }
        4 if is_sysmon => (
            Some("sysmon-state".to_string()),
            Some("Sysmon service state changed".to_string()),
        ),
        5 if is_sysmon => {
            let image = first_data_value(data, &["Image", "ProcessName"]);
            let mut s = "Sysmon process terminated".to_string();
            if let Some(i) = image {
                s.push_str(&format!(": {}", i));
            }
            (Some("sysmon-process".to_string()), Some(s))
        }
        6 if is_sysmon => {
            let image = first_data_value(data, &["ImageLoaded", "Image"]);
            let signed = first_data_value(data, &["Signed", "SignatureStatus"]);
            let mut s = "Sysmon driver loaded".to_string();
            if let Some(i) = image {
                s.push_str(&format!(": {}", i));
            }
            if let Some(sig) = signed {
                s.push_str(&format!(" signed={}", truncate(sig, 80)));
            }
            (Some("sysmon-driver".to_string()), Some(s))
        }
        7 if is_sysmon => {
            let image = first_data_value(data, &["Image"]);
            let loaded = first_data_value(data, &["ImageLoaded"]);
            let mut s = "Sysmon image loaded".to_string();
            if let Some(i) = image {
                s.push_str(&format!(" by {}", i));
            }
            if let Some(l) = loaded {
                s.push_str(&format!(": {}", l));
            }
            (Some("sysmon-module-load".to_string()), Some(s))
        }
        8 if is_sysmon => {
            let source_image = first_data_value(data, &["SourceImage", "Image"]);
            let target_image = first_data_value(data, &["TargetImage"]);
            let start_module = first_data_value(data, &["StartModule", "StartFunction"]);
            let mut s = "Sysmon create remote thread".to_string();
            if let Some(src) = source_image {
                s.push_str(&format!(" source={}", src));
            }
            if let Some(dst) = target_image {
                s.push_str(&format!(" target={}", dst));
            }
            if let Some(module) = start_module {
                s.push_str(&format!(" start={}", module));
            }
            (Some("sysmon-injection".to_string()), Some(s))
        }
        10 if is_sysmon => {
            let source_image = first_data_value(data, &["SourceImage", "Image"]);
            let target_image = first_data_value(data, &["TargetImage"]);
            let granted = first_data_value(data, &["GrantedAccess"]);
            let mut s = "Sysmon process access".to_string();
            if let Some(src) = source_image {
                s.push_str(&format!(" source={}", src));
            }
            if let Some(dst) = target_image {
                s.push_str(&format!(" target={}", dst));
            }
            if let Some(g) = granted {
                s.push_str(&format!(" access={}", g));
            }
            (Some("sysmon-process-access".to_string()), Some(s))
        }
        11 if is_sysmon => {
            let image = first_data_value(data, &["Image"]);
            let target = first_data_value(data, &["TargetFilename", "TargetFileName"]);
            let mut s = "Sysmon file create".to_string();
            if let Some(i) = image {
                s.push_str(&format!(" by {}", i));
            }
            if let Some(t) = target {
                s.push_str(&format!(": {}", t));
            }
            (Some("sysmon-file".to_string()), Some(s))
        }
        9 if is_sysmon => {
            let image = first_data_value(data, &["Image", "ProcessName"]);
            let device = first_data_value(data, &["Device", "DeviceName"]);
            let mut s = "Sysmon raw disk access".to_string();
            if let Some(i) = image {
                s.push_str(&format!(" by {}", i));
            }
            if let Some(d) = device {
                s.push_str(&format!(" ({})", truncate(d, 120)));
            }
            (Some("sysmon-raw-access".to_string()), Some(s))
        }
        15 if is_sysmon => {
            let image = first_data_value(data, &["Image"]);
            let target = first_data_value(data, &["TargetFilename", "TargetFileName"]);
            let mut s = "Sysmon file stream created".to_string();
            if let Some(i) = image {
                s.push_str(&format!(" by {}", i));
            }
            if let Some(t) = target {
                s.push_str(&format!(": {}", truncate(t, 180)));
            }
            (Some("sysmon-file".to_string()), Some(s))
        }
        16 if is_sysmon => {
            let cfg = first_data_value(data, &["Configuration", "RuleName", "SchemaVersion"]);
            let mut s = "Sysmon service configuration changed".to_string();
            if let Some(v) = cfg {
                s.push_str(&format!(" ({})", truncate(v, 180)));
            }
            (Some("sysmon-state".to_string()), Some(s))
        }
        17 | 18 if is_sysmon => {
            let pipe = first_data_value(data, &["PipeName", "PipePath"]);
            let image = first_data_value(data, &["Image"]);
            let mut s = if event_id == 17 {
                "Sysmon pipe created".to_string()
            } else {
                "Sysmon pipe connected".to_string()
            };
            if let Some(p) = pipe {
                s.push_str(&format!(": {}", truncate(p, 180)));
            }
            if let Some(i) = image {
                s.push_str(&format!(" by {}", i));
            }
            (Some("sysmon-pipe".to_string()), Some(s))
        }
        19..=21 if is_sysmon => {
            let consumer = first_data_value(
                data,
                &[
                    "Operation",
                    "EventNamespace",
                    "Filter",
                    "Consumer",
                    "ConsumerType",
                ],
            );
            let mut s = if event_id == 19 {
                "Sysmon WMI event filter activity".to_string()
            } else if event_id == 20 {
                "Sysmon WMI event consumer activity".to_string()
            } else {
                "Sysmon WMI event binding activity".to_string()
            };
            if let Some(c) = consumer {
                s.push_str(&format!(" ({})", truncate(c, 180)));
            }
            (Some("sysmon-wmi".to_string()), Some(s))
        }
        24 if is_sysmon => {
            let image = first_data_value(data, &["Image", "ProcessName"]);
            let mut s = "Sysmon clipboard change".to_string();
            if let Some(i) = image {
                s.push_str(&format!(" by {}", i));
            }
            (Some("sysmon-clipboard".to_string()), Some(s))
        }
        25 if is_sysmon => {
            let image = first_data_value(data, &["Image", "ProcessName"]);
            let typ = first_data_value(data, &["Type"]);
            let mut s = "Sysmon process tampering".to_string();
            if let Some(i) = image {
                s.push_str(&format!(": {}", i));
            }
            if let Some(t) = typ {
                s.push_str(&format!(" ({})", truncate(t, 120)));
            }
            (Some("sysmon-process".to_string()), Some(s))
        }
        27..=29 if is_sysmon => {
            let target = first_data_value(data, &["TargetFilename", "TargetFileName", "Image"]);
            let mut s = match event_id {
                27 => "Sysmon executable block event".to_string(),
                28 => "Sysmon executable shimming event".to_string(),
                _ => "Sysmon executable detection event".to_string(),
            };
            if let Some(t) = target {
                s.push_str(&format!(": {}", truncate(t, 180)));
            }
            (Some("sysmon-file".to_string()), Some(s))
        }
        30 | 31 if is_sysmon => {
            let image = first_data_value(data, &["Image", "ProcessName"]);
            let target = first_data_value(data, &["TargetFilename", "TargetFileName", "Path"]);
            let mut s = if event_id == 30 {
                "Sysmon file block shredding event".to_string()
            } else {
                "Sysmon file delete detected".to_string()
            };
            if let Some(i) = image {
                s.push_str(&format!(" by {}", truncate(i, 140)));
            }
            if let Some(t) = target {
                s.push_str(&format!(": {}", truncate(t, 180)));
            }
            (Some("sysmon-file".to_string()), Some(s))
        }
        255 if is_sysmon => (
            Some("sysmon-state".to_string()),
            Some("Sysmon error event".to_string()),
        ),
        1149 if source_lc.contains("terminalservices") => {
            let user = first_data_value(data, &["User", "TargetUserName"]);
            let ip = first_data_value(data, &["Address", "IpAddress", "ClientAddress"]);
            let mut s = "Remote Desktop authentication succeeded".to_string();
            if let Some(u) = user {
                s.push_str(&format!(" for {}", truncate(u, 120)));
            }
            if let Some(addr) = ip {
                s.push_str(&format!(" from {}", truncate(addr, 120)));
            }
            (Some("remote-access".to_string()), Some(s))
        }
        12..=14 if is_sysmon => {
            let target = first_data_value(data, &["TargetObject", "ObjectName"]);
            let details = first_data_value(data, &["Details", "EventType"]);
            let mut s = "Sysmon registry event".to_string();
            if let Some(t) = target {
                s.push_str(&format!(": {}", t));
            }
            if let Some(d) = details {
                s.push_str(&format!(" ({})", truncate(d, 120)));
            }
            (Some("sysmon-registry".to_string()), Some(s))
        }
        22 if is_sysmon => {
            let query = first_data_value(data, &["QueryName"]);
            let results = first_data_value(data, &["QueryResults"]);
            let mut s = "Sysmon DNS query".to_string();
            if let Some(q) = query {
                s.push_str(&format!(": {}", q));
            }
            if let Some(r) = results {
                s.push_str(&format!(" -> {}", truncate(r, 160)));
            }
            (Some("sysmon-dns".to_string()), Some(s))
        }
        23 | 26 if is_sysmon => {
            let target = first_data_value(data, &["TargetFilename", "TargetFileName"]);
            let mut s = "Sysmon file delete event".to_string();
            if let Some(t) = target {
                s.push_str(&format!(": {}", t));
            }
            (Some("sysmon-file".to_string()), Some(s))
        }
        4104 => {
            let script =
                first_data_value(data, &["ScriptBlockText", "Message"]).unwrap_or("Script block");
            (
                Some("powershell".to_string()),
                Some(format!(
                    "PowerShell script block: {}",
                    truncate(script, 180)
                )),
            )
        }
        _ => {
            let known = get_known_security_event_description(event_id);
            if known != "Unknown event" {
                // Keep broad fallback IDs scoped to security-channel style sources.
                if known == "Extended security auditing event"
                    && !source_lc.contains("security")
                    && !source_lc.contains("audit")
                {
                    // Continue to other source-specific fallbacks below.
                } else {
                    return (Some("security-event".to_string()), Some(known.to_string()));
                }
            }
            if source_lc.contains("powershell") {
                if let Some(script) = first_data_value(data, &["ScriptBlockText", "ContextInfo"]) {
                    return (
                        Some("powershell".to_string()),
                        Some(format!("PowerShell activity: {}", truncate(script, 180))),
                    );
                }
            }
            (
                None,
                message
                    .map(|m| m.trim().to_string())
                    .filter(|m| !m.is_empty()),
            )
        }
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (idx, ch) in s.chars().enumerate() {
        if idx >= max_chars {
            out.push_str("...");
            break;
        }
        out.push(ch);
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() || needle.len() > haystack.len() {
        return None;
    }
    let max = haystack.len() - needle.len();
    let mut i = from;
    while i <= max {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn extract_event_xml_fragments_ascii(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let start_pat = b"<Event";
    let end_pat = b"</Event>";
    let mut cursor = 0usize;

    while let Some(start) = find_subslice(data, start_pat, cursor) {
        let Some(end) = find_subslice(data, end_pat, start) else {
            break;
        };
        let end_idx = end + end_pat.len();
        if end_idx <= data.len() {
            let slice = &data[start..end_idx];
            if let Ok(text) = std::str::from_utf8(slice) {
                out.push(text.to_string());
            }
        }
        cursor = end_idx;
        if out.len() >= 2000 {
            break;
        }
    }
    out
}

fn extract_event_xml_fragments_utf16(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let start_pat = utf16_pattern("<Event");
    let end_pat = utf16_pattern("</Event>");
    let mut cursor = 0usize;

    while let Some(start) = find_subslice(data, &start_pat, cursor) {
        let Some(end) = find_subslice(data, &end_pat, start) else {
            break;
        };
        let end_idx = end + end_pat.len();
        if end_idx <= data.len() {
            let slice = &data[start..end_idx];
            let text = decode_utf16le(slice);
            if text.contains("<Event") && text.contains("</Event>") {
                out.push(text);
            }
        }
        cursor = end_idx;
        if out.len() >= 2000 {
            break;
        }
    }
    out
}

fn utf16_pattern(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        out.push(*b);
        out.push(0);
    }
    out
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        units.push(u16::from_le_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

fn extract_null_terminated_ascii(data: &[u8], start: usize, max_len: usize) -> Option<String> {
    if start >= data.len() {
        return None;
    }
    let end = (start + max_len).min(data.len());
    let len = data[start..end]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(end - start);
    if len == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&data[start..start + len]).to_string())
}

fn filetime_to_unix(filetime: u64) -> Option<u64> {
    if filetime == 0 {
        return None;
    }
    let seconds = filetime / 10_000_000;
    if seconds < FILETIME_UNIX_EPOCH_OFFSET {
        return None;
    }
    Some(seconds - FILETIME_UNIX_EPOCH_OFFSET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_evtx_ascii_xml_event() {
        let xml = r#"<Event>
<System>
<Provider Name="Microsoft-Windows-Security-Auditing"/>
<EventID>4625</EventID>
<Level>2</Level>
<TimeCreated SystemTime="2026-03-09T10:00:00.000Z"/>
<Computer>WIN11LAB</Computer>
<Security UserID="S-1-5-18"/>
</System>
<EventData><Data Name="IpAddress">10.0.0.5</Data></EventData>
</Event>"#;

        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.event_id, 4625);
        assert_eq!(e.level, 2);
        assert_eq!(e.level_name.as_deref(), Some("error"));
        assert_eq!(e.source, "Microsoft-Windows-Security-Auditing");
        assert_eq!(e.channel.as_deref(), None);
        assert_eq!(e.computer.as_deref(), Some("WIN11LAB"));
        assert_eq!(e.user.as_deref(), Some("S-1-5-18"));
        assert_eq!(
            e.event_data.get("IpAddress").map(String::as_str),
            Some("10.0.0.5")
        );
        assert_eq!(e.semantic_category.as_deref(), Some("authentication"));
        assert_eq!(e.message.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn parses_evtx_utf16_xml_event() {
        let xml = r#"<Event>
<System>
<Provider Name="Microsoft-Windows-Security-Auditing"/>
<EventID>4624</EventID>
<Level>4</Level>
<TimeCreated SystemTime="2026-03-09T11:00:00.000Z"/>
<Computer>WIN11LAB</Computer>
</System>
<RenderingInfo><Message>Successful logon</Message></RenderingInfo>
</Event>"#;
        let utf16: Vec<u8> = xml.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

        let entries = parse_evtx_xml_entries(&utf16);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_id, 4624);
        assert_eq!(entries[0].message.as_deref(), Some("Successful logon"));
    }

    #[test]
    fn parses_evtx_semantic_fields_and_named_data() {
        let xml = r#"<Event>
<System>
<Provider Name="Microsoft-Windows-Security-Auditing"/>
<EventID>4624</EventID>
<Level>4</Level>
<Task>12544</Task>
<Opcode>0</Opcode>
<Keywords>0x8020000000000000</Keywords>
<EventRecordID>333</EventRecordID>
<Channel>Security</Channel>
<TimeCreated SystemTime="2026-03-09T13:00:00.000Z"/>
<Computer>WIN11LAB</Computer>
<Execution ProcessID="692" ThreadID="1234"/>
</System>
<EventData>
  <Data Name="TargetUserName">lab</Data>
  <Data Name="IpAddress">10.0.0.7</Data>
</EventData>
</Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.channel.as_deref(), Some("Security"));
        assert_eq!(e.record_id, Some(333));
        assert_eq!(e.task, Some(12544));
        assert_eq!(e.opcode, Some(0));
        assert_eq!(e.keywords.as_deref(), Some("0x8020000000000000"));
        assert_eq!(e.process_id, Some(692));
        assert_eq!(e.thread_id, Some(1234));
        assert_eq!(
            e.event_data.get("TargetUserName").map(String::as_str),
            Some("lab")
        );
        assert!(e
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("Successful logon"));
    }

    #[test]
    fn parse_security_log_counts_events_from_xml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Security.evtx");
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System></Event>
<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Level>2</Level><TimeCreated SystemTime="2026-03-09T12:01:00.000Z"/></System></Event>"#;
        std::fs::write(&path, xml).unwrap();

        let summary = parse_security_log(&path).unwrap();
        assert_eq!(summary.entries.len(), 2);
        assert_eq!(summary.logon_events, 1);
        assert_eq!(summary.failed_logons, 1);
    }

    #[test]
    fn parse_legacy_evt_records_extracts_core_fields() {
        let mut data = vec![0u8; 160];
        data[0..4].copy_from_slice(b"LfLe");
        data[4..8].copy_from_slice(&120u32.to_le_bytes());
        let ft = (FILETIME_UNIX_EPOCH_OFFSET + 1_700_000_000u64) * 10_000_000u64;
        data[8..16].copy_from_slice(&ft.to_le_bytes());
        data[24..28].copy_from_slice(&4624u32.to_le_bytes());
        data[28] = 4;
        data[48..56].copy_from_slice(b"Security");

        let entries = parse_legacy_evt_records(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_id, 4624);
        assert_eq!(entries[0].level, 4);
        assert_eq!(entries[0].source, "Security");
        assert_eq!(entries[0].timestamp, Some(1_700_000_000));
        assert_eq!(entries[0].level_name.as_deref(), Some("information"));
    }

    #[test]
    fn evtx_dedup_keeps_distinct_record_ids() {
        let xml = r#"<Event><System><Provider Name="A"/><EventID>1</EventID><Level>4</Level><EventRecordID>100</EventRecordID><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System></Event>
<Event><System><Provider Name="A"/><EventID>1</EventID><Level>4</Level><EventRecordID>101</EventRecordID><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn semantic_summary_for_process_creation_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c whoami</Data><Data Name="ParentProcessName">C:\Windows\explorer.exe</Data><Data Name="NewProcessId">0x1f4</Data><Data Name="ProcessId">0x3a8</Data><Data Name="TokenElevationType">%%1936</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("process"));
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.contains("cmd.exe"));
        assert!(summary.contains("parent="));
        let summary_lc = summary.to_ascii_lowercase();
        assert!(summary_lc.contains("pid=500 (0x1f4)"));
        assert!(summary_lc.contains("creator_pid=936 (0x3a8)"));
        assert!(summary.contains("token="));
    }

    #[test]
    fn semantic_summary_for_process_terminated_event_includes_pid_and_status() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4689</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="ProcessName">C:\Windows\System32\cmd.exe</Data><Data Name="ProcessId">0x1f4</Data><Data Name="SubjectUserName">analyst</Data><Data Name="Status">0xC0000005</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("process"));
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.to_ascii_lowercase().contains("pid=500 (0x1f4)"));
        assert!(summary.contains("analyst"));
        assert!(summary.contains("status 0xC0000005"));
    }

    #[test]
    fn parses_user_from_event_data_when_security_attr_missing() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">lab.user</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].user.as_deref(), Some("lab.user"));
    }

    #[test]
    fn semantic_summary_for_network_connection_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>5156</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData>
  <Data Name="Application">C:\Windows\System32\svchost.exe</Data>
  <Data Name="SourceAddress">10.0.0.10</Data>
  <Data Name="SourcePort">51515</Data>
  <Data Name="DestAddress">142.250.72.206</Data>
  <Data Name="DestPort">443</Data>
</EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("network"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("10.0.0.10:51515 -> 142.250.72.206:443"));
    }

    #[test]
    fn semantic_summary_for_group_membership_change() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4732</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="MemberName">lab.user</Data><Data Name="GroupName">Administrators</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("group-membership")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("Administrators"));
    }

    #[test]
    fn semantic_summary_for_scheduled_task_delete_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4699</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TaskName">\Microsoft\Windows\UpdateOrchestrator\Schedule Scan</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("scheduled-task")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("deleted"));
    }

    #[test]
    fn semantic_summary_for_system_time_change_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4616</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData>
  <Data Name="PreviousTime">2026-03-09T11:00:00.000Z</Data>
  <Data Name="NewTime">2026-03-09T12:00:00.000Z</Data>
  <Data Name="ProcessName">C:\Windows\System32\w32tm.exe</Data>
</EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("time-change"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("w32tm.exe"));
    }

    #[test]
    fn semantic_summary_for_service_start_type_change_event() {
        let xml = r#"<Event><System><Provider Name="Service Control Manager"/><EventID>7040</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData>
  <Data Name="ServiceName">WinDefend</Data>
  <Data Name="OldStartType">auto start</Data>
  <Data Name="NewStartType">demand start</Data>
</EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("persistence"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("WinDefend"));
    }

    #[test]
    fn semantic_summary_for_sysmon_process_create() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData>
  <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
  <Data Name="CommandLine">cmd.exe /c whoami</Data>
  <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
</EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("sysmon-process")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("cmd.exe"));
    }

    #[test]
    fn semantic_summary_for_sysmon_create_remote_thread() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>8</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData>
  <Data Name="SourceImage">C:\Tools\injector.exe</Data>
  <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
  <Data Name="StartModule">ntdll.dll</Data>
</EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("sysmon-injection")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("lsass.exe"));
    }

    #[test]
    fn semantic_summary_for_sysmon_process_access() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>10</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData>
  <Data Name="SourceImage">C:\Tools\procdump.exe</Data>
  <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
  <Data Name="GrantedAccess">0x1fffff</Data>
</EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("sysmon-process-access")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("0x1fffff"));
    }

    #[test]
    fn semantic_summary_for_sysmon_registry_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>13</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData>
  <Data Name="TargetObject">HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater</Data>
  <Data Name="Details">DWORD (0x00000001)</Data>
</EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("sysmon-registry")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains(r"CurrentVersion\Run\Updater"));
    }

    #[test]
    fn semantic_summary_for_account_lockout() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4740</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">lab.user</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("account-management")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("lab.user"));
    }

    #[test]
    fn semantic_summary_for_account_disable_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4725</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">lab.user</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("account-management")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("disabled"));
    }

    #[test]
    fn semantic_summary_for_account_unlock_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4767</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">locked.user</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("account-management")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("locked.user"));
    }

    #[test]
    fn semantic_summary_for_sensitive_privilege_use_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4673</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="SubjectUserName">lab.admin</Data><Data Name="Service">SeDebugPrivilege</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("privilege"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("lab.admin"));
    }

    #[test]
    fn semantic_summary_for_privileged_object_operation_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4674</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="SubjectUserName">lab.admin</Data><Data Name="ObjectName">LSASS</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("privilege"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("LSASS"));
    }

    #[test]
    fn semantic_summary_for_user_account_changed_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4738</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">lab.user</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("account-management")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("changed"));
    }

    #[test]
    fn semantic_summary_for_computer_account_created_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4741</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">WS-01$</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("account-management")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("created"));
    }

    #[test]
    fn semantic_summary_for_computer_account_changed_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4742</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">WS-01$</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("account-management")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("changed"));
    }

    #[test]
    fn semantic_summary_for_computer_account_deleted_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4743</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">WS-01$</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("account-management")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("deleted"));
    }

    #[test]
    fn semantic_summary_for_service_state_change_event() {
        let xml = r#"<Event><System><Provider Name="Service Control Manager"/><EventID>7036</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="Param1">WinDefend</Data><Data Name="Param2">running</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("service"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("WinDefend"));
    }

    #[test]
    fn semantic_summary_for_service_terminated_event() {
        let xml = r#"<Event><System><Provider Name="Service Control Manager"/><EventID>7034</EventID><Level>2</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="Param1">Spooler</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("service"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("Spooler"));
    }

    #[test]
    fn semantic_summary_for_shutdown_initiated_event() {
        let xml = r#"<Event><System><Provider Name="System"/><EventID>1074</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="Process">C:\Windows\System32\shutdown.exe</Data><Data Name="Reason">Planned</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("system"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("shutdown.exe"));
    }

    #[test]
    fn semantic_summary_for_sysmon_file_time_change_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>2</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData>
  <Data Name="Image">C:\Tools\stomp.exe</Data>
  <Data Name="TargetFilename">C:\Temp\a.txt</Data>
  <Data Name="CreationUtcTime">2026-03-08 12:00:00.000</Data>
</EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("sysmon-file-timestamp")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("stomp.exe"));
    }

    #[test]
    fn semantic_summary_for_registry_value_modified_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4657</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData>
  <Data Name="ObjectName">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</Data>
  <Data Name="ObjectValueName">Updater</Data>
  <Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>
</EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("registry"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("Updater"));
    }

    #[test]
    fn semantic_summary_for_eventlog_clear_event() {
        let xml = r#"<Event><System><Provider Name="EventLog"/><EventID>104</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("tamper"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("cleared"));
    }

    #[test]
    fn semantic_summary_for_unexpected_shutdown_event() {
        let xml = r#"<Event><System><Provider Name="EventLog"/><EventID>6008</EventID><Level>2</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("system"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("unexpected"));
    }

    #[test]
    fn extended_security_catalog_has_expected_size() {
        assert_eq!(
            extended_security_event_catalog_size(),
            4100,
            "extended event-ID catalog should stay at 4100 entries after this batch"
        );
    }

    #[test]
    fn extended_security_catalog_ids_resolve_to_known_description() {
        for event_id in EXTENDED_SECURITY_EVENT_IDS {
            assert_ne!(
                get_known_security_event_description(*event_id),
                "Unknown event",
                "event {} should be recognized in extended catalog",
                event_id
            );
        }
    }

    #[test]
    fn extended_security_range_ids_resolve_to_known_description() {
        for event_id in [
            5200u32, 5999u32, 6999u32, 7999u32, 8599u32, 8888u32, 9099u32,
        ] {
            assert_eq!(
                get_known_security_event_description(event_id),
                "Extended security auditing event"
            );
        }
    }

    #[test]
    fn generic_extended_security_fallback_is_scoped_to_security_source() {
        let xml = r#"<Event><System><Provider Name="Some-App-Provider"/><EventID>5333</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category, None);
    }

    #[test]
    fn generic_extended_security_fallback_applies_for_security_source() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>8888</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("security-event")
        );
        assert_eq!(
            entries[0].semantic_summary.as_deref(),
            Some("Extended security auditing event")
        );
    }

    #[test]
    fn semantic_summary_for_scheduled_task_enable_disable_events() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4701</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TaskName">\Microsoft\Windows\Defrag\ScheduledDefrag</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("scheduled-task")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("disabled"));
    }

    #[test]
    fn semantic_summary_for_workstation_lock_unlock_events() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4800</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">analyst</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("session"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("Workstation locked"));
    }

    #[test]
    fn semantic_summary_for_code_integrity_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-CodeIntegrity"/><EventID>5038</EventID><Level>2</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="FileName">C:\Temp\unsigned.dll</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("code-integrity")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("unsigned.dll"));
    }

    #[test]
    fn semantic_summary_for_network_share_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>5140</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="ShareName">\\*\C$</Data><Data Name="SubjectUserName">analyst</Data><Data Name="IpAddress">10.0.0.15</Data><Data Name="AccessMask">0x120089</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("network-share")
        );
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.contains("analyst"));
        assert!(summary.contains("10.0.0.15"));
        assert!(summary.contains("access=0x120089"));
    }

    #[test]
    fn semantic_summary_for_sysmon_wmi_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>19</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="Operation">WmiEventFilter activity detected</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("sysmon-wmi"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("WMI"));
    }

    #[test]
    fn semantic_summary_for_success_logon_includes_logon_type() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">analyst</Data><Data Name="LogonType">10</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("authentication")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("remote-interactive"));
    }

    #[test]
    fn semantic_summary_for_failed_logon_includes_status_substatus_and_reason() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Level>2</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">analyst</Data><Data Name="IpAddress">10.0.0.44</Data><Data Name="LogonType">3</Data><Data Name="Status">0xC000006D</Data><Data Name="SubStatus">0xC000006A</Data><Data Name="FailureReason">Unknown user name or bad password.</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("authentication")
        );
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.contains("network"));
        assert!(summary.contains("status 0xC000006D:logon-failure"));
        assert!(summary.contains("substatus 0xC000006A:bad-password"));
        assert!(summary.contains("unknown-user-or-bad-password"));
    }

    #[test]
    fn semantic_summary_for_replay_attack_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4649</EventID><Level>2</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">svc_account</Data><Data Name="IpAddress">10.10.10.20</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("authentication")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("Replay attack"));
    }

    #[test]
    fn semantic_summary_for_special_privileges_event_includes_user_and_privileges() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4672</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="SubjectUserName">analyst</Data><Data Name="PrivilegeList">SeDebugPrivilege,SeBackupPrivilege</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("privilege"));
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.contains("analyst"));
        assert!(summary.contains("SeDebugPrivilege"));
    }

    #[test]
    fn semantic_summary_for_kerberos_tgt_event_includes_etype_and_status() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4768</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">analyst</Data><Data Name="IpAddress">10.0.0.25</Data><Data Name="TicketEncryptionType">0x12</Data><Data Name="Status">0x0</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("kerberos"));
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.contains("analyst"));
        assert!(summary.contains("aes256-cts-hmac-sha1-96"));
        assert!(summary.contains("success"));
    }

    #[test]
    fn semantic_summary_for_kerberos_service_ticket_event_includes_service_and_status() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4769</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">analyst</Data><Data Name="ServiceName">cifs/host1.corp.local</Data><Data Name="IpAddress">10.0.0.25</Data><Data Name="TicketEncryptionType">0x17</Data><Data Name="Status">0x0</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("kerberos"));
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.contains("cifs/host1.corp.local"));
        assert!(summary.contains("rc4-hmac"));
        assert!(summary.contains("success"));
    }

    #[test]
    fn semantic_summary_for_kerberos_preauth_failure_includes_status_and_etype() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4771</EventID><Level>2</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">svc.backup</Data><Data Name="ServiceName">krbtgt/contoso.local</Data><Data Name="IpAddress">10.0.0.40</Data><Data Name="TicketEncryptionType">0x12</Data><Data Name="Status">0xC000006A</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("kerberos"));
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.contains("pre-authentication failed"));
        assert!(summary.contains("10.0.0.40"));
        assert!(summary.contains("aes256-cts-hmac-sha1-96"));
        assert!(summary.contains("bad-password"));
    }

    #[test]
    fn semantic_summary_for_ntlm_validation_includes_failure_status() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4776</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">analyst</Data><Data Name="Workstation">WS-01</Data><Data Name="PackageName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data><Data Name="Status">0xC000006A</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("authentication")
        );
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.contains("analyst"));
        assert!(summary.contains("bad-password"));
    }

    #[test]
    fn parse_security_log_counts_ntlm_failure_as_failed_logon() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Security.evtx");
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4776</EventID><Level>2</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">analyst</Data><Data Name="Status">0xC000006A</Data></EventData></Event>"#;
        std::fs::write(&path, xml).unwrap();

        let summary = parse_security_log(&path).unwrap();
        assert_eq!(summary.failed_logons, 1);
    }

    #[test]
    fn semantic_summary_for_user_account_deleted_includes_username() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4726</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">temp.user</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("account-management")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("temp.user"));
    }

    #[test]
    fn semantic_summary_for_service_install_includes_start_type_and_account() {
        let xml = r#"<Event><System><Provider Name="Service Control Manager"/><EventID>7045</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="ServiceName">BadSvc</Data><Data Name="ImagePath">C:\Temp\badsvc.exe</Data><Data Name="StartType">Auto Start</Data><Data Name="AccountName">LocalSystem</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("persistence"));
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.contains("BadSvc"));
        assert!(summary.contains("start=Auto Start"));
        assert!(summary.contains("account=LocalSystem"));
    }

    #[test]
    fn semantic_summary_for_sid_history_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4765</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="TargetUserName">legacy_user</Data><Data Name="SidHistory">S-1-5-21-123-456-789-1001</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("account-management")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("SID history"));
    }

    #[test]
    fn semantic_summary_for_detailed_file_share_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>5147</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="ShareName">\\server\finance</Data><Data Name="RelativeTargetName">Q1-report.xlsx</Data><Data Name="SubjectUserName">analyst</Data><Data Name="Status">0xC000006D</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("network-share")
        );
        let summary = entries[0].semantic_summary.as_deref().unwrap_or("");
        assert!(summary.contains("access granted"));
        assert!(summary.contains("analyst"));
        assert!(summary.contains("logon-failure"));
    }

    #[test]
    fn semantic_summary_for_wfp_block_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>5152</EventID><Level>3</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="Application">C:\Windows\System32\svchost.exe</Data><Data Name="SourceAddress">10.0.0.10</Data><Data Name="DestAddress">10.0.0.20</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("network"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("dropped packet"));
    }

    #[test]
    fn semantic_summary_for_sysmon_config_change_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>16</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="Configuration">sysmon-config.xml updated</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("sysmon-state")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("configuration"));
    }

    #[test]
    fn semantic_summary_for_sysmon_file_delete_detected_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>31</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="Image">C:\Tools\wipe.exe</Data><Data Name="TargetFilename">C:\Temp\artifact.tmp</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].semantic_category.as_deref(), Some("sysmon-file"));
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("delete detected"));
    }

    #[test]
    fn semantic_summary_for_terminal_services_auth_event() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-TerminalServices-RemoteConnectionManager"/><EventID>1149</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/></System>
<EventData><Data Name="User">analyst</Data><Data Name="Address">192.168.1.50</Data></EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].semantic_category.as_deref(),
            Some("remote-access")
        );
        assert!(entries[0]
            .semantic_summary
            .as_deref()
            .unwrap_or("")
            .contains("Remote Desktop"));
    }

    #[test]
    fn known_security_event_description_has_extended_named_ids() {
        assert_eq!(
            get_known_security_event_description(4964),
            "Special groups assigned to new logon"
        );
        assert_eq!(
            get_known_security_event_description(5155),
            "Windows Filtering Platform blocked bind/listen"
        );
    }

    #[test]
    fn parses_event_data_duplicate_keys_with_suffixes() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/></System>
<EventData>
  <Data Name="Hash">SHA256=A</Data>
  <Data Name="Hash">MD5=B</Data>
  <Data Name="Hash">IMPHASH=C</Data>
</EventData></Event>"#;

        let fields = extract_event_data_fields(xml);
        assert_eq!(fields.get("Hash").map(String::as_str), Some("SHA256=A"));
        assert_eq!(fields.get("Hash_2").map(String::as_str), Some("MD5=B"));
        assert_eq!(fields.get("Hash_3").map(String::as_str), Some("IMPHASH=C"));
    }

    #[test]
    fn decodes_xml_entities_in_event_fields() {
        let xml = r#"<Event>
<System>
  <Provider Name="Power&amp;Shell"/>
  <EventID>4104</EventID>
  <Level>4</Level>
  <TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/>
</System>
<EventData>
  <Data Name="Message">A &amp; B &lt; C &#x41; &#65;</Data>
</EventData>
</Event>"#;

        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source, "Power&Shell");
        assert_eq!(
            entries[0].event_data.get("Message").map(String::as_str),
            Some("A & B < C A A")
        );
    }

    #[test]
    fn normalizes_identity_fields_in_event_payload() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><Level>4</Level><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/><Computer>host-a</Computer><Security UserID="s-1-5-21-1000"/></System>
<EventData>
  <Data Name="NewProcessName">"C:/Windows/System32/cmd.exe"</Data>
  <Data Name="SubjectUserSid">s-1-5-18</Data>
</EventData></Event>"#;
        let entries = parse_evtx_xml_entries(xml.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].computer.as_deref(), Some("HOST-A"));
        assert_eq!(entries[0].user.as_deref(), Some("S-1-5-21-1000"));
        assert_eq!(
            entries[0]
                .event_data
                .get("NewProcessName")
                .map(String::as_str),
            Some("C:\\Windows\\System32\\cmd.exe")
        );
        assert_eq!(
            entries[0]
                .event_data
                .get("SubjectUserSid")
                .map(String::as_str),
            Some("S-1-5-18")
        );
    }

    #[test]
    fn detects_input_shapes() {
        assert_eq!(
            detect_eventlog_input_shape(b"ElfFile\0more-data"),
            EventLogInputShape::RawEvtx
        );
        assert_eq!(
            detect_eventlog_input_shape(b"<Event><System><EventID>4624</EventID></System></Event>"),
            EventLogInputShape::XmlExport
        );
        assert_eq!(
            detect_eventlog_input_shape(b"<\0E\0v\0e\0n\0t\0>\0"),
            EventLogInputShape::Utf16XmlExport
        );
        assert_eq!(
            detect_eventlog_input_shape(b"\x00\x01\x02\x03"),
            EventLogInputShape::Unknown
        );
    }

    #[test]
    fn parse_security_log_with_metadata_reports_dedupe() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><Level>4</Level><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/><Computer>HOST1</Computer></System></Event>
<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><Level>4</Level><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-03-09T12:00:00.000Z"/><Computer>HOST1</Computer></System></Event>"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Security.evtx");
        std::fs::write(&path, xml).unwrap();

        let parsed = parse_security_log_with_metadata(&path).unwrap();
        assert_eq!(parsed.summary.entries.len(), 1);
        assert_eq!(parsed.metadata.input_shape, EventLogInputShape::XmlExport);
        assert_eq!(parsed.metadata.deduped_count, 1);
        assert_eq!(parsed.metadata.parser_mode, "evtx_xml");
    }
}
