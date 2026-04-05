use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::errors::ForensicError;

use super::amcache::AmCacheEntry;
use super::autorun::{get_auto_run_keys_from_reg, AutoRunKey};
use super::regbam::{get_bam_state_from_reg, BamEntry};
use super::scheduledtasks::{parse_scheduled_tasks_xml, ActionType, ScheduledTask};

#[derive(Debug, Clone, Default)]
pub struct PersistenceCorrelation {
    pub executable_path: String,
    pub sources: Vec<String>,
    pub autorun_count: u32,
    pub scheduled_task_count: u32,
    pub bam_count: u32,
    pub dam_count: u32,
    pub amcache_count: u32,
    pub latest_execution_unix: Option<u64>,
    pub reason_codes: Vec<String>,
    pub overall_confidence: String,
}

pub fn get_persistence_correlations_from_sources(
    autorun_reg_path: &Path,
    scheduled_tasks_root: &Path,
    bam_reg_path: &Path,
) -> Result<Vec<PersistenceCorrelation>, ForensicError> {
    let autoruns = get_auto_run_keys_from_reg(autorun_reg_path);
    let tasks = parse_scheduled_tasks_xml(scheduled_tasks_root)?;
    let bam = get_bam_state_from_reg(bam_reg_path);
    Ok(build_persistence_correlations(&autoruns, &tasks, &bam))
}

pub fn build_persistence_correlations(
    autoruns: &[AutoRunKey],
    tasks: &[ScheduledTask],
    bam: &[BamEntry],
) -> Vec<PersistenceCorrelation> {
    build_persistence_correlations_with_amcache(autoruns, tasks, bam, &[])
}

pub fn build_persistence_correlations_with_amcache(
    autoruns: &[AutoRunKey],
    tasks: &[ScheduledTask],
    bam: &[BamEntry],
    amcache: &[AmCacheEntry],
) -> Vec<PersistenceCorrelation> {
    let mut index: BTreeMap<String, PersistenceCorrelation> = BTreeMap::new();

    for autorun in autoruns {
        if let Some(path) = extract_executable_path(&autorun.value) {
            let key = canonical_windows_path_key(&path);
            let row = index.entry(key).or_insert_with(|| empty_correlation(path));
            row.autorun_count = row.autorun_count.saturating_add(1);
            push_source(&mut row.sources, "autorun");
            push_reason(&mut row.reason_codes, "autorun_path_match");
        }
    }

    for task in tasks {
        for action in &task.actions {
            if matches!(action.action_type, ActionType::Execute) {
                if let Some(path) = action.path.as_deref().and_then(extract_executable_path) {
                    let key = canonical_windows_path_key(&path);
                    let row = index.entry(key).or_insert_with(|| empty_correlation(path));
                    row.scheduled_task_count = row.scheduled_task_count.saturating_add(1);
                    push_source(&mut row.sources, "scheduled-task");
                    push_reason(&mut row.reason_codes, "scheduled_task_exec_match");
                }
            }
        }
    }

    for hit in bam {
        let path = normalize_windows_path(&hit.program_path);
        if path.is_empty() {
            continue;
        }
        let key = canonical_windows_path_key(&path);
        let row = index.entry(key).or_insert_with(|| empty_correlation(path));
        if hit.source.eq_ignore_ascii_case("dam") {
            row.dam_count = row.dam_count.saturating_add(1);
            push_source(&mut row.sources, "dam");
            push_reason(&mut row.reason_codes, "dam_execution_match");
        } else {
            row.bam_count = row.bam_count.saturating_add(1);
            push_source(&mut row.sources, "bam");
            push_reason(&mut row.reason_codes, "bam_execution_match");
        }
        row.latest_execution_unix = std::cmp::max(row.latest_execution_unix, hit.last_execution);
    }

    for entry in amcache {
        let path = normalize_windows_path(&entry.file_path);
        if path.is_empty() {
            continue;
        }
        let key = canonical_windows_path_key(&path);
        let row = index.entry(key).or_insert_with(|| empty_correlation(path));
        row.amcache_count = row.amcache_count.saturating_add(1);
        push_source(&mut row.sources, "amcache");
        push_reason(&mut row.reason_codes, "amcache_entry_match");
        let observed_value = entry.last_modified.max(entry.created);
        let observed = (observed_value > 0).then_some(observed_value);
        row.latest_execution_unix = std::cmp::max(row.latest_execution_unix, observed);
    }

    let mut out = index.into_values().collect::<Vec<_>>();
    for row in &mut out {
        row.overall_confidence = compute_overall_confidence(row).to_string();
    }
    out.sort_by(|a, b| {
        b.latest_execution_unix
            .unwrap_or(0)
            .cmp(&a.latest_execution_unix.unwrap_or(0))
            .then_with(|| a.executable_path.cmp(&b.executable_path))
    });
    out
}

fn empty_correlation(executable_path: String) -> PersistenceCorrelation {
    PersistenceCorrelation {
        executable_path,
        ..PersistenceCorrelation::default()
    }
}

fn push_source(sources: &mut Vec<String>, source: &str) {
    let mut dedup = sources.iter().cloned().collect::<BTreeSet<_>>();
    dedup.insert(source.to_string());
    *sources = dedup.into_iter().collect();
}

fn push_reason(reasons: &mut Vec<String>, reason: &str) {
    let mut dedup = reasons.iter().cloned().collect::<BTreeSet<_>>();
    dedup.insert(reason.to_string());
    *reasons = dedup.into_iter().collect();
}

fn extract_executable_path(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(stripped) = trimmed.strip_prefix('"') {
        let end = stripped.find('"')?;
        let quoted = &stripped[..end];
        let path = normalize_windows_path(quoted);
        return (!path.is_empty()).then_some(path);
    }

    let first = trimmed.split_whitespace().next().unwrap_or_default();
    let path = normalize_windows_path(first);
    (!path.is_empty()).then_some(path)
}

fn normalize_windows_path(path: &str) -> String {
    let mut cleaned = path.trim().trim_matches('"').replace('/', "\\");
    if let Some(stripped) = cleaned.strip_prefix(r"\\?\") {
        cleaned = stripped.to_string();
    } else if let Some(stripped) = cleaned.strip_prefix(r"\\??\\") {
        cleaned = stripped.to_string();
    } else if let Some(stripped) = cleaned.strip_prefix(r"\?\") {
        cleaned = stripped.to_string();
    } else if let Some(stripped) = cleaned.strip_prefix(r"\??\") {
        cleaned = stripped.to_string();
    }

    let is_unc = cleaned.starts_with(r"\\");
    let body = if is_unc { &cleaned[2..] } else { &cleaned };
    let mut collapsed_body = String::new();
    let mut previous_slash = false;
    for ch in body.chars() {
        if ch == '\\' {
            if !previous_slash {
                collapsed_body.push(ch);
            }
            previous_slash = true;
        } else {
            collapsed_body.push(ch);
            previous_slash = false;
        }
    }

    let mut normalized = if is_unc {
        format!(r"\\{}", collapsed_body.trim_start_matches('\\'))
    } else {
        collapsed_body
    };

    if normalized.len() >= 2 && normalized.as_bytes()[1] == b':' {
        let mut chars = normalized.chars();
        if let Some(drive) = chars.next() {
            let rest: String = chars.collect();
            normalized = format!("{}{}", drive.to_ascii_uppercase(), rest);
        }
    }
    normalized
}

fn canonical_windows_path_key(path: &str) -> String {
    normalize_windows_path(path).to_ascii_lowercase()
}

fn compute_overall_confidence(row: &PersistenceCorrelation) -> &'static str {
    let source_count = row.sources.len();
    let has_execution = row.bam_count > 0 || row.dam_count > 0;
    let has_persistence =
        row.autorun_count > 0 || row.scheduled_task_count > 0 || row.amcache_count > 0;
    if has_execution && has_persistence {
        "high"
    } else if source_count >= 2 || has_execution {
        "medium"
    } else {
        "low"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classification::scheduledtasks::{TaskAction, TaskState, TaskTrigger, TriggerType};

    #[test]
    fn correlation_merges_autorun_tasks_and_bam() {
        let autoruns = vec![AutoRunKey {
            path: "HKCU\\...\\Run\\BadApp".to_string(),
            value: "\"C:\\Tools\\bad.exe\" --silent".to_string(),
        }];

        let tasks = vec![ScheduledTask {
            name: "TaskA".to_string(),
            path: r"C:\Windows\System32\Tasks\TaskA".to_string(),
            state: TaskState::Ready,
            last_run_time: None,
            next_run_time: None,
            author: None,
            description: None,
            triggers: vec![TaskTrigger {
                trigger_type: TriggerType::Daily,
                start_time: None,
                end_time: None,
                interval: None,
                days_of_week: None,
            }],
            actions: vec![TaskAction {
                action_type: ActionType::Execute,
                path: Some(r"C:\Tools\bad.exe".to_string()),
                arguments: None,
            }],
        }];

        let bam = vec![BamEntry {
            program_path: r"C:\Tools\bad.exe".to_string(),
            last_execution: Some(1_700_000_123),
            last_execution_utc: None,
            actor_sid: Some("S-1-5-21".to_string()),
            source: "bam".to_string(),
        }];

        let rows = build_persistence_correlations(&autoruns, &tasks, &bam);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].executable_path, r"C:\Tools\bad.exe");
        assert_eq!(rows[0].autorun_count, 1);
        assert_eq!(rows[0].scheduled_task_count, 1);
        assert_eq!(rows[0].bam_count, 1);
        assert_eq!(rows[0].dam_count, 0);
        assert_eq!(rows[0].amcache_count, 0);
        assert_eq!(rows[0].latest_execution_unix, Some(1_700_000_123));
        assert_eq!(
            rows[0].sources,
            vec![
                "autorun".to_string(),
                "bam".to_string(),
                "scheduled-task".to_string()
            ]
        );
    }

    #[test]
    fn correlation_ignores_empty_paths() {
        let autoruns = vec![AutoRunKey {
            path: "HKCU\\...\\Run\\Empty".to_string(),
            value: "".to_string(),
        }];
        let rows = build_persistence_correlations(&autoruns, &[], &[]);
        assert!(rows.is_empty());
    }

    #[test]
    fn correlation_tracks_dam_as_separate_source() {
        let bam = vec![BamEntry {
            program_path: r"C:\Windows\System32\svchost.exe".to_string(),
            last_execution: Some(1_700_010_000),
            last_execution_utc: None,
            actor_sid: Some("S-1-5-18".to_string()),
            source: "dam".to_string(),
        }];
        let rows = build_persistence_correlations(&[], &[], &bam);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bam_count, 0);
        assert_eq!(rows[0].dam_count, 1);
        assert_eq!(rows[0].amcache_count, 0);
        assert_eq!(rows[0].sources, vec!["dam".to_string()]);
    }

    #[test]
    fn correlation_tracks_amcache_as_separate_source() {
        let amcache = vec![AmCacheEntry {
            file_path: r"C:\Tools\bad.exe".to_string(),
            sha1: None,
            program_id: Some("Program-1".to_string()),
            last_modified: 1_700_040_000,
            last_modified_utc: None,
            created: 1_700_030_000,
            created_utc: None,
        }];
        let rows = build_persistence_correlations_with_amcache(&[], &[], &[], &amcache);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].amcache_count, 1);
        assert_eq!(rows[0].latest_execution_unix, Some(1_700_040_000));
        assert_eq!(rows[0].sources, vec!["amcache".to_string()]);
        assert_eq!(rows[0].overall_confidence, "low");
        assert_eq!(
            rows[0].reason_codes,
            vec!["amcache_entry_match".to_string()]
        );
    }

    #[test]
    fn correlation_normalizes_case_and_device_prefixes() {
        let autoruns = vec![AutoRunKey {
            path: "HKCU\\...\\Run\\BadApp".to_string(),
            value: r#""\??\c:\tools\bad.exe" --silent"#.to_string(),
        }];
        let bam = vec![BamEntry {
            program_path: r"\\?\C:\TOOLS\bad.exe".to_string(),
            last_execution: Some(1_700_050_000),
            last_execution_utc: None,
            actor_sid: None,
            source: "bam".to_string(),
        }];
        let rows = build_persistence_correlations(&autoruns, &[], &bam);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].executable_path, r"C:\tools\bad.exe");
        assert_eq!(rows[0].autorun_count, 1);
        assert_eq!(rows[0].bam_count, 1);
        assert_eq!(rows[0].overall_confidence, "high");
    }

    #[test]
    fn correlation_has_deterministic_reason_codes() {
        let autoruns = vec![AutoRunKey {
            path: "HKCU\\...\\Run\\BadApp".to_string(),
            value: "\"C:\\Tools\\bad.exe\" --silent".to_string(),
        }];
        let bam = vec![BamEntry {
            program_path: r"C:\Tools\bad.exe".to_string(),
            last_execution: Some(1_700_000_000),
            last_execution_utc: None,
            actor_sid: None,
            source: "bam".to_string(),
        }];
        let rows = build_persistence_correlations(&autoruns, &[], &bam);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].reason_codes,
            vec![
                "autorun_path_match".to_string(),
                "bam_execution_match".to_string()
            ]
        );
    }
}
