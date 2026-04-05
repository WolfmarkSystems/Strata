use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::errors::ForensicError;

use super::jumplist::{parseautomaticdestinations, JumpListEntry};
use super::prefetch::{scan_prefetch_directory, PrefetchInfo};
use super::shortcuts::{collect_all_shortcuts, ShortcutInfo};

#[derive(Debug, Clone, Default)]
pub struct ExecutionCorrelation {
    pub executable_name: String,
    pub sources: Vec<String>,
    pub prefetch_count: u32,
    pub jumplist_count: u32,
    pub shortcut_count: u32,
    pub total_hits: u32,
    pub first_seen_unix: Option<i64>,
    pub last_seen_unix: Option<i64>,
    pub latest_prefetch_unix: Option<i64>,
    pub latest_jumplist_unix: Option<i64>,
    pub latest_shortcut_unix: Option<i64>,
    pub sample_paths: Vec<String>,
}

pub fn get_execution_correlations_from_sources(
    prefetch_dir: &Path,
    jumplist_path: &Path,
    shortcuts_base: &Path,
) -> Result<Vec<ExecutionCorrelation>, ForensicError> {
    let prefetch = scan_prefetch_directory(prefetch_dir)?;
    let jumplist = parseautomaticdestinations(jumplist_path)?.entries;
    let shortcuts = collect_all_shortcuts(shortcuts_base)?;
    Ok(build_execution_correlations(
        &prefetch, &jumplist, &shortcuts,
    ))
}

pub fn build_execution_correlations(
    prefetch: &[PrefetchInfo],
    jumplist: &[JumpListEntry],
    shortcuts: &[ShortcutInfo],
) -> Vec<ExecutionCorrelation> {
    let mut index: BTreeMap<String, ExecutionCorrelation> = BTreeMap::new();

    for item in prefetch {
        let Some(exe) = extract_executable_name(&item.program_name) else {
            continue;
        };
        let row = index.entry(exe.clone()).or_insert_with(|| empty_row(&exe));
        row.prefetch_count = row.prefetch_count.saturating_add(1);
        row.total_hits = row.total_hits.saturating_add(1);
        row.first_seen_unix = min_ts(row.first_seen_unix, item.last_run_time);
        row.last_seen_unix = max_ts(row.last_seen_unix, item.last_run_time);
        row.latest_prefetch_unix = max_ts(row.latest_prefetch_unix, item.last_run_time);
        push_source(&mut row.sources, "prefetch");
        push_sample_path(&mut row.sample_paths, &item.program_name);
    }

    for item in jumplist {
        let mut hit = false;
        let mut exe_name: Option<String> = None;

        if let Some(target) = item.target_path.as_deref() {
            exe_name = extract_executable_name(target);
            if exe_name.is_some() {
                hit = true;
            }
        }
        if exe_name.is_none() {
            exe_name = item
                .arguments
                .as_deref()
                .and_then(extract_executable_name_from_command_line);
        }

        let Some(exe) = exe_name else {
            continue;
        };
        let row = index.entry(exe.clone()).or_insert_with(|| empty_row(&exe));
        row.jumplist_count = row.jumplist_count.saturating_add(1);
        row.total_hits = row.total_hits.saturating_add(1);
        row.first_seen_unix = min_ts(row.first_seen_unix, item.timestamp);
        row.last_seen_unix = max_ts(row.last_seen_unix, item.timestamp);
        row.latest_jumplist_unix = max_ts(row.latest_jumplist_unix, item.timestamp);
        push_source(&mut row.sources, "jumplist");
        if hit {
            if let Some(path) = item.target_path.as_deref() {
                push_sample_path(&mut row.sample_paths, path);
            }
        } else if let Some(args) = item.arguments.as_deref() {
            push_sample_path(&mut row.sample_paths, args);
        }
    }

    for item in shortcuts {
        let exe_name = item
            .target
            .as_deref()
            .and_then(extract_executable_name)
            .or_else(|| {
                item.arguments
                    .as_deref()
                    .and_then(extract_executable_name_from_command_line)
            });
        let Some(exe) = exe_name else {
            continue;
        };

        let row = index.entry(exe.clone()).or_insert_with(|| empty_row(&exe));
        row.shortcut_count = row.shortcut_count.saturating_add(1);
        row.total_hits = row.total_hits.saturating_add(1);
        let shortcut_first = min_ts(item.created, item.modified);
        let shortcut_last = max_ts(item.created, item.modified);
        row.first_seen_unix = min_ts(row.first_seen_unix, shortcut_first);
        row.last_seen_unix = max_ts(row.last_seen_unix, shortcut_last);
        row.latest_shortcut_unix = max_ts(row.latest_shortcut_unix, shortcut_last);
        push_source(&mut row.sources, "shortcut");
        if let Some(target) = item.target.as_deref() {
            push_sample_path(&mut row.sample_paths, target);
        }
    }

    let mut out = index.into_values().collect::<Vec<_>>();
    out.sort_by(|a, b| {
        b.last_seen_unix
            .unwrap_or(i64::MIN)
            .cmp(&a.last_seen_unix.unwrap_or(i64::MIN))
            .then_with(|| a.executable_name.cmp(&b.executable_name))
    });
    out
}

fn empty_row(executable_name: &str) -> ExecutionCorrelation {
    ExecutionCorrelation {
        executable_name: executable_name.to_string(),
        ..ExecutionCorrelation::default()
    }
}

fn max_ts(existing: Option<i64>, candidate: Option<i64>) -> Option<i64> {
    match (existing, candidate) {
        (Some(a), Some(b)) => Some(std::cmp::max(a, b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn min_ts(existing: Option<i64>, candidate: Option<i64>) -> Option<i64> {
    match (existing, candidate) {
        (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn push_source(sources: &mut Vec<String>, source: &str) {
    let mut dedup = sources.iter().cloned().collect::<BTreeSet<_>>();
    dedup.insert(source.to_string());
    *sources = dedup.into_iter().collect();
}

fn push_sample_path(paths: &mut Vec<String>, raw: &str) {
    let normalized = normalize_windows_path(raw);
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return;
    }
    if paths.iter().any(|p| p.eq_ignore_ascii_case(trimmed)) {
        return;
    }
    paths.push(trimmed.to_string());
    if paths.len() > 12 {
        paths.truncate(12);
    }
}

fn extract_executable_name_from_command_line(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    for token in split_command_tokens(trimmed) {
        if let Some(exe) = extract_executable_name(&token) {
            return Some(exe);
        }
    }
    extract_executable_name(trimmed)
}

fn extract_executable_name(value: &str) -> Option<String> {
    let normalized = normalize_windows_path(value);
    if normalized.is_empty() {
        return None;
    }
    let base = normalized
        .rsplit('\\')
        .next()
        .unwrap_or(normalized.as_str())
        .trim()
        .trim_end_matches([';', ',', ')']);
    let candidate = if let Some(idx) = base.find(',') {
        let head = base[..idx].trim();
        if looks_executable_name(head) {
            head
        } else {
            base
        }
    } else {
        base
    };

    if !looks_executable_name(candidate) {
        return None;
    }
    Some(candidate.to_ascii_lowercase())
}

fn looks_executable_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".com", ".msi", ".scr",
    ]
    .iter()
    .any(|ext| n.ends_with(ext))
}

fn normalize_windows_path(value: &str) -> String {
    value.trim().trim_matches('"').replace('/', "\\")
}

fn split_command_tokens(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut token = String::new();
    let mut in_quotes = false;
    let mut chars = value.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    token.push('"');
                    let _ = chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !token.trim().is_empty() {
                    out.push(token.trim().to_string());
                    token.clear();
                }
            }
            _ => token.push(ch),
        }
    }

    if !token.trim().is_empty() {
        out.push(token.trim().to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classification::jumplist::JumpListEntryType;

    #[test]
    fn correlation_merges_prefetch_jumplist_shortcut_hits() {
        let prefetch = vec![PrefetchInfo {
            version: 30,
            program_name: "CMD.EXE".to_string(),
            last_run_time: Some(1_700_000_000),
            run_times: vec![1_700_000_000],
            run_count: 3,
            volumes_referenced: vec![],
            files_referenced: vec![],
            directories_referenced: vec![],
        }];
        let jumplist = vec![JumpListEntry {
            entry_type: JumpListEntryType::Recent,
            target_path: Some(r"C:\Windows\System32\cmd.exe".to_string()),
            arguments: None,
            timestamp: Some(1_700_000_050),
            app_id: "app".to_string(),
            source_record_id: Some(1),
            mru_rank: Some(1),
        }];
        let shortcuts = vec![ShortcutInfo {
            path: r"C:\Users\lab\Desktop\Cmd.lnk".to_string(),
            target: Some(r"C:\Windows\System32\cmd.exe".to_string()),
            arguments: None,
            working_dir: None,
            created: Some(1_699_999_900),
            modified: Some(1_700_000_100),
            description: None,
        }];

        let rows = build_execution_correlations(&prefetch, &jumplist, &shortcuts);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.executable_name, "cmd.exe");
        assert_eq!(row.prefetch_count, 1);
        assert_eq!(row.jumplist_count, 1);
        assert_eq!(row.shortcut_count, 1);
        assert_eq!(row.total_hits, 3);
        assert_eq!(row.first_seen_unix, Some(1_699_999_900));
        assert_eq!(row.last_seen_unix, Some(1_700_000_100));
        assert_eq!(row.latest_prefetch_unix, Some(1_700_000_000));
        assert_eq!(row.latest_jumplist_unix, Some(1_700_000_050));
        assert_eq!(row.latest_shortcut_unix, Some(1_700_000_100));
        assert!(row.sources.iter().any(|s| s == "prefetch"));
        assert!(row.sources.iter().any(|s| s == "jumplist"));
        assert!(row.sources.iter().any(|s| s == "shortcut"));
    }

    #[test]
    fn correlation_skips_non_executable_targets() {
        let prefetch = vec![PrefetchInfo {
            version: 30,
            program_name: "NOTEPAD.EXE".to_string(),
            last_run_time: Some(1_700_000_000),
            run_times: vec![],
            run_count: 1,
            volumes_referenced: vec![],
            files_referenced: vec![],
            directories_referenced: vec![],
        }];
        let jumplist = vec![JumpListEntry {
            entry_type: JumpListEntryType::Recent,
            target_path: Some(r"C:\Users\lab\Desktop\notes.txt".to_string()),
            arguments: None,
            timestamp: Some(1_700_000_050),
            app_id: "app".to_string(),
            source_record_id: None,
            mru_rank: None,
        }];
        let shortcuts = vec![ShortcutInfo {
            path: "a".to_string(),
            target: Some(r"C:\Users\lab\Desktop\report.docx".to_string()),
            arguments: None,
            working_dir: None,
            created: None,
            modified: Some(1_700_000_100),
            description: None,
        }];

        let rows = build_execution_correlations(&prefetch, &jumplist, &shortcuts);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].executable_name, "notepad.exe");
    }

    #[test]
    fn correlation_extracts_executable_from_arguments() {
        let jumplist = vec![JumpListEntry {
            entry_type: JumpListEntryType::Tasks,
            target_path: None,
            arguments: Some(
                "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop"
                    .to_string(),
            ),
            timestamp: Some(1_700_000_123),
            app_id: "app".to_string(),
            source_record_id: None,
            mru_rank: None,
        }];

        let rows = build_execution_correlations(&[], &jumplist, &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].executable_name, "powershell.exe");
        assert_eq!(rows[0].jumplist_count, 1);
    }

    #[test]
    fn correlation_extracts_executable_from_non_first_argument_token() {
        let jumplist = vec![JumpListEntry {
            entry_type: JumpListEntryType::Tasks,
            target_path: None,
            arguments: Some("/c C:\\Windows\\System32\\cmd.exe /k whoami".to_string()),
            timestamp: Some(1_700_000_124),
            app_id: "app".to_string(),
            source_record_id: None,
            mru_rank: None,
        }];

        let rows = build_execution_correlations(&[], &jumplist, &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].executable_name, "cmd.exe");
    }

    #[test]
    fn correlation_extracts_executable_with_trailing_punctuation() {
        let jumplist = vec![JumpListEntry {
            entry_type: JumpListEntryType::Tasks,
            target_path: None,
            arguments: Some("rundll32.exe,Shell32.dll,Control_RunDLL".to_string()),
            timestamp: Some(1_700_000_125),
            app_id: "app".to_string(),
            source_record_id: None,
            mru_rank: None,
        }];

        let rows = build_execution_correlations(&[], &jumplist, &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].executable_name, "rundll32.exe");
    }

    #[test]
    fn correlation_sample_paths_normalize_slashes_and_dedupe() {
        let prefetch = vec![
            PrefetchInfo {
                version: 30,
                program_name: "C:/Windows/System32/CMD.EXE".to_string(),
                last_run_time: Some(1_700_000_010),
                run_times: vec![],
                run_count: 1,
                volumes_referenced: vec![],
                files_referenced: vec![],
                directories_referenced: vec![],
            },
            PrefetchInfo {
                version: 30,
                program_name: "C:\\Windows\\System32\\cmd.exe".to_string(),
                last_run_time: Some(1_700_000_011),
                run_times: vec![],
                run_count: 1,
                volumes_referenced: vec![],
                files_referenced: vec![],
                directories_referenced: vec![],
            },
        ];

        let rows = build_execution_correlations(&prefetch, &[], &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].sample_paths.len(), 1);
        assert_eq!(rows[0].sample_paths[0], "C:\\Windows\\System32\\CMD.EXE");
    }

    #[test]
    fn correlation_sorts_by_latest_seen_desc() {
        let prefetch = vec![
            PrefetchInfo {
                version: 30,
                program_name: "A.EXE".to_string(),
                last_run_time: Some(1_700_000_010),
                run_times: vec![],
                run_count: 1,
                volumes_referenced: vec![],
                files_referenced: vec![],
                directories_referenced: vec![],
            },
            PrefetchInfo {
                version: 30,
                program_name: "B.EXE".to_string(),
                last_run_time: Some(1_700_000_900),
                run_times: vec![],
                run_count: 1,
                volumes_referenced: vec![],
                files_referenced: vec![],
                directories_referenced: vec![],
            },
        ];

        let rows = build_execution_correlations(&prefetch, &[], &[]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].executable_name, "b.exe");
        assert_eq!(rows[1].executable_name, "a.exe");
    }
}
