use crate::errors::ForensicError;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ShortcutInfo {
    pub path: String,
    pub target: Option<String>,
    pub arguments: Option<String>,
    pub working_dir: Option<String>,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ShortcutCollection {
    pub shortcuts: Vec<ShortcutInfo>,
    pub total_count: usize,
}

#[derive(Debug, Clone)]
pub struct ShortcutAnalysis {
    pub total_shortcuts: usize,
    pub unique_targets: usize,
    pub recent_shortcuts: Vec<ShortcutInfo>,
}

pub fn collect_all_shortcuts(base_path: &Path) -> Result<Vec<ShortcutInfo>, ForensicError> {
    let mut shortcuts = Vec::new();

    let locations = vec![
        base_path
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("Recent"),
        base_path.join("Desktop"),
        base_path.join("SendTo"),
    ];

    for location in locations {
        if location.exists() {
            walk_dir_for_shortcuts(&location, &mut shortcuts)?;
        }
    }

    Ok(shortcuts)
}

fn walk_dir_for_shortcuts(
    dir_path: &Path,
    shortcuts: &mut Vec<ShortcutInfo>,
) -> Result<(), ForensicError> {
    if let Ok(entries) = strata_fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                walk_dir_for_shortcuts(&path, shortcuts)?;
            } else if path.extension().map(|e| e == "lnk").unwrap_or(false) {
                if let Ok(lnk) = crate::classification::parse_lnk(&path) {
                    let meta = strata_fs::metadata(&path).ok();

                    shortcuts.push(ShortcutInfo {
                        path: path.display().to_string(),
                        target: lnk.target_path,
                        arguments: lnk.arguments,
                        working_dir: lnk.working_directory,
                        created: meta.as_ref().and_then(|m| m.created().ok()).map(|t| {
                            t.duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64
                        }),
                        modified: meta.as_ref().and_then(|m| m.modified().ok()).map(|t| {
                            t.duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64
                        }),
                        description: lnk.description,
                    });
                }
            }
        }
    }
    Ok(())
}

pub fn analyze_shortcut_patterns(shortcuts: &[ShortcutInfo]) -> ShortcutAnalysis {
    let mut target_counts: HashMap<String, usize> = HashMap::new();

    for shortcut in shortcuts {
        if let Some(ref target) = shortcut.target {
            *target_counts.entry(target.clone()).or_insert(0) += 1;
        }
    }

    let mut recent = shortcuts.to_vec();
    recent.sort_by(|a, b| {
        let a_time = a.modified.unwrap_or(0);
        let b_time = b.modified.unwrap_or(0);
        b_time.cmp(&a_time)
    });

    ShortcutAnalysis {
        total_shortcuts: shortcuts.len(),
        unique_targets: target_counts.len(),
        recent_shortcuts: recent.into_iter().take(50).collect(),
    }
}
