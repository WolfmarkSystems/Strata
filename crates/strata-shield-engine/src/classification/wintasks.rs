use std::path::Path;

use super::reg_export::default_reg_path;
use super::regtask;

pub fn get_windows_scheduled_tasks() -> Vec<ScheduledTask> {
    get_windows_scheduled_tasks_from_reg(&default_reg_path("tasks.reg"))
}

pub fn get_windows_scheduled_tasks_from_reg(path: &Path) -> Vec<ScheduledTask> {
    regtask::get_scheduled_tasks_reg_from_reg(path)
        .into_iter()
        .map(|task| {
            let lower_path = task.path.to_ascii_lowercase();
            let outside_microsoft_path = !lower_path.contains("\\microsoft\\windows\\");

            let mut reasons = Vec::new();
            if outside_microsoft_path {
                reasons.push("non_microsoft_task_path".to_string());
            }
            if outside_microsoft_path
                && has_persistence_like_name(&task.name)
            {
                reasons.push("persistence_like_task_name".to_string());
            }
            if task.state.eq_ignore_ascii_case("Running") {
                reasons.push("task_currently_running".to_string());
            }

            ScheduledTask {
                name: task.name,
                state: task.state,
                path: task.path,
                outside_microsoft_path,
                suspicious: !reasons.is_empty(),
                reasons,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ScheduledTask {
    pub name: String,
    pub state: String,
    pub path: String,
    pub outside_microsoft_path: bool,
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

fn has_persistence_like_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["update", "updater", "startup", "run", "persist", "agent"]
        .iter()
        .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_tasks_and_flags_non_microsoft_persistence_candidates() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("tasks.reg");

        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Defrag\ScheduledDefrag]
"State"=dword:00000003

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Custom\StartupUpdater]
"State"=dword:00000004
"#,
        )
        .expect("write reg");

        let rows = get_windows_scheduled_tasks_from_reg(&file);
        assert_eq!(rows.len(), 2);

        let microsoft = rows
            .iter()
            .find(|task| task.name == "ScheduledDefrag")
            .expect("microsoft task");
        assert!(!microsoft.suspicious);

        let custom = rows
            .iter()
            .find(|task| task.name == "StartupUpdater")
            .expect("custom task");
        assert!(custom.suspicious);
        assert!(custom
            .reasons
            .iter()
            .any(|reason| reason == "non_microsoft_task_path"));
        assert!(custom
            .reasons
            .iter()
            .any(|reason| reason == "persistence_like_task_name"));
        assert!(custom
            .reasons
            .iter()
            .any(|reason| reason == "task_currently_running"));
    }
}
