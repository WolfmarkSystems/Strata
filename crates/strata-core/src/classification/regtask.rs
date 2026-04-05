use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32,
};

pub fn get_scheduled_tasks_reg() -> Vec<ScheduledTaskReg> {
    get_scheduled_tasks_reg_from_reg(&default_reg_path("tasks.reg"))
}

pub fn get_scheduled_tasks_reg_from_reg(path: &Path) -> Vec<ScheduledTaskReg> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\microsoft\\windows nt\\currentversion\\schedule\\taskcache\\tree\\")
    }) {
        out.push(ScheduledTaskReg {
            path: record.path.clone(),
            name: key_leaf(&record.path),
            state: record
                .values
                .get("State")
                .and_then(|v| parse_reg_u32(v))
                .map(map_task_state)
                .unwrap_or_else(|| "Unknown".to_string()),
            last_run: None,
            next_run: None,
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct ScheduledTaskReg {
    pub path: String,
    pub name: String,
    pub state: String,
    pub last_run: Option<u64>,
    pub next_run: Option<u64>,
}

pub fn get_task_scheduler_v2() -> Vec<TaskSchedulerV2> {
    get_task_scheduler_v2_from_reg(&default_reg_path("tasks.reg"))
}

pub fn get_task_scheduler_v2_from_reg(path: &Path) -> Vec<TaskSchedulerV2> {
    get_scheduled_tasks_reg_from_reg(path)
        .into_iter()
        .map(|entry| TaskSchedulerV2 {
            folder: folder_from_task_path(&entry.path),
            name: entry.name,
            action: "NotExposedInRegistryExport".to_string(),
            trigger: "NotExposedInRegistryExport".to_string(),
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TaskSchedulerV2 {
    pub folder: String,
    pub name: String,
    pub action: String,
    pub trigger: String,
}

fn map_task_state(value: u32) -> String {
    match value {
        0 => "Unknown",
        1 => "Disabled",
        2 => "Queued",
        3 => "Ready",
        4 => "Running",
        _ => "Unknown",
    }
    .to_string()
}

fn folder_from_task_path(key_path: &str) -> String {
    let marker = "\\TaskCache\\Tree\\";
    if let Some(idx) = key_path.find(marker) {
        let rest = &key_path[idx + marker.len()..];
        if let Some((folder, _name)) = rest.rsplit_once('\\') {
            return folder.to_string();
        }
        return "\\".to_string();
    }
    String::new()
}

#[allow(dead_code)]
fn parse_task_id(record_value: Option<&String>) -> Option<String> {
    record_value.and_then(|v| decode_reg_string(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_taskcache_tree_entries() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tasks.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Defrag\ScheduledDefrag]
"State"=dword:00000003
"Id"="{11111111-1111-1111-1111-111111111111}"
"#,
        )
        .unwrap();

        let rows = get_scheduled_tasks_reg_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "ScheduledDefrag");
        assert_eq!(rows[0].state, "Ready");
    }
}
