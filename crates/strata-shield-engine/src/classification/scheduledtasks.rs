use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use crate::errors::ForensicError;
use chrono::{DateTime, NaiveDateTime};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledTaskInputShape {
    Missing,
    Directory,
    Binary,
    Xml,
    JsonObject,
    JsonArray,
    Csv,
    LineText,
    Unknown,
}

impl ScheduledTaskInputShape {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Directory => "directory",
            Self::Binary => "binary",
            Self::Xml => "xml",
            Self::JsonObject => "json_object",
            Self::JsonArray => "json_array",
            Self::Csv => "csv",
            Self::LineText => "line_text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_scheduled_tasks_input_shape(path: &Path) -> ScheduledTaskInputShape {
    if !path.exists() {
        return ScheduledTaskInputShape::Missing;
    }
    if path.is_dir() {
        return ScheduledTaskInputShape::Directory;
    }

    let Ok(raw) = std::fs::read(path) else {
        return ScheduledTaskInputShape::Missing;
    };
    if raw.is_empty() {
        return ScheduledTaskInputShape::Unknown;
    }
    if raw
        .iter()
        .take(1024)
        .any(|b| *b == 0 && *b != b'\n' && *b != b'\r' && *b != b'\t')
    {
        return ScheduledTaskInputShape::Binary;
    }
    let text = String::from_utf8_lossy(&raw);
    let trimmed = text.trim_start();
    if trimmed.starts_with("<?xml") || trimmed.starts_with("<Task") {
        return ScheduledTaskInputShape::Xml;
    }
    if trimmed.starts_with('{') {
        return ScheduledTaskInputShape::JsonObject;
    }
    if trimmed.starts_with('[') {
        return ScheduledTaskInputShape::JsonArray;
    }
    if let Some(first_line) = trimmed.lines().next() {
        if first_line.contains(',') {
            return ScheduledTaskInputShape::Csv;
        }
    }
    if !trimmed.is_empty() {
        return ScheduledTaskInputShape::LineText;
    }
    ScheduledTaskInputShape::Unknown
}

#[derive(Debug, Clone)]
pub struct ScheduledTask {
    pub name: String,
    pub path: String,
    pub state: TaskState,
    pub last_run_time: Option<i64>,
    pub next_run_time: Option<i64>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub triggers: Vec<TaskTrigger>,
    pub actions: Vec<TaskAction>,
}

#[derive(Debug, Clone)]
pub enum TaskState {
    Ready,
    Running,
    Disabled,
    Queued,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct TaskTrigger {
    pub trigger_type: TriggerType,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub interval: Option<u32>,
    pub days_of_week: Option<u8>,
}

#[derive(Debug, Clone)]
pub enum TriggerType {
    Once,
    Daily,
    Weekly,
    Monthly,
    OnBoot,
    OnLogon,
    OnIdle,
    EventTrigger,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct TaskAction {
    pub action_type: ActionType,
    pub path: Option<String>,
    pub arguments: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ActionType {
    Execute,
    ComObject,
    Unknown,
}

pub fn parse_scheduled_tasks_xml(tasks_path: &Path) -> Result<Vec<ScheduledTask>, ForensicError> {
    let mut tasks = Vec::new();

    if !tasks_path.exists() {
        return Ok(tasks);
    }

    if let Ok(entries) = strata_fs::read_dir(tasks_path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();

            if entry_path.is_dir() {
                if let Ok(sub_tasks) = parse_scheduled_tasks_xml(&entry_path) {
                    tasks.extend(sub_tasks);
                }
            } else if is_task_xml_candidate(&entry_path) {
                if let Ok(content) = read_text_prefix(&entry_path, DEFAULT_TEXT_MAX_BYTES) {
                    if !content.contains("<Task") {
                        continue;
                    }
                    if let Ok(task) = parse_task_xml(&content, &entry_path) {
                        tasks.push(task);
                    }
                }
            }
        }
    }

    Ok(tasks)
}

pub fn parse_scheduled_tasks_text_fallback(tasks_path: &Path) -> Vec<ScheduledTask> {
    let mut tasks = Vec::new();
    collect_text_fallback(tasks_path, &mut tasks);
    tasks
}

fn collect_text_fallback(path: &Path, out: &mut Vec<ScheduledTask>) {
    if !path.exists() {
        return;
    }
    if path.is_dir() {
        if let Ok(entries) = strata_fs::read_dir(path) {
            for entry in entries.flatten() {
                collect_text_fallback(&entry.path(), out);
            }
        }
        return;
    }

    let Ok(content) = read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES) else {
        return;
    };
    if content.trim().is_empty() {
        return;
    }

    let mut actions = Vec::new();
    let commands = extract_xml_values(&content, "Command");
    let arguments = extract_xml_values(&content, "Arguments");
    for (idx, command) in commands.into_iter().enumerate() {
        actions.push(TaskAction {
            action_type: ActionType::Execute,
            path: Some(command),
            arguments: arguments.get(idx).cloned(),
        });
    }
    for class_id in extract_xml_values(&content, "ClassId") {
        actions.push(TaskAction {
            action_type: ActionType::ComObject,
            path: Some(class_id),
            arguments: None,
        });
    }

    if actions.is_empty() {
        for line in content.lines().take(300) {
            if let Some(path_candidate) = extract_executable_path(line) {
                actions.push(TaskAction {
                    action_type: ActionType::Execute,
                    path: Some(path_candidate),
                    arguments: None,
                });
            }
        }
    }

    if actions.is_empty() {
        return;
    }

    let last_run_time = extract_xml_values(&content, "LastRunTime")
        .first()
        .and_then(|v| parse_xml_datetime(v));
    let next_run_time = extract_xml_values(&content, "NextRunTime")
        .first()
        .and_then(|v| parse_xml_datetime(v));

    out.push(ScheduledTask {
        name: path
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        path: path.display().to_string(),
        state: TaskState::Unknown,
        last_run_time,
        next_run_time,
        author: extract_xml_values(&content, "Author").first().cloned(),
        description: extract_xml_values(&content, "Description").first().cloned(),
        triggers: Vec::new(),
        actions,
    });
}

fn extract_executable_path(line: &str) -> Option<String> {
    let lowered = line.to_ascii_lowercase();
    for marker in [
        ".exe", ".dll", ".cmd", ".bat", ".ps1", ".vbs", ".js", ".msi", ".psm1",
    ] {
        if let Some(end) = lowered.find(marker) {
            let prefix = &line[..end + marker.len()];
            let candidate = prefix
                .split(['"', '\'', ' ', '\t', '>', '<'])
                .rfind(|part| !part.trim().is_empty())
                .unwrap_or("")
                .trim_matches('"')
                .trim_matches('\'');
            if !candidate.is_empty() {
                return Some(candidate.replace('/', "\\"));
            }
        }
    }
    None
}

fn parse_task_xml(content: &str, path: &Path) -> Result<ScheduledTask, ForensicError> {
    let mut task = ScheduledTask {
        name: path
            .file_name()
            .map(|n| {
                n.to_string_lossy()
                    .to_string()
                    .trim_end_matches(".xml")
                    .to_string()
            })
            .unwrap_or_default(),
        path: path.display().to_string(),
        state: TaskState::Unknown,
        last_run_time: None,
        next_run_time: None,
        author: None,
        description: None,
        triggers: Vec::new(),
        actions: Vec::new(),
    };

    for line in content.lines() {
        let line = line.trim();

        if line.contains("<Author>") {
            task.author = extract_xml_value(line, "Author");
        } else if line.contains("<Description>") {
            task.description = extract_xml_value(line, "Description");
        } else if line.contains("<State>") {
            task.state = parse_task_state(extract_xml_value(line, "State").unwrap_or_default());
        } else if line.contains("<LastRunTime>") {
            task.last_run_time = extract_xml_value(line, "LastRunTime")
                .as_deref()
                .and_then(parse_xml_datetime);
        } else if line.contains("<NextRunTime>") {
            task.next_run_time = extract_xml_value(line, "NextRunTime")
                .as_deref()
                .and_then(parse_xml_datetime);
        } else if line.contains("<Trigger") || line.contains("Trigger>") {
            if let Some(trigger) = parse_trigger(line) {
                task.triggers.push(trigger);
            }
        } else if line.contains("<Exec>") || line.contains("<ComObject>") {
            if let Some(action) = parse_action(line) {
                task.actions.push(action);
            }
        }
    }

    if task.actions.is_empty() {
        let commands = extract_xml_values(content, "Command");
        let arguments = extract_xml_values(content, "Arguments");
        for (idx, command) in commands.into_iter().enumerate() {
            task.actions.push(TaskAction {
                action_type: ActionType::Execute,
                path: Some(command),
                arguments: arguments.get(idx).cloned(),
            });
        }
    }

    // Some task XML variants use ComHandler/ClassId blocks instead of Exec.
    let class_ids = extract_xml_values(content, "ClassId");
    let com_data = extract_xml_values(content, "Data");
    for (idx, class_id) in class_ids.into_iter().enumerate() {
        task.actions.push(TaskAction {
            action_type: ActionType::ComObject,
            path: Some(class_id),
            arguments: com_data.get(idx).cloned(),
        });
    }

    if task.author.is_none() {
        task.author = extract_xml_values(content, "UserId").first().cloned();
    }

    task.actions = dedupe_actions(task.actions);

    Ok(task)
}

fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);

    if let Some(start) = line.find(&start_tag) {
        let value_start = start + start_tag.len();
        if let Some(end) = line[value_start..].find(&end_tag) {
            return Some(line[value_start..value_start + end].to_string());
        }
    }

    None
}

fn extract_xml_values(content: &str, tag: &str) -> Vec<String> {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);
    let mut out = Vec::new();
    let mut rest = content;

    while let Some(start) = rest.find(&start_tag) {
        let value_start = start + start_tag.len();
        let after_start = &rest[value_start..];
        if let Some(end) = after_start.find(&end_tag) {
            let value = after_start[..end].trim();
            if !value.is_empty() {
                out.push(value.to_string());
            }
            rest = &after_start[end + end_tag.len()..];
        } else {
            break;
        }
    }

    out
}

fn parse_task_state(state: String) -> TaskState {
    let normalized = state.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "0" | "unknown" => TaskState::Unknown,
        "1" | "disabled" => TaskState::Disabled,
        "2" | "queued" => TaskState::Queued,
        "3" | "ready" => TaskState::Ready,
        "4" | "running" => TaskState::Running,
        _ if normalized.contains("ready") => TaskState::Ready,
        _ if normalized.contains("running") => TaskState::Running,
        _ if normalized.contains("disable") => TaskState::Disabled,
        _ if normalized.contains("queue") => TaskState::Queued,
        _ => TaskState::Unknown,
    }
}

fn parse_xml_datetime(datetime: &str) -> Option<i64> {
    let trimmed = datetime.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("n/a")
    {
        return None;
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.timestamp());
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, fmt) {
            return Some(naive.and_utc().timestamp());
        }
    }
    if let Some(ts) = parse_iso_datetime(trimmed) {
        return Some(ts);
    }
    if trimmed.len() >= 19 {
        if let Some(ts) = parse_iso_datetime(&trimmed[0..19]) {
            return Some(ts);
        }
    }

    None
}

fn parse_iso_datetime(datetime: &str) -> Option<i64> {
    if datetime.len() < 19 {
        return None;
    }

    let parts: Vec<&str> = datetime.split(['T', '-', ':', 'Z', '+']).collect();

    if parts.len() < 6 {
        return None;
    }

    let year: i64 = parts[0].parse().ok()?;
    let month: i64 = parts[1].parse().ok()?;
    let day: i64 = parts[2].parse().ok()?;
    let hour: i64 = parts[3].parse().ok()?;
    let minute: i64 = parts[4].parse().ok()?;
    let second: i64 = parts[5].parse().ok()?;

    let days_since_epoch = days_since_ymd(year, month, day);
    let seconds = ((days_since_epoch * 24 + hour) * 60 + minute) * 60 + second;

    Some(seconds)
}

fn days_since_ymd(year: i64, month: i64, day: i64) -> i64 {
    let mut days =
        (year - 1970) * 365 + (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400;

    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[(m - 1) as usize] as i64;
    }

    if month > 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
        days += 1;
    }

    days + day - 1
}

fn parse_trigger(line: &str) -> Option<TaskTrigger> {
    let trigger_type = if line.contains("TimeTrigger") {
        TriggerType::Once
    } else if line.contains("DailyTrigger") {
        TriggerType::Daily
    } else if line.contains("WeeklyTrigger") {
        TriggerType::Weekly
    } else if line.contains("MonthlyTrigger") {
        TriggerType::Monthly
    } else if line.contains("BootTrigger") {
        TriggerType::OnBoot
    } else if line.contains("LogonTrigger") {
        TriggerType::OnLogon
    } else if line.contains("IdleTrigger") {
        TriggerType::OnIdle
    } else {
        TriggerType::Unknown
    };

    let start_time = extract_xml_value(line, "StartBoundary")
        .as_deref()
        .and_then(parse_xml_datetime);

    let end_time = extract_xml_value(line, "EndBoundary")
        .as_deref()
        .and_then(parse_xml_datetime);

    Some(TaskTrigger {
        trigger_type,
        start_time,
        end_time,
        interval: None,
        days_of_week: None,
    })
}

fn is_task_xml_candidate(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    path.extension()
        .map(|e| e.eq_ignore_ascii_case("xml"))
        .unwrap_or_else(|| path.extension().is_none())
}

fn dedupe_actions(actions: Vec<TaskAction>) -> Vec<TaskAction> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for action in actions {
        let key = format!(
            "{:?}|{}|{}",
            action.action_type,
            action.path.as_deref().unwrap_or(""),
            action.arguments.as_deref().unwrap_or("")
        );
        if seen.insert(key) {
            out.push(action);
        }
    }
    out
}

fn parse_action(line: &str) -> Option<TaskAction> {
    if line.contains("<Exec>") {
        let path = extract_xml_value(line, "Command");
        let args = extract_xml_value(line, "Arguments");

        if path.is_none() && args.is_none() {
            return None;
        }

        Some(TaskAction {
            action_type: ActionType::Execute,
            path,
            arguments: args,
        })
    } else if line.contains("<ComObject>") {
        let com = extract_xml_value(line, "ComObject");
        com.as_ref()?;

        Some(TaskAction {
            action_type: ActionType::ComObject,
            path: com,
            arguments: None,
        })
    } else {
        None
    }
}

pub fn scan_task_scheduler() -> Result<Vec<ScheduledTask>, ForensicError> {
    let mut all_tasks = Vec::new();

    let system_tasks = Path::new("C:\\Windows\\System32\\Tasks");
    if let Ok(tasks) = parse_scheduled_tasks_xml(system_tasks) {
        all_tasks.extend(tasks);
    }

    let user_tasks = Path::new("C:\\Users\\");
    if let Ok(entries) = strata_fs::read_dir(user_tasks) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let user_task_path = path
                    .join("AppData")
                    .join("Local")
                    .join("Microsoft")
                    .join("Windows")
                    .join("Tasks");
                if user_task_path.exists() {
                    if let Ok(tasks) = parse_scheduled_tasks_xml(&user_task_path) {
                        all_tasks.extend(tasks);
                    }
                }
            }
        }
    }

    Ok(all_tasks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_task_xml_extracts_multiline_exec_blocks() {
        let xml = r#"
<Task>
  <RegistrationInfo>
    <Author>ACME</Author>
  </RegistrationInfo>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Tools\agent.exe</Command>
      <Arguments>--silent</Arguments>
    </Exec>
  </Actions>
</Task>
"#;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("task.xml");
        std::fs::write(&path, xml).unwrap();

        let task = parse_task_xml(xml, &path).unwrap();
        assert_eq!(task.actions.len(), 1);
        assert_eq!(task.actions[0].path.as_deref(), Some(r"C:\Tools\agent.exe"));
        assert_eq!(task.actions[0].arguments.as_deref(), Some("--silent"));
    }

    #[test]
    fn parse_iso_datetime_basic() {
        assert_eq!(parse_iso_datetime("1970-01-01T00:00:00"), Some(0));
    }

    #[test]
    fn parse_task_xml_extracts_com_handler_blocks() {
        let xml = r#"
<Task>
  <Actions Context="Author">
    <ComHandler>
      <ClassId>{11111111-2222-3333-4444-555555555555}</ClassId>
      <Data>payload</Data>
    </ComHandler>
  </Actions>
</Task>
"#;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("com_task.xml");
        std::fs::write(&path, xml).unwrap();

        let task = parse_task_xml(xml, &path).unwrap();
        assert_eq!(task.actions.len(), 1);
        assert!(matches!(task.actions[0].action_type, ActionType::ComObject));
        assert_eq!(
            task.actions[0].path.as_deref(),
            Some("{11111111-2222-3333-4444-555555555555}")
        );
        assert_eq!(task.actions[0].arguments.as_deref(), Some("payload"));
    }

    #[test]
    fn detect_scheduled_tasks_input_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tasks");
        let xml = dir.path().join("task.xml");
        let csv = dir.path().join("tasks.csv");
        let json = dir.path().join("tasks.json");

        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&xml, "<?xml version=\"1.0\"?><Task></Task>").unwrap();
        std::fs::write(&csv, "name,command\nA,C:\\Tools\\a.exe\n").unwrap();
        std::fs::write(&json, r#"[{"name":"A"}]"#).unwrap();

        assert_eq!(
            detect_scheduled_tasks_input_shape(&root),
            ScheduledTaskInputShape::Directory
        );
        assert_eq!(
            detect_scheduled_tasks_input_shape(&xml),
            ScheduledTaskInputShape::Xml
        );
        assert_eq!(
            detect_scheduled_tasks_input_shape(&csv),
            ScheduledTaskInputShape::Csv
        );
        assert_eq!(
            detect_scheduled_tasks_input_shape(&json),
            ScheduledTaskInputShape::JsonArray
        );
        assert_eq!(ScheduledTaskInputShape::Directory.as_str(), "directory");
    }

    #[test]
    fn parse_scheduled_tasks_text_fallback_extracts_actions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("fallback.txt");
        std::fs::write(
            &file,
            r#"
<Task>
  <Author>LabUser</Author>
  <LastRunTime>2026-03-10T11:15:00</LastRunTime>
  <Actions>
    <Exec>
      <Command>C:\Tools\taskrunner.exe</Command>
      <Arguments>--daily</Arguments>
    </Exec>
  </Actions>
</Task>
"#,
        )
        .unwrap();

        let rows = parse_scheduled_tasks_text_fallback(dir.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actions.len(), 1);
        assert_eq!(
            rows[0].actions[0].path.as_deref(),
            Some(r"C:\Tools\taskrunner.exe")
        );
        assert_eq!(rows[0].actions[0].arguments.as_deref(), Some("--daily"));
        assert_eq!(rows[0].author.as_deref(), Some("LabUser"));
        assert!(rows[0].last_run_time.is_some());
    }

    #[test]
    fn parse_xml_datetime_supports_timezone_offsets() {
        assert_eq!(
            parse_xml_datetime("2026-03-10T12:00:00+02:00"),
            Some(1_773_136_800)
        );
    }

    #[test]
    fn parse_task_state_accepts_numeric_codes() {
        assert!(matches!(
            parse_task_state("3".to_string()),
            TaskState::Ready
        ));
        assert!(matches!(
            parse_task_state("4".to_string()),
            TaskState::Running
        ));
        assert!(matches!(
            parse_task_state("1".to_string()),
            TaskState::Disabled
        ));
        assert!(matches!(
            parse_task_state("2".to_string()),
            TaskState::Queued
        ));
    }

    #[test]
    fn parse_scheduled_tasks_xml_reads_extensionless_task_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("TaskWithoutExtension");
        std::fs::write(
            &file,
            r#"<Task><Actions><Exec><Command>C:\Tools\runner.exe</Command></Exec></Actions></Task>"#,
        )
        .unwrap();

        let rows = parse_scheduled_tasks_xml(dir.path()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actions.len(), 1);
        assert_eq!(
            rows[0].actions[0].path.as_deref(),
            Some(r"C:\Tools\runner.exe")
        );
    }

    #[test]
    fn parse_task_xml_uses_userid_when_author_missing_and_dedupes_com_actions() {
        let xml = r#"
<Task>
  <Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals>
  <Actions>
    <ComHandler><ClassId>{11111111-2222-3333-4444-555555555555}</ClassId></ComHandler>
  </Actions>
  <Actions>
    <ComHandler><ClassId>{11111111-2222-3333-4444-555555555555}</ClassId></ComHandler>
  </Actions>
</Task>
"#;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("dup_com.xml");
        std::fs::write(&path, xml).unwrap();

        let task = parse_task_xml(xml, &path).unwrap();
        assert_eq!(task.author.as_deref(), Some("S-1-5-18"));
        assert_eq!(task.actions.len(), 1);
        assert!(matches!(task.actions[0].action_type, ActionType::ComObject));
    }
}
