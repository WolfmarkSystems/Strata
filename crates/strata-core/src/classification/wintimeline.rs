use crate::errors::ForensicError;
use rusqlite::{types::ValueRef, Connection};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct TimelineEntry {
    pub id: String,
    pub app_name: String,
    pub title: String,
    pub description: String,
    pub timestamp: u64,
    pub payload: String,
    pub group_id: Option<String>,
}

pub fn get_timeline_entries() -> Result<Vec<TimelineEntry>, ForensicError> {
    if let Some(path) = resolve_activities_cache_path() {
        return Ok(load_timeline_entries_from_db(&path));
    }
    Ok(Vec::new())
}

pub fn get_timeline_range(start: u64, end: u64) -> Result<Vec<TimelineEntry>, ForensicError> {
    let entries = get_timeline_entries()?;
    Ok(entries
        .into_iter()
        .filter(|e| e.timestamp >= start && e.timestamp <= end)
        .collect())
}

pub fn get_timeline_apps() -> Result<Vec<TimelineApp>, ForensicError> {
    let entries = get_timeline_entries()?;
    let mut by_app: BTreeMap<String, TimelineApp> = BTreeMap::new();
    for entry in entries {
        let app = by_app.entry(entry.app_name.clone()).or_insert(TimelineApp {
            name: entry.app_name.clone(),
            entry_count: 0,
            last_used: None,
        });
        app.entry_count += 1;
        app.last_used = Some(app.last_used.unwrap_or(0).max(entry.timestamp));
    }
    Ok(by_app.into_values().collect())
}

#[derive(Debug, Clone, Default)]
pub struct TimelineApp {
    pub name: String,
    pub entry_count: u32,
    pub last_used: Option<u64>,
}

pub fn search_timeline(query: &str) -> Result<Vec<TimelineEntry>, ForensicError> {
    let q = query.to_ascii_lowercase();
    let entries = get_timeline_entries()?;
    Ok(entries
        .into_iter()
        .filter(|e| {
            e.title.to_ascii_lowercase().contains(&q)
                || e.description.to_ascii_lowercase().contains(&q)
                || e.app_name.to_ascii_lowercase().contains(&q)
        })
        .collect())
}

pub fn get_timeline_sync_status() -> Result<TimelineSyncStatus, ForensicError> {
    let path = resolve_activities_cache_path();
    Ok(TimelineSyncStatus {
        enabled: path.is_some(),
        last_sync: path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
    })
}

#[derive(Debug, Clone, Default)]
pub struct TimelineSyncStatus {
    pub enabled: bool,
    pub last_sync: Option<u64>,
}

pub fn get_timeline_group(group_id: &str) -> Result<Vec<TimelineEntry>, ForensicError> {
    let entries = get_timeline_entries()?;
    Ok(entries
        .into_iter()
        .filter(|e| e.group_id.as_deref().unwrap_or_default() == group_id)
        .collect())
}

pub fn get_activities_cache_path() -> String {
    if let Some(path) = resolve_activities_cache_path() {
        return path.display().to_string();
    }
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        return PathBuf::from(user_profile)
            .join("AppData")
            .join("Local")
            .join("ConnectedDevicesPlatform")
            .display()
            .to_string();
    }
    r"C:\Users\Default\AppData\Local\ConnectedDevicesPlatform".to_string()
}

fn resolve_activities_cache_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("FORENSIC_TIMELINE_DB") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    let user_profile = std::env::var("USERPROFILE").ok()?;
    let base = PathBuf::from(user_profile)
        .join("AppData")
        .join("Local")
        .join("ConnectedDevicesPlatform");
    if !base.exists() {
        return None;
    }

    // Typical location: ...\ConnectedDevicesPlatform\<SID>\ActivitiesCache.db
    if let Ok(entries) = std::fs::read_dir(&base) {
        for entry in entries.flatten() {
            let p = entry.path().join("ActivitiesCache.db");
            if p.exists() {
                return Some(p);
            }
        }
    }

    None
}

fn load_timeline_entries_from_db(path: &Path) -> Vec<TimelineEntry> {
    let conn = match Connection::open(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let table_names = list_tables(&conn);
    let mut all = Vec::new();
    for table in table_names
        .into_iter()
        .filter(|t| t.to_ascii_lowercase().contains("activity"))
    {
        let mut rows = load_from_table(&conn, &table);
        all.append(&mut rows);
    }

    all.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    all
}

fn list_tables(conn: &Connection) -> Vec<String> {
    let mut out = Vec::new();
    let mut stmt = match conn.prepare("SELECT name FROM sqlite_master WHERE type='table'") {
        Ok(s) => s,
        Err(_) => return out,
    };
    let mapped = stmt.query_map([], |row| row.get::<_, String>(0));
    if let Ok(iter) = mapped {
        for name in iter.flatten() {
            out.push(name);
        }
    }
    out
}

fn load_from_table(conn: &Connection, table: &str) -> Vec<TimelineEntry> {
    let columns = table_columns(conn, table);
    if columns.is_empty() {
        return Vec::new();
    }

    let ts_col = choose_column(
        &columns,
        &[
            "StartTime",
            "LastModifiedTime",
            "LastModifiedOnClient",
            "CreatedTime",
            "ActivityStartTime",
        ],
    );
    let app_col = choose_column(
        &columns,
        &[
            "AppId",
            "AppActivityId",
            "PlatformDeviceId",
            "PackageIdHash",
        ],
    );
    let title_col = choose_column(
        &columns,
        &["DisplayText", "ActivityType", "Group", "ClipboardPayload"],
    );
    let desc_col = choose_column(&columns, &["Payload", "Content", "Description"]);
    let group_col = choose_column(&columns, &["Group", "ParentActivityId", "ActivityId"]);

    let sql = format!(
        "SELECT rowid, {}, {}, {}, {} FROM \"{}\" LIMIT 1000",
        selected_or_null(ts_col.as_deref()),
        selected_or_null(app_col.as_deref()),
        selected_or_null(title_col.as_deref()),
        selected_or_null(desc_col.as_deref()),
        table
    );

    let mut out = Vec::new();
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return out,
    };

    let rows = stmt.query_map([], |row| {
        let rowid: i64 = row.get(0)?;
        let ts = normalize_timestamp(value_ref_to_string(row.get_ref(1)?));
        let app_name =
            value_ref_to_string(row.get_ref(2)?).unwrap_or_else(|| "unknown".to_string());
        let title = value_ref_to_string(row.get_ref(3)?).unwrap_or_else(|| table.to_string());
        let description = value_ref_to_string(row.get_ref(4)?).unwrap_or_default();
        Ok((rowid, ts, app_name, title, description))
    });

    if let Ok(iter) = rows {
        for (rowid, ts, app_name, title, description) in iter.flatten() {
            let group_id = if let Some(col) = &group_col {
                query_group_value(conn, table, rowid, col)
            } else {
                None
            };

            out.push(TimelineEntry {
                id: format!("{table}:{rowid}"),
                app_name,
                title,
                description: description.clone(),
                timestamp: ts,
                payload: description,
                group_id,
            });
        }
    }

    out
}

fn query_group_value(conn: &Connection, table: &str, rowid: i64, col: &str) -> Option<String> {
    let sql = format!("SELECT \"{}\" FROM \"{}\" WHERE rowid = ?1", col, table);
    let mut stmt = conn.prepare(&sql).ok()?;
    let value = stmt.query_row([rowid], |row| {
        let value = value_ref_to_string(row.get_ref(0)?);
        Ok(value)
    });
    value.ok().flatten()
}

fn table_columns(conn: &Connection, table: &str) -> Vec<String> {
    let mut out = Vec::new();
    let sql = format!("PRAGMA table_info(\"{}\")", table);
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return out,
    };
    let rows = stmt.query_map([], |row| row.get::<_, String>(1));
    if let Ok(iter) = rows {
        for col in iter.flatten() {
            out.push(col);
        }
    }
    out
}

fn choose_column(columns: &[String], preferred: &[&str]) -> Option<String> {
    for wanted in preferred {
        if let Some(found) = columns.iter().find(|c| c.eq_ignore_ascii_case(wanted)) {
            return Some(found.clone());
        }
    }
    None
}

fn selected_or_null(column: Option<&str>) -> String {
    match column {
        Some(c) => format!("\"{}\"", c),
        None => "NULL".to_string(),
    }
}

fn value_ref_to_string(value: ValueRef<'_>) -> Option<String> {
    match value {
        ValueRef::Null => None,
        ValueRef::Integer(v) => Some(v.to_string()),
        ValueRef::Real(v) => Some(v.to_string()),
        ValueRef::Text(bytes) => Some(String::from_utf8_lossy(bytes).to_string()),
        ValueRef::Blob(bytes) => Some(format!("blob:{}b", bytes.len())),
    }
}

fn normalize_timestamp(value: Option<String>) -> u64 {
    let Some(raw) = value else {
        return 0;
    };
    let parsed = match raw.trim().parse::<i64>() {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if parsed <= 0 {
        return 0;
    }

    // FILETIME-like values
    if parsed > 11644473600_i64 * 10_000_000_i64 {
        return (parsed as u64 / 10_000_000u64).saturating_sub(11_644_473_600u64);
    }

    // millisecond epoch
    if parsed > 4_000_000_000_i64 {
        return (parsed as u64) / 1000u64;
    }

    parsed as u64
}
