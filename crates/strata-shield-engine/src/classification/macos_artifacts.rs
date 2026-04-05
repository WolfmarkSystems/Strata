use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;

const APPLE_UNIX_EPOCH_OFFSET_SECS: i64 = 978_307_200;
const DEFAULT_DB_QUERY_LIMIT: usize = 5_000;

#[derive(Debug, Clone, Default)]
pub struct MacosSafariHistoryEntry {
    pub url: String,
    pub title: Option<String>,
    pub visit_time_unix: Option<u64>,
    pub visit_count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct MacosSafariDownload {
    pub source_url: String,
    pub target_path: String,
    pub downloaded_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct MacosQuarantineEvent {
    pub event_id: String,
    pub timestamp_unix: Option<u64>,
    pub agent_name: String,
    pub agent_bundle_id: String,
    pub data_url: String,
    pub origin_url: String,
    pub sender_name: String,
}

#[derive(Debug, Clone, Default)]
pub struct MacosShellHistoryEntry {
    pub shell: String,
    pub command: String,
    pub timestamp_unix: Option<u64>,
    pub source_path: String,
}

pub fn get_macos_safari_history() -> Vec<MacosSafariHistoryEntry> {
    for db_path in safari_history_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let rows = parse_safari_history_db(&conn);
        if !rows.is_empty() {
            return rows;
        }
    }
    Vec::new()
}

pub fn get_macos_safari_downloads() -> Vec<MacosSafariDownload> {
    for db_path in safari_history_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let rows = parse_safari_downloads_db(&conn);
        if !rows.is_empty() {
            return rows;
        }
    }
    Vec::new()
}

pub fn get_macos_quarantine_events() -> Vec<MacosQuarantineEvent> {
    for db_path in quarantine_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let rows = parse_quarantine_events_db(&conn);
        if !rows.is_empty() {
            return rows;
        }
    }
    Vec::new()
}

pub fn get_macos_shell_history() -> Vec<MacosShellHistoryEntry> {
    let mut out = Vec::new();
    out.extend(load_shell_history(
        "zsh",
        zsh_history_candidates(),
        parse_zsh_history_text,
    ));
    out.extend(load_shell_history(
        "bash",
        bash_history_candidates(),
        parse_bash_history_text,
    ));
    out
}

type ShellHistoryParser = fn(&str) -> Vec<(String, Option<u64>)>;

fn load_shell_history(
    shell: &str,
    candidates: Vec<PathBuf>,
    parser: ShellHistoryParser,
) -> Vec<MacosShellHistoryEntry> {
    let mut out = Vec::new();
    for path in candidates {
        let Ok(content) = read_text_prefix(&path, DEFAULT_TEXT_MAX_BYTES) else {
            continue;
        };
        let parsed = parser(&content);
        for (command, timestamp_unix) in parsed {
            if command.is_empty() {
                continue;
            }
            out.push(MacosShellHistoryEntry {
                shell: shell.to_string(),
                command,
                timestamp_unix,
                source_path: path.display().to_string(),
            });
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

fn parse_safari_history_db(conn: &Connection) -> Vec<MacosSafariHistoryEntry> {
    let mut out = Vec::new();
    let query = format!(
        "SELECT COALESCE(hi.url, ''), COALESCE(hi.title, ''), \
         CAST(hv.visit_time AS REAL), COALESCE(hi.visit_count, 1) \
         FROM history_visits hv \
         JOIN history_items hi ON hi.id = hv.history_item \
         ORDER BY hv.visit_time DESC \
         LIMIT {}",
        DEFAULT_DB_QUERY_LIMIT
    );

    let Ok(mut stmt) = conn.prepare(&query) else {
        return out;
    };
    let rows = stmt.query_map([], |row| {
        let title_raw = row.get::<_, String>(1).unwrap_or_default();
        Ok(MacosSafariHistoryEntry {
            url: row.get::<_, String>(0).unwrap_or_default(),
            title: if title_raw.trim().is_empty() {
                None
            } else {
                Some(title_raw)
            },
            visit_time_unix: coerce_row_time_to_unix(row.get_ref(2).ok()),
            visit_count: row.get::<_, i64>(3).unwrap_or(1).max(0) as u32,
        })
    });
    let Ok(iter) = rows else {
        return out;
    };
    for item in iter.flatten() {
        if !item.url.is_empty() {
            out.push(item);
        }
    }
    out
}

fn parse_safari_downloads_db(conn: &Connection) -> Vec<MacosSafariDownload> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    let queries = [
        format!(
            "SELECT COALESCE(duc.url, ''), COALESCE(d.path, ''), CAST(d.download_entry_date AS REAL) \
             FROM downloads d \
             LEFT JOIN downloads_url_chains duc ON duc.id = d.id \
             ORDER BY d.download_entry_date DESC \
             LIMIT {}",
            DEFAULT_DB_QUERY_LIMIT
        ),
        format!(
            "SELECT COALESCE(url, ''), COALESCE(path, ''), CAST(download_entry_date AS REAL) \
             FROM downloads \
             ORDER BY download_entry_date DESC \
             LIMIT {}",
            DEFAULT_DB_QUERY_LIMIT
        ),
    ];

    for query in &queries {
        let Ok(mut stmt) = conn.prepare(query) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            Ok(MacosSafariDownload {
                source_url: row.get::<_, String>(0).unwrap_or_default(),
                target_path: row.get::<_, String>(1).unwrap_or_default(),
                downloaded_at_unix: coerce_row_time_to_unix(row.get_ref(2).ok()),
            })
        });
        let Ok(iter) = rows else {
            continue;
        };
        for item in iter.flatten() {
            if item.source_url.is_empty() && item.target_path.is_empty() {
                continue;
            }
            let key = format!(
                "{}|{}|{}",
                item.source_url,
                item.target_path,
                item.downloaded_at_unix.unwrap_or(0)
            );
            if seen.insert(key) {
                out.push(item);
            }
        }
    }

    out
}

fn parse_quarantine_events_db(conn: &Connection) -> Vec<MacosQuarantineEvent> {
    let mut out = Vec::new();
    let query = format!(
        "SELECT \
            COALESCE(LSQuarantineEventIdentifier, ''), \
            CAST(LSQuarantineTimeStamp AS REAL), \
            COALESCE(LSQuarantineAgentName, ''), \
            COALESCE(LSQuarantineAgentBundleIdentifier, ''), \
            COALESCE(LSQuarantineDataURLString, ''), \
            COALESCE(LSQuarantineOriginURLString, ''), \
            COALESCE(LSQuarantineSenderName, '') \
         FROM LSQuarantineEvent \
         ORDER BY LSQuarantineTimeStamp DESC \
         LIMIT {}",
        DEFAULT_DB_QUERY_LIMIT
    );

    let Ok(mut stmt) = conn.prepare(&query) else {
        return out;
    };
    let rows = stmt.query_map([], |row| {
        Ok(MacosQuarantineEvent {
            event_id: row.get::<_, String>(0).unwrap_or_default(),
            timestamp_unix: coerce_row_time_to_unix(row.get_ref(1).ok()),
            agent_name: row.get::<_, String>(2).unwrap_or_default(),
            agent_bundle_id: row.get::<_, String>(3).unwrap_or_default(),
            data_url: row.get::<_, String>(4).unwrap_or_default(),
            origin_url: row.get::<_, String>(5).unwrap_or_default(),
            sender_name: row.get::<_, String>(6).unwrap_or_default(),
        })
    });
    let Ok(iter) = rows else {
        return out;
    };

    for item in iter.flatten() {
        if item.event_id.is_empty() && item.data_url.is_empty() && item.origin_url.is_empty() {
            continue;
        }
        out.push(item);
    }
    out
}

fn coerce_row_time_to_unix(value: Option<ValueRef<'_>>) -> Option<u64> {
    match value {
        Some(ValueRef::Integer(v)) => normalize_possible_apple_time(v as f64),
        Some(ValueRef::Real(v)) => normalize_possible_apple_time(v),
        Some(ValueRef::Text(bytes)) => {
            let text = String::from_utf8_lossy(bytes);
            text.trim()
                .parse::<f64>()
                .ok()
                .and_then(normalize_possible_apple_time)
        }
        _ => None,
    }
}

fn normalize_possible_apple_time(raw: f64) -> Option<u64> {
    if !raw.is_finite() || raw <= 0.0 {
        return None;
    }

    // Heuristic:
    // - If timestamp is already in Unix epoch seconds, keep it.
    // - Otherwise treat it as macOS absolute time (seconds since 2001-01-01 UTC).
    if raw >= 1_000_000_000.0 {
        return Some(raw as u64);
    }

    let unix = (raw as i64).saturating_add(APPLE_UNIX_EPOCH_OFFSET_SECS);
    if unix > 0 {
        Some(unix as u64)
    } else {
        None
    }
}

fn parse_zsh_history_text(content: &str) -> Vec<(String, Option<u64>)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Extended history format:
        // : 1700000000:0;command here
        if let Some(rest) = trimmed.strip_prefix(": ") {
            let mut parts = rest.splitn(2, ';');
            let meta = parts.next().unwrap_or_default();
            let command = parts.next().unwrap_or_default().trim();
            if command.is_empty() {
                continue;
            }
            let ts = meta
                .split(':')
                .next()
                .and_then(|x| x.trim().parse::<u64>().ok());
            out.push((command.to_string(), ts));
            continue;
        }

        out.push((trimmed.to_string(), None));
    }
    out
}

fn parse_bash_history_text(content: &str) -> Vec<(String, Option<u64>)> {
    let mut out = Vec::new();
    let mut pending_ts: Option<u64> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // HISTTIMEFORMAT style:
        // #1700000000
        if let Some(raw_ts) = trimmed.strip_prefix('#') {
            if raw_ts.chars().all(|ch| ch.is_ascii_digit()) {
                pending_ts = raw_ts.parse::<u64>().ok();
                continue;
            }
        }

        out.push((trimmed.to_string(), pending_ts));
        pending_ts = None;
    }

    out
}

fn paths_from_env_list(key: &str) -> Vec<PathBuf> {
    let Ok(raw) = env::var(key) else {
        return Vec::new();
    };
    raw.split(';')
        .flat_map(|chunk| chunk.split(','))
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn home_dir() -> Option<PathBuf> {
    env::var("HOME").ok().map(PathBuf::from)
}

fn safari_history_db_candidates() -> Vec<PathBuf> {
    let mut out = paths_from_env_list("FORENSIC_MACOS_SAFARI_HISTORY_DB");
    if let Some(home) = home_dir() {
        out.push(home.join("Library").join("Safari").join("History.db"));
    }
    out.push(
        PathBuf::from("artifacts")
            .join("macos")
            .join("safari")
            .join("History.db"),
    );
    out.push(
        PathBuf::from("artifacts")
            .join("browser")
            .join("safari")
            .join("History.db"),
    );
    dedup_paths(out)
}

fn quarantine_db_candidates() -> Vec<PathBuf> {
    let mut out = paths_from_env_list("FORENSIC_MACOS_QUARANTINE_DB");
    if let Some(home) = home_dir() {
        let prefs = home.join("Library").join("Preferences");
        out.push(prefs.join("com.apple.LaunchServices.QuarantineEventsV2"));
        out.push(prefs.join("com.apple.LaunchServices.QuarantineEventsV2.db"));
    }
    out.push(
        PathBuf::from("artifacts")
            .join("macos")
            .join("quarantine")
            .join("QuarantineEventsV2.db"),
    );
    dedup_paths(out)
}

fn zsh_history_candidates() -> Vec<PathBuf> {
    let mut out = paths_from_env_list("FORENSIC_MACOS_ZSH_HISTORY");
    if let Some(home) = home_dir() {
        out.push(home.join(".zsh_history"));
    }
    out.push(
        PathBuf::from("artifacts")
            .join("macos")
            .join("shell")
            .join(".zsh_history"),
    );
    dedup_paths(out)
}

fn bash_history_candidates() -> Vec<PathBuf> {
    let mut out = paths_from_env_list("FORENSIC_MACOS_BASH_HISTORY");
    if let Some(home) = home_dir() {
        out.push(home.join(".bash_history"));
    }
    out.push(
        PathBuf::from("artifacts")
            .join("macos")
            .join("shell")
            .join(".bash_history"),
    );
    dedup_paths(out)
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in paths {
        let key = path.to_string_lossy().to_string();
        if seen.insert(key) {
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_zsh_extended_history_format() {
        let parsed = parse_zsh_history_text(": 1700001234:0;ls -la\n: 1700001235:0;pwd\n");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "ls -la");
        assert_eq!(parsed[0].1, Some(1_700_001_234));
        assert_eq!(parsed[1].0, "pwd");
    }

    #[test]
    fn parses_bash_history_with_timestamp_markers() {
        let parsed = parse_bash_history_text("#1700000000\nls\n#1700000001\ncat test.txt\n");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "ls");
        assert_eq!(parsed[0].1, Some(1_700_000_000));
        assert_eq!(parsed[1].0, "cat test.txt");
        assert_eq!(parsed[1].1, Some(1_700_000_001));
    }

    #[test]
    fn converts_apple_epoch_to_unix() {
        let unix = normalize_possible_apple_time(600.0).unwrap();
        assert_eq!(unix, 978_307_800);
    }

    #[test]
    fn parses_quarantine_rows_from_sqlite() {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("QuarantineEventsV2.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE LSQuarantineEvent (
                LSQuarantineEventIdentifier TEXT,
                LSQuarantineTimeStamp REAL,
                LSQuarantineAgentName TEXT,
                LSQuarantineAgentBundleIdentifier TEXT,
                LSQuarantineDataURLString TEXT,
                LSQuarantineOriginURLString TEXT,
                LSQuarantineSenderName TEXT
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO LSQuarantineEvent (
                LSQuarantineEventIdentifier,
                LSQuarantineTimeStamp,
                LSQuarantineAgentName,
                LSQuarantineAgentBundleIdentifier,
                LSQuarantineDataURLString,
                LSQuarantineOriginURLString,
                LSQuarantineSenderName
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                "evt-1",
                1200.0f64,
                "Safari",
                "com.apple.Safari",
                "https://example.com/file.dmg",
                "https://example.com",
                "example.com",
            ),
        )
        .unwrap();
        drop(conn);

        let conn = Connection::open(&db_path).unwrap();
        let events = parse_quarantine_events_db(&conn);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-1");
        assert_eq!(events[0].agent_name, "Safari");
        assert_eq!(events[0].timestamp_unix, Some(978_308_400));
    }
}
