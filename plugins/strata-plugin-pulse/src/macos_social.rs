//! macOS third-party social app database coverage.
//!
//! Pulse owns user-installed third-party apps. This module targets the
//! common macOS app-support/container locations for Twitter/X,
//! Instagram, Facebook Messenger, Snapchat, and TikTok, extracting
//! deterministic row-level message/activity records when familiar
//! SQLite tables are present and falling back to table inventory records
//! for schema drift.

use rusqlite::Connection;
use serde_json::json;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use crate::ios::util::{count_rows, open_sqlite_ro, table_exists};

struct SocialApp {
    app: &'static str,
    path_needles: &'static [&'static str],
    db_names: &'static [&'static str],
    table_specs: &'static [TableSpec],
}

struct TableSpec {
    table: &'static str,
    artifact_type: &'static str,
    title: &'static str,
    text_cols: &'static [&'static str],
    actor_cols: &'static [&'static str],
    ts_cols: &'static [&'static str],
    mitre: &'static str,
    value: ForensicValue,
}

const TWITTER: SocialApp = SocialApp {
    app: "Twitter/X",
    path_needles: &[
        "/library/application support/twitter/",
        "/library/containers/com.twitter.twitter-mac/",
    ],
    db_names: &["gryphon.sqlite", "db.sqlite", "twitter.sqlite"],
    table_specs: &[
        TableSpec {
            table: "messages",
            artifact_type: "social_twitter_dm",
            title: "Twitter/X direct message",
            text_cols: &["text", "message", "body", "content"],
            actor_cols: &["sender", "sender_id", "user_id", "author_id"],
            ts_cols: &["created_at", "created", "timestamp", "time"],
            mitre: "T1636.002",
            value: ForensicValue::High,
        },
        TableSpec {
            table: "statuses",
            artifact_type: "social_twitter_status",
            title: "Twitter/X status",
            text_cols: &["text", "full_text", "body", "content"],
            actor_cols: &["user_id", "author_id", "screen_name"],
            ts_cols: &["created_at", "created", "timestamp", "time"],
            mitre: "T1636.002",
            value: ForensicValue::Medium,
        },
    ],
};

const INSTAGRAM: SocialApp = SocialApp {
    app: "Instagram",
    path_needles: &["/library/application support/instagram/"],
    db_names: &["direct.db", "directphotos.sqlite", "db.sqlite"],
    table_specs: &[TableSpec {
        table: "messages",
        artifact_type: "social_instagram_dm",
        title: "Instagram direct message",
        text_cols: &["text", "message", "body", "content"],
        actor_cols: &["sender_id", "sender", "user_id", "thread_id"],
        ts_cols: &["timestamp", "created_at", "created_time", "time"],
        mitre: "T1636.002",
        value: ForensicValue::High,
    }],
};

const FACEBOOK: SocialApp = SocialApp {
    app: "Facebook Messenger",
    path_needles: &[
        "/library/application support/facebook/",
        "/library/application support/messenger/",
    ],
    db_names: &["messenger.db", "fbmessenger.db", "threads_db2"],
    table_specs: &[TableSpec {
        table: "messages",
        artifact_type: "social_facebook_message",
        title: "Facebook Messenger message",
        text_cols: &["text", "message", "body", "content"],
        actor_cols: &["sender", "sender_id", "user_id", "thread_id"],
        ts_cols: &["timestamp", "created_at", "created_time", "time"],
        mitre: "T1636.002",
        value: ForensicValue::High,
    }],
};

const SNAPCHAT: SocialApp = SocialApp {
    app: "Snapchat",
    path_needles: &["/library/application support/snapchat/"],
    db_names: &["arroyo.db", "gallery.encrypted.db", "db.sqlite"],
    table_specs: &[TableSpec {
        table: "messages",
        artifact_type: "social_snapchat_message",
        title: "Snapchat message metadata",
        text_cols: &["body", "text", "message", "content"],
        actor_cols: &["sender", "sender_id", "conversation_id", "thread_id"],
        ts_cols: &["timestamp", "created_at", "created_time", "time"],
        mitre: "T1636.002",
        value: ForensicValue::High,
    }],
};

const TIKTOK: SocialApp = SocialApp {
    app: "TikTok",
    path_needles: &["/library/application support/tiktok/"],
    db_names: &["awemeim.db", "db.sqlite"],
    table_specs: &[TableSpec {
        table: "msg",
        artifact_type: "social_tiktok_dm",
        title: "TikTok direct message",
        text_cols: &["content", "text", "message", "body"],
        actor_cols: &["sender", "sender_id", "user_id", "conversation_id"],
        ts_cols: &["created_time", "timestamp", "created_at", "time"],
        mitre: "T1636.002",
        value: ForensicValue::High,
    }],
};

const APPS: &[SocialApp] = &[TWITTER, INSTAGRAM, FACEBOOK, SNAPCHAT, TIKTOK];

pub fn matches(path: &Path) -> bool {
    app_for_path(path).is_some() || cloud_container_app(path).is_some()
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    if let Some((app, artifact_type)) = cloud_container_app(path) {
        return vec![ArtifactRecord {
            category: ArtifactCategory::SocialMedia,
            subcategory: artifact_type.to_string(),
            timestamp: None,
            title: format!("{app} iCloud container metadata"),
            detail: format!(
                "{app} iCloud container metadata present at {}",
                path.to_string_lossy()
            ),
            source_path: path.to_string_lossy().into_owned(),
            forensic_value: ForensicValue::Medium,
            mitre_technique: Some("T1636.002".to_string()),
            is_suspicious: false,
            raw_data: Some(json!({
                "artifact_type": artifact_type,
                "app": app,
                "confidence": "Medium",
            })),
            confidence: 65,
        }];
    }

    let Some(app) = app_for_path(path) else {
        return Vec::new();
    };
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for spec in app.table_specs {
        if table_exists(&conn, spec.table) {
            out.extend(parse_table(&conn, path, app, spec));
        }
    }

    if out.is_empty() {
        out.extend(inventory_record(&conn, path, app));
    }
    out
}

fn cloud_container_app(path: &Path) -> Option<(&'static str, &'static str)> {
    let path_lc = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let in_cloud_container = path_lc
        .contains("/library/application support/clouddocs/session/containers/")
        || path_lc.contains("/library/mobile documents/");
    if !in_cloud_container {
        return None;
    }
    if path_lc.contains("com.burbn.instagram") || path_lc.contains("icloud~com~burbn~instagram") {
        return Some(("Instagram", "social_instagram_icloud_container"));
    }
    if path_lc.contains("com.facebook") || path_lc.contains("com.messenger") {
        return Some(("Facebook Messenger", "social_facebook_icloud_container"));
    }
    if path_lc.contains("com.toyopagroup.picaboo") || path_lc.contains("snapchat") {
        return Some(("Snapchat", "social_snapchat_icloud_container"));
    }
    if path_lc.contains("musically") || path_lc.contains("tiktok") {
        return Some(("TikTok", "social_tiktok_icloud_container"));
    }
    None
}

fn app_for_path(path: &Path) -> Option<&'static SocialApp> {
    let path_lc = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name_lc = path.file_name()?.to_str()?.to_ascii_lowercase();
    APPS.iter().find(|app| {
        app.path_needles
            .iter()
            .any(|needle| path_lc.contains(needle))
            && app.db_names.iter().any(|name| name_lc == *name)
    })
}

fn parse_table(
    conn: &Connection,
    path: &Path,
    app: &SocialApp,
    spec: &TableSpec,
) -> Vec<ArtifactRecord> {
    let text_col = first_existing_column(conn, spec.table, spec.text_cols);
    let actor_col = first_existing_column(conn, spec.table, spec.actor_cols);
    let ts_col = first_existing_column(conn, spec.table, spec.ts_cols);
    let count = count_rows(conn, spec.table);

    let Some(text_col) = text_col else {
        return vec![summary_record(path, app, spec, count)];
    };

    let mut select_cols = vec![text_col.clone()];
    if let Some(actor) = &actor_col {
        select_cols.push(actor.clone());
    }
    if let Some(ts) = &ts_col {
        select_cols.push(ts.clone());
    }
    let sql = format!(
        "SELECT {} FROM \"{}\" LIMIT 10000",
        select_cols
            .iter()
            .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(", "),
        spec.table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(_) => return vec![summary_record(path, app, spec, count)],
    };
    let rows = match stmt.query_map([], |row| {
        let text = row.get::<_, Option<String>>(0)?;
        let actor = if actor_col.is_some() {
            row.get::<_, Option<String>>(1)?
        } else {
            None
        };
        let ts_idx = 1 + usize::from(actor_col.is_some());
        let ts = if ts_col.is_some() {
            read_timestamp(row, ts_idx)?
        } else {
            None
        };
        Ok((text, actor, ts))
    }) {
        Ok(rows) => rows,
        Err(_) => return vec![summary_record(path, app, spec, count)],
    };

    let mut out = Vec::new();
    for row in rows.flatten() {
        let (text, actor, timestamp) = row;
        let text = text.unwrap_or_default();
        if text.trim().is_empty() {
            continue;
        }
        let preview: String = text.chars().take(140).collect();
        let actor_detail = actor.as_deref().unwrap_or("unknown");
        out.push(ArtifactRecord {
            category: ArtifactCategory::SocialMedia,
            subcategory: spec.artifact_type.to_string(),
            timestamp,
            title: format!("{}: {}", spec.title, preview),
            detail: format!(
                "{} {} row from {} actor={} text={}",
                app.app,
                spec.table,
                path.to_string_lossy(),
                actor_detail,
                text
            ),
            source_path: path.to_string_lossy().into_owned(),
            forensic_value: spec.value.clone(),
            mitre_technique: Some(spec.mitre.to_string()),
            is_suspicious: false,
            raw_data: Some(json!({
                "artifact_type": spec.artifact_type,
                "app": app.app,
                "table": spec.table,
                "confidence": "Medium",
            })),
            confidence: 65,
        });
    }

    if out.is_empty() {
        vec![summary_record(path, app, spec, count)]
    } else {
        out
    }
}

fn first_existing_column(conn: &Connection, table: &str, candidates: &[&str]) -> Option<String> {
    let mut stmt = conn
        .prepare(&format!(
            "PRAGMA table_info(\"{}\")",
            table.replace('"', "\"\"")
        ))
        .ok()?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1)).ok()?;
    let columns: Vec<String> = rows.flatten().collect();
    candidates
        .iter()
        .find(|candidate| columns.iter().any(|c| c.eq_ignore_ascii_case(candidate)))
        .map(|candidate| (*candidate).to_string())
}

fn read_timestamp(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Option<i64>> {
    if let Ok(v) = row.get::<_, Option<i64>>(idx) {
        return Ok(normalize_timestamp(v));
    }
    if let Ok(v) = row.get::<_, Option<String>>(idx) {
        return Ok(v
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(|n| normalize_timestamp(Some(n))));
    }
    Ok(None)
}

fn normalize_timestamp(value: Option<i64>) -> Option<i64> {
    let value = value?;
    if value <= 0 {
        None
    } else if value > 10_000_000_000_000 {
        Some(value / 1_000_000)
    } else if value > 10_000_000_000 {
        Some(value / 1000)
    } else {
        Some(value)
    }
}

fn summary_record(
    path: &Path,
    app: &SocialApp,
    spec: &TableSpec,
    row_count: i64,
) -> ArtifactRecord {
    ArtifactRecord {
        category: ArtifactCategory::SocialMedia,
        subcategory: spec.artifact_type.to_string(),
        timestamp: None,
        title: format!("{} social database table: {}", app.app, spec.table),
        detail: format!(
            "{} table '{}' present with {} rows; schema did not expose a recognized message text column",
            app.app, spec.table, row_count
        ),
        source_path: path.to_string_lossy().into_owned(),
        forensic_value: spec.value.clone(),
        mitre_technique: Some(spec.mitre.to_string()),
        is_suspicious: false,
        raw_data: Some(json!({
            "artifact_type": spec.artifact_type,
            "app": app.app,
            "table": spec.table,
            "confidence": "Medium",
        })),
        confidence: 65,
    }
}

fn inventory_record(conn: &Connection, path: &Path, app: &SocialApp) -> Vec<ArtifactRecord> {
    let tables = table_names(conn);
    if tables.is_empty() {
        return Vec::new();
    }
    let total: i64 = tables.iter().map(|table| count_rows(conn, table)).sum();
    vec![ArtifactRecord {
        category: ArtifactCategory::SocialMedia,
        subcategory: format!(
            "social_{}_inventory",
            app.app.to_ascii_lowercase().replace('/', "")
        ),
        timestamp: None,
        title: format!("{} social database", app.app),
        detail: format!(
            "{} database present with {} rows across {} tables: {}",
            app.app,
            total,
            tables.len(),
            tables.join(", ")
        ),
        source_path: path.to_string_lossy().into_owned(),
        forensic_value: ForensicValue::Medium,
        mitre_technique: Some("T1636.002".to_string()),
        is_suspicious: false,
        raw_data: Some(json!({
            "artifact_type": "social_app_inventory",
            "app": app.app,
            "confidence": "Medium",
        })),
        confidence: 65,
    }]
}

fn table_names(conn: &Connection) -> Vec<String> {
    let mut stmt = match conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    {
        Ok(stmt) => stmt,
        Err(_) => return Vec::new(),
    };
    let out = match stmt.query_map([], |row| row.get::<_, String>(0)) {
        Ok(rows) => rows.flatten().collect(),
        Err(_) => Vec::new(),
    };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db(
        path: &Path,
        schema: &str,
        inserts: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(schema)?;
        for sql in inserts {
            conn.execute(sql, [])?;
        }
        Ok(())
    }

    #[test]
    fn parses_twitter_direct_messages_as_social_media() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir
            .path()
            .join("Library/Application Support/Twitter/gryphon.sqlite");
        make_db(
            &path,
            "CREATE TABLE messages (text TEXT, sender_id TEXT, created_at INTEGER)",
            &["INSERT INTO messages VALUES ('hello from x', 'alice', 1700000000)"],
        )?;

        assert!(matches(&path));
        let records = parse(&path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].category, ArtifactCategory::SocialMedia);
        assert_eq!(records[0].subcategory, "social_twitter_dm");
        assert_eq!(records[0].mitre_technique.as_deref(), Some("T1636.002"));
        assert_eq!(records[0].confidence, 65);
        Ok(())
    }

    #[test]
    fn parses_instagram_direct_messages_as_social_media() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let path = dir
            .path()
            .join("Library/Application Support/Instagram/direct.db");
        make_db(
            &path,
            "CREATE TABLE messages (body TEXT, sender TEXT, timestamp INTEGER)",
            &["INSERT INTO messages VALUES ('ig dm', 'bob', 1700000100000)"],
        )?;

        let records = parse(&path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].subcategory, "social_instagram_dm");
        assert_eq!(records[0].timestamp, Some(1_700_000_100));
        assert!(records[0].detail.contains("bob"));
        Ok(())
    }

    #[test]
    fn parses_facebook_messenger_as_social_media() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir
            .path()
            .join("Library/Application Support/Messenger/messenger.db");
        make_db(
            &path,
            "CREATE TABLE messages (content TEXT, thread_id TEXT, created_time INTEGER)",
            &["INSERT INTO messages VALUES ('fb message', 'thread-1', 1700000200)"],
        )?;

        let records = parse(&path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].category, ArtifactCategory::SocialMedia);
        assert_eq!(records[0].subcategory, "social_facebook_message");
        Ok(())
    }

    #[test]
    fn parses_instagram_icloud_container_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir
            .path()
            .join("Users/alex/Library/Application Support/CloudDocs/session/containers/iCloud.com.burbn.instagram.plist");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, b"plist metadata")?;

        assert!(matches(&path));
        let records = parse(&path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].category, ArtifactCategory::SocialMedia);
        assert_eq!(records[0].subcategory, "social_instagram_icloud_container");
        Ok(())
    }
}
