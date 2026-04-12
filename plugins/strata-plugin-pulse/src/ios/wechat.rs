//! WeChat iOS — `MM.sqlite`, `WCDB_Contact.sqlite`, `EnMicroMsg.db`.
//!
//! iLEAPP keys off the CoreData + WCDB tables under `*/WeChat/*`.
//! `Chat_*` tables store messages with `CreateTime` (Unix seconds).

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    let wechat = util::path_contains(path, "wechat") || util::path_contains(path, "micromsg");
    wechat && (util::name_is(path, &["mm.sqlite", "wcdb_contact.sqlite", "enmicromsg.db"])
        || {
            let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.ends_with(".sqlite") || n.ends_with(".db")
        })
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();

    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut s| { let r = s.query_map([], |row| row.get::<_, String>(0))?; Ok(r.flatten().collect()) })
        .unwrap_or_default();
    if tables.is_empty() { return out; }

    // Count Chat_* tables specifically (WeChat DM tables)
    let chat_tables: Vec<&String> = tables.iter().filter(|t| t.starts_with("Chat_")).collect();
    let mut chat_rows = 0_i64;
    for t in &chat_tables { chat_rows += util::count_rows(&conn, t); }

    let mut total = 0_i64;
    for t in &tables { total += util::count_rows(&conn, t); }

    let detail = if !chat_tables.is_empty() {
        format!("{} Chat_* message rows across {} chats, {} total rows in {} tables",
            chat_rows, chat_tables.len(), total, tables.len())
    } else {
        format!("{} rows across {} tables", total, tables.len())
    };

    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "WeChat".to_string(),
        timestamp: None,
        title: "WeChat iOS database".to_string(),
        detail,
        source_path: source,
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_wechat_paths() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/WeChatPrivate/xxx/MM.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_chat_tables() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("WeChat");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("MM.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE Chat_abc (MesLocalID INTEGER, Message TEXT, CreateTime INTEGER)", []).unwrap();
        c.execute("INSERT INTO Chat_abc VALUES (1, 'hello', 1700000000)", []).unwrap();
        c.execute("INSERT INTO Chat_abc VALUES (2, 'hi', 1700000001)", []).unwrap();
        let recs = parse(&p);
        let r = recs.iter().find(|r| r.subcategory == "WeChat").unwrap();
        assert!(r.detail.contains("2 Chat_* message rows"));
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("WeChat");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("MM.sqlite");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}
