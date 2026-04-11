//! iOS MobileContainerManager — `Containers.sqlite`.
//!
//! Maps bundle IDs to sandbox UUIDs with creation/access dates.
//! Essential for building an app installation timeline.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["containers.sqlite"])
        && util::path_contains(path, "containermanager")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "containers") { return out; }
    let source = path.to_string_lossy().to_string();
    let count = util::count_rows(&conn, "containers");
    out.push(ArtifactRecord {
        category: ArtifactCategory::ExecutionHistory,
        subcategory: "Container manager".to_string(),
        timestamp: None,
        title: "iOS app container registry".to_string(),
        detail: format!("{} container rows (bundle ID → UUID mapping with install dates)", count),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_containermanager_path() {
        assert!(matches(Path::new("/var/mobile/Library/containermanagerd/ContainerManager/Containers.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/Containers.sqlite")));
    }

    #[test]
    fn parses_container_count() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("containermanagerd");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("Containers.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE containers (id INTEGER PRIMARY KEY, identifier TEXT, uuid TEXT)", []).unwrap();
        c.execute("INSERT INTO containers (identifier, uuid) VALUES ('com.apple.mobilesafari', 'AAAA')", []).unwrap();
        c.execute("INSERT INTO containers (identifier, uuid) VALUES ('com.example.app', 'BBBB')", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("2 container"));
    }

    #[test]
    fn missing_table_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("containermanagerd");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("Containers.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}
