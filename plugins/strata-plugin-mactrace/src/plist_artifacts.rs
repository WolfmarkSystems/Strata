//! macOS property-list (plist) artifact parser.
//!
//! Covers five high-value system-managed plists that document user and
//! volume activity:
//!
//! | Filename fragment                              | Variant                 |
//! |-----------------------------------------------|-------------------------|
//! | `com.apple.recentitems.plist`                  | [`PlistArtifactType::RecentItems`]     |
//! | `com.apple.loginitems.plist` / `LoginItems.plist` | [`PlistArtifactType::LoginItems`]      |
//! | `com.apple.LaunchServices.QuarantineEventsV2`  | [`PlistArtifactType::QuarantineEvents`] *(SQLite)* |
//! | `sidebarlists.plist`                           | [`PlistArtifactType::SidebarLists`]    |
//! | `com.apple.dock.plist`                         | [`PlistArtifactType::DockItems`]       |
//!
//! Most of these are **binary plists**; the [`plist`] crate reads both
//! binary and XML variants transparently. QuarantineEventsV2 despite
//! the bundle name is a SQLite database, so we use [`rusqlite`] for it
//! (the plugin already depends on rusqlite for other parsers).
//!
//! ## MITRE ATT&CK
//! * **T1074.001** (Local Data Staging) — Recent Items.
//! * **T1547.011** (Plist File Modification) — Login Items and Dock.
//! * **T1566 / T1105** — Quarantine Events (web/attachment download).
//! * **T1052.001** (Exfiltration Over USB) — Sidebar Lists (mounted
//!   removable volume history).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use plist::Value;
use std::path::Path;

/// Offset from Unix epoch to the CoreData / Mach absolute-time epoch
/// (2001-01-01 00:00:00 UTC expressed as Unix seconds). Used for
/// QuarantineEventsV2 `LSQuarantineTimeStamp` values.
const APPLE_EPOCH_OFFSET: i64 = 978_307_200;

/// Which flavour of plist artifact this record came from. Drives how
/// consumers (UI, Sigma, timeline) interpret the `value` / `metadata`
/// fields of [`PlistArtifact`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlistArtifactType {
    /// `com.apple.recentitems.plist` — recently opened documents,
    /// applications, or servers.
    RecentItems,
    /// `com.apple.loginitems.plist` / `LoginItems.plist` — per-user
    /// login-item persistence.
    LoginItems,
    /// `com.apple.LaunchServices.QuarantineEventsV2` — the OS-wide
    /// download-provenance database (SQLite).
    QuarantineEvents,
    /// `sidebarlists.plist` — Finder sidebar, which retains a history
    /// of mounted removable and network volumes.
    SidebarLists,
    /// `com.apple.dock.plist` — pinned application Dock tiles and
    /// persistent document tiles.
    DockItems,
}

impl PlistArtifactType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlistArtifactType::RecentItems => "RecentItems",
            PlistArtifactType::LoginItems => "LoginItems",
            PlistArtifactType::QuarantineEvents => "QuarantineEvents",
            PlistArtifactType::SidebarLists => "SidebarLists",
            PlistArtifactType::DockItems => "DockItems",
        }
    }

    /// Recommended MITRE ATT&CK technique for this plist type.
    pub fn mitre(&self) -> &'static str {
        match self {
            PlistArtifactType::RecentItems => "T1074.001",
            PlistArtifactType::LoginItems | PlistArtifactType::DockItems => "T1547.011",
            PlistArtifactType::QuarantineEvents => "T1566",
            PlistArtifactType::SidebarLists => "T1052.001",
        }
    }

    /// Forensic value tier for this plist type.
    pub fn forensic_value(&self) -> &'static str {
        match self {
            PlistArtifactType::QuarantineEvents | PlistArtifactType::SidebarLists => "High",
            _ => "Medium",
        }
    }

    /// Classify a filesystem path to one of the known plist types.
    /// Returns `None` for paths this parser does not handle.
    pub fn from_path(path: &Path) -> Option<PlistArtifactType> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match name.as_str() {
            "com.apple.recentitems.plist" => Some(PlistArtifactType::RecentItems),
            "com.apple.loginitems.plist" | "loginitems.plist" => {
                Some(PlistArtifactType::LoginItems)
            }
            "com.apple.launchservices.quarantineeventsv2" => {
                Some(PlistArtifactType::QuarantineEvents)
            }
            "sidebarlists.plist" => Some(PlistArtifactType::SidebarLists),
            "com.apple.dock.plist" => Some(PlistArtifactType::DockItems),
            _ => None,
        }
    }
}

/// One typed record extracted from a macOS plist (or the
/// QuarantineEventsV2 SQLite database).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlistArtifact {
    /// Which plist source produced this record.
    pub artifact_type: PlistArtifactType,
    /// Human-readable name of the item. For RecentItems this is the
    /// filename; for LoginItems the declared `Name`; for Quarantine
    /// the `LSQuarantineAgentName`; for SidebarLists the volume name;
    /// for DockItems the app's `file-label`.
    pub name: String,
    /// Path, URL, or bundle identifier associated with the item.
    pub value: String,
    /// Supplemental metadata: `hidden=true` for LoginItems, kind /
    /// tile-type for Dock, origin URL for Quarantine, mount path for
    /// SidebarLists. `None` when no extra context is available.
    pub metadata: Option<String>,
    /// Event timestamp when available (currently populated only for
    /// QuarantineEvents via `LSQuarantineTimeStamp`).
    pub timestamp: Option<DateTime<Utc>>,
}

/// Parse a plist (or QuarantineEventsV2 SQLite) file by filename
/// classification. Returns every typed record discovered. Empty vector
/// on unknown filename, unreadable file, or malformed content. Never
/// panics.
pub fn parse(path: &Path) -> Vec<PlistArtifact> {
    match PlistArtifactType::from_path(path) {
        Some(PlistArtifactType::QuarantineEvents) => parse_quarantine(path),
        Some(t) => parse_plist_file(path, t),
        None => Vec::new(),
    }
}

fn parse_plist_file(path: &Path, kind: PlistArtifactType) -> Vec<PlistArtifact> {
    let Ok(value) = plist::Value::from_file(path) else {
        return Vec::new();
    };
    match kind {
        PlistArtifactType::RecentItems => parse_recent_items(&value),
        PlistArtifactType::LoginItems => parse_login_items(&value),
        PlistArtifactType::SidebarLists => parse_sidebar_lists(&value),
        PlistArtifactType::DockItems => parse_dock_items(&value),
        PlistArtifactType::QuarantineEvents => Vec::new(),
    }
}

fn parse_recent_items(root: &Value) -> Vec<PlistArtifact> {
    let mut out = Vec::new();
    let Some(dict) = root.as_dictionary() else {
        return out;
    };
    // Each of `RecentDocuments`, `RecentApplications`, `RecentServers`
    // is keyed to a dictionary with a `CustomListItems` array of
    // bookmark dictionaries. We extract either the `Name` (preferred)
    // or `Bookmark` bytes' rendered description.
    let sections: &[(&str, &str)] = &[
        ("RecentDocuments", "Document"),
        ("RecentApplications", "Application"),
        ("RecentServers", "Server"),
    ];
    for (key, kind) in sections {
        let Some(section) = dict.get(key) else {
            continue;
        };
        let Some(section_dict) = section.as_dictionary() else {
            continue;
        };
        let Some(items) = section_dict.get("CustomListItems") else {
            continue;
        };
        let Some(items_arr) = items.as_array() else {
            continue;
        };
        for item in items_arr {
            let Some(item_dict) = item.as_dictionary() else {
                continue;
            };
            let name = item_dict
                .get("Name")
                .and_then(|v| v.as_string())
                .unwrap_or("<unknown>")
                .to_string();
            let value = item_dict
                .get("URL")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string())
                .or_else(|| {
                    item_dict
                        .get("Bookmark")
                        .and_then(|v| v.as_data())
                        .map(|b| format!("<bookmark:{} bytes>", b.len()))
                })
                .unwrap_or_default();
            out.push(PlistArtifact {
                artifact_type: PlistArtifactType::RecentItems,
                name,
                value,
                metadata: Some((*kind).to_string()),
                timestamp: None,
            });
        }
    }
    out
}

fn parse_login_items(root: &Value) -> Vec<PlistArtifact> {
    let mut out = Vec::new();
    let Some(dict) = root.as_dictionary() else {
        return out;
    };
    // Modern layout: `SessionItems.CustomListItems` array of dicts
    // with `Name`, `Alias` (bookmark bytes), and `Hide`.
    let items = dict
        .get("SessionItems")
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("CustomListItems"))
        .and_then(|v| v.as_array());
    let Some(items) = items else {
        return out;
    };
    for item in items {
        let Some(item_dict) = item.as_dictionary() else {
            continue;
        };
        let name = item_dict
            .get("Name")
            .and_then(|v| v.as_string())
            .unwrap_or("<unknown>")
            .to_string();
        let path_str = item_dict
            .get("Path")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
            .or_else(|| {
                item_dict
                    .get("Alias")
                    .and_then(|v| v.as_data())
                    .map(|b| format!("<alias:{} bytes>", b.len()))
            })
            .unwrap_or_default();
        let hidden = item_dict
            .get("Hide")
            .and_then(|v| v.as_boolean())
            .unwrap_or(false);
        let kind = item_dict
            .get("Kind")
            .and_then(|v| v.as_string())
            .unwrap_or("Application");
        let metadata = format!("kind={}; hidden={}", kind, hidden);
        out.push(PlistArtifact {
            artifact_type: PlistArtifactType::LoginItems,
            name,
            value: path_str,
            metadata: Some(metadata),
            timestamp: None,
        });
    }
    out
}

fn parse_sidebar_lists(root: &Value) -> Vec<PlistArtifact> {
    let mut out = Vec::new();
    let Some(dict) = root.as_dictionary() else {
        return out;
    };
    // `systemitems` (volumes) and `favoriteservers` (network mounts).
    let sections: &[(&str, &str)] = &[
        ("systemitems", "volume"),
        ("favoriteservers", "server"),
        ("favorites", "favorite"),
    ];
    for (key, kind) in sections {
        let Some(section) = dict.get(key) else {
            continue;
        };
        let items = section
            .as_dictionary()
            .and_then(|d| d.get("VolumesList").or_else(|| d.get("CustomListItems")))
            .and_then(|v| v.as_array());
        let Some(items) = items else {
            continue;
        };
        for item in items {
            let Some(item_dict) = item.as_dictionary() else {
                continue;
            };
            let name = item_dict
                .get("Name")
                .and_then(|v| v.as_string())
                .unwrap_or("<unknown>")
                .to_string();
            let value = item_dict
                .get("URL")
                .and_then(|v| v.as_string())
                .or_else(|| item_dict.get("Alias").and_then(|v| v.as_string()))
                .unwrap_or("")
                .to_string();
            out.push(PlistArtifact {
                artifact_type: PlistArtifactType::SidebarLists,
                name,
                value,
                metadata: Some((*kind).to_string()),
                timestamp: None,
            });
        }
    }
    out
}

fn parse_dock_items(root: &Value) -> Vec<PlistArtifact> {
    let mut out = Vec::new();
    let Some(dict) = root.as_dictionary() else {
        return out;
    };
    let tile_sections: &[(&str, &str)] = &[
        ("persistent-apps", "persistent-app"),
        ("recent-apps", "recent-app"),
        ("persistent-others", "persistent-other"),
    ];
    for (key, tile_type) in tile_sections {
        let Some(tiles) = dict.get(key).and_then(|v| v.as_array()) else {
            continue;
        };
        for tile in tiles {
            let Some(tile_dict) = tile.as_dictionary() else {
                continue;
            };
            let Some(tile_data) = tile_dict.get("tile-data").and_then(|v| v.as_dictionary()) else {
                continue;
            };
            let name = tile_data
                .get("file-label")
                .and_then(|v| v.as_string())
                .unwrap_or("<unknown>")
                .to_string();
            let file_url = tile_data
                .get("file-data")
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("_CFURLString"))
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string();
            out.push(PlistArtifact {
                artifact_type: PlistArtifactType::DockItems,
                name,
                value: file_url,
                metadata: Some((*tile_type).to_string()),
                timestamp: None,
            });
        }
    }
    out
}

fn parse_quarantine(path: &Path) -> Vec<PlistArtifact> {
    use rusqlite::{Connection, OpenFlags};
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = Connection::open_with_flags(path, flags) else {
        return Vec::new();
    };
    let sql = "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, \
                      LSQuarantineDataURLString, LSQuarantineOriginURLString, \
                      LSQuarantineOriginTitle \
               FROM LSQuarantineEvent \
               ORDER BY LSQuarantineTimeStamp ASC";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        let ts: Option<f64> = row.get(0)?;
        let agent: Option<String> = row.get(1)?;
        let data_url: Option<String> = row.get(2)?;
        let origin_url: Option<String> = row.get(3)?;
        let origin_title: Option<String> = row.get(4)?;
        Ok((ts, agent, data_url, origin_url, origin_title))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for row in rows {
        let Ok((ts, agent, data_url, origin_url, origin_title)) = row else {
            continue;
        };
        let timestamp = ts.and_then(apple_epoch_to_utc);
        let name = agent.unwrap_or_else(|| "<unknown agent>".to_string());
        let value = data_url.unwrap_or_default();
        let metadata_parts: Vec<String> = [
            origin_url.map(|u| format!("origin_url={}", u)),
            origin_title.map(|t| format!("origin_title={}", t)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let metadata = if metadata_parts.is_empty() {
            None
        } else {
            Some(metadata_parts.join("; "))
        };
        out.push(PlistArtifact {
            artifact_type: PlistArtifactType::QuarantineEvents,
            name,
            value,
            metadata,
            timestamp,
        });
    }
    out
}

fn apple_epoch_to_utc(apple_secs: f64) -> Option<DateTime<Utc>> {
    if !apple_secs.is_finite() {
        return None;
    }
    let secs = apple_secs.trunc() as i64;
    let nanos = ((apple_secs - apple_secs.trunc()) * 1_000_000_000.0) as u32;
    DateTime::<Utc>::from_timestamp(secs.saturating_add(APPLE_EPOCH_OFFSET), nanos)
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Value;
    use rusqlite::Connection;

    fn dict(entries: Vec<(&str, Value)>) -> Value {
        let mut m = plist::Dictionary::new();
        for (k, v) in entries {
            m.insert(k.to_string(), v);
        }
        Value::Dictionary(m)
    }

    /// A plist written into a tempdir with a fixed filename so the
    /// path-based classifier matches it. The tempdir cleans up on drop.
    struct PlistFixture {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
    }

    impl PlistFixture {
        fn new(filename: &str, root: Value) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join(filename);
            root.to_file_xml(&path).expect("write plist");
            Self { _dir: dir, path }
        }
    }

    #[test]
    fn from_path_classifies_known_filenames() {
        assert_eq!(
            PlistArtifactType::from_path(Path::new("/etc/com.apple.recentitems.plist")),
            Some(PlistArtifactType::RecentItems)
        );
        assert_eq!(
            PlistArtifactType::from_path(Path::new("/a/com.apple.loginitems.plist")),
            Some(PlistArtifactType::LoginItems)
        );
        assert_eq!(
            PlistArtifactType::from_path(Path::new("/a/LoginItems.plist")),
            Some(PlistArtifactType::LoginItems)
        );
        assert_eq!(
            PlistArtifactType::from_path(Path::new(
                "/a/com.apple.LaunchServices.QuarantineEventsV2"
            )),
            Some(PlistArtifactType::QuarantineEvents)
        );
        assert_eq!(
            PlistArtifactType::from_path(Path::new("/a/sidebarlists.plist")),
            Some(PlistArtifactType::SidebarLists)
        );
        assert_eq!(
            PlistArtifactType::from_path(Path::new("/a/com.apple.dock.plist")),
            Some(PlistArtifactType::DockItems)
        );
        assert!(PlistArtifactType::from_path(Path::new("/a/random.plist")).is_none());
    }

    #[test]
    fn parse_unknown_path_returns_empty() {
        let records = parse(Path::new("/nonexistent/whatever.plist"));
        assert!(records.is_empty());
    }

    #[test]
    fn parse_recent_items_pulls_name_and_url() {
        let doc_item = dict(vec![
            ("Name", Value::String("report.pdf".into())),
            (
                "URL",
                Value::String("file:///Users/alice/Docs/report.pdf".into()),
            ),
        ]);
        let recents = dict(vec![("CustomListItems", Value::Array(vec![doc_item]))]);
        let root = dict(vec![("RecentDocuments", recents)]);
        let fx = PlistFixture::new("com.apple.recentitems.plist", root);
        let records = parse(&fx.path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].artifact_type, PlistArtifactType::RecentItems);
        assert_eq!(records[0].name, "report.pdf");
        assert!(records[0].value.contains("report.pdf"));
        assert_eq!(records[0].metadata.as_deref(), Some("Document"));
    }

    #[test]
    fn parse_login_items_captures_hidden_flag() {
        let item = dict(vec![
            ("Name", Value::String("HelperAgent".into())),
            ("Path", Value::String("/Applications/Helper.app".into())),
            ("Hide", Value::Boolean(true)),
            ("Kind", Value::String("Application".into())),
        ]);
        let session = dict(vec![("CustomListItems", Value::Array(vec![item]))]);
        let root = dict(vec![("SessionItems", session)]);
        let fx = PlistFixture::new("com.apple.loginitems.plist", root);
        let records = parse(&fx.path);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.artifact_type, PlistArtifactType::LoginItems);
        assert_eq!(r.name, "HelperAgent");
        assert_eq!(r.value, "/Applications/Helper.app");
        assert_eq!(r.metadata.as_deref(), Some("kind=Application; hidden=true"));
    }

    #[test]
    fn parse_dock_items_extracts_persistent_apps() {
        let tile_data = dict(vec![
            ("file-label", Value::String("Safari".into())),
            (
                "file-data",
                dict(vec![(
                    "_CFURLString",
                    Value::String("file:///Applications/Safari.app/".into()),
                )]),
            ),
        ]);
        let tile = dict(vec![("tile-data", tile_data)]);
        let root = dict(vec![("persistent-apps", Value::Array(vec![tile]))]);
        let fx = PlistFixture::new("com.apple.dock.plist", root);
        let records = parse(&fx.path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].artifact_type, PlistArtifactType::DockItems);
        assert_eq!(records[0].name, "Safari");
        assert!(records[0].value.contains("Safari.app"));
        assert_eq!(records[0].metadata.as_deref(), Some("persistent-app"));
    }

    #[test]
    fn parse_sidebar_lists_captures_volume_entries() {
        let volume = dict(vec![
            ("Name", Value::String("BACKUP_USB".into())),
            ("Alias", Value::String("/Volumes/BACKUP_USB".into())),
        ]);
        let sysitems = dict(vec![("VolumesList", Value::Array(vec![volume]))]);
        let root = dict(vec![("systemitems", sysitems)]);
        let fx = PlistFixture::new("sidebarlists.plist", root);
        let records = parse(&fx.path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].artifact_type, PlistArtifactType::SidebarLists);
        assert_eq!(records[0].name, "BACKUP_USB");
        assert_eq!(records[0].value, "/Volumes/BACKUP_USB");
        assert_eq!(records[0].metadata.as_deref(), Some("volume"));
    }

    #[test]
    fn parse_quarantine_events_reads_sqlite_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir
            .path()
            .join("com.apple.LaunchServices.QuarantineEventsV2");
        let conn = Connection::open(&db_path).expect("open fixture db");
        conn.execute_batch(
            "CREATE TABLE LSQuarantineEvent ( \
                 LSQuarantineEventIdentifier TEXT, \
                 LSQuarantineTimeStamp REAL, \
                 LSQuarantineAgentName TEXT, \
                 LSQuarantineDataURLString TEXT, \
                 LSQuarantineOriginURLString TEXT, \
                 LSQuarantineOriginTitle TEXT \
             );",
        )
        .expect("create table");
        // 2024-06-01 12:00:00 UTC == CoreData 738_936_000
        conn.execute(
            "INSERT INTO LSQuarantineEvent VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "id-1",
                738_936_000.0_f64,
                "Safari",
                "https://example.com/installer.dmg",
                "https://example.com/page.html",
                "Example download page",
            ],
        )
        .expect("insert");
        drop(conn);

        let records = parse(&db_path);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.artifact_type, PlistArtifactType::QuarantineEvents);
        assert_eq!(r.name, "Safari");
        assert!(r.value.ends_with("installer.dmg"));
        let meta = r.metadata.as_deref().unwrap_or("");
        assert!(meta.contains("origin_url=https://example.com/page.html"));
        assert!(meta.contains("origin_title=Example download page"));
        let ts = r.timestamp.expect("timestamp decoded");
        assert_eq!(ts.timestamp(), 1_717_243_200);
    }

    #[test]
    fn mitre_and_forensic_value_map_per_type() {
        assert_eq!(PlistArtifactType::RecentItems.mitre(), "T1074.001");
        assert_eq!(PlistArtifactType::LoginItems.mitre(), "T1547.011");
        assert_eq!(PlistArtifactType::DockItems.mitre(), "T1547.011");
        assert_eq!(PlistArtifactType::QuarantineEvents.mitre(), "T1566");
        assert_eq!(PlistArtifactType::SidebarLists.mitre(), "T1052.001");
        assert_eq!(PlistArtifactType::QuarantineEvents.forensic_value(), "High");
        assert_eq!(PlistArtifactType::SidebarLists.forensic_value(), "High");
        assert_eq!(PlistArtifactType::RecentItems.forensic_value(), "Medium");
    }
}
