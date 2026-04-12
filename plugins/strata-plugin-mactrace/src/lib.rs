//! # MacTrace — macOS + iOS artifact plugin
//!
//! Covers FOR518 (macOS/APFS) and FOR585 (iOS) artifacts that have clean
//! filename signatures. Owns:
//!
//!   * LaunchAgents / LaunchDaemons — macOS persistence (plist files under
//!     Library/LaunchAgents/ and /Library/LaunchDaemons/)
//!   * KnowledgeC.db — macOS/iOS activity timeline (SQLite)
//!   * PowerLog (CurrentPowerlog.PLSQL) — iOS app usage (SQLite)
//!   * locationd clients.plist — iOS location authorizations
//!   * sms.db / chat.db — iOS/macOS Messages (SQLite)
//!   * CallHistory.storedata — iOS/macOS call history (SQLite)
//!   * AddressBook.sqlitedb — iOS/macOS contacts (SQLite)
//!   * SharedFileList (sfl2) — recent items
//!   * Unified Log archives (logarchive bundles) — surfaced by presence
//!   * WhatsApp ChatStorage.sqlite (iOS) / msgstore.db (Android)
//!
//! For SQLite-backed artifacts, MacTrace opens the database read-only and
//! runs a conservative query — enough to prove "the evidence is here",
//! with extraction depth to be expanded in v1.1+.

use std::path::{Path, PathBuf};

use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct MacTracePlugin {
    name: String,
    version: String,
}

impl Default for MacTracePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl MacTracePlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata MacTrace".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    fn classify(path: &Path) -> Option<(&'static str, &'static str)> {
        let lc_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        let lc_path = path.to_string_lossy().to_lowercase();

        // ── LaunchAgents / LaunchDaemons ─────────────────────────────
        if lc_name.ends_with(".plist")
            && (lc_path.contains("/launchagents/") || lc_path.contains("/launchdaemons/"))
        {
            return Some(("LaunchAgent/Daemon", "Persistence"));
        }

        // ── KnowledgeC.db ─────────────────────────────────────────────
        if lc_name == "knowledgec.db" || lc_path.ends_with("/knowledge/knowledgec.db") {
            return Some(("KnowledgeC", "Activity Timeline"));
        }

        // ── iOS PowerLog ──────────────────────────────────────────────
        if lc_name == "currentpowerlog.plsql" || lc_name.starts_with("powerlog_") {
            return Some(("PowerLog", "App Usage"));
        }

        // ── locationd clients.plist ──────────────────────────────────
        if lc_name == "clients.plist" && lc_path.contains("/locationd/") {
            return Some(("Locationd", "Location"));
        }

        // ── SMS / iMessage ────────────────────────────────────────────
        if lc_name == "sms.db" || lc_name == "chat.db" {
            return Some(("SMS/iMessage", "Communications"));
        }

        // ── Call history ──────────────────────────────────────────────
        if lc_name == "callhistory.storedata" {
            return Some(("CallHistory", "Communications"));
        }

        // ── Address book ──────────────────────────────────────────────
        if lc_name == "addressbook.sqlitedb" {
            return Some(("AddressBook", "Contacts"));
        }

        // ── SharedFileList recent items ──────────────────────────────
        if lc_name.ends_with(".sfl2") || lc_name.ends_with(".sfl3") {
            return Some(("SharedFileList", "Recent Items"));
        }

        // ── Safari History ────────────────────────────────────────────
        if lc_name == "history.db" && lc_path.contains("/safari/") {
            return Some(("Safari History", "Web Activity"));
        }

        // ── Unified Log ───────────────────────────────────────────────
        if lc_path.contains(".logarchive/") && lc_name.ends_with(".tracev3") {
            return Some(("Unified Log", "System Activity"));
        }

        // ── Recent items plist ───────────────────────────────────────
        if lc_name == "com.apple.recentitems.plist" {
            return Some(("Recent Items", "User Activity"));
        }

        // ── loginitems ────────────────────────────────────────────────
        if lc_name == "com.apple.loginitems.plist"
            || lc_name == "backgrounditems.btm"
        {
            return Some(("LoginItems", "Persistence"));
        }

        // ── WhatsApp iOS ──────────────────────────────────────────────
        if lc_name == "chatstorage.sqlite" && lc_path.contains("whatsapp") {
            return Some(("WhatsApp iOS", "Communications"));
        }

        // ── WhatsApp Android ──────────────────────────────────────────
        if lc_name == "msgstore.db" && lc_path.contains("whatsapp") {
            return Some(("WhatsApp Android", "Communications"));
        }

        // ── Signal ────────────────────────────────────────────────────
        if lc_name == "signal.db" {
            return Some(("Signal", "Communications"));
        }

        // ── Telegram ──────────────────────────────────────────────────
        if lc_name == "db.sqlite" && lc_path.contains("telegram") {
            return Some(("Telegram", "Communications"));
        }

        // ── v1.5.0 macOS expansion ───────────────────────────────────
        if lc_name == "bookmarks.plist" && lc_path.contains("/safari/") {
            return Some(("Safari Bookmarks", "Web Activity"));
        }
        if lc_name == "topsites.plist" && lc_path.contains("/safari/") {
            return Some(("Safari TopSites", "Web Activity"));
        }
        if lc_name == "downloads.plist" && lc_path.contains("/safari/") {
            return Some(("Safari Downloads (plist)", "Web Activity"));
        }
        if lc_name == "history" && lc_path.contains("/google/chrome/") {
            return Some(("Chrome History (macOS)", "Web Activity"));
        }
        if lc_name == "preferences" && lc_path.contains("/google/chrome/") {
            return Some(("Chrome Preferences (macOS)", "Web Activity"));
        }
        if lc_name == "places.sqlite" && lc_path.contains("/firefox/") {
            return Some(("Firefox Places (macOS)", "Web Activity"));
        }
        if lc_name == "extensions.json" && lc_path.contains("/firefox/") {
            return Some(("Firefox Extensions (macOS)", "Web Activity"));
        }
        if lc_name == "client.db" && lc_path.contains("clouddocs") {
            return Some(("iCloud CloudDocs Client DB", "Cloud Storage"));
        }
        if lc_name == "com.apple.bird.plist" {
            return Some(("iCloud Bird Daemon Prefs", "Cloud Storage"));
        }
        if lc_name == "com.apple.dock.plist" {
            return Some(("macOS Dock", "User Activity"));
        }
        if lc_name == "db.sqlite" && lc_path.contains(".documentrevisions-v100") {
            return Some(("Document Revisions", "User Activity"));
        }
        if lc_name == "knowledgec.db" && lc_path.contains("/knowledge/") {
            return Some(("Screen Time KnowledgeC", "User Activity"));
        }
        if lc_name == "com.apple.ssh.plist" {
            return Some(("macOS SSH Prefs", "Remote Access"));
        }
        if lc_name == "authorized_keys" && lc_path.contains("/users/") {
            return Some(("macOS authorized_keys", "Remote Access"));
        }
        if lc_name == "known_hosts" && lc_path.contains("/users/") {
            return Some(("macOS known_hosts", "Remote Access"));
        }
        if lc_path.contains("/.zsh_sessions/") || lc_path.contains("/.bash_sessions/") {
            return Some(("Shell Session History", "User Activity"));
        }
        if lc_name == "fish_history" {
            return Some(("Fish Shell History", "User Activity"));
        }
        if lc_path.contains("kmditem") || lc_name == ".com.apple.metadata.plist" {
            return Some(("Spotlight Metadata Xattr", "Metadata"));
        }
        if lc_path.ends_with(".ufdr") {
            return Some(("UFDR Container", "Mobile Extraction"));
        }

        None
    }

    fn count_sqlite_rows(path: &Path, table: &str) -> Option<i64> {
        use rusqlite::{Connection, OpenFlags};
        let conn =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
                .ok()?;
        let mut stmt = conn.prepare(&format!("SELECT COUNT(*) FROM {}", table)).ok()?;
        let n: i64 = stmt.query_row([], |row| row.get(0)).ok()?;
        Some(n)
    }
}

impl StrataPlugin for MacTracePlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "plist".to_string(),
            "db".to_string(),
            "sqlite".to_string(),
            "sqlitedb".to_string(),
            "storedata".to_string(),
        ]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }
    fn description(&self) -> &str {
        "macOS + iOS artifact parsing: LaunchAgents, KnowledgeC, PowerLog, SMS, CallHistory, Signal, WhatsApp"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut out = Vec::new();

        let files = match walk_dir(root) {
            Ok(f) => f,
            Err(_) => return Ok(out),
        };

        for path in files {
            let Some((file_type, _category)) = Self::classify(&path) else {
                continue;
            };
            let path_str = path.to_string_lossy().to_string();

            let (title, detail, mitre, severity, suspicious) = match file_type {
                "LaunchAgent/Daemon" => (
                    format!("macOS persistence: {}", path.file_name().and_then(|n| n.to_str()).unwrap_or("")),
                    "LaunchAgent / LaunchDaemon plist — examine ProgramArguments for suspicious paths (Temp, user-writable, unsigned binary)".to_string(),
                    Some("T1543.001"),
                    "High",
                    path_str.contains("/tmp/") || path_str.contains("/private/tmp/"),
                ),

                "KnowledgeC" => {
                    let row_count = Self::count_sqlite_rows(&path, "ZOBJECT").unwrap_or(0);
                    (
                        "KnowledgeC activity database".to_string(),
                        format!("macOS/iOS activity timeline — {} ZOBJECT rows (app usage, notifications, battery, lock events)", row_count),
                        Some("T1005"),
                        "Critical",
                        false,
                    )
                }

                "PowerLog" => {
                    let row_count = Self::count_sqlite_rows(&path, "PLApplicationAgent_EventForward_ApplicationRunTime").unwrap_or(0);
                    (
                        "iOS PowerLog".to_string(),
                        format!("iOS app usage log — {} foreground events recorded", row_count),
                        Some("T1005"),
                        "Critical",
                        false,
                    )
                }

                "Locationd" => (
                    "iOS location authorization log".to_string(),
                    "Per-app location access history (clients.plist)".to_string(),
                    Some("T1430"),
                    "High",
                    false,
                ),

                "SMS/iMessage" => {
                    let row_count = Self::count_sqlite_rows(&path, "message").unwrap_or(0);
                    (
                        "SMS / iMessage database".to_string(),
                        format!("{} message rows", row_count),
                        Some("T1005"),
                        "Critical",
                        false,
                    )
                }

                "CallHistory" => {
                    let row_count = Self::count_sqlite_rows(&path, "ZCALLRECORD").unwrap_or(0);
                    (
                        "Call history".to_string(),
                        format!("{} call records", row_count),
                        Some("T1005"),
                        "Critical",
                        false,
                    )
                }

                "AddressBook" => {
                    let row_count = Self::count_sqlite_rows(&path, "ABPerson").unwrap_or(0);
                    (
                        "Contacts database".to_string(),
                        format!("{} contacts", row_count),
                        None,
                        "High",
                        false,
                    )
                }

                "SharedFileList" => (
                    "Recent items (sfl2/sfl3)".to_string(),
                    "Binary plist of recently opened items — decode with plist crate".to_string(),
                    Some("T1083"),
                    "Medium",
                    false,
                ),

                "Safari History" => {
                    let rows = Self::count_sqlite_rows(&path, "history_items").unwrap_or(0);
                    (
                        "Safari browsing history".to_string(),
                        format!("{} history_items rows", rows),
                        None,
                        "High",
                        false,
                    )
                }

                "Unified Log" => (
                    "macOS Unified Log tracev3".to_string(),
                    "Requires log show or direct tracev3 parse. See: /private/var/db/uuidtext/ for strings resolution.".to_string(),
                    None,
                    "High",
                    false,
                ),

                "Recent Items" => (
                    "Apple Menu Recent Items".to_string(),
                    "Recent applications/documents/servers plist".to_string(),
                    Some("T1083"),
                    "Medium",
                    false,
                ),

                "LoginItems" => (
                    "macOS LoginItems".to_string(),
                    "Per-user login item persistence".to_string(),
                    Some("T1547"),
                    "High",
                    false,
                ),

                "WhatsApp iOS" => {
                    let rows = Self::count_sqlite_rows(&path, "ZWAMESSAGE").unwrap_or(0);
                    (
                        "WhatsApp iOS".to_string(),
                        format!("{} ZWAMESSAGE rows", rows),
                        Some("T1005"),
                        "Critical",
                        false,
                    )
                }

                "WhatsApp Android" => {
                    let rows = Self::count_sqlite_rows(&path, "messages").unwrap_or(0);
                    (
                        "WhatsApp Android".to_string(),
                        format!("{} messages rows", rows),
                        Some("T1005"),
                        "Critical",
                        false,
                    )
                }

                "Signal" => (
                    "Signal messenger database".to_string(),
                    "Signal encrypted database — requires key from SQLCipher or backup".to_string(),
                    Some("T1005"),
                    "High",
                    false,
                ),

                "Telegram" => (
                    "Telegram local database".to_string(),
                    "Telegram local storage (messages, chats, media metadata)".to_string(),
                    Some("T1005"),
                    "High",
                    false,
                ),

                "Safari Bookmarks" => (
                    "Safari bookmarks tree".to_string(),
                    "Bookmarks.plist — folder hierarchy of saved URLs".to_string(),
                    None,
                    "Medium",
                    false,
                ),
                "Safari TopSites" => (
                    "Safari TopSites".to_string(),
                    "User's frequently visited sites — surfaces the homepage tile data".to_string(),
                    None,
                    "Medium",
                    false,
                ),
                "Safari Downloads (plist)" => (
                    "Safari downloads (plist)".to_string(),
                    "Legacy downloads.plist — pre-Yosemite or synced".to_string(),
                    None,
                    "High",
                    false,
                ),
                "Chrome History (macOS)" => (
                    "Chrome History DB (macOS)".to_string(),
                    "Chromium history SQLite — urls + downloads + visits".to_string(),
                    None,
                    "High",
                    false,
                ),
                "Chrome Preferences (macOS)" => (
                    "Chrome Preferences (macOS)".to_string(),
                    "Chromium Preferences JSON — extensions + sync settings".to_string(),
                    None,
                    "Medium",
                    false,
                ),
                "Firefox Places (macOS)" => (
                    "Firefox places.sqlite (macOS)".to_string(),
                    "Firefox URL history + bookmarks + visits".to_string(),
                    None,
                    "High",
                    false,
                ),
                "Firefox Extensions (macOS)" => (
                    "Firefox extensions.json (macOS)".to_string(),
                    "Installed Firefox add-ons with sourceURI".to_string(),
                    None,
                    "Medium",
                    false,
                ),
                "iCloud CloudDocs Client DB" => (
                    "iCloud CloudDocs client.db".to_string(),
                    "Local cache of synced iCloud Drive items + timestamps".to_string(),
                    None,
                    "High",
                    false,
                ),
                "iCloud Bird Daemon Prefs" => (
                    "iCloud bird daemon plist".to_string(),
                    "Identifies the active iCloud account and default container".to_string(),
                    None,
                    "Medium",
                    false,
                ),
                "macOS Dock" => (
                    "macOS Dock plist".to_string(),
                    "persistent-apps + recent-apps — pinned and recent application icons".to_string(),
                    Some("T1083"),
                    "Medium",
                    false,
                ),
                "Document Revisions" => (
                    "DocumentRevisions snapshot DB".to_string(),
                    "macOS document versioning DB — recovers prior versions of edited documents".to_string(),
                    Some("T1005"),
                    "High",
                    false,
                ),
                "Screen Time KnowledgeC" => (
                    "Screen Time KnowledgeC".to_string(),
                    "macOS Knowledge graph — per-app foreground/usage events".to_string(),
                    Some("T1005"),
                    "Critical",
                    false,
                ),
                "macOS SSH Prefs" => (
                    "macOS com.apple.ssh.plist".to_string(),
                    "User-level SSH client preferences and cached host keys".to_string(),
                    Some("T1021.004"),
                    "Medium",
                    false,
                ),
                "macOS authorized_keys" => (
                    "macOS authorized_keys".to_string(),
                    "Public keys authorised for remote login on this account".to_string(),
                    Some("T1098.004"),
                    "High",
                    true,
                ),
                "macOS known_hosts" => (
                    "macOS known_hosts".to_string(),
                    "Servers this account previously SSH'd to (proves outbound activity)".to_string(),
                    Some("T1021.004"),
                    "Medium",
                    false,
                ),
                "Shell Session History" => (
                    "Shell session history file".to_string(),
                    "Per-session zsh/bash history (commonly missed by .zsh_history-only sweeps)".to_string(),
                    Some("T1059.004"),
                    "High",
                    false,
                ),
                "Fish Shell History" => (
                    "Fish shell history".to_string(),
                    "Fish shell command history with timestamps".to_string(),
                    Some("T1059.004"),
                    "High",
                    false,
                ),
                "Spotlight Metadata Xattr" => (
                    "Spotlight metadata xattr".to_string(),
                    "kMDItemWhereFroms / DownloadedDate — proves origin and provenance".to_string(),
                    None,
                    "High",
                    false,
                ),
                "UFDR Container" => (
                    "Cellebrite UFDR container".to_string(),
                    "Mobile extraction archive — original device paths reconstructed by UFDR parser".to_string(),
                    None,
                    "Critical",
                    false,
                ),

                _ => (
                    "Mac/iOS artifact".to_string(),
                    path_str.clone(),
                    None,
                    "Medium",
                    false,
                ),
            };

            let mut a = Artifact::new(file_type, &path_str);
            a.add_field("title", &title);
            a.add_field("detail", &detail);
            a.add_field("file_type", file_type);
            a.add_field("forensic_value", severity);
            if suspicious {
                a.add_field("suspicious", "true");
            }
            if let Some(m) = mitre {
                a.add_field("mitre", m);
            }
            out.push(a);
        }

        Ok(out)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::new();
        let mut cats: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut suspicious = 0usize;
        for a in &artifacts {
            let ft = a.data.get("file_type").cloned().unwrap_or_default();
            let is_sus = a.data.get("suspicious").map(|s| s == "true").unwrap_or(false);
            if is_sus {
                suspicious += 1;
            }
            let category = match ft.as_str() {
                "SMS/iMessage" | "WhatsApp iOS" | "WhatsApp Android" | "Signal" | "Telegram"
                | "CallHistory" => ArtifactCategory::Communications,
                "Safari History" => ArtifactCategory::WebActivity,
                "AddressBook" => ArtifactCategory::AccountsCredentials,
                _ => ArtifactCategory::SystemActivity,
            };
            cats.insert(category.as_str().to_string());
            let fv = match a.data.get("forensic_value").map(|s| s.as_str()) {
                Some("Critical") => ForensicValue::Critical,
                Some("High") => ForensicValue::High,
                _ => ForensicValue::Medium,
            };
            records.push(ArtifactRecord {
                category,
                subcategory: ft,
                timestamp: None,
                title: a.data.get("title").cloned().unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value: fv,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: is_sus,
                raw_data: None,
                confidence: 0,
            });
        }
        let total = records.len();
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count: suspicious,
                categories_populated: cats.into_iter().collect(),
                headline: format!(
                    "MacTrace: {} macOS/iOS artifacts ({} suspicious)",
                    total, suspicious
                ),
            },
            warnings: vec![],
        })
    }
}

fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut out = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                if let Ok(sub) = walk_dir(&p) {
                    out.extend(sub);
                }
            } else {
                out.push(p);
            }
        }
    }
    Ok(out)
}

#[no_mangle]
pub extern "C" fn create_plugin_mactrace() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(MacTracePlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}
