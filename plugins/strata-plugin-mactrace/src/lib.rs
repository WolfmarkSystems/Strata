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
