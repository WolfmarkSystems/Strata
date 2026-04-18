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

pub mod biome;
pub mod clipboard_history;
pub mod fsevents;
pub mod imessage;
pub mod ios_biome;
pub mod ios_knowledgec;
pub mod knowledgec;
pub mod modern_macos;
pub mod plist_artifacts;
pub mod rosetta;
pub mod tcc;
pub mod unified_logs;

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
        if lc_name == "com.apple.loginitems.plist" || lc_name == "backgrounditems.btm" {
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
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .ok()?;
        let mut stmt = conn
            .prepare(&format!("SELECT COUNT(*) FROM {}", table))
            .ok()?;
        let n: i64 = stmt.query_row([], |row| row.get(0)).ok()?;
        Some(n)
    }
}

/// Render a [`modern_macos::ModernMacosRecord`] into (title, detail,
/// extra_fields, suspicious) for emission into the MacTrace artifact
/// stream. Kept outside the main routing loop to keep that loop
/// readable.
fn render_modern_macos(
    record: &crate::modern_macos::ModernMacosRecord,
) -> (String, String, Vec<(&'static str, String)>, bool) {
    use crate::modern_macos::ModernMacosRecord as R;
    match record {
        R::BackgroundTask(e) => {
            let suspicious = crate::modern_macos::is_suspicious_background_task(e);
            let title = format!("BackgroundTask: {}", e.app_identifier);
            let detail = format!(
                "App: {} | Developer: {} | Path: {} | Legacy: {} | Approved: {} | Created: {}",
                e.app_identifier,
                e.developer_name,
                e.app_path,
                e.is_legacy,
                e.user_approved,
                e.created_at
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
            let fields = vec![
                ("app_identifier", e.app_identifier.clone()),
                ("app_path", e.app_path.clone()),
                ("developer_name", e.developer_name.clone()),
                ("is_legacy", e.is_legacy.to_string()),
                ("user_approved", e.user_approved.to_string()),
            ];
            (title, detail, fields, suspicious)
        }
        R::ScreenTime(e) => {
            let title = format!("ScreenTime: {} ({:.0}s)", e.bundle_id, e.total_time_secs);
            let detail = format!(
                "Bundle: {} | Total seconds: {} | Date: {}",
                e.bundle_id,
                e.total_time_secs,
                e.date.format("%Y-%m-%d %H:%M:%S UTC"),
            );
            let fields = vec![
                ("bundle_id", e.bundle_id.clone()),
                ("total_time_secs", e.total_time_secs.to_string()),
            ];
            (title, detail, fields, false)
        }
        R::InstallHistory(e) => {
            let title = format!("Install: {} {}", e.display_name, e.display_version);
            let detail = format!(
                "Name: {} | Version: {} | Package: {} | Process: {} | Date: {}",
                e.display_name,
                e.display_version,
                e.package_identifier,
                e.process_name,
                e.install_date.format("%Y-%m-%d %H:%M:%S UTC"),
            );
            let fields = vec![
                ("display_name", e.display_name.clone()),
                ("display_version", e.display_version.clone()),
                ("package_identifier", e.package_identifier.clone()),
                ("process_name", e.process_name.clone()),
            ];
            (title, detail, fields, false)
        }
        R::NetworkUsage(e) => {
            let total = e.wifi_in + e.wifi_out + e.wired_in + e.wired_out;
            // Flag when a process transferred more than 500 MB — the
            // UI can then review for exfil patterns.
            let suspicious = total > 500 * 1024 * 1024;
            let title = format!(
                "NetworkUsage: {} ({} bytes)",
                e.process_name, total
            );
            let detail = format!(
                "Process: {} | WiFi In/Out: {}/{} | Wired In/Out: {}/{} | Timestamp: {}",
                e.process_name,
                e.wifi_in,
                e.wifi_out,
                e.wired_in,
                e.wired_out,
                e.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            );
            let fields = vec![
                ("process_name", e.process_name.clone()),
                ("wifi_in", e.wifi_in.to_string()),
                ("wifi_out", e.wifi_out.to_string()),
                ("wired_in", e.wired_in.to_string()),
                ("wired_out", e.wired_out.to_string()),
                ("total_bytes", total.to_string()),
            ];
            (title, detail, fields, suspicious)
        }
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
            // ── TCC.db — Transparency, Consent, and Control. macOS
            // privacy-grant database. See `crate::tcc`.
            let lower_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if lower_name == "tcc.db" {
                let path_str = path.to_string_lossy().to_string();
                let entries = crate::tcc::parse(&path);
                for e in &entries {
                    let mut a = Artifact::new("TCC Permission", &path_str);
                    a.timestamp = Some(e.last_modified.timestamp() as u64);
                    let suspicious = crate::tcc::is_suspicious(e);
                    let severity = crate::tcc::forensic_value_for(e);
                    let mitre = crate::tcc::mitre_for_service(&e.service_friendly);
                    a.add_field(
                        "title",
                        &format!(
                            "TCC: {} -> {} ({})",
                            e.client,
                            e.service_friendly,
                            e.auth_value.as_str()
                        ),
                    );
                    a.add_field(
                        "detail",
                        &format!(
                            "Service: {} ({}) | Client: {} | Client type: {} | \
                             Auth: {} | Auth reason: {} | Last modified: {} | \
                             Policy ID: {}",
                            e.service_friendly,
                            e.service,
                            e.client,
                            e.client_type.as_str(),
                            e.auth_value.as_str(),
                            e.auth_reason,
                            e.last_modified.format("%Y-%m-%d %H:%M:%S UTC"),
                            e.policy_id
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                        ),
                    );
                    a.add_field("file_type", "TCC Permission");
                    a.add_field("service", &e.service);
                    a.add_field("service_friendly", &e.service_friendly);
                    a.add_field("client", &e.client);
                    a.add_field("client_type", e.client_type.as_str());
                    a.add_field("auth_value", e.auth_value.as_str());
                    a.add_field("auth_reason", &e.auth_reason.to_string());
                    a.add_field(
                        "last_modified",
                        &e.last_modified.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                    );
                    if let Some(p) = e.policy_id {
                        a.add_field("policy_id", &p.to_string());
                    }
                    a.add_field("mitre", mitre);
                    a.add_field("forensic_value", severity);
                    if suspicious {
                        a.add_field("suspicious", "true");
                        a.add_field(
                            "suspicious_reason",
                            "Third-party app holds FullDiskAccess or Accessibility grant",
                        );
                    }
                    out.push(a);
                }
                continue;
            }

            // FSEvents (/.fseventsd/) — gzipped binary log of every
            // filesystem event the kernel surfaced. See
            // `crate::fsevents`. Highest-value source for proving
            // deletes / renames after the file is gone.
            let path_lower_pre = path.to_string_lossy().to_ascii_lowercase();
            if path_lower_pre.contains("/.fseventsd/")
                && !path_lower_pre.ends_with("fseventsd-uuid")
            {
                let path_str = path.to_string_lossy().to_string();
                if let Ok(data) = std::fs::read(&path) {
                    let events = crate::fsevents::parse(&path, &data);
                    for ev in &events {
                        let mut a = Artifact::new("FSEvent", &path_str);
                        if let Some(dt) = ev.approximate_date {
                            a.timestamp = Some(dt.timestamp() as u64);
                        }
                        let flags_str = ev.flags.as_string();
                        a.add_field("title", &format!("FSEvent [{}]: {}", flags_str, ev.path));
                        a.add_field(
                            "detail",
                            &format!(
                                "Path: {} | event_id: {} | flags: {} | is_directory: {} | \
                                 approximate_date: {} | source: {}",
                                ev.path,
                                ev.event_id,
                                flags_str,
                                ev.is_directory,
                                ev.approximate_date
                                    .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                    .unwrap_or_else(|| "-".to_string()),
                                path_str,
                            ),
                        );
                        a.add_field("file_type", "FSEvent");
                        a.add_field("path", &ev.path);
                        a.add_field("event_id", &ev.event_id.to_string());
                        a.add_field("flags_str", &flags_str);
                        a.add_field(
                            "is_directory",
                            if ev.is_directory { "true" } else { "false" },
                        );
                        if let Some(dt) = ev.approximate_date {
                            a.add_field(
                                "approximate_date",
                                &dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                            );
                        }
                        // MITRE per spec:
                        //   Removed       -> T1070.004 (file deletion)
                        //   Created+large -> T1074.001 (data staging)
                        //   else          -> T1083     (file/dir discovery)
                        let mitre = if ev.flags.removed() {
                            "T1070.004"
                        } else if ev.flags.created()
                            && (ev.path.to_ascii_lowercase().contains(".zip")
                                || ev.path.to_ascii_lowercase().contains(".7z")
                                || ev.path.to_ascii_lowercase().contains(".tar")
                                || ev.path.to_ascii_lowercase().contains(".dmg"))
                        {
                            "T1074.001"
                        } else {
                            "T1083"
                        };
                        a.add_field("mitre", mitre);
                        let severity = if ev.flags.removed() || ev.flags.renamed() {
                            "High"
                        } else {
                            "Medium"
                        };
                        a.add_field("forensic_value", severity);
                        if ev.flags.removed() || ev.flags.renamed() {
                            a.add_field("suspicious", "true");
                        }
                        out.push(a);
                    }
                }
                continue;
            }

            // Modern macOS (13+) artifacts — Background Task Management,
            // Screen Time, Install History, Network Usage. See
            // `crate::modern_macos`.
            if crate::modern_macos::ModernMacosArtifactType::from_path(&path).is_some() {
                let path_str = path.to_string_lossy().to_string();
                let records = crate::modern_macos::parse(&path);
                for r in &records {
                    let kind = r.artifact_type();
                    let (title, detail, extra_fields, suspicious) = render_modern_macos(r);
                    let mut a = Artifact::new("Modern macOS Artifact", &path_str);
                    a.timestamp = r.timestamp().map(|dt| dt.timestamp() as u64);
                    a.add_field("title", &title);
                    a.add_field("detail", &detail);
                    a.add_field("file_type", "Modern macOS Artifact");
                    a.add_field("artifact_type", kind.as_str());
                    for (k, v) in &extra_fields {
                        a.add_field(k, v);
                    }
                    if let Some(dt) = r.timestamp() {
                        a.add_field(
                            "timestamp",
                            &dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                        );
                    }
                    a.add_field("mitre", kind.mitre());
                    let severity = if suspicious {
                        "High"
                    } else {
                        kind.forensic_value()
                    };
                    a.add_field("forensic_value", severity);
                    if suspicious {
                        a.add_field("suspicious", "true");
                    }
                    out.push(a);
                }
                continue;
            }

            // Plist artifacts — Recent Items, Login Items, Quarantine
            // Events, Sidebar Lists, Dock Items. See
            // `crate::plist_artifacts` for the full schema.
            if crate::plist_artifacts::PlistArtifactType::from_path(&path).is_some() {
                let path_str = path.to_string_lossy().to_string();
                let records = crate::plist_artifacts::parse(&path);
                for r in &records {
                    let mut a = Artifact::new("Plist Artifact", &path_str);
                    a.timestamp = r.timestamp.map(|dt| dt.timestamp() as u64);
                    let title = format!("{} [{}]: {}", r.artifact_type.as_str(), r.name, r.value,);
                    let detail = format!(
                        "Type: {} | Name: {} | Value: {} | Metadata: {} | Timestamp: {}",
                        r.artifact_type.as_str(),
                        r.name,
                        r.value,
                        r.metadata.as_deref().unwrap_or("-"),
                        r.timestamp
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    );
                    a.add_field("title", &title);
                    a.add_field("detail", &detail);
                    a.add_field("file_type", "Plist Artifact");
                    a.add_field("artifact_type", r.artifact_type.as_str());
                    a.add_field("name", &r.name);
                    a.add_field("value", &r.value);
                    if let Some(v) = &r.metadata {
                        a.add_field("metadata", v);
                    }
                    if let Some(dt) = r.timestamp {
                        a.add_field("timestamp", &dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                    }
                    a.add_field("mitre", r.artifact_type.mitre());
                    a.add_field("forensic_value", r.artifact_type.forensic_value());
                    out.push(a);
                }
                // Per-record plist routing owns this file; skip
                // classify() to avoid the legacy summary duplicate.
                continue;
            }

            // iMessage / SMS enhanced per-message parser (MOB-3). Runs
            // before classify() so every message becomes its own
            // artifact rather than a single row-count summary.
            if crate::imessage::is_imessage_path(&path) {
                let path_str = path.to_string_lossy().to_string();
                let records = crate::imessage::parse(&path);
                for r in &records {
                    let mut a = Artifact::new("iMessage", &path_str);
                    a.timestamp = Some(r.date.timestamp() as u64);
                    let body = r
                        .text
                        .clone()
                        .or_else(|| r.attributed_text.clone())
                        .unwrap_or_default();
                    let title = format!(
                        "iMessage {} {}: {}",
                        if r.was_downgraded { "(SMS)" } else { "" },
                        r.handle.as_deref().unwrap_or("?"),
                        body.chars().take(120).collect::<String>()
                    );
                    let att_summary = r
                        .attachments
                        .iter()
                        .map(|att| {
                            format!(
                                "{} ({} bytes, {})",
                                att.transfer_name.as_deref().unwrap_or("-"),
                                att.total_bytes,
                                att.mime_type.as_deref().unwrap_or("-"),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                    let detail = format!(
                        "rowid={} | date={} | handle={} | text={} | thread={} | \
                         assoc={} | style={} | downgraded={} | attachments=[{}]",
                        r.rowid,
                        r.date.format("%Y-%m-%d %H:%M:%S UTC"),
                        r.handle.as_deref().unwrap_or("-"),
                        body.chars().take(512).collect::<String>(),
                        r.thread_originator_guid.as_deref().unwrap_or("-"),
                        r.associated_message_guid.as_deref().unwrap_or("-"),
                        r.expressive_send_style_id.as_deref().unwrap_or("-"),
                        r.was_downgraded,
                        att_summary,
                    );
                    a.add_field("title", &title);
                    a.add_field("detail", &detail);
                    a.add_field("file_type", "iMessage");
                    a.add_field("rowid", &r.rowid.to_string());
                    if let Some(h) = &r.handle {
                        a.add_field("handle", h);
                    }
                    if !body.is_empty() {
                        a.add_field("body", &body);
                    }
                    if let Some(v) = &r.thread_originator_guid {
                        a.add_field("thread_originator_guid", v);
                    }
                    if let Some(v) = &r.associated_message_guid {
                        a.add_field("associated_message_guid", v);
                    }
                    if let Some(v) = &r.expressive_send_style_id {
                        a.add_field("expressive_send_style_id", v);
                    }
                    if r.was_downgraded {
                        a.add_field("was_downgraded", "true");
                    }
                    for att in &r.attachments {
                        if let Some(n) = &att.transfer_name {
                            a.add_field("attachment_name", n);
                        }
                        if let Some(m) = &att.mime_type {
                            a.add_field("attachment_mime", m);
                        }
                        a.add_field("attachment_bytes", &att.total_bytes.to_string());
                        if att.is_sticker {
                            a.add_field("attachment_is_sticker", "true");
                        }
                    }
                    let mitre = if r.attachments.iter().any(|att| {
                        att.mime_type
                            .as_deref()
                            .map(|m| m.starts_with("image") || m.starts_with("video"))
                            .unwrap_or(false)
                    }) {
                        "T1530"
                    } else {
                        "T1636.002"
                    };
                    a.add_field("mitre", mitre);
                    a.add_field("forensic_value", "High");
                    out.push(a);
                }
                continue;
            }

            // iOS KnowledgeC — same filename but different schema than
            // macOS (extra battery / media / messages streams). Routed
            // before the macOS parser when the path lives under the
            // iOS mobile CoreDuet location.
            if crate::ios_knowledgec::is_ios_knowledgec_path(&path) {
                let path_str = path.to_string_lossy().to_string();
                let recs = crate::ios_knowledgec::parse(&path);
                for r in &recs {
                    let mut a = Artifact::new("iOS KnowledgeC Record", &path_str);
                    a.timestamp = Some(r.start_time.timestamp() as u64);
                    let title = match r.stream_name.as_str() {
                        "/app/inFocus" => format!(
                            "iOS KnowledgeC [inFocus]: {}",
                            r.bundle_id.as_deref().unwrap_or("<unknown>")
                        ),
                        "/device/isPluggedIn" => format!(
                            "iOS KnowledgeC [isPluggedIn]: {}",
                            match r.value_integer {
                                Some(v) if v != 0 => "plugged in",
                                Some(_) => "unplugged",
                                None => "unknown",
                            }
                        ),
                        "/device/batteryPercentage" => format!(
                            "iOS KnowledgeC [battery]: {:.0}%",
                            r.value_double.unwrap_or(0.0) * 100.0
                        ),
                        "/media/nowPlaying" => format!(
                            "iOS KnowledgeC [nowPlaying]: {}",
                            r.media_title.as_deref().unwrap_or("<unknown>")
                        ),
                        "/safari/history" | "/safariHistory" => format!(
                            "iOS KnowledgeC [safari]: {}",
                            r.url.as_deref().unwrap_or("<unknown>")
                        ),
                        "/com.apple.messages.count" => format!(
                            "iOS KnowledgeC [messages.count]: {}",
                            r.value_integer.unwrap_or(0)
                        ),
                        other => format!("iOS KnowledgeC [{}]", other),
                    };
                    a.add_field("title", &title);
                    a.add_field(
                        "detail",
                        &format!(
                            "Stream: {} | start: {} | bundle: {} | url: {} | \
                             media: {} | int: {} | double: {}",
                            r.stream_name,
                            r.start_time.format("%Y-%m-%d %H:%M:%S UTC"),
                            r.bundle_id.as_deref().unwrap_or("-"),
                            r.url.as_deref().unwrap_or("-"),
                            r.media_title.as_deref().unwrap_or("-"),
                            r.value_integer
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            r.value_double
                                .map(|v| format!("{:.3}", v))
                                .unwrap_or_else(|| "-".to_string()),
                        ),
                    );
                    a.add_field("file_type", "iOS KnowledgeC Record");
                    a.add_field("stream_name", &r.stream_name);
                    if let Some(v) = &r.bundle_id {
                        a.add_field("bundle_id", v);
                    }
                    if let Some(v) = &r.url {
                        a.add_field("url", v);
                    }
                    if let Some(v) = &r.media_title {
                        a.add_field("media_title", v);
                    }
                    if let Some(v) = r.value_integer {
                        a.add_field("value_integer", &v.to_string());
                    }
                    if let Some(v) = r.value_double {
                        a.add_field("value_double", &format!("{:.3}", v));
                    }
                    a.add_field(
                        "mitre",
                        crate::ios_knowledgec::mitre_for_stream(&r.stream_name),
                    );
                    a.add_field("forensic_value", "High");
                    out.push(a);
                }
                continue;
            }

            // KnowledgeC.db — pre-macOS-13 user-activity store. Per-row
            // parsing supersedes the generic row-count summary produced
            // by `classify()` for the same filename.
            if lower_name == "knowledgec.db" {
                let path_str = path.to_string_lossy().to_string();
                let records = crate::knowledgec::parse(&path);
                for r in &records {
                    let mut a = Artifact::new("KnowledgeC Record", &path_str);
                    a.timestamp = Some(r.start_time.timestamp() as u64);
                    let title = match r.stream_name.as_str() {
                        "/app/inFocus" => format!(
                            "KnowledgeC [app/inFocus]: {}",
                            r.bundle_id.as_deref().unwrap_or("<unknown>")
                        ),
                        "/user/appSession" => format!(
                            "KnowledgeC [appSession]: {} ({}s)",
                            r.bundle_id.as_deref().unwrap_or("<unknown>"),
                            crate::knowledgec::session_duration_secs(r).unwrap_or(0),
                        ),
                        "/safari/history" => format!(
                            "KnowledgeC [safari/history]: {}",
                            r.url.as_deref().unwrap_or("<unknown>")
                        ),
                        "/app/webUsage" => format!(
                            "KnowledgeC [app/webUsage]: {}",
                            r.url.as_deref().unwrap_or("<unknown>")
                        ),
                        "/device/isLocked" => format!(
                            "KnowledgeC [device/isLocked]: {}",
                            match r.value_integer {
                                Some(v) if v != 0 => "locked",
                                Some(_) => "unlocked",
                                None => "unknown",
                            }
                        ),
                        "/display/isBacklit" => format!(
                            "KnowledgeC [display/isBacklit]: {}",
                            match r.value_integer {
                                Some(v) if v != 0 => "on",
                                Some(_) => "off",
                                None => "unknown",
                            }
                        ),
                        other => format!("KnowledgeC [{}]", other),
                    };
                    let detail = format!(
                        "Stream: {} | bundle_id: {} | url: {} | start: {} | end: {} | \
                         value_integer: {} | device_id: {}",
                        r.stream_name,
                        r.bundle_id.as_deref().unwrap_or("-"),
                        r.url.as_deref().unwrap_or("-"),
                        r.start_time.format("%Y-%m-%d %H:%M:%S UTC"),
                        r.end_time
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        r.value_integer
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        r.device_id.as_deref().unwrap_or("-"),
                    );
                    a.add_field("title", &title);
                    a.add_field("detail", &detail);
                    a.add_field("file_type", "KnowledgeC Record");
                    a.add_field("stream_name", &r.stream_name);
                    if let Some(v) = &r.bundle_id {
                        a.add_field("bundle_id", v);
                    }
                    if let Some(v) = &r.url {
                        a.add_field("url", v);
                    }
                    a.add_field(
                        "start_time",
                        &r.start_time.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                    );
                    if let Some(dt) = r.end_time {
                        a.add_field("end_time", &dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                    }
                    if let Some(v) = r.value_integer {
                        a.add_field("value_integer", &v.to_string());
                    }
                    if let Some(v) = &r.device_id {
                        a.add_field("device_id", v);
                    }
                    a.add_field("mitre", crate::knowledgec::mitre_for_stream(&r.stream_name));
                    a.add_field("forensic_value", "High");
                    out.push(a);
                }
                // Per-record routing owns this file; skip classify() to
                // avoid the legacy row-count duplicate.
                continue;
            }

            // Unified Logs (`.tracev3`) — Apple Unified Logging System.
            // Per-record decoding is deferred; the indicator reader
            // surfaces forensically significant process / subsystem
            // tokens. See `crate::unified_logs`.
            if lower_name.ends_with(".tracev3") {
                let path_str = path.to_string_lossy().to_string();
                if let Ok(data) = std::fs::read(&path) {
                    let entries = crate::unified_logs::parse(&path, &data);
                    for e in &entries {
                        if !e.is_forensically_significant() {
                            continue;
                        }
                        let mut a = Artifact::new("Unified Log Entry", &path_str);
                        a.timestamp = Some(e.timestamp.timestamp() as u64);
                        let title = match e.subsystem.as_deref() {
                            Some(sub) => format!("Unified Log [{}]: {}", sub, e.message),
                            None => format!("Unified Log [{}]: {}", e.process, e.message),
                        };
                        let detail = format!(
                            "Process: {} | PID: {} | Subsystem: {} | Category: {} | \
                             Level: {} | Timestamp: {} | Message: {}",
                            e.process,
                            e.pid,
                            e.subsystem.as_deref().unwrap_or("-"),
                            e.category.as_deref().unwrap_or("-"),
                            e.log_level,
                            e.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                            e.message,
                        );
                        a.add_field("title", &title);
                        a.add_field("detail", &detail);
                        a.add_field("file_type", "Unified Log Entry");
                        a.add_field("process", &e.process);
                        a.add_field("pid", &e.pid.to_string());
                        if let Some(v) = &e.subsystem {
                            a.add_field("subsystem", v);
                        }
                        if let Some(v) = &e.category {
                            a.add_field("category", v);
                        }
                        a.add_field("log_level", &e.log_level);
                        a.add_field("message", &e.message);
                        a.add_field(
                            "timestamp",
                            &e.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                        );
                        a.add_field("mitre", e.mitre_technique());
                        a.add_field("forensic_value", e.forensic_value());
                        out.push(a);
                    }
                }
                // tracev3 routing owns this file; skip classify() to
                // avoid the legacy summary duplicate.
                continue;
            }

            // iOS Biome — same SEGB container but iOS-only stream
            // shapes (photos, messaging, significant location). Routed
            // before the macOS Biome block so iOS paths don't fall
            // through to the macOS decoder.
            if crate::ios_biome::is_ios_biome_path(&path) {
                let path_str = path.to_string_lossy().to_string();
                if let Ok(data) = std::fs::read(&path) {
                    let records = crate::ios_biome::parse(&path, &data);
                    for r in &records {
                        let mut a = Artifact::new("iOS Biome Record", &path_str);
                        a.timestamp = r.start_time.map(|d| d.timestamp() as u64);
                        let title = match r.stream_type {
                            crate::ios_biome::IosBiomeStream::PhotoAssetAdded => format!(
                                "iOS Biome [photos/assetAdded]: {}",
                                r.photo_asset_id.as_deref().unwrap_or("<unknown>")
                            ),
                            crate::ios_biome::IosBiomeStream::MessagingSent => format!(
                                "iOS Biome [messaging/sent]: to {}",
                                r.message_recipient.as_deref().unwrap_or("<unknown>")
                            ),
                            crate::ios_biome::IosBiomeStream::LocationSignificant => format!(
                                "iOS Biome [location/significant]: {:.6},{:.6}",
                                r.latitude.unwrap_or(0.0),
                                r.longitude.unwrap_or(0.0)
                            ),
                            crate::ios_biome::IosBiomeStream::Shared => format!(
                                "iOS Biome [{}]: {}",
                                r.stream_type.as_str(),
                                r.bundle_id
                                    .clone()
                                    .or_else(|| r.url.clone())
                                    .unwrap_or_else(|| "<unknown>".to_string())
                            ),
                            crate::ios_biome::IosBiomeStream::Unknown => {
                                "iOS Biome record (stream unknown)".to_string()
                            }
                        };
                        a.add_field("title", &title);
                        a.add_field(
                            "detail",
                            &format!(
                                "Stream: {} | time: {} | lat: {} | lon: {} | \
                                 asset: {} | recipient: {}",
                                r.stream_type.as_str(),
                                r.start_time
                                    .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                    .unwrap_or_else(|| "-".to_string()),
                                r.latitude
                                    .map(|v| format!("{:.6}", v))
                                    .unwrap_or_else(|| "-".to_string()),
                                r.longitude
                                    .map(|v| format!("{:.6}", v))
                                    .unwrap_or_else(|| "-".to_string()),
                                r.photo_asset_id.as_deref().unwrap_or("-"),
                                r.message_recipient.as_deref().unwrap_or("-"),
                            ),
                        );
                        a.add_field("file_type", "iOS Biome Record");
                        a.add_field("stream_type", r.stream_type.as_str());
                        if let Some(v) = r.latitude {
                            a.add_field("latitude", &format!("{:.6}", v));
                        }
                        if let Some(v) = r.longitude {
                            a.add_field("longitude", &format!("{:.6}", v));
                        }
                        if let Some(v) = &r.photo_asset_id {
                            a.add_field("photo_asset_id", v);
                        }
                        if let Some(v) = &r.message_recipient {
                            a.add_field("message_recipient", v);
                        }
                        if let Some(v) = &r.bundle_id {
                            a.add_field("bundle_id", v);
                        }
                        if let Some(v) = &r.url {
                            a.add_field("url", v);
                        }
                        a.add_field("mitre", r.stream_type.mitre());
                        a.add_field("forensic_value", r.stream_type.forensic_value());
                        out.push(a);
                    }
                }
                continue;
            }

            // Apple Biome (macOS 13+) — highest-priority user-activity
            // store. Detect by `/biome/` (system) or `/Biome/`
            // (per-user) path fragment. SEGB format, custom protobuf.
            // See `crate::biome` for the full schema.
            let path_lower = path.to_string_lossy().to_ascii_lowercase();
            if path_lower.contains("/biome/") {
                let path_str = path.to_string_lossy().to_string();
                if let Ok(data) = std::fs::read(&path) {
                    let records = crate::biome::parse(&path, &data);
                    for r in &records {
                        let mut a = Artifact::new("Biome Record", &path_str);
                        a.timestamp = r.start_time.map(|dt| dt.timestamp() as u64);
                        let title = match r.stream_type {
                            crate::biome::BiomeStreamType::AppInFocus => format!(
                                "Biome [app/inFocus]: {}",
                                r.bundle_id.as_deref().unwrap_or("<unknown>")
                            ),
                            crate::biome::BiomeStreamType::DeviceLocked => format!(
                                "Biome [device/locked]: {}",
                                match r.locked {
                                    Some(true) => "locked",
                                    Some(false) => "unlocked",
                                    None => "unknown",
                                }
                            ),
                            crate::biome::BiomeStreamType::SafariHistory => format!(
                                "Biome [Safari]: {}",
                                r.title
                                    .clone()
                                    .or_else(|| r.url.clone())
                                    .unwrap_or_else(|| "<unknown>".to_string())
                            ),
                            crate::biome::BiomeStreamType::AppSession => format!(
                                "Biome [appSession]: {} ({}s)",
                                r.bundle_id.as_deref().unwrap_or("<unknown>"),
                                r.duration_secs.unwrap_or(0),
                            ),
                            crate::biome::BiomeStreamType::Unknown => {
                                "Biome record (stream unknown)".to_string()
                            }
                        };
                        let detail = format!(
                            "Stream: {} | bundle_id: {} | url: {} | title: {} | \
                             start: {} | end: {} | locked: {} | duration_secs: {}",
                            r.stream_type.as_str(),
                            r.bundle_id.as_deref().unwrap_or("-"),
                            r.url.as_deref().unwrap_or("-"),
                            r.title.as_deref().unwrap_or("-"),
                            r.start_time
                                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            r.end_time
                                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            match r.locked {
                                Some(true) => "true",
                                Some(false) => "false",
                                None => "-",
                            },
                            r.duration_secs
                                .map(|d| d.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                        );
                        a.add_field("title", &title);
                        a.add_field("detail", &detail);
                        a.add_field("file_type", "Biome Record");
                        a.add_field("stream_type", r.stream_type.as_str());
                        if let Some(v) = &r.bundle_id {
                            a.add_field("bundle_id", v);
                        }
                        if let Some(v) = &r.url {
                            a.add_field("url", v);
                        }
                        if let Some(v) = &r.title {
                            a.add_field("page_title", v);
                        }
                        if let Some(dt) = r.start_time {
                            a.add_field(
                                "start_time",
                                &dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                            );
                        }
                        if let Some(dt) = r.end_time {
                            a.add_field(
                                "end_time",
                                &dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                            );
                        }
                        if let Some(l) = r.locked {
                            a.add_field("locked", if l { "true" } else { "false" });
                        }
                        if let Some(d) = r.duration_secs {
                            a.add_field("duration_secs", &d.to_string());
                        }
                        // MITRE per stream: T1217 for Safari history,
                        // T1059 for app focus / sessions, otherwise
                        // generic T1005 (Data from Local System).
                        let mitre = match r.stream_type {
                            crate::biome::BiomeStreamType::SafariHistory => "T1217",
                            crate::biome::BiomeStreamType::AppInFocus
                            | crate::biome::BiomeStreamType::AppSession => "T1059",
                            _ => "T1005",
                        };
                        a.add_field("mitre", mitre);
                        a.add_field("forensic_value", "High");
                        out.push(a);
                    }
                }
                // Biome routing owns this path; skip the generic
                // classify() step to avoid double-emission.
                continue;
            }

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
            let is_sus = a
                .data
                .get("suspicious")
                .map(|s| s == "true")
                .unwrap_or(false);
            if is_sus {
                suspicious += 1;
            }
            let category = match ft.as_str() {
                "SMS/iMessage" | "iMessage" | "WhatsApp iOS" | "WhatsApp Android"
                | "Signal" | "Telegram" | "CallHistory" => ArtifactCategory::Communications,
                "Safari History" => ArtifactCategory::WebActivity,
                "AddressBook" => ArtifactCategory::AccountsCredentials,
                "Biome Record"
                | "iOS Biome Record"
                | "KnowledgeC Record"
                | "iOS KnowledgeC Record"
                | "Plist Artifact"
                | "Modern macOS Artifact" => ArtifactCategory::UserActivity,
                "FSEvent" | "Unified Log Entry" => ArtifactCategory::SystemActivity,
                "TCC Permission" => ArtifactCategory::AccountsCredentials,
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
                title: a
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| a.source.clone()),
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
