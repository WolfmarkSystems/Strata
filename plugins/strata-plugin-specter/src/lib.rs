use std::collections::HashSet;
use std::path::Path;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct SpecterPlugin {
    name: String,
    version: String,
}

impl Default for SpecterPlugin {
    fn default() -> Self { Self::new() }
}

impl SpecterPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Specter".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    /// Query iOS WhatsApp ChatStorage.sqlite for message statistics.
    fn query_whatsapp_ios(path: &Path, path_str: &str) -> Vec<Artifact> {
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY;
        let conn = match rusqlite::Connection::open_with_flags(path, flags) {
            Ok(c) => c,
            Err(_) => return Self::whatsapp_fallback(path_str, "iOS"),
        };

        // Apple Core Data epoch offset: 2001-01-01 00:00:00 UTC
        const APPLE_EPOCH: i64 = 978_307_200;

        let query = "\
            SELECT m.ZTEXT, m.ZISFROMME, m.ZMESSAGEDATE, m.ZFROMJID, c.ZPARTNERNAME \
            FROM ZWAMESSAGE m \
            LEFT JOIN ZWACHATSESSION c ON m.ZCHATSESSION = c.Z_PK \
            ORDER BY m.ZMESSAGEDATE DESC LIMIT 1000";

        let mut stmt = match conn.prepare(query) {
            Ok(s) => s,
            Err(_) => return Self::whatsapp_fallback(path_str, "iOS"),
        };

        let rows = match stmt.query_map([], |row| {
            let is_from_me: i32 = row.get(1).unwrap_or(0);
            let wa_date: f64 = row.get(2).unwrap_or(0.0);
            let from_jid: String = row.get(3).unwrap_or_default();
            Ok((is_from_me, wa_date, from_jid))
        }) {
            Ok(r) => r,
            Err(_) => return Self::whatsapp_fallback(path_str, "iOS"),
        };

        let mut total: u64 = 0;
        let mut sent: u64 = 0;
        let mut received: u64 = 0;
        let mut jids = HashSet::new();
        let mut earliest_ts: Option<i64> = None;
        let mut latest_ts: Option<i64> = None;

        for row_result in rows {
            let Ok((is_from_me, wa_date, from_jid)) = row_result else { continue };
            total += 1;
            if is_from_me == 1 { sent += 1; } else { received += 1; }
            if !from_jid.is_empty() { jids.insert(from_jid); }
            let unix_ts = (wa_date as i64) + APPLE_EPOCH;
            match earliest_ts {
                Some(e) if unix_ts < e => earliest_ts = Some(unix_ts),
                None => earliest_ts = Some(unix_ts),
                _ => {}
            }
            match latest_ts {
                Some(l) if unix_ts > l => latest_ts = Some(unix_ts),
                None => latest_ts = Some(unix_ts),
                _ => {}
            }
        }

        if total == 0 {
            return Self::whatsapp_fallback(path_str, "iOS");
        }

        let fmt_ts = |ts: i64| -> String {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| ts.to_string())
        };
        let earliest_str = earliest_ts.map(fmt_ts).unwrap_or_default();
        let latest_str = latest_ts.map(fmt_ts).unwrap_or_default();

        let detail = format!(
            "Messages: {} | Sent: {} | Received: {} | Contacts: {} | Date range: {} to {}",
            total, sent, received, jids.len(), earliest_str, latest_str
        );
        let mut a = Artifact::new("Communications", path_str);
        a.add_field("subcategory", "WhatsApp Messages (iOS)");
        a.add_field("title", &format!("WhatsApp: {} messages found", total));
        a.add_field("detail", &detail);
        a.add_field("forensic_value", "Critical");
        a.add_field("mitre", "T1636");
        vec![a]
    }

    /// Query Android WhatsApp msgstore.db for message statistics.
    fn query_whatsapp_android(path: &Path, path_str: &str) -> Vec<Artifact> {
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY;
        let conn = match rusqlite::Connection::open_with_flags(path, flags) {
            Ok(c) => c,
            Err(_) => return Self::whatsapp_fallback(path_str, "Android"),
        };

        let query = "\
            SELECT data, key_from_me, timestamp, key_remote_jid, media_mime_type \
            FROM messages \
            ORDER BY timestamp DESC LIMIT 1000";

        let mut stmt = match conn.prepare(query) {
            Ok(s) => s,
            Err(_) => return Self::whatsapp_fallback(path_str, "Android"),
        };

        let rows = match stmt.query_map([], |row| {
            let key_from_me: i32 = row.get(1).unwrap_or(0);
            let timestamp_ms: i64 = row.get(2).unwrap_or(0);
            let remote_jid: String = row.get(3).unwrap_or_default();
            let media_mime: Option<String> = row.get(4).ok();
            Ok((key_from_me, timestamp_ms, remote_jid, media_mime))
        }) {
            Ok(r) => r,
            Err(_) => return Self::whatsapp_fallback(path_str, "Android"),
        };

        let mut total: u64 = 0;
        let mut sent: u64 = 0;
        let mut received: u64 = 0;
        let mut media_count: u64 = 0;
        let mut jids = HashSet::new();
        let mut earliest_ts: Option<i64> = None;
        let mut latest_ts: Option<i64> = None;

        for row_result in rows {
            let Ok((key_from_me, timestamp_ms, remote_jid, media_mime)) = row_result else { continue };
            total += 1;
            if key_from_me == 1 { sent += 1; } else { received += 1; }
            if media_mime.as_ref().is_some_and(|m| !m.is_empty()) { media_count += 1; }
            if !remote_jid.is_empty() { jids.insert(remote_jid); }
            let unix_ts = timestamp_ms / 1000;
            match earliest_ts {
                Some(e) if unix_ts < e => earliest_ts = Some(unix_ts),
                None => earliest_ts = Some(unix_ts),
                _ => {}
            }
            match latest_ts {
                Some(l) if unix_ts > l => latest_ts = Some(unix_ts),
                None => latest_ts = Some(unix_ts),
                _ => {}
            }
        }

        if total == 0 {
            return Self::whatsapp_fallback(path_str, "Android");
        }

        let fmt_ts = |ts: i64| -> String {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| ts.to_string())
        };
        let earliest_str = earliest_ts.map(fmt_ts).unwrap_or_default();
        let latest_str = latest_ts.map(fmt_ts).unwrap_or_default();

        let detail = format!(
            "Messages: {} | Sent: {} | Received: {} | Media: {} | Contacts: {} | Date range: {} to {}",
            total, sent, received, media_count, jids.len(), earliest_str, latest_str
        );
        let mut a = Artifact::new("Communications", path_str);
        a.add_field("subcategory", "WhatsApp Messages (Android)");
        a.add_field("title", &format!("WhatsApp: {} messages found", total));
        a.add_field("detail", &detail);
        a.add_field("forensic_value", "Critical");
        a.add_field("mitre", "T1636");
        vec![a]
    }

    /// Query iOS Signal (signal.sqlite) for message statistics.
    fn query_signal_ios(path: &Path) -> Vec<Artifact> {
        let path_str = path.to_string_lossy().to_string();
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY;
        let conn = match rusqlite::Connection::open_with_flags(path, flags) {
            Ok(c) => c,
            Err(_) => return Self::signal_fallback(&path_str, "iOS"),
        };

        let query = "\
            SELECT m.body, m.date, m.type, t.contact_phone_number, t.contact_name \
            FROM message m \
            LEFT JOIN thread t ON m.thread_id = t.id \
            ORDER BY m.date DESC LIMIT 1000";

        let mut stmt = match conn.prepare(query) {
            Ok(s) => s,
            Err(_) => return Self::signal_fallback(&path_str, "iOS"),
        };

        let rows = match stmt.query_map([], |row| {
            let msg_type: i32 = row.get(2).unwrap_or(0);
            let contact_phone: String = row.get(3).unwrap_or_default();
            let date_ms: i64 = row.get(1).unwrap_or(0);
            Ok((msg_type, contact_phone, date_ms))
        }) {
            Ok(r) => r,
            Err(_) => return Self::signal_fallback(&path_str, "iOS"),
        };

        let mut total: u64 = 0;
        let mut sent: u64 = 0;
        let mut received: u64 = 0;
        let mut contacts = HashSet::new();
        let mut earliest_ts: Option<i64> = None;
        let mut latest_ts: Option<i64> = None;

        for row_result in rows {
            let Ok((msg_type, contact_phone, date_ms)) = row_result else { continue };
            total += 1;
            // type 1=incoming, 2=outgoing
            if msg_type == 2 { sent += 1; } else { received += 1; }
            if !contact_phone.is_empty() { contacts.insert(contact_phone); }
            let unix_ts = date_ms / 1000;
            match earliest_ts {
                Some(e) if unix_ts < e => earliest_ts = Some(unix_ts),
                None => earliest_ts = Some(unix_ts),
                _ => {}
            }
            match latest_ts {
                Some(l) if unix_ts > l => latest_ts = Some(unix_ts),
                None => latest_ts = Some(unix_ts),
                _ => {}
            }
        }

        if total == 0 {
            return Self::signal_fallback(&path_str, "iOS");
        }

        let fmt_ts = |ts: i64| -> String {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| ts.to_string())
        };
        let earliest_str = earliest_ts.map(fmt_ts).unwrap_or_default();
        let latest_str = latest_ts.map(fmt_ts).unwrap_or_default();

        let detail = format!(
            "Messages: {} | Sent: {} | Received: {} | Unique contacts: {} | Date range: {} to {}",
            total, sent, received, contacts.len(), earliest_str, latest_str
        );
        let mut a = Artifact::new("Communications", &path_str);
        a.add_field("subcategory", "Signal Messages");
        a.add_field("title", &format!("Signal: {} messages", total));
        a.add_field("detail", &detail);
        a.add_field("forensic_value", "Critical");
        a.add_field("mitre", "T1636");
        vec![a]
    }

    /// Query Android Signal (signal.db) for message statistics.
    fn query_signal_android(path: &Path) -> Vec<Artifact> {
        let path_str = path.to_string_lossy().to_string();
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY;
        let conn = match rusqlite::Connection::open_with_flags(path, flags) {
            Ok(c) => c,
            Err(_) => return Self::signal_fallback(&path_str, "Android"),
        };

        let query = "\
            SELECT s.body, s.date, s.type, s.address \
            FROM sms s \
            ORDER BY s.date DESC LIMIT 1000";

        let mut stmt = match conn.prepare(query) {
            Ok(s) => s,
            Err(_) => return Self::signal_fallback(&path_str, "Android"),
        };

        let rows = match stmt.query_map([], |row| {
            let msg_type: i32 = row.get(2).unwrap_or(0);
            let address: String = row.get(3).unwrap_or_default();
            let date_ms: i64 = row.get(1).unwrap_or(0);
            Ok((msg_type, address, date_ms))
        }) {
            Ok(r) => r,
            Err(_) => return Self::signal_fallback(&path_str, "Android"),
        };

        let mut total: u64 = 0;
        let mut sent: u64 = 0;
        let mut received: u64 = 0;
        let mut contacts = HashSet::new();
        let mut earliest_ts: Option<i64> = None;
        let mut latest_ts: Option<i64> = None;

        for row_result in rows {
            let Ok((msg_type, address, date_ms)) = row_result else { continue };
            total += 1;
            // type 1=inbox, 2=sent
            if msg_type == 2 { sent += 1; } else { received += 1; }
            if !address.is_empty() { contacts.insert(address); }
            let unix_ts = date_ms / 1000;
            match earliest_ts {
                Some(e) if unix_ts < e => earliest_ts = Some(unix_ts),
                None => earliest_ts = Some(unix_ts),
                _ => {}
            }
            match latest_ts {
                Some(l) if unix_ts > l => latest_ts = Some(unix_ts),
                None => latest_ts = Some(unix_ts),
                _ => {}
            }
        }

        if total == 0 {
            return Self::signal_fallback(&path_str, "Android");
        }

        let fmt_ts = |ts: i64| -> String {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| ts.to_string())
        };
        let earliest_str = earliest_ts.map(fmt_ts).unwrap_or_default();
        let latest_str = latest_ts.map(fmt_ts).unwrap_or_default();

        let detail = format!(
            "Messages: {} | Sent: {} | Received: {} | Unique contacts: {} | Date range: {} to {}",
            total, sent, received, contacts.len(), earliest_str, latest_str
        );
        let mut a = Artifact::new("Communications", &path_str);
        a.add_field("subcategory", "Signal Messages");
        a.add_field("title", &format!("Signal: {} messages", total));
        a.add_field("detail", &detail);
        a.add_field("forensic_value", "Critical");
        a.add_field("mitre", "T1636");
        vec![a]
    }

    /// Fallback when Signal DB is found but cannot be queried.
    fn signal_fallback(path_str: &str, platform: &str) -> Vec<Artifact> {
        let mut a = Artifact::new("Communications", path_str);
        a.add_field("subcategory", "Signal Messages");
        a.add_field("title", &format!("Signal database ({})", platform));
        a.add_field(
            "detail",
            "Signal database found but could not query \u{2014} may be encrypted or require key",
        );
        a.add_field("mitre", "T1636");
        vec![a]
    }

    /// Query iOS Telegram (tgdata.db) for message statistics.
    fn query_telegram_ios(path: &Path) -> Vec<Artifact> {
        let path_str = path.to_string_lossy().to_string();
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY;
        let conn = match rusqlite::Connection::open_with_flags(path, flags) {
            Ok(c) => c,
            Err(_) => return Self::telegram_fallback(&path_str),
        };

        let query = "\
            SELECT m.message, m.date, m.fromId, d.name \
            FROM t_messages m \
            LEFT JOIN t_dialogs d ON m.did = d.did \
            ORDER BY m.date DESC LIMIT 1000";

        let mut stmt = match conn.prepare(query) {
            Ok(s) => s,
            Err(_) => return Self::telegram_fallback(&path_str),
        };

        let rows = match stmt.query_map([], |row| {
            let date_unix: i64 = row.get(1).unwrap_or(0);
            let dialog_name: String = row.get(3).unwrap_or_default();
            Ok((date_unix, dialog_name))
        }) {
            Ok(r) => r,
            Err(_) => return Self::telegram_fallback(&path_str),
        };

        let mut total: u64 = 0;
        let mut dialogs = HashSet::new();
        let mut earliest_ts: Option<i64> = None;
        let mut latest_ts: Option<i64> = None;

        for row_result in rows {
            let Ok((date_unix, dialog_name)) = row_result else { continue };
            total += 1;
            if !dialog_name.is_empty() { dialogs.insert(dialog_name); }
            match earliest_ts {
                Some(e) if date_unix < e => earliest_ts = Some(date_unix),
                None => earliest_ts = Some(date_unix),
                _ => {}
            }
            match latest_ts {
                Some(l) if date_unix > l => latest_ts = Some(date_unix),
                None => latest_ts = Some(date_unix),
                _ => {}
            }
        }

        if total == 0 {
            return Self::telegram_fallback(&path_str);
        }

        let fmt_ts = |ts: i64| -> String {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| ts.to_string())
        };
        let earliest_str = earliest_ts.map(fmt_ts).unwrap_or_default();
        let latest_str = latest_ts.map(fmt_ts).unwrap_or_default();

        let detail = format!(
            "Messages: {} | Unique dialogs: {} | Date range: {} to {}",
            total, dialogs.len(), earliest_str, latest_str
        );
        let mut a = Artifact::new("Communications", &path_str);
        a.add_field("subcategory", "Telegram Messages");
        a.add_field("title", &format!("Telegram: {} messages", total));
        a.add_field("detail", &detail);
        a.add_field("forensic_value", "Critical");
        a.add_field("mitre", "T1636");
        vec![a]
    }

    /// Fallback when Telegram DB is found but cannot be queried.
    fn telegram_fallback(path_str: &str) -> Vec<Artifact> {
        let mut a = Artifact::new("Communications", path_str);
        a.add_field("subcategory", "Telegram Messages");
        a.add_field("title", "Telegram database");
        a.add_field(
            "detail",
            "Telegram database found but could not query \u{2014} may be encrypted or require key",
        );
        a.add_field("mitre", "T1636");
        vec![a]
    }

    /// Fallback when WhatsApp DB is found but cannot be queried.
    fn whatsapp_fallback(path_str: &str, platform: &str) -> Vec<Artifact> {
        let mut a = Artifact::new("Communications", path_str);
        a.add_field("subcategory", &format!("WhatsApp Messages ({})", platform));
        a.add_field("title", &format!("WhatsApp database ({})", platform));
        a.add_field(
            "detail",
            "WhatsApp database found but could not query — may be encrypted or require key",
        );
        a.add_field("mitre", "T1636");
        vec![a]
    }

    fn detect_artifacts(path: &Path, name: &str, path_str: &str) -> Vec<Artifact> {
        let mut results = Vec::new();
        let name_lower = name.to_lowercase();
        let path_lower = path_str.to_lowercase();
        
        // iOS KnowledgeC
        if name_lower == "knowledgec.db" {
            let mut a = Artifact::new("iOS App Usage", path_str);
            a.add_field("subcategory", "iOS App Usage (KnowledgeC)");
            a.add_field("title", "KnowledgeC database");
            a.add_field("detail", "iOS app usage database — contains app activity timeline");
            a.add_field("mitre", "T1636");
            results.push(a);
        }
        // iOS DataUsage
        if name_lower == "datausage.sqlite" {
            let mut a = Artifact::new("Network Artifacts", path_str);
            a.add_field("subcategory", "iOS Network Usage");
            a.add_field("title", "DataUsage.sqlite");
            a.add_field("detail", "iOS network usage per process");
            results.push(a);
        }
        // WhatsApp iOS — ChatStorage.sqlite
        if name_lower == "chatstorage.sqlite" {
            results.extend(Self::query_whatsapp_ios(path, path_str));
        }
        // WhatsApp Android — msgstore.db (path must contain "whatsapp")
        if name_lower == "msgstore.db" && path_lower.contains("whatsapp") {
            results.extend(Self::query_whatsapp_android(path, path_str));
        }
        // Signal iOS — signal.sqlite
        if name_lower == "signal.sqlite" && path_lower.contains("signal") {
            results.extend(Self::query_signal_ios(path));
        }
        // Signal Android — signal.db
        if name_lower == "signal.db" && path_lower.contains("signal") {
            results.extend(Self::query_signal_android(path));
        }
        // Telegram iOS — tgdata.db
        if name_lower == "tgdata.db" {
            results.extend(Self::query_telegram_ios(path));
        }
        // Telegram (other DBs in telegram path)
        if name_lower == "cache4.db" && path_lower.contains("telegram") {
            let mut a = Artifact::new("Communications", path_str);
            a.add_field("subcategory", "Telegram Data");
            a.add_field("title", &format!("Telegram: {}", name));
            results.push(a);
        }
        // Snapchat
        if name_lower.contains("scdb") && name_lower.ends_with(".sqlite3") {
            let mut a = Artifact::new("Social Media", path_str);
            a.add_field("subcategory", "Snapchat Data");
            a.add_field("title", &format!("Snapchat: {}", name));
            results.push(a);
        }
        // Android backup
        if name_lower.ends_with(".ab") {
            if let Ok(data) = std::fs::read(path) {
                if data.starts_with(b"ANDROID BACKUP\n") {
                    let mut a = Artifact::new("Communications", path_str);
                    a.add_field("subcategory", "Android ADB Backup");
                    a.add_field("title", &format!("ADB Backup: {}", name));
                    a.add_field("detail", &format!("Android backup file — {} bytes", data.len()));
                    results.push(a);
                }
            }
        }
        // Facebook Android
        if path_lower.contains("com.facebook") && (name_lower.ends_with(".db") || name_lower.ends_with(".sqlite")) {
            let mut a = Artifact::new("Social Media", path_str);
            a.add_field("subcategory", "Facebook Data (Android)");
            a.add_field("title", &format!("Facebook: {}", name));
            results.push(a);
        }
        // Gmail Android
        if path_lower.contains("com.google.android.gm") && name_lower.ends_with(".db") {
            let mut a = Artifact::new("Communications", path_str);
            a.add_field("subcategory", "Gmail Data (Android)");
            a.add_field("title", &format!("Gmail: {}", name));
            results.push(a);
        }

        results
    }
}

impl StrataPlugin for SpecterPlugin {
    fn name(&self) -> &str { &self.name }
    fn version(&self) -> &str { &self.version }
    fn supported_inputs(&self) -> Vec<String> { vec!["*".to_string()] }
    fn plugin_type(&self) -> PluginType { PluginType::Analyzer }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }
    fn description(&self) -> &str { "Mobile device artifact analysis" }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let mut results = Vec::new();
        let root = Path::new(&ctx.root_path);
        if root.is_dir() {
            fn walk(dir: &Path, results: &mut Vec<Artifact>) {
                let Ok(entries) = std::fs::read_dir(dir) else { return };
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                    let path_str = path.to_string_lossy().to_string();
                    results.extend(SpecterPlugin::detect_artifacts(&path, &name, &path_str));
                    if path.is_dir() && results.len() < 50000 { walk(&path, results); }
                }
            }
            walk(root, &mut results);
        }
        Ok(results)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, strata_plugin_sdk::PluginError> {
        let start = std::time::Instant::now();
        let artifacts_raw = self.run(context)?;
        let mut records = Vec::new();
        for a in &artifacts_raw {
            let subcat = a.data.get("subcategory").cloned().unwrap_or_else(|| a.category.clone());
            let is_sus = a.data.get("suspicious").map(|v| v == "true").unwrap_or(false);
            let mitre = a.data.get("mitre").cloned();
            let cat = match subcat.as_str() {
                s if s.contains("iOS") || s.contains("Android") || s.contains("WhatsApp") || s.contains("Signal") || s.contains("Telegram") || s.contains("Gmail") || s.contains("Discord") || s.contains("ADB") => ArtifactCategory::Communications,
                s if s.contains("Snapchat") || s.contains("Facebook") || s.contains("Instagram") => ArtifactCategory::SocialMedia,
                s if s.contains("Network") => ArtifactCategory::NetworkArtifacts,
                _ => ArtifactCategory::UserActivity,
            };
            let fv_field = a.data.get("forensic_value").map(|s| s.as_str());
            let fv = if is_sus || fv_field == Some("Critical") { ForensicValue::Critical } else { ForensicValue::High };
            records.push(ArtifactRecord {
                category: cat,
                subcategory: subcat.clone(),
                timestamp: a.timestamp.map(|t| t as i64),
                title: a.data.get("title").cloned().unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value: fv,
                mitre_technique: mitre,
                is_suspicious: is_sus,
                raw_data: None,
            });
        }
        let sus = records.iter().filter(|r| r.is_suspicious).count();
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: artifacts_raw.len(),
                suspicious_count: sus,
                categories_populated: vec![],
                headline: format!("{}: {} artifacts ({} suspicious)", self.name(), artifacts_raw.len(), sus),
            },
            warnings: vec![],
        })
    }
}

#[no_mangle]
pub extern "C" fn create_plugin_specter() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(SpecterPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}
