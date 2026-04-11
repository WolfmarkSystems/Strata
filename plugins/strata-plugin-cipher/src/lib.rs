use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

/// Sensitive URL keywords that flag a credential as suspicious.
const SENSITIVE_URL_KEYWORDS: &[&str] = &["bank", "paypal", "gov", "vpn", "admin", "login"];

/// Max file size for text credential/config reads (50 MB). AnyDesk
/// ad.trace can grow large on heavily-used systems; anything above
/// this cap is skipped to prevent OOM.
const MAX_TEXT_READ_BYTES: u64 = 50 * 1024 * 1024;

/// Size-gated `read_to_string` — returns `None` if the file exceeds
/// `MAX_TEXT_READ_BYTES` or cannot be read.
fn read_text_gated(path: &Path) -> Option<String> {
    let meta = path.metadata().ok()?;
    if meta.len() > MAX_TEXT_READ_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

pub struct CipherPlugin {
    name: String,
    version: String,
}

impl Default for CipherPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl CipherPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Cipher".to_string(),
            version: "2.0.0".to_string(),
        }
    }

    fn classify_file(path: &Path) -> Option<(&'static str, &'static str)> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let lower_name = name.to_lowercase();
        let lower_ext = ext.to_lowercase();

        // Chrome/Chromium credential stores
        if lower_name == "login data" || lower_name == "web data" {
            return Some(("Browser Credentials", "Saved Passwords"));
        }

        // Firefox credential stores
        if lower_name == "logins.json" {
            return Some(("Browser Credentials", "Saved Passwords"));
        }

        // SSH artifacts
        if lower_name == "known_hosts"
            || lower_name == "authorized_keys"
            || lower_name == "id_rsa"
            || lower_name == "id_ed25519"
            || lower_name == "id_ecdsa"
            || lower_name == "id_dsa"
        {
            return Some(("SSH Key", "SSH Keys"));
        }

        // Certificate files
        if lower_ext == "pem" || lower_ext == "pfx" || lower_ext == "p12" || lower_ext == "crt" {
            return Some(("Certificate", "Certificates"));
        }

        None
    }

    // ─── Chrome credential extraction ───────────────────────────────────

    /// Extract credentials from Chrome/Chromium Login Data or Web Data SQLite databases.
    /// Returns Vec of (url, username, detail, optional_unix_timestamp).
    fn extract_chrome_credentials(
        path: &Path,
    ) -> Vec<(String, String, String, Option<i64>)> {
        let mut results = Vec::new();

        let conn = match rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) {
            Ok(c) => c,
            Err(_) => return results,
        };

        let mut stmt = match conn.prepare(
            "SELECT origin_url, username_value, date_created, times_used \
             FROM logins ORDER BY date_created DESC LIMIT 5000",
        ) {
            Ok(s) => s,
            Err(_) => return results,
        };

        let rows = match stmt.query_map([], |row| {
            let url: String = row.get(0).unwrap_or_default();
            let username: String = row.get(1).unwrap_or_default();
            let date_created: i64 = row.get(2).unwrap_or(0);
            let times_used: i64 = row.get(3).unwrap_or(0);
            Ok((url, username, date_created, times_used))
        }) {
            Ok(r) => r,
            Err(_) => return results,
        };

        for row in rows.flatten() {
            {
                let (url, username, chrome_time, times_used) = row;
                // Chrome epoch: microseconds since 1601-01-01 → Unix seconds
                let unix_ts = if chrome_time > 0 {
                    Some((chrome_time - 11_644_473_600_000_000) / 1_000_000)
                } else {
                    None
                };

                let detail = format!(
                    "Used {} times | Password: [DPAPI encrypted]",
                    times_used
                );

                results.push((url, username, detail, unix_ts));
            }
        }

        results
    }

    // ─── Firefox credential extraction ──────────────────────────────────

    /// Extract credentials from Firefox logins.json.
    /// Returns Vec of (hostname, encrypted_username_placeholder, detail, optional_unix_timestamp).
    fn extract_firefox_credentials(
        path: &Path,
    ) -> Vec<(String, String, String, Option<i64>)> {
        let mut results = Vec::new();

        let content = match read_text_gated(path) {
            Some(c) => c,
            None => return results,
        };

        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return results,
        };

        let logins = match json.get("logins").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => return results,
        };

        for login in logins {
            let hostname = login
                .get("hostname")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let _encrypted_username = login
                .get("encryptedUsername")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let time_created = login
                .get("timeCreated")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            let times_used = login
                .get("timesUsed")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            // timeCreated is milliseconds since epoch
            let unix_ts = if time_created > 0 {
                Some(time_created / 1000)
            } else {
                None
            };

            let detail = format!(
                "Password: [NSS encrypted] | Used: {} times",
                times_used
            );

            results.push((hostname, "[encrypted]".to_string(), detail, unix_ts));
        }

        results
    }

    // ─── SSH known_hosts parsing ────────────────────────────────────────

    /// Parse SSH known_hosts file. Returns Vec of (hostname, key_type).
    fn parse_ssh_known_hosts(path: &Path) -> Vec<(String, String)> {
        let mut results = Vec::new();

        let content = match read_text_gated(path) {
            Some(c) => c,
            None => return results,
        };

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let hostname = parts[0].to_string();
                let key_type = parts[1].to_string();
                results.push((hostname, key_type));
            }
        }

        results
    }

    // ─── SSH authorized_keys parsing ────────────────────────────────────

    /// Parse SSH authorized_keys file. Returns Vec of (key_type, comment).
    fn parse_ssh_authorized_keys(path: &Path) -> Vec<(String, String)> {
        let mut results = Vec::new();

        let content = match read_text_gated(path) {
            Some(c) => c,
            None => return results,
        };

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            // authorized_keys format: [options] keytype base64key [comment]
            // Key types start with "ssh-" or "ecdsa-" or "sk-"
            let (key_type, comment) = if parts[0].starts_with("ssh-")
                || parts[0].starts_with("ecdsa-")
                || parts[0].starts_with("sk-")
            {
                // No options prefix
                let kt = parts[0].to_string();
                let cmt = if parts.len() >= 3 {
                    parts[2..].join(" ")
                } else {
                    String::new()
                };
                (kt, cmt)
            } else {
                // Has options prefix — key type is next field
                if parts.len() >= 2 {
                    let kt = parts[1].to_string();
                    let cmt = if parts.len() >= 4 {
                        parts[3..].join(" ")
                    } else {
                        String::new()
                    };
                    (kt, cmt)
                } else {
                    continue;
                }
            };

            results.push((key_type, comment));
        }

        results
    }

    // ─── Entropy calculation ────────────────────────────────────────────

    /// Calculate Shannon entropy of a byte slice in bits per byte.
    /// Maximum value is 8.0 for uniformly distributed random data.
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let total = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    // ─── Windows Credential Manager (DPAPI) ──────────────────────────
    fn detect_credential_manager(path: &Path, _name: &str) -> Vec<Artifact> {
        let path_str = path.to_string_lossy();
        if path_str.contains("Microsoft\\Credentials") || path_str.contains("Microsoft/Credentials")
        {
            let mut artifact = Artifact::new("Windows Credential", &path_str);
            artifact.add_field("title", "DPAPI Credential Blob");
            artifact.add_field(
                "detail",
                "DPAPI encrypted credential blob found — type unknown without decryption key",
            );
            artifact.add_field("file_type", "Windows Credential");
            artifact.add_field("forensic_value", "Critical");
            artifact.add_field("mitre", "T1555");
            vec![artifact]
        } else {
            Vec::new()
        }
    }

    // ─── Remote Access Tools ────────────────────────────────────────────
    fn detect_remote_access(path: &Path, _name: &str) -> Vec<Artifact> {
        let path_str = path.to_string_lossy();
        let mut results = Vec::new();

        let checks: &[(&str, &str)] = &[
            ("TeamViewer", "TeamViewer Session"),
            ("AnyDesk", "AnyDesk Connection"),
            ("LogMeIn", "LogMeIn Session"),
        ];

        for (keyword, subcategory) in checks {
            if path_str.contains(keyword) {
                let mut artifact = Artifact::new(subcategory, &path_str);
                artifact.add_field("title", subcategory);
                artifact.add_field(
                    "detail",
                    &format!("{} artifact: {}", subcategory, path.display()),
                );
                artifact.add_field("file_type", subcategory);
                artifact.add_field("forensic_value", "Critical");
                artifact.add_field("mitre", "T1219");
                artifact.add_field("suspicious", "true");
                results.push(artifact);
                break;
            }
        }

        results
    }

    // ─── Cloud & Sync artifacts ─────────────────────────────────────────
    fn detect_cloud_sync(path: &Path, name: &str) -> Vec<Artifact> {
        let path_str = path.to_string_lossy();
        let lower_name = name.to_lowercase();
        let mut results = Vec::new();

        if path_str.contains("OneDrive") && (lower_name.contains("log") || lower_name.contains("sync")) {
            let mut artifact = Artifact::new("Cloud & Sync", &path_str);
            artifact.add_field("title", "OneDrive Sync Activity");
            artifact.add_field("subcategory", "OneDrive Sync Activity");
            artifact.add_field(
                "detail",
                &format!("OneDrive sync/log artifact: {}", path.display()),
            );
            artifact.add_field("file_type", "OneDrive Sync Activity");
            artifact.add_field("forensic_value", "High");
            artifact.add_field("mitre", "T1567.002");
            results.push(artifact);
        }

        if path_str.contains("Dropbox") {
            let mut artifact = Artifact::new("Cloud & Sync", &path_str);
            artifact.add_field("title", "Dropbox Sync Activity");
            artifact.add_field("subcategory", "Dropbox Sync Activity");
            artifact.add_field(
                "detail",
                &format!("Dropbox sync artifact: {}", path.display()),
            );
            artifact.add_field("file_type", "Dropbox Sync Activity");
            artifact.add_field("forensic_value", "High");
            artifact.add_field("mitre", "T1567.002");
            results.push(artifact);
        }

        if path_str.contains("Google/DriveFS") || path_str.contains("Google\\DriveFS") {
            let mut artifact = Artifact::new("Cloud & Sync", &path_str);
            artifact.add_field("title", "Google Drive Activity");
            artifact.add_field("subcategory", "Google Drive Activity");
            artifact.add_field(
                "detail",
                &format!("Google Drive sync artifact: {}", path.display()),
            );
            artifact.add_field("file_type", "Google Drive Activity");
            artifact.add_field("forensic_value", "High");
            artifact.add_field("mitre", "T1567.002");
            results.push(artifact);
        }

        results
    }

    // ─── FileZilla saved credentials ────────────────────────────────────
    fn detect_filezilla(path: &Path, name: &str) -> Vec<Artifact> {
        let lower_name = name.to_lowercase();
        if lower_name != "recentservers.xml" && lower_name != "sitemanager.xml" {
            return Vec::new();
        }

        let path_str = path.to_string_lossy();
        let content = match read_text_gated(path) {
            Some(c) => c,
            None => {
                // File unreadable — still record its presence
                let mut artifact = Artifact::new("FTP Saved Credential", &path_str);
                artifact.add_field("title", "FileZilla Credential File");
                artifact.add_field(
                    "detail",
                    &format!("FileZilla credential file (unreadable): {}", path.display()),
                );
                artifact.add_field("file_type", "FTP Saved Credential");
                artifact.add_field("forensic_value", "Critical");
                artifact.add_field("mitre", "T1552.001");
                return vec![artifact];
            }
        };

        let mut results = Vec::new();

        // Simple tag extraction: find all <Host>...</Host> and <User>...</User> pairs
        let hosts: Vec<&str> = content
            .match_indices("<Host>")
            .filter_map(|(start, _)| {
                let rest = &content[start + 6..];
                rest.find("</Host>").map(|end| &rest[..end])
            })
            .collect();

        let users: Vec<&str> = content
            .match_indices("<User>")
            .filter_map(|(start, _)| {
                let rest = &content[start + 6..];
                rest.find("</User>").map(|end| &rest[..end])
            })
            .collect();

        let count = hosts.len().max(users.len());
        if count == 0 {
            let mut artifact = Artifact::new("FTP Saved Credential", &path_str);
            artifact.add_field("title", "FileZilla Credential File");
            artifact.add_field(
                "detail",
                &format!("FileZilla credential file (no entries): {}", path.display()),
            );
            artifact.add_field("file_type", "FTP Saved Credential");
            artifact.add_field("forensic_value", "Critical");
            artifact.add_field("mitre", "T1552.001");
            results.push(artifact);
        } else {
            for i in 0..count {
                let host = hosts.get(i).unwrap_or(&"unknown");
                let user = users.get(i).unwrap_or(&"unknown");
                let mut artifact = Artifact::new("FTP Saved Credential", &path_str);
                artifact.add_field("title", &format!("FTP: {}@{}", user, host));
                artifact.add_field(
                    "detail",
                    &format!("FileZilla saved credential — host: {}, user: {}", host, user),
                );
                artifact.add_field("file_type", "FTP Saved Credential");
                artifact.add_field("forensic_value", "Critical");
                artifact.add_field("mitre", "T1552.001");
                results.push(artifact);
            }
        }

        results
    }

    // ─── WiFi profile XML full parse (FIX 7) ─────────────────────────
    fn parse_wifi_profile_xml(path: &Path, _name: &str, data: &[u8]) -> Vec<Artifact> {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        // Simple tag extractor helper
        fn extract_tag<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
            let open = format!("<{}>", tag);
            let close = format!("</{}>", tag);
            if let Some(start) = text.find(&open) {
                let rest = &text[start + open.len()..];
                if let Some(end) = rest.find(&close) {
                    return Some(&rest[..end]);
                }
            }
            None
        }

        let ssid = extract_tag(text, "name").unwrap_or("Unknown");
        let auth = extract_tag(text, "authentication").unwrap_or("Unknown");
        let encryption = extract_tag(text, "encryption").unwrap_or("Unknown");
        let key_type = extract_tag(text, "keyType").unwrap_or("");
        let conn_mode = extract_tag(text, "connectionMode").unwrap_or("");

        let password_stored = if key_type.eq_ignore_ascii_case("passPhrase") {
            "yes"
        } else {
            "no"
        };
        let auto_connect = if conn_mode.eq_ignore_ascii_case("auto") {
            "yes"
        } else {
            "no"
        };

        let path_str = path.to_string_lossy();
        let mut artifact = Artifact::new("WiFi Network Profile", &path_str);
        artifact.add_field("title", ssid);
        artifact.add_field(
            "detail",
            &format!(
                "SSID: {} | Auth: {} | Encryption: {} | Password stored: {} | Auto-connect: {} | Key: DPAPI encrypted on disk",
                ssid, auth, encryption, password_stored, auto_connect
            ),
        );
        artifact.add_field("file_type", "WiFi Network Profile");
        artifact.add_field("forensic_value", "High");
        artifact.add_field("mitre", "T1552.001");

        vec![artifact]
    }

    // ─── TeamViewer session log parse (FIX 8) ───────────────────────
    fn parse_teamviewer_connections(path: &Path, name: &str, path_str: &str) -> Vec<Artifact> {
        let lower_name = name.to_lowercase();
        let mut results = Vec::new();

        // Connection log files
        if lower_name == "connections_incoming.txt" || lower_name == "connections.txt" {
            let direction = if lower_name.contains("incoming") {
                "incoming"
            } else {
                "outgoing"
            };

            let content = match read_text_gated(path) {
                Some(c) => c,
                None => return results,
            };

            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let fields: Vec<&str> = trimmed.split('\t').collect();
                // Expected: [ID, DisplayName, Start, End, LocalUser, Country, Code]
                if fields.len() < 2 {
                    continue;
                }

                let id = fields[0].trim();
                let display_name = fields.get(1).map(|s| s.trim()).unwrap_or("unknown");
                let start = fields.get(2).map(|s| s.trim()).unwrap_or("unknown");
                let end = fields.get(3).map(|s| s.trim()).unwrap_or("unknown");
                let local_user = fields.get(4).map(|s| s.trim()).unwrap_or("unknown");

                let mut artifact = Artifact::new("TeamViewer Session", path_str);
                artifact.add_field(
                    "title",
                    &format!("TeamViewer: {} ({})", id, display_name),
                );
                artifact.add_field(
                    "detail",
                    &format!(
                        "Direction: {} | Partner: {} ({}) | Start: {} | End: {} | Local user: {}",
                        direction, id, display_name, start, end, local_user
                    ),
                );
                artifact.add_field("file_type", "TeamViewer Session");
                artifact.add_field("forensic_value", "Critical");
                artifact.add_field("suspicious", "true");
                artifact.add_field("mitre", "T1219");
                results.push(artifact);
            }

            return results;
        }

        // TeamViewer log files
        if lower_name.contains("teamviewer") && lower_name.ends_with("_logfile.log") {
            let mut artifact = Artifact::new("TeamViewer Log", path_str);
            artifact.add_field("title", &format!("TeamViewer Log: {}", name));
            artifact.add_field(
                "detail",
                "TeamViewer log file — may contain session details, partner IDs, timestamps",
            );
            artifact.add_field("file_type", "TeamViewer Log");
            artifact.add_field("forensic_value", "High");
            artifact.add_field("mitre", "T1219");
            results.push(artifact);
        }

        results
    }

    // ─── AnyDesk connection_trace.txt and ad.trace parsing ────────────
    fn parse_anydesk_trace(path: &Path, name: &str, path_str: &str) -> Vec<Artifact> {
        let lower_name = name.to_lowercase();
        let path_lower = path_str.to_lowercase();

        if !path_lower.contains("anydesk") {
            return Vec::new();
        }

        let mut results = Vec::new();

        // connection_trace.txt — pipe-delimited structured log
        if lower_name == "connection_trace.txt" {
            let content = match read_text_gated(path) {
                Some(c) => c,
                None => return results,
            };

            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let fields: Vec<&str> = trimmed.split('|').collect();
                let timestamp = fields.first().map(|s| s.trim()).unwrap_or("unknown");
                let direction = fields.get(1).map(|s| s.trim()).unwrap_or("unknown");
                let remote_id = fields.get(2).map(|s| s.trim()).unwrap_or("unknown");
                let remote_alias = fields.get(3).map(|s| s.trim()).unwrap_or("unknown");
                let local_user = fields.get(4).map(|s| s.trim()).unwrap_or("unknown");
                let duration = fields.get(5).map(|s| s.trim()).unwrap_or("unknown");

                let mut artifact = Artifact::new("AnyDesk Connection", path_str);
                artifact.add_field(
                    "title",
                    &format!("{} connection {} ({})", direction, remote_id, remote_alias),
                );
                artifact.add_field(
                    "detail",
                    &format!(
                        "Remote: {} ({}) | Direction: {} | Time: {} | Duration: {} | Local: {}",
                        remote_id, remote_alias, direction, timestamp, duration, local_user
                    ),
                );
                artifact.add_field("file_type", "AnyDesk Connection");
                artifact.add_field("forensic_value", "Critical");
                artifact.add_field("suspicious", "true");
                artifact.add_field("mitre", "T1219");
                results.push(artifact);
            }

            return results;
        }

        // ad.trace — free-form log, scan for connection events
        if lower_name == "ad.trace" {
            let content = match read_text_gated(path) {
                Some(c) => c,
                None => return results,
            };

            let event_count = content
                .lines()
                .filter(|l| {
                    let lower = l.to_lowercase();
                    lower.contains("logged in from") || lower.contains("connected to")
                })
                .count();

            if event_count > 0 {
                let mut artifact = Artifact::new("AnyDesk Connection", path_str);
                artifact.add_field(
                    "title",
                    &format!("AnyDesk Trace: {} connection events", event_count),
                );
                artifact.add_field(
                    "detail",
                    &format!(
                        "AnyDesk trace log found \u{2014} {} connection events detected",
                        event_count
                    ),
                );
                artifact.add_field("file_type", "AnyDesk Connection");
                artifact.add_field("forensic_value", "Critical");
                artifact.add_field("suspicious", "true");
                artifact.add_field("mitre", "T1219");
                results.push(artifact);
            }
        }

        results
    }

    /// Check whether a URL/hostname contains sensitive keywords.
    fn is_sensitive_url(url: &str) -> bool {
        let lower = url.to_lowercase();
        SENSITIVE_URL_KEYWORDS.iter().any(|kw| lower.contains(kw))
    }
}

impl StrataPlugin for CipherPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn supported_inputs(&self) -> Vec<String> {
        vec!["registry".to_string(), "config".to_string()]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Cipher
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::EncryptionAnalysis,
            PluginCapability::CredentialExtraction,
        ]
    }

    fn description(&self) -> &str {
        "Encryption analysis and credential extraction"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut results = Vec::new();

        if let Ok(entries) = walk_dir(root) {
            for entry_path in entries {
                if let Some((file_type, category)) = Self::classify_file(&entry_path) {
                    let lower_name = entry_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_lowercase();

                    match category {
                        // ── Saved Passwords (Chrome) ────────────────────
                        "Saved Passwords"
                            if lower_name == "login data" || lower_name == "web data" =>
                        {
                            let creds = Self::extract_chrome_credentials(&entry_path);
                            if creds.is_empty() {
                                // Fallback: still record the file even if DB is empty/locked
                                let mut artifact =
                                    Artifact::new(category, &entry_path.to_string_lossy());
                                artifact.add_field("title", file_type);
                                artifact.add_field(
                                    "detail",
                                    &format!("{}: {} (no rows extracted)", file_type, entry_path.display()),
                                );
                                artifact.add_field("file_type", file_type);
                                results.push(artifact);
                            } else {
                                for (url, username, detail, ts) in &creds {
                                    let mut artifact =
                                        Artifact::new(category, &entry_path.to_string_lossy());
                                    if let Some(t) = ts {
                                        artifact.timestamp = Some(*t as u64);
                                    }
                                    let title = format!("Chrome: {} — {}", username, url);
                                    artifact.add_field("title", &title);
                                    artifact.add_field("detail", detail);
                                    artifact.add_field("url", url);
                                    artifact.add_field("username", username);
                                    artifact.add_field("file_type", file_type);
                                    if Self::is_sensitive_url(url) {
                                        artifact.add_field("suspicious", "true");
                                    }
                                    results.push(artifact);
                                }
                            }
                        }

                        // ── Saved Passwords (Firefox) ───────────────────
                        "Saved Passwords" if lower_name == "logins.json" => {
                            let creds = Self::extract_firefox_credentials(&entry_path);
                            if creds.is_empty() {
                                let mut artifact =
                                    Artifact::new(category, &entry_path.to_string_lossy());
                                artifact.add_field("title", file_type);
                                artifact.add_field(
                                    "detail",
                                    &format!("{}: {} (no logins found)", file_type, entry_path.display()),
                                );
                                artifact.add_field("file_type", file_type);
                                results.push(artifact);
                            } else {
                                for (hostname, username, detail, ts) in &creds {
                                    let mut artifact =
                                        Artifact::new(category, &entry_path.to_string_lossy());
                                    if let Some(t) = ts {
                                        artifact.timestamp = Some(*t as u64);
                                    }
                                    let title =
                                        format!("Firefox: {} — {}", username, hostname);
                                    artifact.add_field("title", &title);
                                    artifact.add_field("detail", detail);
                                    artifact.add_field("url", hostname);
                                    artifact.add_field("username", username);
                                    artifact.add_field("file_type", file_type);
                                    if Self::is_sensitive_url(hostname) {
                                        artifact.add_field("suspicious", "true");
                                    }
                                    results.push(artifact);
                                }
                            }
                        }

                        // ── SSH known_hosts ─────────────────────────────
                        "SSH Keys" if lower_name == "known_hosts" => {
                            let hosts = Self::parse_ssh_known_hosts(&entry_path);
                            if hosts.is_empty() {
                                let mut artifact =
                                    Artifact::new(category, &entry_path.to_string_lossy());
                                artifact.add_field("title", file_type);
                                artifact.add_field(
                                    "detail",
                                    &format!("{}: {}", file_type, entry_path.display()),
                                );
                                artifact.add_field("file_type", file_type);
                                results.push(artifact);
                            } else {
                                for (hostname, key_type) in &hosts {
                                    let mut artifact =
                                        Artifact::new(category, &entry_path.to_string_lossy());
                                    let title = format!("SSH -> {}", hostname);
                                    let detail = format!(
                                        "Key type: {} | Host: {}",
                                        key_type, hostname
                                    );
                                    artifact.add_field("title", &title);
                                    artifact.add_field("detail", &detail);
                                    artifact.add_field("hostname", hostname);
                                    artifact.add_field("key_type", key_type);
                                    artifact.add_field("file_type", file_type);
                                    // Flag .onion hostnames
                                    if hostname.ends_with(".onion")
                                        || hostname.contains(".onion,")
                                    {
                                        artifact.add_field("suspicious", "true");
                                    }
                                    results.push(artifact);
                                }
                            }
                        }

                        // ── SSH authorized_keys ─────────────────────────
                        "SSH Keys" if lower_name == "authorized_keys" => {
                            let keys = Self::parse_ssh_authorized_keys(&entry_path);
                            if keys.is_empty() {
                                let mut artifact =
                                    Artifact::new(category, &entry_path.to_string_lossy());
                                artifact.add_field("title", file_type);
                                artifact.add_field(
                                    "detail",
                                    &format!("{}: {}", file_type, entry_path.display()),
                                );
                                artifact.add_field("file_type", file_type);
                                results.push(artifact);
                            } else {
                                for (key_type, comment) in &keys {
                                    let mut artifact =
                                        Artifact::new(category, &entry_path.to_string_lossy());
                                    let title = format!(
                                        "Authorized Key: {} {}",
                                        key_type,
                                        if comment.is_empty() {
                                            "(no comment)"
                                        } else {
                                            comment.as_str()
                                        }
                                    );
                                    let detail = format!(
                                        "Type: {} | Comment: {}",
                                        key_type,
                                        if comment.is_empty() {
                                            "(none)"
                                        } else {
                                            comment.as_str()
                                        }
                                    );
                                    artifact.add_field("title", &title);
                                    artifact.add_field("detail", &detail);
                                    artifact.add_field("key_type", key_type);
                                    artifact.add_field("comment", comment);
                                    artifact.add_field("file_type", file_type);

                                    // Flag forced commands (options contain command=)
                                    // We detect this by reading the original line
                                    // but since we already parsed, flag if comment
                                    // contains suspicious patterns
                                    if comment.contains("command=") {
                                        artifact.add_field("suspicious", "true");
                                    }
                                    results.push(artifact);
                                }
                            }
                        }

                        // ── Default: file-level artifact (SSH keys, certs, etc.) ──
                        _ => {
                            let mut artifact =
                                Artifact::new(category, &entry_path.to_string_lossy());
                            artifact.add_field("title", file_type);
                            artifact.add_field(
                                "detail",
                                &format!("{}: {}", file_type, entry_path.display()),
                            );
                            artifact.add_field("file_type", file_type);
                            results.push(artifact);
                        }
                    }
                } else {
                    // ── High-entropy detection for unrecognized large files ──
                    // Files > 512 KB with no recognized extension
                    if let Ok(meta) = entry_path.metadata() {
                        if meta.len() > 512 * 1024 {
                            let ext = entry_path
                                .extension()
                                .and_then(|e| e.to_str())
                                .unwrap_or("")
                                .to_lowercase();

                            // Skip common known extensions
                            let known_exts = [
                                "exe", "dll", "so", "dylib", "zip", "gz", "tar", "jpg",
                                "jpeg", "png", "gif", "bmp", "mp4", "avi", "mov", "pdf",
                                "doc", "docx", "xls", "xlsx",
                            ];
                            if !known_exts.contains(&ext.as_str()) {
                                // Read first 1 MB
                                if let Ok(mut file) = std::fs::File::open(&entry_path) {
                                    let mut buf = vec![0u8; 1_048_576];
                                    let bytes_read = file.read(&mut buf).unwrap_or_default();
                                    if bytes_read > 0 {
                                        let entropy =
                                            Self::calculate_entropy(&buf[..bytes_read]);
                                        if entropy > 7.9 {
                                            let mut artifact = Artifact::new(
                                                "Certificates",
                                                &entry_path.to_string_lossy(),
                                            );
                                            artifact.add_field(
                                                "title",
                                                "Encrypted Container (high entropy)",
                                            );
                                            artifact.add_field(
                                                "detail",
                                                &format!(
                                                    "Entropy: {:.2} bits/byte — likely encrypted | Size: {} bytes",
                                                    entropy,
                                                    meta.len()
                                                ),
                                            );
                                            artifact
                                                .add_field("file_type", "Encrypted Container");
                                            artifact.add_field("suspicious", "true");
                                            results.push(artifact);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // ── v2.0 path-based detectors ──────────────────────────────
                let file_name = entry_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");

                results.extend(Self::detect_credential_manager(&entry_path, file_name));
                results.extend(Self::detect_remote_access(&entry_path, file_name));
                results.extend(Self::detect_cloud_sync(&entry_path, file_name));
                results.extend(Self::detect_filezilla(&entry_path, file_name));

                // ── FIX 7: WiFi profile XML ──────────────────────────
                let path_str_check = entry_path.to_string_lossy();
                if (path_str_check.contains("Wlansvc/Profiles")
                    || path_str_check.contains("Wlansvc\\Profiles"))
                    && file_name.to_lowercase().ends_with(".xml")
                {
                    if let Ok(data) = std::fs::read(&entry_path) {
                        results.extend(Self::parse_wifi_profile_xml(
                            &entry_path,
                            file_name,
                            &data,
                        ));
                    }
                }

                // ── FIX 8: TeamViewer session logs ───────────────────
                results.extend(Self::parse_teamviewer_connections(
                    &entry_path,
                    file_name,
                    &path_str_check,
                ));

                // ── GAP 6: AnyDesk connection_trace.txt / ad.trace ──
                results.extend(Self::parse_anydesk_trace(
                    &entry_path,
                    file_name,
                    &path_str_check,
                ));
            }
        }

        Ok(results)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::new();

        for artifact in &artifacts {
            let file_type = artifact.data.get("file_type").cloned().unwrap_or_default();
            let category_str = artifact.category.clone();
            let is_suspicious = artifact
                .data
                .get("suspicious")
                .map(|v| v == "true")
                .unwrap_or(false);

            let (category, subcategory, forensic_value, mitre) = match category_str.as_str() {
                "Saved Passwords" => (
                    ArtifactCategory::AccountsCredentials,
                    "Saved Browser Password".to_string(),
                    if is_suspicious {
                        ForensicValue::Critical
                    } else {
                        ForensicValue::High
                    },
                    Some("T1555.003".to_string()),
                ),
                "SSH Keys" => (
                    ArtifactCategory::EncryptionKeyMaterial,
                    "SSH Keys".to_string(),
                    if is_suspicious {
                        ForensicValue::Critical
                    } else {
                        ForensicValue::High
                    },
                    Some("T1021.004".to_string()),
                ),
                "Certificates" => (
                    ArtifactCategory::EncryptionKeyMaterial,
                    if file_type == "Encrypted Container" {
                        "Encrypted Container".to_string()
                    } else {
                        "Certificate".to_string()
                    },
                    if is_suspicious {
                        ForensicValue::Critical
                    } else {
                        ForensicValue::High
                    },
                    None,
                ),
                "Windows Credential" => (
                    ArtifactCategory::AccountsCredentials,
                    "Windows Credential".to_string(),
                    ForensicValue::Critical,
                    Some("T1555".to_string()),
                ),
                "TeamViewer Session" | "AnyDesk Connection" | "LogMeIn Session" => (
                    ArtifactCategory::AccountsCredentials,
                    category_str.clone(),
                    ForensicValue::Critical,
                    Some("T1219".to_string()),
                ),
                "TeamViewer Log" => (
                    ArtifactCategory::AccountsCredentials,
                    "TeamViewer Log".to_string(),
                    ForensicValue::High,
                    Some("T1219".to_string()),
                ),
                "Cloud & Sync" => {
                    let subcategory = artifact
                        .data
                        .get("subcategory")
                        .cloned()
                        .unwrap_or_else(|| "Cloud Sync Activity".to_string());
                    (
                        ArtifactCategory::CloudSync,
                        subcategory,
                        ForensicValue::High,
                        Some("T1567.002".to_string()),
                    )
                }
                "FTP Saved Credential" => (
                    ArtifactCategory::AccountsCredentials,
                    "FTP Saved Credential".to_string(),
                    ForensicValue::Critical,
                    Some("T1552.001".to_string()),
                ),
                "WiFi Network Profile" => (
                    ArtifactCategory::AccountsCredentials,
                    "WiFi Network Profile".to_string(),
                    ForensicValue::High,
                    Some("T1552.001".to_string()),
                ),
                _ => (
                    ArtifactCategory::AccountsCredentials,
                    file_type.clone(),
                    ForensicValue::Medium,
                    None,
                ),
            };

            records.push(ArtifactRecord {
                category,
                subcategory,
                timestamp: artifact.timestamp.map(|t| t as i64),
                title: artifact
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| artifact.source.clone()),
                detail: artifact
                    .data
                    .get("detail")
                    .cloned()
                    .unwrap_or_default(),
                source_path: artifact.source.clone(),
                forensic_value,
                mitre_technique: mitre,
                is_suspicious,
                raw_data: None,
            });
        }

        let suspicious_count = records.iter().filter(|r| r.is_suspicious).count();
        let categories: Vec<String> = records
            .iter()
            .map(|r| r.category.as_str().to_string())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records.clone(),
            summary: PluginSummary {
                total_artifacts: records.len(),
                suspicious_count,
                categories_populated: categories,
                headline: format!(
                    "Cipher analysis: {} credential/key artifacts found ({} suspicious)",
                    records.len(),
                    suspicious_count
                ),
            },
            warnings: vec![],
        })
    }
}

use strata_plugin_sdk::PluginError;

fn walk_dir(dir: &Path) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let mut paths = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if let Ok(sub) = walk_dir(&path) {
                    paths.extend(sub);
                }
            } else {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

#[no_mangle]
pub extern "C" fn create_plugin_cipher() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(CipherPlugin::new());
    let plugin_holder = Box::new(plugin);
    Box::into_raw(plugin_holder) as *mut std::ffi::c_void
}
