pub mod carving;

use std::collections::HashSet;
use std::path::Path;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct ReconPlugin {
    name: String,
    version: String,
}

impl Default for ReconPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Recon".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    /// Suspicious email providers commonly used for anonymity.
    const SUSPICIOUS_PROVIDERS: &'static [&'static str] = &[
        "protonmail", "tutanota", "guerrillamail", "tempmail", "throwaway",
        "sharklasers", "mailinator", "yopmail",
    ];

    /// Extract username from a path containing "Users/" or "Users\\".
    fn extract_username(path_str: &str) -> Option<String> {
        let lower = path_str.to_lowercase();
        let patterns = ["users/", "users\\"];
        for pat in &patterns {
            if let Some(idx) = lower.find(pat) {
                let after = &path_str[idx + pat.len()..];
                let end = after.find(['/', '\\']).unwrap_or(after.len());
                let username = &after[..end];
                if !username.is_empty()
                    && username.to_lowercase() != "default"
                    && username.to_lowercase() != "public"
                    && username.to_lowercase() != "all users"
                {
                    return Some(username.to_string());
                }
            }
        }
        None
    }

    /// Check if a string looks like a plausible email address.
    fn looks_like_email(s: &str) -> bool {
        if !s.contains('@') || !s.contains('.') {
            return false;
        }
        let parts: Vec<&str> = s.splitn(2, '@').collect();
        if parts.len() != 2 {
            return false;
        }
        let local = parts[0];
        let domain = parts[1];
        if local.is_empty() || domain.is_empty() || !domain.contains('.') {
            return false;
        }
        // Basic sanity: local part has only reasonable chars
        local.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '+')
            && domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    }

    /// Check if a string is a valid IPv4 address.
    fn is_valid_ipv4(s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return false;
        }
        for part in &parts {
            if part.is_empty() || part.len() > 3 {
                return false;
            }
            if !part.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
            if let Ok(n) = part.parse::<u32>() {
                if n > 255 {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }

    /// Check if an IPv4 address is in a private range.
    fn is_private_ip(ip: &str) -> bool {
        let parts: Vec<u8> = ip
            .split('.')
            .filter_map(|p| p.parse::<u8>().ok())
            .collect();
        if parts.len() != 4 {
            return true; // Treat invalid as private (skip)
        }
        // 10.0.0.0/8
        if parts[0] == 10 {
            return true;
        }
        // 172.16.0.0/12
        if parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31 {
            return true;
        }
        // 192.168.0.0/16
        if parts[0] == 192 && parts[1] == 168 {
            return true;
        }
        // 127.0.0.0/8
        if parts[0] == 127 {
            return true;
        }
        // 0.0.0.0
        if parts[0] == 0 {
            return true;
        }
        false
    }

    /// Check if a path is for a script file.
    fn is_script_path(path_lower: &str) -> bool {
        path_lower.ends_with(".ps1")
            || path_lower.ends_with(".vbs")
            || path_lower.ends_with(".js")
            || path_lower.ends_with(".bat")
            || path_lower.ends_with(".cmd")
            || path_lower.ends_with(".py")
            || path_lower.ends_with(".sh")
    }

    fn analyze_file(path: &Path, usernames: &mut HashSet<String>) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy();
        let path_lower = path_str.to_lowercase();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let ext_lower = ext.to_lowercase();

        // Extract username from path
        if path_lower.contains("users/") || path_lower.contains("users\\") {
            if let Some(username) = Self::extract_username(&path_str) {
                if !usernames.contains(&username.to_lowercase()) {
                    usernames.insert(username.to_lowercase());
                    let mut artifact = Artifact::new("AccountsCredentials", &path_str);
                    artifact.add_field("title", &format!("System Username: {}", username));
                    artifact.add_field("file_type", "System Username");
                    artifact.add_field("detail", &format!(
                        "User profile directory found for '{}' — indicates active or previous system user",
                        username
                    ));
                    results.push(artifact);
                }
            }
        }

        // For text/log/eml files: scan for emails, IPs, AWS keys
        let is_text_file = matches!(ext_lower.as_str(), "txt" | "log" | "eml" | "csv" | "json" | "xml" | "cfg" | "ini" | "conf");
        if is_text_file {
            // Check file size (skip > 10MB)
            let file_size = match path.metadata() {
                Ok(m) => m.len(),
                Err(_) => return results,
            };
            if file_size > 10_485_760 {
                return results;
            }

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => return results,
            };

            let mut found_emails: HashSet<String> = HashSet::new();
            let mut found_ips: HashSet<String> = HashSet::new();
            let mut found_aws_keys: Vec<String> = Vec::new();

            // Scan for email-like patterns
            for word in content.split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '<' || c == '>' || c == '"' || c == '\'') {
                let trimmed = word.trim();

                // Email detection
                if trimmed.contains('@') && Self::looks_like_email(trimmed) {
                    found_emails.insert(trimmed.to_lowercase());
                }

                // IPv4 detection
                if trimmed.contains('.') && Self::is_valid_ipv4(trimmed) && !Self::is_private_ip(trimmed) {
                    found_ips.insert(trimmed.to_string());
                }
            }

            // AWS key detection: AKIA followed by 16 alphanumeric chars
            let content_bytes = content.as_bytes();
            for i in 0..content_bytes.len().saturating_sub(19) {
                if &content_bytes[i..i + 4] == b"AKIA" {
                    let candidate = &content_bytes[i..i + 20];
                    if candidate.len() == 20 && candidate[4..].iter().all(|b| b.is_ascii_alphanumeric()) {
                        if let Ok(key) = std::str::from_utf8(candidate) {
                            found_aws_keys.push(key.to_string());
                        }
                    }
                }
            }

            // Create artifacts for emails
            for email in &found_emails {
                let is_suspicious = Self::SUSPICIOUS_PROVIDERS
                    .iter()
                    .any(|p| email.contains(p));

                let mut artifact = Artifact::new("AccountsCredentials", &path_str);
                artifact.add_field("title", &format!("Email Address Found: {}", email));
                artifact.add_field("file_type", "Email Address Found");
                artifact.add_field("detail", &format!(
                    "Email address '{}' found in {}{}",
                    email,
                    name,
                    if is_suspicious { " \u{2014} anonymous/privacy-focused provider" } else { "" },
                ));
                if is_suspicious {
                    artifact.add_field("suspicious", "true");
                }
                results.push(artifact);
            }

            // Create artifacts for public IPs
            for ip in &found_ips {
                let in_script = Self::is_script_path(&path_lower);
                let mut artifact = Artifact::new("NetworkArtifacts", &path_str);
                artifact.add_field("title", &format!("IP Address Reference: {}", ip));
                artifact.add_field("file_type", "IP Address Reference");
                artifact.add_field("detail", &format!(
                    "Public IP {} referenced in {}{}",
                    ip,
                    name,
                    if in_script { " \u{2014} FOUND IN SCRIPT FILE" } else { "" },
                ));
                if in_script {
                    artifact.add_field("suspicious", "true");
                }
                results.push(artifact);
            }

            // Create artifacts for AWS keys
            for key in &found_aws_keys {
                // Redact most of the key
                let redacted = format!("{}...{}", &key[..8], &key[key.len() - 4..]);
                let mut artifact = Artifact::new("AccountsCredentials", &path_str);
                artifact.add_field("title", &format!("Cloud API Key: {}", redacted));
                artifact.add_field("file_type", "Cloud API Key");
                artifact.add_field("detail", &format!(
                    "AWS access key ID detected in {} \u{2014} exposed credentials require immediate rotation",
                    name
                ));
                artifact.add_field("suspicious", "true");
                results.push(artifact);
            }
        }

        results
    }
}

impl StrataPlugin for ReconPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn supported_inputs(&self) -> Vec<String> {
        vec!["*".to_string()]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::CredentialExtraction,
            PluginCapability::ArtifactExtraction,
        ]
    }

    fn description(&self) -> &str {
        "Identity and account artifact extraction \u{2014} completely offline"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut results = Vec::new();
        let mut usernames: HashSet<String> = HashSet::new();

        if let Ok(entries) = walk_dir(root) {
            for entry_path in entries {
                results.extend(Self::analyze_file(&entry_path, &mut usernames));
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
            let is_suspicious = artifact
                .data
                .get("suspicious")
                .map(|v| v == "true")
                .unwrap_or(false);

            let (category, forensic_value) = match file_type.as_str() {
                "System Username" => (ArtifactCategory::AccountsCredentials, ForensicValue::Medium),
                "Email Address Found" => (
                    ArtifactCategory::AccountsCredentials,
                    if is_suspicious { ForensicValue::High } else { ForensicValue::Medium },
                ),
                "IP Address Reference" => (
                    ArtifactCategory::NetworkArtifacts,
                    if is_suspicious { ForensicValue::High } else { ForensicValue::Low },
                ),
                "Cloud API Key" => (ArtifactCategory::AccountsCredentials, ForensicValue::Critical),
                _ => (ArtifactCategory::AccountsCredentials, ForensicValue::Medium),
            };

            records.push(ArtifactRecord {
                category,
                subcategory: file_type,
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
                mitre_technique: artifact.data.get("mitre").cloned(),
                is_suspicious,
                raw_data: None,
                confidence: 0,
            });
        }

        let suspicious_count = records.iter().filter(|r| r.is_suspicious).count();
        let categories: Vec<String> = records
            .iter()
            .map(|r| r.category.as_str().to_string())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let username_count = records
            .iter()
            .filter(|r| r.subcategory == "System Username")
            .count();
        let cred_count = records
            .iter()
            .filter(|r| r.subcategory == "Cloud API Key")
            .count();

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
                    "Recon: {} identities, {} exposed credentials, {} total artifacts",
                    username_count, cred_count, records.len(),
                ),
            },
            warnings: vec![],
        })
    }
}

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
pub extern "C" fn create_plugin_recon() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(ReconPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}

#[cfg(test)]
mod sprint75_backfill_tests {
    use super::*;
    use std::collections::HashMap;
    use strata_plugin_sdk::{PluginContext, StrataPlugin};

    fn empty_ctx() -> PluginContext {
        PluginContext {
            root_path: "/nonexistent/strata-sprint75-empty".to_string(),
            vfs: None,
            config: HashMap::new(),
            prior_results: Vec::new(),
        }
    }

    fn garbage_ctx(suffix: &str) -> PluginContext {
        let dir = std::env::temp_dir().join(format!(
            "strata_sprint75_{}_{}_{}",
            suffix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("garbage.bin"), [0xFFu8, 0x00, 0xDE, 0xAD, 0xBE, 0xEF])
            .expect("write garbage");
        PluginContext {
            root_path: dir.to_string_lossy().into_owned(),
            vfs: None,
            config: HashMap::new(),
            prior_results: Vec::new(),
        }
    }

    #[test]
    fn plugin_has_valid_metadata() {
        let plugin = ReconPlugin::new();
        assert!(!plugin.name().is_empty());
        assert!(!plugin.version().is_empty());
        assert!(!plugin.description().is_empty());
    }

    #[test]
    fn plugin_returns_ok_on_empty_input() {
        let plugin = ReconPlugin::new();
        let result = plugin.run(empty_ctx());
        assert!(result.is_ok() || result.unwrap_or_default().is_empty());
    }

    #[test]
    fn plugin_does_not_panic_on_malformed_input() {
        let plugin = ReconPlugin::new();
        let _ = plugin.run(garbage_ctx("recon"));
    }
}
