use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

pub struct AndroidKeystoreParser;

impl AndroidKeystoreParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AndroidCredentialEntry {
    pub artifact_kind: String,
    pub lock_screen_type: Option<String>,
    pub key_alias: Option<String>,
    pub hardware_backed: Option<bool>,
    pub encryption_state: Option<String>,
    pub encryption_type: Option<String>,
    pub user_id: Option<String>,
    pub wifi_ssid: Option<String>,
    pub wifi_psk: Option<String>,
    pub notes: Option<String>,
}

impl Default for AndroidKeystoreParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for AndroidKeystoreParser {
    fn name(&self) -> &str {
        "Android Keystore & Credential Storage"
    }

    fn artifact_type(&self) -> &str {
        "android_keystore"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "misc/keystore",
            "misc/gatekeeper",
            "misc/vold",
            "locksettings",
            "wificonfigstore",
            "wpa_supplicant",
            "misc/wifi",
            "wifi_config",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_string();
        let path_lower = path_str.to_ascii_lowercase();

        parse_gatekeeper(path, &path_lower, data, &mut artifacts);
        parse_keystore_aliases(path, &path_lower, data, &mut artifacts);
        parse_vold(path, &path_lower, data, &mut artifacts);
        parse_wifi(path, &path_lower, data, &mut artifacts);

        dedupe_artifacts(&mut artifacts);
        Ok(artifacts)
    }
}

fn parse_gatekeeper(path: &Path, path_lower: &str, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    if !path_lower.contains("gatekeeper") && !path_lower.contains("locksettings") {
        return;
    }

    let lock_type = infer_lock_type(path_lower, data);
    let entry = AndroidCredentialEntry {
        artifact_kind: "gatekeeper".to_string(),
        lock_screen_type: lock_type.clone(),
        key_alias: None,
        hardware_backed: Some(path_lower.contains("gatekeeper")),
        encryption_state: None,
        encryption_type: None,
        user_id: extract_user_id(path_lower),
        wifi_ssid: None,
        wifi_psk: None,
        notes: Some(format!("len={} bytes", data.len())),
    };
    out.push(ParsedArtifact {
        timestamp: None,
        artifact_type: "android_keystore".to_string(),
        description: format!(
            "Gatekeeper credential data ({})",
            lock_type.unwrap_or_else(|| "unknown".to_string())
        ),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    });
}

fn parse_keystore_aliases(
    path: &Path,
    path_lower: &str,
    data: &[u8],
    out: &mut Vec<ParsedArtifact>,
) {
    if !path_lower.contains("keystore") {
        return;
    }

    let mut aliases = HashSet::new();
    if let Some(file_alias) = path.file_name().and_then(|v| v.to_str()) {
        let trimmed = file_alias.trim().trim_matches('"');
        if is_reasonable_alias(trimmed) {
            aliases.insert(trimmed.to_string());
        }
    }

    let text = String::from_utf8_lossy(data);
    let alias_re = match Regex::new(r"(?:alias|name|key_alias)\s*[:=]\s*([A-Za-z0-9._:-]{3,128})") {
        Ok(r) => r,
        Err(_) => return,
    };
    for cap in alias_re.captures_iter(&text).take(200) {
        if let Some(v) = cap.get(1).map(|m| m.as_str()) {
            if is_reasonable_alias(v) {
                aliases.insert(v.to_string());
            }
        }
    }

    for alias in aliases {
        let entry = AndroidCredentialEntry {
            artifact_kind: "keystore_alias".to_string(),
            lock_screen_type: None,
            key_alias: Some(alias.clone()),
            hardware_backed: Some(
                path_lower.contains("/misc/keystore") || path_lower.contains("\\misc\\keystore"),
            ),
            encryption_state: None,
            encryption_type: None,
            user_id: extract_user_id(path_lower),
            wifi_ssid: None,
            wifi_psk: None,
            notes: None,
        };
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "android_keystore".to_string(),
            description: format!("Keystore alias {}", alias),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_vold(path: &Path, path_lower: &str, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    if !path_lower.contains("vold") && !path_lower.contains("fstab") {
        return;
    }

    let text = String::from_utf8_lossy(data);
    let encryption_state = extract_prop(&text, &["ro.crypto.state", "vold.decrypt"]);
    let encryption_type = extract_prop(
        &text,
        &[
            "ro.crypto.type",
            "fileencryption",
            "forcefdeorfbe",
            "encryptable",
        ],
    )
    .or_else(|| infer_encryption_type(&text));

    let entry = AndroidCredentialEntry {
        artifact_kind: "vold_encryption".to_string(),
        lock_screen_type: None,
        key_alias: None,
        hardware_backed: None,
        encryption_state,
        encryption_type,
        user_id: extract_user_id(path_lower),
        wifi_ssid: None,
        wifi_psk: None,
        notes: Some("Parsed vold/fstab encryption directives".to_string()),
    };

    out.push(ParsedArtifact {
        timestamp: None,
        artifact_type: "android_keystore".to_string(),
        description: "Vold / device encryption settings".to_string(),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    });
}

fn parse_wifi(path: &Path, path_lower: &str, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    if !(path_lower.contains("wifi")
        || path_lower.contains("wificonfigstore")
        || path_lower.contains("wpa_supplicant"))
    {
        return;
    }

    let text = String::from_utf8_lossy(data);
    parse_wifi_config_store(path, &text, out);
    parse_wpa_supplicant(path, &text, out);
}

fn parse_wifi_config_store(path: &Path, text: &str, out: &mut Vec<ParsedArtifact>) {
    if !text.contains("WifiConfiguration") && !text.contains("NetworkList") {
        return;
    }

    let ssid_re = match Regex::new(r#"<string name="SSID">"?([^"<]+)"?</string>"#) {
        Ok(r) => r,
        Err(_) => return,
    };
    let psk_re = match Regex::new(r#"<string name="PreSharedKey">"?([^"<]+)"?</string>"#) {
        Ok(r) => r,
        Err(_) => return,
    };

    let ssids: Vec<String> = ssid_re
        .captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim_matches('"').to_string()))
        .collect();
    let psks: Vec<String> = psk_re
        .captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim_matches('"').to_string()))
        .collect();

    for (idx, ssid) in ssids.iter().enumerate().take(200) {
        let psk = psks.get(idx).cloned();
        let entry = AndroidCredentialEntry {
            artifact_kind: "wifi_credential".to_string(),
            lock_screen_type: None,
            key_alias: None,
            hardware_backed: None,
            encryption_state: None,
            encryption_type: Some("WPA/WPA2".to_string()),
            user_id: None,
            wifi_ssid: Some(ssid.clone()),
            wifi_psk: psk.clone(),
            notes: Some("Recovered from WifiConfigStore XML".to_string()),
        };
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "android_keystore".to_string(),
            description: format!("Wi-Fi credential {}", ssid),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_wpa_supplicant(path: &Path, text: &str, out: &mut Vec<ParsedArtifact>) {
    if !text.contains("network={") {
        return;
    }

    for block in text.split("network={").skip(1).take(500) {
        let ssid = extract_quoted_value(block, "ssid");
        let psk = extract_quoted_value(block, "psk");
        if ssid.is_none() && psk.is_none() {
            continue;
        }
        let entry = AndroidCredentialEntry {
            artifact_kind: "wifi_credential".to_string(),
            lock_screen_type: None,
            key_alias: None,
            hardware_backed: None,
            encryption_state: None,
            encryption_type: extract_raw_value(block, "key_mgmt"),
            user_id: None,
            wifi_ssid: ssid.clone(),
            wifi_psk: psk.clone(),
            notes: Some("Recovered from wpa_supplicant".to_string()),
        };
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "android_keystore".to_string(),
            description: format!(
                "Wi-Fi credential {}",
                ssid.unwrap_or_else(|| "unknown".to_string())
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn infer_lock_type(path_lower: &str, data: &[u8]) -> Option<String> {
    if path_lower.contains("pattern") || path_lower.contains("gesture") {
        return Some("pattern".to_string());
    }
    if path_lower.contains("password") {
        return Some("password".to_string());
    }
    if path_lower.contains("pin") {
        return Some("pin".to_string());
    }

    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    if text.contains("password_type=131072") || text.contains("password_quality_numeric") {
        return Some("pin".to_string());
    }
    if text.contains("password_type=65536") || text.contains("password_quality_something") {
        return Some("pattern".to_string());
    }
    if text.contains("password_type") {
        return Some("password".to_string());
    }
    None
}

fn extract_user_id(path_lower: &str) -> Option<String> {
    let marker = "user_";
    let idx = path_lower.find(marker)?;
    let tail = &path_lower[idx + marker.len()..];
    let mut digits = String::new();
    for ch in tail.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else {
            break;
        }
    }
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

fn extract_prop(text: &str, keys: &[&str]) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        for key in keys {
            if line.starts_with(key) {
                if let Some(eq) = line.find('=') {
                    return Some(line[eq + 1..].trim().to_string());
                }
                if let Some(colon) = line.find(':') {
                    return Some(line[colon + 1..].trim().to_string());
                }
            }
        }
    }
    None
}

fn infer_encryption_type(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("fileencryption=") || lower.contains("wrappedkey_v0") {
        Some("FBE".to_string())
    } else if lower.contains("forceencrypt") || lower.contains("encryptable") {
        Some("FDE".to_string())
    } else {
        None
    }
}

fn extract_quoted_value(block: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = block.find(&needle)?;
    let rest = &block[start + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_raw_value(block: &str, key: &str) -> Option<String> {
    for line in block.lines() {
        let trimmed = line.trim();
        if let Some(stripped) = trimmed.strip_prefix(&format!("{key}=")) {
            return Some(stripped.trim().to_string());
        }
    }
    None
}

fn is_reasonable_alias(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
}

fn dedupe_artifacts(artifacts: &mut Vec<ParsedArtifact>) {
    let mut seen = HashSet::new();
    artifacts.retain(|artifact| {
        let key = format!(
            "{}|{}|{}|{}",
            artifact.artifact_type, artifact.description, artifact.source_path, artifact.json_data
        );
        seen.insert(key)
    });
}
