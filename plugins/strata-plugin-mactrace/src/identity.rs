//! macOS identity and credential metadata collectors.
//!
//! These routines intentionally avoid secret extraction. Keychain hits
//! report database presence and file metadata only; user account hits
//! read dslocal account plist attributes that identify local accounts.

use chrono::{DateTime, Utc};
use plist::Value;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacosUserAccount {
    pub username: String,
    pub real_name: Option<String>,
    pub uid: Option<String>,
    pub gid: Option<String>,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub generated_uid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeychainMetadata {
    pub keychain_type: &'static str,
    pub owner_hint: Option<String>,
    pub size: Option<u64>,
    pub modified_utc: Option<DateTime<Utc>>,
}

pub fn parse_user_account(path: &Path) -> Option<MacosUserAccount> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if !lower.contains("/var/db/dslocal/nodes/default/users/")
        || !lower.ends_with(".plist")
        || lower.ends_with("/root.plist")
        || lower.ends_with("/daemon.plist")
        || lower.ends_with("/nobody.plist")
    {
        return None;
    }

    let value = Value::from_file(path).ok()?;
    let dict = value.as_dictionary()?;
    let username = first_string(dict.get("name"))
        .or_else(|| first_string(dict.get("RecordName")))
        .or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(ToOwned::to_owned)
        })?;

    Some(MacosUserAccount {
        username,
        real_name: first_string(dict.get("realname"))
            .or_else(|| first_string(dict.get("RealName"))),
        uid: first_string(dict.get("uid")).or_else(|| first_string(dict.get("UniqueID"))),
        gid: first_string(dict.get("gid")).or_else(|| first_string(dict.get("PrimaryGroupID"))),
        home: first_string(dict.get("home")).or_else(|| first_string(dict.get("NFSHomeDirectory"))),
        shell: first_string(dict.get("shell")).or_else(|| first_string(dict.get("UserShell"))),
        generated_uid: first_string(dict.get("generateduid"))
            .or_else(|| first_string(dict.get("GeneratedUID"))),
    })
}

pub fn detect_keychain(path: &Path) -> Option<KeychainMetadata> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    let is_keychain = name.ends_with(".keychain")
        || name.ends_with(".keychain-db")
        || (name == "keychain-2.db" && lower.contains("/local items/"));
    if !is_keychain || !lower.contains("keychain") {
        return None;
    }

    let keychain_type = if lower.contains("/system/library/keychains/") {
        "System Keychain"
    } else if lower.contains("/library/keychains/") && !lower.contains("/users/") {
        "Local Machine Keychain"
    } else if lower.contains("/local items/") {
        "Local Items Keychain"
    } else {
        "User Login Keychain"
    };

    let metadata = std::fs::metadata(path).ok();
    let modified_utc = metadata
        .as_ref()
        .and_then(|m| m.modified().ok())
        .map(DateTime::<Utc>::from);

    Some(KeychainMetadata {
        keychain_type,
        owner_hint: owner_from_path(path),
        size: metadata.as_ref().map(|m| m.len()),
        modified_utc,
    })
}

fn first_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Array(values) => values.iter().find_map(|v| match v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        }),
        Value::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

fn owner_from_path(path: &Path) -> Option<String> {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    parts
        .windows(2)
        .find(|w| w[0].eq_ignore_ascii_case("users"))
        .map(|w| w[1].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_account_reads_dslocal_plist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let users_dir = dir.path().join("var/db/dslocal/nodes/Default/users");
        std::fs::create_dir_all(&users_dir).expect("mkdir");
        let path = users_dir.join("alice.plist");

        let mut dict = plist::Dictionary::new();
        dict.insert(
            "name".into(),
            Value::Array(vec![Value::String("alice".into())]),
        );
        dict.insert(
            "realname".into(),
            Value::Array(vec![Value::String("Alice Example".into())]),
        );
        dict.insert(
            "uid".into(),
            Value::Array(vec![Value::String("501".into())]),
        );
        dict.insert(
            "home".into(),
            Value::Array(vec![Value::String("/Users/alice".into())]),
        );
        Value::Dictionary(dict)
            .to_file_xml(&path)
            .expect("write plist");

        let account = parse_user_account(&path).expect("account");
        assert_eq!(account.username, "alice");
        assert_eq!(account.real_name.as_deref(), Some("Alice Example"));
        assert_eq!(account.uid.as_deref(), Some("501"));
        assert_eq!(account.home.as_deref(), Some("/Users/alice"));
    }

    #[test]
    fn detect_keychain_reports_metadata_without_secrets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keychains = dir.path().join("Users/alice/Library/Keychains");
        std::fs::create_dir_all(&keychains).expect("mkdir");
        let path = keychains.join("login.keychain-db");
        std::fs::write(&path, b"metadata only").expect("write keychain");

        let meta = detect_keychain(&path).expect("keychain");
        assert_eq!(meta.keychain_type, "User Login Keychain");
        assert_eq!(meta.owner_hint.as_deref(), Some("alice"));
        assert_eq!(meta.size, Some(13));
        assert!(meta.modified_utc.is_some());
    }
}
