//! macOS identity and credential metadata collectors.
//!
//! These routines intentionally avoid secret extraction. Keychain hits
//! report database presence and file metadata only; user account hits
//! read dslocal account plist attributes that identify local accounts.

use chrono::{DateTime, Utc};
use plist::Value;
use rusqlite::types::ValueRef;
use rusqlite::Connection;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeychainEntry {
    pub table: String,
    pub label: Option<String>,
    pub service: Option<String>,
    pub account: Option<String>,
    pub server: Option<String>,
    pub protocol: Option<String>,
    pub auth_type: Option<String>,
    pub port: Option<i64>,
    pub url_path: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial_number: Option<String>,
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub access_group: Option<String>,
    pub icloud_synced: bool,
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

pub fn parse_keychain_entries(path: &Path) -> Vec<KeychainEntry> {
    let Ok(conn) = Connection::open(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_genp_entries(&conn));
    out.extend(parse_inet_entries(&conn));
    out.extend(parse_cert_entries(&conn));
    out
}

fn parse_genp_entries(conn: &Connection) -> Vec<KeychainEntry> {
    query_keychain_table(
        conn,
        "genp",
        &["labl", "svce", "acct", "cdat", "mdat", "agrp", "sync"],
        |values| KeychainEntry {
            table: "genp".to_string(),
            label: values.get("labl").cloned(),
            service: values.get("svce").cloned(),
            account: values.get("acct").cloned(),
            server: None,
            protocol: None,
            auth_type: None,
            port: None,
            url_path: None,
            subject: None,
            issuer: None,
            serial_number: None,
            created_utc: values.get("cdat").and_then(|v| parse_keychain_time(v)),
            modified_utc: values.get("mdat").and_then(|v| parse_keychain_time(v)),
            access_group: values.get("agrp").cloned(),
            icloud_synced: values.get("sync").map(|v| v == "1").unwrap_or(false),
        },
    )
}

fn parse_inet_entries(conn: &Connection) -> Vec<KeychainEntry> {
    query_keychain_table(
        conn,
        "inet",
        &[
            "labl", "srvr", "ptcl", "atyp", "port", "path", "acct", "cdat", "mdat",
        ],
        |values| KeychainEntry {
            table: "inet".to_string(),
            label: values.get("labl").cloned(),
            service: None,
            account: values.get("acct").cloned(),
            server: values.get("srvr").cloned(),
            protocol: values.get("ptcl").cloned(),
            auth_type: values.get("atyp").cloned(),
            port: values.get("port").and_then(|v| v.parse::<i64>().ok()),
            url_path: values.get("path").cloned(),
            subject: None,
            issuer: None,
            serial_number: None,
            created_utc: values.get("cdat").and_then(|v| parse_keychain_time(v)),
            modified_utc: values.get("mdat").and_then(|v| parse_keychain_time(v)),
            access_group: None,
            icloud_synced: false,
        },
    )
}

fn parse_cert_entries(conn: &Connection) -> Vec<KeychainEntry> {
    query_keychain_table(
        conn,
        "cert",
        &["subj", "issr", "slnr", "cdat", "mdat"],
        |values| KeychainEntry {
            table: "cert".to_string(),
            label: None,
            service: None,
            account: None,
            server: None,
            protocol: None,
            auth_type: None,
            port: None,
            url_path: None,
            subject: values.get("subj").cloned(),
            issuer: values.get("issr").cloned(),
            serial_number: values.get("slnr").cloned(),
            created_utc: values.get("cdat").and_then(|v| parse_keychain_time(v)),
            modified_utc: values.get("mdat").and_then(|v| parse_keychain_time(v)),
            access_group: None,
            icloud_synced: false,
        },
    )
}

fn query_keychain_table<F>(
    conn: &Connection,
    table: &str,
    columns: &[&str],
    mut build: F,
) -> Vec<KeychainEntry>
where
    F: FnMut(&std::collections::HashMap<String, String>) -> KeychainEntry,
{
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |_| Ok(()),
        )
        .is_ok();
    if !exists {
        return Vec::new();
    }
    let sql = format!("SELECT {} FROM {}", columns.join(","), table);
    let Ok(mut stmt) = conn.prepare(&sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        let mut values = std::collections::HashMap::new();
        for (idx, col) in columns.iter().enumerate() {
            if let Ok(value) = row.get_ref(idx) {
                if let Some(s) = value_ref_to_string(value) {
                    values.insert((*col).to_string(), s);
                }
            }
        }
        Ok(build(&values))
    });
    match rows {
        Ok(rows) => rows.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

fn value_ref_to_string(value: ValueRef<'_>) -> Option<String> {
    match value {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Text(bytes) => std::str::from_utf8(bytes).ok().map(ToOwned::to_owned),
        ValueRef::Blob(bytes) => Some(encode_hex(bytes)),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_keychain_time(raw: &str) -> Option<String> {
    if let Ok(epoch) = raw.parse::<i64>() {
        let unix = if epoch > 1_000_000_000 {
            epoch
        } else {
            epoch.saturating_add(978_307_200)
        };
        return DateTime::<Utc>::from_timestamp(unix, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
    }
    if let Ok(epoch) = raw.parse::<f64>() {
        let unix = if epoch > 1_000_000_000.0 {
            epoch
        } else {
            epoch + 978_307_200.0
        };
        return DateTime::<Utc>::from_timestamp(unix as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
    }
    DateTime::parse_from_rfc3339(raw).ok().map(|dt| {
        dt.with_timezone(&Utc)
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string()
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

    #[test]
    fn keychain_icloud_sync_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("login.keychain-db");
        let conn = Connection::open(&path).expect("open sqlite");
        conn.execute(
            "CREATE TABLE genp (labl TEXT, svce TEXT, acct TEXT, cdat INTEGER, mdat INTEGER, agrp TEXT, sync INTEGER)",
            [],
        )
        .expect("create genp");
        conn.execute(
            "INSERT INTO genp VALUES ('Safari', 'com.apple.safari.savedpasswords', 'user@example.com', 0, 60, 'com.apple.safari.savedpasswords', 1)",
            [],
        )
        .expect("insert genp");
        drop(conn);

        let entries = parse_keychain_entries(&path);

        assert_eq!(entries.len(), 1);
        assert!(entries[0].icloud_synced);
        assert_eq!(
            entries[0].access_group.as_deref(),
            Some("com.apple.safari.savedpasswords")
        );
    }

    #[test]
    fn keychain_internet_password_includes_server() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("login.keychain-db");
        let conn = Connection::open(&path).expect("open sqlite");
        conn.execute(
            "CREATE TABLE inet (labl TEXT, srvr TEXT, ptcl TEXT, atyp TEXT, port INTEGER, path TEXT, acct TEXT, cdat INTEGER, mdat INTEGER)",
            [],
        )
        .expect("create inet");
        conn.execute(
            "INSERT INTO inet VALUES ('Example', 'example.com', 'htps', 'dflt', 443, '/login', 'user@example.com', 0, 0)",
            [],
        )
        .expect("insert inet");
        drop(conn);

        let entries = parse_keychain_entries(&path);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].server.as_deref(), Some("example.com"));
        assert_eq!(entries[0].protocol.as_deref(), Some("htps"));
        assert_eq!(entries[0].port, Some(443));
    }

    #[test]
    fn keychain_creation_date_parsed_correctly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("login.keychain-db");
        let conn = Connection::open(&path).expect("open sqlite");
        conn.execute(
            "CREATE TABLE cert (subj TEXT, issr TEXT, slnr TEXT, cdat INTEGER, mdat INTEGER)",
            [],
        )
        .expect("create cert");
        conn.execute(
            "INSERT INTO cert VALUES ('Subject', 'Issuer', '01', 0, 60)",
            [],
        )
        .expect("insert cert");
        drop(conn);

        let entries = parse_keychain_entries(&path);

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].created_utc.as_deref(),
            Some("2001-01-01 00:00:00 UTC")
        );
    }
}
