use std::env;
use std::path::PathBuf;

use rusqlite::Connection;

pub fn get_chrome_passwords() -> Vec<PasswordEntry> {
    let mut out = Vec::new();
    for db_path in login_data_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT origin_url, username_value, date_created FROM logins ORDER BY date_created DESC LIMIT 3000",
        ) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            Ok(PasswordEntry {
                origin_url: row.get::<_, String>(0).unwrap_or_default(),
                username: row.get::<_, String>(1).unwrap_or_default(),
                password: "<encrypted>".to_string(),
                date_created: chrome_time_to_unix(row.get::<_, i64>(2).unwrap_or(0)),
            })
        });
        if let Ok(iter) = rows {
            for item in iter.flatten() {
                out.push(item);
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct PasswordEntry {
    pub origin_url: String,
    pub username: String,
    pub password: String,
    pub date_created: Option<u64>,
}

pub fn get_chrome_credit_cards() -> Vec<CreditCard> {
    let mut out = Vec::new();
    for db_path in web_data_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT name_on_card, expiration_month, expiration_year FROM credit_cards ORDER BY use_count DESC LIMIT 2000",
        ) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            Ok(CreditCard {
                name_on_card: row.get::<_, String>(0).unwrap_or_default(),
                expiration_month: row.get::<_, i64>(1).unwrap_or(0).max(0) as u16,
                expiration_year: row.get::<_, i64>(2).unwrap_or(0).max(0) as u16,
                card_number: "<encrypted>".to_string(),
            })
        });
        if let Ok(iter) = rows {
            for item in iter.flatten() {
                out.push(item);
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct CreditCard {
    pub name_on_card: String,
    pub expiration_month: u16,
    pub expiration_year: u16,
    pub card_number: String,
}

pub fn get_chrome_webauthn() -> Vec<WebAuthn> {
    let mut out = Vec::new();
    for db_path in webauthn_db_candidates() {
        let Ok(conn) = Connection::open(&db_path) else {
            continue;
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT relying_party_id, credential_id, user_handle FROM webauthn_credentials LIMIT 3000",
        ) else {
            continue;
        };
        let rows = stmt.query_map([], |row| {
            Ok(WebAuthn {
                relying_party_id: row.get::<_, String>(0).unwrap_or_default(),
                credential_id: row.get::<_, Vec<u8>>(1).unwrap_or_default(),
                user_handle: row.get::<_, Vec<u8>>(2).unwrap_or_default(),
            })
        });
        if let Ok(iter) = rows {
            for item in iter.flatten() {
                out.push(item);
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct WebAuthn {
    pub relying_party_id: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
}

fn login_data_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_CHROME_LOGIN_DATA") {
        return vec![PathBuf::from(path)];
    }
    if let Ok(user_profile) = env::var("USERPROFILE") {
        return vec![
            PathBuf::from(&user_profile)
                .join("AppData")
                .join("Local")
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Login Data"),
            PathBuf::from("artifacts")
                .join("browser")
                .join("chrome")
                .join("Login Data"),
        ];
    }
    vec![PathBuf::from("artifacts")
        .join("browser")
        .join("chrome")
        .join("Login Data")]
}

fn web_data_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_CHROME_WEBDATA_DB") {
        return vec![PathBuf::from(path)];
    }
    if let Ok(user_profile) = env::var("USERPROFILE") {
        return vec![
            PathBuf::from(&user_profile)
                .join("AppData")
                .join("Local")
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Web Data"),
            PathBuf::from("artifacts")
                .join("browser")
                .join("chrome")
                .join("Web Data"),
        ];
    }
    vec![PathBuf::from("artifacts")
        .join("browser")
        .join("chrome")
        .join("Web Data")]
}

fn webauthn_db_candidates() -> Vec<PathBuf> {
    if let Ok(path) = env::var("FORENSIC_CHROME_WEBAUTHN_DB") {
        return vec![PathBuf::from(path)];
    }
    if let Ok(user_profile) = env::var("USERPROFILE") {
        return vec![
            PathBuf::from(&user_profile)
                .join("AppData")
                .join("Local")
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("WebAuthn"),
            PathBuf::from("artifacts")
                .join("browser")
                .join("chrome")
                .join("WebAuthn"),
        ];
    }
    vec![PathBuf::from("artifacts")
        .join("browser")
        .join("chrome")
        .join("WebAuthn")]
}

fn chrome_time_to_unix(raw: i64) -> Option<u64> {
    if raw <= 0 {
        return None;
    }
    let seconds = raw / 1_000_000;
    if seconds < 11_644_473_600 {
        return None;
    }
    Some((seconds - 11_644_473_600) as u64)
}
