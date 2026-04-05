use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};

pub fn get_complete_passwords() -> Vec<PasswordEntry> {
    get_complete_passwords_from_reg(&default_reg_path("passwords.reg"))
}

pub fn get_complete_passwords_from_reg(path: &Path) -> Vec<PasswordEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\credentials\\"))
    {
        out.push(PasswordEntry {
            target: record
                .values
                .get("TargetName")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| key_leaf(&record.path)),
            username: record
                .values
                .get("UserName")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            password: "<redacted>".to_string(),
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct PasswordEntry {
    pub target: String,
    pub username: String,
    pub password: String,
}

pub fn get_vault_credentials() -> Vec<VaultCredential> {
    get_vault_credentials_from_reg(&default_reg_path("passwords.reg"))
}

pub fn get_vault_credentials_from_reg(path: &Path) -> Vec<VaultCredential> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\vault\\"))
    {
        out.push(VaultCredential {
            resource: record
                .values
                .get("Resource")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| key_leaf(&record.path)),
            username: record
                .values
                .get("UserName")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            credential_type: record
                .values
                .get("Type")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| "vault".to_string()),
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct VaultCredential {
    pub resource: String,
    pub username: String,
    pub credential_type: String,
}
