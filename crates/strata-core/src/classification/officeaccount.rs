use std::env;
use std::path::{Path, PathBuf};

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};

pub fn get_office_accounts() -> Vec<OfficeAccount> {
    let path = env::var("FORENSIC_OFFICE_ACCOUNT_REG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_reg_path("office_accounts.reg"));
    get_office_accounts_from_reg(&path)
}

pub fn get_office_accounts_from_reg(path: &Path) -> Vec<OfficeAccount> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("office") && (p.contains("common\\identity") || p.contains("account"))
    }) {
        let email = record
            .values
            .get("EmailAddress")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| record.values.get("UPN").and_then(|v| decode_reg_string(v)))
            .or_else(|| {
                record
                    .values
                    .get("UserName")
                    .and_then(|v| decode_reg_string(v))
            })
            .unwrap_or_default();
        if email.is_empty() {
            continue;
        }
        out.push(OfficeAccount {
            email,
            account_type: record
                .values
                .get("Provider")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| infer_account_type(&record.path)),
        });
    }

    out
}

fn infer_account_type(path: &str) -> String {
    let leaf = key_leaf(path).to_ascii_lowercase();
    if leaf.contains("aad") || leaf.contains("azure") {
        "azure_ad".to_string()
    } else if leaf.contains("msa") || leaf.contains("microsoft") {
        "microsoft".to_string()
    } else {
        "office".to_string()
    }
}

#[derive(Debug, Clone, Default)]
pub struct OfficeAccount {
    pub email: String,
    pub account_type: String,
}
