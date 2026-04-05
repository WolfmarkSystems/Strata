use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_hex_bytes, parse_reg_u32,
};

pub fn get_audit_security() -> AuditSecurity {
    get_audit_security_from_reg(&default_reg_path("security.reg"))
}

pub fn get_audit_security_from_reg(path: &Path) -> AuditSecurity {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| is_lsa_policy_key(&r.path)) {
        AuditSecurity {
            logon_events: record
                .values
                .get("AuditLogonEvents")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            object_access: record
                .values
                .get("AuditObjectAccess")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            process_tracking: record
                .values
                .get("AuditProcessTracking")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            policy_changes: record
                .values
                .get("AuditPolicyChange")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            account_management: record
                .values
                .get("AuditAccountManage")
                .or_else(|| record.values.get("AuditAccountManagement"))
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            account_logon: record
                .values
                .get("AuditAccountLogon")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
        }
    } else {
        AuditSecurity::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditSecurity {
    pub logon_events: bool,
    pub object_access: bool,
    pub process_tracking: bool,
    pub policy_changes: bool,
    pub account_management: bool,
    pub account_logon: bool,
}

pub fn get_user_rights() -> Vec<UserRightEntry> {
    get_user_rights_from_reg(&default_reg_path("security.reg"))
}

pub fn get_user_rights_from_reg(path: &Path) -> Vec<UserRightEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\secedit\\userrights")
    }) {
        for (name, raw) in &record.values {
            if !name.starts_with("Se") {
                continue;
            }
            let accounts = parse_user_right_accounts(raw);
            out.push(UserRightEntry {
                privilege: name.clone(),
                principals: accounts.clone(),
                accounts,
            });
        }
    }
    out.sort_by(|a, b| a.privilege.cmp(&b.privilege));
    out.into_iter()
        .fold(Vec::<UserRightEntry>::new(), |mut acc, item| {
            if let Some(last) = acc.last_mut() {
                if last.privilege == item.privilege {
                    for principal in item.principals {
                        if !last
                            .principals
                            .iter()
                            .any(|p| p.eq_ignore_ascii_case(&principal))
                        {
                            last.principals.push(principal.clone());
                            last.accounts.push(principal);
                        }
                    }
                    return acc;
                }
            }
            acc.push(item);
            acc
        })
}

#[derive(Debug, Clone, Default)]
pub struct UserRightEntry {
    pub privilege: String,
    pub accounts: Vec<String>,
    pub principals: Vec<String>,
}

pub fn get_password_policy() -> PasswordPolicy {
    get_password_policy_from_reg(&default_reg_path("security.reg"))
}

pub fn get_password_policy_from_reg(path: &Path) -> PasswordPolicy {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| is_lsa_policy_key(&r.path)) {
        PasswordPolicy {
            min_length: record
                .values
                .get("MinimumPasswordLength")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0),
            max_age: record
                .values
                .get("MaximumPasswordAge")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0),
            min_age: record
                .values
                .get("MinimumPasswordAge")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0),
            lockout_threshold: record
                .values
                .get("LockoutBadCount")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0),
            history_length: record
                .values
                .get("PasswordHistorySize")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0),
            complexity_enabled: record
                .values
                .get("PasswordComplexity")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            reversible_encryption_enabled: record
                .values
                .get("ClearTextPassword")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
        }
    } else {
        PasswordPolicy::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub max_age: u32,
    pub min_age: u32,
    pub lockout_threshold: u32,
    pub history_length: u32,
    pub complexity_enabled: bool,
    pub reversible_encryption_enabled: bool,
}

fn is_lsa_policy_key(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("\\control\\lsa") || lower.contains("\\control\\securityproviders\\lsa")
}

fn parse_user_right_accounts(raw: &str) -> Vec<String> {
    let mut accounts = decode_reg_string(raw)
        .map(|s| split_accounts(&s))
        .unwrap_or_default();
    if let Some(bytes) = parse_hex_bytes(raw) {
        let parsed = parse_accounts_from_hex_bytes(&bytes);
        if has_meaningful_accounts(&parsed) {
            accounts.extend(parsed);
        }
    }
    if !has_meaningful_accounts(&accounts) {
        accounts.clear();
    }

    let mut seen = std::collections::HashSet::new();
    accounts
        .into_iter()
        .map(|v| normalize_principal(&v))
        .filter(|v| !v.is_empty())
        .filter(|v| seen.insert(v.to_ascii_lowercase()))
        .collect()
}

fn parse_accounts_from_hex_bytes(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let utf16 = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    if let Ok(text) = String::from_utf16(&utf16) {
        let parsed = split_accounts(&text.replace('\0', ","));
        if has_meaningful_accounts(&parsed) {
            return parsed;
        }
    }
    let ascii = String::from_utf8_lossy(bytes);
    split_accounts(&ascii.replace('\0', ","))
}

fn has_meaningful_accounts(values: &[String]) -> bool {
    values.iter().any(|entry| {
        entry
            .chars()
            .any(|c| c.is_ascii_alphanumeric() || c == '-' || c == '\\' || c == '*')
    })
}

fn split_accounts(text: &str) -> Vec<String> {
    text.split([',', ';', '\n', '\r', '|'])
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

fn normalize_principal(value: &str) -> String {
    value.trim().trim_start_matches('*').to_string()
}

#[allow(dead_code)]
fn _key_name(path: &str) -> String {
    key_leaf(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_password_policy() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("security.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"MinimumPasswordLength"=dword:0000000c
"MaximumPasswordAge"=dword:0000002d
"LockoutBadCount"=dword:00000005
"#,
        )
        .unwrap();
        let p = get_password_policy_from_reg(&file);
        assert_eq!(p.min_length, 12);
        assert_eq!(p.lockout_threshold, 5);
    }

    #[test]
    fn parse_password_policy_extended_flags() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("security.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"PasswordHistorySize"=dword:00000018
"PasswordComplexity"=dword:00000001
"ClearTextPassword"=dword:00000000
"#,
        )
        .unwrap();

        let p = get_password_policy_from_reg(&file);
        assert_eq!(p.history_length, 24);
        assert!(p.complexity_enabled);
        assert!(!p.reversible_encryption_enabled);
    }

    #[test]
    fn parse_user_rights_normalizes_accounts_and_hex_multistring() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("security.reg");

        let utf16 = "Administrators\0*S-1-5-18\0\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>();
        let payload = utf16
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(",");

        strata_fs::write(
            &file,
            format!(
                r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SecEdit\UserRights]
"SeBackupPrivilege"=hex(7):{payload}
"SeRestorePrivilege"="*S-1-5-32-544, Administrators , ; "
"#
            ),
        )
        .unwrap();

        let rights = get_user_rights_from_reg(&file);
        assert_eq!(rights.len(), 2);

        let backup = rights
            .iter()
            .find(|r| r.privilege == "SeBackupPrivilege")
            .unwrap();
        assert_eq!(backup.accounts, vec!["Administrators", "S-1-5-18"]);

        let restore = rights
            .iter()
            .find(|r| r.privilege == "SeRestorePrivilege")
            .unwrap();
        assert_eq!(restore.accounts, vec!["S-1-5-32-544", "Administrators"]);
        assert_eq!(restore.principals, restore.accounts);
    }

    #[test]
    fn parse_audit_security_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("security.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"AuditAccountManagement"=dword:00000001
"AuditAccountLogon"=dword:00000001
"#,
        )
        .unwrap();

        let audit = get_audit_security_from_reg(&file);
        assert!(audit.account_management);
        assert!(audit.account_logon);
    }

    #[test]
    fn parse_user_rights_dedupes_case_insensitive_and_newline_delimiters() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("security.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SecEdit\UserRights]
"SeDenyRemoteInteractiveLogonRight"="Administrators;administrators|*S-1-5-32-544"
"#,
        )
        .unwrap();

        let rights = get_user_rights_from_reg(&file);
        assert_eq!(rights.len(), 1);
        assert_eq!(
            rights[0].accounts,
            vec!["Administrators".to_string(), "S-1-5-32-544".to_string()]
        );
    }

    #[test]
    fn parse_user_rights_hex_ascii_fallback_when_utf16_decode_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("security.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SecEdit\UserRights]
"SeImpersonatePrivilege"=hex:41,64,6d,69,6e,69,73,74,72,61,74,6f,72,73,00,2a,53,2d,31,2d,35,2d,31,38,00
"#,
        )
        .unwrap();

        let rights = get_user_rights_from_reg(&file);
        assert_eq!(rights.len(), 1);
        assert_eq!(rights[0].privilege, "SeImpersonatePrivilege");
        assert!(rights[0].accounts.iter().any(|v| v == "Administrators"));
        assert!(
            rights[0].accounts.iter().any(|v| v == "S-1-5-18"),
            "accounts={:?}",
            rights[0].accounts
        );
    }
}
