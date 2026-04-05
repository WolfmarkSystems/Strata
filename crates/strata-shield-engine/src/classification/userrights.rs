use std::collections::BTreeSet;
use std::path::Path;

use super::reg_export::default_reg_path;
use super::regsecurity;

pub fn get_user_rights() -> Vec<UserRight> {
    get_user_rights_from_reg(&default_reg_path("security.reg"))
}

pub fn get_user_rights_from_reg(path: &Path) -> Vec<UserRight> {
    regsecurity::get_user_rights_from_reg(path)
        .into_iter()
        .map(|entry| {
            let mut resolved_accounts = entry
                .accounts
                .iter()
                .map(|account| resolve_principal(account))
                .collect::<Vec<_>>();
            resolved_accounts.sort();
            resolved_accounts.dedup();

            let high_risk = is_high_risk_privilege(&entry.privilege);
            let non_builtin_accounts = entry
                .accounts
                .iter()
                .filter(|account| !is_builtin_principal(account))
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();

            UserRight {
                privilege: entry.privilege,
                accounts: entry.accounts,
                resolved_accounts,
                high_risk,
                non_builtin_accounts,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct UserRight {
    pub privilege: String,
    pub accounts: Vec<String>,
    pub resolved_accounts: Vec<String>,
    pub high_risk: bool,
    pub non_builtin_accounts: Vec<String>,
}

fn resolve_principal(principal: &str) -> String {
    match principal.trim() {
        "S-1-5-18" => "LocalSystem".to_string(),
        "S-1-5-19" => "LocalService".to_string(),
        "S-1-5-20" => "NetworkService".to_string(),
        "S-1-5-32-544" => "Administrators (Builtin)".to_string(),
        "S-1-5-32-545" => "Users (Builtin)".to_string(),
        "S-1-5-32-546" => "Guests (Builtin)".to_string(),
        "S-1-5-32-551" => "Backup Operators (Builtin)".to_string(),
        "S-1-5-32-555" => "Remote Desktop Users (Builtin)".to_string(),
        other => other.to_string(),
    }
}

fn is_high_risk_privilege(privilege: &str) -> bool {
    matches!(
        privilege,
        "SeDebugPrivilege"
            | "SeImpersonatePrivilege"
            | "SeLoadDriverPrivilege"
            | "SeTakeOwnershipPrivilege"
            | "SeBackupPrivilege"
            | "SeRestorePrivilege"
            | "SeTcbPrivilege"
            | "SeAssignPrimaryTokenPrivilege"
    )
}

fn is_builtin_principal(principal: &str) -> bool {
    let normalized = principal.trim().to_ascii_lowercase();
    normalized.starts_with("s-1-5-32-")
        || normalized == "s-1-5-18"
        || normalized == "s-1-5-19"
        || normalized == "s-1-5-20"
        || normalized == "administrators"
        || normalized == "users"
        || normalized == "guests"
        || normalized.starts_with("nt authority\\")
        || normalized.starts_with("builtin\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn maps_well_known_sids_and_flags_high_risk_privileges() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("security.reg");

        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SecEdit\UserRights]
"SeDebugPrivilege"="*S-1-5-32-544,DOMAIN\\alice"
"SeBackupPrivilege"="*S-1-5-18"
"#,
        )
        .expect("write reg");

        let rights = get_user_rights_from_reg(&file);
        assert_eq!(rights.len(), 2);

        let debug = rights
            .iter()
            .find(|entry| entry.privilege == "SeDebugPrivilege")
            .expect("debug entry");
        assert!(debug.high_risk);
        assert!(
            debug
                .resolved_accounts
                .iter()
                .any(|v| v == "Administrators (Builtin)"),
            "resolved_accounts={:?}",
            debug.resolved_accounts
        );
        assert_eq!(debug.non_builtin_accounts, vec!["DOMAIN\\alice"]);

        let backup = rights
            .iter()
            .find(|entry| entry.privilege == "SeBackupPrivilege")
            .expect("backup entry");
        assert!(backup.high_risk);
        assert!(backup.resolved_accounts.iter().any(|v| v == "LocalSystem"));
    }

    #[test]
    fn keeps_non_high_risk_privileges_without_false_positive() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("security.reg");

        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SecEdit\UserRights]
"SeChangeNotifyPrivilege"="*S-1-5-32-545"
"#,
        )
        .expect("write reg");

        let rights = get_user_rights_from_reg(&file);
        assert_eq!(rights.len(), 1);
        assert!(!rights[0].high_risk);
        assert!(rights[0].non_builtin_accounts.is_empty());
        assert!(rights[0]
            .resolved_accounts
            .iter()
            .any(|v| v == "Users (Builtin)"));
    }
}
