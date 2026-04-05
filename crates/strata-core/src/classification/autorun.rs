use std::env;
use std::path::{Path, PathBuf};

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records};

pub fn get_auto_run_keys() -> Vec<AutoRunKey> {
    let reg_path = env::var("FORENSIC_AUTORUN_REG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_reg_path("autorun.reg"));
    get_auto_run_keys_from_reg(&reg_path)
}

pub fn get_auto_run_keys_from_reg(path: &Path) -> Vec<AutoRunKey> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| is_autorun_key(&r.path)) {
        for (name, raw) in &record.values {
            if name.eq_ignore_ascii_case("@") && !should_include_default_value(&record.path) {
                continue;
            }
            if !is_interesting_autorun_value(&record.path, name) {
                continue;
            }
            let value = decode_reg_string(raw)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| raw.clone());
            out.push(AutoRunKey {
                path: format!("{}\\{}", record.path, name),
                value,
            });
        }
    }

    out
}

fn is_autorun_key(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("\\currentversion\\run")
        || p.contains("\\currentversion\\runonce")
        || p.contains("\\currentversion\\runonceex")
        || p.contains("\\currentversion\\runservices")
        || p.contains("\\policies\\explorer\\run")
        || p.contains("\\winlogon")
        || p.contains("\\startupapproved\\run")
        || p.contains("\\image file execution options\\")
        || p.contains("\\windows nt\\currentversion\\windows")
}

fn should_include_default_value(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("\\currentversion\\runonceex\\")
}

fn is_interesting_autorun_value(path: &str, value_name: &str) -> bool {
    if value_name.trim().is_empty() {
        return false;
    }

    let p = path.to_ascii_lowercase();
    if p.contains("\\image file execution options\\") {
        return value_name.eq_ignore_ascii_case("Debugger")
            || value_name.eq_ignore_ascii_case("VerifierDlls");
    }
    if p.contains("\\windows nt\\currentversion\\windows") {
        return value_name.eq_ignore_ascii_case("AppInit_DLLs");
    }
    if p.contains("\\winlogon") {
        return value_name.eq_ignore_ascii_case("Shell")
            || value_name.eq_ignore_ascii_case("Userinit")
            || value_name.eq_ignore_ascii_case("Taskman")
            || value_name.eq_ignore_ascii_case("VmApplet")
            || value_name.eq_ignore_ascii_case("GinaDLL");
    }
    true
}

#[derive(Debug, Clone, Default)]
pub struct AutoRunKey {
    pub path: String,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_autorun_registry_export() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("autorun.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"OneDrive"="C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background"
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Userinit"="C:\\Windows\\system32\\userinit.exe,"
"#,
        )
        .unwrap();

        let rows = get_auto_run_keys_from_reg(&file);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|r| r.path.contains("Run\\OneDrive")));
        assert!(rows.iter().any(|r| r.path.contains("Winlogon\\Userinit")));
    }

    #[test]
    fn parse_autorun_extended_registry_persistence_keys() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("autorun.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001]
"1"="C:\\Tools\\runner.exe"
@="C:\\Tools\\runner_default.exe"
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe]
"Debugger"="C:\\Tools\\dbg.exe -p %ld"
"GlobalFlag"=dword:00000200
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows]
"AppInit_DLLs"="C:\\Tools\\bad.dll"
"LoadAppInit_DLLs"=dword:00000001
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Shell"="explorer.exe, badshell.exe"
"System"="IgnoreNoise"
"#,
        )
        .unwrap();

        let rows = get_auto_run_keys_from_reg(&file);
        assert!(rows.iter().any(|r| r.path.contains(r"RunOnceEx\0001\1")));
        assert!(rows.iter().any(|r| r.path.contains(r"RunOnceEx\0001\@")));
        assert!(rows.iter().any(|r| r
            .path
            .contains(r"Image File Execution Options\notepad.exe\Debugger")));
        assert!(rows
            .iter()
            .any(|r| r.path.ends_with(r"Windows\AppInit_DLLs")));
        assert!(rows.iter().any(|r| r.path.ends_with(r"Winlogon\Shell")));
        assert!(!rows.iter().any(|r| r
            .path
            .contains(r"Image File Execution Options\notepad.exe\GlobalFlag")));
        assert!(!rows
            .iter()
            .any(|r| r.path.ends_with(r"Windows\LoadAppInit_DLLs")));
        assert!(!rows.iter().any(|r| r.path.ends_with(r"Winlogon\System")));
    }
}
