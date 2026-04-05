use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_yyyymmdd_to_unix,
    unix_to_utc_rfc3339,
};

pub fn get_uninstall_string() -> Vec<UninstallEntry> {
    get_uninstall_string_from_reg(&default_reg_path("uninstall.reg"))
}

pub fn get_uninstall_string_from_reg(path: &Path) -> Vec<UninstallEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\currentversion\\uninstall\\")
    }) {
        let name = record
            .values
            .get("DisplayName")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| key_leaf(&record.path));
        if name.is_empty() {
            continue;
        }

        let install_date = record
            .values
            .get("InstallDate")
            .and_then(|v| decode_reg_string(v))
            .and_then(|s| parse_install_date(&s));

        out.push(UninstallEntry {
            name,
            version: record
                .values
                .get("DisplayVersion")
                .and_then(|v| decode_reg_string(v))
                .map(|v| v.trim().to_string())
                .unwrap_or_default(),
            publisher: record
                .values
                .get("Publisher")
                .and_then(|v| decode_reg_string(v))
                .map(|v| v.trim().to_string())
                .unwrap_or_default(),
            install_date_utc: install_date.and_then(unix_to_utc_rfc3339),
            install_date,
            install_location: record
                .values
                .get("InstallLocation")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            uninstall_string: record
                .values
                .get("UninstallString")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct UninstallEntry {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: Option<u64>,
    pub install_date_utc: Option<String>,
    pub install_location: String,
    pub uninstall_string: String,
}

pub fn get_windows_update() -> Vec<WindowsUpdateEntry> {
    get_windows_update_from_reg(&default_reg_path("uninstall.reg"))
}

pub fn get_windows_update_from_reg(path: &Path) -> Vec<WindowsUpdateEntry> {
    let entries = get_uninstall_string_from_reg(path);
    let mut out = Vec::new();
    for entry in entries {
        if entry.name.to_ascii_uppercase().contains("KB") {
            out.push(WindowsUpdateEntry {
                hotfix_id: extract_kb_id(&entry.name).unwrap_or(entry.name),
                installed_on: entry.install_date,
                installed_on_utc: entry.install_date_utc,
                installed_by: entry.publisher,
            });
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct WindowsUpdateEntry {
    pub hotfix_id: String,
    pub installed_on: Option<u64>,
    pub installed_on_utc: Option<String>,
    pub installed_by: String,
}

fn extract_kb_id(name: &str) -> Option<String> {
    let upper = name.to_ascii_uppercase();
    let kb_pos = upper.find("KB")?;
    let suffix = &upper[kb_pos..];
    let mut id = String::from("KB");
    for ch in suffix[2..].chars() {
        if ch.is_ascii_digit() {
            id.push(ch);
        } else {
            break;
        }
    }
    if id.len() > 2 {
        Some(id)
    } else {
        None
    }
}

pub(crate) fn parse_install_date(text: &str) -> Option<u64> {
    let trimmed = text.trim();

    if let Some(unix_from_ymd) = parse_yyyymmdd_to_unix(trimmed) {
        return Some(unix_from_ymd);
    }

    if let Ok(unix) = trimmed.parse::<u64>() {
        if unix >= 946_684_800 {
            return Some(unix);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_uninstall_entries() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("uninstall.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Test]
"DisplayName"="KB503123 Security Update"
"DisplayVersion"="1.0"
"Publisher"="Microsoft"
"InstallDate"="20240305"
"UninstallString"="msiexec /x {GUID}"
"#,
        )
        .unwrap();

        let rows = get_uninstall_string_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "KB503123 Security Update");
        assert_eq!(rows[0].install_date, Some(1_709_596_800));
        assert_eq!(get_windows_update_from_reg(&file).len(), 1);
    }

    #[test]
    fn parse_uninstall_entries_with_partial_values() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("uninstall.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FooApp]
"DisplayName"="Foo App"
"InstallDate"="not-a-date"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NoDisplay]
"Publisher"="Unknown"
"#,
        )
        .unwrap();

        let rows = get_uninstall_string_from_reg(&file);
        assert_eq!(rows.len(), 2);
        let foo = rows.iter().find(|r| r.name == "Foo App").unwrap();
        assert_eq!(foo.install_date, None);
    }
}
