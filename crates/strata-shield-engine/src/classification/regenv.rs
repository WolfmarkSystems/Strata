use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records};

pub fn get_environment() -> Vec<EnvEntry> {
    get_environment_from_reg(&default_reg_path("env.reg"))
}

pub fn get_environment_from_reg(path: &Path) -> Vec<EnvEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\environment"))
    {
        let is_user = record
            .path
            .to_ascii_lowercase()
            .starts_with("hkey_current_user\\");
        for (name, raw) in &record.values {
            if name.eq_ignore_ascii_case("@") {
                continue;
            }
            if let Some(value) = decode_reg_string(raw) {
                out.push(EnvEntry {
                    name: name.clone(),
                    value,
                    user: is_user,
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct EnvEntry {
    pub name: String,
    pub value: String,
    pub user: bool,
}

pub fn get_system_environment() -> Vec<EnvEntry> {
    get_environment()
        .into_iter()
        .filter(|e| !e.user)
        .collect::<Vec<_>>()
}

pub fn get_path_entries() -> Vec<PathEntry> {
    get_path_entries_from_reg(&default_reg_path("env.reg"))
}

pub fn get_path_entries_from_reg(path: &Path) -> Vec<PathEntry> {
    let mut out = Vec::new();
    for entry in get_environment_from_reg(path) {
        if entry.name.eq_ignore_ascii_case("Path") {
            for p in entry.value.split(';') {
                let cleaned = p.trim();
                if cleaned.is_empty() {
                    continue;
                }
                out.push(PathEntry {
                    path: cleaned.to_string(),
                    user: entry.user,
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct PathEntry {
    pub path: String,
    pub user: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_environment_path_entries() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("env.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Environment]
"Path"="C:\Tools;C:\Users\me\bin"
"TEMP"="C:\Temp"
"#,
        )
        .unwrap();
        let paths = get_path_entries_from_reg(&file);
        assert_eq!(paths.len(), 2);
    }
}
