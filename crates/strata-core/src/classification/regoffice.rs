use std::collections::BTreeSet;
use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};

pub fn get_office_mru() -> Vec<OfficeMru> {
    get_office_mru_from_reg(&default_reg_path("office.reg"))
}

pub fn get_office_mru_from_reg(path: &Path) -> Vec<OfficeMru> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\office\\") && r.path.contains("MRU"))
    {
        let app = infer_office_app(&record.path);
        for (name, raw) in &record.values {
            if name.eq_ignore_ascii_case("@") {
                continue;
            }
            if let Some(value) = decode_reg_string(raw) {
                if let Some(file_path) = extract_office_path(&value) {
                    out.push(OfficeMru {
                        app: app.clone(),
                        file_path,
                        timestamp: None,
                    });
                }
            }
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct OfficeMru {
    pub app: String,
    pub file_path: String,
    pub timestamp: Option<u64>,
}

pub fn get_office_recent() -> Vec<OfficeRecent> {
    get_office_recent_from_reg(&default_reg_path("office.reg"))
}

pub fn get_office_recent_from_reg(path: &Path) -> Vec<OfficeRecent> {
    get_office_mru_from_reg(path)
        .into_iter()
        .map(|mru| OfficeRecent {
            document: mru.file_path,
            timestamp: mru.timestamp,
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct OfficeRecent {
    pub document: String,
    pub timestamp: Option<u64>,
}

pub fn get_office_files() -> Vec<OfficeFile> {
    get_office_files_from_reg(&default_reg_path("office.reg"))
}

pub fn get_office_files_from_reg(path: &Path) -> Vec<OfficeFile> {
    let mru = get_office_mru_from_reg(path);
    let mut dedup = BTreeSet::new();
    let mut files = Vec::new();

    for entry in mru {
        let key = format!("{}|{}", entry.app, entry.file_path.to_ascii_lowercase());
        if dedup.insert(key) {
            files.push(OfficeFile {
                path: entry.file_path,
                app: entry.app,
            });
        }
    }

    files
}

#[derive(Debug, Clone, Default)]
pub struct OfficeFile {
    pub path: String,
    pub app: String,
}

fn extract_office_path(raw: &str) -> Option<String> {
    // Common Office MRU value forms:
    // *C:\path\file.docx
    // [F00000000][T01D9...]*C:\path\file.docx
    if let Some(idx) = raw.rfind('*') {
        let path = raw[idx + 1..].trim();
        if !path.is_empty() {
            return Some(path.to_string());
        }
    }
    if raw.contains(':') && raw.contains('\\') {
        return Some(raw.trim().to_string());
    }
    None
}

fn infer_office_app(key_path: &str) -> String {
    let lower = key_path.to_ascii_lowercase();
    for app in [
        "word",
        "excel",
        "powerpoint",
        "outlook",
        "onenote",
        "access",
    ] {
        if lower.contains(&format!("\\{app}\\")) {
            return app.to_string();
        }
    }
    key_leaf(key_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_office_mru_paths() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("office.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\File MRU]
"Item 1"="[F00000000][T00000000]*C:\Docs\report.docx"
"#,
        )
        .unwrap();
        let rows = get_office_mru_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].app, "word");
        assert_eq!(rows[0].file_path, "C:\\Docs\\report.docx");
    }
}
