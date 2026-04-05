use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};

pub fn get_autoplay() -> AutoplaySettings {
    get_autoplay_from_reg(&default_reg_path("autoplay.reg"))
}

pub fn get_autoplay_from_reg(path: &Path) -> AutoplaySettings {
    let records = load_reg_records(path);
    let mut devices = Vec::new();
    let mut default_behavior = String::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\explorer\\autoplayhandlers")
    }) {
        if default_behavior.is_empty() {
            default_behavior = record
                .values
                .get("DisableAutoplay")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| "NotConfigured".to_string());
        }

        for (name, raw) in &record.values {
            if let Some(action) = decode_reg_string(raw) {
                devices.push(AutoplayDevice {
                    device_type: name.clone(),
                    action,
                });
            }
        }
    }

    AutoplaySettings {
        default_behavior,
        devices,
    }
}

#[derive(Debug, Clone, Default)]
pub struct AutoplaySettings {
    pub default_behavior: String,
    pub devices: Vec<AutoplayDevice>,
}

#[derive(Debug, Clone, Default)]
pub struct AutoplayDevice {
    pub device_type: String,
    pub action: String,
}

pub fn get_default_programs() -> Vec<DefaultProgram> {
    get_default_programs_from_reg(&default_reg_path("autoplay.reg"))
}

pub fn get_default_programs_from_reg(path: &Path) -> Vec<DefaultProgram> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\software\\classes\\.")
    }) {
        if let Some(raw) = record.values.get("@") {
            if let Some(prog_id) = decode_reg_string(raw) {
                out.push(DefaultProgram {
                    extension: key_leaf(&record.path),
                    prog_id,
                });
            }
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct DefaultProgram {
    pub extension: String,
    pub prog_id: String,
}

pub fn get_file_associations() -> Vec<FileAssociation> {
    get_default_programs()
        .into_iter()
        .map(|p| FileAssociation {
            extension: p.extension,
            handler: p.prog_id,
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct FileAssociation {
    pub extension: String,
    pub handler: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_default_programs() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("autoplay.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Software\Classes\.pdf]
@="AcroExch.Document.DC"
"#,
        )
        .unwrap();
        let rows = get_default_programs_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].extension, ".pdf");
    }
}
