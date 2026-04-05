use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records, parse_reg_u32};

pub fn get_compatibility_flags() -> CompatFlagEntry {
    get_compatibility_flags_from_reg(&default_reg_path("uac.reg"))
}

pub fn get_compatibility_flags_from_reg(path: &Path) -> CompatFlagEntry {
    let records = load_reg_records(path);
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("appcompatflags\\layers")
    }) {
        if let Some((program, raw)) = record.values.iter().next() {
            if let Some(flags) = decode_reg_string(raw) {
                let normalized = flags.to_ascii_uppercase();
                return CompatFlagEntry {
                    program: program.clone(),
                    compatibility_mode: normalized.contains("WIN") || normalized.contains("VISTA"),
                    dpi_aware: normalized.contains("HIGHDPIAWARE"),
                };
            }
        }
    }
    CompatFlagEntry::default()
}

#[derive(Debug, Clone, Default)]
pub struct CompatFlagEntry {
    pub program: String,
    pub compatibility_mode: bool,
    pub dpi_aware: bool,
}

pub fn get_elevation_policies() -> Vec<ElevationPolicy> {
    get_elevation_policies_from_reg(&default_reg_path("uac.reg"))
}

pub fn get_elevation_policies_from_reg(path: &Path) -> Vec<ElevationPolicy> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("appcompatflags\\layers")
    }) {
        for (program, raw) in &record.values {
            if let Some(value) = decode_reg_string(raw) {
                out.push(ElevationPolicy {
                    program: program.clone(),
                    auto_elevate: value.to_ascii_uppercase().contains("RUNASADMIN"),
                });
            }
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct ElevationPolicy {
    pub program: String,
    pub auto_elevate: bool,
}

pub fn get_uac_policies() -> UacPolicy {
    get_uac_policies_from_reg(&default_reg_path("uac.reg"))
}

pub fn get_uac_policies_from_reg(path: &Path) -> UacPolicy {
    let records = load_reg_records(path);
    if let Some(record) = records
        .iter()
        .find(|r| r.path.to_ascii_lowercase().contains("policies\\system"))
    {
        UacPolicy {
            enabled: record
                .values
                .get("EnableLUA")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            prompt_behavior: record
                .values
                .get("ConsentPromptBehaviorAdmin")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0),
        }
    } else {
        UacPolicy::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct UacPolicy {
    pub enabled: bool,
    pub prompt_behavior: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_uac_policy() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("uac.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableLUA"=dword:00000001
"ConsentPromptBehaviorAdmin"=dword:00000005
"#,
        )
        .unwrap();
        let p = get_uac_policies_from_reg(&file);
        assert!(p.enabled);
        assert_eq!(p.prompt_behavior, 5);
    }
}
