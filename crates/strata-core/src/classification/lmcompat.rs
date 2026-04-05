use std::path::Path;

use super::reg_export::{default_reg_path, load_reg_records, parse_reg_u32};

pub fn get_lm_compatibility() -> LmCompatibility {
    get_lm_compatibility_from_reg(&default_reg_path("security.reg"))
}

pub fn get_lm_compatibility_from_reg(path: &Path) -> LmCompatibility {
    let records = load_reg_records(path);

    for record in records
        .iter()
        .filter(|record| record.path.to_ascii_lowercase().contains("\\control\\lsa"))
    {
        if let Some(level) = record
            .values
            .get("LmCompatibilityLevel")
            .and_then(|value| parse_reg_u32(value))
        {
            return LmCompatibility {
                level,
                description: describe_lm_compatibility_level(level).to_string(),
                ntlmv1_allowed: level <= 2,
            };
        }
    }

    LmCompatibility::default()
}

#[derive(Debug, Clone, Default)]
pub struct LmCompatibility {
    pub level: u32,
    pub description: String,
    pub ntlmv1_allowed: bool,
}

fn describe_lm_compatibility_level(level: u32) -> &'static str {
    match level {
        0 => "Send LM and NTLM responses",
        1 => "Send LM and NTLM - use NTLMv2 session security if negotiated",
        2 => "Send NTLM response only",
        3 => "Send NTLMv2 response only",
        4 => "Send NTLMv2 response only, refuse LM",
        5 => "Send NTLMv2 response only, refuse LM and NTLM",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_lm_compatibility_level_and_policy() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("security.reg");

        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"LmCompatibilityLevel"=dword:00000005
"#,
        )
        .expect("write reg");

        let info = get_lm_compatibility_from_reg(&file);
        assert_eq!(info.level, 5);
        assert_eq!(
            info.description,
            "Send NTLMv2 response only, refuse LM and NTLM"
        );
        assert!(!info.ntlmv1_allowed);
    }

    #[test]
    fn defaults_when_policy_value_missing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("security.reg");
        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"SomeOtherValue"=dword:00000001
"#,
        )
        .expect("write reg");

        let info = get_lm_compatibility_from_reg(&file);
        assert_eq!(info.level, 0);
        assert!(info.description.is_empty());
        assert!(!info.ntlmv1_allowed);
    }
}
