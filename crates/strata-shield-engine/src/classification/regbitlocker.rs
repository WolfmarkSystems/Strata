use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32, parse_reg_u64,
};

pub fn get_bitlocker_status() -> Vec<BitlockerVolume> {
    get_bitlocker_status_from_reg(&default_reg_path("bitlocker.reg"))
}

pub fn get_bitlocker_status_from_reg(path: &Path) -> Vec<BitlockerVolume> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path.to_ascii_lowercase().contains("bitlocker")
            || r.path.to_ascii_lowercase().contains("\\fve\\")
    }) {
        let drive = record
            .values
            .get("MountPoint")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| key_leaf(&record.path));
        let protection_status = match record
            .values
            .get("ProtectionStatus")
            .and_then(|v| parse_reg_u32(v))
            .unwrap_or(0)
        {
            0 => "Off",
            1 => "On",
            2 => "Unknown",
            _ => "Unknown",
        }
        .to_string();
        let encryption_method = match record
            .values
            .get("EncryptionMethod")
            .and_then(|v| parse_reg_u32(v))
            .unwrap_or(0)
        {
            6 => "XTS-AES-128",
            7 => "XTS-AES-256",
            3 => "AES-128",
            4 => "AES-256",
            _ => "Unknown",
        }
        .to_string();

        out.push(BitlockerVolume {
            drive,
            protection_status,
            encryption_method,
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct BitlockerVolume {
    pub drive: String,
    pub protection_status: String,
    pub encryption_method: String,
}

pub fn get_recovery_passwords() -> Vec<RecoveryPassword> {
    get_recovery_passwords_from_reg(&default_reg_path("bitlocker.reg"))
}

pub fn get_recovery_passwords_from_reg(path: &Path) -> Vec<RecoveryPassword> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("recovery") || p.contains("keyprotector")
    }) {
        let volume = record
            .values
            .get("Volume")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| key_leaf(&record.path));
        let password_id = record
            .values
            .get("RecoveryPasswordId")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("RecoveryGuid")
                    .and_then(|v| decode_reg_string(v))
            })
            .unwrap_or_default();
        let created = record.values.get("Created").and_then(|v| parse_reg_u64(v));

        if !password_id.is_empty() || !volume.is_empty() {
            out.push(RecoveryPassword {
                volume,
                password_id,
                created,
            });
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct RecoveryPassword {
    pub volume: String,
    pub password_id: String,
    pub created: Option<u64>,
}

pub fn get_tpm_status() -> TpmStatusReg {
    get_tpm_status_from_reg(&default_reg_path("bitlocker.reg"))
}

pub fn get_tpm_status_from_reg(path: &Path) -> TpmStatusReg {
    let records = load_reg_records(path);
    if let Some(record) = records
        .iter()
        .find(|r| r.path.to_ascii_lowercase().contains("\\tpm"))
    {
        TpmStatusReg {
            present: record
                .values
                .get("TpmPresent")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            ready: record
                .values
                .get("TpmReady")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
            enabled: record
                .values
                .get("TpmEnabled")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
        }
    } else {
        TpmStatusReg::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct TpmStatusReg {
    pub present: bool,
    pub ready: bool,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_bitlocker_status() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bitlocker.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FVE\Volumes\{VOL}]
"MountPoint"="C:"
"ProtectionStatus"=dword:00000001
"EncryptionMethod"=dword:00000007
"#,
        )
        .unwrap();
        let rows = get_bitlocker_status_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].drive, "C:");
    }
}
