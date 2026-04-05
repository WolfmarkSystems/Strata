use crate::errors::ForensicError;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const BITLOCKER_METADATA_READ_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct BitlockerVolume {
    pub volume_guid: [u8; 16],
    pub encryption_method: BitlockerMethod,
    pub protection_status: ProtectionStatus,
    pub encrypted_metadata_size: u64,
    pub conversion_status: ConversionStatus,
    pub version: u8,
    pub key_protectors: Vec<KeyProtector>,
}

#[derive(Debug, Clone)]
pub enum BitlockerMethod {
    None,
    AES128Diffuser,
    AES256Diffuser,
    AES256,
    HardwareEncryption,
    XtsAES128,
    XtsAES256,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum ProtectionStatus {
    Unprotected,
    Protected,
    ProtectionSuspended,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum ConversionStatus {
    FullyEncrypted,
    FullyDecrypted,
    EncryptionInProgress,
    DecryptionInProgress,
    EncryptionPaused,
    DecryptionPaused,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum KeyProtector {
    Password(String),
    RecoveryPassword(String),
    TPM,
    TPMAndPIN,
    TPMAndStartupKey,
    TPMAndRecoveryPassword,
    ExternalKey,
    NumericPassword,
}

pub fn parse_bitlocker_metadata(partition_path: &Path) -> Result<BitlockerVolume, ForensicError> {
    let data = read_prefix(partition_path, BITLOCKER_METADATA_READ_BYTES)?;

    if data.len() < 512 {
        return Err(ForensicError::InvalidOffset);
    }

    if &data[0..4] != b"-FVE-FS" {
        return Err(ForensicError::UnsupportedFilesystem);
    }

    let mut volume = BitlockerVolume {
        volume_guid: [0u8; 16],
        encryption_method: BitlockerMethod::Unknown,
        protection_status: ProtectionStatus::Unknown,
        encrypted_metadata_size: 0,
        conversion_status: ConversionStatus::Unknown,
        version: 0,
        key_protectors: Vec::new(),
    };

    volume.version = data[4];

    let encryption_flags = u16::from_le_bytes([data[6], data[7]]);
    volume.encryption_method = match encryption_flags {
        0 => BitlockerMethod::None,
        1 => BitlockerMethod::AES128Diffuser,
        2 => BitlockerMethod::AES256Diffuser,
        3 => BitlockerMethod::AES256,
        4 => BitlockerMethod::HardwareEncryption,
        5 => BitlockerMethod::XtsAES128,
        6 => BitlockerMethod::XtsAES256,
        _ => BitlockerMethod::Unknown,
    };

    volume.conversion_status = match data[8] {
        0 => ConversionStatus::FullyDecrypted,
        1 => ConversionStatus::FullyEncrypted,
        2 => ConversionStatus::EncryptionInProgress,
        3 => ConversionStatus::DecryptionInProgress,
        4 => ConversionStatus::EncryptionPaused,
        5 => ConversionStatus::DecryptionPaused,
        _ => ConversionStatus::Unknown,
    };

    volume.protection_status = match data[9] {
        0 => ProtectionStatus::Unprotected,
        1 => ProtectionStatus::Protected,
        2 => ProtectionStatus::ProtectionSuspended,
        _ => ProtectionStatus::Unknown,
    };

    Ok(volume)
}

fn read_prefix(path: &Path, limit: usize) -> Result<Vec<u8>, ForensicError> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; limit];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

pub fn detect_bitlocker(partition_data: &[u8]) -> bool {
    if partition_data.len() < 512 {
        return false;
    }
    &partition_data[0..8] == b"-FVE-FS\0"
}

pub fn extract_recovery_password(partition_data: &[u8]) -> Option<String> {
    if partition_data.len() < 512 {
        return None;
    }

    if &partition_data[0..8] != b"-FVE-FS\0" {
        return None;
    }

    let mut offset = 256;
    while offset + 24 < partition_data.len() {
        if &partition_data[offset..offset + 4] == b"FVPK" {
            let protector_type =
                u16::from_le_bytes([partition_data[offset + 4], partition_data[offset + 5]]);

            if protector_type == 4 {
                return extract_numeric_password(&partition_data[offset..]);
            }
        }
        offset += 1;
    }
    None
}

fn extract_numeric_password(data: &[u8]) -> Option<String> {
    if data.len() < 24 {
        return None;
    }

    let password_data = &data[16..24];
    let mut password = String::new();

    for i in 0..8 {
        let digit = u16::from_le_bytes([password_data[i * 2], password_data[i * 2 + 1]]);
        password.push_str(&digit.to_string());
        if i < 7 {
            password.push('-');
        }
    }

    if password.len() == 39 {
        Some(password)
    } else {
        None
    }
}
