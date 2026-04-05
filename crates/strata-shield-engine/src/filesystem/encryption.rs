use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

#[derive(Debug, Clone)]
pub enum EncryptionType {
    BitLocker,
    LUKS,
    FileVault,
    TrueCrypt,
    VeraCrypt,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct EncryptionDetection {
    pub encryption_type: EncryptionType,
    pub offset: u64,
    pub confidence: f32,
    pub description: String,
}

pub fn detect_encryption<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
) -> Result<Option<EncryptionDetection>, ForensicError> {
    let sector_size = container.sector_size();
    if sector_size == 0 {
        return Ok(None);
    }

    let read_len = (sector_size * 2).min(container.size().saturating_sub(volume_base_offset));
    if read_len < sector_size {
        return Ok(None);
    }

    let data = container.read_at(volume_base_offset, read_len)?;

    if data.len() >= 512 && (data[0..11] == b"-FVE-FS-"[..] || data[3..11] == b"FVE-FS-"[..]) {
        return Ok(Some(EncryptionDetection {
            encryption_type: EncryptionType::BitLocker,
            offset: volume_base_offset,
            confidence: 0.95,
            description: "BitLocker To Go detected".to_string(),
        }));
    }

    let sector_17_offset = 17 * 512;
    if data.len() >= sector_17_offset + 8
        && data[sector_17_offset..sector_17_offset + 8] == b"LUKS\xBA\xBE\x00\x00"[..]
    {
        return Ok(Some(EncryptionDetection {
            encryption_type: EncryptionType::LUKS,
            offset: volume_base_offset + sector_17_offset as u64,
            confidence: 0.99,
            description: "LUKS encryption detected".to_string(),
        }));
    }

    if data.len() >= 512 && data[0..6] == b"ApplFS"[..] {
        return Ok(Some(EncryptionDetection {
            encryption_type: EncryptionType::FileVault,
            offset: volume_base_offset,
            confidence: 0.9,
            description: "Apple FileVault detected".to_string(),
        }));
    }

    if data.len() >= 512 && (data[0..4] == b"TCSD"[..] || data[0..4] == b"VERA"[..]) {
        return Ok(Some(EncryptionDetection {
            encryption_type: EncryptionType::VeraCrypt,
            offset: volume_base_offset,
            confidence: 0.85,
            description: "TrueCrypt/VeraCrypt container detected".to_string(),
        }));
    }

    Ok(None)
}

pub fn detect_encryption_at_offset<C: EvidenceContainerRO>(
    container: &C,
    offset: u64,
) -> Result<Option<EncryptionDetection>, ForensicError> {
    let read_len = 18 * 512;
    if offset + read_len > container.size() {
        return Ok(None);
    }

    let data = container.read_at(offset, read_len)?;

    if data.len() >= 512 && (data[0..11] == b"-FVE-FS-"[..] || data[3..11] == b"FVE-FS-"[..]) {
        return Ok(Some(EncryptionDetection {
            encryption_type: EncryptionType::BitLocker,
            offset,
            confidence: 0.95,
            description: "BitLocker To Go detected".to_string(),
        }));
    }

    if data.len() >= 18 * 512 && data[17 * 512..17 * 512 + 8] == b"LUKS\xBA\xBE\x00\x00"[..] {
        return Ok(Some(EncryptionDetection {
            encryption_type: EncryptionType::LUKS,
            offset: offset + (17 * 512) as u64,
            confidence: 0.99,
            description: "LUKS encryption detected".to_string(),
        }));
    }

    Ok(None)
}
