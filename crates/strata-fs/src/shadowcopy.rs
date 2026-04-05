use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

#[derive(Debug, Clone)]
pub enum ShadowCopyType {
    VSS,
    VSSProvider,
    ShadowVolume,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ShadowCopyInfo {
    pub copy_type: ShadowCopyType,
    pub offset: u64,
    pub size: Option<u64>,
    pub description: String,
}

pub fn detect_shadow_copies<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    volume_size: u64,
) -> Result<Vec<ShadowCopyInfo>, ForensicError> {
    let mut results = Vec::new();
    let sector_size = container.sector_size();

    if sector_size == 0 {
        return Ok(results);
    }

    let vss_offset = volume_base_offset + (volume_size - (64 * 1024 * 1024));
    if vss_offset + (sector_size * 2) <= container.size() {
        if let Ok(data) = container.read_at(vss_offset, sector_size * 2) {
            if data.len() >= 512 && (data[0..4] == b"VSS\x00"[..] || data[4..8] == b"VSS\x00"[..]) {
                results.push(ShadowCopyInfo {
                    copy_type: ShadowCopyType::VSS,
                    offset: vss_offset,
                    size: Some(64 * 1024 * 1024),
                    description: "Volume Shadow Copy detected".to_string(),
                });
            }
        }
    }

    let config_offset = volume_base_offset + (2 * 1024 * 1024 * 1024);
    if config_offset + (sector_size * 16) <= container.size() {
        if let Ok(data) = container.read_at(config_offset, sector_size * 16) {
            if data.len() >= 16 && (data[0..4] == b"STOC"[..] || data[0..4] == b"toc1"[..]) {
                results.push(ShadowCopyInfo {
                    copy_type: ShadowCopyType::ShadowVolume,
                    offset: config_offset,
                    size: None,
                    description: "Shadow volume structure detected".to_string(),
                });
            }
        }
    }

    Ok(results)
}

pub fn list_shadow_volume_offsets<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    max_shadows: u32,
) -> Result<Vec<u64>, ForensicError> {
    let mut offsets = Vec::new();
    let sector_size = container.sector_size();

    if sector_size == 0 {
        return Ok(offsets);
    }

    let header_offset = volume_base_offset + 0x180000;
    let read_size = (sector_size * 256).min(container.size().saturating_sub(header_offset));

    if read_size < sector_size {
        return Ok(offsets);
    }

    if let Ok(data) = container.read_at(header_offset, read_size) {
        for i in (0..data.len() - 32).step_by(512) {
            if i >= (max_shadows * 512) as usize {
                break;
            }

            if data.len() > i + 32
                && (data[i..i + 4] == b"VSS\x00"[..] || data[i..i + 4] == b"vSS\x00"[..])
            {
                let offset = header_offset + i as u64;
                offsets.push(offset);
            }
        }
    }

    Ok(offsets)
}
