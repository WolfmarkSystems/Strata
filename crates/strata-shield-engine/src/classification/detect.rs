use super::layout::DiskLayout;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

pub fn detect_layout<C: EvidenceContainerRO>(container: &C) -> Result<DiskLayout, ForensicError> {
    let sector_size = container.sector_size();

    // Read first sector
    let boot_sector = container.read_at(0, sector_size)?;

    // GPT signature at LBA 1 ("EFI PART")
    if container.size() >= sector_size * 2 {
        let gpt_header = container.read_at(sector_size, sector_size)?;
        if &gpt_header[0..8] == b"EFI PART" {
            return Ok(DiskLayout::GPT);
        }
    }

    // MBR signature 0x55AA at bytes 510–511
    if boot_sector.len() >= 512 && boot_sector[510] == 0x55 && boot_sector[511] == 0xAA {
        return Ok(DiskLayout::MBR);
    }

    Ok(DiskLayout::Raw)
}
