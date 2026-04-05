use crate::container::layout::DiskLayout;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

pub fn detect_disk_layout<C: EvidenceContainerRO>(
    container: &C,
) -> Result<DiskLayout, ForensicError> {
    // Read first sector
    let sector = container.sector_size();
    let data = container.read_at(0, sector)?;

    // MBR signature at offset 510–511
    if data.len() >= 512 && data[510] == 0x55 && data[511] == 0xAA {
        // GPT has protective MBR + GPT header at LBA 1
        let gpt_header = container.read_at(sector, sector)?;

        if gpt_header.len() >= 8 && &gpt_header[0..8] == b"EFI PART" {
            return Ok(DiskLayout::GPT);
        }

        return Ok(DiskLayout::MBR);
    }

    Ok(DiskLayout::Unknown)
}
