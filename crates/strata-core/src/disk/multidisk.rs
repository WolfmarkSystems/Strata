use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum RaidType {
    RAID0,
    RAID1,
    RAID5,
    RAID6,
    RAID10,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DiskSet {
    pub images: Vec<PathBuf>,
    pub raid_type: RaidType,
    pub stripe_size: u32,
    pub order: u32,
}

impl DiskSet {
    pub fn linear(images: Vec<PathBuf>) -> Self {
        Self {
            images,
            raid_type: RaidType::Unknown,
            stripe_size: 0,
            order: 0,
        }
    }

    pub fn raid0(images: Vec<PathBuf>, stripe_size: u32) -> Self {
        Self {
            images,
            raid_type: RaidType::RAID0,
            stripe_size,
            order: 0,
        }
    }

    pub fn raid1(images: Vec<PathBuf>) -> Self {
        Self {
            images,
            raid_type: RaidType::RAID1,
            stripe_size: 0,
            order: 0,
        }
    }

    pub fn total_size(&self, individual_size: u64) -> u64 {
        match self.raid_type {
            RaidType::RAID0 => individual_size * (self.images.len() as u64),
            RaidType::RAID1 => individual_size,
            RaidType::RAID5 => individual_size * ((self.images.len() - 1) as u64),
            RaidType::RAID6 => individual_size * ((self.images.len() - 2) as u64),
            RaidType::RAID10 => individual_size * ((self.images.len() / 2) as u64),
            _ => individual_size * (self.images.len() as u64),
        }
    }
}

pub fn detect_raid_config(images: &[PathBuf]) -> Option<DiskSet> {
    if images.is_empty() {
        return None;
    }

    let count = images.len();

    if count == 1 {
        return Some(DiskSet::linear(images.to_vec()));
    }

    let metadata_files: Vec<_> = images
        .iter()
        .filter_map(|p| {
            let name = p.file_stem()?.to_str()?;
            if name.contains("disk1") || name.contains("disk01") || name.contains("01") {
                Some(1)
            } else if name.contains("disk2") || name.contains("disk02") || name.contains("02") {
                Some(2)
            } else {
                name.chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .ok()
            }
        })
        .collect();

    if metadata_files.len() == count {
        return Some(DiskSet::linear(images.to_vec()));
    }

    Some(DiskSet::linear(images.to_vec()))
}

pub fn read_from_disk_set<C: crate::container::EvidenceContainerRO>(
    _disk_set: &DiskSet,
    _container: &C,
    _offset: u64,
    _length: u64,
) -> Result<Vec<u8>, crate::errors::ForensicError> {
    Err(crate::errors::ForensicError::InvalidImageFormat)
}
