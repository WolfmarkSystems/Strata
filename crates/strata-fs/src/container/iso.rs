use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

#[derive(Debug, Clone)]
pub struct IsoDirectoryEntry {
    pub name: String,
    pub lba: u32,
    pub size: u32,
    pub is_dir: bool,
}

pub struct IsoContainer {
    pub path: PathBuf,
    pub size: u64,
    pub root_lba: u32,
    pub root_size: u32,
    pub joliet: bool,
}

impl IsoContainer {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();

        let mut root_lba = 0u32;
        let mut root_size = 0u32;
        let mut joliet = false;
        let mut found_primary = false;

        // Volume descriptors start at sector 16.
        for sector in 16u64..=128 {
            let mut vd = [0u8; 2048];
            read_at(&file, sector * 2048, &mut vd).map_err(ForensicError::Io)?;
            let vd_type = vd[0];

            if &vd[1..6] != b"CD001" {
                if sector == 16 {
                    return Err(ForensicError::InvalidImageFormat);
                }
                continue;
            }

            if vd_type == 255 {
                break;
            }

            if vd_type == 1 && !found_primary {
                if let Some((lba, size)) = parse_root_directory_entry(&vd) {
                    root_lba = lba;
                    root_size = size;
                    found_primary = true;
                }
            }

            // Supplementary Volume Descriptor + Joliet escape sequence (%/@, %/C, %/E)
            if vd_type == 2 && is_joliet_descriptor(&vd) {
                if let Some((lba, size)) = parse_root_directory_entry(&vd) {
                    root_lba = lba;
                    root_size = size;
                    joliet = true;
                }
            }
        }

        if root_size == 0 {
            return Err(ForensicError::InvalidImageFormat);
        }

        Ok(Self {
            path: path.to_path_buf(),
            size,
            root_lba,
            root_size,
            joliet,
        })
    }

    pub fn read_directory(
        &self,
        lba: u32,
        size: u32,
    ) -> Result<Vec<IsoDirectoryEntry>, ForensicError> {
        let file = File::open(&self.path)?;
        let mut data = vec![0u8; size as usize];
        read_at(&file, lba as u64 * 2048, &mut data).map_err(ForensicError::Io)?;

        let mut entries = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let entry_len = data[offset] as usize;
            if entry_len == 0 {
                // End of directory block (entries are padded to sector boundaries usually, but check)
                let remaining_in_sector = 2048 - (offset % 2048);
                if remaining_in_sector > 0 && offset + remaining_in_sector < data.len() {
                    offset += remaining_in_sector;
                    continue;
                }
                break;
            }

            if offset + entry_len > data.len() {
                break;
            }

            let entry = &data[offset..offset + entry_len];
            let name_len = entry[32] as usize;
            let flags = entry[25];
            let is_dir = (flags & 2) != 0;
            let lba = u32::from_le_bytes(entry[2..6].try_into().unwrap());
            let size = u32::from_le_bytes(entry[10..14].try_into().unwrap());

            let name_bytes = &entry[33..33 + name_len];
            let name = if name_bytes == [0] {
                ".".to_string()
            } else if name_bytes == [1] {
                "..".to_string()
            } else {
                decode_iso_name(name_bytes, self.joliet)
            };

            if name != "." && name != ".." {
                entries.push(IsoDirectoryEntry {
                    name,
                    lba,
                    size,
                    is_dir,
                });
            }

            offset += entry_len;
        }

        Ok(entries)
    }
}

fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    #[cfg(unix)]
    {
        file.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        file.seek_read(buf, offset)
    }
}

impl EvidenceContainerRO for IsoContainer {
    fn description(&self) -> &str {
        "ISO Optical Media Image"
    }

    fn source_path(&self) -> &Path {
        &self.path
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn sector_size(&self) -> u64 {
        2048
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        let file = File::open(&self.path)?;
        let mut filled = 0usize;

        while filled < buf.len() {
            let read_offset = offset + filled as u64;
            let n = read_at(&file, read_offset, &mut buf[filled..]).map_err(ForensicError::Io)?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        Ok(())
    }
}

fn parse_root_directory_entry(vd: &[u8; 2048]) -> Option<(u32, u32)> {
    let root_entry = vd.get(156..190)?;
    if root_entry.first().copied().unwrap_or(0) < 34 {
        return None;
    }
    let lba = u32::from_le_bytes(root_entry[2..6].try_into().ok()?);
    let size = u32::from_le_bytes(root_entry[10..14].try_into().ok()?);
    Some((lba, size))
}

fn is_joliet_descriptor(vd: &[u8; 2048]) -> bool {
    let esc = &vd[88..91];
    esc == b"%/@" || esc == b"%/C" || esc == b"%/E"
}

fn decode_iso_name(name_bytes: &[u8], joliet: bool) -> String {
    if joliet && name_bytes.len() >= 2 {
        let mut u16s = Vec::with_capacity(name_bytes.len() / 2);
        for chunk in name_bytes.chunks_exact(2) {
            u16s.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        let mut s = String::from_utf16_lossy(&u16s);
        if let Some(pos) = s.find(';') {
            s.truncate(pos);
        }
        return s;
    }

    String::from_utf8_lossy(name_bytes)
        .split(';')
        .next()
        .unwrap_or("")
        .to_string()
}
