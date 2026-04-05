use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;
use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

pub struct SplitRawPart {
    pub path: PathBuf,
    pub file: File,
    pub size: u64,
    pub global_offset: u64,
}

pub struct SplitRawContainer {
    pub parts: Vec<SplitRawPart>,
    pub total_size: u64,
}

impl SplitRawContainer {
    pub fn open(first_part: &Path) -> Result<Self, ForensicError> {
        let mut parts = Vec::new();
        let mut total_size = 0u64;

        let Some(ext) = first_part.extension().and_then(|e| e.to_str()) else {
            // Not a recognized split pattern, just open as single raw?
            // Caller should have checked, but let's be safe.
            let file = File::open(first_part)?;
            let size = file.metadata()?.len();
            parts.push(SplitRawPart {
                path: first_part.to_path_buf(),
                file,
                size,
                global_offset: 0,
            });
            return Ok(Self {
                parts,
                total_size: size,
            });
        };
        let ext = ext.to_ascii_lowercase();
        let stem = first_part
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let parent = first_part.parent().unwrap_or_else(|| Path::new("."));

        let pattern = if ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
            SplitPattern::Numeric3(ext.parse::<u32>().unwrap_or(1))
        } else if ext.len() == 3
            && ext.starts_with('r')
            && ext[1..].chars().all(|c| c.is_ascii_digit())
        {
            SplitPattern::Rxx(ext[1..].parse::<u32>().unwrap_or(1))
        } else if ext.len() == 2
            && ext.starts_with('a')
            && ext.chars().all(|c| c.is_ascii_lowercase())
        {
            SplitPattern::Alpha2(alpha_to_index(&ext))
        } else {
            let file = File::open(first_part)?;
            let size = file.metadata()?.len();
            parts.push(SplitRawPart {
                path: first_part.to_path_buf(),
                file,
                size,
                global_offset: 0,
            });
            return Ok(Self {
                parts,
                total_size: size,
            });
        };

        let mut i = pattern.start_index();
        loop {
            let candidate_name = match pattern {
                SplitPattern::Numeric3(_) => format!("{stem}.{i:03}"),
                SplitPattern::Rxx(_) => format!("{stem}.r{i:02}"),
                SplitPattern::Alpha2(_) => {
                    let Some(ext2) = index_to_alpha(i) else {
                        break;
                    };
                    format!("{stem}.{ext2}")
                }
            };
            let current_path = parent.join(candidate_name);

            if !current_path.exists() {
                break;
            }

            let file = File::open(&current_path)?;
            let size = file.metadata()?.len();
            parts.push(SplitRawPart {
                path: current_path.to_path_buf(),
                file,
                size,
                global_offset: total_size,
            });
            total_size += size;
            i += 1;
        }

        if parts.is_empty() {
            return Err(ForensicError::NotFound(format!(
                "No split parts found for {}",
                first_part.display()
            )));
        }

        Ok(Self { parts, total_size })
    }
}

#[derive(Clone, Copy)]
enum SplitPattern {
    Numeric3(u32),
    Rxx(u32),
    Alpha2(u32),
}

impl SplitPattern {
    fn start_index(self) -> u32 {
        match self {
            SplitPattern::Numeric3(v) | SplitPattern::Rxx(v) | SplitPattern::Alpha2(v) => v,
        }
    }
}

fn alpha_to_index(ext: &str) -> u32 {
    let bytes = ext.as_bytes();
    if bytes.len() != 2 {
        return 0;
    }
    ((bytes[0] - b'a') as u32) * 26 + (bytes[1] - b'a') as u32
}

fn index_to_alpha(index: u32) -> Option<String> {
    if index >= 26 * 26 {
        return None;
    }
    let high = ((index / 26) as u8) + b'a';
    let low = ((index % 26) as u8) + b'a';
    Some(format!("{}{}", high as char, low as char))
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

impl EvidenceContainerRO for SplitRawContainer {
    fn description(&self) -> &str {
        "Split RAW/DD Image"
    }

    fn source_path(&self) -> &Path {
        &self.parts[0].path
    }

    fn size(&self) -> u64 {
        self.total_size
    }

    fn sector_size(&self) -> u64 {
        512 // Default for RAW
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        let length = buf.len() as u64;
        if length == 0 {
            return Ok(());
        }

        if offset + length > self.total_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "read beyond split container boundaries",
            )
            .into());
        }

        let mut remaining = length;
        let mut current_offset = offset;
        let mut out_idx = 0usize;

        while remaining > 0 {
            // Find which part contains current_offset
            let part = self
                .parts
                .iter()
                .find(|p| {
                    current_offset >= p.global_offset && current_offset < p.global_offset + p.size
                })
                .ok_or_else(|| {
                    ForensicError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Offset not found in any split part",
                    ))
                })?;

            let offset_in_part = current_offset - part.global_offset;
            let bytes_to_read = std::cmp::min(remaining, part.size - offset_in_part);

            let mut filled = 0usize;
            let target_len = bytes_to_read as usize;
            while filled < target_len {
                let n = read_at(
                    &part.file,
                    offset_in_part + filled as u64,
                    &mut buf[out_idx + filled..out_idx + target_len],
                )
                .map_err(ForensicError::Io)?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "short read in split part",
                    )
                    .into());
                }
                filled += n;
            }

            current_offset += bytes_to_read;
            remaining -= bytes_to_read;
            out_idx += target_len;
        }

        Ok(())
    }
}
