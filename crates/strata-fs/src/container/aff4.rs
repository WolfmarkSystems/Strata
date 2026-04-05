use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;
use zip::ZipArchive;

pub fn open_aff4(path: &Path) -> Result<Aff4Container, ForensicError> {
    Aff4Container::open(path)
}

pub struct Aff4Container {
    pub path: PathBuf,
    pub archive: Mutex<ZipArchive<File>>,
    pub size: u64,
    pub streams: Vec<Aff4Stream>,
}

#[derive(Debug, Clone)]
pub struct Aff4DirectoryEntry {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

impl Aff4Container {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let archive_file_size = file.metadata()?.len();
        let mut archive = ZipArchive::new(file).map_err(|_| ForensicError::InvalidImageFormat)?;
        let mut streams = Vec::new();

        for i in 0..archive.len() {
            if let Ok(member) = archive.by_index(i) {
                if member.is_dir() {
                    continue;
                }
                let name = member.name().to_string();
                if is_aff4_metadata_member(&name) {
                    continue;
                }
                streams.push(Aff4Stream {
                    urn: name.clone(),
                    size: member.size(),
                    member_name: name,
                });
            }
        }

        streams.sort_by(|a, b| b.size.cmp(&a.size));
        let size = streams.first().map(|s| s.size).unwrap_or(archive_file_size);

        Ok(Self {
            path: path.to_path_buf(),
            archive: Mutex::new(archive),
            size,
            streams,
        })
    }

    fn normalize_member_path(path: &str) -> String {
        path.replace('\\', "/").trim_matches('/').to_string()
    }

    fn display_path(path: &str) -> String {
        if path.is_empty() {
            "/".to_string()
        } else {
            format!("/{path}")
        }
    }

    fn is_unsupported_stream(path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        lower.contains("encrypted") || lower.ends_with(".aes") || lower.contains("aes256")
    }

    pub fn read_directory(&self, path: &str) -> Result<Vec<Aff4DirectoryEntry>, ForensicError> {
        let normalized = Self::normalize_member_path(path);
        let prefix = if normalized.is_empty() {
            String::new()
        } else {
            format!("{normalized}/")
        };
        let prefix_lower = prefix.to_ascii_lowercase();

        let mut entries: BTreeMap<String, Aff4DirectoryEntry> = BTreeMap::new();

        for stream in &self.streams {
            let member_path = Self::normalize_member_path(&stream.member_name);
            if Self::is_unsupported_stream(&member_path) {
                return Err(ForensicError::UnsupportedParser(
                    "AFF4 encryption not supported".to_string(),
                ));
            }

            let member_lower = member_path.to_ascii_lowercase();
            let remainder = if normalized.is_empty() {
                member_path.as_str()
            } else {
                if !member_lower.starts_with(&prefix_lower) {
                    continue;
                }
                &member_path[prefix.len()..]
            };

            if remainder.is_empty() {
                continue;
            }

            if let Some((segment, _)) = remainder.split_once('/') {
                let child_path = if normalized.is_empty() {
                    segment.to_string()
                } else {
                    format!("{normalized}/{segment}")
                };
                entries
                    .entry(child_path.to_ascii_lowercase())
                    .or_insert_with(|| Aff4DirectoryEntry {
                        path: Self::display_path(&child_path),
                        name: segment.to_string(),
                        is_dir: true,
                        size: 0,
                    });
            } else {
                entries
                    .entry(member_path.to_ascii_lowercase())
                    .or_insert_with(|| Aff4DirectoryEntry {
                        path: Self::display_path(&member_path),
                        name: remainder.to_string(),
                        is_dir: false,
                        size: stream.size,
                    });
            }
        }

        Ok(entries.into_values().collect())
    }

    pub fn read_member(&self, path: &str) -> Result<Vec<u8>, ForensicError> {
        let normalized = Self::normalize_member_path(path);
        if normalized.is_empty() {
            return Err(ForensicError::NotFound("/".to_string()));
        }
        if Self::is_unsupported_stream(&normalized) {
            return Err(ForensicError::UnsupportedParser(
                "AFF4 encryption not supported".to_string(),
            ));
        }

        let member_name = self
            .streams
            .iter()
            .find(|stream| {
                Self::normalize_member_path(&stream.member_name).eq_ignore_ascii_case(&normalized)
            })
            .map(|stream| stream.member_name.clone())
            .ok_or_else(|| ForensicError::NotFound(Self::display_path(&normalized)))?;

        let mut archive = self
            .archive
            .lock()
            .map_err(|_| ForensicError::Io(std::io::Error::other("AFF4 archive lock failed")))?;
        let mut stream = archive
            .by_name(&member_name)
            .map_err(|e| ForensicError::Container(format!("AFF4 stream lookup failed: {e}")))?;

        let mut data = Vec::with_capacity(stream.size() as usize);
        stream
            .read_to_end(&mut data)
            .map_err(|e| ForensicError::Container(format!("AFF4 stream read failed: {e}")))?;
        Ok(data)
    }

    pub fn metadata_for_path(&self, path: &str) -> Result<Aff4DirectoryEntry, ForensicError> {
        let normalized = Self::normalize_member_path(path);
        if normalized.is_empty() {
            return Ok(Aff4DirectoryEntry {
                path: "/".to_string(),
                name: "/".to_string(),
                is_dir: true,
                size: self.size,
            });
        }

        if let Some(stream) = self.streams.iter().find(|stream| {
            Self::normalize_member_path(&stream.member_name).eq_ignore_ascii_case(&normalized)
        }) {
            return Ok(Aff4DirectoryEntry {
                path: Self::display_path(&normalized),
                name: normalized
                    .rsplit('/')
                    .next()
                    .unwrap_or(&normalized)
                    .to_string(),
                is_dir: false,
                size: stream.size,
            });
        }

        let children = self.read_directory(&normalized)?;
        if !children.is_empty() {
            return Ok(Aff4DirectoryEntry {
                path: Self::display_path(&normalized),
                name: normalized
                    .rsplit('/')
                    .next()
                    .unwrap_or(&normalized)
                    .to_string(),
                is_dir: true,
                size: 0,
            });
        }

        Err(ForensicError::NotFound(Self::display_path(&normalized)))
    }
}

impl EvidenceContainerRO for Aff4Container {
    fn description(&self) -> &str {
        "AFF4 Forensic Container"
    }
    fn source_path(&self) -> &Path {
        &self.path
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u64 {
        512
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut archive = self
            .archive
            .lock()
            .map_err(|_| ForensicError::Io(std::io::Error::other("AFF4 archive lock failed")))?;

        let Some(primary_stream) = self.streams.first() else {
            buf.fill(0);
            return Ok(());
        };

        let mut stream = archive
            .by_name(&primary_stream.member_name)
            .map_err(|e| ForensicError::Container(format!("AFF4 stream lookup failed: {e}")))?;

        let mut remaining_skip = offset;
        let mut discard = [0u8; 8192];
        while remaining_skip > 0 {
            let to_read = remaining_skip.min(discard.len() as u64) as usize;
            let n = stream
                .read(&mut discard[..to_read])
                .map_err(|e| ForensicError::Container(format!("AFF4 offset skip failed: {e}")))?;
            if n == 0 {
                buf.fill(0);
                return Ok(());
            }
            remaining_skip -= n as u64;
        }

        let mut filled = 0usize;
        while filled < buf.len() {
            let n = stream
                .read(&mut buf[filled..])
                .map_err(|e| ForensicError::Container(format!("AFF4 stream read failed: {e}")))?;
            if n == 0 {
                break;
            }
            filled += n;
        }

        if filled < buf.len() {
            buf[filled..].fill(0);
        }
        Ok(())
    }
}

pub struct Aff4Stream {
    pub urn: String,
    pub size: u64,
    pub member_name: String,
}

fn is_aff4_metadata_member(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".turtle")
        || lower.ends_with(".rdf")
        || lower.ends_with(".map")
        || lower.contains("information")
        || lower.contains("metadata")
}
