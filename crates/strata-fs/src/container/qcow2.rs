use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;
use flate2::read::ZlibDecoder;

pub fn open_qcow2(path: &Path) -> Result<Qcow2Container, ForensicError> {
    Qcow2Container::open(path)
}

pub struct Qcow2Container {
    pub path: PathBuf,
    pub file: File,
    pub magic: [u8; 4],
    pub version: u32,
    pub backing_file_offset: u64,
    pub backing_file_size: u32,
    pub cluster_bits: u32,
    pub size: u64,
    pub crypt_method: u32,
    pub l1_size: u32,
    pub l1_table_offset: u64,
}

impl Qcow2Container {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        let mut buf = [0u8; 72];
        let n = read_at(&file, 0, &mut buf)?;

        if n < 72 || &buf[0..4] != b"QFI\xfb" {
            return Err(ForensicError::InvalidImageFormat);
        }

        let magic = [buf[0], buf[1], buf[2], buf[3]];
        let version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let backing_file_offset = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        let backing_file_size = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        let cluster_bits = u32::from_be_bytes(buf[20..24].try_into().unwrap());
        let size = u64::from_be_bytes(buf[24..32].try_into().unwrap());
        let crypt_method = u32::from_be_bytes(buf[32..36].try_into().unwrap());
        let l1_size = u32::from_be_bytes(buf[36..40].try_into().unwrap());
        let l1_table_offset = u64::from_be_bytes(buf[40..48].try_into().unwrap());

        Ok(Self {
            path: path.to_path_buf(),
            file,
            magic,
            version,
            backing_file_offset,
            backing_file_size,
            cluster_bits,
            size,
            crypt_method,
            l1_size,
            l1_table_offset,
        })
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

impl EvidenceContainerRO for Qcow2Container {
    fn description(&self) -> &str {
        "QEMU QCOW2 Image"
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
        let length = buf.len() as u64;
        if length == 0 {
            return Ok(());
        }
        if offset >= self.size {
            return Err(
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read beyond EOF").into(),
            );
        }

        let cluster_size = 1u64 << self.cluster_bits;
        let mut remaining = length.min(self.size - offset);
        let mut current_pos = offset;
        let mut out_offset = 0usize;

        while remaining > 0 {
            let cluster_idx = current_pos / cluster_size;
            let offset_in_cluster = current_pos % cluster_size;
            let bytes_to_read = std::cmp::min(remaining, cluster_size - offset_in_cluster);

            let l1_idx = cluster_idx / (cluster_size / 8);
            let l2_idx = cluster_idx % (cluster_size / 8);

            if l1_idx >= self.l1_size as u64 {
                for i in 0..bytes_to_read as usize {
                    buf[out_offset + i] = 0;
                }
            } else {
                let mut l1_entry_buf = [0u8; 8];
                read_at(
                    &self.file,
                    self.l1_table_offset + l1_idx * 8,
                    &mut l1_entry_buf,
                )
                .map_err(ForensicError::Io)?;
                let l1_entry = u64::from_be_bytes(l1_entry_buf);
                let l2_table_offset = l1_entry & 0x00fffffffffffe00u64;

                if l2_table_offset == 0 {
                    for i in 0..bytes_to_read as usize {
                        buf[out_offset + i] = 0;
                    }
                } else {
                    let mut l2_entry_buf = [0u8; 8];
                    read_at(&self.file, l2_table_offset + l2_idx * 8, &mut l2_entry_buf)
                        .map_err(ForensicError::Io)?;
                    let l2_entry = u64::from_be_bytes(l2_entry_buf);
                    let cluster_offset = l2_entry & 0x00fffffffffffe00u64;
                    let is_compressed = (l2_entry & (1u64 << 62)) != 0;

                    if cluster_offset == 0 {
                        for i in 0..bytes_to_read as usize {
                            buf[out_offset + i] = 0;
                        }
                    } else if is_compressed {
                        let cluster = read_compressed_cluster(
                            &self.file,
                            cluster_offset,
                            cluster_size as usize,
                        )?;
                        let start = offset_in_cluster as usize;
                        let end = start
                            .saturating_add(bytes_to_read as usize)
                            .min(cluster.len());
                        let chunk = &cluster[start..end];
                        buf[out_offset..out_offset + chunk.len()].copy_from_slice(chunk);
                        if chunk.len() < bytes_to_read as usize {
                            buf[out_offset + chunk.len()..out_offset + bytes_to_read as usize]
                                .fill(0);
                        }
                    } else {
                        let n = read_at(
                            &self.file,
                            cluster_offset + offset_in_cluster,
                            &mut buf[out_offset..out_offset + bytes_to_read as usize],
                        )
                        .map_err(ForensicError::Io)?;
                        if n < bytes_to_read as usize {
                            for i in n..bytes_to_read as usize {
                                buf[out_offset + i] = 0;
                            }
                        }
                    }
                }
            }

            current_pos += bytes_to_read;
            remaining -= bytes_to_read;
            out_offset += bytes_to_read as usize;
        }

        Ok(())
    }
}

fn read_compressed_cluster(
    file: &File,
    cluster_offset: u64,
    cluster_size: usize,
) -> Result<Vec<u8>, ForensicError> {
    let mut reader = file.try_clone().map_err(ForensicError::Io)?;
    reader
        .seek(SeekFrom::Start(cluster_offset))
        .map_err(ForensicError::Io)?;

    let mut compressed = Vec::new();
    reader
        .read_to_end(&mut compressed)
        .map_err(ForensicError::Io)?;

    let mut decoder = ZlibDecoder::new(&compressed[..]);
    let mut decompressed = Vec::with_capacity(cluster_size);
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| ForensicError::Container(format!("QCOW2 zlib decode failed: {e}")))?;

    if decompressed.len() < cluster_size {
        decompressed.resize(cluster_size, 0);
    } else if decompressed.len() > cluster_size {
        decompressed.truncate(cluster_size);
    }
    Ok(decompressed)
}
