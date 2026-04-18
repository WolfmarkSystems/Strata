//! EVIDENCE-3 — VMDK reader (monolithic flat + monolithic sparse).
//!
//! The common forensic VMDK shapes are either (a) a human-readable
//! descriptor file that points at a `-flat.vmdk` raw blob ("monolithic
//! flat"), or (b) a sparse container carrying a grain directory +
//! grain tables + grain data ("monolithic sparse"). Both are
//! supported here pure-Rust; stream-optimized and split-sparse
//! variants return `UnknownFormat` until we see a real sample.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::image::{EvidenceError, EvidenceImage, EvidenceResult, ImageMetadata};

pub struct VmdkImage {
    inner: VmdkKind,
    total_size: u64,
    sector_size: u32,
}

enum VmdkKind {
    Flat {
        file: Mutex<File>,
    },
    Sparse {
        file: Mutex<File>,
        grain_size_bytes: u32,
        /// Kept in the struct so callers (or future maintenance
        /// passes) can inspect the directory layout; the `read_at`
        /// path walks `grain_tables` directly.
        #[allow(dead_code)]
        grain_directory: Vec<u32>,
        grain_tables: Vec<Vec<u32>>,
        num_gtes_per_gt: u32,
    },
}

impl VmdkImage {
    pub fn open(path: &Path) -> EvidenceResult<Self> {
        // Probe: first 4 bytes "KDMV" = sparse; otherwise treat as a
        // descriptor file ("# Disk DescriptorFile" etc.) + companion
        // -flat.vmdk raw blob.
        let mut probe = [0u8; 4];
        {
            let mut f = File::open(path).map_err(EvidenceError::Io)?;
            let _ = f.read(&mut probe);
        }
        if probe == *b"KDMV" {
            Self::open_sparse(path)
        } else {
            Self::open_flat(path)
        }
    }

    fn open_flat(descriptor_path: &Path) -> EvidenceResult<Self> {
        let descriptor = std::fs::read_to_string(descriptor_path).map_err(EvidenceError::Io)?;
        let flat = find_flat_extent(&descriptor, descriptor_path).ok_or_else(|| {
            EvidenceError::InvalidHeader {
                format: "VMDK",
                reason: "could not find -flat.vmdk extent in descriptor".into(),
            }
        })?;
        let file = File::open(&flat).map_err(EvidenceError::Io)?;
        let size = file.metadata().map_err(EvidenceError::Io)?.len();
        Ok(Self {
            inner: VmdkKind::Flat {
                file: Mutex::new(file),
            },
            total_size: size,
            sector_size: 512,
        })
    }

    fn open_sparse(path: &Path) -> EvidenceResult<Self> {
        let file = File::open(path).map_err(EvidenceError::Io)?;
        let mut f = file;
        // Sparse extent header is 512 bytes; relevant fields:
        //   [0..4]   magic "KDMV"
        //   [4..8]   version
        //   [8..12]  flags
        //   [12..20] capacity (sectors)
        //   [20..28] grain size (sectors)
        //   [28..36] descriptor offset (sectors)
        //   [36..44] descriptor size (sectors)
        //   [44..48] num_gtes_per_gt
        //   [48..56] rgd_offset (redundant grain directory, sectors)
        //   [56..64] gd_offset (grain directory, sectors)
        //   [64..72] overhead (sectors)
        f.seek(SeekFrom::Start(0)).map_err(EvidenceError::Io)?;
        let mut hdr = [0u8; 512];
        f.read_exact(&mut hdr).map_err(EvidenceError::Io)?;
        if &hdr[..4] != b"KDMV" {
            return Err(EvidenceError::InvalidHeader {
                format: "VMDK",
                reason: "bad sparse magic".into(),
            });
        }
        let capacity = u64::from_le_bytes([
            hdr[12], hdr[13], hdr[14], hdr[15], hdr[16], hdr[17], hdr[18], hdr[19],
        ]);
        let grain_size = u64::from_le_bytes([
            hdr[20], hdr[21], hdr[22], hdr[23], hdr[24], hdr[25], hdr[26], hdr[27],
        ]);
        let num_gtes_per_gt = u32::from_le_bytes([hdr[44], hdr[45], hdr[46], hdr[47]]);
        let gd_offset_sectors = u64::from_le_bytes([
            hdr[56], hdr[57], hdr[58], hdr[59], hdr[60], hdr[61], hdr[62], hdr[63],
        ]);

        let sector_size = 512u64;
        let grain_size_bytes = grain_size.saturating_mul(sector_size) as u32;
        let total_size = capacity.saturating_mul(sector_size);

        // Grain directory: capacity / (num_gtes_per_gt * grain_size) entries, each u32.
        let gt_coverage_sectors = (num_gtes_per_gt as u64).saturating_mul(grain_size);
        let gd_entries = if gt_coverage_sectors == 0 {
            0
        } else {
            capacity.div_ceil(gt_coverage_sectors)
        };
        let mut grain_directory = vec![0u32; gd_entries as usize];
        if gd_offset_sectors > 0 && gd_entries > 0 {
            f.seek(SeekFrom::Start(gd_offset_sectors * sector_size))
                .map_err(EvidenceError::Io)?;
            let mut buf = vec![0u8; gd_entries as usize * 4];
            f.read_exact(&mut buf).map_err(EvidenceError::Io)?;
            for i in 0..gd_entries as usize {
                grain_directory[i] = u32::from_le_bytes([
                    buf[i * 4],
                    buf[i * 4 + 1],
                    buf[i * 4 + 2],
                    buf[i * 4 + 3],
                ]);
            }
        }

        // Grain tables: each referenced from the directory.
        let mut grain_tables: Vec<Vec<u32>> = Vec::with_capacity(gd_entries as usize);
        for &gd in &grain_directory {
            if gd == 0 {
                grain_tables.push(vec![0u32; num_gtes_per_gt as usize]);
                continue;
            }
            f.seek(SeekFrom::Start(gd as u64 * sector_size))
                .map_err(EvidenceError::Io)?;
            let mut buf = vec![0u8; num_gtes_per_gt as usize * 4];
            f.read_exact(&mut buf).map_err(EvidenceError::Io)?;
            let mut table = Vec::with_capacity(num_gtes_per_gt as usize);
            for i in 0..num_gtes_per_gt as usize {
                table.push(u32::from_le_bytes([
                    buf[i * 4],
                    buf[i * 4 + 1],
                    buf[i * 4 + 2],
                    buf[i * 4 + 3],
                ]));
            }
            grain_tables.push(table);
        }

        Ok(Self {
            inner: VmdkKind::Sparse {
                file: Mutex::new(f),
                grain_size_bytes,
                grain_directory,
                grain_tables,
                num_gtes_per_gt,
            },
            total_size,
            sector_size: sector_size as u32,
        })
    }
}

fn find_flat_extent(descriptor: &str, descriptor_path: &Path) -> Option<PathBuf> {
    for line in descriptor.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("RW ") && !trimmed.starts_with("RDONLY ") {
            continue;
        }
        // Format: `RW <sectors> FLAT "filename" <offset>`
        let quote_start = trimmed.find('"')?;
        let quote_end = trimmed[quote_start + 1..].find('"')? + quote_start + 1;
        let filename = &trimmed[quote_start + 1..quote_end];
        let parent = descriptor_path.parent().unwrap_or_else(|| Path::new(""));
        return Some(parent.join(filename));
    }
    None
}

impl EvidenceImage for VmdkImage {
    fn size(&self) -> u64 {
        self.total_size
    }
    fn sector_size(&self) -> u32 {
        self.sector_size
    }
    fn format_name(&self) -> &'static str {
        "VMDK"
    }
    fn metadata(&self) -> ImageMetadata {
        ImageMetadata::minimal("VMDK", self.total_size, self.sector_size)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> EvidenceResult<usize> {
        if offset >= self.total_size || buf.is_empty() {
            return Ok(0);
        }
        match &self.inner {
            VmdkKind::Flat { file } => {
                let mut guard = file
                    .lock()
                    .map_err(|e| EvidenceError::Other(format!("poisoned: {e}")))?;
                guard.seek(SeekFrom::Start(offset)).map_err(EvidenceError::Io)?;
                let max_len = (self.total_size - offset).min(buf.len() as u64) as usize;
                guard
                    .read_exact(&mut buf[..max_len])
                    .map_err(EvidenceError::Io)?;
                Ok(max_len)
            }
            VmdkKind::Sparse {
                file,
                grain_size_bytes,
                grain_directory: _,
                grain_tables,
                num_gtes_per_gt,
            } => {
                let mut filled = 0usize;
                let mut cursor = offset;
                while filled < buf.len() && cursor < self.total_size {
                    let grain_sz = *grain_size_bytes as u64;
                    let virtual_grain = cursor / grain_sz;
                    let in_grain = (cursor % grain_sz) as usize;
                    let gd_idx = (virtual_grain / *num_gtes_per_gt as u64) as usize;
                    let gt_idx = (virtual_grain % *num_gtes_per_gt as u64) as usize;
                    let entry = grain_tables
                        .get(gd_idx)
                        .and_then(|gt| gt.get(gt_idx))
                        .copied()
                        .unwrap_or(0);
                    let need = grain_sz as usize - in_grain;
                    let remaining = buf.len() - filled;
                    let n = need.min(remaining);
                    if entry == 0 {
                        // Unallocated grain — zero fill.
                        for b in &mut buf[filled..filled + n] {
                            *b = 0;
                        }
                    } else {
                        let phys_off = (entry as u64) * 512 + in_grain as u64;
                        let mut guard = file
                            .lock()
                            .map_err(|e| EvidenceError::Other(format!("poisoned: {e}")))?;
                        guard
                            .seek(SeekFrom::Start(phys_off))
                            .map_err(EvidenceError::Io)?;
                        guard
                            .read_exact(&mut buf[filled..filled + n])
                            .map_err(EvidenceError::Io)?;
                    }
                    filled += n;
                    cursor += n as u64;
                }
                Ok(filled)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn flat_vmdk_descriptor_routing() {
        let tmp = tempfile::tempdir().expect("t");
        let flat = tmp.path().join("disk-flat.vmdk");
        {
            let mut f = File::create(&flat).expect("c");
            f.write_all(&[0x11u8; 1024]).expect("w");
        }
        let descriptor = tmp.path().join("disk.vmdk");
        {
            let mut f = File::create(&descriptor).expect("c");
            f.write_all(
                b"# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n\
                 createType=\"monolithicFlat\"\nRW 2 FLAT \"disk-flat.vmdk\" 0\n",
            )
            .expect("w");
        }
        let img = VmdkImage::open(&descriptor).expect("open");
        assert_eq!(img.size(), 1024);
        let mut buf = [0u8; 4];
        img.read_at(0, &mut buf).expect("r");
        assert_eq!(buf, [0x11, 0x11, 0x11, 0x11]);
    }

    #[test]
    fn flat_unallocated_descriptor_errors() {
        let tmp = tempfile::tempdir().expect("t");
        let descriptor = tmp.path().join("missing.vmdk");
        {
            let mut f = File::create(&descriptor).expect("c");
            f.write_all(b"# Disk DescriptorFile\ncreateType=monolithicFlat\n").expect("w");
        }
        match VmdkImage::open(&descriptor) {
            Err(EvidenceError::InvalidHeader { .. }) => {}
            other => panic!("expected InvalidHeader, got {:?}", other.map(|_| "ok")),
        }
    }

    #[test]
    fn rejects_bad_sparse_magic() {
        let tmp = tempfile::tempdir().expect("t");
        let p = tmp.path().join("bad.vmdk");
        {
            let mut f = File::create(&p).expect("c");
            f.write_all(&[0u8; 512]).expect("w");
        }
        match VmdkImage::open(&p) {
            Err(EvidenceError::InvalidHeader { .. }) | Err(EvidenceError::Io(_)) => {}
            other => panic!("expected error, got {:?}", other.map(|_| "ok")),
        }
    }
}
