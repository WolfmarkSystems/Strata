//! EVIDENCE-1 — raw / dd / split-raw image reader.
//!
//! The simplest forensic container: the entire disk as a flat sequence
//! of bytes. Multi-segment splits (`.001`, `.002`, …) are detected
//! automatically; the logical image is the concatenation of every
//! discovered segment. Reads use `seek` + `read_exact` behind a
//! short-lived `Mutex` lock so the reader is `Send + Sync` without
//! requiring any `unsafe {}` blocks.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::image::{EvidenceError, EvidenceImage, EvidenceResult, ImageMetadata};

struct Segment {
    file: Mutex<File>,
    len: u64,
    /// Cumulative start offset within the logical image.
    start: u64,
}

pub struct RawImage {
    segments: Vec<Segment>,
    total_size: u64,
    sector_size: u32,
    primary_path: PathBuf,
}

impl RawImage {
    /// Open a raw image. Auto-detects `.001`/`.002`/… split siblings.
    pub fn open(path: &Path) -> EvidenceResult<Self> {
        let primary_path = path.to_path_buf();
        let paths = discover_split_siblings(path)?;
        let mut segments: Vec<Segment> = Vec::with_capacity(paths.len());
        let mut cumulative = 0u64;
        for p in paths {
            let file = File::open(&p).map_err(EvidenceError::Io)?;
            let len = file.metadata().map_err(EvidenceError::Io)?.len();
            segments.push(Segment {
                file: Mutex::new(file),
                len,
                start: cumulative,
            });
            cumulative = cumulative.saturating_add(len);
        }
        let total_size = cumulative;
        let sector_size = detect_sector_size(total_size);
        Ok(Self {
            segments,
            total_size,
            sector_size,
            primary_path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.primary_path
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }
}

impl EvidenceImage for RawImage {
    fn size(&self) -> u64 {
        self.total_size
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn format_name(&self) -> &'static str {
        "Raw"
    }

    fn metadata(&self) -> ImageMetadata {
        ImageMetadata::minimal("Raw", self.total_size, self.sector_size)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> EvidenceResult<usize> {
        if offset >= self.total_size || buf.is_empty() {
            return Ok(0);
        }
        let mut filled = 0usize;
        let mut cursor = offset;
        while filled < buf.len() && cursor < self.total_size {
            let seg = match self
                .segments
                .iter()
                .find(|s| cursor >= s.start && cursor < s.start.saturating_add(s.len))
            {
                Some(s) => s,
                None => break,
            };
            let in_seg = cursor - seg.start;
            let remaining_in_seg = seg.len.saturating_sub(in_seg) as usize;
            let remaining_in_buf = buf.len() - filled;
            let n = remaining_in_seg.min(remaining_in_buf);
            if n == 0 {
                break;
            }
            {
                let mut guard = seg
                    .file
                    .lock()
                    .map_err(|e| EvidenceError::Other(format!("raw segment poisoned: {e}")))?;
                guard
                    .seek(SeekFrom::Start(in_seg))
                    .map_err(EvidenceError::Io)?;
                guard
                    .read_exact(&mut buf[filled..filled + n])
                    .map_err(EvidenceError::Io)?;
            }
            filled += n;
            cursor = cursor.saturating_add(n as u64);
        }
        Ok(filled)
    }
}

fn detect_sector_size(total: u64) -> u32 {
    if total == 0 {
        return 512;
    }
    if total.is_multiple_of(512) {
        return 512;
    }
    if total.is_multiple_of(4096) {
        return 4096;
    }
    512
}

fn discover_split_siblings(primary: &Path) -> EvidenceResult<Vec<PathBuf>> {
    // Match the conventional .NNN suffix chain: given path ending in
    // .001, .002, .003, …, return all existing siblings in order.
    // For any other extension, just return the single file.
    let name = primary.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let parent = primary.parent().unwrap_or_else(|| Path::new(""));
    let stem_idx = name.rfind('.');
    let Some(idx) = stem_idx else {
        return Ok(vec![primary.to_path_buf()]);
    };
    let ext = &name[idx + 1..];
    if ext.len() != 3 || !ext.chars().all(|c| c.is_ascii_digit()) {
        return Ok(vec![primary.to_path_buf()]);
    }
    let stem = &name[..idx];
    let mut out: Vec<PathBuf> = Vec::new();
    for i in 1u32..=999 {
        let candidate = parent.join(format!("{stem}.{i:03}"));
        if candidate.exists() {
            out.push(candidate);
        } else {
            break;
        }
    }
    if out.is_empty() {
        out.push(primary.to_path_buf());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_bytes(path: &Path, bytes: &[u8]) {
        let mut f = File::create(path).expect("create");
        f.write_all(bytes).expect("write");
    }

    #[test]
    fn opens_single_file_and_reads() {
        let tmp = tempfile::tempdir().expect("tmp");
        let p = tmp.path().join("img.raw");
        let data: Vec<u8> = (0..2048u16).map(|i| (i & 0xFF) as u8).collect();
        write_bytes(&p, &data);
        let img = RawImage::open(&p).expect("open");
        assert_eq!(img.size(), 2048);
        let mut buf = vec![0u8; 10];
        let n = img.read_at(0, &mut buf).expect("read");
        assert_eq!(n, 10);
        assert_eq!(buf, data[..10]);
    }

    #[test]
    fn reads_across_offset() {
        let tmp = tempfile::tempdir().expect("tmp");
        let p = tmp.path().join("x.dd");
        write_bytes(&p, &(0..1024).map(|i| i as u8).collect::<Vec<u8>>());
        let img = RawImage::open(&p).expect("open");
        let mut buf = vec![0u8; 4];
        img.read_at(1000, &mut buf).expect("r");
        assert_eq!(buf, [0xE8u8, 0xE9, 0xEA, 0xEB]);
    }

    #[test]
    fn read_past_eof_returns_zero_not_error() {
        let tmp = tempfile::tempdir().expect("tmp");
        let p = tmp.path().join("x.raw");
        write_bytes(&p, b"abc");
        let img = RawImage::open(&p).expect("open");
        let mut buf = [0u8; 8];
        let n = img.read_at(1000, &mut buf).expect("r");
        assert_eq!(n, 0);
    }

    #[test]
    fn multi_segment_split_raw() {
        let tmp = tempfile::tempdir().expect("tmp");
        let base = tmp.path();
        write_bytes(&base.join("image.001"), &[0xAAu8; 512]);
        write_bytes(&base.join("image.002"), &[0xBBu8; 512]);
        write_bytes(&base.join("image.003"), &[0xCCu8; 128]);
        let img = RawImage::open(&base.join("image.001")).expect("open");
        assert_eq!(img.size(), 512 + 512 + 128);
        assert_eq!(img.segment_count(), 3);
        // Read across the .001/.002 boundary.
        let mut buf = [0u8; 8];
        img.read_at(510, &mut buf).expect("r");
        assert_eq!(buf[..2], [0xAA, 0xAA]);
        assert_eq!(buf[2..], [0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB]);
    }

    #[test]
    fn sector_size_detection() {
        let tmp = tempfile::tempdir().expect("tmp");
        let p = tmp.path().join("x.raw");
        write_bytes(&p, &[0u8; 512 * 100]);
        let img = RawImage::open(&p).expect("open");
        assert_eq!(img.sector_size(), 512);
    }
}
