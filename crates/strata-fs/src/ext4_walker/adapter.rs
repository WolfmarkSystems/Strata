//! Offset-addressed adapter over `Arc<dyn EvidenceImage>` for
//! `ext4-view::Ext4Read`.
//!
//! v15 Session B. Unlike the NTFS walker's `PartitionReader`, this
//! adapter does NOT implement `Read + Seek` — `ext4-view`'s
//! `Ext4Read` trait is itself offset-addressed
//! (`fn read(start_byte: u64, dst: &mut [u8]) -> Result<...>`), so
//! the adapter delegates one-to-one onto `EvidenceImage::read_at`.
//! No buffering layer. The v14 plan's speculative
//! `BufReader<Mutex<PartitionReader>>` stack is intentionally not
//! reintroduced here per the Phase A research findings in
//! `docs/RESEARCH_v15_EXT4_VIEW.md`.

use std::error::Error;
use std::sync::Arc;

use ext4_view::Ext4Read;
use strata_evidence::EvidenceImage;

pub struct Ext4PartitionReader {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
}

impl Ext4PartitionReader {
    pub fn new(image: Arc<dyn EvidenceImage>, partition_offset: u64, partition_size: u64) -> Self {
        Self {
            image,
            partition_offset,
            partition_size,
        }
    }

    pub fn partition_offset(&self) -> u64 {
        self.partition_offset
    }

    pub fn partition_size(&self) -> u64 {
        self.partition_size
    }
}

impl Ext4Read for Ext4PartitionReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        // Hard-reject reads that would cross the partition boundary.
        // The filesystem layer must never read beyond its declared
        // window.
        let want = dst.len() as u64;
        let end = start_byte.checked_add(want).ok_or_else(|| {
            Box::<dyn Error + Send + Sync>::from(format!(
                "ext4 read offset overflow: {start_byte} + {want}"
            ))
        })?;
        if end > self.partition_size {
            return Err(format!(
                "ext4 read past partition end: {start_byte}..{end}, size={}",
                self.partition_size
            )
            .into());
        }
        let absolute = self.partition_offset.saturating_add(start_byte);
        let mut filled = 0usize;
        while filled < dst.len() {
            let n = self
                .image
                .read_at(absolute + filled as u64, &mut dst[filled..])
                .map_err(|e| {
                    Box::<dyn Error + Send + Sync>::from(format!(
                        "evidence read_at failed at absolute {}: {e}",
                        absolute + filled as u64
                    ))
                })?;
            if n == 0 {
                return Err(format!(
                    "short evidence read at abs {}: got {filled}, wanted {}",
                    absolute,
                    dst.len()
                )
                .into());
            }
            filled += n;
        }
        Ok(())
    }
}
