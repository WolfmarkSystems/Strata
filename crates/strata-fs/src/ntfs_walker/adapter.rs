//! Read+Seek adapter over an `Arc<dyn EvidenceImage>` partition window.
//!
//! The `ntfs` crate (and the forthcoming ext4/FAT walkers) expects a
//! reader speaking `Read + Seek`. Our evidence image layer speaks
//! `read_at(offset, buf)`. The adapter translates the two.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use strata_evidence::EvidenceImage;

pub struct PartitionReader {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    cursor: u64,
}

impl PartitionReader {
    pub fn new(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
        _sector_size: usize,
    ) -> Self {
        Self {
            image,
            partition_offset,
            partition_size,
            cursor: 0,
        }
    }

    pub fn partition_offset(&self) -> u64 {
        self.partition_offset
    }

    pub fn partition_size(&self) -> u64 {
        self.partition_size
    }
}

impl Read for PartitionReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cursor >= self.partition_size {
            return Ok(0);
        }
        let remaining = self.partition_size - self.cursor;
        let to_read = (buf.len() as u64).min(remaining) as usize;
        let slice = &mut buf[..to_read];
        let n = self
            .image
            .read_at(self.partition_offset + self.cursor, slice)
            .map_err(|e| io::Error::other(format!("evidence read: {e}")))?;
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Seek for PartitionReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(v) => v as i64,
            SeekFrom::End(v) => self.partition_size as i64 + v,
            SeekFrom::Current(v) => self.cursor as i64 + v,
        };
        if new < 0 {
            return Err(io::Error::other("seek before start"));
        }
        self.cursor = new as u64;
        Ok(self.cursor)
    }
}
