//! Partition-table walkers: MBR (legacy) and GPT (modern).
//!
//! Each walker takes an `&dyn EvidenceImage`, reads the appropriate
//! table, and returns a normalised list of partitions. Callers
//! iterate partitions and hand each one's byte range to a
//! filesystem walker (Part 3).

pub mod gpt;
pub mod mbr;
