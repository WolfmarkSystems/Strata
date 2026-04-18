//! strata-evidence — pure-Rust evidence image readers + partition walkers.
//!
//! Exposes a single trait (`EvidenceImage`) that the rest of Strata
//! queries to get bytes out of a forensic image regardless of whether
//! the underlying format is raw dd, multi-segment split raw, EWF/E01,
//! VMDK, VHD, VHDX, or Apple DMG. Partition walkers (MBR + GPT) then
//! consume bytes from the image trait without caring which concrete
//! image type is underneath.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

pub mod dispatch;
pub mod e01;
pub mod image;
pub mod partition;
pub mod raw;
pub mod vhd;
pub mod vmdk;

pub use dispatch::{open_evidence, ImageFormat};
pub use e01::E01Image;
pub use image::{EvidenceError, EvidenceImage, EvidenceResult, EvidenceWarning, ImageMetadata};
pub use partition::{
    gpt::{read_gpt, GptPartition},
    mbr::{read_mbr, MbrPartition},
};
pub use raw::RawImage;
pub use vhd::{VhdImage, VhdxImage};
pub use vmdk::VmdkImage;
