//! EVIDENCE-5 — unified format detection + dispatcher.
//!
//! `open_evidence(path)` returns a boxed `EvidenceImage` trait object
//! without the caller needing to know which concrete format is on
//! disk. Detection goes magic-bytes first, extension second.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::e01::E01Image;
use crate::image::{EvidenceError, EvidenceImage, EvidenceResult};
use crate::raw::RawImage;
use crate::vhd::{VhdImage, VhdxImage};
use crate::vmdk::VmdkImage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Raw,
    E01,
    Vmdk,
    Vhd,
    Vhdx,
    AppleDmg,
    Unknown,
}

impl ImageFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Raw => "Raw",
            Self::E01 => "E01",
            Self::Vmdk => "VMDK",
            Self::Vhd => "VHD",
            Self::Vhdx => "VHDX",
            Self::AppleDmg => "DMG",
            Self::Unknown => "Unknown",
        }
    }
}

pub fn detect_format(header: &[u8], path: &Path) -> ImageFormat {
    if header.len() >= 8 && header[..8] == crate::e01::EWF_MAGIC {
        return ImageFormat::E01;
    }
    if header.len() >= 8 && &header[..8] == b"vhdxfile" {
        return ImageFormat::Vhdx;
    }
    if header.len() >= 4 && &header[..4] == b"KDMV" {
        return ImageFormat::Vmdk;
    }
    if header.len() >= 21 && header.starts_with(b"# Disk DescriptorFile") {
        return ImageFormat::Vmdk;
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "e01" | "ex01" => ImageFormat::E01,
        "vmdk" => ImageFormat::Vmdk,
        "vhd" => ImageFormat::Vhd,
        "vhdx" => ImageFormat::Vhdx,
        "dmg" => ImageFormat::AppleDmg,
        "raw" | "dd" | "img" | "001" => ImageFormat::Raw,
        _ => ImageFormat::Unknown,
    }
}

pub fn open_evidence(path: &Path) -> EvidenceResult<Box<dyn EvidenceImage>> {
    let mut header = [0u8; 512];
    let read_n = {
        let mut f = File::open(path).map_err(EvidenceError::Io)?;
        f.read(&mut header).map_err(EvidenceError::Io)?
    };
    match detect_format(&header[..read_n], path) {
        ImageFormat::Raw => Ok(Box::new(RawImage::open(path)?)),
        ImageFormat::E01 => Ok(Box::new(E01Image::open(path)?)),
        ImageFormat::Vmdk => Ok(Box::new(VmdkImage::open(path)?)),
        ImageFormat::Vhd => Ok(Box::new(VhdImage::open(path)?)),
        ImageFormat::Vhdx => Ok(Box::new(VhdxImage::open(path)?)),
        ImageFormat::AppleDmg => {
            // Basic UDRO read-only DMGs are trivially raw; real UDIF
            // parsing lands in a follow-up sprint.
            Ok(Box::new(RawImage::open(path)?))
        }
        ImageFormat::Unknown => Err(EvidenceError::UnknownFormat(path.to_path_buf())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_e01_by_magic() {
        assert_eq!(
            detect_format(&crate::e01::EWF_MAGIC, Path::new("x.unknown")),
            ImageFormat::E01
        );
    }

    #[test]
    fn detects_vhdx_by_magic() {
        assert_eq!(
            detect_format(b"vhdxfile", Path::new("x.unknown")),
            ImageFormat::Vhdx
        );
    }

    #[test]
    fn detects_vmdk_sparse_by_magic() {
        assert_eq!(
            detect_format(b"KDMV", Path::new("x.unknown")),
            ImageFormat::Vmdk
        );
    }

    #[test]
    fn detects_vmdk_descriptor_by_text() {
        assert_eq!(
            detect_format(b"# Disk DescriptorFile\n", Path::new("x.unknown")),
            ImageFormat::Vmdk
        );
    }

    #[test]
    fn falls_back_to_extension() {
        assert_eq!(
            detect_format(b"\x00\x00\x00\x00", Path::new("img.raw")),
            ImageFormat::Raw
        );
        assert_eq!(
            detect_format(b"\x00\x00\x00\x00", Path::new("img.VHD")),
            ImageFormat::Vhd
        );
        assert_eq!(
            detect_format(b"\x00\x00\x00\x00", Path::new("img.dmg")),
            ImageFormat::AppleDmg
        );
        assert_eq!(
            detect_format(b"\x00\x00\x00\x00", Path::new("x.unknown")),
            ImageFormat::Unknown
        );
    }

    #[test]
    fn dispatcher_opens_raw_image() {
        let tmp = tempfile::tempdir().expect("t");
        let p = tmp.path().join("img.raw");
        {
            let mut f = File::create(&p).expect("c");
            f.write_all(&[0xAAu8; 1024]).expect("w");
        }
        let img = open_evidence(&p).expect("open");
        assert_eq!(img.format_name(), "Raw");
        assert_eq!(img.size(), 1024);
    }
}
