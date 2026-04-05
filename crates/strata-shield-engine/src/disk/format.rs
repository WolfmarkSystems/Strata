use crate::errors::ForensicError;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ImageFormatInfo {
    pub format: ImageFormat,
    pub version: Option<String>,
    pub description: String,
    pub is_compressed: bool,
    pub is_encrypted: bool,
    pub segment_count: usize,
    pub total_size: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImageFormat {
    Raw,
    E01,
    AFF,
    AFF4,
    S01,
    Lx01,
    Lx02,
    VMDK,
    VHD,
    VHDX,
    DMG,
    ISO,
    CDR,
    ZIP,
    TAR,
    GZIP,
    SEVENZIP,
    UFDR,
    GRAYKEY,
    AXIOM,
    ITUNES,
    ADB,
    PLIST,
    SQLITE,
    SplitRaw,
    Unknown,
}

impl ImageFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            ImageFormat::Raw => "RAW/DD",
            ImageFormat::E01 => "EnCase E01",
            ImageFormat::AFF => "AFF",
            ImageFormat::AFF4 => "AFF4",
            ImageFormat::S01 => "SmartSure S01",
            ImageFormat::Lx01 => "LinEn Lx01",
            ImageFormat::Lx02 => "LinEn Lx02",
            ImageFormat::VMDK => "VMware VMDK",
            ImageFormat::VHD => "Microsoft VHD",
            ImageFormat::VHDX => "Microsoft VHDX",
            ImageFormat::DMG => "Apple DMG",
            ImageFormat::ISO => "ISO 9660",
            ImageFormat::CDR => "CD-ROM",
            ImageFormat::ZIP => "ZIP Archive",
            ImageFormat::TAR => "TAR Archive",
            ImageFormat::GZIP => "GZIP Archive",
            ImageFormat::SEVENZIP => "7-Zip Archive",
            ImageFormat::UFDR => "Cellebrite UFDR",
            ImageFormat::GRAYKEY => "GrayKey Export",
            ImageFormat::AXIOM => "Magnet AXIOM Export",
            ImageFormat::ITUNES => "iTunes Backup",
            ImageFormat::ADB => "ADB Backup",
            ImageFormat::PLIST => "Property List",
            ImageFormat::SQLITE => "SQLite Database",
            ImageFormat::SplitRaw => "Split RAW",
            ImageFormat::Unknown => "Unknown",
        }
    }

    pub fn is_container(&self) -> bool {
        matches!(
            self,
            ImageFormat::E01
                | ImageFormat::AFF
                | ImageFormat::AFF4
                | ImageFormat::S01
                | ImageFormat::Lx01
                | ImageFormat::Lx02
                | ImageFormat::VMDK
                | ImageFormat::VHD
                | ImageFormat::VHDX
                | ImageFormat::DMG
                | ImageFormat::ISO
                | ImageFormat::ZIP
                | ImageFormat::TAR
                | ImageFormat::UFDR
                | ImageFormat::GRAYKEY
                | ImageFormat::AXIOM
                | ImageFormat::SplitRaw
        )
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(
            self,
            ImageFormat::DMG
                | ImageFormat::ZIP
                | ImageFormat::SEVENZIP
                | ImageFormat::GRAYKEY
                | ImageFormat::AXIOM
        )
    }
}

pub struct ImageSegment {
    pub path: std::path::PathBuf,
    pub index: usize,
    pub size: u64,
}

pub fn detect_image_format(path: &Path) -> Result<ImageFormatInfo, ForensicError> {
    let metadata = strata_fs::metadata(path)?;
    let size = metadata.len();
    let mut file = strata_fs::File::open(path)?;
    let mut data = vec![0u8; 8192];
    let n = file.read(&mut data)?;
    data.truncate(n);
    let vhd_footer_detected = size >= 512 && {
        let mut footer = [0u8; 8];
        file.seek(SeekFrom::End(-512))?;
        file.read_exact(&mut footer).is_ok() && &footer == b"conectix"
    };

    if data.len() < 512 {
        if vhd_footer_detected {
            return Ok(ImageFormatInfo {
                format: ImageFormat::VHD,
                version: None,
                description: "Microsoft VHD".to_string(),
                is_compressed: false,
                is_encrypted: false,
                segment_count: 1,
                total_size: size,
            });
        }

        return Ok(
            extension_fallback_format(path, size).unwrap_or(ImageFormatInfo {
                format: ImageFormat::Raw,
                version: None,
                description: "Raw disk image".to_string(),
                is_compressed: false,
                is_encrypted: false,
                segment_count: 1,
                total_size: size,
            }),
        );
    }

    // E01/EX01 - EnCase Evidence File
    // EWF-S01 magic: 45 57 46 2D 53 30 31 (EWF-S01)
    // EVF1 magic: 45 56 46 31 (EVF1)
    // EVF\x01 magic: 45 56 46 01
    if &data[0..7] == b"EWF-S01" || &data[0..4] == b"EVF\x01" || &data[0..4] == b"\x45\x56\x46\x31" {
        return Ok(ImageFormatInfo {
            format: ImageFormat::E01,
            version: Some("1".to_string()),
            description: "EnCase Evidence File (E01)".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: count_segments(path)?,
            total_size: size,
        });
    }

    // AFF - Advanced Forensic Format
    if &data[0..4] == b"AFF\0" {
        return Ok(ImageFormatInfo {
            format: ImageFormat::AFF,
            version: Some("1".to_string()),
            description: "Advanced Forensic Format".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // AFF4 - Advanced Forensic Format 4
    if data.len() >= 8 && &data[0..8] == b"AFF4\0\0\0" {
        return Ok(ImageFormatInfo {
            format: ImageFormat::AFF4,
            version: Some("4".to_string()),
            description: "Advanced Forensic Format 4".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // S01 - EnCase Lite
    if data.len() > 13 && &data[0..4] == b"\x01\x00\x00\x00" && &data[8..12] == b"S01\x1a" {
        return Ok(ImageFormatInfo {
            format: ImageFormat::S01,
            version: Some("1".to_string()),
            description: "EnCase Lite (S01)".to_string(),
            is_compressed: true,
            is_encrypted: true,
            segment_count: count_segments(path)?,
            total_size: size,
        });
    }

    // Lx01/Lx02 - Linen/Luks
    if &data[0..8] == b"LUKS\xBA\xBE\x00\x00" {
        return Ok(ImageFormatInfo {
            format: ImageFormat::Lx01,
            version: Some("1".to_string()),
            description: "LUKS encryption".to_string(),
            is_compressed: false,
            is_encrypted: true,
            segment_count: 1,
            total_size: size,
        });
    }

    // VMDK - VMware Virtual Machine Disk
    if data.len() >= 4 && &data[0..4] == b"KDMV" {
        return Ok(ImageFormatInfo {
            format: ImageFormat::VMDK,
            version: None,
            description: "VMware VMDK".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // VHD - Virtual Hard Disk
    if data.len() >= 512 && &data[0..8] == b"conectix" {
        return Ok(ImageFormatInfo {
            format: ImageFormat::VHD,
            version: None,
            description: "Microsoft VHD".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    if vhd_footer_detected {
        return Ok(ImageFormatInfo {
            format: ImageFormat::VHD,
            version: None,
            description: "Microsoft VHD".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // VHDX - Virtual Hard Disk v2
    if data.len() >= 512 && &data[0..4] == b"vhdx" {
        return Ok(ImageFormatInfo {
            format: ImageFormat::VHDX,
            version: None,
            description: "Microsoft VHDX".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // DMG - Apple Disk Image
    if data.len() >= 4 && (&data[0..2] == b"koly" || &data[0..4] == b"encrc") {
        return Ok(ImageFormatInfo {
            format: ImageFormat::DMG,
            version: None,
            description: "Apple DMG".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // ISO 9660 - CD-ROM Image
    if data.len() >= 32768 && &data[32768..32776] == b"CD001\x01\x00" {
        return Ok(ImageFormatInfo {
            format: ImageFormat::ISO,
            version: Some("1".to_string()),
            description: "ISO 9660 CD-ROM".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // ZIP - ZIP Archive (also used for UFDR, GrayKey, AXIOM)
    if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        // Check for special ZIP variants
        if data.len() >= 64 {
            let path_str = path.to_string_lossy().to_lowercase();
            if path_str.contains("ufdr") || path_str.contains("cellebrite") {
                return Ok(ImageFormatInfo {
                    format: ImageFormat::UFDR,
                    version: None,
                    description: "Cellebrite UFDR".to_string(),
                    is_compressed: true,
                    is_encrypted: false,
                    segment_count: 1,
                    total_size: size,
                });
            }
            if path_str.contains("graykey") || path_str.contains("grayshift") {
                return Ok(ImageFormatInfo {
                    format: ImageFormat::GRAYKEY,
                    version: None,
                    description: "GrayKey Export".to_string(),
                    is_compressed: true,
                    is_encrypted: true,
                    segment_count: 1,
                    total_size: size,
                });
            }
            if path_str.contains("axiom") || path_str.contains("magnet") {
                return Ok(ImageFormatInfo {
                    format: ImageFormat::AXIOM,
                    version: None,
                    description: "Magnet AXIOM Export".to_string(),
                    is_compressed: true,
                    is_encrypted: true,
                    segment_count: 1,
                    total_size: size,
                });
            }
        }
        return Ok(ImageFormatInfo {
            format: ImageFormat::ZIP,
            version: None,
            description: "ZIP Archive".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // TAR
    if data.len() >= 512 && (data[257..262] == *b"ustar" || data[0..4] == *b"UBSD") {
        return Ok(ImageFormatInfo {
            format: ImageFormat::TAR,
            version: None,
            description: "TAR Archive".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // GZIP
    if data.len() >= 4 && &data[0..2] == b"\x1f\x8b" {
        return Ok(ImageFormatInfo {
            format: ImageFormat::GZIP,
            version: None,
            description: "GZIP Archive".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // SQLite Database
    if data.len() >= 16 && &data[0..16] == b"SQLite format 3\x00" {
        let path_str = path.to_string_lossy().to_lowercase();
        if path_str.contains("itunes")
            || path_str.contains("backup")
            || path_str.ends_with(".itl")
            || path_str.ends_with(".mdbackup")
        {
            return Ok(ImageFormatInfo {
                format: ImageFormat::ITUNES,
                version: None,
                description: "iTunes Backup".to_string(),
                is_compressed: false,
                is_encrypted: false,
                segment_count: 1,
                total_size: size,
            });
        }
        return Ok(ImageFormatInfo {
            format: ImageFormat::SQLITE,
            version: None,
            description: "SQLite Database".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // Property List (binary plist)
    if data.len() >= 8 && (&data[0..8] == b"bplist00" || &data[0..8] == b"bplist0") {
        return Ok(ImageFormatInfo {
            format: ImageFormat::PLIST,
            version: None,
            description: "Apple Property List".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // NTFS Boot Sector
    if data.len() >= 11 && &data[3..11] == b"NTFS    " {
        return Ok(ImageFormatInfo {
            format: ImageFormat::Raw,
            version: None,
            description: "Raw disk image (NTFS)".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // APFS Superblock
    if data.len() >= 4096
        && (&data[4096..4104] == b"NEW\0\0\0".to_vec()
            || &data[4096..4104] == b"NXSB\x00\x00\x00".to_vec())
    {
        return Ok(ImageFormatInfo {
            format: ImageFormat::Raw,
            version: None,
            description: "Raw disk image (APFS)".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // MBR Detection
    if data.len() >= 512
        && (data[0] == 0x00 || data[0] == 0x80)
        && u16::from_le_bytes([data[0x1FE], data[0x1FF]]) == 0xAA55
    {
        return Ok(ImageFormatInfo {
            format: ImageFormat::Raw,
            version: None,
            description: "Raw disk image (MBR detected)".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        });
    }

    // Check for split RAW (001, 002, etc.)
    let path_str = path.to_string_lossy().to_lowercase();
    if path_str.ends_with(".001") || path_str.ends_with(".002") || path_str.ends_with(".003") {
        if let Ok(info) = detect_image_format(Path::new(
            path_str
                .trim_end_matches(".001")
                .trim_end_matches(".002")
                .trim_end_matches(".003"),
        )) {
            if info.format == ImageFormat::Raw {
                return Ok(ImageFormatInfo {
                    format: ImageFormat::SplitRaw,
                    version: None,
                    description: "Split RAW Image".to_string(),
                    is_compressed: false,
                    is_encrypted: false,
                    segment_count: count_segments(path)?,
                    total_size: size,
                });
            }
        }
    }

    Ok(
        extension_fallback_format(path, size).unwrap_or(ImageFormatInfo {
            format: ImageFormat::Raw,
            version: None,
            description: "Raw disk image".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size: size,
        }),
    )
}

fn count_segments(path: &Path) -> Result<usize, ForensicError> {
    let mut count = 1;
    for i in 2..=999 {
        if find_existing_segment_path(path, i).is_some() {
            count = i;
        } else {
            break;
        }
    }

    Ok(count)
}

fn find_existing_segment_path(path: &Path, index: usize) -> Option<PathBuf> {
    segment_path_candidates(path, index)
        .into_iter()
        .find(|candidate| candidate.exists())
}

fn segment_path_candidates(path: &Path, index: usize) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let parent = path.parent().unwrap_or(path);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    // Existing split convention used by current repo code.
    candidates.push(parent.join(format!("{}_{:03}", stem, index)));
    // Common split convention for raw/segment sets.
    candidates.push(parent.join(format!("{}.{:03}", stem, index)));

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_upper = ext.to_ascii_uppercase();

        // EnCase-style extension sequence (E01->E02, S01->S02, A01->A02).
        if ext_upper.len() == 3
            && ext_upper
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false)
            && ext_upper[1..].chars().all(|c| c.is_ascii_digit())
            && index <= 99
        {
            let prefix = ext_upper.chars().next().unwrap();
            candidates.push(path.with_extension(format!("{}{:02}", prefix, index)));
        }

        // Numeric extension sequence (001->002->003).
        if ext_upper.len() == 3 && ext_upper.chars().all(|c| c.is_ascii_digit()) && index <= 999 {
            candidates.push(path.with_extension(format!("{:03}", index)));
        }
    }

    candidates
}

fn extension_fallback_format(path: &Path, total_size: u64) -> Option<ImageFormatInfo> {
    let ext = path
        .extension()
        .map(|s| s.to_string_lossy().to_string().to_ascii_uppercase())?;

    match ext.as_str() {
        "E01" | "EX01" => Some(ImageFormatInfo {
            format: ImageFormat::E01,
            version: Some("1".to_string()),
            description: "Encase Evidence File (E01) [extension heuristic]".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: count_segments(path).unwrap_or(1),
            total_size,
        }),
        "AFF" | "AFD" | "AFM" => Some(ImageFormatInfo {
            format: ImageFormat::AFF,
            version: Some("1".to_string()),
            description: "Advanced Forensic Format [extension heuristic]".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size,
        }),
        "AFF4" => Some(ImageFormatInfo {
            format: ImageFormat::AFF4,
            version: Some("4".to_string()),
            description: "Advanced Forensic Format 4 [extension heuristic]".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: 1,
            total_size,
        }),
        "S01" => Some(ImageFormatInfo {
            format: ImageFormat::S01,
            version: Some("1".to_string()),
            description: "Encase Lite (S01) [extension heuristic]".to_string(),
            is_compressed: true,
            is_encrypted: true,
            segment_count: count_segments(path).unwrap_or(1),
            total_size,
        }),
        "VMDK" => Some(ImageFormatInfo {
            format: ImageFormat::VMDK,
            version: None,
            description: "VMware VMDK [extension heuristic]".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size,
        }),
        "VHD" => Some(ImageFormatInfo {
            format: ImageFormat::VHD,
            version: None,
            description: "Microsoft VHD [extension heuristic]".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size,
        }),
        "VHDX" => Some(ImageFormatInfo {
            format: ImageFormat::VHDX,
            version: None,
            description: "Microsoft VHDX [extension heuristic]".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: 1,
            total_size,
        }),
        "DMG" => Some(ImageFormatInfo {
            format: ImageFormat::DMG,
            version: None,
            description: "Apple DMG [extension heuristic]".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: 1,
            total_size,
        }),
        "ISO" | "IS0" => Some(ImageFormatInfo {
            format: ImageFormat::ISO,
            version: None,
            description: "ISO 9660 Image [extension heuristic]".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: 1,
            total_size,
        }),
        "ZIP" => Some(ImageFormatInfo {
            format: ImageFormat::ZIP,
            version: None,
            description: "ZIP Archive [extension heuristic]".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: 1,
            total_size,
        }),
        "TAR" | "TGZ" | "TBZ2" | "TXZ" => Some(ImageFormatInfo {
            format: ImageFormat::TAR,
            version: None,
            description: "TAR Archive [extension heuristic]".to_string(),
            is_compressed: ext == "TGZ" || ext == "TBZ2" || ext == "TXZ",
            is_encrypted: false,
            segment_count: 1,
            total_size,
        }),
        "7Z" => Some(ImageFormatInfo {
            format: ImageFormat::SEVENZIP,
            version: None,
            description: "7-Zip Archive [extension heuristic]".to_string(),
            is_compressed: true,
            is_encrypted: false,
            segment_count: 1,
            total_size,
        }),
        "001" | "002" | "003" | "004" | "005" | "RAW" | "DD" | "IMG" => Some(ImageFormatInfo {
            format: ImageFormat::SplitRaw,
            version: None,
            description: "Split RAW Image [extension heuristic]".to_string(),
            is_compressed: false,
            is_encrypted: false,
            segment_count: count_segments(path).unwrap_or(1),
            total_size,
        }),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn detect_image_format_uses_extension_fallback_for_e01() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.E01");
        std::fs::write(&path, b"not-evf-header").unwrap();

        let info = detect_image_format(&path).unwrap();
        assert!(matches!(info.format, ImageFormat::E01));
    }

    #[test]
    fn detect_image_format_uses_extension_fallback_for_s01() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.S01");
        std::fs::write(&path, b"no-s01-magic").unwrap();

        let info = detect_image_format(&path).unwrap();
        assert!(matches!(info.format, ImageFormat::S01));
    }

    #[test]
    fn count_segments_detects_e01_style_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let e01 = dir.path().join("sample.E01");
        let e02 = dir.path().join("sample.E02");
        let e03 = dir.path().join("sample.E03");
        std::fs::write(&e01, b"seg1").unwrap();
        std::fs::write(&e02, b"seg2").unwrap();
        std::fs::write(&e03, b"seg3").unwrap();

        let count = count_segments(&e01).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn get_image_segments_detects_e01_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let e01 = dir.path().join("sample.E01");
        let e02 = dir.path().join("sample.E02");
        std::fs::write(&e01, b"seg1").unwrap();
        std::fs::write(&e02, b"seg2").unwrap();

        let segments = get_image_segments(&e01).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].index, 1);
        assert_eq!(segments[1].index, 2);
        assert_eq!(segments[1].path, e02);
    }

    #[test]
    fn get_image_segments_detects_numeric_extension_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let s1 = dir.path().join("image.001");
        let s2 = dir.path().join("image.002");
        let s3 = dir.path().join("image.003");
        std::fs::write(&s1, b"seg1").unwrap();
        std::fs::write(&s2, b"seg2").unwrap();
        std::fs::write(&s3, b"seg3").unwrap();

        let segments = get_image_segments(&s1).unwrap();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[2].index, 3);
        assert_eq!(segments[2].path, s3);
    }

    #[test]
    fn get_image_segments_detects_underscore_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let s1 = dir.path().join("capture.E01");
        let s2 = dir.path().join("capture_002");
        let s3 = dir.path().join("capture_003");
        std::fs::write(&s1, b"seg1").unwrap();
        std::fs::write(&s2, b"seg2").unwrap();
        std::fs::write(&s3, b"seg3").unwrap();

        let segments = get_image_segments(&s1).unwrap();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[1].path, s2);
        assert_eq!(segments[2].path, s3);
    }
}

pub fn get_image_segments(path: &Path) -> Result<Vec<ImageSegment>, ForensicError> {
    let mut segments = Vec::new();

    if find_existing_segment_path(path, 2).is_none() {
        segments.push(ImageSegment {
            path: path.to_path_buf(),
            index: 1,
            size: strata_fs::metadata(path)?.len(),
        });
        return Ok(segments);
    }

    // Always include the first segment as the path provided by caller.
    segments.push(ImageSegment {
        path: path.to_path_buf(),
        index: 1,
        size: strata_fs::metadata(path)?.len(),
    });
    for i in 2..=999 {
        let Some(segment_path) = find_existing_segment_path(path, i) else {
            break;
        };
        let size = strata_fs::metadata(&segment_path)?.len();
        segments.push(ImageSegment {
            path: segment_path,
            index: i,
            size,
        });
    }

    Ok(segments)
}
