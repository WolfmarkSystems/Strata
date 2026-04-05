use serde::{Deserialize, Serialize};

pub const CARVER_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveSignature {
    pub name: String,
    pub header: Vec<u8>,
    pub footer: Option<Vec<u8>>,
    pub max_size: u64,
    pub min_size: u64,
    pub extension: String,
    pub file_type: String,
    pub method: CarveMethod,
    pub size_offset: Option<usize>,
    pub size_endian: Option<Endian>,
    pub size_adjust: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CarveMethod {
    HeaderFooter,
    HeaderSize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Endian {
    Little,
    Big,
}

impl std::fmt::Display for CarveMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CarveMethod::HeaderFooter => write!(f, "header_footer"),
            CarveMethod::HeaderSize => write!(f, "header_size"),
        }
    }
}

pub fn get_default_signatures() -> Vec<CarveSignature> {
    vec![
        CarveSignature {
            name: "JPEG".to_string(),
            header: vec![0xFF, 0xD8, 0xFF],
            footer: Some(vec![0xFF, 0xD9]),
            max_size: 100 * 1024 * 1024,
            min_size: 100,
            extension: "jpg".to_string(),
            file_type: "image/jpeg".to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "PNG".to_string(),
            header: vec![0x89, 0x50, 0x4E, 0x47],
            footer: Some(vec![0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
            max_size: 100 * 1024 * 1024,
            min_size: 100,
            extension: "png".to_string(),
            file_type: "image/png".to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "GIF".to_string(),
            header: vec![0x47, 0x49, 0x46, 0x38],
            footer: Some(vec![0x00, 0x3B]),
            max_size: 50 * 1024 * 1024,
            min_size: 100,
            extension: "gif".to_string(),
            file_type: "image/gif".to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "PDF".to_string(),
            header: vec![0x25, 0x50, 0x44, 0x46],
            footer: Some(vec![0x25, 0x25, 0x45, 0x4F, 0x46]),
            max_size: 100 * 1024 * 1024,
            min_size: 100,
            extension: "pdf".to_string(),
            file_type: "application/pdf".to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "ZIP".to_string(),
            header: vec![0x50, 0x4B, 0x03, 0x04],
            footer: Some(vec![0x50, 0x4B, 0x05, 0x06]),
            max_size: 100 * 1024 * 1024,
            min_size: 100,
            extension: "zip".to_string(),
            file_type: "application/zip".to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "DOCX".to_string(),
            header: vec![0x50, 0x4B, 0x03, 0x04],
            footer: Some(vec![0x50, 0x4B, 0x05, 0x06]),
            max_size: 100 * 1024 * 1024,
            min_size: 100,
            extension: "docx".to_string(),
            file_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                .to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "XLSX".to_string(),
            header: vec![0x50, 0x4B, 0x03, 0x04],
            footer: Some(vec![0x50, 0x4B, 0x05, 0x06]),
            max_size: 100 * 1024 * 1024,
            min_size: 100,
            extension: "xlsx".to_string(),
            file_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                .to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "PPTX".to_string(),
            header: vec![0x50, 0x4B, 0x03, 0x04],
            footer: Some(vec![0x50, 0x4B, 0x05, 0x06]),
            max_size: 100 * 1024 * 1024,
            min_size: 100,
            extension: "pptx".to_string(),
            file_type: "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                .to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "RTF".to_string(),
            header: vec![0x7B, 0x5C, 0x72, 0x74, 0x66],
            footer: None,
            max_size: 50 * 1024 * 1024,
            min_size: 10,
            extension: "rtf".to_string(),
            file_type: "application/rtf".to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "MP3".to_string(),
            header: vec![0xFF, 0xFB],
            footer: None,
            max_size: 50 * 1024 * 1024,
            min_size: 100,
            extension: "mp3".to_string(),
            file_type: "audio/mpeg".to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "AVI".to_string(),
            header: vec![0x52, 0x49, 0x46, 0x46],
            footer: Some(vec![0x41, 0x56, 0x49, 0x20]),
            max_size: 100 * 1024 * 1024,
            min_size: 100,
            extension: "avi".to_string(),
            file_type: "video/x-msvideo".to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
        CarveSignature {
            name: "MP4".to_string(),
            header: vec![0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70],
            footer: None,
            max_size: 100 * 1024 * 1024,
            min_size: 100,
            extension: "mp4".to_string(),
            file_type: "video/mp4".to_string(),
            method: CarveMethod::HeaderFooter,
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        },
    ]
}

pub fn find_signature(name: &str) -> Option<CarveSignature> {
    get_default_signatures()
        .into_iter()
        .find(|s| s.name == name)
}

pub fn find_signatures(names: &[String]) -> Vec<CarveSignature> {
    let all = get_default_signatures();
    all.into_iter()
        .filter(|s| names.contains(&s.name))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedHit {
    pub evidence_id: String,
    pub volume_id: Option<String>,
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub signature_name: String,
    pub extension: String,
    pub file_type: String,
    pub confidence: Confidence,
    pub flags: CarveFlags,
    pub output_path: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Low => write!(f, "LOW"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::High => write!(f, "HIGH"),
        }
    }
}

impl std::str::FromStr for Confidence {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "LOW" => Ok(Confidence::Low),
            "MEDIUM" => Ok(Confidence::Medium),
            "HIGH" => Ok(Confidence::High),
            _ => Err(format!("Unknown confidence: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CarveFlags {
    pub truncated: bool,
    pub footer_missing: bool,
    pub header_corrupted: bool,
    pub write_failed: bool,
}

impl CarveFlags {
    pub fn to_bits(&self) -> u32 {
        let mut bits = 0u32;
        if self.truncated {
            bits |= 1 << 0;
        }
        if self.footer_missing {
            bits |= 1 << 1;
        }
        if self.header_corrupted {
            bits |= 1 << 2;
        }
        if self.write_failed {
            bits |= 1 << 3;
        }
        bits
    }

    pub fn from_bits(bits: u32) -> Self {
        Self {
            truncated: bits & (1 << 0) != 0,
            footer_missing: bits & (1 << 1) != 0,
            header_corrupted: bits & (1 << 2) != 0,
            write_failed: bits & (1 << 3) != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_signatures_exist() {
        let sigs = get_default_signatures();
        assert!(!sigs.is_empty());

        let jpeg = sigs.iter().find(|s| s.name == "JPEG").unwrap();
        assert_eq!(jpeg.extension, "jpg");
        assert_eq!(jpeg.method, CarveMethod::HeaderFooter);
    }

    #[test]
    fn test_find_signature() {
        let sig = find_signature("PNG").unwrap();
        assert_eq!(sig.extension, "png");
    }

    #[test]
    fn test_carve_flags_bits() {
        let flags = CarveFlags {
            truncated: true,
            footer_missing: true,
            ..Default::default()
        };

        let bits = flags.to_bits();
        assert!(bits & 1 != 0);
        assert!(bits & 2 != 0);

        let restored = CarveFlags::from_bits(bits);
        assert!(restored.truncated);
        assert!(restored.footer_missing);
    }

    #[test]
    fn test_confidence_parsing() {
        assert_eq!("HIGH".parse::<Confidence>().unwrap(), Confidence::High);
        assert_eq!("low".parse::<Confidence>().unwrap(), Confidence::Low);
    }
}
