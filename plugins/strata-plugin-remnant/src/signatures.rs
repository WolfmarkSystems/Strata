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
    let s = |name: &str, header: &[u8], footer: Option<&[u8]>, ext: &str, ft: &str, max_mb: u64| {
        CarveSignature {
            name: name.to_string(),
            header: header.to_vec(),
            footer: footer.map(|f| f.to_vec()),
            max_size: max_mb * 1024 * 1024,
            min_size: 32,
            extension: ext.to_string(),
            file_type: ft.to_string(),
            method: if footer.is_some() { CarveMethod::HeaderFooter } else { CarveMethod::HeaderSize },
            size_offset: None,
            size_endian: None,
            size_adjust: 0,
        }
    };

    vec![
        // ── CRITICAL: Forensic-specific ──────────────────────────────────
        s("PE Executable", b"MZ", None, "exe", "application/x-dosexec", 500),
        s("Windows Event Log", b"ElfFile\x00", None, "evtx", "application/x-evtx", 1000),
        s("Registry Hive", b"regf", None, "hve", "application/x-registry", 500),
        s("SQLite Database", b"SQLite format 3\x00", None, "db", "application/x-sqlite3", 2000),
        s("PST Email Archive", &[0x21, 0x42, 0x44, 0x4E], None, "pst", "application/vnd.ms-outlook", 50000),
        s("Prefetch File", b"MAM\x04", None, "pf", "application/x-prefetch", 10),
        s("LNK Shortcut", &[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00], None, "lnk", "application/x-ms-shortcut", 1),
        s("PEM Private Key", b"-----BEGIN", None, "pem", "application/x-pem", 1),
        s("PFX Certificate", &[0x30, 0x82], None, "pfx", "application/x-pkcs12", 10),

        // ── HIGH: Documents ──────────────────────────────────────────────
        s("PDF", b"%PDF", Some(b"%%EOF"), "pdf", "application/pdf", 500),
        s("ZIP/DOCX/XLSX", b"PK\x03\x04", Some(b"PK\x05\x06"), "zip", "application/zip", 2000),
        s("Legacy DOC/XLS", &[0xD0, 0xCF, 0x11, 0xE0], None, "doc", "application/msword", 200),
        s("RTF", &[0x7B, 0x5C, 0x72, 0x74, 0x66], None, "rtf", "application/rtf", 50),
        s("EML Email", b"From ", None, "eml", "message/rfc822", 100),
        s("MBOX Mailbox", b"From ", None, "mbox", "application/mbox", 5000),

        // ── MEDIUM: Images ───────────────────────────────────────────────
        s("JPEG", &[0xFF, 0xD8, 0xFF], Some(&[0xFF, 0xD9]), "jpg", "image/jpeg", 50),
        s("PNG", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]), "png", "image/png", 50),
        s("GIF87a", b"GIF87a", Some(&[0x00, 0x3B]), "gif", "image/gif", 20),
        s("GIF89a", b"GIF89a", Some(&[0x00, 0x3B]), "gif", "image/gif", 20),
        s("BMP", b"BM", None, "bmp", "image/bmp", 50),
        s("TIFF LE", &[0x49, 0x49, 0x2A, 0x00], None, "tif", "image/tiff", 200),
        s("TIFF BE", &[0x4D, 0x4D, 0x00, 0x2A], None, "tif", "image/tiff", 200),
        s("WEBP", b"RIFF", None, "webp", "image/webp", 50),
        s("ICO", &[0x00, 0x00, 0x01, 0x00], None, "ico", "image/x-icon", 5),
        s("PSD", b"8BPS", None, "psd", "image/vnd.adobe.photoshop", 500),

        // ── MEDIUM: Audio/Video ──────────────────────────────────────────
        s("MP4/M4A", &[0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], None, "mp4", "video/mp4", 4000),
        s("MP4 ftyp", &[0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70], None, "mp4", "video/mp4", 4000),
        s("AVI RIFF", b"RIFF", None, "avi", "video/x-msvideo", 4000),
        s("MP3 ID3", b"ID3", None, "mp3", "audio/mpeg", 500),
        s("MP3 Sync", &[0xFF, 0xFB], None, "mp3", "audio/mpeg", 500),
        s("WAV", b"RIFF", None, "wav", "audio/wav", 500),
        s("OGG", b"OggS", None, "ogg", "audio/ogg", 500),
        s("FLV", b"FLV", None, "flv", "video/x-flv", 2000),
        s("MKV/WebM", &[0x1A, 0x45, 0xDF, 0xA3], None, "mkv", "video/x-matroska", 4000),
        s("MOV", &[0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70], None, "mov", "video/quicktime", 4000),

        // ── MEDIUM: Archives ─────────────────────────────────────────────
        s("RAR4", b"Rar!\x1A\x07\x00", None, "rar", "application/x-rar", 2000),
        s("RAR5", b"Rar!\x1A\x07\x01\x00", None, "rar", "application/x-rar", 2000),
        s("7Z", &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], None, "7z", "application/x-7z-compressed", 2000),
        s("GZIP", &[0x1F, 0x8B, 0x08], None, "gz", "application/gzip", 2000),
        s("BZIP2", b"BZ", None, "bz2", "application/x-bzip2", 2000),
        s("XZ", &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], None, "xz", "application/x-xz", 2000),
        s("TAR", &[0x75, 0x73, 0x74, 0x61, 0x72], None, "tar", "application/x-tar", 4000),
        s("CAB", b"MSCF", None, "cab", "application/vnd.ms-cab-compressed", 500),

        // ── HIGH: Crypto/Keys ────────────────────────────────────────────
        s("SSH Private Key", b"-----BEGIN OPENSSH PRIVATE KEY", None, "key", "application/x-ssh-key", 1),
        s("RSA Private Key", b"-----BEGIN RSA PRIVATE KEY", None, "key", "application/x-pem", 1),
        s("EC Private Key", b"-----BEGIN EC PRIVATE KEY", None, "key", "application/x-pem", 1),
        s("X.509 Certificate", b"-----BEGIN CERTIFICATE", None, "crt", "application/x-x509-cert", 1),

        // ── HIGH: System ─────────────────────────────────────────────────
        s("ELF Executable", &[0x7F, 0x45, 0x4C, 0x46], None, "elf", "application/x-elf", 500),
        s("Mach-O 64", &[0xCF, 0xFA, 0xED, 0xFE], None, "macho", "application/x-mach-binary", 500),
        s("Mach-O 32", &[0xCE, 0xFA, 0xED, 0xFE], None, "macho", "application/x-mach-binary", 500),
        s("Java Class", &[0xCA, 0xFE, 0xBA, 0xBE], None, "class", "application/java-vm", 50),
        s("DEX (Android)", b"dex\n", None, "dex", "application/x-dex", 100),

        // ── MEDIUM: macOS/Mobile ─────────────────────────────────────────
        s("Binary PLIST", b"bplist00", None, "plist", "application/x-plist", 100),
        s("macOS DMG", &[0x78, 0x01, 0x73, 0x0D], None, "dmg", "application/x-apple-diskimage", 50000),
        s("Android Backup", b"ANDROID BACKUP\n", None, "ab", "application/x-android-backup", 50000),

        // ── MEDIUM: Forensic containers ──────────────────────────────────
        s("E01 (EnCase)", b"EVF\x09\x0D\x0A\xFF\x00", None, "E01", "application/x-encase", 50000),
        s("QCOW2", b"QFI\xFB", None, "qcow2", "application/x-qcow2", 50000),
        s("VMDK", b"KDMV", None, "vmdk", "application/x-vmdk", 50000),

        // ── LOW: Misc ────────────────────────────────────────────────────
        s("XML", b"<?xml", None, "xml", "application/xml", 100),
        s("HTML", b"<!DOCTYPE html", None, "html", "text/html", 50),
        s("HTML tag", b"<html", None, "html", "text/html", 50),
        s("JSON Object", b"{\"", None, "json", "application/json", 100),
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
