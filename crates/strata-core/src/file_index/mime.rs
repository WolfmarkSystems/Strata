//! Magic-byte MIME detection — never trusts file extensions.
//!
//! The signature table covers the file types Strata plugins care
//! about most (SQLite, PE, ELF, PDF, ZIP/DOCX, RAR, 7z, JPEG, PNG,
//! GIF, MP4, MP3, PST/OST, LNK, Mach-O, registry hive). Returns
//! `None` when no signature matches — callers may fall back to
//! extension-based labels, but must document that the MIME is
//! inferred.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

pub struct MimeSignature {
    pub mime: &'static str,
    pub magic: &'static [u8],
    pub offset: usize,
}

pub const SIGNATURES: &[MimeSignature] = &[
    MimeSignature {
        mime: "application/x-sqlite3",
        magic: b"SQLite format 3\0",
        offset: 0,
    },
    MimeSignature {
        mime: "application/vnd.microsoft.portable-executable",
        magic: b"MZ",
        offset: 0,
    },
    MimeSignature {
        mime: "application/x-executable",
        magic: &[0x7F, b'E', b'L', b'F'],
        offset: 0,
    },
    MimeSignature {
        mime: "application/x-mach-binary",
        magic: &[0xCF, 0xFA, 0xED, 0xFE],
        offset: 0,
    },
    MimeSignature {
        mime: "application/x-mach-binary",
        magic: &[0xCE, 0xFA, 0xED, 0xFE],
        offset: 0,
    },
    MimeSignature {
        mime: "application/pdf",
        magic: b"%PDF",
        offset: 0,
    },
    MimeSignature {
        mime: "application/zip",
        magic: &[0x50, 0x4B, 0x03, 0x04],
        offset: 0,
    },
    MimeSignature {
        mime: "application/x-rar",
        magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
        offset: 0,
    },
    MimeSignature {
        mime: "application/x-7z-compressed",
        magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        offset: 0,
    },
    MimeSignature {
        mime: "image/jpeg",
        magic: &[0xFF, 0xD8, 0xFF],
        offset: 0,
    },
    MimeSignature {
        mime: "image/png",
        magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        offset: 0,
    },
    MimeSignature {
        mime: "image/gif",
        magic: b"GIF8",
        offset: 0,
    },
    MimeSignature {
        mime: "image/webp",
        magic: b"WEBP",
        offset: 8,
    },
    MimeSignature {
        mime: "image/heif",
        magic: b"ftypheic",
        offset: 4,
    },
    MimeSignature {
        mime: "image/heif",
        magic: b"ftypmif1",
        offset: 4,
    },
    MimeSignature {
        mime: "video/mp4",
        magic: b"ftyp",
        offset: 4,
    },
    MimeSignature {
        mime: "audio/mpeg",
        magic: &[0xFF, 0xFB],
        offset: 0,
    },
    MimeSignature {
        mime: "audio/mpeg",
        magic: b"ID3",
        offset: 0,
    },
    MimeSignature {
        mime: "application/vnd.ms-outlook-pst",
        magic: b"!BDN",
        offset: 0,
    },
    MimeSignature {
        mime: "application/x-ms-shortcut",
        magic: &[0x4C, 0x00, 0x00, 0x00],
        offset: 0,
    },
    MimeSignature {
        mime: "application/x-windows-registry-hive",
        magic: b"regf",
        offset: 0,
    },
    MimeSignature {
        mime: "application/x-windows-prefetch",
        magic: b"SCCA",
        offset: 4,
    },
    MimeSignature {
        mime: "application/x-gzip",
        magic: &[0x1F, 0x8B],
        offset: 0,
    },
    MimeSignature {
        mime: "application/x-bzip2",
        magic: b"BZh",
        offset: 0,
    },
    MimeSignature {
        mime: "application/x-xz",
        magic: &[0xFD, b'7', b'z', b'X', b'Z', 0x00],
        offset: 0,
    },
];

/// Classify a MIME type from magic bytes. Pass at least the first 64
/// bytes of the file.
pub fn detect(bytes: &[u8]) -> Option<&'static str> {
    for sig in SIGNATURES {
        let end = sig.offset + sig.magic.len();
        if bytes.len() < end {
            continue;
        }
        if &bytes[sig.offset..end] == sig.magic {
            return Some(sig.mime);
        }
    }
    if is_probably_text(bytes) {
        return Some("text/plain");
    }
    None
}

fn is_probably_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let sample = &bytes[..bytes.len().min(512)];
    let printable = sample
        .iter()
        .filter(|b| (0x20u8..=0x7E).contains(*b) || matches!(**b, b'\t' | b'\n' | b'\r'))
        .count();
    (printable as f64 / sample.len() as f64) > 0.95
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sqlite_header() {
        assert_eq!(
            detect(b"SQLite format 3\0something"),
            Some("application/x-sqlite3")
        );
    }

    #[test]
    fn detects_pe_and_elf() {
        assert_eq!(
            detect(b"MZ\x90\x00"),
            Some("application/vnd.microsoft.portable-executable")
        );
        assert_eq!(
            detect(&[0x7F, b'E', b'L', b'F', 0x02]),
            Some("application/x-executable")
        );
    }

    #[test]
    fn detects_zip_pdf_jpeg() {
        assert_eq!(detect(b"%PDF-1.7"), Some("application/pdf"));
        assert_eq!(detect(&[0x50, 0x4B, 0x03, 0x04]), Some("application/zip"));
        assert_eq!(detect(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
    }

    #[test]
    fn detects_mp4_at_offset_4() {
        let mut blob = vec![0u8; 4];
        blob.extend_from_slice(b"ftypisom");
        assert_eq!(detect(&blob), Some("video/mp4"));
    }

    #[test]
    fn falls_back_to_text_plain_for_ascii() {
        assert_eq!(detect(b"hello world"), Some("text/plain"));
        assert!(detect(&[0u8, 1, 2, 3]).is_none());
    }

    #[test]
    fn returns_none_on_empty_input() {
        assert!(detect(&[]).is_none());
    }
}
