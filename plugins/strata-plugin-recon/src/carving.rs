//! Header/footer-signature file carver (R-4).
//!
//! Research reference: searchlight (MIT) — studied only; implementation
//! written independently.
//!
//! Scans raw disk-image bytes for well-known file signatures. The
//! carver runs read-only and never materialises the carved bytes to
//! disk — it emits lightweight metadata (offset, header hex, entropy)
//! that the UI can use to guide targeted extraction.
//!
//! ## Signatures
//! JPEG, PNG, PDF, ZIP-family (ZIP/DOCX/XLSX/APK/JAR), RAR, 7z, SQLite,
//! ELF, PE/MZ, GIF, MP4 (header at offset 4).
//!
//! ## Caps
//! * Max carved items per input file: 10 000.
//! * Max carved byte size per item: signature-specific.
//!
//! ## MITRE ATT&CK
//! * **T1027** — Obfuscated Files or Information (high-entropy hits).
//! * **T1083** — File and Directory Discovery.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

/// A declared carving signature.
#[derive(Debug, Clone, Copy)]
pub struct CarveSignature {
    pub file_type: &'static str,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    pub max_size: usize,
    pub mime_type: &'static str,
    /// Header offset within the file (usually 0). MP4 lives at 4.
    pub header_offset: usize,
}

pub const SIGNATURES: &[CarveSignature] = &[
    CarveSignature {
        file_type: "JPEG",
        header: &[0xFF, 0xD8, 0xFF],
        footer: Some(&[0xFF, 0xD9]),
        max_size: 64 * 1024 * 1024,
        mime_type: "image/jpeg",
        header_offset: 0,
    },
    CarveSignature {
        file_type: "PNG",
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
        max_size: 256 * 1024 * 1024,
        mime_type: "image/png",
        header_offset: 0,
    },
    CarveSignature {
        file_type: "PDF",
        header: &[0x25, 0x50, 0x44, 0x46],
        footer: Some(&[0x25, 0x25, 0x45, 0x4F, 0x46]),
        max_size: 512 * 1024 * 1024,
        mime_type: "application/pdf",
        header_offset: 0,
    },
    CarveSignature {
        file_type: "ZIP/DOCX/XLSX",
        header: &[0x50, 0x4B, 0x03, 0x04],
        footer: None,
        max_size: 2 * 1024 * 1024 * 1024,
        mime_type: "application/zip",
        header_offset: 0,
    },
    CarveSignature {
        file_type: "RAR",
        header: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
        footer: None,
        max_size: 2 * 1024 * 1024 * 1024,
        mime_type: "application/x-rar",
        header_offset: 0,
    },
    CarveSignature {
        file_type: "7Z",
        header: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        footer: None,
        max_size: 2 * 1024 * 1024 * 1024,
        mime_type: "application/x-7z-compressed",
        header_offset: 0,
    },
    CarveSignature {
        file_type: "SQLite",
        header: b"SQLite format 3\0",
        footer: None,
        max_size: 1024 * 1024 * 1024,
        mime_type: "application/x-sqlite3",
        header_offset: 0,
    },
    CarveSignature {
        file_type: "ELF",
        header: &[0x7F, 0x45, 0x4C, 0x46],
        footer: None,
        max_size: 512 * 1024 * 1024,
        mime_type: "application/x-executable",
        header_offset: 0,
    },
    CarveSignature {
        file_type: "PE/EXE/DLL",
        header: &[0x4D, 0x5A],
        footer: None,
        max_size: 512 * 1024 * 1024,
        mime_type: "application/vnd.microsoft.portable-executable",
        header_offset: 0,
    },
    CarveSignature {
        file_type: "GIF",
        header: &[0x47, 0x49, 0x46, 0x38],
        footer: Some(&[0x00, 0x3B]),
        max_size: 64 * 1024 * 1024,
        mime_type: "image/gif",
        header_offset: 0,
    },
    CarveSignature {
        file_type: "MP4",
        header: &[0x66, 0x74, 0x79, 0x70],
        footer: None,
        max_size: 2 * 1024 * 1024 * 1024,
        mime_type: "video/mp4",
        header_offset: 4,
    },
];

/// Hard cap on carved files surfaced per input file.
pub const MAX_CARVED_PER_FILE: usize = 10_000;

/// One hit.
#[derive(Debug, Clone, PartialEq)]
pub struct CarvedFile {
    pub file_type: &'static str,
    pub mime_type: &'static str,
    pub offset: u64,
    pub size: usize,
    /// Hex of the first 16 bytes of the carved run.
    pub header_hex: String,
    /// Shannon entropy over a sample of the carved bytes (0.0..=8.0).
    pub entropy: f64,
    /// True when entropy > 7.5 or when a PE hit lands outside an
    /// executable-like location (caller enriches that latter context).
    pub suspicious: bool,
}

/// Carve `bytes`. Safe to call on very large slices — internal cap.
pub fn carve(bytes: &[u8]) -> Vec<CarvedFile> {
    let mut out = Vec::new();
    for sig in SIGNATURES {
        if out.len() >= MAX_CARVED_PER_FILE {
            break;
        }
        let mut cursor = 0usize;
        while let Some(rel) = find_from(bytes, cursor, sig) {
            if out.len() >= MAX_CARVED_PER_FILE {
                break;
            }
            let hit_start = rel;
            let size = match sig.footer {
                Some(foot) => {
                    let scan_end = (hit_start + sig.max_size).min(bytes.len());
                    if let Some(rel_end) =
                        find_in_range(bytes, hit_start + sig.header.len(), scan_end, foot)
                    {
                        rel_end + foot.len() - hit_start
                    } else {
                        sig.header.len().min(bytes.len() - hit_start)
                    }
                }
                None => {
                    // No footer — sample up to 64 KiB for entropy and
                    // record that as the captured size. Callers that
                    // need the full body re-read from `offset` with a
                    // format-specific extractor.
                    const SAMPLE: usize = 64 * 1024;
                    SAMPLE.min(bytes.len() - hit_start)
                }
            };
            let end = (hit_start + size).min(bytes.len());
            let slice = &bytes[hit_start..end];
            let header_hex = hex(&slice[..slice.len().min(16)]);
            let entropy = shannon_entropy(&slice[..slice.len().min(65_536)]);
            let suspicious = entropy > 7.5;
            out.push(CarvedFile {
                file_type: sig.file_type,
                mime_type: sig.mime_type,
                offset: hit_start as u64,
                size,
                header_hex,
                entropy,
                suspicious,
            });
            cursor = hit_start + sig.header.len();
        }
    }
    out
}

fn find_from(haystack: &[u8], from: usize, sig: &CarveSignature) -> Option<usize> {
    let effective_start = from.checked_sub(sig.header_offset).unwrap_or(from);
    let pos = memmem(&haystack[effective_start..], sig.header)?;
    let absolute = effective_start + pos;
    absolute.checked_sub(sig.header_offset)
}

fn find_in_range(haystack: &[u8], from: usize, to: usize, needle: &[u8]) -> Option<usize> {
    let end = to.min(haystack.len());
    if from >= end {
        return None;
    }
    memmem(&haystack[from..end], needle).map(|p| p + from)
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02X}", b));
    }
    out
}

/// Shannon entropy in bits/byte over the sample slice.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carve_empty_returns_empty() {
        assert!(carve(&[]).is_empty());
    }

    #[test]
    fn carve_finds_pdf_with_footer() {
        let mut blob = vec![0u8; 100];
        let body = b"%PDF-1.7\ncontent goes here\n%%EOF";
        blob.extend_from_slice(body);
        blob.extend_from_slice(&[0u8; 50]);
        let hits = carve(&blob);
        assert!(hits
            .iter()
            .any(|h| h.file_type == "PDF" && h.offset == 100 && h.size == body.len()));
    }

    #[test]
    fn carve_finds_multiple_signatures_and_captures_header_hex() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"SQLite format 3\0");
        blob.extend_from_slice(&[0u8; 32]);
        blob.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]);
        blob.extend_from_slice(&[0xFF, 0xD9]);
        let hits = carve(&blob);
        assert!(hits.iter().any(|h| h.file_type == "SQLite"));
        assert!(hits.iter().any(|h| h.file_type == "JPEG"));
        let jpg = hits.iter().find(|h| h.file_type == "JPEG").expect("jpeg");
        assert!(jpg.header_hex.starts_with("FFD8FF"));
    }

    #[test]
    fn carve_high_entropy_payload_flags_suspicious() {
        // Random-looking bytes after a PE header → high entropy → flagged.
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0x4D, 0x5A]);
        // Pseudo-random body via a simple xorshift.
        let mut x: u64 = 0x1234_5678_9ABC_DEF0;
        for _ in 0..65_536 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            blob.push((x & 0xFF) as u8);
        }
        let hits = carve(&blob);
        let pe = hits
            .iter()
            .find(|h| h.file_type == "PE/EXE/DLL")
            .expect("pe");
        assert!(pe.entropy > 7.0, "entropy was {}", pe.entropy);
    }

    #[test]
    fn shannon_entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0u8; 32]), 0.0);
        let uniform: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&uniform);
        assert!((e - 8.0).abs() < 0.001);
    }

    #[test]
    fn carve_mp4_uses_offset_header() {
        let mut blob = vec![0u8; 4];
        blob.extend_from_slice(b"ftyp");
        blob.extend_from_slice(b"isom");
        blob.extend_from_slice(&[0u8; 32]);
        let hits = carve(&blob);
        assert!(hits.iter().any(|h| h.file_type == "MP4" && h.offset == 0));
    }
}
