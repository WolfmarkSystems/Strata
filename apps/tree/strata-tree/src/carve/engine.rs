// carve/engine.rs — File carving from raw disk images / unallocated space.
// Phase 2, Task 2.2.
//
// Strategy: header-only carving with a per-type size cap.
// For formats with footers (JPEG, ZIP, PDF) the footer offset is also recorded.
// All output files are written to an <output_dir> and reported via progress channel.
// Evidence is opened READ-ONLY — no writes to source image.

use anyhow::{Context, Result};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

// ─── File Signatures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FileSignature {
    pub name: &'static str,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    pub extension: &'static str,
    /// Maximum carved size in bytes.  When footer is None we carve exactly this many bytes.
    pub max_size: u64,
}

/// 26 well-known forensic carving signatures.
pub const SIGNATURES: &[FileSignature] = &[
    // Images
    FileSignature {
        name: "JPEG",
        header: b"\xFF\xD8\xFF",
        footer: Some(b"\xFF\xD9"),
        extension: "jpg",
        max_size: 20_000_000,
    },
    FileSignature {
        name: "PNG",
        header: b"\x89PNG\r\n\x1A\n",
        footer: Some(b"\x49\x45\x4E\x44\xAE\x42\x60\x82"),
        extension: "png",
        max_size: 50_000_000,
    },
    FileSignature {
        name: "GIF87a",
        header: b"GIF87a",
        footer: Some(b"\x00\x3B"),
        extension: "gif",
        max_size: 10_000_000,
    },
    FileSignature {
        name: "GIF89a",
        header: b"GIF89a",
        footer: Some(b"\x00\x3B"),
        extension: "gif",
        max_size: 10_000_000,
    },
    FileSignature {
        name: "BMP",
        header: b"BM",
        footer: None,
        extension: "bmp",
        max_size: 50_000_000,
    },
    FileSignature {
        name: "TIFF-LE",
        header: b"II\x2A\x00",
        footer: None,
        extension: "tif",
        max_size: 100_000_000,
    },
    FileSignature {
        name: "TIFF-BE",
        header: b"MM\x00\x2A",
        footer: None,
        extension: "tif",
        max_size: 100_000_000,
    },
    FileSignature {
        name: "WEBP",
        header: b"RIFF",
        footer: None,
        extension: "webp",
        max_size: 20_000_000,
    },
    // Documents
    FileSignature {
        name: "PDF",
        header: b"%PDF-",
        footer: Some(b"%%EOF"),
        extension: "pdf",
        max_size: 200_000_000,
    },
    FileSignature {
        name: "DOCX/ZIP",
        header: b"PK\x03\x04",
        footer: Some(b"PK\x05\x06"),
        extension: "zip",
        max_size: 200_000_000,
    },
    FileSignature {
        name: "DOC",
        header: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        footer: None,
        extension: "doc",
        max_size: 50_000_000,
    },
    FileSignature {
        name: "RTF",
        header: b"{\\rtf1",
        footer: None,
        extension: "rtf",
        max_size: 50_000_000,
    },
    // Archives
    FileSignature {
        name: "RAR4",
        header: b"Rar!\x1A\x07\x00",
        footer: None,
        extension: "rar",
        max_size: 500_000_000,
    },
    FileSignature {
        name: "RAR5",
        header: b"Rar!\x1A\x07\x01\x00",
        footer: None,
        extension: "rar",
        max_size: 500_000_000,
    },
    FileSignature {
        name: "7ZIP",
        header: b"7z\xBC\xAF'\x1C",
        footer: None,
        extension: "7z",
        max_size: 500_000_000,
    },
    FileSignature {
        name: "GZIP",
        header: b"\x1F\x8B\x08",
        footer: None,
        extension: "gz",
        max_size: 200_000_000,
    },
    // Executables
    FileSignature {
        name: "PE EXE",
        header: b"MZ",
        footer: None,
        extension: "exe",
        max_size: 100_000_000,
    },
    FileSignature {
        name: "ELF",
        header: b"\x7FELF",
        footer: None,
        extension: "elf",
        max_size: 100_000_000,
    },
    // Video
    FileSignature {
        name: "AVI",
        header: b"RIFF",
        footer: None,
        extension: "avi",
        max_size: 2_000_000_000,
    },
    FileSignature {
        name: "MP4",
        header: b"\x00\x00\x00\x18ftyp",
        footer: None,
        extension: "mp4",
        max_size: 2_000_000_000,
    },
    FileSignature {
        name: "MP4-2",
        header: b"\x00\x00\x00\x20ftyp",
        footer: None,
        extension: "mp4",
        max_size: 2_000_000_000,
    },
    // Audio
    FileSignature {
        name: "MP3",
        header: b"\xFF\xFB",
        footer: None,
        extension: "mp3",
        max_size: 50_000_000,
    },
    FileSignature {
        name: "WAV",
        header: b"RIFF",
        footer: None,
        extension: "wav",
        max_size: 200_000_000,
    },
    // Databases / Email
    FileSignature {
        name: "SQLite3",
        header: b"SQLite format 3\x00",
        footer: None,
        extension: "db",
        max_size: 1_000_000_000,
    },
    FileSignature {
        name: "PST",
        header: b"!BDN",
        footer: None,
        extension: "pst",
        max_size: 2_000_000_000,
    },
    // XML / HTML (text-prefixed)
    FileSignature {
        name: "XML",
        header: b"<?xml",
        footer: None,
        extension: "xml",
        max_size: 10_000_000,
    },
];

// ─── Progress / Stats ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CarvedFile {
    pub signature_name: String,
    pub extension: String,
    pub offset: u64,
    pub size: u64,
    pub output_path: PathBuf,
}

#[derive(Debug)]
pub struct CarveStats {
    pub files_carved: u64,
    pub bytes_scanned: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug)]
pub enum CarveProgress {
    Scanning { bytes_done: u64, bytes_total: u64 },
    FileCarved(CarvedFile),
    Complete(CarveStats),
    Failed(String),
}

// ─── Engine ──────────────────────────────────────────────────────────────────

const SCAN_CHUNK: usize = 1024 * 1024; // 1 MB scan window
const PROGRESS_INTERVAL_BYTES: u64 = 10 * 1024 * 1024; // report every 10 MB

pub struct CarveEngine {
    source_path: PathBuf,
    output_dir: PathBuf,
    signatures: Vec<FileSignature>,
    cancel_flag: Option<Arc<AtomicBool>>,
}

impl CarveEngine {
    pub fn new(source_path: impl AsRef<Path>, output_dir: impl AsRef<Path>) -> Self {
        Self {
            source_path: source_path.as_ref().to_path_buf(),
            output_dir: output_dir.as_ref().to_path_buf(),
            signatures: SIGNATURES.to_vec(),
            cancel_flag: None,
        }
    }

    pub fn with_signatures(mut self, signatures: Vec<FileSignature>) -> Self {
        if !signatures.is_empty() {
            self.signatures = signatures;
        }
        self
    }

    pub fn with_cancel_flag(mut self, cancel_flag: Arc<AtomicBool>) -> Self {
        self.cancel_flag = Some(cancel_flag);
        self
    }

    /// Carve the source file/image.  Reports progress via `tx`.
    pub fn carve(&self, tx: Option<Sender<CarveProgress>>) -> Result<CarveStats> {
        let start = std::time::Instant::now();
        std::fs::create_dir_all(&self.output_dir).with_context(|| {
            format!(
                "Cannot create carve output dir: {}",
                self.output_dir.display()
            )
        })?;

        let file = std::fs::File::open(&self.source_path)
            .with_context(|| format!("Cannot open source: {}", self.source_path.display()))?;
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut reader = BufReader::with_capacity(SCAN_CHUNK * 2, file);

        let max_header_len = SIGNATURES.iter().map(|s| s.header.len()).max().unwrap_or(0);

        let mut buf = vec![0u8; SCAN_CHUNK + max_header_len];
        let mut file_offset: u64 = 0;
        let mut carved_count: u64 = 0;
        let mut last_progress_at: u64 = 0;

        loop {
            if let Some(flag) = &self.cancel_flag {
                if flag.load(Ordering::Relaxed) {
                    if let Some(ref tx) = tx {
                        let _ = tx.send(CarveProgress::Failed(
                            "Carving canceled by examiner".to_string(),
                        ));
                    }
                    return Ok(CarveStats {
                        files_carved: carved_count,
                        bytes_scanned: file_offset,
                        elapsed_ms: start.elapsed().as_millis() as u64,
                    });
                }
            }

            let n = reader.read(&mut buf).context("Read error on source")?;
            if n == 0 {
                break;
            }

            let window = &buf[..n];

            // Scan window for each signature.
            for sig in &self.signatures {
                let hlen = sig.header.len();
                if hlen > window.len() {
                    continue;
                }
                for i in 0..=(window.len() - hlen) {
                    if window[i..i + hlen] != *sig.header {
                        continue;
                    }

                    let abs_offset = file_offset + i as u64;

                    // Stream carved bytes directly to disk — never hold
                    // the full carved file in memory (can be 2 GB for
                    // PST/MP4/AVI signatures).
                    let out_name = format!(
                        "carved_{:08}_{}.{}",
                        carved_count,
                        sig.name.to_lowercase().replace(' ', "_"),
                        sig.extension
                    );
                    let out_path = self.output_dir.join(&out_name);
                    let size = match extract_carved_to_file(
                        &self.source_path,
                        abs_offset,
                        sig,
                        &out_path,
                    ) {
                        Ok(s) => s,
                        Err(_) => {
                            let _ = std::fs::remove_file(&out_path);
                            continue;
                        }
                    };

                    let carved_file = CarvedFile {
                        signature_name: sig.name.to_string(),
                        extension: sig.extension.to_string(),
                        offset: abs_offset,
                        size,
                        output_path: out_path,
                    };
                    carved_count += 1;
                    if let Some(ref tx) = tx {
                        let _ = tx.send(CarveProgress::FileCarved(carved_file));
                    }
                }
            }

            file_offset += n as u64;

            // Seek back by max_header_len so we don't miss headers crossing chunk boundaries.
            let backtrack = max_header_len.min(n);
            if backtrack < n {
                reader.seek(SeekFrom::Current(-(backtrack as i64))).ok();
                file_offset -= backtrack as u64;
            }

            if file_offset - last_progress_at >= PROGRESS_INTERVAL_BYTES {
                last_progress_at = file_offset;
                if let Some(ref tx) = tx {
                    let _ = tx.send(CarveProgress::Scanning {
                        bytes_done: file_offset,
                        bytes_total: file_len,
                    });
                }
            }
        }

        let stats = CarveStats {
            files_carved: carved_count,
            bytes_scanned: file_offset,
            elapsed_ms: start.elapsed().as_millis() as u64,
        };

        if let Some(ref tx) = tx {
            let _ = tx.send(CarveProgress::Complete(CarveStats {
                files_carved: stats.files_carved,
                bytes_scanned: stats.bytes_scanned,
                elapsed_ms: stats.elapsed_ms,
            }));
        }

        Ok(stats)
    }
}

pub fn carve_unallocated_with_options(
    source: &crate::state::EvidenceSource,
    signatures: Vec<FileSignature>,
    output_root: PathBuf,
    cancel_flag: Option<Arc<AtomicBool>>,
    tx: Sender<CarveProgress>,
) -> std::thread::JoinHandle<()> {
    let source_path = PathBuf::from(&source.path);
    let source_id = source.id.clone();
    std::thread::spawn(move || {
        let output_dir = output_root.join(source_id);

        let mut engine = CarveEngine::new(&source_path, &output_dir).with_signatures(signatures);
        if let Some(flag) = cancel_flag {
            engine = engine.with_cancel_flag(flag);
        }
        if let Err(e) = engine.carve(Some(tx.clone())) {
            let _ = tx.send(CarveProgress::Failed(e.to_string()));
        }
    })
}

/// Stream carved data from `source` at `offset` directly to `out_path`
/// using 64 KB chunks. Never holds the full carved file in memory.
/// Returns the number of bytes written. For signatures with a footer
/// pattern, maintains a small overlap buffer across chunk boundaries
/// to detect the footer, then truncates the output file.
fn extract_carved_to_file(
    source: &Path,
    offset: u64,
    sig: &FileSignature,
    out_path: &Path,
) -> Result<u64> {
    use std::io::Write;
    let mut f = std::fs::File::open(source)?;
    f.seek(SeekFrom::Start(offset))?;

    let mut out = std::io::BufWriter::new(std::fs::File::create(out_path)?);
    let cap = sig.max_size as usize;
    let mut chunk = vec![0u8; 65536];
    let mut written = 0usize;

    let footer_len = sig.footer.map(|ft| ft.len()).unwrap_or(0);
    let overlap_keep = footer_len.saturating_sub(1);
    let mut tail = Vec::with_capacity(overlap_keep);

    loop {
        if written >= cap {
            break;
        }
        let to_read = chunk.len().min(cap - written);
        let n = f.read(&mut chunk[..to_read])?;
        if n == 0 {
            break;
        }

        if let Some(footer) = sig.footer {
            let mut search_buf = Vec::with_capacity(tail.len() + n);
            search_buf.extend_from_slice(&tail);
            search_buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_pattern(&search_buf, footer) {
                let footer_end = pos + footer.len();
                let new_bytes = footer_end.saturating_sub(tail.len());
                out.write_all(&chunk[..new_bytes.min(n)])?;
                written += new_bytes.min(n);
                out.flush()?;
                let total = written as u64;
                let inner = out.into_inner()?;
                inner.set_len(total)?;
                return Ok(total);
            }
            tail.clear();
            if overlap_keep > 0 && n >= overlap_keep {
                tail.extend_from_slice(&chunk[n - overlap_keep..n]);
            } else if overlap_keep > 0 {
                tail.extend_from_slice(&chunk[..n]);
                if tail.len() > overlap_keep {
                    let excess = tail.len() - overlap_keep;
                    tail.drain(0..excess);
                }
            }
        }

        out.write_all(&chunk[..n])?;
        written += n;
    }

    out.flush()?;
    Ok(written as u64)
}

/// Open the source read-only, seek to `offset`, and extract up to sig.max_size bytes.
/// If a footer pattern is defined, scan for it and truncate there.
#[allow(dead_code)]
fn extract_carved(source: &Path, offset: u64, sig: &FileSignature) -> Result<Vec<u8>> {
    let mut f = std::fs::File::open(source)?;
    f.seek(SeekFrom::Start(offset))?;

    let cap = sig.max_size as usize;
    let mut data = Vec::with_capacity(cap.min(1024 * 1024));
    let mut chunk = vec![0u8; 65536];
    let mut read_total = 0usize;

    loop {
        if read_total >= cap {
            break;
        }
        let to_read = chunk.len().min(cap - read_total);
        let n = f.read(&mut chunk[..to_read])?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..n]);
        read_total += n;

        // Check footer.
        if let Some(footer) = sig.footer {
            if let Some(pos) = find_pattern(&data, footer) {
                data.truncate(pos + footer.len());
                return Ok(data);
            }
        }
    }

    Ok(data)
}

/// Simple Boyer-Moore-Horspool-inspired pattern search. Returns first occurrence index.
fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Validate a carved file to detect corruption or false positives.
/// Returns (is_valid, confidence, reason).
#[allow(dead_code)]
pub fn validate_carved_file(data: &[u8], sig_name: &str) -> (bool, f32, String) {
    if data.is_empty() {
        return (false, 0.0, "Empty file".to_string());
    }

    match sig_name {
        "JPEG" => validate_jpeg(data),
        "PNG" => validate_png(data),
        "PDF" => validate_pdf(data),
        "ZIP" | "DOCX" | "XLSX" | "PPTX" => validate_zip(data),
        "PE" => validate_pe(data),
        "SQLite" => validate_sqlite(data),
        _ => (true, 0.5, "No specific validation available".to_string()),
    }
}

fn validate_jpeg(data: &[u8]) -> (bool, f32, String) {
    if data.len() < 20 {
        return (false, 0.1, "Too small for JPEG".to_string());
    }
    // Check SOI marker
    if data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
        return (false, 0.0, "Invalid JPEG SOI marker".to_string());
    }
    // Check for EOI at end
    let has_eoi = data.len() >= 2 && data[data.len() - 2] == 0xFF && data[data.len() - 1] == 0xD9;
    if has_eoi {
        // Check for reasonable JPEG structure: should have at least one marker segment
        let marker_count = data
            .windows(2)
            .filter(|w| w[0] == 0xFF && w[1] >= 0xC0 && w[1] != 0xFF)
            .count();
        if marker_count >= 3 {
            (true, 0.95, format!("Valid JPEG with EOI ({} markers)", marker_count))
        } else {
            (true, 0.6, "JPEG with EOI but few markers".to_string())
        }
    } else {
        (true, 0.3, "JPEG without EOI — may be truncated".to_string())
    }
}

fn validate_png(data: &[u8]) -> (bool, f32, String) {
    if data.len() < 33 {
        return (false, 0.1, "Too small for PNG".to_string());
    }
    // Check magic
    if &data[0..8] != b"\x89PNG\r\n\x1A\n" {
        return (false, 0.0, "Invalid PNG magic".to_string());
    }
    // Check IHDR chunk
    if &data[12..16] == b"IHDR" {
        let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        if width > 0 && width < 65536 && height > 0 && height < 65536 {
            // Check for IEND at end
            let has_iend = data.len() >= 8 && &data[data.len() - 8..data.len() - 4] == b"IEND";
            if has_iend {
                (true, 0.95, format!("Valid PNG {}x{} with IEND", width, height))
            } else {
                (true, 0.5, format!("PNG {}x{} without IEND — may be truncated", width, height))
            }
        } else {
            (false, 0.2, format!("PNG with unreasonable dimensions {}x{}", width, height))
        }
    } else {
        (false, 0.2, "PNG missing IHDR chunk".to_string())
    }
}

fn validate_pdf(data: &[u8]) -> (bool, f32, String) {
    if data.len() < 20 {
        return (false, 0.1, "Too small for PDF".to_string());
    }
    if &data[0..5] != b"%PDF-" {
        return (false, 0.0, "Invalid PDF header".to_string());
    }
    // Check for %%EOF at end
    let tail = &data[data.len().saturating_sub(128)..];
    let has_eof = tail.windows(5).any(|w| w == b"%%EOF");
    if has_eof {
        (true, 0.9, "Valid PDF with %%EOF".to_string())
    } else {
        (true, 0.4, "PDF without %%EOF — may be truncated".to_string())
    }
}

fn validate_zip(data: &[u8]) -> (bool, f32, String) {
    if data.len() < 30 {
        return (false, 0.1, "Too small for ZIP".to_string());
    }
    if &data[0..4] != b"PK\x03\x04" {
        return (false, 0.0, "Invalid ZIP local file header".to_string());
    }
    // Check for End of Central Directory
    let has_eocd = data.windows(4).any(|w| w == b"PK\x05\x06");
    if has_eocd {
        (true, 0.9, "Valid ZIP with EOCD".to_string())
    } else {
        (true, 0.4, "ZIP without EOCD — may be truncated".to_string())
    }
}

fn validate_pe(data: &[u8]) -> (bool, f32, String) {
    if data.len() < 64 {
        return (false, 0.1, "Too small for PE".to_string());
    }
    if data[0] != 0x4D || data[1] != 0x5A {
        return (false, 0.0, "Invalid MZ header".to_string());
    }
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_offset > 0 && pe_offset + 4 < data.len() && &data[pe_offset..pe_offset + 4] == b"PE\x00\x00" {
        (true, 0.9, "Valid PE with PE signature".to_string())
    } else {
        (true, 0.3, "MZ header but no PE signature".to_string())
    }
}

fn validate_sqlite(data: &[u8]) -> (bool, f32, String) {
    if data.len() < 100 {
        return (false, 0.1, "Too small for SQLite".to_string());
    }
    if &data[0..16] == b"SQLite format 3\x00" {
        let page_size = u16::from_be_bytes([data[16], data[17]]) as usize;
        if (512..=65536).contains(&page_size) && data.len() >= page_size {
            (true, 0.9, format!("Valid SQLite (page_size={})", page_size))
        } else {
            (true, 0.5, "SQLite header but unexpected page size".to_string())
        }
    } else {
        (false, 0.0, "Invalid SQLite header".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{CarveEngine, SIGNATURES};

    #[test]
    fn carving_writes_output_files_to_selected_directory() {
        let root =
            std::env::temp_dir().join(format!("strata_carve_test_{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&root);
        let source = root.join("source.bin");
        let output = root.join("carved_out");

        let mut payload = vec![0u8; 4096];
        let jpeg = b"\xFF\xD8\xFF\xE0TESTJPEGDATA\xFF\xD9";
        payload[512..512 + jpeg.len()].copy_from_slice(jpeg);
        std::fs::write(&source, payload).expect("write source");

        let jpeg_sig = SIGNATURES
            .iter()
            .find(|sig| sig.name == "JPEG")
            .expect("jpeg signature")
            .clone();
        let engine = CarveEngine::new(&source, &output).with_signatures(vec![jpeg_sig]);
        let stats = engine.carve(None).expect("carve run");
        assert!(stats.files_carved >= 1);

        let carved_count = std::fs::read_dir(&output).expect("read output").count();
        assert!(carved_count >= 1);

        let _ = std::fs::remove_dir_all(&root);
    }
}
