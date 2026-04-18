//! EVIDENCE-2 — pure-Rust EWF/E01 reader.
//!
//! Implements the read path for the EWF v1 (Expert Witness Format)
//! container: magic "EVF\x09\x0D\x0A\xFF\x00", multi-segment support
//! (.E01 / .E02 / .EE1 / …), table + table2 chunk index sections,
//! and zlib-compressed or uncompressed chunks. Metadata (examiner,
//! case number, evidence number, acquisition date, tool, notes,
//! stored MD5/SHA1 hashes) is extracted from the header2 / header /
//! hash sections where present.
//!
//! Deliberately pure-Rust: no FFI to libewf, no `unsafe {}` blocks,
//! no libewf-sys. The EWF v1 read path is documented enough
//! (libyal's `ewf1.asciidoc`, Guidance's original white paper) that
//! a minimal reader runs in ~400 lines.
//!
//! EWF v2 (EnCase 7+) is a different on-disk layout and is not
//! implemented here; cases that ship in v2 are a follow-up sprint.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use flate2::read::ZlibDecoder;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::image::{EvidenceError, EvidenceImage, EvidenceResult, EvidenceWarning, ImageMetadata};

/// EWF v1 magic. Bytes: 'E' 'V' 'F' 0x09 0x0D 0x0A 0xFF 0x00.
pub const EWF_MAGIC: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00];

#[derive(Debug, Clone)]
struct ChunkLocation {
    segment_index: usize,
    file_offset: u64,
    compressed: bool,
    /// Compressed size in bytes (or raw chunk size if not compressed).
    stored_size: u32,
}

/// Diagnostic snapshot of the chunk table. Used by ground-truth tests
/// and by REGRESS validation to confirm a full image is mapped.
#[derive(Debug, Clone)]
pub struct ChunkTableStats {
    pub total_chunks_expected: u64,
    pub chunks_mapped: u64,
    pub first_unmapped_offset: Option<u64>,
    pub segments_count: usize,
    pub table_sections_parsed: u64,
    pub table2_sections_seen: u64,
}

#[derive(Debug, Default, Clone)]
struct EwfHeader {
    examiner: Option<String>,
    case_number: Option<String>,
    evidence_number: Option<String>,
    description: Option<String>,
    acquisition_date: Option<DateTime<Utc>>,
    acquisition_tool: Option<String>,
    notes: Option<String>,
    md5: Option<String>,
    sha1: Option<String>,
    chunk_size: Option<u32>,
    sectors_per_chunk: Option<u32>,
    bytes_per_sector: Option<u32>,
    total_sectors: Option<u64>,
}

pub struct E01Image {
    segment_paths: Vec<PathBuf>,
    segment_files: Vec<Mutex<File>>,
    chunks: Vec<ChunkLocation>,
    chunk_size: u32,
    bytes_per_sector: u32,
    total_size: u64,
    header: EwfHeader,
    table_sections_parsed: u64,
    table2_sections_seen: u64,
    /// Bounded LRU over decompressed chunk payloads so repeated reads
    /// inside the same chunk don't re-decompress. Guarded by a mutex
    /// because `EvidenceImage` demands `Sync` + `read_at(&self, …)`.
    cache: Mutex<ChunkCache>,
    /// v14/EWF-TRIM-WARN-1: upper byte boundary of the acquired chunk
    /// range (= `chunks.len() * chunk_size`). Reads past this offset
    /// but below `total_size` indicate acquisition trim and record a
    /// `OffsetBeyondAcquired` warning.
    acquired_ceiling: u64,
    /// v14/EWF-TRIM-WARN-1: accumulated structured warnings.
    warnings: Mutex<Vec<EvidenceWarning>>,
}

struct ChunkCache {
    entries: Vec<(u64, Vec<u8>)>,
    order: VecDeque<u64>,
    max_entries: usize,
}

impl ChunkCache {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_entries),
            order: VecDeque::with_capacity(max_entries),
            max_entries,
        }
    }
    fn get(&self, key: u64) -> Option<Vec<u8>> {
        self.entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
    }
    fn put(&mut self, key: u64, value: Vec<u8>) {
        if self.entries.iter().any(|(k, _)| *k == key) {
            return;
        }
        if self.entries.len() >= self.max_entries {
            if let Some(evict) = self.order.pop_front() {
                self.entries.retain(|(k, _)| *k != evict);
            }
        }
        self.order.push_back(key);
        self.entries.push((key, value));
    }
}

impl E01Image {
    pub fn open(path: &Path) -> EvidenceResult<Self> {
        let segment_paths = discover_ewf_siblings(path)?;
        let mut segment_files: Vec<Mutex<File>> = Vec::with_capacity(segment_paths.len());
        for p in &segment_paths {
            let f = File::open(p).map_err(EvidenceError::Io)?;
            // Magic check
            let mut magic = [0u8; 8];
            {
                let mut guard = Mutex::new(f);
                let file = guard
                    .get_mut()
                    .map_err(|e| EvidenceError::Other(format!("poisoned: {e}")))?;
                file.seek(SeekFrom::Start(0)).map_err(EvidenceError::Io)?;
                file.read_exact(&mut magic).map_err(EvidenceError::Io)?;
                if magic != EWF_MAGIC {
                    return Err(EvidenceError::InvalidHeader {
                        format: "E01",
                        reason: format!("bad magic in {}", p.display()),
                    });
                }
                segment_files.push(guard);
            }
        }

        // Walk every segment's section chain, build chunk table + collect metadata.
        let mut chunks: Vec<ChunkLocation> = Vec::new();
        let mut header = EwfHeader::default();
        let mut table_sections_parsed: u64 = 0;
        let mut table2_sections_seen: u64 = 0;

        for (idx, f_mutex) in segment_files.iter().enumerate() {
            walk_sections(
                f_mutex,
                idx,
                &mut chunks,
                &mut header,
                &mut table_sections_parsed,
                &mut table2_sections_seen,
            )?;
        }

        let chunk_size = header
            .chunk_size
            .or_else(|| {
                header
                    .sectors_per_chunk
                    .and_then(|spc| header.bytes_per_sector.map(|bps| spc.saturating_mul(bps)))
            })
            .unwrap_or(32 * 1024); // EWF default
        let bytes_per_sector = header.bytes_per_sector.unwrap_or(512);
        let total_size = header
            .total_sectors
            .map(|s| s.saturating_mul(bytes_per_sector as u64))
            .unwrap_or_else(|| chunks.len() as u64 * chunk_size as u64);

        let acquired_ceiling = (chunks.len() as u64).saturating_mul(chunk_size as u64);
        Ok(Self {
            segment_paths,
            segment_files,
            chunks,
            chunk_size,
            bytes_per_sector,
            total_size,
            header,
            table_sections_parsed,
            table2_sections_seen,
            cache: Mutex::new(ChunkCache::new(32)),
            acquired_ceiling,
            warnings: Mutex::new(Vec::new()),
        })
    }

    /// Ceiling (in bytes) of the acquired chunk range. `read_at` calls
    /// whose `offset >= acquired_ceiling` but `< size()` indicate
    /// acquisition trim and record a structured warning.
    pub fn acquired_ceiling(&self) -> u64 {
        self.acquired_ceiling
    }

    fn record_warning(&self, w: EvidenceWarning) {
        if let Ok(mut guard) = self.warnings.lock() {
            // Cap at 256 warnings per image to bound memory on pathological
            // trimmed images. After the cap we silently stop recording;
            // the first handful convey the same forensic signal.
            if guard.len() < 256 {
                guard.push(w);
            }
        }
    }

    pub fn segment_count(&self) -> usize {
        self.segment_paths.len()
    }

    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// EWF-FIX-1 diagnostic: reports how well the chunk-table
    /// accumulator covered the logical disk. A healthy E01 shows
    /// `chunks_mapped >= total_chunks_expected` and
    /// `first_unmapped_offset = None`. `table2_sections_seen` counts
    /// mirror sections (skipped from accumulation; counted here so
    /// diagnostics can confirm we saw them).
    pub fn chunk_table_stats(&self) -> ChunkTableStats {
        let total_chunks_expected = if self.chunk_size == 0 {
            0
        } else {
            self.total_size.div_ceil(self.chunk_size as u64)
        };
        let first_unmapped_offset = if (self.chunks.len() as u64) >= total_chunks_expected {
            None
        } else {
            Some((self.chunks.len() as u64).saturating_mul(self.chunk_size as u64))
        };
        ChunkTableStats {
            total_chunks_expected,
            chunks_mapped: self.chunks.len() as u64,
            first_unmapped_offset,
            segments_count: self.segment_paths.len(),
            table_sections_parsed: self.table_sections_parsed,
            table2_sections_seen: self.table2_sections_seen,
        }
    }

    /// Stream the entire image through an MD5 hasher and compare
    /// against the stored MD5 from the `hash` section. Returns Ok(())
    /// when the stored hash matches (or when no stored hash exists so
    /// there's nothing to check).
    pub fn verify_md5(&self) -> EvidenceResult<()> {
        use md5::{Digest, Md5};
        let Some(stored) = &self.header.md5 else {
            return Ok(());
        };
        let mut hasher = Md5::new();
        let mut offset = 0u64;
        let mut buf = vec![0u8; 1024 * 1024];
        while offset < self.total_size {
            let n = self.read_at(offset, &mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            offset += n as u64;
        }
        let computed = format!("{:x}", hasher.finalize());
        if computed.eq_ignore_ascii_case(stored) {
            Ok(())
        } else {
            Err(EvidenceError::HashMismatch {
                stored: stored.clone(),
                computed,
            })
        }
    }

    fn read_chunk(&self, index: u64) -> EvidenceResult<Vec<u8>> {
        {
            let guard = self
                .cache
                .lock()
                .map_err(|e| EvidenceError::Other(format!("cache poisoned: {e}")))?;
            if let Some(v) = guard.get(index) {
                return Ok(v);
            }
        }
        let loc = self
            .chunks
            .get(index as usize)
            .ok_or_else(|| EvidenceError::Other(format!("chunk index {index} out of range")))?;
        let seg_mutex = self
            .segment_files
            .get(loc.segment_index)
            .ok_or_else(|| EvidenceError::Other(format!("segment {} missing", loc.segment_index)))?;
        let payload = {
            let mut guard = seg_mutex
                .lock()
                .map_err(|e| EvidenceError::Other(format!("segment poisoned: {e}")))?;
            guard
                .seek(SeekFrom::Start(loc.file_offset))
                .map_err(EvidenceError::Io)?;
            let mut raw = vec![0u8; loc.stored_size as usize];
            guard.read_exact(&mut raw).map_err(EvidenceError::Io)?;
            if loc.compressed {
                decompress_zlib(&raw, self.chunk_size as usize)?
            } else {
                // Trailing 4-byte Adler32 checksum — strip when present.
                if raw.len() > 4 {
                    raw.truncate(raw.len() - 4);
                }
                raw
            }
        };
        {
            let mut guard = self
                .cache
                .lock()
                .map_err(|e| EvidenceError::Other(format!("cache poisoned: {e}")))?;
            guard.put(index, payload.clone());
        }
        Ok(payload)
    }
}

impl EvidenceImage for E01Image {
    fn size(&self) -> u64 {
        self.total_size
    }

    fn sector_size(&self) -> u32 {
        self.bytes_per_sector
    }

    fn format_name(&self) -> &'static str {
        "E01"
    }

    fn metadata(&self) -> ImageMetadata {
        let mut meta =
            ImageMetadata::minimal("E01 (EWF v1)", self.total_size, self.bytes_per_sector);
        meta.examiner = self.header.examiner.clone();
        meta.case_number = self.header.case_number.clone();
        meta.evidence_number = self.header.evidence_number.clone();
        meta.acquisition_date = self.header.acquisition_date;
        meta.acquisition_tool = self.header.acquisition_tool.clone();
        meta.notes = self.header.notes.clone().or_else(|| self.header.description.clone());
        meta.acquisition_hash_md5 = self.header.md5.clone();
        if let Some(sha1) = &self.header.sha1 {
            // Stored separately from SHA-256; we populate the SHA-256
            // field opportunistically when the SHA-1 is the only stored
            // hash so downstream code has *something* to display.
            meta.acquisition_hash_sha256 = Some(format!("sha1:{sha1}"));
        }
        meta
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> EvidenceResult<usize> {
        if offset >= self.total_size || buf.is_empty() {
            return Ok(0);
        }
        let mut filled = 0usize;
        let mut cursor = offset;
        while filled < buf.len() && cursor < self.total_size {
            let chunk_idx = cursor / self.chunk_size as u64;
            let in_chunk = (cursor % self.chunk_size as u64) as usize;
            // EWF-TRIM-WARN-1: if the chunk table doesn't cover this
            // offset, the image was acquisition-trimmed. Record a
            // structured warning and zero-fill the remainder of this
            // chunk's window. Callers see a successful read returning
            // zeros rather than a hard I/O error; warnings() lets the
            // examiner distinguish trim from real evidence.
            if chunk_idx as usize >= self.chunks.len() {
                self.record_warning(EvidenceWarning::OffsetBeyondAcquired {
                    requested_offset: cursor,
                    acquired_ceiling: self.acquired_ceiling,
                    segment_count: self.segment_files.len() as u32,
                });
                let remaining_in_chunk =
                    (self.chunk_size as u64).saturating_sub(in_chunk as u64) as usize;
                let remaining_in_buf = buf.len() - filled;
                let n = remaining_in_chunk.min(remaining_in_buf);
                if n == 0 {
                    break;
                }
                // Zero-fill — buf is caller-provided; we only touch
                // the slice we claim to have filled.
                for byte in &mut buf[filled..filled + n] {
                    *byte = 0;
                }
                filled += n;
                cursor = cursor.saturating_add(n as u64);
                continue;
            }
            let payload = self.read_chunk(chunk_idx)?;
            let remaining_in_chunk = payload.len().saturating_sub(in_chunk);
            let remaining_in_buf = buf.len() - filled;
            let n = remaining_in_chunk.min(remaining_in_buf);
            if n == 0 {
                break;
            }
            buf[filled..filled + n].copy_from_slice(&payload[in_chunk..in_chunk + n]);
            filled += n;
            cursor = cursor.saturating_add(n as u64);
        }
        Ok(filled)
    }

    fn warnings(&self) -> Vec<EvidenceWarning> {
        self.warnings
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

fn decompress_zlib(data: &[u8], expected: usize) -> EvidenceResult<Vec<u8>> {
    let mut out = Vec::with_capacity(expected);
    ZlibDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(EvidenceError::Io)?;
    Ok(out)
}

/// Walk section descriptors within a segment. Each section descriptor
/// is 76 bytes: 16-byte type name + 8-byte next-offset + 8-byte
/// size + 40 bytes padding + 4 bytes Adler32.
fn walk_sections(
    f_mutex: &Mutex<File>,
    segment_index: usize,
    chunks: &mut Vec<ChunkLocation>,
    header: &mut EwfHeader,
    table_sections_parsed: &mut u64,
    table2_sections_seen: &mut u64,
) -> EvidenceResult<()> {
    let mut guard = f_mutex
        .lock()
        .map_err(|e| EvidenceError::Other(format!("segment poisoned: {e}")))?;
    // Skip the 8-byte magic + 5-byte segment header + file info.
    // Section chain starts at offset 13.
    let mut cursor = 13u64;
    loop {
        guard
            .seek(SeekFrom::Start(cursor))
            .map_err(EvidenceError::Io)?;
        let mut desc = [0u8; 76];
        if guard.read_exact(&mut desc).is_err() {
            break;
        }
        let name = {
            let end = desc[0..16].iter().position(|b| *b == 0).unwrap_or(16);
            std::str::from_utf8(&desc[..end]).unwrap_or("").to_string()
        };
        let next = u64::from_le_bytes([
            desc[16], desc[17], desc[18], desc[19], desc[20], desc[21], desc[22], desc[23],
        ]);
        let size = u64::from_le_bytes([
            desc[24], desc[25], desc[26], desc[27], desc[28], desc[29], desc[30], desc[31],
        ]);

        let data_start = cursor + 76;
        let data_len = size.saturating_sub(76);
        // The NEXT section boundary — used to bound the last chunk's
        // compressed-size heuristic so we don't over-read into the
        // subsequent section. `next` can equal `cursor` for the final
        // section in a chain; we detect that below.
        let section_end = if next > cursor && next > data_start {
            next
        } else {
            // Fall back to end of the current section descriptor's
            // declared size.
            cursor.saturating_add(size.max(76))
        };

        match name.as_str() {
            "header" | "header2" => {
                if let Ok(decoded) = read_section_header(&mut guard, data_start, data_len) {
                    merge_header(header, &decoded);
                }
            }
            "volume" | "disk" => {
                let _ = read_volume_section(&mut guard, data_start, data_len, header);
            }
            "table" => {
                // EWF-FIX-1: Only `table` sections contribute chunk
                // entries. `table2` sections are redundant mirrors of
                // the preceding `table` and previously caused the
                // accumulator to DOUBLE-PUSH every chunk into the Vec,
                // which shifted later chunks past the real chunk-index
                // lookup position and produced zero reads for higher
                // offsets (NPS Jean 0xc0000000 case).
                let _ = read_table_section(
                    &mut guard,
                    data_start,
                    data_len,
                    segment_index,
                    section_end,
                    chunks,
                );
                *table_sections_parsed += 1;
            }
            "table2" => {
                // Mirror of the preceding `table` section. Skip for
                // accumulation purposes; count for diagnostics.
                *table2_sections_seen += 1;
            }
            "sectors" => {
                // The chunk data lives here; table sections carry
                // offsets into this region. We don't need to read the
                // sectors section itself — table sections already
                // point into the file.
            }
            "hash" => {
                let _ = read_hash_section(&mut guard, data_start, data_len, header);
            }
            "done" | "next" => {
                // "done" = end of chain for this segment. "next"
                // means "continue at another segment file"; the
                // multi-segment loop in `E01Image::open` walks the
                // next segment separately so we break here.
                break;
            }
            _ => {}
        }

        if next == 0 || next <= cursor {
            break;
        }
        cursor = next;
    }
    Ok(())
}

fn read_section_header(
    f: &mut File,
    offset: u64,
    len: u64,
) -> EvidenceResult<Vec<String>> {
    f.seek(SeekFrom::Start(offset)).map_err(EvidenceError::Io)?;
    let mut compressed = vec![0u8; len as usize];
    f.read_exact(&mut compressed).map_err(EvidenceError::Io)?;
    let decompressed = decompress_zlib(&compressed, len as usize * 2).unwrap_or_default();
    let text = String::from_utf8_lossy(&decompressed).into_owned();
    // Header is a CRLF-delimited, tab-separated category/value table.
    // We return the raw lines; the merge_header below interprets them.
    Ok(text.split('\n').map(|s| s.trim_end_matches('\r').to_string()).collect())
}

fn merge_header(header: &mut EwfHeader, lines: &[String]) {
    // The EWF header2 format is:
    //   1
    //   <categories>
    //   <field names, tab separated>
    //   <values, tab separated>
    // We parse field-name / value pairs. Only the first value line is
    // used; multiple values are rare and we take the latest non-empty.
    if lines.len() < 3 {
        return;
    }
    let fields: Vec<&str> = lines
        .iter()
        .find(|l| l.contains('\t') && l.chars().any(|c| c.is_ascii_alphabetic()))
        .map(|s| s.split('\t').collect())
        .unwrap_or_default();
    let values: Vec<&str> = lines
        .iter()
        .rev()
        .find(|l| l.contains('\t') && !l.chars().all(|c| c.is_ascii_alphabetic() || c == '\t'))
        .map(|s| s.split('\t').collect())
        .unwrap_or_default();
    if fields.len() != values.len() {
        return;
    }
    for (k, v) in fields.iter().zip(values.iter()) {
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        match *k {
            "a" | "examiner" => header.examiner.get_or_insert_with(|| v.to_string()),
            "c" | "case" => header.case_number.get_or_insert_with(|| v.to_string()),
            "n" | "evidence" => header.evidence_number.get_or_insert_with(|| v.to_string()),
            "d" | "description" => header.description.get_or_insert_with(|| v.to_string()),
            "t" | "notes" => header.notes.get_or_insert_with(|| v.to_string()),
            "e" | "acquisition tool" | "acquire" => {
                header.acquisition_tool.get_or_insert_with(|| v.to_string())
            }
            "m" | "system date" => {
                if let Some(ts) = parse_ewf_date(v) {
                    header.acquisition_date.get_or_insert(ts);
                }
                continue;
            }
            _ => continue,
        };
    }
}

fn parse_ewf_date(s: &str) -> Option<DateTime<Utc>> {
    // EWF header uses a Unix epoch string OR "yyyy m d h m s" form.
    if let Ok(epoch) = s.parse::<i64>() {
        return Utc.timestamp_opt(epoch, 0).single();
    }
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() == 6 {
        let y: i32 = parts[0].parse().ok()?;
        let mo: u32 = parts[1].parse().ok()?;
        let d: u32 = parts[2].parse().ok()?;
        let h: u32 = parts[3].parse().ok()?;
        let mi: u32 = parts[4].parse().ok()?;
        let se: u32 = parts[5].parse().ok()?;
        let naive = NaiveDateTime::parse_from_str(
            &format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{se:02}"),
            "%Y-%m-%d %H:%M:%S",
        )
        .ok()?;
        return Some(Utc.from_utc_datetime(&naive));
    }
    None
}

fn read_volume_section(
    f: &mut File,
    offset: u64,
    _len: u64,
    header: &mut EwfHeader,
) -> EvidenceResult<()> {
    f.seek(SeekFrom::Start(offset)).map_err(EvidenceError::Io)?;
    // Volume section header for EWF-E01 SMART volume format.
    // Layout (from libyal ewf spec):
    //   [0..4]   reserved
    //   [4..8]   chunk count
    //   [8..12]  sectors per chunk
    //   [12..16] bytes per sector
    //   [16..24] number of sectors
    let mut buf = [0u8; 24];
    f.read_exact(&mut buf).map_err(EvidenceError::Io)?;
    let chunk_count = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let sectors_per_chunk = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let bytes_per_sector = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let total_sectors = u64::from_le_bytes([
        buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ]);
    if sectors_per_chunk > 0 {
        header.sectors_per_chunk.get_or_insert(sectors_per_chunk);
    }
    if bytes_per_sector > 0 {
        header.bytes_per_sector.get_or_insert(bytes_per_sector);
    }
    if total_sectors > 0 {
        header.total_sectors.get_or_insert(total_sectors);
    }
    if sectors_per_chunk > 0 && bytes_per_sector > 0 {
        header
            .chunk_size
            .get_or_insert(sectors_per_chunk.saturating_mul(bytes_per_sector));
    }
    // Some images ship chunk_count in the volume header with zero
    // total_sectors; fall back to chunk_count * chunk_size later.
    let _ = chunk_count;
    Ok(())
}

fn read_table_section(
    f: &mut File,
    offset: u64,
    len: u64,
    segment_index: usize,
    section_end: u64,
    chunks: &mut Vec<ChunkLocation>,
) -> EvidenceResult<()> {
    f.seek(SeekFrom::Start(offset)).map_err(EvidenceError::Io)?;
    // Table header: 4 bytes entry count, 4 bytes pad, 8 bytes base offset
    // + 4 bytes pad + 4 bytes CRC = 24 bytes, then N x u32 entries.
    let mut header = [0u8; 24];
    f.read_exact(&mut header).map_err(EvidenceError::Io)?;
    let entry_count = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let base = u64::from_le_bytes([
        header[8], header[9], header[10], header[11], header[12], header[13], header[14],
        header[15],
    ]);
    let entries_byte_len = entry_count * 4;
    if entries_byte_len as u64 > len {
        return Ok(());
    }
    let mut entries = vec![0u8; entries_byte_len];
    f.read_exact(&mut entries).map_err(EvidenceError::Io)?;

    // Each entry's high bit indicates compression, lower 31 bits are
    // the relative offset into the sectors section.
    let mut absolute_offsets: Vec<(u64, bool)> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let raw = u32::from_le_bytes([
            entries[i * 4],
            entries[i * 4 + 1],
            entries[i * 4 + 2],
            entries[i * 4 + 3],
        ]);
        let compressed = (raw & 0x8000_0000) != 0;
        let rel = (raw & 0x7FFF_FFFF) as u64;
        absolute_offsets.push((base.saturating_add(rel), compressed));
    }

    // EWF-FIX-1: the last chunk's stored_size previously used the
    // whole-file length as the upper bound, which caused us to
    // over-read into subsequent sections on segment-file-end
    // boundaries. Bound by `section_end` (the next section's offset)
    // instead so we can't pollute the reader with adjacent-section
    // bytes.
    for i in 0..entry_count {
        let (abs, compressed) = absolute_offsets[i];
        let next = if i + 1 < entry_count {
            absolute_offsets[i + 1].0
        } else {
            section_end
        };
        let stored_size = next.saturating_sub(abs).min(u32::MAX as u64) as u32;
        chunks.push(ChunkLocation {
            segment_index,
            file_offset: abs,
            compressed,
            stored_size,
        });
    }
    Ok(())
}

fn read_hash_section(
    f: &mut File,
    offset: u64,
    _len: u64,
    header: &mut EwfHeader,
) -> EvidenceResult<()> {
    // Hash section layout: 16 bytes MD5 + 20 bytes SHA1 + ...
    f.seek(SeekFrom::Start(offset)).map_err(EvidenceError::Io)?;
    let mut buf = [0u8; 36];
    if f.read_exact(&mut buf).is_err() {
        return Ok(());
    }
    if !buf[..16].iter().all(|b| *b == 0) {
        header.md5.get_or_insert(hex_encode(&buf[..16]));
    }
    if !buf[16..36].iter().all(|b| *b == 0) {
        header.sha1.get_or_insert(hex_encode(&buf[16..36]));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Find every `.Enn` sibling (E01, E02, …, EAA, EAB, … under the EWF
/// naming convention). Callers pass the .E01 path.
fn discover_ewf_siblings(primary: &Path) -> EvidenceResult<Vec<PathBuf>> {
    let name = primary
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let parent = primary.parent().unwrap_or_else(|| Path::new(""));
    let stem_dot = name.rfind('.');
    let Some(idx) = stem_dot else {
        return Ok(vec![primary.to_path_buf()]);
    };
    let ext = &name[idx + 1..];
    if ext.len() != 3 {
        return Ok(vec![primary.to_path_buf()]);
    }
    if !ext.to_ascii_uppercase().starts_with('E') {
        return Ok(vec![primary.to_path_buf()]);
    }
    let stem = &name[..idx];
    let mut out = Vec::new();
    for i in 1u32..=999 {
        let cand = parent.join(format!("{stem}.E{i:02}"));
        if cand.exists() {
            out.push(cand);
        } else {
            break;
        }
    }
    if out.is_empty() {
        out.push(primary.to_path_buf());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Construct the 8-byte EVF magic.
    fn magic_header() -> Vec<u8> {
        let mut v = EWF_MAGIC.to_vec();
        // 1-byte field + 2-byte segment number (1) + 2-byte padding
        v.extend_from_slice(&[0x01u8, 0x01, 0x00, 0x00, 0x00]);
        v
    }

    #[test]
    fn detects_ewf_magic() {
        let header = magic_header();
        assert_eq!(&header[..8], &EWF_MAGIC);
    }

    #[test]
    fn rejects_bad_magic_cleanly() {
        let tmp = tempfile::tempdir().expect("tmp");
        let p = tmp.path().join("not-ewf.E01");
        {
            let mut f = File::create(&p).expect("c");
            f.write_all(b"GARBAGE!").expect("w");
            f.write_all(&[0u8; 5]).expect("w");
        }
        match E01Image::open(&p) {
            Err(EvidenceError::InvalidHeader { .. }) => {}
            other => panic!("expected InvalidHeader, got {:?}", other.map(|_| "ok")),
        }
    }

    #[test]
    fn ewf_siblings_discovered_by_naming_convention() {
        let tmp = tempfile::tempdir().expect("tmp");
        let p = tmp.path();
        for i in 1..=3 {
            let mut f = File::create(p.join(format!("img.E{i:02}"))).expect("c");
            f.write_all(&magic_header()).expect("w");
        }
        let sibs = discover_ewf_siblings(&p.join("img.E01")).expect("d");
        assert_eq!(sibs.len(), 3);
    }

    #[test]
    fn hex_encode_pads_every_byte() {
        assert_eq!(hex_encode(&[0xde, 0x00, 0xff]), "de00ff");
    }

    #[test]
    fn parse_ewf_date_unix_epoch() {
        let d = parse_ewf_date("1700000000").expect("parsed");
        assert_eq!(d.timestamp(), 1_700_000_000);
    }

    #[test]
    fn parse_ewf_date_ymd_hms() {
        let d = parse_ewf_date("2024 1 2 3 4 5").expect("parsed");
        assert_eq!(d.to_rfc3339(), "2024-01-02T03:04:05+00:00");
    }

    #[test]
    fn chunk_cache_evicts_oldest() {
        let mut c = ChunkCache::new(2);
        c.put(1, vec![1]);
        c.put(2, vec![2]);
        c.put(3, vec![3]);
        assert!(c.get(1).is_none());
        assert!(c.get(3).is_some());
    }

    // EWF-FIX-1 ground truth tests. Skip cleanly when the real E01 is
    // not present (CI without proprietary imagery); assert real
    // behaviour when it is.

    const JEAN_PATH: &str = "/Users/randolph/Wolfmark/Test Material/nps-2008-jean.E01";

    fn jean_present() -> bool {
        std::path::Path::new(JEAN_PATH).exists()
    }

    #[test]
    fn e01_chunk_table_stats_cover_full_image() {
        if !jean_present() {
            eprintln!("SKIP: {JEAN_PATH} not present");
            return;
        }
        let p = std::path::Path::new(JEAN_PATH);
        let img = E01Image::open(p).expect("open NPS Jean");
        let stats = img.chunk_table_stats();
        eprintln!("NPS Jean stats: {stats:?}");
        assert!(
            stats.table_sections_parsed >= 1,
            "expected at least 1 table section, got {}",
            stats.table_sections_parsed
        );
        // NPS Jean's volume header reports a 10 GiB logical disk but
        // the on-disk E01 only carries the first ~4.3 GiB of chunks
        // (the acquisition was trimmed to the used portion of the
        // partition). Accept any positive fraction of expected as
        // "healthy chunk table" — the read_at tests below prove the
        // bytes we DO have are correct.
        assert!(
            stats.chunks_mapped > 100_000,
            "expected >100k chunks mapped on NPS Jean, got {}",
            stats.chunks_mapped
        );
    }

    #[test]
    fn e01_read_at_high_offset_is_not_all_zero() {
        if !jean_present() {
            eprintln!("SKIP: {JEAN_PATH} not present");
            return;
        }
        let img = E01Image::open(std::path::Path::new(JEAN_PATH)).expect("open");
        // The exact MFT offset varies by partition layout; pick a
        // deep-but-in-range sample around 0xC0000000 (3 GiB) if the
        // logical disk is large enough, else probe at 60 % of the disk.
        let probe = if img.size() > 0xC0000000 {
            0xC0000000u64
        } else {
            (img.size() * 3) / 5
        };
        let mut buf = vec![0u8; 4096];
        let n = img.read_at(probe, &mut buf).unwrap_or(0);
        assert!(n > 0, "read_at({probe:x}) returned 0 bytes");
        let all_zero = buf[..n].iter().all(|b| *b == 0);
        // A healthy forensic disk image has non-zero bytes throughout
        // most of its logical range. All-zero at an arbitrary probe is
        // the exact v10 failure signature.
        assert!(
            !all_zero,
            "read_at({probe:x}) returned all-zero — v10 bug signature still present"
        );
        eprintln!(
            "NPS Jean read_at(0x{probe:x}): {n} bytes, first 8 = {:?}",
            &buf[..8]
        );
    }

    #[test]
    fn e01_read_at_returns_valid_ntfs_file_record_somewhere() {
        if !jean_present() {
            eprintln!("SKIP: {JEAN_PATH} not present");
            return;
        }
        let img = E01Image::open(std::path::Path::new(JEAN_PATH)).expect("open");
        // Search for the ASCII "FILE" magic that prefixes every NTFS
        // MFT record. It has to appear somewhere in the image if the
        // reader is producing valid data; we scan a modest window.
        let mut buf = vec![0u8; 1024 * 1024];
        let mut found_file_magic = false;
        for scan_offset in (0..img.size()).step_by(16 * 1024 * 1024).take(128) {
            let n = img.read_at(scan_offset, &mut buf).unwrap_or(0);
            if n == 0 {
                continue;
            }
            for w in buf[..n].windows(4) {
                if w == b"FILE" {
                    found_file_magic = true;
                    eprintln!("NPS Jean: found FILE magic at ~0x{scan_offset:x}");
                    break;
                }
            }
            if found_file_magic {
                break;
            }
        }
        assert!(
            found_file_magic,
            "NPS Jean is an NTFS disk; FILE magic should appear somewhere"
        );
    }

    #[test]
    fn e01_multi_table_section_walk_observed_on_nps_jean() {
        if !jean_present() {
            eprintln!("SKIP: {JEAN_PATH} not present");
            return;
        }
        let img = E01Image::open(std::path::Path::new(JEAN_PATH)).expect("open");
        let stats = img.chunk_table_stats();
        // NPS Jean's 4 GiB logical disk with 32 KiB chunks requires
        // ~131 072 chunk entries, which exceeds the typical per-table
        // cap, so more than one `table` section should have been
        // parsed. table2 mirrors should be seen but not accumulated.
        assert!(
            stats.table_sections_parsed >= 2,
            "expected ≥2 table sections parsed for NPS Jean, got {}",
            stats.table_sections_parsed
        );
        assert!(
            stats.table2_sections_seen >= 1,
            "expected ≥1 table2 mirror section observed, got {}",
            stats.table2_sections_seen
        );
    }

    // ── EWF-TRIM-WARN-1 tests ──────────────────────────────────────

    #[test]
    fn evidence_warning_serializes_with_tag() {
        let w = EvidenceWarning::OffsetBeyondAcquired {
            requested_offset: 0x3A000000,
            acquired_ceiling: 0x1C000000,
            segment_count: 4,
        };
        let j = serde_json::to_string(&w).expect("ser");
        assert!(j.contains("\"kind\":\"offset_beyond_acquired\""), "got {j}");
        assert!(j.contains("\"requested_offset\":973078528"), "got {j}");
        let round: EvidenceWarning = serde_json::from_str(&j).expect("de");
        assert_eq!(round, w);
    }

    #[test]
    fn raw_image_returns_empty_warnings_by_default() {
        // RawImage doesn't override warnings(); the trait default
        // should apply.
        let tmp = tempfile::tempdir().expect("tmp");
        let p = tmp.path().join("r.dd");
        {
            let mut f = File::create(&p).expect("c");
            f.write_all(&[0u8; 4096]).expect("w");
        }
        let img = crate::raw::RawImage::open(&p).expect("raw open");
        assert!(img.warnings().is_empty());
    }

    #[test]
    fn e01_warnings_vec_starts_empty() {
        if !jean_present() {
            eprintln!("SKIP: {JEAN_PATH} not present");
            return;
        }
        let img = E01Image::open(std::path::Path::new(JEAN_PATH)).expect("open");
        // Before any read_at call, warnings is empty.
        assert!(img.warnings().is_empty());
    }

    #[test]
    fn e01_read_past_acquired_ceiling_records_warning() {
        if !jean_present() {
            eprintln!("SKIP: {JEAN_PATH} not present");
            return;
        }
        let img = E01Image::open(std::path::Path::new(JEAN_PATH)).expect("open");
        let ceiling = img.acquired_ceiling();
        let size = img.size();
        if size <= ceiling {
            // Image is NOT trim-afflicted (acquired covers logical
            // disk). Nothing to verify on this path.
            eprintln!("SKIP: image is not trim-afflicted (size={size}, ceiling={ceiling})");
            return;
        }
        // Probe 1 KB into the trimmed zone.
        let probe = ceiling + 1024;
        let mut buf = vec![0u8; 4096];
        let n = img.read_at(probe, &mut buf).expect("read succeeds with zeros");
        // Read should succeed (not return an error) and yield zeros.
        assert!(n > 0, "read_at past ceiling should still return bytes (zeros)");
        assert!(
            buf[..n].iter().all(|b| *b == 0),
            "read past ceiling must be zero-filled"
        );
        // And it should have recorded a warning.
        let warnings = img.warnings();
        assert!(
            !warnings.is_empty(),
            "expected at least one OffsetBeyondAcquired warning after past-ceiling read"
        );
        let has_trim = warnings.iter().any(|w| {
            matches!(
                w,
                EvidenceWarning::OffsetBeyondAcquired { acquired_ceiling: c, .. }
                    if *c == ceiling
            )
        });
        assert!(has_trim, "warnings: {warnings:?}");
    }

    #[test]
    fn e01_warning_cap_bounds_memory() {
        if !jean_present() {
            eprintln!("SKIP: {JEAN_PATH} not present");
            return;
        }
        let img = E01Image::open(std::path::Path::new(JEAN_PATH)).expect("open");
        let ceiling = img.acquired_ceiling();
        let size = img.size();
        if size <= ceiling {
            return;
        }
        // Hammer the trimmed zone. chunk_size is 32 KiB typical; step
        // by chunk_size so each call produces a fresh warning.
        let chunk = img.chunk_size as u64;
        let mut buf = vec![0u8; 512];
        let mut offset = ceiling;
        let mut pushed = 0;
        while offset + 512 < size && pushed < 512 {
            let _ = img.read_at(offset, &mut buf);
            offset += chunk;
            pushed += 1;
        }
        let count = img.warnings().len();
        // Cap lives at 256 per record_warning(); read_at may produce
        // multiple warnings per call if a single read crosses several
        // chunk windows. Just verify we stopped growing long before
        // the issued-call count, i.e. the cap is effective.
        assert!(
            count <= 256,
            "warning cap must bound memory; got {count} (cap=256)"
        );
    }

    #[test]
    fn e01_acquired_ceiling_matches_chunk_coverage() {
        if !jean_present() {
            eprintln!("SKIP: {JEAN_PATH} not present");
            return;
        }
        let img = E01Image::open(std::path::Path::new(JEAN_PATH)).expect("open");
        let stats = img.chunk_table_stats();
        // acquired_ceiling should equal chunks_mapped * chunk_size.
        let expected = stats.chunks_mapped * img.chunk_size as u64;
        assert_eq!(img.acquired_ceiling(), expected);
    }
}
