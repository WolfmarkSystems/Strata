//! Windows Thumbnail Cache (`thumbcache_*.db`) typed parser.
//!
//! Located at `%LocalAppData%\Microsoft\Windows\Explorer\` plus
//! `%LocalAppData%\Microsoft\Windows\Caches\` on newer builds, the
//! Thumbnail Cache stores a copy of every file thumbnail Explorer ever
//! generated for the user. Naming convention by size:
//!
//! | File | Pixel size |
//! |---|---|
//! | `thumbcache_32.db`   | 32×32     |
//! | `thumbcache_96.db`   | 96×96     |
//! | `thumbcache_256.db`  | 256×256   |
//! | `thumbcache_1024.db` | 1024×1024 |
//! | `thumbcache_idx.db`  | (index)   |
//!
//! ## Forensic significance
//!
//! **Thumbnails persist after the source file is deleted.** This makes
//! the Thumbnail Cache one of the highest-evidentiary-value Windows
//! artifacts in deletion / anti-forensic cases — even after the user
//! has emptied the Recycle Bin and the file is gone from `$MFT`, the
//! thumbnail can still be reconstructed and shown to the analyst.
//!
//! Combined with `$UsnJrnl` deletion records and the carved file's
//! 64-bit hash (which is derived from the source file's full path),
//! the cache provides "this user previewed this file before deleting
//! it" provenance.
//!
//! ## File format (Windows 7 / 8 / 10 / 11)
//!
//! ```text
//! Header (CMMM):
//!   offset 0x00  u32  magic = "CMMM"  (0x4D4D4D43 LE)
//!   offset 0x04  u32  format_version
//!   offset 0x08  u32  cache_type      (32, 96, 256, 1024, idx, sr, ...)
//!   offset 0x0C  u32  first_cache_entry_offset
//!   ...
//!
//! Per entry (also CMMM-magic):
//!   u32  entry_magic  = "CMMM"
//!   u32  entry_size
//!   u64  hash         (filename-derived, 64-bit)
//!   u8[8] extension   (UTF-16LE; only ~4 chars fit before NULs)
//!   u32  identifier_size
//!   u32  padding_size
//!   u32  data_size
//!   u32  unknown
//!   u64  data_checksum
//!   u64  header_checksum
//!   <identifier bytes, identifier_size bytes>
//!   <thumbnail data, data_size bytes>
//! ```
//!
//! Real-world format variants exist between Windows versions; this
//! parser walks entries by following `entry_size` and gracefully stops
//! when an entry doesn't begin with the `CMMM` magic.
//!
//! ## MITRE ATT&CK
//! * **T1074.001** (Local Data Staging) — every preview is evidence
//!   the user opened a file's parent folder; in deletion / staging
//!   scenarios this answers "did the user actually see the file".
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.

/// Windows Thumbnail Cache file magic, little-endian (`"CMMM"`).
const CMMM_MAGIC_LE: u32 = 0x4D4D_4D43;
/// Hard cap on entries returned per file. Real `thumbcache_256.db`
/// peaks around 50k entries on long-lived hosts; 200k is a safety
/// bound against malformed `entry_size` walks.
const MAX_ENTRIES: usize = 200_000;
/// Hard cap on per-entry thumbnail payload we'll surface (5 MB) to
/// keep one rogue entry from blowing up the artifact stream.
const MAX_THUMB_BYTES: u32 = 5 * 1024 * 1024;
/// Minimum plausible entry header size: 56 bytes. The Win10 layout
/// is magic(4), entry_size(4), hash(8), extension(8), identifier_size(4),
/// padding_size(4), data_size(4), unknown(4), data_checksum(8),
/// header_checksum(8). The variable identifier and thumbnail payload
/// follow.
const MIN_ENTRY_HEADER: usize = 56;

/// One typed `thumbcache_*.db` entry.
///
/// Fields are forensic-meaning-first; downstream consumers (Phantom,
/// Sigma rules, the timeline view) read these without having to know
/// the on-disk byte layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThumbcacheEntry {
    /// Pixel-size bucket the entry came from, e.g. `"256"` or
    /// `"1024"`. Same value as the parent file's `cache_type`.
    /// Repeated on every entry so post-merge consumers don't lose the
    /// provenance.
    pub cache_type: String,

    /// 64-bit hash Windows derives from the source file's full path.
    /// Stable per-path and per-OS — pair with a `$MFT` walk to map
    /// thumbnails back to deleted source filenames. Stored as `u64`,
    /// rendered as 16-hex-digit uppercase in artifact fields.
    pub hash: u64,

    /// File extension of the source file as recorded in the entry
    /// (UTF-16LE, max 4 chars due to the 8-byte slot Windows reserved).
    /// Empty when the entry has no extension or the field decodes to
    /// nothing printable.
    pub extension: String,

    /// Length of the thumbnail blob in bytes (`0` for index/marker
    /// entries that carry no payload). Capped at [`MAX_THUMB_BYTES`]
    /// for the surfaced data — entries beyond the cap still report
    /// the original size here but skip the data.
    pub data_size: u32,

    /// CRC-style checksum over the thumbnail blob. Useful for
    /// identifying duplicate thumbnails across cache files (a
    /// thumbnail that appears in `_256.db` and `_1024.db` for the
    /// same source file shares this checksum).
    pub data_checksum: u64,

    /// CRC-style checksum over the entry header. Pair with
    /// `data_checksum` to detect tampering — Windows recomputes both
    /// on every write.
    pub header_checksum: u64,

    /// Raw thumbnail bytes (typically PNG, JPEG, or BMP). Empty when
    /// `data_size == 0` or the entry's payload exceeded
    /// [`MAX_THUMB_BYTES`]. Consumers can image-render this directly
    /// to show the analyst the deleted-file preview.
    pub thumbnail_data: Vec<u8>,
}

/// Aggregate result of parsing one `thumbcache_*.db` file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThumbcacheFile {
    /// Pixel-size bucket — `"32"`, `"96"`, `"256"`, `"1024"`,
    /// `"idx"`, `"sr"`, or `"unknown"` when the cache_type byte
    /// doesn't match a known value.
    pub cache_type: String,
    pub entries: Vec<ThumbcacheEntry>,
}

/// Parse a `thumbcache_*.db` file from raw bytes. Returns an empty
/// [`ThumbcacheFile`] on unrecognized or corrupt input. Never panics.
pub fn parse(bytes: &[u8]) -> ThumbcacheFile {
    let mut out = ThumbcacheFile::default();
    let Some(magic) = read_u32_le(bytes, 0) else {
        return out;
    };
    if magic != CMMM_MAGIC_LE {
        return out;
    }
    let cache_type_raw = read_u32_le(bytes, 8).unwrap_or(0);
    out.cache_type = cache_type_label(cache_type_raw).to_string();
    let first_entry_off = read_u32_le(bytes, 12).unwrap_or(24) as usize;
    walk_entries(bytes, first_entry_off, &out.cache_type, &mut out.entries);
    out
}

fn walk_entries(bytes: &[u8], start_off: usize, cache_type: &str, out: &mut Vec<ThumbcacheEntry>) {
    let mut offset = start_off;
    while offset + MIN_ENTRY_HEADER <= bytes.len() && out.len() < MAX_ENTRIES {
        let magic = match read_u32_le(bytes, offset) {
            Some(m) => m,
            None => break,
        };
        if magic != CMMM_MAGIC_LE {
            break;
        }
        let entry_size = match read_u32_le(bytes, offset + 4) {
            Some(s) => s as usize,
            None => break,
        };
        // Reject obviously-corrupt sizes that would produce an
        // infinite loop.
        if entry_size < MIN_ENTRY_HEADER {
            break;
        }
        let entry_end = offset.saturating_add(entry_size).min(bytes.len());

        let hash = read_u64_le(bytes, offset + 8).unwrap_or(0);
        let extension = read_utf16le_fixed(bytes, offset + 16, 8);
        let identifier_size = read_u32_le(bytes, offset + 24).unwrap_or(0) as usize;
        let _padding_size = read_u32_le(bytes, offset + 28).unwrap_or(0);
        let data_size = read_u32_le(bytes, offset + 32).unwrap_or(0);
        let _unknown = read_u32_le(bytes, offset + 36).unwrap_or(0);
        let data_checksum = read_u64_le(bytes, offset + 40).unwrap_or(0);
        let header_checksum = read_u64_le(bytes, offset + 48).unwrap_or(0);

        let payload_start = offset
            .saturating_add(MIN_ENTRY_HEADER)
            .saturating_add(identifier_size);
        let payload_end = payload_start
            .saturating_add(data_size as usize)
            .min(entry_end);
        let thumbnail_data = if data_size == 0 || data_size > MAX_THUMB_BYTES {
            Vec::new()
        } else if payload_end > payload_start && payload_end <= bytes.len() {
            bytes[payload_start..payload_end].to_vec()
        } else {
            Vec::new()
        };

        out.push(ThumbcacheEntry {
            cache_type: cache_type.to_string(),
            hash,
            extension,
            data_size,
            data_checksum,
            header_checksum,
            thumbnail_data,
        });

        let next = offset.saturating_add(entry_size);
        if next <= offset {
            break;
        }
        offset = next;
    }
}

/// Map the raw `cache_type` u32 in the file header to its
/// human-readable bucket label. Falls through to `"unknown"` for
/// future Windows variants.
pub(crate) fn cache_type_label(raw: u32) -> &'static str {
    match raw {
        0 => "32",
        1 => "96",
        2 => "256",
        3 => "1024",
        4 => "idx",
        5 => "sr",
        6 => "wide",
        7 => "exif",
        _ => "unknown",
    }
}

// ── byte-reading helpers ─────────────────────────────────────────────────

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off.checked_add(4)?)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let slice = buf.get(off..off.checked_add(8)?)?;
    let arr: [u8; 8] = slice.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
}

/// Read `len` bytes starting at `off` and decode as UTF-16LE up to the
/// first null. `len` must be even; an odd `len` returns the empty
/// string.
fn read_utf16le_fixed(buf: &[u8], off: usize, len: usize) -> String {
    if !len.is_multiple_of(2) {
        return String::new();
    }
    let Some(end) = off.checked_add(len) else {
        return String::new();
    };
    let Some(slice) = buf.get(off..end) else {
        return String::new();
    };
    let u16s: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&ch| ch != 0)
        .collect();
    String::from_utf16_lossy(&u16s)
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le_padded(s: &str, target_bytes: usize) -> Vec<u8> {
        let mut out: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        out.resize(target_bytes, 0);
        out
    }

    /// Build a minimal CMMM file with one entry pointing at fixture
    /// thumbnail bytes.
    fn build_thumbcache_blob(extension: &str, hash: u64, payload: &[u8]) -> Vec<u8> {
        let mut blob: Vec<u8> = Vec::new();
        // Header (24 bytes total).
        blob.extend_from_slice(&CMMM_MAGIC_LE.to_le_bytes()); // magic
        blob.extend_from_slice(&20u32.to_le_bytes()); // format_version
        blob.extend_from_slice(&2u32.to_le_bytes()); // cache_type = 2 ("256")
        blob.extend_from_slice(&24u32.to_le_bytes()); // first_cache_entry_offset
        blob.extend_from_slice(&0u32.to_le_bytes()); // padding to 24
        blob.extend_from_slice(&0u32.to_le_bytes()); // padding

        // Entry header (64 bytes) + identifier(0) + data
        let identifier_size: u32 = 0;
        let data_size = payload.len() as u32;
        let entry_size = (MIN_ENTRY_HEADER as u32)
            .saturating_add(identifier_size)
            .saturating_add(data_size);
        blob.extend_from_slice(&CMMM_MAGIC_LE.to_le_bytes()); // entry_magic
        blob.extend_from_slice(&entry_size.to_le_bytes()); // entry_size
        blob.extend_from_slice(&hash.to_le_bytes()); // hash
        blob.extend_from_slice(&utf16le_padded(extension, 8)); // extension
        blob.extend_from_slice(&identifier_size.to_le_bytes()); // identifier_size
        blob.extend_from_slice(&0u32.to_le_bytes()); // padding_size
        blob.extend_from_slice(&data_size.to_le_bytes()); // data_size
        blob.extend_from_slice(&0u32.to_le_bytes()); // unknown
        blob.extend_from_slice(&0xDEAD_BEEF_CAFE_BABE_u64.to_le_bytes()); // data_checksum
        blob.extend_from_slice(&0xFEED_FACE_BAAD_F00D_u64.to_le_bytes()); // header_checksum
                                                                          // Payload.
        blob.extend_from_slice(payload);
        blob
    }

    #[test]
    fn parse_returns_empty_on_garbage_or_empty_input() {
        let parsed = parse(&[]);
        assert!(parsed.entries.is_empty());
        assert!(parsed.cache_type.is_empty());

        let junk: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
        let parsed = parse(&junk);
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn parse_returns_empty_on_wrong_magic() {
        let mut blob: Vec<u8> = vec![b'X', b'X', b'X', b'X'];
        blob.extend_from_slice(&[0u8; 256]);
        let parsed = parse(&blob);
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn parse_decodes_minimal_single_entry() {
        let payload: Vec<u8> = (0u8..32).collect();
        let blob = build_thumbcache_blob("png", 0xAABB_CCDD_1122_3344, &payload);
        let parsed = parse(&blob);
        assert_eq!(parsed.cache_type, "256");
        assert_eq!(parsed.entries.len(), 1);
        let e = &parsed.entries[0];
        assert_eq!(e.cache_type, "256");
        assert_eq!(e.hash, 0xAABB_CCDD_1122_3344);
        assert_eq!(e.extension, "png");
        assert_eq!(e.data_size, payload.len() as u32);
        assert_eq!(e.data_checksum, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(e.header_checksum, 0xFEED_FACE_BAAD_F00D);
        assert_eq!(e.thumbnail_data, payload);
    }

    #[test]
    fn parse_stops_at_corrupt_entry_size() {
        // Build a valid-ish file but stomp the entry_size to 0 — the
        // walker must bail rather than loop forever.
        let mut blob = build_thumbcache_blob("jpg", 1, &[0u8; 16]);
        // entry_size is at offset 24 (after the 24-byte header) + 4 = 28.
        blob[28..32].copy_from_slice(&0u32.to_le_bytes());
        let parsed = parse(&blob);
        // Walker bails before pushing — no panic, no infinite loop.
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn parse_caps_oversized_payload_data() {
        // Lie about data_size (declare way more than the file holds).
        let mut blob = build_thumbcache_blob("png", 1, &[0u8; 16]);
        // data_size at offset 24 (header) + 32 (entry header offset to data_size) = 56
        blob[56..60].copy_from_slice(&(MAX_THUMB_BYTES + 1).to_le_bytes());
        let parsed = parse(&blob);
        assert_eq!(parsed.entries.len(), 1);
        // Oversized payloads are skipped, original size still reported.
        assert!(parsed.entries[0].thumbnail_data.is_empty());
        assert_eq!(parsed.entries[0].data_size, MAX_THUMB_BYTES + 1);
    }

    #[test]
    fn cache_type_label_maps_known_values() {
        assert_eq!(cache_type_label(0), "32");
        assert_eq!(cache_type_label(1), "96");
        assert_eq!(cache_type_label(2), "256");
        assert_eq!(cache_type_label(3), "1024");
        assert_eq!(cache_type_label(4), "idx");
        assert_eq!(cache_type_label(7), "exif");
        assert_eq!(cache_type_label(99), "unknown");
    }

    #[test]
    fn read_utf16le_fixed_rejects_odd_length_and_oob() {
        let buf = [b'A', 0, b'B', 0];
        assert_eq!(read_utf16le_fixed(&buf, 0, 4), "AB");
        assert_eq!(read_utf16le_fixed(&buf, 0, 3), "");
        assert_eq!(read_utf16le_fixed(&buf, 10, 4), "");
    }

    #[test]
    fn thumbcache_file_default_is_empty() {
        let f = ThumbcacheFile::default();
        assert!(f.cache_type.is_empty());
        assert!(f.entries.is_empty());
    }
}
