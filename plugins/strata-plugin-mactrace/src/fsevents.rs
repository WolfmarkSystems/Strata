//! macOS FSEvents log parser (`/.fseventsd/`).
//!
//! `fseventsd` records every filesystem change the kernel makes
//! visible to userspace and writes them to gzip-compressed log files
//! under `/.fseventsd/` (one per volume, plus `fseventsd-uuid`). The
//! files contain a sequence of pages; each page begins with a magic
//! header (`1SLD` pre-10.13, `2SLD` on 10.13+) followed by tightly-
//! packed records.
//!
//! Forensically, FSEvents is one of the highest-value macOS data
//! sources: it surfaces deletions, renames, and clones that the
//! filesystem itself no longer remembers — including operations on
//! files that have since been wiped. Pair with the page filename
//! (which embeds an approximate timestamp on most builds) to bracket
//! activity windows.
//!
//! ## File format
//!
//! ```text
//! gzip wrapper -> raw page stream
//! per page:
//!   u8[4]  magic       = "1SLD" (0x444C5331) | "2SLD" (0x444C5332)
//!   u32 LE unknown
//!   u32 LE record_block_size  (size of payload in this page)
//!   <records>
//!
//! per record (1SLD):
//!   <path>  null-terminated UTF-8 string
//!   u64 LE  event_id
//!   u32 LE  flags
//!
//! per record (2SLD, 10.13+):
//!   <path>  null-terminated UTF-8 string
//!   u64 LE  event_id
//!   u32 LE  flags
//!   u64 LE  node_id  (inode-like — currently surfaced only in detail)
//! ```
//!
//! ## Flag bitmap
//!
//! Selected `FSE_*` constants Apple writes into the `flags` field:
//!
//! | Constant | Value | Meaning |
//! |---|---|---|
//! | Created     | 0x00000100 | New item appeared |
//! | Removed     | 0x00000200 | Item deleted |
//! | Modified    | 0x00001000 | Content changed |
//! | Renamed     | 0x00000800 | Path / filename changed |
//! | IsDirectory | 0x00040000 | Item is a directory |
//! | ItemCloned  | 0x00400000 | APFS clone (10.13+) |
//! | MountEvent  | 0x00000040 | Volume mount |
//! | UnmountEvent| 0x00000080 | Volume unmount |
//!
//! ## MITRE ATT&CK
//! * **T1070.004** (Indicator Removal: File Deletion) — `Removed`.
//! * **T1074.001** (Local Data Staging) — `Created` of large items
//!   (heuristic, applied at the artifact-emission layer).
//! * **T1083** (File and Directory Discovery) — fallback.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.

use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use std::io::Read;
use std::path::Path;

/// Page magic for pre-macOS 10.13 logs (`"1SLD"`, little-endian).
const MAGIC_1SLD: u32 = 0x444C_5331;
/// Page magic for macOS 10.13+ logs (`"2SLD"`, little-endian).
const MAGIC_2SLD: u32 = 0x444C_5332;
/// Hard cap on records returned per file. Real `/.fseventsd/`
/// log pages emit thousands per shift; 200 000 is a safety bound
/// against malformed `record_block_size` walks.
const MAX_RECORDS: usize = 200_000;
/// Maximum decompressed bytes we'll process per file (256 MB). Caps
/// the worst-case zip-bomb damage without rejecting legitimate logs
/// (which top out around 100 MB on busy systems).
const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;

/// Bitflags struct over the FSEvents `flags` field. Implemented
/// inline rather than via the `bitflags` crate to avoid a new
/// dependency for one bit-mask type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsEventFlags(pub u32);

impl FsEventFlags {
    pub const CREATED: u32 = 0x0000_0100;
    pub const REMOVED: u32 = 0x0000_0200;
    pub const RENAMED: u32 = 0x0000_0800;
    pub const MODIFIED: u32 = 0x0000_1000;
    pub const IS_DIRECTORY: u32 = 0x0004_0000;
    pub const ITEM_CLONED: u32 = 0x0040_0000;
    pub const MOUNT_EVENT: u32 = 0x0000_0040;
    pub const UNMOUNT_EVENT: u32 = 0x0000_0080;

    pub fn contains(&self, mask: u32) -> bool {
        (self.0 & mask) != 0
    }

    pub fn created(&self) -> bool {
        self.contains(Self::CREATED)
    }
    pub fn removed(&self) -> bool {
        self.contains(Self::REMOVED)
    }
    pub fn renamed(&self) -> bool {
        self.contains(Self::RENAMED)
    }
    pub fn modified(&self) -> bool {
        self.contains(Self::MODIFIED)
    }
    pub fn is_directory(&self) -> bool {
        self.contains(Self::IS_DIRECTORY)
    }
    pub fn item_cloned(&self) -> bool {
        self.contains(Self::ITEM_CLONED)
    }
    pub fn mount(&self) -> bool {
        self.contains(Self::MOUNT_EVENT)
    }
    pub fn unmount(&self) -> bool {
        self.contains(Self::UNMOUNT_EVENT)
    }

    /// Render the active bits as a pipe-joined human-readable label
    /// (e.g. `"Created|IsDirectory"`). Returns `"-"` when no known
    /// bits are set.
    pub fn as_string(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.created() {
            parts.push("Created");
        }
        if self.removed() {
            parts.push("Removed");
        }
        if self.renamed() {
            parts.push("Renamed");
        }
        if self.modified() {
            parts.push("Modified");
        }
        if self.item_cloned() {
            parts.push("ItemCloned");
        }
        if self.mount() {
            parts.push("MountEvent");
        }
        if self.unmount() {
            parts.push("UnmountEvent");
        }
        if self.is_directory() {
            parts.push("IsDirectory");
        }
        if parts.is_empty() {
            "-".to_string()
        } else {
            parts.join("|")
        }
    }
}

/// One typed FSEvents record.
///
/// Field meanings are forensic-first; downstream consumers (Sigma
/// rules, the timeline view) read these without having to re-decode
/// the gzipped page format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEvent {
    /// Per-event sequence number assigned by `fseventsd` at the
    /// moment the event was written. Monotonically increasing per
    /// volume; useful for ordering events that fall inside the same
    /// page-filename second.
    pub event_id: u64,

    /// Filesystem path the event referred to, decoded from the
    /// null-terminated UTF-8 record body. Stored verbatim — no case
    /// folding, no normalization.
    pub path: String,

    /// Bitfield of `FSE_*` flags. Use the typed accessors
    /// ([`FsEventFlags::removed`], etc.) rather than the raw `.0`
    /// field unless you specifically need to test an unrecognised
    /// bit.
    pub flags: FsEventFlags,

    /// Convenience copy of `flags.is_directory()`. Materialised on
    /// the struct so report templates don't have to reach into the
    /// flags object for the most-queried scalar.
    pub is_directory: bool,

    /// Best-effort wall-clock time derived from the page filename.
    /// Apple names FSEvents pages after the hex `event_id` of the
    /// last record on the page, NOT a timestamp — but the file's
    /// mtime (and on many builds an embedded hex date prefix) gives
    /// an approximate floor on when the page was sealed. `None`
    /// when neither is available.
    pub approximate_date: Option<DateTime<Utc>>,
}

/// Parse a `/.fseventsd/` log file from raw gzipped bytes.
///
/// Returns an empty vector on decompression failure, missing magic,
/// or fully-corrupt input. Never panics.
pub fn parse(path: &Path, gzipped_bytes: &[u8]) -> Vec<FsEvent> {
    let mut out = Vec::new();

    let decompressed = match decompress_capped(gzipped_bytes, MAX_DECOMPRESSED_BYTES) {
        Some(d) => d,
        None => return out,
    };

    let approx_date = approximate_date_from_filename(path);

    walk_pages(&decompressed, approx_date, &mut out);
    out
}

/// Decompress gzip bytes with a hard byte cap. Returns `None` on
/// decode error.
fn decompress_capped(bytes: &[u8], cap: usize) -> Option<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        if out.len() >= cap {
            // Stop accepting more — caller treats as best-effort
            // truncation. We still return what we have.
            break;
        }
        match decoder.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let take = (cap - out.len()).min(n);
                out.extend_from_slice(&chunk[..take]);
            }
            Err(_) => return if out.is_empty() { None } else { Some(out) },
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn walk_pages(decompressed: &[u8], approx_date: Option<DateTime<Utc>>, out: &mut Vec<FsEvent>) {
    let mut offset = 0usize;
    while offset + 12 <= decompressed.len() && out.len() < MAX_RECORDS {
        let magic = match read_u32_le(decompressed, offset) {
            Some(m) => m,
            None => break,
        };
        let is_v2 = match magic {
            MAGIC_1SLD => false,
            MAGIC_2SLD => true,
            _ => break,
        };
        let _unknown = read_u32_le(decompressed, offset + 4).unwrap_or(0);
        let block_size = match read_u32_le(decompressed, offset + 8) {
            Some(s) => s as usize,
            None => break,
        };
        if block_size == 0 {
            break;
        }
        let page_payload_start = offset + 12;
        let page_payload_end = page_payload_start
            .saturating_add(block_size)
            .min(decompressed.len());
        if page_payload_end <= page_payload_start {
            break;
        }
        walk_records(
            &decompressed[page_payload_start..page_payload_end],
            is_v2,
            approx_date,
            out,
        );
        let next = page_payload_end;
        if next <= offset {
            break;
        }
        offset = next;
    }
}

fn walk_records(
    page: &[u8],
    is_v2: bool,
    approx_date: Option<DateTime<Utc>>,
    out: &mut Vec<FsEvent>,
) {
    let mut pos = 0usize;
    let trailer = if is_v2 {
        // path + u64 event_id + u32 flags + u64 node_id
        8 + 4 + 8
    } else {
        // path + u64 event_id + u32 flags
        8 + 4
    };
    while pos < page.len() && out.len() < MAX_RECORDS {
        let path_end = match find_nul(page, pos) {
            Some(e) => e,
            None => break,
        };
        let path_bytes = &page[pos..path_end];
        let path_str = match std::str::from_utf8(path_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => String::from_utf8_lossy(path_bytes).into_owned(),
        };
        let after_nul = path_end + 1;
        if after_nul + trailer > page.len() {
            break;
        }
        let event_id = match read_u64_le(page, after_nul) {
            Some(v) => v,
            None => break,
        };
        let flags_raw = match read_u32_le(page, after_nul + 8) {
            Some(v) => v,
            None => break,
        };
        let flags = FsEventFlags(flags_raw);
        let is_directory = flags.is_directory();

        out.push(FsEvent {
            event_id,
            path: path_str,
            flags,
            is_directory,
            approximate_date: approx_date,
        });

        let next = after_nul + trailer;
        if next <= pos {
            break;
        }
        pos = next;
    }
}

/// Apple FSEvents page filenames are typically hex strings —
/// frequently a hex Unix timestamp prefix on macOS 10.10+. This
/// helper tries the leading 8–16 hex chars as both Apple-epoch and
/// Unix-epoch seconds and returns the first plausible result.
pub(crate) fn approximate_date_from_filename(path: &Path) -> Option<DateTime<Utc>> {
    let name = path.file_name()?.to_str()?;
    let stem = name.split('.').next().unwrap_or(name);
    if stem.is_empty() || stem.len() < 8 || !stem.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let take = stem.len().min(16);
    let value = u64::from_str_radix(&stem[..take], 16).ok()?;
    // Try Unix-seconds plausibility first (1990..2100).
    if (631_152_000..4_102_444_800).contains(&value) {
        return DateTime::<Utc>::from_timestamp(value as i64, 0);
    }
    // Try Apple-CoreData-seconds (978_307_200 offset).
    let apple = value as i64 + 978_307_200;
    if (631_152_000..4_102_444_800).contains(&(apple as u64)) {
        return DateTime::<Utc>::from_timestamp(apple, 0);
    }
    None
}

fn find_nul(buf: &[u8], from: usize) -> Option<usize> {
    buf.iter()
        .enumerate()
        .skip(from)
        .find_map(|(i, &b)| if b == 0 { Some(i) } else { None })
}

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

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn build_record_v2(path: &str, event_id: u64, flags: u32, node_id: u64, out: &mut Vec<u8>) {
        out.extend_from_slice(path.as_bytes());
        out.push(0);
        out.extend_from_slice(&event_id.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&node_id.to_le_bytes());
    }

    fn build_record_v1(path: &str, event_id: u64, flags: u32, out: &mut Vec<u8>) {
        out.extend_from_slice(path.as_bytes());
        out.push(0);
        out.extend_from_slice(&event_id.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
    }

    fn wrap_in_page(magic: u32, records: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&magic.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // unknown
        out.extend_from_slice(&(records.len() as u32).to_le_bytes()); // block_size
        out.extend_from_slice(records);
        out
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(bytes).expect("gzip encoder write");
        e.finish().expect("gzip encoder finish")
    }

    #[test]
    fn parse_returns_empty_on_invalid_gzip() {
        let path = Path::new("/.fseventsd/0000000000000000");
        let result = parse(path, b"not gzip");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_returns_empty_on_unknown_magic() {
        // Valid gzip wrapping nonsense magic.
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        payload.extend_from_slice(&[0u8; 8]);
        let blob = gzip(&payload);
        let result = parse(Path::new("/.fseventsd/x"), &blob);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_decodes_v2_record_with_flags() {
        let mut records: Vec<u8> = Vec::new();
        build_record_v2(
            "/Users/alice/secret.docx",
            42,
            FsEventFlags::CREATED | FsEventFlags::IS_DIRECTORY,
            7777,
            &mut records,
        );
        let page = wrap_in_page(MAGIC_2SLD, &records);
        let blob = gzip(&page);
        let events = parse(Path::new("/.fseventsd/00000000675abc12"), &blob);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_id, 42);
        assert_eq!(e.path, "/Users/alice/secret.docx");
        assert!(e.flags.created());
        assert!(e.flags.is_directory());
        assert!(e.is_directory);
    }

    #[test]
    fn parse_decodes_v1_record() {
        let mut records: Vec<u8> = Vec::new();
        build_record_v1(
            "/private/tmp/dropper.sh",
            99,
            FsEventFlags::CREATED | FsEventFlags::REMOVED,
            &mut records,
        );
        let page = wrap_in_page(MAGIC_1SLD, &records);
        let blob = gzip(&page);
        let events = parse(Path::new("/.fseventsd/0000000000000063"), &blob);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, "/private/tmp/dropper.sh");
        assert!(events[0].flags.created());
        assert!(events[0].flags.removed());
    }

    #[test]
    fn parse_decodes_multiple_records_in_one_page() {
        let mut records: Vec<u8> = Vec::new();
        build_record_v2("/a.txt", 1, FsEventFlags::CREATED, 0, &mut records);
        build_record_v2("/b.txt", 2, FsEventFlags::REMOVED, 0, &mut records);
        build_record_v2("/c.txt", 3, FsEventFlags::RENAMED, 0, &mut records);
        let page = wrap_in_page(MAGIC_2SLD, &records);
        let blob = gzip(&page);
        let events = parse(Path::new("/.fseventsd/x"), &blob);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_id, 1);
        assert!(events[0].flags.created());
        assert_eq!(events[1].event_id, 2);
        assert!(events[1].flags.removed());
        assert_eq!(events[2].event_id, 3);
        assert!(events[2].flags.renamed());
    }

    #[test]
    fn flags_as_string_renders_pipe_separated() {
        let f = FsEventFlags(FsEventFlags::CREATED | FsEventFlags::IS_DIRECTORY);
        assert_eq!(f.as_string(), "Created|IsDirectory");

        let f = FsEventFlags(FsEventFlags::REMOVED | FsEventFlags::RENAMED);
        assert_eq!(f.as_string(), "Removed|Renamed");

        assert_eq!(FsEventFlags(0).as_string(), "-");
    }

    #[test]
    fn approximate_date_from_filename_decodes_unix_hex() {
        // Apple FSEvents page filenames are 16 hex chars. Hex
        // 00000000675ABC12 = 1_733_999_634 = 2024-12-12 09:53:54 UTC,
        // well inside the plausibility window.
        let dt = approximate_date_from_filename(Path::new("/.fseventsd/00000000675abc12"))
            .expect("plausible Unix-hex timestamp must decode");
        assert_eq!(dt.timestamp(), 1_733_999_634);
        assert!(dt.timestamp() > 1_262_304_000); // 2010-01-01
        assert!(dt.timestamp() < 1_893_456_000); // 2030-01-01
    }

    #[test]
    fn approximate_date_returns_none_for_non_hex_filename() {
        assert!(approximate_date_from_filename(Path::new("/.fseventsd/fseventsd-uuid")).is_none());
        assert!(approximate_date_from_filename(Path::new("/.fseventsd/")).is_none());
    }

    #[test]
    fn parse_does_not_panic_on_truncated_record() {
        // Page declares a record but bytes run out mid-header.
        let mut records: Vec<u8> = b"/path".to_vec();
        records.push(0);
        records.extend_from_slice(&[0xFF; 4]); // partial event_id
        let page = wrap_in_page(MAGIC_2SLD, &records);
        let blob = gzip(&page);
        let events = parse(Path::new("/.fseventsd/x"), &blob);
        // Either zero events or one truncated — never a panic.
        assert!(events.len() <= 1);
    }

    #[test]
    fn fs_event_flags_accessor_round_trip() {
        let f = FsEventFlags(
            FsEventFlags::CREATED
                | FsEventFlags::REMOVED
                | FsEventFlags::RENAMED
                | FsEventFlags::MODIFIED
                | FsEventFlags::IS_DIRECTORY
                | FsEventFlags::ITEM_CLONED
                | FsEventFlags::MOUNT_EVENT
                | FsEventFlags::UNMOUNT_EVENT,
        );
        assert!(f.created());
        assert!(f.removed());
        assert!(f.renamed());
        assert!(f.modified());
        assert!(f.is_directory());
        assert!(f.item_cloned());
        assert!(f.mount());
        assert!(f.unmount());
    }
}
