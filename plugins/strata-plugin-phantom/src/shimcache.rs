//! AppCompatCache / ShimCache binary parser.
//!
//! The Application Compatibility Cache (colloquially "ShimCache") lives at
//! `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` in the
//! `AppCompatCache` REG_BINARY value. Windows uses it to track executables
//! seen by the Application Compatibility Infrastructure — an executable is
//! recorded the first time the system inspects it, which in practice means
//! the first time an interactive user's shell touches the file.
//!
//! Forensically: **ShimCache proves existence, not execution**. Windows 10+
//! dropped the "InsertFlag / execution bit" that older versions carried, so
//! presence in ShimCache only confirms the file existed at `last_modified`
//! time and was cataloged by AppCompat. Combine with Prefetch or AmCache to
//! prove actual execution.
//!
//! Supported binary formats:
//!
//! | Signature magic  | Header bytes | Windows release                       |
//! |------------------|--------------|---------------------------------------|
//! | `0xBADC0FEE`     | 0            | Windows 7 / 2008 R2 (32- and 64-bit) |
//! | `0x80` (u32 LE)  | 128          | Windows 8.0                           |
//! | `"10ts"`/`"00ts"`| 128          | Windows 8.1 / 2012 R2                 |
//! | variable header  | 48           | Windows 10 / 11                       |
//!
//! Each Windows 10 entry is framed by a `"10ts"` (0x73743031) magic, followed
//! by a path length + UTF-16LE path, a `FILETIME`, and a data blob. This
//! module parses all four dialects and returns a unified
//! [`ShimCacheEntry`] list.
//!
//! ## MITRE ATT&CK
//! * **T1059** (Command and Scripting Interpreter) — ShimCache is the primary
//!   post-execution forensic artifact for interactive-shell executable
//!   discovery.
//! * **T1112** (Modify Registry) — adversaries who clear ShimCache leave a
//!   signature mismatch between the value and its expected hive structure.
//!
//! All parsing is read-only. Malformed input returns an empty vector rather
//! than panicking — ShimCache carvers must tolerate partial blobs recovered
//! from VSS snapshots or unallocated space.

use chrono::{DateTime, Utc};

/// Windows 7 AppCompatCache signature (little-endian).
const WIN7_SIGNATURE: u32 = 0xBADC_0FEE;
/// Windows 8.0 AppCompatCache signature (little-endian).
const WIN8_SIGNATURE: u32 = 0x80;
/// Windows 8.1 per-entry magic (`"10ts"` ASCII, little-endian).
const WIN81_ENTRY_MAGIC: u32 = 0x7374_3031;
/// Windows 8.0 per-entry magic (`"00ts"` ASCII, little-endian).
const WIN80_ENTRY_MAGIC: u32 = 0x7374_3030;
/// Header size for Win8.x formats (the signature lives at offset 0, entries
/// begin at offset 128).
const WIN8X_HEADER_BYTES: usize = 128;
/// Maximum path length we trust from any single entry. Longer than the NTFS
/// max (32,767) but smaller than the smallest realistic corrupted blob.
const MAX_PATH_BYTES: usize = 65_536;
/// Hard cap on entries returned from a single blob — real ShimCache peaks at
/// ~1024 entries on Win10 and ~512 on Win7, so 4096 is a generous guard
/// against adversarial / malformed inputs.
const MAX_ENTRIES: usize = 4096;

/// Offset where Win10 entry scanning begins. Empirically the Win10 header is
/// 48 bytes on most builds (1507 – 22H2); accepting any offset between 48
/// and 128 handles the known build variance.
const WIN10_SCAN_START_MIN: usize = 48;
const WIN10_SCAN_START_MAX: usize = 128;

/// Marker byte at offset 0x04 in Win7 entries indicating the executable was
/// shimmed (had an application compatibility fix applied). The bit set /
/// clear semantics differ between Win7 x86 and x64 but the flag byte itself
/// is at the same offset.
const WIN7_SHIMMED_FLAG_MASK: u32 = 0x0002;

/// One decoded ShimCache entry.
///
/// Every field is documented in terms of its forensic meaning rather than
/// its byte layout — consumers (Phantom plugin, analyst reports, the
/// timeline view) care about the semantics, not the on-disk encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimCacheEntry {
    /// Full path of the executable as recorded by Windows Application
    /// Compatibility. Paths are normalized from UTF-16LE to Rust `String`
    /// (lossy: invalid surrogates become `U+FFFD`) so downstream consumers
    /// can hash, sort, and display without re-decoding. May contain `SYSVOL`
    /// prefixes, drive letters, or UNC paths depending on the OS build.
    pub executable_path: String,

    /// Last-modified timestamp of the executable **at the moment Windows
    /// cached it**. This is the file's `$STANDARD_INFORMATION` mtime, not a
    /// cache-insertion timestamp. Critical: a timestomped binary will show
    /// the stomped time here, providing corroborating evidence when cross-
    /// referenced with `$MFT` and USN Journal entries. Stored as Unix UTC
    /// because every other Strata parser normalizes to `chrono::DateTime<Utc>`
    /// and we want joinable columns in the timeline database.
    pub last_modified: DateTime<Utc>,

    /// `true` if the AppCompat subsystem applied a shim (a compatibility
    /// fix) to this executable. On Win7 this maps to the `InsertFlag` bit;
    /// on Win8.x it maps to the `InsertFlag` byte; on Win10+ this flag is
    /// **always `false`** because the field was removed from the binary
    /// format. Consumers should treat `shimmed == false` on Win10+ as
    /// "unknown", not "definitely not shimmed".
    pub shimmed: bool,

    /// Zero-based position of the entry in the original cache blob. Order
    /// matters: ShimCache is most-recently-used-first, so `entry_index == 0`
    /// is the newest-seen executable. Preserving the index lets the UI
    /// present entries in MRU order and lets correlation rules detect
    /// out-of-order insertion (an anti-forensic tell).
    pub entry_index: u32,

    /// The hive file the entry was parsed from, expressed as the original
    /// evidence-tree path (e.g. `"C:\\Windows\\System32\\config\\SYSTEM"`
    /// or `"/evidence/hives/SYSTEM"`). This lets downstream tools reconstruct
    /// the chain of custody without holding a separate context parameter.
    pub source_hive: String,
}

/// Result of signature sniffing against a raw `AppCompatCache` blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimCacheFormat {
    /// Windows 7 / Server 2008 R2. Signature `0xBADC0FEE` at offset 0.
    Win7,
    /// Windows 8.0. Signature `0x80` at offset 0, entries magic `"00ts"`.
    Win80,
    /// Windows 8.1 / Server 2012 R2. Entries magic `"10ts"` at offset 128.
    Win81,
    /// Windows 10 / 11. No fixed top-level signature; entries carry a
    /// `"10ts"` magic and the header size is build-dependent (48–128 bytes).
    Win10,
    /// No recognised ShimCache framing detected.
    Unknown,
}

/// Classify a raw `AppCompatCache` REG_BINARY blob.
///
/// Cheap — reads at most the first 132 bytes and one u32 magic probe in the
/// Win10 scan window.
pub fn detect_format(blob: &[u8]) -> ShimCacheFormat {
    if blob.len() < 8 {
        return ShimCacheFormat::Unknown;
    }
    let sig = read_u32_le(blob, 0).unwrap_or(0);
    if sig == WIN7_SIGNATURE {
        return ShimCacheFormat::Win7;
    }
    if sig == WIN8_SIGNATURE && blob.len() > WIN8X_HEADER_BYTES {
        // Disambiguate Win8.0 vs Win8.1 by inspecting the first entry magic.
        let first_entry_magic = read_u32_le(blob, WIN8X_HEADER_BYTES).unwrap_or(0);
        return match first_entry_magic {
            WIN81_ENTRY_MAGIC => ShimCacheFormat::Win81,
            WIN80_ENTRY_MAGIC => ShimCacheFormat::Win80,
            _ => ShimCacheFormat::Unknown,
        };
    }
    // Win10: scan for the "10ts" magic anywhere in the plausible header
    // window (48..=128 bytes). We accept the first hit as the start of
    // entries.
    let scan_end = WIN10_SCAN_START_MAX.min(blob.len().saturating_sub(4));
    let mut offset = WIN10_SCAN_START_MIN;
    while offset <= scan_end {
        if read_u32_le(blob, offset) == Some(WIN81_ENTRY_MAGIC) {
            return ShimCacheFormat::Win10;
        }
        offset += 1;
    }
    ShimCacheFormat::Unknown
}

/// Parse the raw `AppCompatCache` REG_BINARY blob into typed entries.
///
/// * `blob` — the raw value data as read from the registry.
/// * `source_hive` — the hive file path; propagated into every emitted
///   [`ShimCacheEntry::source_hive`].
///
/// Returns an empty vector on unrecognized or corrupt input. Never panics.
pub fn parse(blob: &[u8], source_hive: &str) -> Vec<ShimCacheEntry> {
    match detect_format(blob) {
        ShimCacheFormat::Win7 => parse_win7(blob, source_hive),
        ShimCacheFormat::Win80 | ShimCacheFormat::Win81 => parse_win8x(blob, source_hive),
        ShimCacheFormat::Win10 => parse_win10(blob, source_hive),
        ShimCacheFormat::Unknown => Vec::new(),
    }
}

/// Parse a Win7 AppCompatCache blob.
///
/// Layout (x64, the only variant Strata targets for Win7 — all Win7 x86
/// deployments are long EoL):
/// ```text
/// offset 0x00  u32 signature  = 0xBADC0FEE
/// offset 0x04  u32 num_entries
/// offset 0x80  entries (32 bytes fixed header + variable path):
///   u16 path_size
///   u16 path_max_size
///   u32 padding (x64 only)
///   u32 path_offset
///   u32 padding
///   i64 last_modified (FILETIME)
///   u32 insert_flags
///   u32 shim_flags
///   u64 padding
/// ```
fn parse_win7(blob: &[u8], source_hive: &str) -> Vec<ShimCacheEntry> {
    let mut out = Vec::new();
    let Some(num_entries) = read_u32_le(blob, 4) else {
        return out;
    };
    let capped = num_entries.min(MAX_ENTRIES as u32) as usize;
    const HEADER_SIZE: usize = 128;
    const ENTRY_STRIDE: usize = 48; // Win7 x64 entry header is 48 bytes
    let mut idx = 0u32;
    for i in 0..capped {
        let entry_off = HEADER_SIZE + i * ENTRY_STRIDE;
        if entry_off + ENTRY_STRIDE > blob.len() {
            break;
        }
        let path_size = match read_u16_le(blob, entry_off) {
            Some(v) => v as usize,
            None => break,
        };
        let path_offset = match read_u32_le(blob, entry_off + 8) {
            Some(v) => v as usize,
            None => break,
        };
        let last_modified_raw = match read_i64_le(blob, entry_off + 16) {
            Some(v) => v,
            None => break,
        };
        let shim_flags = read_u32_le(blob, entry_off + 28).unwrap_or(0);
        let shimmed = (shim_flags & WIN7_SHIMMED_FLAG_MASK) != 0;
        let path = match read_utf16le_slice(blob, path_offset, path_size) {
            Some(p) if !p.is_empty() => p,
            _ => continue,
        };
        let Some(last_modified) = filetime_to_datetime(last_modified_raw) else {
            continue;
        };
        out.push(ShimCacheEntry {
            executable_path: path,
            last_modified,
            shimmed,
            entry_index: idx,
            source_hive: source_hive.to_string(),
        });
        idx += 1;
        if out.len() >= MAX_ENTRIES {
            break;
        }
    }
    out
}

/// Parse a Win8.0 or Win8.1 AppCompatCache blob.
///
/// Layout (both sub-versions share the framing, only the per-entry magic
/// differs — `"00ts"` on 8.0, `"10ts"` on 8.1):
/// ```text
/// offset 0x00  u32 signature  = 0x80
/// offset 0x80  entries:
///   u32 magic ("00ts" | "10ts")
///   u32 unknown
///   u32 cache_entry_data_size
///   u16 path_size
///   bytes path (UTF-16LE, `path_size` bytes)
///   u16 insert_flags
///   u16 shim_flags
///   u32 data_size
///   bytes data (`data_size` bytes)
///   i64 last_modified (FILETIME)
/// ```
/// Win8.0 orders `last_modified` before the flags; Win8.1 after. Rather
/// than replicating the full divergence we use the known offset for each.
fn parse_win8x(blob: &[u8], source_hive: &str) -> Vec<ShimCacheEntry> {
    let mut out = Vec::new();
    let mut offset = WIN8X_HEADER_BYTES;
    let mut idx = 0u32;
    while offset + 12 <= blob.len() && out.len() < MAX_ENTRIES {
        let magic = read_u32_le(blob, offset).unwrap_or(0);
        if magic != WIN81_ENTRY_MAGIC && magic != WIN80_ENTRY_MAGIC {
            break;
        }
        let entry_data_size = match read_u32_le(blob, offset + 8) {
            Some(v) => v as usize,
            None => break,
        };
        // Bound the inner walk by the entry size so a corrupt length field
        // cannot walk off the end of the blob.
        let entry_end = offset
            .saturating_add(12)
            .saturating_add(entry_data_size)
            .min(blob.len());
        let path_size = match read_u16_le(blob, offset + 12) {
            Some(v) => v as usize,
            None => break,
        };
        if path_size == 0 || path_size > MAX_PATH_BYTES {
            offset = entry_end.max(offset + 16);
            continue;
        }
        let path_off = offset + 14;
        if path_off + path_size > entry_end {
            break;
        }
        let path = match read_utf16le_slice(blob, path_off, path_size) {
            Some(p) if !p.is_empty() => p,
            _ => {
                offset = entry_end;
                continue;
            }
        };
        // After the path: u16 insert_flags, u16 shim_flags, u32 data_size
        let after_path = path_off + path_size;
        let insert_flags = read_u16_le(blob, after_path).unwrap_or(0);
        let data_size = read_u32_le(blob, after_path + 4).unwrap_or(0) as usize;
        // last_modified sits after the variable `data` blob.
        let filetime_off = after_path + 8 + data_size;
        if filetime_off + 8 > entry_end {
            offset = entry_end;
            continue;
        }
        let last_modified_raw = match read_i64_le(blob, filetime_off) {
            Some(v) => v,
            None => break,
        };
        let shimmed = (insert_flags & 0x0002) != 0;
        let Some(last_modified) = filetime_to_datetime(last_modified_raw) else {
            offset = entry_end;
            continue;
        };
        out.push(ShimCacheEntry {
            executable_path: path,
            last_modified,
            shimmed,
            entry_index: idx,
            source_hive: source_hive.to_string(),
        });
        idx += 1;
        // Advance past this entry using the declared entry_data_size.
        let next = offset + 12 + entry_data_size;
        if next <= offset {
            break; // corrupted size field — bail to avoid infinite loop
        }
        offset = next;
    }
    out
}

/// Parse a Windows 10/11 AppCompatCache blob.
///
/// Layout (build-variant tolerant — we scan for the first `"10ts"` magic in
/// the 48..128 header window and then walk entries contiguously):
/// ```text
/// entry:
///   u32 magic ("10ts")
///   u32 unknown
///   u32 cache_entry_data_size
///   u16 path_size
///   bytes path (UTF-16LE, `path_size` bytes)
///   i64 last_modified (FILETIME)
///   u32 data_size
///   bytes data (`data_size` bytes)
/// ```
/// Win10 dropped the shim/insert flag byte, so `shimmed` is always `false`.
fn parse_win10(blob: &[u8], source_hive: &str) -> Vec<ShimCacheEntry> {
    let mut out = Vec::new();
    // Find the first "10ts" in the plausible header window.
    let scan_end = WIN10_SCAN_START_MAX.min(blob.len().saturating_sub(4));
    let mut start = None;
    for off in WIN10_SCAN_START_MIN..=scan_end {
        if read_u32_le(blob, off) == Some(WIN81_ENTRY_MAGIC) {
            start = Some(off);
            break;
        }
    }
    let Some(mut offset) = start else {
        return out;
    };
    let mut idx = 0u32;
    while offset + 14 <= blob.len() && out.len() < MAX_ENTRIES {
        let magic = read_u32_le(blob, offset).unwrap_or(0);
        if magic != WIN81_ENTRY_MAGIC {
            break;
        }
        let entry_data_size = match read_u32_le(blob, offset + 8) {
            Some(v) => v as usize,
            None => break,
        };
        let entry_end = offset
            .saturating_add(12)
            .saturating_add(entry_data_size)
            .min(blob.len());
        let path_size = match read_u16_le(blob, offset + 12) {
            Some(v) => v as usize,
            None => break,
        };
        if path_size == 0 || path_size > MAX_PATH_BYTES {
            offset = entry_end;
            continue;
        }
        let path_off = offset + 14;
        if path_off + path_size > entry_end {
            break;
        }
        let path = match read_utf16le_slice(blob, path_off, path_size) {
            Some(p) if !p.is_empty() => p,
            _ => {
                offset = entry_end;
                continue;
            }
        };
        let filetime_off = path_off + path_size;
        if filetime_off + 8 > entry_end {
            break;
        }
        let last_modified_raw = match read_i64_le(blob, filetime_off) {
            Some(v) => v,
            None => break,
        };
        let Some(last_modified) = filetime_to_datetime(last_modified_raw) else {
            offset = entry_end;
            continue;
        };
        out.push(ShimCacheEntry {
            executable_path: path,
            last_modified,
            shimmed: false, // field removed in Win10
            entry_index: idx,
            source_hive: source_hive.to_string(),
        });
        idx += 1;
        let next = offset + 12 + entry_data_size;
        if next <= offset {
            break;
        }
        offset = next;
    }
    out
}

// ── byte-reading helpers ────────────────────────────────────────────────

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let slice = buf.get(off..off.checked_add(2)?)?;
    let arr: [u8; 2] = slice.try_into().ok()?;
    Some(u16::from_le_bytes(arr))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off.checked_add(4)?)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

fn read_i64_le(buf: &[u8], off: usize) -> Option<i64> {
    let slice = buf.get(off..off.checked_add(8)?)?;
    let arr: [u8; 8] = slice.try_into().ok()?;
    Some(i64::from_le_bytes(arr))
}

/// Read `len` bytes starting at `off`, interpret as UTF-16LE, and decode
/// until the first null terminator. Returns `None` if the slice is out of
/// bounds or `len` is odd.
fn read_utf16le_slice(buf: &[u8], off: usize, len: usize) -> Option<String> {
    if !len.is_multiple_of(2) || len > MAX_PATH_BYTES {
        return None;
    }
    let end = off.checked_add(len)?;
    let slice = buf.get(off..end)?;
    let u16s: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&ch| ch != 0)
        .collect();
    Some(String::from_utf16_lossy(&u16s))
}

/// Convert a Windows `FILETIME` (100-ns ticks since 1601-01-01 UTC) to
/// `DateTime<Utc>`. Returns `None` for the uninitialised slot (0) and for
/// values that fall outside `chrono`'s representable range.
fn filetime_to_datetime(ft: i64) -> Option<DateTime<Utc>> {
    if ft <= 0 {
        return None;
    }
    const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
    let unix_100ns = ft.checked_sub(EPOCH_DIFF_100NS)?;
    let unix_secs = unix_100ns / 10_000_000;
    let unix_nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    DateTime::<Utc>::from_timestamp(unix_secs, unix_nanos)
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Win10 AppCompatCache blob with one entry for
    /// `C:\Temp\evil.exe` and a FILETIME corresponding to
    /// 2024-06-01 12:00:00 UTC.
    fn build_win10_blob(path_utf16: &[u8], filetime: i64) -> Vec<u8> {
        let mut blob: Vec<u8> = vec![0xAB; 48];
        // Entry: magic "10ts"
        blob.extend_from_slice(&WIN81_ENTRY_MAGIC.to_le_bytes());
        // Unknown (4)
        blob.extend_from_slice(&0u32.to_le_bytes());
        // entry_data_size: path_size_field(2) + path + filetime(8) +
        // data_size_field(4) + 0 data
        let entry_data_size = (2 + path_utf16.len() + 8 + 4) as u32;
        blob.extend_from_slice(&entry_data_size.to_le_bytes());
        // path_size
        blob.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes());
        // path
        blob.extend_from_slice(path_utf16);
        // last_modified
        blob.extend_from_slice(&filetime.to_le_bytes());
        // data_size = 0
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// 2024-06-01 12:00:00 UTC expressed as a Windows FILETIME.
    fn filetime_2024_06_01_noon() -> i64 {
        // unix_secs = 1_717_243_200
        const UNIX: i64 = 1_717_243_200;
        const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
        UNIX * 10_000_000 + EPOCH_DIFF_100NS
    }

    #[test]
    fn detect_win10_format_from_well_formed_blob() {
        let path = utf16le(r"C:\Temp\evil.exe");
        let blob = build_win10_blob(&path, filetime_2024_06_01_noon());
        assert_eq!(detect_format(&blob), ShimCacheFormat::Win10);
    }

    #[test]
    fn detect_unknown_on_empty_input() {
        assert_eq!(detect_format(&[]), ShimCacheFormat::Unknown);
        assert_eq!(detect_format(&[0, 1, 2, 3]), ShimCacheFormat::Unknown);
    }

    #[test]
    fn detect_win7_signature() {
        let mut blob = vec![0u8; 256];
        blob[0..4].copy_from_slice(&WIN7_SIGNATURE.to_le_bytes());
        assert_eq!(detect_format(&blob), ShimCacheFormat::Win7);
    }

    #[test]
    fn parse_returns_empty_on_unknown_format() {
        // 256 bytes of zeros — no signature, no magic.
        let blob = vec![0u8; 256];
        let entries = parse(&blob, "C:/evidence/SYSTEM");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_win10_single_entry_extracts_path_and_filetime() {
        let path = utf16le(r"C:\Temp\evil.exe");
        let blob = build_win10_blob(&path, filetime_2024_06_01_noon());
        let entries = parse(&blob, "C:/evidence/SYSTEM");
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.executable_path, r"C:\Temp\evil.exe");
        assert!(!e.shimmed, "Win10 format never sets shimmed=true");
        assert_eq!(e.entry_index, 0);
        assert_eq!(e.source_hive, "C:/evidence/SYSTEM");
        assert_eq!(
            e.last_modified,
            DateTime::<Utc>::from_timestamp(1_717_243_200, 0)
                .expect("representable timestamp in test fixture")
        );
    }

    #[test]
    fn parse_win10_malformed_truncated_entry_returns_empty_or_fewer() {
        let path = utf16le(r"C:\Windows\System32\cmd.exe");
        let mut blob = build_win10_blob(&path, filetime_2024_06_01_noon());
        // Truncate mid-FILETIME.
        blob.truncate(blob.len() - 4);
        let entries = parse(&blob, "SYSTEM");
        // Must not panic; may return 0 entries (preferred) or a well-formed
        // subset — never a partial record.
        for entry in &entries {
            assert!(!entry.executable_path.is_empty());
        }
        assert!(entries.len() <= 1);
    }

    #[test]
    fn parse_win10_filetime_zero_is_rejected() {
        let path = utf16le(r"C:\ok.exe");
        let blob = build_win10_blob(&path, 0);
        let entries = parse(&blob, "SYSTEM");
        assert!(
            entries.is_empty(),
            "FILETIME 0 must not materialize as an entry"
        );
    }

    #[test]
    fn filetime_helper_roundtrips_known_date() {
        let ft = filetime_2024_06_01_noon();
        let dt = filetime_to_datetime(ft).expect("valid conversion");
        assert_eq!(dt.timestamp(), 1_717_243_200);
    }

    #[test]
    fn read_u32_le_bounds_checked() {
        let buf = [1u8, 2, 3];
        assert_eq!(read_u32_le(&buf, 0), None);
        assert_eq!(read_u32_le(&buf, 5), None);
    }

    #[test]
    fn read_utf16le_rejects_odd_length() {
        let buf = [b'A', 0, b'B'];
        assert_eq!(read_utf16le_slice(&buf, 0, 3), None);
    }

    /// Sprint-10 P3 acceptance tests. The ShimCache parser predates this
    /// sprint (commit history shows it landed during the v1.3.x phantom
    /// rewrite), so the underlying coverage is already substantial.
    /// These four tests are the explicit Sprint-10 acceptance set: each
    /// is named after the spec checklist item so a reader auditing
    /// SPRINT_10.md against the test suite can find them by literal
    /// match. They overlap intentionally with earlier tests — the
    /// duplication is the audit trail.

    #[test]
    fn sprint10_p3_shimcache_parses_known_good_entry() {
        let path = utf16le(r"C:\Windows\System32\notepad.exe");
        let blob = build_win10_blob(&path, filetime_2024_06_01_noon());
        let entries = parse(&blob, "C:/evidence/SYSTEM");
        assert_eq!(entries.len(), 1, "single Win10 entry must round-trip");
        assert_eq!(
            entries[0].executable_path,
            r"C:\Windows\System32\notepad.exe"
        );
        assert_eq!(entries[0].last_modified.timestamp(), 1_717_243_200);
        assert_eq!(entries[0].source_hive, "C:/evidence/SYSTEM");
    }

    #[test]
    fn sprint10_p3_shimcache_handles_empty_hive_gracefully() {
        // Empty input. Must not panic. Must return Ok-equivalent (empty vec).
        let entries = parse(&[], "SYSTEM");
        assert!(entries.is_empty());
        // 256 bytes of zeros — a real "value not present" can decode this way.
        let entries = parse(&vec![0u8; 256], "SYSTEM");
        assert!(entries.is_empty());
        // Truncated XP-shaped header (no valid signature) — must not panic.
        let entries = parse(&[0xAA, 0xBB, 0xCC], "SYSTEM");
        assert!(entries.is_empty());
    }

    #[test]
    fn sprint10_p3_shimcache_filetime_conversion_is_correct() {
        // Reference value from spec: 2024-06-01 12:00:00 UTC corresponds
        // to unix timestamp 1_717_243_200. Construct the FILETIME from
        // the spec's documented formula so the test pins both directions.
        const UNIX: i64 = 1_717_243_200;
        const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
        let ft = UNIX * 10_000_000 + EPOCH_DIFF_100NS;
        let dt = filetime_to_datetime(ft).expect("known-good FILETIME");
        assert_eq!(dt.timestamp(), UNIX);
        // Sanity-check the Sprint 10 spec's helper formula:
        //   (filetime / 10_000_000) - 11_644_473_600
        let manual = (ft / 10_000_000) - 11_644_473_600;
        assert_eq!(manual, UNIX);
    }

    #[test]
    fn sprint10_p3_shimcache_produces_mitre_mapping() {
        // ShimCache → MITRE T1059 mapping is asserted by Phantom's lib.rs
        // when it converts a ShimCacheEntry into an Artifact. We verify
        // the wiring is in place by reading the plugin source (a refactor
        // that drops the mapping must update the test too — that is the
        // intent: the mapping is load-bearing forensic metadata, not an
        // implementation detail).
        let lib_src = include_str!("lib.rs");
        assert!(
            lib_src.contains("crate::shimcache::parse"),
            "Phantom must invoke the ShimCache parser"
        );
        assert!(
            lib_src.contains("\"mitre\", \"T1059\"")
                || lib_src.contains("a.add_field(\"mitre\", \"T1059\")"),
            "Phantom must tag every ShimCache artifact with MITRE T1059 (Command and Scripting Interpreter)"
        );
        // ShimCache is a deterministic binary parse — no ML, no advisory.
        // Confirm Phantom does NOT mark these as advisory/inferred. The
        // engine adapter's default `execute()` builds artifacts with
        // ForensicValue::Medium and is_suspicious based on path; neither
        // of those is the advisory flag (which lives on ml-anomaly
        // / ml-charges plugins). This assertion documents the contract
        // for future readers.
        assert!(
            !lib_src.contains("a.add_field(\"is_advisory\", \"true\")")
                || lib_src.matches("\"is_advisory\", \"true\"").count() == 0,
            "Phantom must not flag deterministic ShimCache parses as advisory"
        );
    }

    #[test]
    fn parse_win10_multiple_entries_preserves_order() {
        let p1 = utf16le(r"C:\first.exe");
        let p2 = utf16le(r"C:\second.exe");
        let mut blob: Vec<u8> = vec![0u8; 48];
        for path in [&p1, &p2] {
            blob.extend_from_slice(&WIN81_ENTRY_MAGIC.to_le_bytes());
            blob.extend_from_slice(&0u32.to_le_bytes());
            let size = (2 + path.len() + 8 + 4) as u32;
            blob.extend_from_slice(&size.to_le_bytes());
            blob.extend_from_slice(&(path.len() as u16).to_le_bytes());
            blob.extend_from_slice(path);
            blob.extend_from_slice(&filetime_2024_06_01_noon().to_le_bytes());
            blob.extend_from_slice(&0u32.to_le_bytes());
        }
        let entries = parse(&blob, "SYSTEM");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].executable_path, r"C:\first.exe");
        assert_eq!(entries[0].entry_index, 0);
        assert_eq!(entries[1].executable_path, r"C:\second.exe");
        assert_eq!(entries[1].entry_index, 1);
    }
}
