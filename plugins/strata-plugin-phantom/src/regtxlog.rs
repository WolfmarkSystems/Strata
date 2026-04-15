//! Windows registry transaction-log (`*.LOG1` / `*.LOG2`) parser.
//!
//! Every primary hive (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT,
//! UsrClass.dat, AmCache.hve) ships with a pair of transaction logs
//! that the kernel uses to make hive writes crash-safe. Modern (Win8+)
//! logs use the **HvLE** ("Hive Log Entry") format: each entry records
//! a sequence number plus a list of dirty pages waiting to be flushed
//! into the primary hive.
//!
//! ## File format
//!
//! Logs share the primary hive's `regf` base header (4096 bytes):
//!
//! ```text
//! offset 0x00  u32   signature = "regf"
//! offset 0x04  u32   primary_sequence_number    (used as log_sequence_number)
//! offset 0x08  u32   secondary_sequence_number
//! offset 0x1C  u32   file_type      (0 = primary, 1 = transaction log)
//! offset 0x30  u8[64] file_name      (UTF-16LE — the bound hive name)
//! ```
//!
//! After the base header, the body contains HvLE records:
//!
//! ```text
//! offset 0x00  u32   signature = "HvLE"  (0x456C7648 LE)
//! offset 0x04  u32   record_size
//! offset 0x08  u32   sequence_number
//! offset 0x0C  u32   sub_version
//! offset 0x10  u32   dirty_pages_count    (the field we care about)
//! ...
//! ```
//!
//! ## Forensic significance
//!
//! Uncommitted changes in a transaction log mean the kernel was about
//! to write something into the hive but never finished — frequent
//! causes are sudden power loss, BSOD, **or anti-forensic activity
//! that interrupted the system mid-write**. A live host that gets
//! rapid-shutdown to defeat memory acquisition will almost always
//! leave non-zero `dirty_page_count` in one or more logs.
//!
//! Pair with the primary hive's last-write times to compute the
//! window during which the interrupted write occurred.
//!
//! ## MITRE ATT&CK
//! * **T1112** (Modify Registry) — the log records the actual pending
//!   modifications.
//! * **T1070.006** (Indicator Removal: Timestomp / log clearing) —
//!   uncommitted log entries are evidence of attempted but
//!   uncompleted log/hive tampering.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.

/// Primary-hive / transaction-log signature `"regf"`, little-endian.
const REGF_SIGNATURE: u32 = 0x6665_6772;
/// HvLE per-entry signature `"HvLE"`, little-endian.
const HVLE_SIGNATURE: u32 = 0x456C_7648;
/// Transaction-log file_type code at offset 0x1C of the regf header.
const FILE_TYPE_TRANSACTION_LOG: u32 = 1;
/// Size of the regf base header that precedes the HvLE body.
const REGF_BASE_HEADER_BYTES: usize = 4096;
/// Hard cap on HvLE entries we'll walk per log to avoid runaway
/// loops on corrupt size fields. Real logs hold <100 entries.
const MAX_HVLE_ENTRIES: usize = 4096;

/// One typed transaction-log header.
///
/// Each field is documented in terms of forensic meaning, not byte
/// layout — consumers (Phantom, Sigma rules, the timeline view)
/// don't need to know the regf wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegTxLogHeader {
    /// `primary_sequence_number` from the regf header, widened to u64
    /// for compatibility with the wider Strata sequence-number
    /// representation. Logs whose primary and secondary sequence
    /// numbers diverge are evidence of an in-progress / aborted
    /// write — the kernel updates `primary` first, then writes the
    /// dirty pages, then updates `secondary` to match.
    pub log_sequence_number: u64,

    /// Total number of dirty pages declared across every HvLE record
    /// in this log. Non-zero values mean the hive on disk is **not
    /// yet up to date** — the kernel either crashed, was killed, or
    /// was interrupted mid-write before flushing those pages into the
    /// primary hive.
    pub dirty_page_count: u32,

    /// Hive name embedded in the regf header's `file_name` slot at
    /// offset 0x30. Typically a path like
    /// `\??\C:\Windows\System32\config\SYSTEM` or a leaf name like
    /// `\REGISTRY\USER\S-1-5-21-…`. Empty when the field decodes to
    /// nothing printable. Used to bind the log back to its hive even
    /// when the analyst received only the log file.
    pub hive_name: String,
}

/// Parse a `.LOG1` / `.LOG2` transaction-log file from raw bytes.
///
/// Returns `Some(RegTxLogHeader)` on success, `None` when:
///   * the input is shorter than the regf base header,
///   * the `regf` magic is missing, or
///   * the `file_type` field at offset 0x1C is not the
///     transaction-log code (so we don't misinterpret a primary hive
///     as a log file).
///
/// Never panics, never calls `unwrap`, never invokes `unsafe`.
pub fn parse(bytes: &[u8]) -> Option<RegTxLogHeader> {
    if bytes.len() < REGF_BASE_HEADER_BYTES {
        return None;
    }
    let signature = read_u32_le(bytes, 0)?;
    if signature != REGF_SIGNATURE {
        return None;
    }
    let file_type = read_u32_le(bytes, 0x1C)?;
    if file_type != FILE_TYPE_TRANSACTION_LOG {
        // This is a primary hive, not a log — caller is using the
        // wrong parser.
        return None;
    }
    let primary_seq = read_u32_le(bytes, 0x04)?;
    let hive_name = read_utf16le_fixed(bytes, 0x30, 64);
    let dirty_page_count = count_dirty_pages(bytes);

    Some(RegTxLogHeader {
        log_sequence_number: primary_seq as u64,
        dirty_page_count,
        hive_name,
    })
}

/// Walk every HvLE record in the log body and sum its
/// `dirty_pages_count` field. Win7-era logs that don't use HvLE
/// framing return 0 — interpret that as "unable to determine" rather
/// than "no dirty pages".
fn count_dirty_pages(bytes: &[u8]) -> u32 {
    let mut total: u64 = 0;
    let mut offset = REGF_BASE_HEADER_BYTES;
    let mut walked = 0usize;
    while offset + 20 <= bytes.len() && walked < MAX_HVLE_ENTRIES {
        let magic = match read_u32_le(bytes, offset) {
            Some(m) => m,
            None => break,
        };
        if magic != HVLE_SIGNATURE {
            break;
        }
        let record_size = match read_u32_le(bytes, offset + 4) {
            Some(s) => s as usize,
            None => break,
        };
        if record_size < 20 {
            break;
        }
        let dirty = read_u32_le(bytes, offset + 0x10).unwrap_or(0);
        total = total.saturating_add(dirty as u64);
        let next = offset.saturating_add(record_size);
        if next <= offset {
            break;
        }
        offset = next;
        walked += 1;
    }
    total.min(u32::MAX as u64) as u32
}

/// `true` when the log records pending modifications — the canonical
/// "interrupted anti-forensic activity" signal.
pub fn has_uncommitted_changes(header: &RegTxLogHeader) -> bool {
    header.dirty_page_count > 0
}

// ── byte-reading helpers ────────────────────────────────────────────────

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off.checked_add(4)?)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

/// Read `len` bytes starting at `off` and decode as UTF-16LE up to
/// the first null. `len` must be even; an odd `len` returns the empty
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

    /// Build a valid 4096-byte regf log base header with the given
    /// sequence number and hive name. The body is filled with zeros
    /// (i.e. no HvLE entries).
    fn build_log_header(primary_seq: u32, hive_name: &str) -> Vec<u8> {
        let mut blob: Vec<u8> = vec![0u8; REGF_BASE_HEADER_BYTES];
        blob[0..4].copy_from_slice(&REGF_SIGNATURE.to_le_bytes());
        blob[4..8].copy_from_slice(&primary_seq.to_le_bytes());
        // file_type = 1 (transaction log) at offset 0x1C
        blob[0x1C..0x1C + 4].copy_from_slice(&FILE_TYPE_TRANSACTION_LOG.to_le_bytes());
        // hive_name at offset 0x30, 64 bytes
        let name_bytes = utf16le_padded(hive_name, 64);
        blob[0x30..0x30 + 64].copy_from_slice(&name_bytes);
        blob
    }

    /// Append one HvLE record carrying the given dirty-page count.
    fn append_hvle(blob: &mut Vec<u8>, sequence: u32, dirty_pages: u32) {
        let record_size = 32u32;
        blob.extend_from_slice(&HVLE_SIGNATURE.to_le_bytes()); // magic
        blob.extend_from_slice(&record_size.to_le_bytes()); // record_size
        blob.extend_from_slice(&sequence.to_le_bytes()); // sequence_number
        blob.extend_from_slice(&0u32.to_le_bytes()); // sub_version
        blob.extend_from_slice(&dirty_pages.to_le_bytes()); // dirty_pages_count
        // Ensure the body is exactly record-size aligned.
        let body_len = blob.len() - REGF_BASE_HEADER_BYTES;
        let modulo = body_len % record_size as usize;
        if modulo != 0 {
            let needed = record_size as usize - modulo;
            blob.extend(std::iter::repeat_n(0u8, needed));
        }
    }

    #[test]
    fn parse_returns_none_for_empty_input() {
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn parse_returns_none_for_truncated_header() {
        let blob = vec![0u8; REGF_BASE_HEADER_BYTES - 1];
        assert!(parse(&blob).is_none());
    }

    #[test]
    fn parse_returns_none_when_regf_magic_missing() {
        let mut blob = vec![0u8; REGF_BASE_HEADER_BYTES];
        blob[0..4].copy_from_slice(b"XXXX");
        assert!(parse(&blob).is_none());
    }

    #[test]
    fn parse_returns_none_for_primary_hive_not_log() {
        // Valid regf magic but file_type = 0 (primary hive, not log).
        let mut blob = vec![0u8; REGF_BASE_HEADER_BYTES];
        blob[0..4].copy_from_slice(&REGF_SIGNATURE.to_le_bytes());
        blob[0x1C..0x1C + 4].copy_from_slice(&0u32.to_le_bytes()); // primary
        assert!(parse(&blob).is_none());
    }

    #[test]
    fn parse_decodes_header_with_zero_dirty_pages() {
        // The regf file_name slot is 64 bytes (32 UTF-16 chars); use a
        // name that fits without truncation.
        let blob = build_log_header(42, r"SYSTEM-LOG");
        let h = parse(&blob).expect("must parse");
        assert_eq!(h.log_sequence_number, 42);
        assert_eq!(h.dirty_page_count, 0);
        assert_eq!(h.hive_name, "SYSTEM-LOG");
        assert!(!has_uncommitted_changes(&h));
    }

    #[test]
    fn parse_sums_dirty_pages_across_hvle_entries() {
        let mut blob = build_log_header(7, "SOFTWARE");
        append_hvle(&mut blob, 1, 3);
        append_hvle(&mut blob, 2, 5);
        append_hvle(&mut blob, 3, 11);
        let h = parse(&blob).expect("must parse");
        assert_eq!(h.log_sequence_number, 7);
        assert_eq!(h.dirty_page_count, 19);
        assert_eq!(h.hive_name, "SOFTWARE");
        assert!(has_uncommitted_changes(&h));
    }

    #[test]
    fn parse_stops_at_corrupt_hvle_record_size() {
        let mut blob = build_log_header(1, "NTUSER.DAT");
        append_hvle(&mut blob, 1, 4);
        // Append a junk HvLE with record_size < 20 — walker must bail.
        blob.extend_from_slice(&HVLE_SIGNATURE.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes()); // record_size = 0
        let h = parse(&blob).expect("must parse");
        assert_eq!(h.dirty_page_count, 4);
    }

    #[test]
    fn parse_stops_when_post_header_lacks_hvle_magic() {
        // Body fills with non-HvLE bytes — count_dirty_pages should
        // return 0 immediately.
        let mut blob = build_log_header(1, "SAM");
        blob.extend_from_slice(&[0xAB; 256]);
        let h = parse(&blob).expect("must parse");
        assert_eq!(h.dirty_page_count, 0);
    }

    #[test]
    fn has_uncommitted_changes_threshold_at_one() {
        let zero = RegTxLogHeader {
            log_sequence_number: 0,
            dirty_page_count: 0,
            hive_name: "x".into(),
        };
        let one = RegTxLogHeader {
            log_sequence_number: 0,
            dirty_page_count: 1,
            hive_name: "x".into(),
        };
        assert!(!has_uncommitted_changes(&zero));
        assert!(has_uncommitted_changes(&one));
    }
}
