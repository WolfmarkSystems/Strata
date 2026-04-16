//! Apple Biome parser — macOS 13+ (Ventura / Sonoma / Sequoia).
//!
//! Apple Biome replaced KnowledgeC as the primary user-activity store
//! on macOS 13+. Biome streams live at `/private/var/db/biome/` (system)
//! and `~/Library/Biome/` (per-user) and cover essentially every
//! interesting user-activity signal the OS emits: foreground app focus,
//! app sessions, lock/unlock events, Safari history, notifications,
//! location hints, device-usage telemetry.
//!
//! ## SEGB file format
//!
//! Biome stores records in **SEGB** (Segmented Binary) files:
//!
//! ```text
//! offset 0x00  u8[8]  file magic = 00 00 00 00 00 00 00 30
//! per record:
//!   u32 LE  record_size      (size of the protobuf payload)
//!   u32 LE  flags
//!   u8[record_size]  protobuf payload
//!   padding to 8-byte alignment
//! ```
//!
//! Records that declare `record_size == 0` terminate the walk.
//!
//! ## Protobuf payload
//!
//! Each record is a minimal protobuf message. We decode wire types 0
//! (varint), 1 (64-bit fixed), and 2 (length-delimited) — the only
//! ones the stream schemas use. **No `prost` dependency**; the varint
//! + field walker is implemented inline.
//!
//! Per stream (selected by path):
//!
//! | Path fragment | Field | Wire type | Meaning |
//! |---|---|---|---|
//! | `streams/app/inFocus`  | 1 | string  | bundle_id |
//! | `streams/app/inFocus`  | 3 | fixed64 | start_time (Apple epoch) |
//! | `streams/app/inFocus`  | 4 | fixed64 | end_time (Apple epoch) |
//! | `streams/device/locked`| 1 | varint  | locked (bool) |
//! | `streams/device/locked`| 3 | fixed64 | timestamp (Apple epoch) |
//! | `streams/safariHistory`| 1 | string  | url |
//! | `streams/safariHistory`| 2 | string  | title |
//! | `streams/safariHistory`| 3 | fixed64 | timestamp (Apple epoch) |
//! | `streams/appSession`   | 1 | string  | bundle_id |
//! | `streams/appSession`   | 2 | varint  | duration_secs |
//!
//! ## Apple (CoreData) epoch
//!
//! Biome timestamps are seconds since `2001-01-01 00:00:00 UTC` (the
//! CoreData / Mach absolute-time epoch), typically encoded as IEEE 754
//! `f64` in the fixed64 slot. We try `f64` first and fall back to a
//! raw `u64` seconds interpretation if the decoded double is not a
//! finite plausible timestamp.
//!
//! ## MITRE ATT&CK
//! * **T1059** (Command and Scripting Interpreter) — app-focus /
//!   session records are the canonical macOS post-execution signal
//!   when Prefetch/AmCache aren't available.
//! * **T1217** (Browser Information Discovery) — Safari history
//!   entries.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::path::Path;

/// SEGB file magic bytes at offset 0.
const SEGB_MAGIC: &[u8; 8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30];
/// CoreData / Mach absolute-time epoch offset from Unix epoch
/// (2001-01-01 00:00:00 UTC expressed as Unix seconds).
const APPLE_EPOCH_OFFSET: i64 = 978_307_200;
/// Hard cap on records per file to keep runaway parses bounded.
const MAX_RECORDS: usize = 100_000;
/// Hard cap on a single record's protobuf payload (10 MB).
const MAX_RECORD_BYTES: u32 = 10 * 1024 * 1024;

/// Which Biome stream a record came from, inferred from the path of
/// the SEGB file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiomeStreamType {
    /// `streams/app/inFocus` — foreground app focus transitions.
    AppInFocus,
    /// `streams/device/locked` — screen-lock / unlock events.
    DeviceLocked,
    /// `streams/safariHistory` — Safari visit records.
    SafariHistory,
    /// `streams/appSession` — app session duration records.
    AppSession,
    /// Any other Biome stream we don't have a typed schema for yet.
    /// Records still emit but carry no decoded typed fields.
    Unknown,
}

impl BiomeStreamType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BiomeStreamType::AppInFocus => "app/inFocus",
            BiomeStreamType::DeviceLocked => "device/locked",
            BiomeStreamType::SafariHistory => "safariHistory",
            BiomeStreamType::AppSession => "appSession",
            BiomeStreamType::Unknown => "unknown",
        }
    }

    /// Infer the stream type from a Biome SEGB file path. Case-
    /// insensitive match against known path fragments.
    pub fn from_path(path: &Path) -> BiomeStreamType {
        let lower = path.to_string_lossy().to_ascii_lowercase();
        // Most specific matches first.
        if lower.contains("streams/app/infocus") || lower.contains("app/infocus") {
            BiomeStreamType::AppInFocus
        } else if lower.contains("streams/device/locked") || lower.contains("device/locked") {
            BiomeStreamType::DeviceLocked
        } else if lower.contains("safarihistory") {
            BiomeStreamType::SafariHistory
        } else if lower.contains("appsession") {
            BiomeStreamType::AppSession
        } else {
            BiomeStreamType::Unknown
        }
    }
}

/// One typed Biome record.
///
/// Fields are forensic-meaning-first — the enum variant in
/// `stream_type` determines which of the `Option` fields carry data.
#[derive(Debug, Clone, PartialEq)]
pub struct BiomeRecord {
    /// Which Biome stream produced this record. Drives how consumers
    /// (the UI, Sigma rules) should interpret the remaining fields.
    pub stream_type: BiomeStreamType,

    /// macOS bundle identifier (e.g. `"com.apple.Safari"`). Present
    /// for [`BiomeStreamType::AppInFocus`] and
    /// [`BiomeStreamType::AppSession`] records; `None` otherwise. For
    /// AppSession this is the app whose usage was measured.
    pub bundle_id: Option<String>,

    /// URL visited, for [`BiomeStreamType::SafariHistory`] records.
    /// Equivalent to the `visits.url` column in `History.db` but
    /// sourced from the live activity stream — may include entries
    /// that were privately browsed and never written to the regular
    /// history database.
    pub url: Option<String>,

    /// Page title for Safari history entries. Often missing (empty
    /// string in the proto) for pages that hadn't finished loading.
    pub title: Option<String>,

    /// Start of an AppInFocus window. Also carries the timestamp for
    /// DeviceLocked and SafariHistory records (whose schema uses
    /// field 3 for the single event time).
    pub start_time: Option<DateTime<Utc>>,

    /// End of an AppInFocus window. `None` for other streams and for
    /// in-progress focus sessions that hadn't yet emitted their
    /// end-of-focus record.
    pub end_time: Option<DateTime<Utc>>,

    /// Screen-lock state for [`BiomeStreamType::DeviceLocked`]
    /// records: `Some(true)` = screen just locked, `Some(false)` =
    /// screen just unlocked.
    pub locked: Option<bool>,

    /// Session duration in seconds for [`BiomeStreamType::AppSession`]
    /// records.
    pub duration_secs: Option<i64>,
}

impl BiomeRecord {
    fn new(stream_type: BiomeStreamType) -> Self {
        Self {
            stream_type,
            bundle_id: None,
            url: None,
            title: None,
            start_time: None,
            end_time: None,
            locked: None,
            duration_secs: None,
        }
    }
}

/// Parse an entire Biome SEGB file. Returns every typed record found.
/// Empty vector on magic mismatch, truncated file, or unknown stream
/// with no decodable content. Never panics.
pub fn parse(path: &Path, bytes: &[u8]) -> Vec<BiomeRecord> {
    let mut out = Vec::new();
    if bytes.len() < SEGB_MAGIC.len() || &bytes[..SEGB_MAGIC.len()] != SEGB_MAGIC {
        return out;
    }
    let stream_type = BiomeStreamType::from_path(path);
    let mut offset = SEGB_MAGIC.len();
    while offset + 8 <= bytes.len() && out.len() < MAX_RECORDS {
        let record_size = match read_u32_le(bytes, offset) {
            Some(s) => s,
            None => break,
        };
        let _flags = read_u32_le(bytes, offset + 4).unwrap_or(0);
        offset += 8;
        if record_size == 0 {
            break;
        }
        if record_size > MAX_RECORD_BYTES {
            break;
        }
        let payload_end = offset.saturating_add(record_size as usize);
        if payload_end > bytes.len() {
            break;
        }
        let payload = &bytes[offset..payload_end];
        if let Some(record) = decode_record(stream_type, payload) {
            out.push(record);
        }
        // Advance past payload + padding to next 8-byte boundary.
        let padding = (8 - (record_size as usize % 8)) % 8;
        let next = payload_end.saturating_add(padding);
        if next <= offset {
            break;
        }
        offset = next;
    }
    out
}

/// Decode one protobuf payload into a [`BiomeRecord`] using the
/// schema inferred from `stream_type`. Returns `None` when nothing
/// typed could be extracted.
pub(crate) fn decode_record(stream_type: BiomeStreamType, payload: &[u8]) -> Option<BiomeRecord> {
    let mut rec = BiomeRecord::new(stream_type);
    let mut any_field = false;
    let mut pos = 0usize;
    while pos < payload.len() {
        let (tag, varint_len) = match read_varint(payload, pos) {
            Some(v) => v,
            None => break,
        };
        pos += varint_len;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        let consumed = match wire_type {
            0 => {
                // varint
                let (value, vlen) = match read_varint(payload, pos) {
                    Some(v) => v,
                    None => break,
                };
                apply_varint(&mut rec, stream_type, field_number, value);
                any_field = true;
                vlen
            }
            1 => {
                // 64-bit fixed
                if pos + 8 > payload.len() {
                    break;
                }
                let Ok(arr) = <[u8; 8]>::try_from(&payload[pos..pos + 8]) else {
                    break;
                };
                apply_fixed64(&mut rec, stream_type, field_number, arr);
                any_field = true;
                8
            }
            2 => {
                // length-delimited
                let (len, llen) = match read_varint(payload, pos) {
                    Some(v) => v,
                    None => break,
                };
                let start = pos + llen;
                let end = start.saturating_add(len as usize);
                if end > payload.len() {
                    break;
                }
                let bytes = &payload[start..end];
                apply_length_delimited(&mut rec, stream_type, field_number, bytes);
                any_field = true;
                llen + (len as usize)
            }
            5 => {
                // 32-bit fixed — not used by our schemas; skip.
                if pos + 4 > payload.len() {
                    break;
                }
                4
            }
            _ => break,
        };
        pos = pos.saturating_add(consumed);
    }
    if any_field {
        Some(rec)
    } else {
        None
    }
}

fn apply_varint(
    rec: &mut BiomeRecord,
    stream_type: BiomeStreamType,
    field_number: u32,
    value: u64,
) {
    match (stream_type, field_number) {
        (BiomeStreamType::DeviceLocked, 1) => {
            rec.locked = Some(value != 0);
        }
        (BiomeStreamType::AppSession, 2) => {
            rec.duration_secs = Some(value as i64);
        }
        _ => {}
    }
}

fn apply_fixed64(
    rec: &mut BiomeRecord,
    stream_type: BiomeStreamType,
    field_number: u32,
    bytes: [u8; 8],
) {
    let ts = decode_apple_timestamp(bytes);
    match (stream_type, field_number) {
        (BiomeStreamType::AppInFocus, 3) => rec.start_time = ts,
        (BiomeStreamType::AppInFocus, 4) => rec.end_time = ts,
        (BiomeStreamType::DeviceLocked, 3) | (BiomeStreamType::SafariHistory, 3) => {
            rec.start_time = ts;
        }
        _ => {}
    }
}

fn apply_length_delimited(
    rec: &mut BiomeRecord,
    stream_type: BiomeStreamType,
    field_number: u32,
    bytes: &[u8],
) {
    match (stream_type, field_number) {
        (BiomeStreamType::AppInFocus, 1) | (BiomeStreamType::AppSession, 1) => {
            if let Ok(s) = std::str::from_utf8(bytes) {
                rec.bundle_id = Some(s.to_string());
            }
        }
        (BiomeStreamType::SafariHistory, 1) => {
            if let Ok(s) = std::str::from_utf8(bytes) {
                rec.url = Some(s.to_string());
            }
        }
        (BiomeStreamType::SafariHistory, 2) => {
            if let Ok(s) = std::str::from_utf8(bytes) {
                rec.title = Some(s.to_string());
            }
        }
        _ => {}
    }
}

/// Decode an Apple Biome timestamp from 8 raw fixed64 bytes.
/// Tries IEEE 754 `f64` (the common encoding) first and falls back
/// to raw `u64` seconds if the double is not a finite, plausible
/// timestamp.
pub(crate) fn decode_apple_timestamp(bytes: [u8; 8]) -> Option<DateTime<Utc>> {
    // All-zero bytes are the uninitialized-slot marker; never a real
    // timestamp. Return None without attempting to decode.
    if bytes == [0; 8] {
        return None;
    }
    let as_f64 = f64::from_le_bytes(bytes);
    if as_f64.is_finite() {
        // Plausible Biome range: 1999-01-01 (Apple epoch -2y) through
        // 2100-01-01 (~Apple epoch +99y). Use the u64 seconds fallback
        // for values outside this window.
        if (-63_115_200.0..3_124_137_600.0).contains(&as_f64) {
            let secs = as_f64.floor() as i64;
            let nanos = ((as_f64 - as_f64.floor()) * 1_000_000_000.0) as u32;
            return DateTime::<Utc>::from_timestamp(secs.saturating_add(APPLE_EPOCH_OFFSET), nanos);
        }
    }
    let as_u64 = u64::from_le_bytes(bytes);
    if as_u64 == 0 || as_u64 > i64::MAX as u64 {
        return None;
    }
    DateTime::<Utc>::from_timestamp((as_u64 as i64).saturating_add(APPLE_EPOCH_OFFSET), 0)
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off.checked_add(4)?)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

/// Read one protobuf varint starting at `pos`. Returns
/// `(value, bytes_consumed)` or `None` on truncated / overflowed
/// input. Supports up to 10 continuation bytes (the u64 limit).
pub(crate) fn read_varint(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut consumed: usize = 0;
    while consumed < 10 {
        let byte = *buf.get(pos + consumed)?;
        consumed += 1;
        let chunk = u64::from(byte & 0x7F);
        result |= chunk.checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some((result, consumed));
        }
        shift = shift.checked_add(7)?;
    }
    None
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
                out.push(byte);
            } else {
                out.push(byte);
                return;
            }
        }
    }

    fn encode_tag(field: u32, wire: u8, out: &mut Vec<u8>) {
        let tag = ((field << 3) | (wire as u32)) as u64;
        encode_varint(tag, out);
    }

    fn encode_string_field(field: u32, s: &str, out: &mut Vec<u8>) {
        encode_tag(field, 2, out); // wire type 2 (length-delimited)
        encode_varint(s.len() as u64, out);
        out.extend_from_slice(s.as_bytes());
    }

    fn encode_fixed64_field(field: u32, bytes: [u8; 8], out: &mut Vec<u8>) {
        encode_tag(field, 1, out);
        out.extend_from_slice(&bytes);
    }

    fn encode_varint_field(field: u32, value: u64, out: &mut Vec<u8>) {
        encode_tag(field, 0, out);
        encode_varint(value, out);
    }

    fn wrap_in_segb(payload: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(SEGB_MAGIC);
        let size = payload.len() as u32;
        out.extend_from_slice(&size.to_le_bytes()); // record_size
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(payload);
        // 8-byte padding.
        let padding = (8 - (payload.len() % 8)) % 8;
        out.extend(std::iter::repeat_n(0u8, padding));
        out
    }

    fn apple_ts_f64(apple_secs: f64) -> [u8; 8] {
        apple_secs.to_le_bytes()
    }

    #[test]
    fn parse_returns_empty_on_wrong_magic() {
        let blob = vec![0xFFu8; 32];
        let records = parse(Path::new("/biome/streams/app/inFocus/1"), &blob);
        assert!(records.is_empty());
    }

    #[test]
    fn parse_returns_empty_on_truncated_header() {
        let blob: Vec<u8> = vec![0x00; 4];
        let records = parse(Path::new("/biome/streams/app/inFocus/1"), &blob);
        assert!(records.is_empty());
    }

    #[test]
    fn parse_decodes_app_in_focus_record() {
        // 2024-06-01 12:00:00 UTC = Unix 1_717_243_200
        // Apple epoch seconds = 1_717_243_200 - 978_307_200 = 738_936_000
        let start = apple_ts_f64(738_936_000.0);
        let end = apple_ts_f64(738_936_060.0);

        let mut payload: Vec<u8> = Vec::new();
        encode_string_field(1, "com.apple.Safari", &mut payload);
        encode_fixed64_field(3, start, &mut payload);
        encode_fixed64_field(4, end, &mut payload);

        let blob = wrap_in_segb(&payload);
        let records = parse(Path::new("/biome/streams/app/inFocus/1"), &blob);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.stream_type, BiomeStreamType::AppInFocus);
        assert_eq!(r.bundle_id.as_deref(), Some("com.apple.Safari"));
        let start_ts = r.start_time.expect("start_time decoded");
        assert_eq!(start_ts.timestamp(), 1_717_243_200);
        let end_ts = r.end_time.expect("end_time decoded");
        assert_eq!(end_ts.timestamp(), 1_717_243_260);
    }

    #[test]
    fn parse_decodes_device_locked_record() {
        let ts = apple_ts_f64(738_936_000.0);
        let mut payload: Vec<u8> = Vec::new();
        encode_varint_field(1, 1, &mut payload); // locked = true
        encode_fixed64_field(3, ts, &mut payload);
        let blob = wrap_in_segb(&payload);
        let records = parse(Path::new("/biome/streams/device/locked/1"), &blob);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].stream_type, BiomeStreamType::DeviceLocked);
        assert_eq!(records[0].locked, Some(true));
        assert!(records[0].start_time.is_some());
    }

    #[test]
    fn parse_decodes_safari_history_record() {
        let ts = apple_ts_f64(738_936_000.0);
        let mut payload: Vec<u8> = Vec::new();
        encode_string_field(1, "https://example.com/", &mut payload);
        encode_string_field(2, "Example Domain", &mut payload);
        encode_fixed64_field(3, ts, &mut payload);
        let blob = wrap_in_segb(&payload);
        let records = parse(Path::new("/Library/Biome/streams/safariHistory/1"), &blob);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].stream_type, BiomeStreamType::SafariHistory);
        assert_eq!(records[0].url.as_deref(), Some("https://example.com/"));
        assert_eq!(records[0].title.as_deref(), Some("Example Domain"));
    }

    #[test]
    fn parse_decodes_app_session_duration() {
        let mut payload: Vec<u8> = Vec::new();
        encode_string_field(1, "com.apple.Terminal", &mut payload);
        encode_varint_field(2, 3600, &mut payload); // 1 hour
        let blob = wrap_in_segb(&payload);
        let records = parse(Path::new("/biome/streams/appSession/x"), &blob);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].stream_type, BiomeStreamType::AppSession);
        assert_eq!(records[0].bundle_id.as_deref(), Some("com.apple.Terminal"));
        assert_eq!(records[0].duration_secs, Some(3600));
    }

    #[test]
    fn parse_stops_on_zero_record_size_terminator() {
        let mut payload: Vec<u8> = Vec::new();
        encode_string_field(1, "com.apple.TextEdit", &mut payload);
        let mut blob = wrap_in_segb(&payload);
        // Append a zero-size terminator record header.
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        // Plus some junk that must NOT be parsed.
        blob.extend_from_slice(b"ignored");
        let records = parse(Path::new("/biome/streams/appSession/1"), &blob);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn stream_type_from_path_matches_known_fragments() {
        assert_eq!(
            BiomeStreamType::from_path(Path::new("/biome/streams/app/inFocus/1")),
            BiomeStreamType::AppInFocus
        );
        assert_eq!(
            BiomeStreamType::from_path(Path::new("/biome/streams/device/locked/x")),
            BiomeStreamType::DeviceLocked
        );
        assert_eq!(
            BiomeStreamType::from_path(Path::new("/Library/Biome/streams/safariHistory/a")),
            BiomeStreamType::SafariHistory
        );
        assert_eq!(
            BiomeStreamType::from_path(Path::new("/biome/streams/appSession/y")),
            BiomeStreamType::AppSession
        );
        assert_eq!(
            BiomeStreamType::from_path(Path::new("/biome/streams/something-else")),
            BiomeStreamType::Unknown
        );
    }

    #[test]
    fn read_varint_rejects_truncated_or_overflowed_input() {
        // Truncated: first byte has continuation bit but no follow-up.
        let buf = [0x80u8];
        assert!(read_varint(&buf, 0).is_none());
        // >10 continuation bytes → overflow guard.
        let buf = vec![0x80u8; 12];
        assert!(read_varint(&buf, 0).is_none());
        // Normal one-byte varint.
        assert_eq!(read_varint(&[0x05], 0), Some((5, 1)));
        // Two-byte varint 300 = 0xAC 0x02.
        assert_eq!(read_varint(&[0xAC, 0x02], 0), Some((300, 2)));
    }

    #[test]
    fn decode_apple_timestamp_handles_zero_and_nonfinite() {
        assert!(decode_apple_timestamp([0; 8]).is_none());
        // NaN pattern should not panic — either yields None or a
        // fallback u64 value; contract is "no panic".
        let nan_bytes = f64::NAN.to_le_bytes();
        let _ = decode_apple_timestamp(nan_bytes);
    }
}
