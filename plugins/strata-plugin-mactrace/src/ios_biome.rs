//! iOS Biome parser — extends [`crate::biome`] with iOS-specific streams.
//!
//! iOS uses the same SEGB + protobuf container as macOS Biome (Sprint
//! M-1), so we reuse `crate::biome::parse` to decode the outer
//! container and then re-interpret the fields for iOS-only streams:
//!
//! | Path fragment                       | Meaning                                      |
//! |-------------------------------------|----------------------------------------------|
//! | `streams/photos/assetAdded`         | Photo captured — `asset_id` (str field 1)    |
//! | `streams/messaging/sent`            | iMessage sent — `recipient` (str field 1)    |
//! | `streams/location/significant`      | Location — lat (f64 f1), lon (f64 f2)        |
//!
//! We also pass through the macOS streams (`app/inFocus`,
//! `device/locked`, `safariHistory`, `appSession`) because iOS emits
//! them too.
//!
//! ## MITRE ATT&CK
//! * **T1430** — Location tracking (significant-location stream).
//! * **T1636.002** — SMS/iMessage enumeration.
//! * **T1217** — Safari history discovery.
//!
//! Location decoding: iOS encodes latitude and longitude as IEEE-754
//! f64 in fixed64 slots (wire type 1). We read the raw 8 bytes and
//! reinterpret as f64 via `f64::from_le_bytes`.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::path::Path;

use crate::biome::{decode_apple_timestamp, read_varint};

/// iOS-recognised stream categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IosBiomeStream {
    /// `streams/photos/assetAdded`.
    PhotoAssetAdded,
    /// `streams/messaging/sent`.
    MessagingSent,
    /// `streams/location/significant`.
    LocationSignificant,
    /// Shared macOS streams (`app/inFocus`, `device/locked`, Safari,
    /// `appSession`) — decoded via [`crate::biome`] where possible but
    /// re-emitted here so the iOS entry-point produces a single record
    /// type.
    Shared,
    /// Any other iOS stream we don't have a typed schema for.
    Unknown,
}

impl IosBiomeStream {
    pub fn as_str(&self) -> &'static str {
        match self {
            IosBiomeStream::PhotoAssetAdded => "photos/assetAdded",
            IosBiomeStream::MessagingSent => "messaging/sent",
            IosBiomeStream::LocationSignificant => "location/significant",
            IosBiomeStream::Shared => "shared",
            IosBiomeStream::Unknown => "unknown",
        }
    }

    pub fn from_path(path: &Path) -> IosBiomeStream {
        let lower = path.to_string_lossy().to_ascii_lowercase();
        if lower.contains("photos/assetadded") {
            IosBiomeStream::PhotoAssetAdded
        } else if lower.contains("messaging/sent") {
            IosBiomeStream::MessagingSent
        } else if lower.contains("location/significant") {
            IosBiomeStream::LocationSignificant
        } else if lower.contains("app/infocus")
            || lower.contains("device/locked")
            || lower.contains("safarihistory")
            || lower.contains("appsession")
        {
            IosBiomeStream::Shared
        } else {
            IosBiomeStream::Unknown
        }
    }

    pub fn mitre(&self) -> &'static str {
        match self {
            IosBiomeStream::LocationSignificant => "T1430",
            IosBiomeStream::MessagingSent => "T1636.002",
            IosBiomeStream::PhotoAssetAdded => "T1005",
            IosBiomeStream::Shared => "T1217",
            IosBiomeStream::Unknown => "T1005",
        }
    }

    pub fn forensic_value(&self) -> &'static str {
        match self {
            IosBiomeStream::LocationSignificant | IosBiomeStream::MessagingSent => "High",
            _ => "Medium",
        }
    }
}

/// One iOS Biome record.
#[derive(Debug, Clone, PartialEq)]
pub struct IosBiomeRecord {
    pub stream_type: IosBiomeStream,
    pub start_time: Option<DateTime<Utc>>,
    pub bundle_id: Option<String>,
    pub url: Option<String>,
    pub title: Option<String>,
    pub locked: Option<bool>,
    pub duration_secs: Option<i64>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub photo_asset_id: Option<String>,
    pub message_recipient: Option<String>,
}

impl IosBiomeRecord {
    fn new(stream_type: IosBiomeStream) -> Self {
        Self {
            stream_type,
            start_time: None,
            bundle_id: None,
            url: None,
            title: None,
            locked: None,
            duration_secs: None,
            latitude: None,
            longitude: None,
            photo_asset_id: None,
            message_recipient: None,
        }
    }
}

/// SEGB file magic bytes at offset 0.
const SEGB_MAGIC: &[u8; 8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30];
const MAX_RECORDS: usize = 100_000;
const MAX_RECORD_BYTES: u32 = 10 * 1024 * 1024;

/// Parse an iOS Biome SEGB file. Empty vec on wrong magic / truncated.
pub fn parse(path: &Path, bytes: &[u8]) -> Vec<IosBiomeRecord> {
    let mut out = Vec::new();
    if bytes.len() < SEGB_MAGIC.len() || &bytes[..SEGB_MAGIC.len()] != SEGB_MAGIC {
        return out;
    }
    let stream = IosBiomeStream::from_path(path);
    let mut offset = SEGB_MAGIC.len();
    while offset + 8 <= bytes.len() && out.len() < MAX_RECORDS {
        let Some(record_size) = read_u32_le(bytes, offset) else {
            break;
        };
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
        if let Some(record) = decode_ios_record(stream, payload) {
            out.push(record);
        }
        let padding = (8 - (record_size as usize % 8)) % 8;
        let next = payload_end.saturating_add(padding);
        if next <= offset {
            break;
        }
        offset = next;
    }
    out
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off.checked_add(4)?)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

fn decode_ios_record(stream: IosBiomeStream, payload: &[u8]) -> Option<IosBiomeRecord> {
    let mut rec = IosBiomeRecord::new(stream);
    let mut any = false;
    let mut pos = 0usize;
    while pos < payload.len() {
        let (tag, vlen) = read_varint(payload, pos)?;
        pos += vlen;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        let consumed = match wire_type {
            0 => {
                let (_value, vlen) = read_varint(payload, pos)?;
                vlen
            }
            1 => {
                if pos + 8 > payload.len() {
                    break;
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&payload[pos..pos + 8]);
                apply_fixed64(&mut rec, stream, field_number, arr);
                any = true;
                8
            }
            2 => {
                let (len, llen) = read_varint(payload, pos)?;
                let start = pos + llen;
                let end = start.saturating_add(len as usize);
                if end > payload.len() {
                    break;
                }
                apply_length_delimited(&mut rec, stream, field_number, &payload[start..end]);
                any = true;
                llen + (len as usize)
            }
            5 => {
                if pos + 4 > payload.len() {
                    break;
                }
                4
            }
            _ => break,
        };
        pos = pos.saturating_add(consumed);
    }
    if any {
        Some(rec)
    } else {
        None
    }
}

fn apply_fixed64(rec: &mut IosBiomeRecord, stream: IosBiomeStream, field: u32, bytes: [u8; 8]) {
    match (stream, field) {
        (IosBiomeStream::LocationSignificant, 1) => {
            rec.latitude = Some(f64::from_le_bytes(bytes));
        }
        (IosBiomeStream::LocationSignificant, 2) => {
            rec.longitude = Some(f64::from_le_bytes(bytes));
        }
        (_, 3) => {
            rec.start_time = decode_apple_timestamp(bytes);
        }
        _ => {}
    }
}

fn apply_length_delimited(
    rec: &mut IosBiomeRecord,
    stream: IosBiomeStream,
    field: u32,
    bytes: &[u8],
) {
    match (stream, field) {
        (IosBiomeStream::PhotoAssetAdded, 1) => {
            if let Ok(s) = std::str::from_utf8(bytes) {
                rec.photo_asset_id = Some(s.to_string());
            }
        }
        (IosBiomeStream::MessagingSent, 1) => {
            if let Ok(s) = std::str::from_utf8(bytes) {
                rec.message_recipient = Some(s.to_string());
            }
        }
        (IosBiomeStream::Shared, 1) => {
            if let Ok(s) = std::str::from_utf8(bytes) {
                // Shared streams typically carry bundle_id (app/inFocus,
                // appSession) or URL (safariHistory) in field 1.
                if s.starts_with("http") {
                    rec.url = Some(s.to_string());
                } else {
                    rec.bundle_id = Some(s.to_string());
                }
            }
        }
        _ => {}
    }
}

/// True when `path` looks like an iOS Biome container — contains
/// `mobile/Library/Biome` or `var/db/biome` (case-insensitive).
pub fn is_ios_biome_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.contains("mobile/library/biome") || lower.contains("var/db/biome")
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                b |= 0x80;
                out.push(b);
            } else {
                out.push(b);
                return;
            }
        }
    }

    fn tag(field: u32, wire: u8, out: &mut Vec<u8>) {
        encode_varint(((field << 3) | wire as u32) as u64, out);
    }

    fn string_field(field: u32, s: &str, out: &mut Vec<u8>) {
        tag(field, 2, out);
        encode_varint(s.len() as u64, out);
        out.extend_from_slice(s.as_bytes());
    }

    fn fixed64_field(field: u32, bytes: [u8; 8], out: &mut Vec<u8>) {
        tag(field, 1, out);
        out.extend_from_slice(&bytes);
    }

    fn wrap(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SEGB_MAGIC);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(payload);
        let pad = (8 - (payload.len() % 8)) % 8;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    #[test]
    fn parse_empty_on_wrong_magic() {
        assert!(parse(Path::new("/x/photos/assetAdded/1"), &[0xFFu8; 32]).is_empty());
    }

    #[test]
    fn parse_photo_asset_added() {
        let mut p = Vec::new();
        string_field(1, "ASSET-UUID-1", &mut p);
        fixed64_field(3, 738_936_000.0_f64.to_le_bytes(), &mut p);
        let blob = wrap(&p);
        let recs = parse(
            Path::new("/private/var/mobile/Library/Biome/streams/photos/assetAdded/1"),
            &blob,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].stream_type, IosBiomeStream::PhotoAssetAdded);
        assert_eq!(recs[0].photo_asset_id.as_deref(), Some("ASSET-UUID-1"));
        assert_eq!(
            recs[0].start_time.map(|d| d.timestamp()),
            Some(1_717_243_200)
        );
    }

    #[test]
    fn parse_messaging_sent() {
        let mut p = Vec::new();
        string_field(1, "+15551234567", &mut p);
        fixed64_field(3, 738_936_000.0_f64.to_le_bytes(), &mut p);
        let blob = wrap(&p);
        let recs = parse(
            Path::new("/private/var/mobile/Library/Biome/streams/messaging/sent/1"),
            &blob,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].stream_type, IosBiomeStream::MessagingSent);
        assert_eq!(recs[0].message_recipient.as_deref(), Some("+15551234567"));
    }

    #[test]
    fn parse_location_significant() {
        let mut p = Vec::new();
        fixed64_field(1, 37.7749_f64.to_le_bytes(), &mut p);
        fixed64_field(2, (-122.4194_f64).to_le_bytes(), &mut p);
        fixed64_field(3, 738_936_000.0_f64.to_le_bytes(), &mut p);
        let blob = wrap(&p);
        let recs = parse(
            Path::new("/private/var/mobile/Library/Biome/streams/location/significant/1"),
            &blob,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].stream_type, IosBiomeStream::LocationSignificant);
        let lat = recs[0].latitude.expect("lat");
        let lon = recs[0].longitude.expect("lon");
        assert!((lat - 37.7749).abs() < 1e-6);
        assert!((lon - -122.4194).abs() < 1e-6);
    }

    #[test]
    fn stream_mitre_and_severity() {
        assert_eq!(IosBiomeStream::LocationSignificant.mitre(), "T1430");
        assert_eq!(IosBiomeStream::MessagingSent.mitre(), "T1636.002");
        assert_eq!(IosBiomeStream::Shared.mitre(), "T1217");
        assert_eq!(IosBiomeStream::LocationSignificant.forensic_value(), "High");
    }

    #[test]
    fn is_ios_biome_path_recognises_expected_prefixes() {
        assert!(is_ios_biome_path(Path::new(
            "/private/var/mobile/Library/Biome/streams/photos/assetAdded/1"
        )));
        assert!(is_ios_biome_path(Path::new(
            "/private/var/db/biome/streams/location/significant/1"
        )));
        assert!(!is_ios_biome_path(Path::new("/Users/a/Library/Biome/")));
    }
}
