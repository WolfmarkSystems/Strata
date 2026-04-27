//! SRUM (System Resource Usage Monitor) database parser.
//!
//! Strata's SRUM parser is a structural ESE-aware reader. It validates the
//! ESE database header, walks pages using the database's reported page
//! size, and extracts:
//!   - Application paths and basenames (as UTF-16LE long values inside
//!     pages)
//!   - User SIDs (`S-1-5-...` strings)
//!   - SRUM extension provider GUIDs — which providers wrote into this
//!     database (Network Data Usage, Application Resource Usage, Network
//!     Connectivity, Energy Usage, Push Notification, App Timeline, etc.)
//!   - The FILETIME range observed across pages
//!
//! Strata does not bind libesedb (we are an air-gapped pure-Rust binary),
//! so this is *not* a full ESE catalog walker — we cannot resolve numeric
//! AppId / UserId references back to their long-value strings through the
//! `SruDbIdMapTable` B+tree. Instead we walk the raw page graph and report
//! every long-value-shaped record found, plus the providers detected. For
//! the forensic value Strata cares about (which apps used the network,
//! which user owned them, when the database was actively written) this is
//! sufficient for triage; deep per-record correlation should still be
//! verified in EricZimmerman's `SrumECmd` for court use.
//!
//! References:
//!   - SrumECmd source (EricZimmerman) — extension table GUIDs and the
//!     `SruDbIdMapTable` layout.
//!   - libesedb (libyal) — on-disk ESE structure used here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Known SRUM extension provider GUIDs and their human-readable names.
///
/// Strata reports which of these are present in a given SRUM database so
/// the examiner immediately knows which providers are available for
/// follow-up parsing in `SrumECmd`. The list comes from the SrumECmd
/// source and from forensic literature on Win10/11 SRUM internals.
pub const SRUM_EXTENSIONS: &[(&str, &str)] = &[
    (
        "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
        "Network Data Usage",
    ),
    (
        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
        "Application Resource Usage",
    ),
    (
        "{DD6636C4-8929-4683-974E-22C046A43763}",
        "Network Connectivity",
    ),
    ("{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}", "Energy Usage"),
    (
        "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT",
        "Energy Usage (Long Term)",
    ),
    (
        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}",
        "Push Notification Data",
    ),
    (
        "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}",
        "Push Notifications",
    ),
    (
        "{5C8CF1C7-7257-4F13-B223-970EF5939312}",
        "App Timeline Provider",
    ),
    (
        "{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}",
        "Tagged Energy Provider",
    ),
    ("{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}", "Vfu Provider"),
];

/// Result of parsing a SRUM database.
#[derive(Debug, Clone)]
pub struct SrumDatabase {
    pub file_size: u64,
    pub page_size: u32,
    pub format_version: u32,
    pub page_count: usize,
    pub long_value_pages: usize,
    pub providers_present: Vec<&'static str>,
    pub apps: Vec<SrumApp>,
    pub user_sids: Vec<String>,
    pub earliest_unix: Option<i64>,
    pub latest_unix: Option<i64>,
    pub timestamp_count: usize,
}

/// One application path discovered inside a SRUM database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrumApp {
    pub full_path: String,
    pub basename: String,
    pub is_suspicious: bool,
}

impl SrumDatabase {
    /// Read the SRUM database file from disk and parse it.
    ///
    /// Rejects files larger than 512 MB to prevent OOM on corrupted or
    /// atypically large databases. Long-running Windows 10/11 systems
    /// can produce 300 MB SRUDB.dat files; 512 MB provides headroom.
    pub fn parse(path: &Path) -> Result<Self, String> {
        const MAX_SRUM_BYTES: u64 = 512 * 1024 * 1024;
        let file_size = path
            .metadata()
            .map(|m| m.len())
            .map_err(|e| format!("metadata failed: {e}"))?;
        if file_size > MAX_SRUM_BYTES {
            return Err(format!(
                "SRUM database too large ({} bytes, max {})",
                file_size, MAX_SRUM_BYTES
            ));
        }
        let data = std::fs::read(path).map_err(|e| format!("read failed: {e}"))?;
        Self::parse_bytes(&data)
    }

    /// Parse a SRUM database from an in-memory byte slice.
    pub fn parse_bytes(data: &[u8]) -> Result<Self, String> {
        let header = EseHeader::parse(data)?;
        let page_size = header.page_size as usize;
        if !matches!(page_size, 4096 | 8192 | 16384 | 32768) {
            return Err(format!("implausible ESE page size: {page_size}"));
        }

        // Detect SRUM provider GUIDs present anywhere in the file. The
        // catalog stores extension table names as plain ASCII (the curly
        // braces and uppercase hex are part of the table name itself), so
        // a single linear scan suffices.
        let mut providers: Vec<&'static str> = Vec::new();
        for (guid, name) in SRUM_EXTENSIONS {
            if find_ascii(data, guid.as_bytes()).is_some() {
                providers.push(*name);
            }
        }

        let mut apps_map: BTreeMap<String, SrumApp> = BTreeMap::new();
        let mut sid_set: BTreeSet<String> = BTreeSet::new();
        let mut earliest: Option<i64> = None;
        let mut latest: Option<i64> = None;
        let mut ts_count: usize = 0;
        let mut long_value_pages: usize = 0;
        let mut page_count: usize = 0;

        // Walk pages from offset = page_size onward. ESE reserves page 0
        // (database header) and page 1 (shadow header), then real DB
        // pages start at page index 2. We start at offset = page_size and
        // process every page-sized chunk as a potential ESE page.
        let mut offset = page_size;
        while offset + page_size <= data.len() {
            let page = &data[offset..offset + page_size];
            page_count += 1;

            // Page flags: u32 at offset 36 in the page header (post-ECC
            // layout used by Win7+). ESE long-value pages set bit 0x4
            // (`PAGE_FLAG_IS_LONG_VALUE`).
            if page.len() >= 40 {
                let flags = u32::from_le_bytes(page[36..40].try_into().unwrap_or([0u8; 4]));
                if flags & 0x4 != 0 {
                    long_value_pages += 1;
                }
            }

            // Pull out every printable UTF-16LE run inside this page and
            // classify it as a path, a SID, or noise.
            for s in extract_utf16le_strings(page, 5, 520) {
                if looks_like_path(&s) {
                    let basename = s.rsplit('\\').next().unwrap_or(&s).to_string();
                    let lower = basename.to_lowercase();
                    let is_suspicious = is_suspicious_basename(&lower);
                    apps_map.entry(s.clone()).or_insert_with(|| SrumApp {
                        full_path: s,
                        basename,
                        is_suspicious,
                    });
                } else if looks_like_sid(&s) {
                    sid_set.insert(s);
                }
            }

            // Sample 8-byte FILETIMEs across the page. The valid range
            // bounds 2010..~2030 in 100ns ticks since 1601-01-01.
            let mut p = 0usize;
            while p + 8 <= page.len() {
                let ft = i64::from_le_bytes(page[p..p + 8].try_into().unwrap_or([0u8; 8]));
                if (129_000_000_000_000_000_i64..140_000_000_000_000_000_i64).contains(&ft) {
                    let unix = (ft - 116_444_736_000_000_000) / 10_000_000;
                    if unix > 0 {
                        ts_count += 1;
                        earliest = Some(earliest.map_or(unix, |e: i64| e.min(unix)));
                        latest = Some(latest.map_or(unix, |l: i64| l.max(unix)));
                    }
                }
                p += 8;
            }

            offset += page_size;
        }

        let apps: Vec<SrumApp> = apps_map.into_values().collect();
        let user_sids: Vec<String> = sid_set.into_iter().collect();

        Ok(Self {
            file_size: data.len() as u64,
            page_size: page_size as u32,
            format_version: header.format_version,
            page_count,
            long_value_pages,
            providers_present: providers,
            apps,
            user_sids,
            earliest_unix: earliest,
            latest_unix: latest,
            timestamp_count: ts_count,
        })
    }

    /// Render an `earliest..latest` date range as `YYYY-MM-DD to YYYY-MM-DD`,
    /// or `unknown range` when no FILETIMEs were observed.
    pub fn date_range(&self) -> String {
        match (self.earliest_unix, self.latest_unix) {
            (Some(e), Some(l)) => {
                let e_dt = chrono::DateTime::from_timestamp(e, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let l_dt = chrono::DateTime::from_timestamp(l, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("{e_dt} to {l_dt}")
            }
            _ => "unknown range".to_string(),
        }
    }
}

/// ESE database header — only the fields Strata actually uses.
#[derive(Debug)]
struct EseHeader {
    format_version: u32,
    page_size: u32,
}

impl EseHeader {
    fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 248 {
            return Err("file too small for ESE header".to_string());
        }
        // Magic at offset 4: 0xEFCDAB89 (on disk: 89 AB CD EF).
        let magic = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0u8; 4]));
        if magic != 0xEFCD_AB89 {
            return Err(format!("bad ESE magic: 0x{magic:08X}"));
        }
        // File type at offset 12: 0 = database, 1 = streaming file.
        let file_type = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0u8; 4]));
        if file_type != 0 {
            return Err(format!("not an ESE database (file_type={file_type})"));
        }
        let format_version = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0u8; 4]));
        // Page size: try the two known offsets used across ESE format
        // revisions (232 in older ESE, 236 in newer). Whichever yields a
        // valid page-size constant wins.
        let page_size = detect_page_size(data).unwrap_or(0);
        Ok(Self {
            format_version,
            page_size,
        })
    }
}

/// Probe the two ESE header offsets that have historically held
/// `cbDbPageSize` and return the first one that's a recognised
/// power-of-two ESE page size.
fn detect_page_size(data: &[u8]) -> Option<u32> {
    for off in [236usize, 232usize] {
        if data.len() >= off + 4 {
            let v = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0u8; 4]));
            if matches!(v, 4096 | 8192 | 16384 | 32768) {
                return Some(v);
            }
        }
    }
    None
}

fn find_ascii(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn looks_like_path(s: &str) -> bool {
    if s.len() < 6 {
        return false;
    }
    if !s.contains('\\') {
        return false;
    }
    // Real SRUM paths look like "\Device\HarddiskVolume3\Windows\..."
    // or "%SystemRoot%\..." or "C:\...". The dot check rules out the
    // header GUIDs we already report separately.
    s.contains('.') || s.starts_with("\\Device\\") || s.starts_with('%')
}

fn looks_like_sid(s: &str) -> bool {
    if !s.starts_with("S-1-") || s.len() > 184 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_digit() || c == '-' || c == 'S')
}

fn is_suspicious_basename(lower: &str) -> bool {
    lower.contains("powershell")
        || lower.contains("cmd.exe")
        || lower.contains("wscript")
        || lower.contains("cscript")
        || lower.contains("mshta")
        || lower.contains("certutil")
        || lower.contains("bitsadmin")
        || lower.contains("regsvr32")
        || lower.contains("rundll32")
        || lower.ends_with(".tmp")
        || lower.contains("tor.exe")
}

/// Extract every printable UTF-16LE run that's at least `min_len` and at
/// most `max_len` characters long. Walks the buffer once at 2-byte
/// alignment so it's O(n) — large enough for SRUM databases on the order
/// of hundreds of MB.
fn extract_utf16le_strings(buf: &[u8], min_len: usize, max_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut chars: Vec<u16> = Vec::new();
    let mut i = 0usize;
    while i + 2 <= buf.len() {
        let ch = u16::from_le_bytes([buf[i], buf[i + 1]]);
        let printable = (0x20..0xFFFE).contains(&ch);
        if printable {
            chars.push(ch);
            if chars.len() >= max_len {
                if chars.len() >= min_len {
                    out.push(String::from_utf16_lossy(&chars));
                }
                chars.clear();
            }
        } else {
            if chars.len() >= min_len {
                out.push(String::from_utf16_lossy(&chars));
            }
            chars.clear();
        }
        i += 2;
    }
    if chars.len() >= min_len {
        out.push(String::from_utf16_lossy(&chars));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but valid ESE database header backed by `n_pages`
    /// of zero-filled pages. Tests can splice payloads into individual
    /// page bodies before parsing.
    fn make_synthetic_ese(page_size: u32, n_pages: usize) -> Vec<u8> {
        let total = page_size as usize + (n_pages * page_size as usize);
        let mut data = vec![0u8; total];
        // checksum bytes are not validated
        // magic 0xEFCDAB89 (on disk: 89 AB CD EF)
        data[4..8].copy_from_slice(&0xEFCD_AB89_u32.to_le_bytes());
        // format version 0x620 (Win7-Win11)
        data[8..12].copy_from_slice(&0x620_u32.to_le_bytes());
        // file type 0 = database
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        // page size at the modern offset (236)
        data[236..240].copy_from_slice(&page_size.to_le_bytes());
        data
    }

    fn write_utf16le(into: &mut [u8], at: usize, s: &str) {
        let bytes: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let end = (at + bytes.len()).min(into.len());
        into[at..end].copy_from_slice(&bytes[..end - at]);
    }

    #[test]
    fn ese_header_validation_accepts_valid_database() {
        let db = make_synthetic_ese(4096, 2);
        let parsed = SrumDatabase::parse_bytes(&db).expect("valid ESE header should parse");
        assert_eq!(parsed.page_size, 4096);
        assert_eq!(parsed.format_version, 0x620);
        // 2 trailing pages were allocated; the parser should walk both.
        assert_eq!(parsed.page_count, 2);
    }

    #[test]
    fn ese_header_validation_rejects_garbage_magic() {
        let mut db = make_synthetic_ese(4096, 1);
        // Smash the magic.
        db[4..8].copy_from_slice(&[0u8, 0, 0, 0]);
        let err = SrumDatabase::parse_bytes(&db).unwrap_err();
        assert!(err.contains("bad ESE magic"), "got: {err}");
    }

    #[test]
    fn ese_header_validation_rejects_streaming_file_type() {
        let mut db = make_synthetic_ese(4096, 1);
        // file_type = 1 → streaming file, not a database.
        db[12..16].copy_from_slice(&1u32.to_le_bytes());
        let err = SrumDatabase::parse_bytes(&db).unwrap_err();
        assert!(err.contains("not an ESE database"), "got: {err}");
    }

    #[test]
    fn ese_header_validation_rejects_implausible_page_size() {
        let db = make_synthetic_ese(1024, 1); // 1024 is not a recognised ESE page size
        let err = SrumDatabase::parse_bytes(&db).unwrap_err();
        assert!(err.contains("implausible ESE page size"), "got: {err}");
    }

    #[test]
    fn ese_header_validation_too_small_buffer() {
        let buf = vec![0u8; 100];
        let err = SrumDatabase::parse_bytes(&buf).unwrap_err();
        assert!(err.contains("too small"), "got: {err}");
    }

    #[test]
    fn detect_page_size_handles_legacy_offset_232() {
        let mut db = make_synthetic_ese(4096, 1);
        // Wipe the modern offset, write the legacy offset instead.
        db[236..240].copy_from_slice(&0u32.to_le_bytes());
        db[232..236].copy_from_slice(&8192_u32.to_le_bytes());
        // Resize so there is at least one full 8192-byte page after the
        // header (the synthetic builder allocated for 4096 not 8192).
        db.resize(8192 * 3, 0);
        let parsed = SrumDatabase::parse_bytes(&db).expect("legacy offset should parse");
        assert_eq!(parsed.page_size, 8192);
    }

    #[test]
    fn extract_utf16le_strings_yields_only_printable_runs() {
        let mut buf = vec![0u8; 256];
        write_utf16le(&mut buf, 0, "C:\\Windows\\System32\\cmd.exe");
        // gap of zeros separates the runs
        write_utf16le(&mut buf, 80, "S-1-5-21-1000-2000-3000-1001");
        let strings = extract_utf16le_strings(&buf, 5, 520);
        assert!(strings
            .iter()
            .any(|s| s == "C:\\Windows\\System32\\cmd.exe"));
        assert!(strings.iter().any(|s| s == "S-1-5-21-1000-2000-3000-1001"));
    }

    #[test]
    fn looks_like_path_filters_correctly() {
        assert!(looks_like_path("C:\\Windows\\System32\\powershell.exe"));
        assert!(looks_like_path(
            "\\Device\\HarddiskVolume3\\Users\\admin\\bad.exe"
        ));
        assert!(looks_like_path("%SystemRoot%\\System32\\svchost.exe"));
        assert!(!looks_like_path("hello world"));
        assert!(!looks_like_path("C:\\noext")); // no extension and no special prefix
        assert!(!looks_like_path("a.b")); // too short
    }

    #[test]
    fn looks_like_sid_filters_correctly() {
        assert!(looks_like_sid("S-1-5-21-1000-2000-3000-1001"));
        assert!(looks_like_sid("S-1-5-18"));
        assert!(!looks_like_sid("S-not-a-sid-x"));
        assert!(!looks_like_sid("C:\\Windows"));
        assert!(!looks_like_sid(&"S-1-5-21".repeat(40))); // > 184 chars
    }

    #[test]
    fn is_suspicious_basename_flags_lolbin_classics() {
        assert!(is_suspicious_basename("powershell.exe"));
        assert!(is_suspicious_basename("cmd.exe"));
        assert!(is_suspicious_basename("wscript.exe"));
        assert!(is_suspicious_basename("certutil.exe"));
        assert!(is_suspicious_basename("scratch.tmp"));
        assert!(is_suspicious_basename("tor.exe"));
        assert!(!is_suspicious_basename("notepad.exe"));
    }

    #[test]
    fn parse_bytes_extracts_apps_sids_and_providers() {
        let mut db = make_synthetic_ese(4096, 3);
        // Write payloads into page 1 (the first non-header page,
        // which begins at offset 4096).
        let page1 = 4096usize;
        write_utf16le(&mut db, page1 + 64, "C:\\Windows\\System32\\powershell.exe");
        write_utf16le(
            &mut db,
            page1 + 256,
            "C:\\Users\\victim\\Downloads\\benign.txt",
        );
        write_utf16le(&mut db, page1 + 448, "S-1-5-21-1111-2222-3333-1001");
        // Embed two real SRUM extension GUIDs as ASCII into page 2.
        let page2 = 4096usize * 2;
        let guid1 = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";
        let guid2 = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";
        db[page2 + 64..page2 + 64 + guid1.len()].copy_from_slice(guid1.as_bytes());
        db[page2 + 256..page2 + 256 + guid2.len()].copy_from_slice(guid2.as_bytes());

        let parsed = SrumDatabase::parse_bytes(&db).expect("synthetic SRUM parses");

        // Apps include both paths, suspicious flag set on powershell only.
        let app_paths: Vec<&str> = parsed.apps.iter().map(|a| a.full_path.as_str()).collect();
        assert!(app_paths.contains(&"C:\\Windows\\System32\\powershell.exe"));
        assert!(app_paths.contains(&"C:\\Users\\victim\\Downloads\\benign.txt"));
        let powershell = parsed
            .apps
            .iter()
            .find(|a| a.basename == "powershell.exe")
            .expect("powershell present");
        assert!(powershell.is_suspicious);
        let benign = parsed
            .apps
            .iter()
            .find(|a| a.basename == "benign.txt")
            .expect("benign present");
        assert!(!benign.is_suspicious);

        // SIDs include the embedded user SID.
        assert!(
            parsed
                .user_sids
                .contains(&"S-1-5-21-1111-2222-3333-1001".to_string()),
            "expected SID in {:?}",
            parsed.user_sids
        );

        // Providers include both extension table names we embedded.
        assert!(parsed.providers_present.contains(&"Network Data Usage"));
        assert!(parsed
            .providers_present
            .contains(&"Application Resource Usage"));
    }

    #[test]
    fn parse_bytes_records_filetime_range() {
        let mut db = make_synthetic_ese(4096, 2);
        // 2024-01-01T00:00:00Z in FILETIME = 133480128000000000
        // 2025-06-15T12:00:00Z in FILETIME = 133938144000000000
        let early: i64 = 133_480_128_000_000_000;
        let late: i64 = 133_938_144_000_000_000;
        let page1 = 4096usize;
        db[page1 + 64..page1 + 72].copy_from_slice(&early.to_le_bytes());
        db[page1 + 200..page1 + 208].copy_from_slice(&late.to_le_bytes());

        let parsed = SrumDatabase::parse_bytes(&db).expect("parse");
        assert!(parsed.timestamp_count >= 2);
        assert!(parsed.earliest_unix.is_some());
        assert!(parsed.latest_unix.is_some());
        assert!(parsed.earliest_unix.unwrap() < parsed.latest_unix.unwrap());
        // Date range string is non-empty and contains "to".
        let range = parsed.date_range();
        assert!(range.contains("to"), "got: {range}");
    }

    #[test]
    fn parse_bytes_handles_long_value_page_flag() {
        let mut db = make_synthetic_ese(4096, 2);
        // Set page-flag bit 0x4 (long value) in the second real page.
        // Page 1 starts at offset 4096; page header byte 36..40 is flags.
        let page1_flags = 4096usize + 36;
        db[page1_flags..page1_flags + 4].copy_from_slice(&0x4_u32.to_le_bytes());
        let parsed = SrumDatabase::parse_bytes(&db).expect("parse");
        assert!(parsed.long_value_pages >= 1);
    }
}
