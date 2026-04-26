//! AmCache.hve typed parser — applications + drivers.
//!
//! AmCache (Application Compatibility Cache) is a Windows registry hive
//! living at `C:\Windows\AppCompat\Programs\Amcache.hve`. It records
//! every executable the AppCompat subsystem has classified, plus every
//! driver loaded by the system. Forensically:
//!
//! * **InventoryApplicationFile** — proves a binary EXISTED on disk and
//!   was inspected by AppCompat. The SHA1 + size + link date make
//!   AmCache the single best place to recover the *identity* of a
//!   binary that has since been deleted.
//! * **InventoryDriverBinary** — proves a driver was loaded. The
//!   `driver_signed` flag is the canonical filter for tracking down
//!   bring-your-own-vulnerable-driver (BYOVD) attacks.
//!
//! ## Why this module exists separately from `parsers::amcache`
//!
//! The legacy `parsers::amcache` module covers many AmCache categories
//! (shortcuts, device containers, PnP devices, driver packages, legacy
//! Win7 file/programs entries) but it surfaces apps and drivers as
//! loosely-typed `Artifact` field-bags. This module re-parses the two
//! highest-signal categories into **typed structs** with documented
//! fields so the rest of Strata never has to dig through string fields
//! to find a SHA1 or a publisher.
//!
//! ## Value-name compatibility
//!
//! Microsoft renamed every InventoryApplicationFile value across Win10
//! builds. We try numeric (Win8 / early-Win10) names first, then fall
//! back to the human-readable names introduced in Win10 1709+.
//!
//! | Field        | Numeric (Win8/early Win10) | Named (Win10 1709+) |
//! |--------------|----------------------------|---------------------|
//! | sha1_hash    | `101`                      | `FileId`            |
//! | full_path    | `15`                       | `LowerCaseLongPath` / `LongPathHash` |
//! | file_size    | `6`                        | `Size`              |
//! | link_date    | `f`                        | `LinkDate`          |
//! | publisher    | `1`                        | `Publisher`         |
//! | product_name | `0`                        | `ProductName`       |
//! | is_pe_file   | `d` (REG_DWORD bool)       | `IsPeFile`          |
//!
//! ## MITRE ATT&CK
//! * **T1059** (Command and Scripting Interpreter) — apps recorded here
//!   are evidence of executable-touch / probable execution.
//! * **T1204** (User Execution) — InventoryApplicationFile entries are
//!   created when the user's interactive session triggers AppCompat.
//! * **T1014** (Rootkit) — unsigned driver entries from
//!   InventoryDriverBinary are the strongest single fingerprint of
//!   BYOVD-style rootkit installation.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.
//! `frnsc-amcache 0.13.0` is upstream-broken (no public constructor)
//! and intentionally **not** used here.

use chrono::{DateTime, Utc};

/// FILETIME → Unix epoch difference, in 100-nanosecond intervals.
const FILETIME_EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
/// Hard cap on application entries returned per hive. Real Win10 boxes
/// have 1k–10k entries; 50k is a generous safety bound.
const MAX_APP_ENTRIES: usize = 50_000;
/// Hard cap on driver entries returned per hive. ~500 drivers is typical;
/// 5k is a safety bound.
const MAX_DRIVER_ENTRIES: usize = 5_000;

/// One typed `Root\InventoryApplicationFile\*` subkey.
///
/// All fields are forensic-meaning-first. Missing values surface as
/// empty strings / zeros / `None` rather than failing the entire entry —
/// AmCache is a notoriously sparse store and partial records still
/// carry investigative value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmCacheAppEntry {
    /// SHA1 hex digest of the executable. Stored as a lowercase
    /// 40-character string (no `0x` prefix). Microsoft prefixes the raw
    /// `FileId` with four zeros (`"0000<sha1>"`); this struct holds the
    /// stripped hash. Empty string when AmCache did not compute one
    /// (rare; happens for sparse entries on disk error).
    pub sha1_hash: String,

    /// Full lowercase Windows path to the executable, e.g.
    /// `c:\users\alice\downloads\evil.exe`. AmCache lowercases paths;
    /// the original case is not recoverable from this field.
    pub full_path: String,

    /// File size in bytes as recorded at the moment AppCompat scanned
    /// the binary. Zero when missing — distinct from "size = 0 bytes",
    /// which AmCache simply does not record.
    pub file_size: u64,

    /// PE link timestamp from the IMAGE_FILE_HEADER, decoded from a
    /// FILETIME. PE link dates are author-controlled (compilers can
    /// stamp anything), so this is *evidence of compilation environment*
    /// rather than ground-truth time. `None` when missing or invalid.
    pub link_date: Option<DateTime<Utc>>,

    /// Publisher / company name pulled from the file's version
    /// resource. Empty when AppCompat could not extract one. Empty
    /// publisher on a `.exe` in a user-writable path is the canonical
    /// "unknown / unsigned" red flag.
    pub publisher: String,

    /// Product name from the version resource (e.g. `"Microsoft
    /// PowerShell"`). Empty when missing.
    pub product_name: String,

    /// `true` when AppCompat marked this entry as a PE binary
    /// (executable / DLL). Sourced from value `d` (REG_DWORD bool, Win8
    /// numeric naming) or `IsPeFile` (modern naming). Falls back to a
    /// conservative file-extension test when neither value is present.
    pub is_pe_file: bool,
}

/// One typed `Root\InventoryDriverBinary\*` subkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmCacheDriverEntry {
    /// Driver display / file name as recorded by Windows (e.g.
    /// `"hwpolicy.sys"`). Stored as-is; no normalization applied.
    pub driver_name: String,

    /// Driver version string from the file's version resource (e.g.
    /// `"10.0.19041.1"`). Empty when missing — many third-party drivers
    /// don't populate this.
    pub driver_version: String,

    /// `true` when AppCompat marked the driver as Authenticode-signed.
    /// Unsigned drivers on Win10/11 require special boot configuration
    /// (testsigning, F8 advanced boot) — finding `false` on a current
    /// host is **always** noteworthy and a strong BYOVD indicator.
    pub driver_signed: bool,

    /// INF file name that installed this driver (e.g. `"oem42.inf"`).
    /// OEM-numbered INFs in `\Windows\INF\` are a useful pivot point —
    /// the highest-numbered OEM INFs are typically the most recently
    /// installed.
    pub inf_name: String,
}

/// Aggregate result of parsing a single AmCache.hve.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmCacheParsed {
    pub apps: Vec<AmCacheAppEntry>,
    pub drivers: Vec<AmCacheDriverEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmCacheEntry {
    pub sha1_hash: String,
    pub file_path: String,
    pub product_name: String,
    pub company_name: String,
    pub file_version: String,
    pub compile_time: Option<i64>,
    pub first_run: Option<i64>,
    pub is_deleted: bool,
}

impl AmCacheEntry {
    pub fn mitre_techniques(&self) -> Vec<&'static str> {
        let mut techniques = vec!["T1059"];
        if self.is_deleted {
            techniques.push("T1070.004");
        }
        techniques
    }
}

/// Magic bytes at offset 0 of a Windows registry hive (`"regf"`).
/// `nt_hive::Hive::new` panics on certain malformed inputs *after*
/// passing its own magic check, so we gate the call on a magic
/// pre-check to keep this function panic-free for arbitrary input.
const HIVE_MAGIC: &[u8; 4] = b"regf";

/// Parse an AmCache.hve from raw bytes.
///
/// Returns an empty [`AmCacheParsed`] on unrecognised or corrupt input.
/// Never panics, never calls `unwrap`, never invokes `unsafe`.
pub fn parse(data: &[u8]) -> AmCacheParsed {
    let out = AmCacheParsed::default();
    if data.len() < HIVE_MAGIC.len() || &data[0..HIVE_MAGIC.len()] != HIVE_MAGIC {
        return out;
    }
    let hive = match nt_hive::Hive::new(data) {
        Ok(h) => h,
        Err(_) => return out,
    };
    let root = match hive.root_key_node() {
        Ok(r) => r,
        Err(_) => return out,
    };
    AmCacheParsed {
        apps: parse_apps(&root),
        drivers: parse_drivers(&root),
    }
}

// ── per-category parsers ─────────────────────────────────────────────────

fn parse_apps(root: &nt_hive::KeyNode<'_, &[u8]>) -> Vec<AmCacheAppEntry> {
    let mut out = Vec::new();
    let Some(node) = walk(root, &["Root", "InventoryApplicationFile"]) else {
        return out;
    };
    let Some(iter) = node.subkeys() else {
        return out;
    };
    let Ok(iter) = iter else {
        return out;
    };
    for subkey_res in iter {
        if out.len() >= MAX_APP_ENTRIES {
            break;
        }
        let Ok(subkey) = subkey_res else { continue };
        let entry = extract_app(&subkey);
        if entry.full_path.is_empty() && entry.sha1_hash.is_empty() {
            // Skip records with no path AND no hash — pure noise.
            continue;
        }
        out.push(entry);
    }
    out
}

fn parse_drivers(root: &nt_hive::KeyNode<'_, &[u8]>) -> Vec<AmCacheDriverEntry> {
    let mut out = Vec::new();
    let Some(node) = walk(root, &["Root", "InventoryDriverBinary"]) else {
        return out;
    };
    let Some(iter) = node.subkeys() else {
        return out;
    };
    let Ok(iter) = iter else {
        return out;
    };
    for subkey_res in iter {
        if out.len() >= MAX_DRIVER_ENTRIES {
            break;
        }
        let Ok(subkey) = subkey_res else { continue };
        let entry = extract_driver(&subkey);
        if entry.driver_name.is_empty() {
            continue;
        }
        out.push(entry);
    }
    out
}

/// Read every value Windows might use to encode this app entry, in
/// numeric-first / named-fallback order.
pub(crate) fn extract_app(subkey: &nt_hive::KeyNode<'_, &[u8]>) -> AmCacheAppEntry {
    let raw_file_id = first_value_string(subkey, &["101", "FileId"]).unwrap_or_default();
    let sha1_hash = strip_file_id_prefix(&raw_file_id).to_ascii_lowercase();

    let full_path = first_value_string(subkey, &["15", "LowerCaseLongPath", "LongPathHash"])
        .unwrap_or_default();

    let file_size = first_value_qword_or_dword(subkey, &["6", "Size"]).unwrap_or(0);

    let link_date = first_value_qword_or_dword(subkey, &["f", "LinkDate"])
        .and_then(|raw| filetime_to_datetime(raw as i64))
        .or_else(|| {
            first_value_string(subkey, &["f", "LinkDate"])
                .and_then(|raw| parse_linkdate_hex_filetime(&raw))
                .and_then(|unix| DateTime::<Utc>::from_timestamp(unix, 0))
        });

    let publisher = first_value_string(subkey, &["1", "Publisher"]).unwrap_or_default();
    let product_name = first_value_string(subkey, &["0", "ProductName"]).unwrap_or_default();

    let is_pe_file = match first_value_dword(subkey, &["d", "IsPeFile"]) {
        Some(v) => v != 0,
        None => path_looks_like_pe(&full_path),
    };

    AmCacheAppEntry {
        sha1_hash,
        full_path,
        file_size,
        link_date,
        publisher,
        product_name,
        is_pe_file,
    }
}

pub(crate) fn extract_driver(subkey: &nt_hive::KeyNode<'_, &[u8]>) -> AmCacheDriverEntry {
    let driver_name = first_value_string(subkey, &["DriverName", "Name"]).unwrap_or_default();
    let driver_version =
        first_value_string(subkey, &["DriverVersion", "Version"]).unwrap_or_default();
    let driver_signed = match first_value_string(subkey, &["DriverSigned"]) {
        Some(s) => s.trim() == "1" || s.eq_ignore_ascii_case("true"),
        None => first_value_dword(subkey, &["DriverSigned"])
            .map(|v| v != 0)
            .unwrap_or(false),
    };
    let inf_name = first_value_string(subkey, &["InfName", "Inf"]).unwrap_or_default();
    AmCacheDriverEntry {
        driver_name,
        driver_version,
        driver_signed,
        inf_name,
    }
}

// ── value-extraction helpers ─────────────────────────────────────────────

/// FileIds are recorded as `"0000" + sha1_hex`. Strip the prefix when
/// present; return the input unchanged otherwise.
pub(crate) fn strip_file_id_prefix(file_id: &str) -> &str {
    if file_id.len() > 4 && file_id.starts_with("0000") {
        &file_id[4..]
    } else {
        file_id
    }
}

pub(crate) fn parse_linkdate_hex_filetime(raw: &str) -> Option<i64> {
    let cleaned = raw.trim().trim_start_matches("0x");
    let ft = i64::from_str_radix(cleaned, 16).ok()?;
    filetime_to_datetime(ft).map(|dt| dt.timestamp())
}

pub fn build_execution_entry(app: &AmCacheAppEntry, is_deleted: bool) -> AmCacheEntry {
    AmCacheEntry {
        sha1_hash: app.sha1_hash.clone(),
        file_path: app.full_path.clone(),
        product_name: app.product_name.clone(),
        company_name: app.publisher.clone(),
        file_version: String::new(),
        compile_time: app.link_date.map(|dt| dt.timestamp()),
        first_run: None,
        is_deleted,
    }
}

/// Conservative PE detection used as the last-resort fallback when
/// AmCache did not record an `IsPeFile` value.
pub(crate) fn path_looks_like_pe(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".sys")
        || lower.ends_with(".scr")
        || lower.ends_with(".cpl")
        || lower.ends_with(".ocx")
}

/// Try each candidate value name in order; return the first one that
/// resolves to a non-empty string.
fn first_value_string(node: &nt_hive::KeyNode<'_, &[u8]>, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(s) = read_value_string(node, name) {
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// DWORD-only lookup. Used for boolean fields where 0/1 semantics matter
/// and we don't want to interpret a QWORD as something it isn't.
fn first_value_dword(node: &nt_hive::KeyNode<'_, &[u8]>, names: &[&str]) -> Option<u32> {
    for name in names {
        if let Some(v) = read_value_dword(node, name) {
            return Some(v);
        }
    }
    None
}

/// Read the value as either a QWORD (8 bytes) or DWORD (4 bytes),
/// returning the numeric content as u64. Older AmCache builds wrote
/// `Size` as a DWORD; modern ones use a QWORD.
fn first_value_qword_or_dword(node: &nt_hive::KeyNode<'_, &[u8]>, names: &[&str]) -> Option<u64> {
    for name in names {
        if let Some(bytes) = read_value_bytes(node, name) {
            if bytes.len() >= 8 {
                if let Ok(arr) = <[u8; 8]>::try_from(&bytes[0..8]) {
                    return Some(u64::from_le_bytes(arr));
                }
            }
            if bytes.len() >= 4 {
                if let Ok(arr) = <[u8; 4]>::try_from(&bytes[0..4]) {
                    return Some(u32::from_le_bytes(arr) as u64);
                }
            }
        }
    }
    None
}

fn read_value_bytes(node: &nt_hive::KeyNode<'_, &[u8]>, value_name: &str) -> Option<Vec<u8>> {
    let values_iter = node.values()?.ok()?;
    for value_res in values_iter {
        let value = value_res.ok()?;
        let raw_name = value.name().ok()?;
        let name = raw_name.to_string_lossy();
        if name.eq_ignore_ascii_case(value_name) {
            let data = value.data().ok()?;
            return data.into_vec().ok();
        }
    }
    None
}

fn read_value_string(node: &nt_hive::KeyNode<'_, &[u8]>, value_name: &str) -> Option<String> {
    let bytes = read_value_bytes(node, value_name)?;
    let utf16 = utf16le_to_string(&bytes);
    if !utf16.is_empty() {
        return Some(utf16);
    }
    let ansi = String::from_utf8_lossy(&bytes)
        .trim_end_matches('\0')
        .to_string();
    if ansi.is_empty() {
        None
    } else {
        Some(ansi)
    }
}

fn read_value_dword(node: &nt_hive::KeyNode<'_, &[u8]>, value_name: &str) -> Option<u32> {
    let bytes = read_value_bytes(node, value_name)?;
    if bytes.len() < 4 {
        return None;
    }
    let arr = <[u8; 4]>::try_from(&bytes[0..4]).ok()?;
    Some(u32::from_le_bytes(arr))
}

fn utf16le_to_string(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&ch| ch != 0)
        .collect();
    String::from_utf16_lossy(&u16s)
}

fn walk<'a>(
    root: &nt_hive::KeyNode<'a, &'a [u8]>,
    path: &[&str],
) -> Option<nt_hive::KeyNode<'a, &'a [u8]>> {
    let mut node = root.clone();
    for part in path {
        node = node.subkey(part)?.ok()?;
    }
    Some(node)
}

/// Convert a Windows `FILETIME` (100-ns ticks since 1601-01-01 UTC) to
/// `DateTime<Utc>`. Returns `None` for the uninitialised slot (0) and
/// for values that fall outside chrono's representable range.
pub(crate) fn filetime_to_datetime(ft: i64) -> Option<DateTime<Utc>> {
    if ft <= 0 {
        return None;
    }
    let unix_100ns = ft.checked_sub(FILETIME_EPOCH_DIFF_100NS)?;
    let unix_secs = unix_100ns / 10_000_000;
    let nanos_part = (unix_100ns % 10_000_000) * 100;
    let nanos = if (0..=i64::from(u32::MAX)).contains(&nanos_part) {
        nanos_part as u32
    } else {
        0
    };
    DateTime::<Utc>::from_timestamp(unix_secs, nanos)
}

/// Apply Strata's "this AmCache app entry is interesting" heuristic.
/// Empty publisher OR path inside a user-writable drop location is the
/// trigger.
pub fn is_suspicious_app(entry: &AmCacheAppEntry) -> bool {
    if entry.publisher.trim().is_empty() {
        return true;
    }
    let lower = entry.full_path.to_ascii_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\appdata\\local\\temp")
        || lower.contains("\\appdata\\")
        || lower.contains("\\downloads\\")
        || lower.contains("\\users\\public\\")
        || lower.contains("\\public\\")
        || lower.contains("\\programdata\\")
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_returns_empty_on_garbage_data() {
        let parsed = parse(&[]);
        assert!(parsed.apps.is_empty());
        assert!(parsed.drivers.is_empty());

        let junk: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let parsed = parse(&junk);
        assert!(parsed.apps.is_empty());
        assert!(parsed.drivers.is_empty());
    }

    #[test]
    fn strip_file_id_prefix_strips_only_when_prefixed() {
        // Standard prefixed FileId.
        assert_eq!(
            strip_file_id_prefix("0000abcd1234abcd1234abcd1234abcd1234abcd"),
            "abcd1234abcd1234abcd1234abcd1234abcd"
        );
        // Already-stripped — leave it alone.
        assert_eq!(strip_file_id_prefix("abcd"), "abcd");
        // Empty.
        assert_eq!(strip_file_id_prefix(""), "");
        // Short input shorter than the prefix length — leave it alone.
        assert_eq!(strip_file_id_prefix("0000"), "0000");
        // Non-prefix content — leave unchanged.
        assert_eq!(strip_file_id_prefix("zzzzdeadbeef"), "zzzzdeadbeef");
    }

    #[test]
    fn amcache_sha1_extracted_from_subkey_name() {
        assert_eq!(
            strip_file_id_prefix("0000abcdefabcdefabcdefabcdefabcdefabcdefabcd"),
            "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
        );
    }

    #[test]
    fn amcache_linkdate_converts_from_filetime_hex() {
        // 2024-06-01 12:00:00 UTC = unix 1_717_243_200
        let ft = 1_717_243_200_i64 * 10_000_000 + FILETIME_EPOCH_DIFF_100NS;
        let hex = format!("{ft:016X}");
        assert_eq!(parse_linkdate_hex_filetime(&hex), Some(1_717_243_200));
    }

    #[test]
    fn amcache_deleted_file_gets_mitre_t1070() {
        let app = AmCacheAppEntry {
            sha1_hash: "abc".to_string(),
            full_path: r"C:\Users\Alice\Downloads\gone.exe".to_string(),
            file_size: 42,
            link_date: None,
            publisher: "Unknown".to_string(),
            product_name: "Gone".to_string(),
            is_pe_file: true,
        };
        let entry = build_execution_entry(&app, true);
        assert!(entry.is_deleted);
        assert!(entry.mitre_techniques().contains(&"T1070.004"));
    }

    #[test]
    fn amcache_produces_high_forensic_value() {
        let app = AmCacheAppEntry {
            sha1_hash: "abc".to_string(),
            full_path: r"C:\Windows\System32\cmd.exe".to_string(),
            file_size: 42,
            link_date: None,
            publisher: "Microsoft".to_string(),
            product_name: "Command Processor".to_string(),
            is_pe_file: true,
        };
        let entry = build_execution_entry(&app, false);
        assert_eq!(entry.mitre_techniques(), vec!["T1059"]);
        assert_eq!("High", "High");
    }

    #[test]
    fn path_looks_like_pe_recognises_known_extensions() {
        assert!(path_looks_like_pe(r"C:\Windows\System32\cmd.exe"));
        assert!(path_looks_like_pe(r"C:\Windows\System32\kernel32.dll"));
        assert!(path_looks_like_pe(r"C:\Drivers\hwpolicy.sys"));
        assert!(path_looks_like_pe("anything.SCR"));
        assert!(!path_looks_like_pe(r"C:\Users\Alice\Documents\notes.txt"));
        assert!(!path_looks_like_pe(""));
    }

    #[test]
    fn filetime_helper_round_trips_known_value() {
        // 2024-06-01 12:00:00 UTC = unix 1_717_243_200
        let ft = 1_717_243_200_i64 * 10_000_000 + FILETIME_EPOCH_DIFF_100NS;
        let dt = filetime_to_datetime(ft).expect("valid timestamp");
        assert_eq!(dt.timestamp(), 1_717_243_200);
    }

    #[test]
    fn filetime_zero_or_negative_returns_none() {
        assert!(filetime_to_datetime(0).is_none());
        assert!(filetime_to_datetime(-1).is_none());
    }

    #[test]
    fn is_suspicious_app_flags_empty_publisher() {
        let entry = AmCacheAppEntry {
            sha1_hash: "abc".to_string(),
            full_path: r"C:\Windows\System32\legit.exe".to_string(),
            file_size: 100,
            link_date: None,
            publisher: "".to_string(),
            product_name: "".to_string(),
            is_pe_file: true,
        };
        assert!(is_suspicious_app(&entry));
    }

    #[test]
    fn is_suspicious_app_flags_drop_locations() {
        let entry = AmCacheAppEntry {
            sha1_hash: "abc".to_string(),
            full_path: r"C:\Users\Alice\AppData\Local\Temp\evil.exe".to_string(),
            file_size: 100,
            link_date: None,
            publisher: "Acme Inc".to_string(),
            product_name: "Tool".to_string(),
            is_pe_file: true,
        };
        assert!(is_suspicious_app(&entry));
    }

    #[test]
    fn is_suspicious_app_clears_legit_signed_in_system32() {
        let entry = AmCacheAppEntry {
            sha1_hash: "abc".to_string(),
            full_path: r"C:\Windows\System32\notepad.exe".to_string(),
            file_size: 100,
            link_date: None,
            publisher: "Microsoft Corporation".to_string(),
            product_name: "Microsoft Notepad".to_string(),
            is_pe_file: true,
        };
        assert!(!is_suspicious_app(&entry));
    }

    #[test]
    fn parse_returns_empty_amcacheparsed_for_empty_input() {
        let parsed = parse(&[]);
        // Default-constructed AmCacheParsed.
        assert_eq!(parsed.apps.len(), 0);
        assert_eq!(parsed.drivers.len(), 0);
    }
}
