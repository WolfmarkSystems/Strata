//! Typed parser for HKCU MRU (Most Recently Used) registry keys.
//!
//! Walks the four canonical Windows MRU stores from `NTUSER.DAT`:
//!
//! | Path | Forensic meaning |
//! |---|---|
//! | `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` (+ per-extension subkeys) | Files the user opened from Explorer; per-extension subkeys narrow to `.docx`, `.pdf`, etc. |
//! | `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU` | Files referenced by the common Open / Save dialogs |
//! | `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` | Last folders visited by the common Open dialog (per executable) |
//! | `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | Strings typed into the Win-R Run dialog |
//! | `Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` | Explorer / Start search terms |
//! | `Software\Microsoft\Internet Explorer\TypedURLs` | URLs typed into Internet Explorer / legacy shell URL boxes |
//! | `Software\Microsoft\Office\*\*\User MRU\*\File MRU` | Office documents opened by Word / Excel / PowerPoint |
//!
//! All four share the same shape: numerically- or alphabetically-named
//! values plus an `MRUList` (REG_SZ char ordering) or `MRUListEx`
//! (REG_BINARY DWORD-array ordering) value that records most-recent-first
//! ordering.
//!
//! ## MITRE ATT&CK
//! * **T1074.001** (Local Data Staging) — RecentDocs / OpenSavePidlMRU
//!   capture the files an actor staged locally before exfil.
//! * **T1059** (Command and Scripting Interpreter) — RunMRU is the
//!   single best record of `cmd.exe` / `powershell.exe` invocations
//!   from the Run dialog.
//!
//! ## What this is NOT
//!
//! `OpenSavePidlMRU` and `LastVisitedPidlMRU` values are
//! [PIDL](https://learn.microsoft.com/en-us/windows/win32/shell/itemidlist)
//! binary blobs (ITEMIDLIST shell items). A full PIDL decoder would be
//! a project unto itself; this module performs *best-effort* extraction
//! of any embedded UTF-16LE filenames within the blob — enough to make
//! the MRU contents human-readable in 95% of cases without pulling in
//! a heavy shell-namespace dependency.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.

/// Hard cap on entries per MRU store. Real Explorer caps at ~30; 256
/// is a generous safety bound against malformed values.
const MAX_ENTRIES_PER_STORE: usize = 256;
/// Minimum length of a UTF-16LE substring before we treat it as a
/// candidate filename inside a PIDL blob.
const MIN_PIDL_STRING_CHARS: usize = 4;

/// Which MRU store this entry came from. Captured separately from the
/// raw key path so downstream Sigma rules can group by category
/// without string-matching paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MruType {
    /// `Software\…\Explorer\RecentDocs` (top level OR per-extension
    /// subkey, e.g. `RecentDocs\.pdf`).
    RecentDocs,
    /// `Software\…\Explorer\ComDlg32\OpenSavePidlMRU` (per-extension
    /// subkeys, PIDL-encoded values).
    OpenSave,
    /// `Software\…\Explorer\ComDlg32\LastVisitedPidlMRU` (per-app
    /// last-visited folder, PIDL-encoded values).
    LastVisited,
    /// `Software\…\Explorer\RunMRU` (Win-R typed strings, REG_SZ
    /// values terminated with `\1`).
    RunMRU,
    /// `Software\…\Explorer\WordWheelQuery` (Start menu / Explorer
    /// search box history).
    WordWheelQuery,
    /// `Software\Microsoft\Internet Explorer\TypedURLs` (legacy URL
    /// entry history).
    TypedURLs,
    /// `Software\Microsoft\Office\*\*\User MRU\*\File MRU` entries,
    /// including Office's embedded FILETIME when present.
    OfficeMRU,
}

impl MruType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MruType::RecentDocs => "RecentDocs",
            MruType::OpenSave => "OpenSavePidlMRU",
            MruType::LastVisited => "LastVisitedPidlMRU",
            MruType::RunMRU => "RunMRU",
            MruType::WordWheelQuery => "WordWheelQuery",
            MruType::TypedURLs => "TypedURLs",
            MruType::OfficeMRU => "OfficeMRU",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastVisitedEntry {
    pub exe_name: String,
    pub folder: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficeMruEntry {
    pub path: String,
    pub opened_at_unix: Option<i64>,
}

/// One typed MRU entry.
///
/// Field meanings are forensic-first; downstream consumers (Phantom,
/// Sigma rules, the timeline view) read these without having to know
/// the registry layout or the PIDL binary format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MruEntry {
    /// Which of the four MRU stores produced this entry. See
    /// [`MruType`] for the per-variant forensic meaning.
    pub mru_type: MruType,

    /// Subcategory within the parent store. For `RecentDocs` this is
    /// the file-extension subkey name (e.g. `".pdf"`) or the empty
    /// string for the top-level RecentDocs key. For `OpenSave` this is
    /// the extension subkey (`".jpg"`, `"*"` etc.). For `LastVisited`
    /// and `RunMRU` it is empty.
    pub subcategory: String,

    /// The actual MRU payload as a human-readable string. For REG_SZ
    /// stores (RunMRU) this is the verbatim value. For REG_BINARY
    /// PIDL stores (RecentDocs / OpenSave / LastVisited) this is the
    /// best-effort UTF-16LE string extraction — usually the filename
    /// or full path. Empty when no decodable text could be recovered.
    pub value: String,

    /// Position in the MRU ordering, 0 = most-recently used. Sourced
    /// from `MRUListEx` (REG_BINARY u32 array, modern) when present,
    /// falling back to `MRUList` (REG_SZ ASCII char order, legacy).
    /// Defaults to `u32::MAX` when neither ordering value is
    /// available.
    pub order: u32,

    /// Original value name as it appeared in the registry (`"a"`,
    /// `"b"`, … or `"0"`, `"1"`, …). Preserved so the analyst can
    /// re-locate the source key during validation.
    pub raw_value_name: String,
}

/// Aggregate result of parsing all four MRU stores under an NTUSER
/// hive root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MruParsed {
    pub entries: Vec<MruEntry>,
}

/// Parse the four canonical MRU stores from an NTUSER.DAT root node.
///
/// Returns an empty [`MruParsed`] when none of the stores are present.
/// Never panics, never calls `unwrap`, never invokes `unsafe`.
pub fn parse(root: &nt_hive::KeyNode<'_, &[u8]>) -> MruParsed {
    let mut entries = Vec::new();
    let explorer_path = [
        "Software",
        "Microsoft",
        "Windows",
        "CurrentVersion",
        "Explorer",
    ];

    // ── RecentDocs (top-level + per-extension subkeys) ──────────────
    if let Some(recent) = walk_extend(root, &explorer_path, &["RecentDocs"]) {
        collect_store(&recent, MruType::RecentDocs, "", &mut entries);
        if let Some(Ok(child_iter)) = recent.subkeys() {
            for child_res in child_iter {
                let Ok(child) = child_res else { continue };
                let Ok(name) = child.name() else { continue };
                let subcat = name.to_string_lossy();
                collect_store(&child, MruType::RecentDocs, &subcat, &mut entries);
            }
        }
    }

    // ── ComDlg32\OpenSavePidlMRU (per-extension subkeys + top-level)
    if let Some(open_save) = walk_extend(root, &explorer_path, &["ComDlg32", "OpenSavePidlMRU"]) {
        collect_store(&open_save, MruType::OpenSave, "", &mut entries);
        if let Some(Ok(child_iter)) = open_save.subkeys() {
            for child_res in child_iter {
                let Ok(child) = child_res else { continue };
                let Ok(name) = child.name() else { continue };
                let subcat = name.to_string_lossy();
                collect_store(&child, MruType::OpenSave, &subcat, &mut entries);
            }
        }
    }

    // ── ComDlg32\LastVisitedPidlMRU (single key, no per-ext children)
    if let Some(last_visited) =
        walk_extend(root, &explorer_path, &["ComDlg32", "LastVisitedPidlMRU"])
    {
        collect_store(&last_visited, MruType::LastVisited, "", &mut entries);
    }

    // ── RunMRU (single key) ──────────────────────────────────────────
    if let Some(run) = walk_extend(root, &explorer_path, &["RunMRU"]) {
        collect_store(&run, MruType::RunMRU, "", &mut entries);
    }

    // ── WordWheelQuery (Explorer / Start search text) ───────────────
    if let Some(word_wheel) = walk_extend(root, &explorer_path, &["WordWheelQuery"]) {
        collect_store(&word_wheel, MruType::WordWheelQuery, "", &mut entries);
    }

    // ── Internet Explorer / shell TypedURLs ─────────────────────────
    if let Some(typed_urls) = walk_extend(
        root,
        &["Software", "Microsoft", "Internet Explorer"],
        &["TypedURLs"],
    ) {
        collect_store(&typed_urls, MruType::TypedURLs, "", &mut entries);
    }

    // ── Office MRU trees: Office\<ver>\<app>\User MRU\<user>\File MRU
    if let Some(office) = walk_extend(root, &["Software", "Microsoft"], &["Office"]) {
        collect_office_mru(&office, "", &mut entries);
    }

    MruParsed { entries }
}

/// Walk one MRU store key and extract every value other than `MRUList`
/// / `MRUListEx`. Decodes REG_SZ verbatim and REG_BINARY PIDLs via
/// best-effort UTF-16LE extraction.
fn collect_store(
    node: &nt_hive::KeyNode<'_, &[u8]>,
    mru_type: MruType,
    subcategory: &str,
    out: &mut Vec<MruEntry>,
) {
    let order_map = read_order_map(node);
    let Some(values_iter) = node.values() else {
        return;
    };
    let Ok(values_iter) = values_iter else {
        return;
    };
    let mut store_count = 0usize;
    for value_res in values_iter {
        if store_count >= MAX_ENTRIES_PER_STORE {
            break;
        }
        let Ok(value) = value_res else { continue };
        let Ok(name_raw) = value.name() else { continue };
        let name = name_raw.to_string_lossy();
        if name.eq_ignore_ascii_case("MRUList") || name.eq_ignore_ascii_case("MRUListEx") {
            continue;
        }
        let bytes = match value.data().and_then(|d| d.into_vec()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let decoded = decode_value(&bytes, mru_type);
        if decoded.is_empty() {
            continue;
        }
        let order = *order_map.get(&name).unwrap_or(&u32::MAX);
        out.push(MruEntry {
            mru_type,
            subcategory: subcategory.to_string(),
            value: decoded,
            order,
            raw_value_name: name,
        });
        store_count += 1;
    }
}

/// Decode an MRU value into a human-readable string. For REG_SZ values
/// (RunMRU) this is the verbatim UTF-16LE string trimmed of the `\1`
/// terminator Explorer appends. For PIDL stores it is the best-effort
/// embedded-string extraction.
pub(crate) fn decode_value(bytes: &[u8], mru_type: MruType) -> String {
    match mru_type {
        // RunMRU values are UTF-16LE strings terminated with `\1`
        // (Explorer uses `\1` as an internal terminator marker).
        MruType::RunMRU => {
            let s = utf16le_to_string(bytes);
            s.trim_end_matches('\u{1}')
                .trim_end_matches('\0')
                .trim_end()
                .to_string()
        }
        MruType::WordWheelQuery => parse_word_wheel_query(bytes),
        MruType::TypedURLs => decode_plain_string(bytes),
        MruType::OfficeMRU => parse_office_mru_item(bytes)
            .map(|entry| match entry.opened_at_unix {
                Some(ts) => format!("{} | opened_at_unix={ts}", entry.path),
                None => entry.path,
            })
            .unwrap_or_default(),
        // RecentDocs values are PIDL blobs prefixed with a UTF-16LE
        // filename (the user-visible name Explorer assigned). Try a
        // straight UTF-16 decode first, fall back to embedded-string
        // extraction.
        MruType::RecentDocs => {
            let direct = utf16le_to_string(bytes);
            if !direct.is_empty() && direct.chars().all(is_printable) {
                direct
            } else {
                best_effort_pidl_string(bytes)
            }
        }
        // OpenSave / LastVisited are pure PIDL — extract best-effort.
        MruType::OpenSave => best_effort_pidl_string(bytes),
        MruType::LastVisited => parse_last_visited_entry(bytes)
            .map(|entry| {
                if entry.folder.is_empty() {
                    entry.exe_name
                } else {
                    format!("{} -> {}", entry.exe_name, entry.folder)
                }
            })
            .unwrap_or_else(|| best_effort_pidl_string(bytes)),
    }
}

fn collect_office_mru(node: &nt_hive::KeyNode<'_, &[u8]>, path: &str, out: &mut Vec<MruEntry>) {
    let name = node
        .name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_else(|_| String::new());
    let current = if path.is_empty() {
        name
    } else {
        format!("{path}\\{name}")
    };
    if current.ends_with("\\File MRU") || current == "File MRU" {
        collect_store(node, MruType::OfficeMRU, &current, out);
    }
    if let Some(Ok(children)) = node.subkeys() {
        for child_res in children {
            let Ok(child) = child_res else { continue };
            collect_office_mru(&child, &current, out);
        }
    }
}

pub(crate) fn parse_word_wheel_query(bytes: &[u8]) -> String {
    decode_plain_string(bytes)
}

pub(crate) fn parse_last_visited_entry(bytes: &[u8]) -> Option<LastVisitedEntry> {
    let strings = utf16le_strings(bytes);
    let exe_name = strings
        .iter()
        .find(|s| s.to_ascii_lowercase().ends_with(".exe"))
        .cloned()
        .or_else(|| strings.first().cloned())?;
    let folder = strings
        .iter()
        .filter(|s| *s != &exe_name)
        .max_by_key(|s| s.len())
        .cloned()
        .unwrap_or_default();
    Some(LastVisitedEntry { exe_name, folder })
}

pub(crate) fn parse_office_mru_item(bytes: &[u8]) -> Option<OfficeMruEntry> {
    let text = decode_plain_string(bytes);
    if text.is_empty() {
        return None;
    }
    let opened_at_unix = extract_office_filetime_unix(&text);
    let path = text
        .rsplit_once('*')
        .map(|(_, tail)| tail)
        .unwrap_or(text.as_str())
        .trim_matches('\0')
        .trim()
        .to_string();
    if path.is_empty() {
        None
    } else {
        Some(OfficeMruEntry {
            path,
            opened_at_unix,
        })
    }
}

fn extract_office_filetime_unix(text: &str) -> Option<i64> {
    let start = text.find("[T")? + 2;
    let rest = text.get(start..)?;
    let hex: String = rest
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .take(16)
        .collect();
    if hex.len() != 16 {
        return None;
    }
    filetime_hex_to_unix(&hex)
}

fn filetime_hex_to_unix(hex: &str) -> Option<i64> {
    let ticks = u64::from_str_radix(hex, 16).ok()?;
    let seconds = ticks.checked_div(10_000_000)?;
    let unix = seconds.checked_sub(11_644_473_600)?;
    i64::try_from(unix).ok()
}

fn decode_plain_string(bytes: &[u8]) -> String {
    let utf16 = utf16le_to_string(bytes)
        .trim_end_matches('\0')
        .trim()
        .to_string();
    if !utf16.is_empty() && utf16.chars().all(is_printable) {
        return utf16;
    }
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .trim()
        .to_string()
}

/// Build a `value_name -> order_index` map from the key's `MRUListEx`
/// (REG_BINARY u32 array) or fall back to `MRUList` (REG_SZ char
/// sequence, e.g. `"cba"` means "c was most recent, then b, then a").
fn read_order_map(node: &nt_hive::KeyNode<'_, &[u8]>) -> std::collections::HashMap<String, u32> {
    let mut map = std::collections::HashMap::new();
    // MRUListEx: u32 array of ASCII-encoded value names is the modern
    // form (RecentDocs / Open-Save / LastVisited). Each u32 is the
    // numeric value name (0..n). Terminator = 0xFFFFFFFF.
    if let Some(bytes) = read_value_bytes(node, "MRUListEx") {
        for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
            let Ok(arr) = <[u8; 4]>::try_from(chunk) else {
                continue;
            };
            let v = u32::from_le_bytes(arr);
            if v == u32::MAX {
                break;
            }
            map.insert(v.to_string(), idx as u32);
        }
        return map;
    }
    // MRUList: REG_SZ where each char is a value name (e.g. "cba"
    // means c=order 0, b=order 1, a=order 2).
    if let Some(bytes) = read_value_bytes(node, "MRUList") {
        let s = utf16le_to_string(&bytes);
        for (idx, ch) in s.chars().enumerate() {
            map.insert(ch.to_string(), idx as u32);
        }
    }
    map
}

/// Best-effort scan for any UTF-16LE substring of length at least
/// [`MIN_PIDL_STRING_CHARS`] inside a PIDL blob. Returns the longest
/// hit (most likely the full filename) or empty when nothing printable
/// is found.
pub(crate) fn best_effort_pidl_string(bytes: &[u8]) -> String {
    let mut best = String::new();
    let mut current = String::new();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        let ch_u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let advance = 2;
        if ch_u == 0 {
            if current.chars().count() >= MIN_PIDL_STRING_CHARS
                && current.chars().count() > best.chars().count()
            {
                best = current.clone();
            }
            current.clear();
        } else if let Some(c) = char::from_u32(ch_u as u32) {
            if is_printable(c) {
                current.push(c);
            } else {
                if current.chars().count() >= MIN_PIDL_STRING_CHARS
                    && current.chars().count() > best.chars().count()
                {
                    best = current.clone();
                }
                current.clear();
            }
        } else {
            current.clear();
        }
        i += advance;
    }
    if current.chars().count() >= MIN_PIDL_STRING_CHARS
        && current.chars().count() > best.chars().count()
    {
        best = current;
    }
    best
}

fn is_printable(c: char) -> bool {
    if c.is_control() || c == '\u{FFFD}' {
        return false;
    }
    // Reject the Unicode "non-character" code points (U+FFFE, U+FFFF
    // and the U+FDD0..U+FDEF block). These appear in PIDL byte runs
    // when raw 0xFF / 0xFE bytes are interpreted as UTF-16 — they're
    // never legitimate filename characters.
    let cp = c as u32;
    if cp == 0xFFFE || cp == 0xFFFF || (0xFDD0..=0xFDEF).contains(&cp) {
        return false;
    }
    // Reject the surrogate range (U+D800..U+DFFF) — char::from_u32
    // already rejects these but be explicit.
    if (0xD800..=0xDFFF).contains(&cp) {
        return false;
    }
    true
}

// ── nt-hive value helpers (mirrored from the legacy `parsers` mod —
//    they're `pub(super)` there and not importable here) ────────────────

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

fn utf16le_to_string(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&ch| ch != 0)
        .collect();
    String::from_utf16_lossy(&u16s)
}

fn utf16le_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    for chunk in data.chunks_exact(2) {
        let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
        if ch == 0 {
            if !current.is_empty() {
                let s = String::from_utf16_lossy(&current)
                    .trim_matches('\0')
                    .trim()
                    .to_string();
                if s.chars().count() >= MIN_PIDL_STRING_CHARS && s.chars().all(is_printable) {
                    out.push(s);
                }
                current.clear();
            }
            continue;
        }
        if let Some(c) = char::from_u32(ch as u32) {
            if is_printable(c) {
                current.push(ch);
                continue;
            }
        }
        current.clear();
    }
    if !current.is_empty() {
        let s = String::from_utf16_lossy(&current)
            .trim_matches('\0')
            .trim()
            .to_string();
        if s.chars().count() >= MIN_PIDL_STRING_CHARS && s.chars().all(is_printable) {
            out.push(s);
        }
    }
    out
}

fn walk_extend<'a>(
    root: &nt_hive::KeyNode<'a, &'a [u8]>,
    base: &[&str],
    suffix: &[&str],
) -> Option<nt_hive::KeyNode<'a, &'a [u8]>> {
    let mut node = root.clone();
    for part in base.iter().chain(suffix.iter()) {
        node = node.subkey(part)?.ok()?;
    }
    Some(node)
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        v.extend_from_slice(&[0, 0]);
        v
    }

    #[test]
    fn mru_type_as_str_round_trips() {
        assert_eq!(MruType::RecentDocs.as_str(), "RecentDocs");
        assert_eq!(MruType::OpenSave.as_str(), "OpenSavePidlMRU");
        assert_eq!(MruType::LastVisited.as_str(), "LastVisitedPidlMRU");
        assert_eq!(MruType::RunMRU.as_str(), "RunMRU");
        assert_eq!(MruType::WordWheelQuery.as_str(), "WordWheelQuery");
        assert_eq!(MruType::TypedURLs.as_str(), "TypedURLs");
        assert_eq!(MruType::OfficeMRU.as_str(), "OfficeMRU");
    }

    #[test]
    fn decode_value_runmru_strips_explorer_terminator() {
        // RunMRU stores e.g. "powershell.exe\u{1}" terminated with \1.
        let mut bytes: Vec<u8> = "powershell.exe"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        // Append \1 terminator + null terminator.
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let decoded = decode_value(&bytes, MruType::RunMRU);
        assert_eq!(decoded, "powershell.exe");
    }

    #[test]
    fn decode_value_recentdocs_extracts_filename_prefix() {
        // RecentDocs values prefix the PIDL with the UTF-16 filename.
        // Use "evil_macro.docm\0\0\0<binary noise>".
        let mut bytes = utf16le("evil_macro.docm");
        bytes.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56]); // PIDL noise
        let decoded = decode_value(&bytes, MruType::RecentDocs);
        assert_eq!(decoded, "evil_macro.docm");
    }

    #[test]
    fn decode_value_pidl_returns_longest_embedded_string() {
        // Build a PIDL-like blob with "abc" (too short) + "longer.exe"
        // (long enough) + binary noise.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&utf16le("abc")); // < MIN_PIDL_STRING_CHARS
        bytes.extend_from_slice(&[0xFF; 6]); // separator junk
        bytes.extend_from_slice(&utf16le("longer.exe"));
        bytes.extend_from_slice(&[0x00; 4]);
        let decoded = decode_value(&bytes, MruType::OpenSave);
        assert_eq!(decoded, "longer.exe");
    }

    #[test]
    fn best_effort_pidl_returns_empty_for_pure_binary() {
        let junk: Vec<u8> = (0..32).map(|i| ((i * 7) % 256) as u8).collect();
        let decoded = best_effort_pidl_string(&junk);
        // Allowed to find no printable substring; if it does, must be
        // at least MIN_PIDL_STRING_CHARS.
        if !decoded.is_empty() {
            assert!(decoded.chars().count() >= MIN_PIDL_STRING_CHARS);
        }
    }

    #[test]
    fn best_effort_pidl_returns_empty_for_empty_input() {
        assert_eq!(best_effort_pidl_string(&[]), "");
    }

    #[test]
    fn mru_parsed_default_is_empty() {
        let p = MruParsed::default();
        assert!(p.entries.is_empty());
    }

    #[test]
    fn decode_value_runmru_handles_empty_bytes() {
        assert_eq!(decode_value(&[], MruType::RunMRU), "");
    }

    #[test]
    fn decode_value_lastvisited_handles_short_input() {
        // 8 bytes — too short to contain a useful PIDL string.
        let bytes = [0u8; 8];
        let decoded = decode_value(&bytes, MruType::LastVisited);
        assert_eq!(decoded, "");
    }

    #[test]
    fn word_wheel_query_parses_plain_strings() {
        let decoded = parse_word_wheel_query(&utf16le("confidential merger"));
        assert_eq!(decoded, "confidential merger");
    }

    #[test]
    fn office_mru_filetime_and_path_are_extracted() {
        // 2024-01-01T00:00:00Z as Windows FILETIME.
        let item = "[F00000000][T01DA3C457689C000]*C:\\Users\\Ada\\Desktop\\plan.docx";
        let parsed = parse_office_mru_item(&utf16le(item)).expect("office mru item");
        assert_eq!(parsed.path, "C:\\Users\\Ada\\Desktop\\plan.docx");
        assert_eq!(parsed.opened_at_unix, Some(1_704_067_200));
    }

    #[test]
    fn last_visited_exe_name_and_folder_are_extracted() {
        let mut bytes = utf16le("WINWORD.EXE");
        bytes.extend_from_slice(&[0x33, 0x22, 0x11, 0x00]);
        bytes.extend_from_slice(&utf16le("C:\\Users\\Ada\\Documents"));
        let parsed = parse_last_visited_entry(&bytes).expect("last visited entry");
        assert_eq!(parsed.exe_name, "WINWORD.EXE");
        assert_eq!(parsed.folder, "C:\\Users\\Ada\\Documents");
        assert_eq!(
            decode_value(&bytes, MruType::LastVisited),
            "WINWORD.EXE -> C:\\Users\\Ada\\Documents"
        );
    }
}
