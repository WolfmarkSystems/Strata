use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records, parse_hex_bytes};

pub fn get_open_save_mru() -> Vec<MruEntry> {
    get_open_save_mru_from_reg(&default_reg_path("mru2.reg"))
}

pub fn get_open_save_mru_from_reg(path: &Path) -> Vec<MruEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\comdlg32\\opensavemru")
    }) {
        let order_map =
            parse_mru_order_map(record.values.get("MRUListEx"), record.values.get("MRUList"));
        let mut fallback_index = order_map.len() as u32;
        let mut record_entries = Vec::new();

        for (name, raw) in &record.values {
            if name.eq_ignore_ascii_case("MRUList") || name.eq_ignore_ascii_case("MRUListEx") {
                continue;
            }
            if let Some(path_value) = decode_mru_string(raw) {
                let key = name.trim().to_ascii_lowercase();
                let entry_index = order_map.get(&key).copied().unwrap_or_else(|| {
                    let idx = fallback_index;
                    fallback_index = fallback_index.saturating_add(1);
                    idx
                });
                record_entries.push((
                    entry_index,
                    MruEntry {
                        name: name.clone(),
                        path: normalize_mru_path(&path_value),
                    },
                ));
            }
        }

        record_entries.sort_by_key(|(idx, _)| *idx);
        out.extend(record_entries.into_iter().map(|(_, row)| row));
    }
    dedupe_mru_entries(out)
}

#[derive(Debug, Clone, Default)]
pub struct MruEntry {
    pub name: String,
    pub path: String,
}

pub fn get_lastvisited() -> Vec<LastVisited> {
    get_lastvisited_from_reg(&default_reg_path("mru2.reg"))
}

pub fn get_lastvisited_from_reg(path: &Path) -> Vec<LastVisited> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\comdlg32\\lastvisitedmru")
    }) {
        let order_map =
            parse_mru_order_map(record.values.get("MRUListEx"), record.values.get("MRUList"));
        let mut fallback_index = order_map.len() as u32;
        let mut record_entries = Vec::new();

        for (name, raw) in &record.values {
            if name.eq_ignore_ascii_case("MRUList") || name.eq_ignore_ascii_case("MRUListEx") {
                continue;
            }
            if let Some(target) = decode_mru_string(raw) {
                let key = name.trim().to_ascii_lowercase();
                let entry_index = order_map.get(&key).copied().unwrap_or_else(|| {
                    let idx = fallback_index;
                    fallback_index = fallback_index.saturating_add(1);
                    idx
                });
                record_entries.push((
                    entry_index,
                    LastVisited {
                        target: normalize_mru_path(&target),
                        timestamp: None,
                    },
                ));
            }
        }

        record_entries.sort_by_key(|(idx, _)| *idx);
        out.extend(record_entries.into_iter().map(|(_, row)| row));
    }
    dedupe_lastvisited_entries(out)
}

#[derive(Debug, Clone, Default)]
pub struct LastVisited {
    pub target: String,
    pub timestamp: Option<u64>,
}

fn parse_mru_order_map(
    mru_list_ex_raw: Option<&String>,
    mru_list_raw: Option<&String>,
) -> std::collections::HashMap<String, u32> {
    let mut order_map = std::collections::HashMap::new();

    if let Some(raw) = mru_list_ex_raw {
        if let Some(order_items) = parse_mrulistex(raw) {
            for (idx, name) in order_items.into_iter().enumerate() {
                order_map.insert(name, idx as u32);
            }
            return order_map;
        }
    }

    if let Some(raw) = mru_list_raw {
        if let Some(order) = decode_reg_string(raw) {
            for (idx, ch) in order.chars().enumerate() {
                order_map.insert(ch.to_string().to_ascii_lowercase(), idx as u32);
            }
        }
    }

    order_map
}

fn parse_mrulistex(raw: &str) -> Option<Vec<String>> {
    let bytes = parse_hex_bytes(raw)?;
    if bytes.is_empty() {
        return Some(Vec::new());
    }

    let mut out = Vec::new();
    for chunk in bytes.chunks_exact(4) {
        let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if val == u32::MAX {
            break;
        }
        out.push(val.to_string());
    }
    Some(out)
}

fn decode_mru_string(raw: &str) -> Option<String> {
    if let Some(value) = decode_reg_string(raw) {
        let trimmed = value.trim_matches('\0').trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let bytes = parse_hex_bytes(raw)?;
    if bytes.is_empty() {
        return None;
    }
    let utf16 = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    if let Ok(text) = String::from_utf16(&utf16) {
        let normalized = text.replace('\0', "").trim().to_string();
        if !normalized.is_empty() {
            return Some(normalized);
        }
    }
    let ascii = String::from_utf8_lossy(&bytes).replace('\0', "");
    let trimmed = ascii.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn normalize_mru_path(value: &str) -> String {
    value.trim().trim_matches('"').replace('/', "\\")
}

fn dedupe_mru_entries(rows: Vec<MruEntry>) -> Vec<MruEntry> {
    let mut seen = std::collections::BTreeSet::new();
    rows.into_iter()
        .filter(|row| seen.insert(format!("{}|{}", row.name.to_ascii_lowercase(), row.path)))
        .collect()
}

fn dedupe_lastvisited_entries(rows: Vec<LastVisited>) -> Vec<LastVisited> {
    let mut seen = std::collections::BTreeSet::new();
    rows.into_iter()
        .filter(|row| seen.insert(row.target.to_ascii_lowercase()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_open_save_mru() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("mru2.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU\docx]
"a"="C:\Docs\draft.docx"
"#,
        )
        .unwrap();
        let rows = get_open_save_mru_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, r"C:\Docs\draft.docx");
    }

    #[test]
    fn parse_open_save_mru_mrulistex_order() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("mru2.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU\docx]
"MRUListEx"=hex:01,00,00,00,00,00,00,00,ff,ff,ff,ff
"0"="C:\Docs\old.docx"
"1"="C:\Docs\new.docx"
"#,
        )
        .unwrap();

        let rows = get_open_save_mru_from_reg(&file);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].path, r"C:\Docs\new.docx");
        assert_eq!(rows[1].path, r"C:\Docs\old.docx");
    }

    #[test]
    fn parse_open_save_mru_hex_value_decodes_utf16_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("mru2.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU\txt]
"0"=hex(2):43,00,3a,00,5c,00,54,00,65,00,73,00,74,00,5c,00,6e,00,6f,00,74,00,65,00,73,00,2e,00,74,00,78,00,74,00,00,00
"#,
        )
        .unwrap();

        let rows = get_open_save_mru_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, r"C:\Test\notes.txt");
    }

    #[test]
    fn parse_lastvisited_respects_mrulistex_order() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("mru2.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU]
"MRUListEx"=hex:01,00,00,00,00,00,00,00,ff,ff,ff,ff
"0"="C:\Windows\System32\notepad.exe"
"1"="C:\Windows\System32\cmd.exe"
"#,
        )
        .unwrap();

        let rows = get_lastvisited_from_reg(&file);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].target, r"C:\Windows\System32\cmd.exe");
        assert_eq!(rows[1].target, r"C:\Windows\System32\notepad.exe");
    }
}
