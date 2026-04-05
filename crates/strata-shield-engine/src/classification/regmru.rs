use std::collections::HashMap;
use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records, parse_reg_u64};

pub fn get_run_mru() -> Vec<MruEntry> {
    get_run_mru_from_reg(&default_reg_path("runmru.reg"))
}

pub fn get_run_mru_from_reg(path: &Path) -> Vec<MruEntry> {
    let records = load_reg_records(path);
    let mut output = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\explorer\\runmru"))
    {
        let order_map =
            parse_mru_order_map(record.values.get("MRUListEx"), record.values.get("MRUList"));
        let mut fallback_index = order_map.len() as u32;
        let mut entries = Vec::new();

        for (name, raw) in &record.values {
            if name.eq_ignore_ascii_case("MRUList")
                || name.eq_ignore_ascii_case("MRUListEx")
                || name.eq_ignore_ascii_case("@")
            {
                continue;
            }
            if let Some(value) = decode_reg_string(raw) {
                let key = normalize_mru_value_name(name);
                let entry_index = order_map.get(&key).copied().unwrap_or_else(|| {
                    let idx = fallback_index;
                    fallback_index = fallback_index.saturating_add(1);
                    idx
                });
                entries.push(MruEntry {
                    index: entry_index,
                    value,
                });
            }
        }

        entries.sort_by_key(|e| e.index);
        output.extend(entries);
    }

    output
}

#[derive(Debug, Clone, Default)]
pub struct MruEntry {
    pub index: u32,
    pub value: String,
}

pub fn get_recent_docs() -> Vec<RecentDoc> {
    get_recent_docs_from_reg(&default_reg_path("recentdocs.reg"))
}

pub fn get_recent_docs_from_reg(path: &Path) -> Vec<RecentDoc> {
    let records = load_reg_records(path);
    let mut docs = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\explorer\\recentdocs")
    }) {
        for (name, raw) in &record.values {
            if name.eq_ignore_ascii_case("MRUListEx") || name.eq_ignore_ascii_case("@") {
                continue;
            }
            let decoded = decode_reg_string(raw).or_else(|| {
                parse_reg_u64(raw).map(|v| {
                    if v == 0 {
                        String::new()
                    } else {
                        format!("{v}")
                    }
                })
            });

            if let Some(name_value) = decoded {
                if !name_value.is_empty() {
                    docs.push(RecentDoc {
                        name: name_value,
                        timestamp: None,
                    });
                }
            }
        }
    }

    docs
}

#[derive(Debug, Clone, Default)]
pub struct RecentDoc {
    pub name: String,
    pub timestamp: Option<u64>,
}

pub fn get_shellbags() -> Vec<ShellbagEntry> {
    get_shellbags_from_reg(&default_reg_path("shellbags.reg"))
}

pub fn get_shellbags_from_reg(path: &Path) -> Vec<ShellbagEntry> {
    let records = load_reg_records(path);
    let mut entries = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\shell\\bagmru"))
    {
        let modified = record
            .values
            .get("LastWriteTime")
            .and_then(|raw| parse_reg_u64(raw));
        entries.push(ShellbagEntry {
            path: record.path.clone(),
            modified,
        });
    }

    entries
}

#[derive(Debug, Clone, Default)]
pub struct ShellbagEntry {
    pub path: String,
    pub modified: Option<u64>,
}

fn parse_mru_order_map(
    mru_list_ex_raw: Option<&String>,
    mru_list_raw: Option<&String>,
) -> HashMap<String, u32> {
    let mut order_map = HashMap::new();

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
    let bytes = super::reg_export::parse_hex_bytes(raw)?;
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

fn normalize_mru_value_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_run_mru_from_reg_export() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("runmru.reg");
        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU]
"MRUList"="ba"
"a"="cmd.exe"
"b"="powershell.exe"
"#,
        )
        .unwrap();

        let rows = get_run_mru_from_reg(&file);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].value, "powershell.exe");
        assert_eq!(rows[1].value, "cmd.exe");
    }

    #[test]
    fn parse_run_mru_prefers_mrulistex_order() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("runmru.reg");
        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU]
"MRUListEx"=hex:01,00,00,00,00,00,00,00,ff,ff,ff,ff
"0"="cmd.exe"
"1"="powershell.exe"
"MRUList"="01"
"#,
        )
        .unwrap();

        let rows = get_run_mru_from_reg(&file);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].value, "powershell.exe");
        assert_eq!(rows[1].value, "cmd.exe");
    }
}
