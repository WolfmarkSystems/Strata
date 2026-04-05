use chrono::{DateTime, Utc};
use nt_hive::{Hive, KeyNode, KeyValueData};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct ShellbagEntry {
    pub path: String,
    pub last_interacted: Option<DateTime<Utc>>,
    pub bag_key: String,
}

pub fn parse_shellbags(
    data: &[u8],
    hive_alias: &str,
    fallback_time: Option<DateTime<Utc>>,
) -> Result<Vec<ShellbagEntry>, String> {
    let hive = Hive::new(data).map_err(|e| format!("Hive parse error: {}", e))?;
    let root = hive
        .root_key_node()
        .map_err(|e| format!("Root key error: {}", e))?;

    let mut out = Vec::new();
    for root_rel in [
        "Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    ] {
        if let Some(Ok(bagmru)) = root.subpath(root_rel) {
            walk_bagmru(hive_alias, root_rel, bagmru, fallback_time, &mut out);
        }
    }

    // Deduplicate by key+path and keep deterministic order.
    let mut seen = HashSet::<String>::new();
    out.retain(|e| {
        let key = format!("{}|{}", e.bag_key.to_lowercase(), e.path.to_lowercase());
        seen.insert(key)
    });
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn walk_bagmru(
    hive_alias: &str,
    bagmru_root: &str,
    bagmru_node: KeyNode<'_, &[u8]>,
    fallback_time: Option<DateTime<Utc>>,
    out: &mut Vec<ShellbagEntry>,
) {
    let mut stack: Vec<(String, KeyNode<'_, &[u8]>, String)> =
        vec![(bagmru_root.to_string(), bagmru_node, String::new())];

    while let Some((bag_key_rel, node, base_path)) = stack.pop() {
        let Some(subkeys_res) = node.subkeys() else {
            continue;
        };
        let Ok(subkeys) = subkeys_res else {
            continue;
        };

        for child_res in subkeys {
            let Ok(child) = child_res else {
                continue;
            };
            let Ok(child_name_raw) = child.name() else {
                continue;
            };
            let child_name = child_name_raw.to_string();
            if child_name.is_empty() {
                continue;
            }

            let segment = if child_name.chars().all(|c| c.is_ascii_digit()) {
                extract_value_blob(&node, &child_name)
                    .and_then(|b| decode_shell_item_blob(&b))
                    .unwrap_or_else(|| format!("item_{}", child_name))
            } else {
                child_name.clone()
            };
            let joined = join_path(&base_path, &segment);
            let child_key_rel = format!("{}\\{}", bag_key_rel, child_name);

            out.push(ShellbagEntry {
                path: joined.clone(),
                last_interacted: fallback_time,
                bag_key: format!("{}\\{}", hive_alias, child_key_rel),
            });

            stack.push((child_key_rel, child, joined));
        }
    }
}

fn join_path(base: &str, segment: &str) -> String {
    if base.is_empty() {
        segment.to_string()
    } else {
        format!("{}/{}", base, segment)
    }
}

fn extract_value_blob(node: &KeyNode<'_, &[u8]>, value_name: &str) -> Option<Vec<u8>> {
    let values = node.values()?;
    let values = values.ok()?;

    for value_res in values {
        let value = value_res.ok()?;
        let name = value.name().ok().map(|n| n.to_string()).unwrap_or_default();
        if name != value_name {
            continue;
        }

        return match value.data().ok()? {
            KeyValueData::Small(bytes) => Some(bytes.to_vec()),
            KeyValueData::Big(chunks) => {
                let mut out = Vec::new();
                for chunk in chunks.flatten() {
                    out.extend_from_slice(chunk);
                }
                Some(out)
            }
        };
    }

    None
}

fn decode_shell_item_blob(blob: &[u8]) -> Option<String> {
    if blob.len() < 4 {
        return None;
    }

    let item_type = blob[2];
    let name = match item_type {
        0x1f => "Desktop".to_string(),
        0x2f => extract_drive_letter(blob).unwrap_or_else(|| "Drive".to_string()),
        0x20 | 0x30 => extract_best_name(blob).unwrap_or_else(|| "Folder".to_string()),
        0x40 => extract_unc_path(blob).unwrap_or_else(|| "Network".to_string()),
        0x61 => extract_url(blob).unwrap_or_else(|| "URI".to_string()),
        _ => extract_best_name(blob).unwrap_or_else(|| format!("Item_{:02X}", item_type)),
    };

    let clean = name
        .replace('\\', "/")
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

fn extract_drive_letter(blob: &[u8]) -> Option<String> {
    for w in blob.windows(2) {
        let c = w[0] as char;
        if c.is_ascii_alphabetic() && w[1] == b':' {
            return Some(format!("{}:", c.to_ascii_uppercase()));
        }
    }
    None
}

fn extract_unc_path(blob: &[u8]) -> Option<String> {
    let ascii = extract_ascii_strings(blob);
    ascii
        .into_iter()
        .find(|s| s.starts_with("\\\\") || s.contains("\\\\"))
}

fn extract_url(blob: &[u8]) -> Option<String> {
    let ascii = extract_ascii_strings(blob);
    ascii.into_iter().find(|s| {
        let sl = s.to_lowercase();
        sl.starts_with("http://") || sl.starts_with("https://") || sl.starts_with("file://")
    })
}

fn extract_best_name(blob: &[u8]) -> Option<String> {
    let mut cands = extract_utf16_strings(blob);
    cands.extend(extract_ascii_strings(blob));
    cands
        .into_iter()
        .filter(|s| s.len() >= 2)
        .filter(|s| !s.eq_ignore_ascii_case("node"))
        .max_by_key(|s| s.len())
}

fn extract_utf16_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::<u16>::new();
    let mut i = 0usize;

    while i + 1 < data.len() {
        let v = u16::from_le_bytes([data[i], data[i + 1]]);
        if v == 0 {
            if cur.len() >= 2 {
                if let Ok(s) = String::from_utf16(&cur) {
                    let trimmed = s.trim().to_string();
                    if !trimmed.is_empty() {
                        out.push(trimmed);
                    }
                }
            }
            cur.clear();
        } else if (0x20..=0x7E).contains(&v) {
            cur.push(v);
        } else {
            if cur.len() >= 2 {
                if let Ok(s) = String::from_utf16(&cur) {
                    let trimmed = s.trim().to_string();
                    if !trimmed.is_empty() {
                        out.push(trimmed);
                    }
                }
            }
            cur.clear();
        }
        i += 2;
    }

    out
}

fn extract_ascii_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::<u8>::new();

    for b in data {
        if (0x20..=0x7E).contains(b) {
            cur.push(*b);
        } else {
            if cur.len() >= 3 {
                let s = String::from_utf8_lossy(&cur).trim().to_string();
                if !s.is_empty() {
                    out.push(s);
                }
            }
            cur.clear();
        }
    }

    if cur.len() >= 3 {
        let s = String::from_utf8_lossy(&cur).trim().to_string();
        if !s.is_empty() {
            out.push(s);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_shellbags_rejects_invalid_hive() {
        let err = parse_shellbags(&[0u8; 8], "NTUSER.DAT", None)
            .err()
            .unwrap_or_default();
        assert!(!err.is_empty());
    }

    #[test]
    fn join_path_handles_empty_and_non_empty_base() {
        assert_eq!(join_path("", "Desktop"), "Desktop");
        assert_eq!(join_path("C:", "Users"), "C:/Users");
    }

    #[test]
    fn extract_ascii_strings_collects_printable_sequences() {
        let bytes = b"\x00abc\x00de\x00hello_world\x00";
        let out = extract_ascii_strings(bytes);
        assert!(out.iter().any(|s| s == "abc"));
        assert!(out.iter().any(|s| s == "hello_world"));
    }

    #[test]
    fn decode_shell_item_blob_extracts_drive_letter() {
        let blob = [0x00, 0x00, 0x2F, 0x00, b'C', b':', 0x00, 0x00];
        let out = decode_shell_item_blob(&blob).unwrap_or_default();
        assert_eq!(out, "C:");
    }
}
