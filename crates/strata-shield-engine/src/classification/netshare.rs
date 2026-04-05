use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};

pub fn get_network_shares() -> Vec<NetworkShare> {
    get_network_shares_from_reg(&default_reg_path("netshare.reg"))
}

pub fn get_network_shares_from_reg(path: &Path) -> Vec<NetworkShare> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\lanmanserver\\shares")
    }) {
        for (name, raw) in &record.values {
            let mut share_path = decode_reg_string(raw).unwrap_or_default();
            if share_path.is_empty() {
                share_path = key_leaf(&record.path);
            }
            out.push(NetworkShare {
                name: name.clone(),
                path: share_path,
            });
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct NetworkShare {
    pub name: String,
    pub path: String,
}
