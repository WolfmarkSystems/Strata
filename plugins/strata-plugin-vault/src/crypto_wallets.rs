//! Cryptocurrency wallet + exchange export detection (CRYPTO-1).
//!
//! Detects wallet files and exchange transaction CSVs. Wallet content
//! is never decrypted — presence and metadata only.
//!
//! MITRE: T1531 (account access removal), T1657 (financial theft).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use std::fs;
use std::path::Path;
use strata_plugin_sdk::Artifact;

const BDB_MAGIC: [u8; 8] = [0x00, 0x31, 0xBB, 0x30, 0xDB, 0xBB, 0xC4, 0x02];

pub fn scan(path: &Path) -> Vec<Artifact> {
    let mut out = Vec::new();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let lower = path.to_string_lossy().to_ascii_lowercase();
    // Bitcoin Core wallet.dat.
    if name == "wallet.dat" {
        let meta = fs::metadata(path).ok();
        let size = meta.map(|m| m.len()).unwrap_or(0);
        let mut has_bdb_magic = false;
        if let Ok(bytes) = fs::read(path) {
            has_bdb_magic = bytes.len() >= 8 && bytes[..8] == BDB_MAGIC;
        }
        let mut a = Artifact::new("Crypto Wallet", &path.to_string_lossy());
        a.add_field("title", "Bitcoin Core wallet.dat");
        a.add_field(
            "detail",
            &format!(
                "File: wallet.dat | size: {} bytes | BDB magic: {}",
                size, has_bdb_magic
            ),
        );
        a.add_field("file_type", "Crypto Wallet");
        a.add_field("wallet_kind", "Bitcoin Core");
        a.add_field("file_size", &size.to_string());
        a.add_field("bdb_magic", if has_bdb_magic { "true" } else { "false" });
        a.add_field("mitre", "T1657");
        a.add_field("forensic_value", "High");
        a.add_field("suspicious", "true");
        out.push(a);
        return out;
    }
    // Electrum wallet: default_wallet or *.wallet JSON files in Electrum dir.
    if (lower.contains("/electrum/wallets/") || lower.contains("\\electrum\\wallets\\"))
        && (name == "default_wallet" || name.ends_with(".wallet"))
    {
        let mut a = Artifact::new("Crypto Wallet", &path.to_string_lossy());
        a.add_field("title", &format!("Electrum wallet: {}", name));
        a.add_field("file_type", "Crypto Wallet");
        a.add_field("wallet_kind", "Electrum");
        if let Ok(body) = fs::read_to_string(path) {
            if body.contains("\"use_encryption\": true") || body.contains("\"use_encryption\":true") {
                a.add_field("encrypted", "true");
            }
            if let Some(wallet_type) = extract_json_field(&body, "wallet_type") {
                a.add_field("wallet_type", &wallet_type);
            }
        }
        a.add_field("mitre", "T1657");
        a.add_field("forensic_value", "High");
        a.add_field("suspicious", "true");
        out.push(a);
        return out;
    }
    // MetaMask LevelDB extension settings.
    if lower.contains("nkbihfbeogaeaoehlefnkodbefgpgknn")
        && (name.ends_with(".ldb") || name.ends_with(".log"))
    {
        let mut a = Artifact::new("Crypto Wallet", &path.to_string_lossy());
        a.add_field("title", "MetaMask extension storage");
        a.add_field("file_type", "Crypto Wallet");
        a.add_field("wallet_kind", "MetaMask");
        a.add_field("mitre", "T1657");
        a.add_field("forensic_value", "High");
        a.add_field("suspicious", "true");
        out.push(a);
        return out;
    }
    // Exchange CSV detection.
    if name.ends_with(".csv") {
        if let Ok(body) = fs::read_to_string(path) {
            if let Some(exchange) = identify_exchange(&body) {
                let mut a = Artifact::new("Exchange Export", &path.to_string_lossy());
                a.add_field("title", &format!("{} exchange export: {}", exchange, name));
                a.add_field("file_type", "Exchange Export");
                a.add_field("exchange", exchange);
                a.add_field("mitre", "T1657");
                a.add_field("forensic_value", "High");
                a.add_field("suspicious", "true");
                out.push(a);
            }
        }
    }
    out
}

fn extract_json_field(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{}\"", field);
    let pos = body.find(&needle)? + needle.len();
    let after = &body[pos..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        let end = rest.find([',', '}']).unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

fn identify_exchange(body: &str) -> Option<&'static str> {
    let first_line = body.lines().next()?;
    let lc = first_line.to_ascii_lowercase();
    if lc.contains("timestamp") && lc.contains("transaction type") && lc.contains("asset")
        && lc.contains("quantity transacted")
    {
        return Some("Coinbase");
    }
    if lc.contains("date(utc)") && lc.contains("pair") && lc.contains("side") && lc.contains("executed") {
        return Some("Binance");
    }
    if lc.contains("txid") && lc.contains("ordertxid") && lc.contains("pair") && lc.contains("ordertype") {
        return Some("Kraken");
    }
    if lc.contains("date")
        && lc.contains("time (utc)")
        && lc.contains("type")
        && lc.contains("symbol")
        && lc.contains("specification")
    {
        return Some("Gemini");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_wallet_dat() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wallet.dat");
        let mut body = BDB_MAGIC.to_vec();
        body.extend_from_slice(&[0u8; 128]);
        std::fs::write(&path, &body).expect("write");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("wallet_kind").map(|s| s.as_str()) == Some("Bitcoin Core")));
    }

    #[test]
    fn detects_coinbase_csv() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("coinbase.csv");
        std::fs::write(
            &path,
            "Timestamp,Transaction Type,Asset,Quantity Transacted,Spot Price at Transaction\n2024-01-01T00:00:00Z,Buy,BTC,0.01,45000\n",
        )
        .expect("write");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("exchange").map(|s| s.as_str()) == Some("Coinbase")));
    }

    #[test]
    fn detects_electrum_wallet() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wd = dir.path().join("Electrum").join("wallets");
        std::fs::create_dir_all(&wd).expect("mkdirs");
        let path = wd.join("default_wallet");
        std::fs::write(
            &path,
            "{\n  \"wallet_type\": \"standard\",\n  \"use_encryption\": true\n}",
        )
        .expect("write");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("wallet_kind").map(|s| s.as_str()) == Some("Electrum")));
    }

    #[test]
    fn detects_metamask_ldb() {
        let dir = tempfile::tempdir().expect("tempdir");
        let metamask_dir = dir
            .path()
            .join("Chrome")
            .join("User Data")
            .join("Default")
            .join("Local Extension Settings")
            .join("nkbihfbeogaeaoehlefnkodbefgpgknn");
        std::fs::create_dir_all(&metamask_dir).expect("mkdirs");
        let path = metamask_dir.join("000003.ldb");
        std::fs::write(&path, b"").expect("write");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("wallet_kind").map(|s| s.as_str()) == Some("MetaMask")));
    }

    #[test]
    fn noop_on_unrelated_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.txt");
        std::fs::write(&path, b"hello").expect("write");
        assert!(scan(&path).is_empty());
    }
}
