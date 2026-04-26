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
const EXCHANGE_DOMAINS: &[(&str, &str)] = &[
    ("coinbase.com", "Coinbase"),
    ("binance.com", "Binance"),
    ("kraken.com", "Kraken"),
    ("crypto.com", "Crypto.com"),
    ("gemini.com", "Gemini"),
    ("blockchain.com", "Blockchain.com"),
];
const HARDWARE_WALLETS: &[(&str, &str, &str)] = &[
    ("VID_2C97", "PID_0001", "Ledger Nano S"),
    ("VID_2C97", "PID_4011", "Ledger Nano X"),
    ("VID_1209", "PID_53C1", "Trezor Model T"),
    ("VID_1209", "PID_53C0", "Trezor One"),
    ("VID_1209", "PID_4B24", "Coldcard"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectrumWallet {
    pub file_path: String,
    pub wallet_type: String,
    pub seed_version: Option<i64>,
    pub use_encryption: bool,
    pub is_encrypted: bool,
}

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
            if let Some(wallet) = parse_electrum_wallet_at(path, &body) {
                a.add_field(
                    "encrypted",
                    if wallet.is_encrypted { "true" } else { "false" },
                );
                a.add_field(
                    "use_encryption",
                    if wallet.use_encryption {
                        "true"
                    } else {
                        "false"
                    },
                );
                a.add_field("wallet_type", &wallet.wallet_type);
                if let Some(seed_version) = wallet.seed_version {
                    a.add_field("seed_version", &seed_version.to_string());
                }
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
        && (name.ends_with(".ldb") || name.ends_with(".log") || name == "manifest-000001")
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
    if let Some(exchange) = identify_exchange_domain(&lower) {
        let mut a = Artifact::new("Exchange Browser Artifact", &path.to_string_lossy());
        a.add_field("title", &format!("{exchange} browser artifact"));
        a.add_field("file_type", "Exchange Browser Artifact");
        a.add_field("exchange", exchange);
        a.add_field("mitre", "T1583.006");
        a.add_field("forensic_value", "High");
        a.add_field("suspicious", "true");
        out.push(a);
    }
    if let Some(wallet) = identify_hardware_wallet(&lower) {
        let mut a = Artifact::new("Crypto Hardware Wallet", &path.to_string_lossy());
        a.add_field("title", &format!("Hardware wallet USB artifact: {wallet}"));
        a.add_field("file_type", "Crypto Hardware Wallet");
        a.add_field("wallet_kind", wallet);
        a.add_field("mitre", "T1583.006");
        a.add_field("forensic_value", "High");
        a.add_field("suspicious", "true");
        out.push(a);
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

pub fn parse_electrum_wallet(json: &str) -> Option<ElectrumWallet> {
    parse_electrum_wallet_at(Path::new(""), json)
}

fn parse_electrum_wallet_at(path: &Path, json: &str) -> Option<ElectrumWallet> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let wallet_type = value
        .get("wallet_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let seed_version = value.get("seed_version").and_then(|v| v.as_i64());
    let use_encryption = value
        .get("use_encryption")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_encrypted = use_encryption
        || value.get("keystore").is_some()
        || value
            .get("wallet_type")
            .and_then(|v| v.as_str())
            .map(|v| v.contains("hardware"))
            .unwrap_or(false);
    Some(ElectrumWallet {
        file_path: path.to_string_lossy().to_string(),
        wallet_type,
        seed_version,
        use_encryption,
        is_encrypted,
    })
}

pub fn identify_exchange_domain(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    for (domain, name) in EXCHANGE_DOMAINS {
        if lower.contains(domain) {
            return Some(*name);
        }
    }
    None
}

pub fn identify_hardware_wallet(text: &str) -> Option<&'static str> {
    let upper = text.to_ascii_uppercase();
    for (vid, pid, name) in HARDWARE_WALLETS {
        if upper.contains(vid) && upper.contains(pid) {
            return Some(*name);
        }
    }
    None
}

fn identify_exchange(body: &str) -> Option<&'static str> {
    let first_line = body.lines().next()?;
    let lc = first_line.to_ascii_lowercase();
    if lc.contains("timestamp")
        && lc.contains("transaction type")
        && lc.contains("asset")
        && lc.contains("quantity transacted")
    {
        return Some("Coinbase");
    }
    if lc.contains("date(utc)")
        && lc.contains("pair")
        && lc.contains("side")
        && lc.contains("executed")
    {
        return Some("Binance");
    }
    if lc.contains("txid")
        && lc.contains("ordertxid")
        && lc.contains("pair")
        && lc.contains("ordertype")
    {
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
    fn electrum_wallet_encryption_detected() {
        let json = r#"{"wallet_type":"standard","use_encryption":true,"seed_version":17}"#;
        let wallet = parse_electrum_wallet(json).expect("electrum wallet");
        assert!(wallet.is_encrypted);
        assert_eq!(wallet.seed_version, Some(17));
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

    #[test]
    fn hardware_wallet_vid_pid_detected() {
        assert_eq!(
            identify_hardware_wallet(r"HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_2C97&PID_4011"),
            Some("Ledger Nano X")
        );
    }

    #[test]
    fn exchange_domain_detected_from_browser_artifact_path() {
        assert_eq!(
            identify_exchange_domain("/History https://www.coinbase.com/transactions"),
            Some("Coinbase")
        );
    }
}
