//! Cryptocurrency address detection across artifact text.

use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq)]
pub struct CryptoAddress {
    pub address: String,
    pub currency: CryptoCurrency,
    pub confidence: f32,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoCurrency {
    Bitcoin,
    BitcoinSegwit,
    Ethereum,
    Monero,
    Unknown,
}

impl CryptoCurrency {
    pub fn as_str(&self) -> &'static str {
        match self {
            CryptoCurrency::Bitcoin => "Bitcoin",
            CryptoCurrency::BitcoinSegwit => "Bitcoin SegWit",
            CryptoCurrency::Ethereum => "Ethereum",
            CryptoCurrency::Monero => "Monero",
            CryptoCurrency::Unknown => "Unknown",
        }
    }
}

pub fn scan_for_crypto_addresses(text: &str) -> Vec<CryptoAddress> {
    let mut out = Vec::new();
    scan_regex(
        btc_legacy_re(),
        text,
        CryptoCurrency::Bitcoin,
        0.90,
        &mut out,
    );
    scan_regex(
        btc_segwit_re(),
        text,
        CryptoCurrency::BitcoinSegwit,
        0.95,
        &mut out,
    );
    scan_regex(eth_re(), text, CryptoCurrency::Ethereum, 0.90, &mut out);
    scan_regex(xmr_re(), text, CryptoCurrency::Monero, 0.95, &mut out);
    out.sort_by_key(|a| a.start);
    out.dedup_by(|a, b| a.address == b.address && a.currency == b.currency);
    out
}

fn scan_regex(
    re: &Regex,
    text: &str,
    currency: CryptoCurrency,
    confidence: f32,
    out: &mut Vec<CryptoAddress>,
) {
    for m in re.find_iter(text) {
        out.push(CryptoAddress {
            address: m.as_str().to_string(),
            currency,
            confidence,
            start: m.start(),
            end: m.end(),
        });
    }
}

fn btc_legacy_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(
        || match Regex::new(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b") {
            Ok(re) => re,
            Err(e) => panic!("BTC legacy regex is invalid: {e}"),
        },
    )
}

fn btc_segwit_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| match Regex::new(r"\bbc1[a-z0-9]{39,59}\b") {
        Ok(re) => re,
        Err(e) => panic!("BTC SegWit regex is invalid: {e}"),
    })
}

fn eth_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| match Regex::new(r"\b0x[a-fA-F0-9]{34,40}\b") {
        Ok(re) => re,
        Err(e) => panic!("ETH regex is invalid: {e}"),
    })
}

fn xmr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(
        || match Regex::new(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b") {
            Ok(re) => re,
            Err(e) => panic!("XMR regex is invalid: {e}"),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_detect_btc_legacy_address() {
        let text = "send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf6X";
        let addrs = scan_for_crypto_addresses(text);
        assert_eq!(addrs.len(), 1);
        assert!(matches!(addrs[0].currency, CryptoCurrency::Bitcoin));
    }

    #[test]
    fn crypto_detect_eth_address() {
        let text = "wallet: 0x742d35Cc6634C0532925a3b8D4C9f5E6734";
        let addrs = scan_for_crypto_addresses(text);
        assert!(addrs
            .iter()
            .any(|a| matches!(a.currency, CryptoCurrency::Ethereum)));
    }

    #[test]
    fn crypto_detect_no_false_positive_on_random_hex() {
        let text = "sha256: a3f4b2c1d8e9f0a1b2c3d4e5f6a7b8c9";
        let addrs = scan_for_crypto_addresses(text);
        assert!(addrs.is_empty());
    }
}
