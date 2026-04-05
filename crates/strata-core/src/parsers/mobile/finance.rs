use crate::errors::ForensicError;

/// Parser interface for Crypto Wallets and Financial Ledgers.
pub struct FinancialParser;

impl Default for FinancialParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FinancialParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_app_data(
        &self,
        app_domain: &str,
        data: &[u8],
    ) -> Result<Vec<FinancialTx>, ForensicError> {
        match app_domain {
            // Crypto
            "wallet.dat" | "org.electrum.electrum" => self.parse_crypto_wallet(data),
            "io.metamask" | "com.wallet.crypto.trustapp" => self.parse_defi_wallet(data),

            // FinTech
            "com.squareup.cash" | "com.venmo" => self.parse_p2p_payment(data),
            "com.paypal.android.p2pmobile" | "com.coinbase.android" => self.parse_exchange(data),

            _ => Err(ForensicError::UnsupportedParser(format!(
                "Unknown finance domain: {}",
                app_domain
            ))),
        }
    }

    fn parse_crypto_wallet(&self, _data: &[u8]) -> Result<Vec<FinancialTx>, ForensicError> {
        Ok(vec![])
    }
    fn parse_defi_wallet(&self, _data: &[u8]) -> Result<Vec<FinancialTx>, ForensicError> {
        Ok(vec![])
    }
    fn parse_p2p_payment(&self, _data: &[u8]) -> Result<Vec<FinancialTx>, ForensicError> {
        Ok(vec![])
    }
    fn parse_exchange(&self, _data: &[u8]) -> Result<Vec<FinancialTx>, ForensicError> {
        Ok(vec![])
    }
}

#[derive(Debug, Clone)]
pub struct FinancialTx {
    pub timestamp: u64,
    pub tx_type: String, // "SEND", "RECEIVE", "SWAP"
    pub amount: f64,
    pub currency: String,
    pub counterparty: String,
    pub tx_hash: Option<String>,
}
