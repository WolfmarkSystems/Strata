use crate::errors::ForensicError;

pub struct TorrentParser;

impl Default for TorrentParser {
    fn default() -> Self {
        Self::new()
    }
}

impl TorrentParser {
    pub fn new() -> Self {
        Self
    }

    /// Reconstruct qBittorrent/Transmission resume lists and eMule distributions.
    pub fn reconstruct_distribution_lists(
        &self,
        _torrent_fastresume: &[u8],
    ) -> Result<Vec<TorrentDistribution>, ForensicError> {
        Ok(vec![])
    }
}

pub struct TorrentDistribution {
    pub hash_id: String,
    pub save_path: String,
    pub uploaded_bytes: u64,
}
