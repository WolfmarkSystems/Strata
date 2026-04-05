use std::collections::HashMap;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Debug, Clone)]
pub struct HashDatabase {
    entries: HashMap<HashKey, HashEntry>,
    pub index: HashIndex,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct HashKey {
    pub hash_type: HashType,
    pub hash_value: Vec<u8>,
    pub file_size: u64,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Default)]
pub enum HashType {
    #[default]
    Md5,
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, Default)]
pub struct HashEntry {
    pub file_name: Option<String>,
    pub file_size: u64,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    pub vendor_name: Option<String>,
    pub application_type: Option<String>,
    pub source: HashSource,
}

#[derive(Debug, Clone, Default)]
pub enum HashSource {
    #[default]
    NSRL,
    CustomAllowlist,
    CustomBlocklist,
    ThreatIntel,
}

#[derive(Debug, Clone, Default)]
pub struct HashIndex {
    pub md5_index: HashMap<String, Vec<HashKey>>,
    pub sha1_index: HashMap<String, Vec<HashKey>>,
    pub sha256_index: HashMap<String, Vec<HashKey>>,
    pub size_index: HashMap<u64, Vec<HashKey>>,
}

impl HashDatabase {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            index: HashIndex::default(),
        }
    }

    pub fn add_entry(&mut self, key: HashKey, entry: HashEntry) {
        self.entries.insert(key.clone(), entry);

        match key.hash_type {
            HashType::Md5 => {
                let hash_str = to_hex(&key.hash_value);
                self.index
                    .md5_index
                    .entry(hash_str)
                    .or_default()
                    .push(key.clone());
            }
            HashType::Sha1 => {
                let hash_str = to_hex(&key.hash_value);
                self.index
                    .sha1_index
                    .entry(hash_str)
                    .or_default()
                    .push(key.clone());
            }
            HashType::Sha256 => {
                let hash_str = to_hex(&key.hash_value);
                self.index
                    .sha256_index
                    .entry(hash_str)
                    .or_default()
                    .push(key.clone());
            }
        }

        self.index
            .size_index
            .entry(key.file_size)
            .or_default()
            .push(key);
    }

    pub fn lookup(&self, hash_type: HashType, hash: &[u8], size: u64) -> Vec<&HashEntry> {
        let hash_str = to_hex(hash);

        let keys = match hash_type {
            HashType::Md5 => self.index.md5_index.get(&hash_str),
            HashType::Sha1 => self.index.sha1_index.get(&hash_str),
            HashType::Sha256 => self.index.sha256_index.get(&hash_str),
        };

        match keys {
            Some(keys) => keys
                .iter()
                .filter(|k| k.file_size == size)
                .filter_map(|k| self.entries.get(k))
                .collect(),
            None => vec![],
        }
    }

    pub fn get_stats(&self) -> HashDbStats {
        HashDbStats {
            total_entries: self.entries.len(),
            md5_count: self.index.md5_index.len(),
            sha1_count: self.index.sha1_index.len(),
            sha256_count: self.index.sha256_index.len(),
        }
    }
}

impl Default for HashDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct HashDbStats {
    pub total_entries: usize,
    pub md5_count: usize,
    pub sha1_count: usize,
    pub sha256_count: usize,
}

pub fn load_hash_database(
    _path: &std::path::Path,
) -> Result<HashDatabase, crate::errors::ForensicError> {
    Ok(HashDatabase::new())
}

pub fn load_nsrl_rds(
    _path: &std::path::Path,
) -> Result<HashDatabase, crate::errors::ForensicError> {
    Ok(HashDatabase::new())
}
