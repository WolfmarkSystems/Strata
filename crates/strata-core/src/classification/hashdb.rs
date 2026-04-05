use std::path::Path;

#[derive(Debug, Clone)]
pub struct HashDbEntry {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub file_size: u64,
    pub file_name: Option<String>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
}

pub struct HashDatabase {
    md5_index: std::collections::HashMap<String, HashDbEntry>,
    sha1_index: std::collections::HashMap<String, HashDbEntry>,
    sha256_index: std::collections::HashMap<String, HashDbEntry>,
    loaded: bool,
    entry_count: usize,
}

impl HashDatabase {
    pub fn new() -> Self {
        Self {
            md5_index: std::collections::HashMap::new(),
            sha1_index: std::collections::HashMap::new(),
            sha256_index: std::collections::HashMap::new(),
            loaded: false,
            entry_count: 0,
        }
    }

    pub fn load_nsrl<R: std::io::BufRead>(reader: &mut R) -> Result<Self, std::io::Error> {
        let mut db = Self::new();
        let mut line = String::new();

        let mut count = 0;
        let max_entries = 1_000_000;

        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }

            if count >= max_entries {
                break;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                let md5 = parts.first().map(|s| s.to_lowercase());
                let sha1 = parts.get(1).map(|s| s.to_lowercase());
                let sha256 = parts.get(2).map(|s| s.to_lowercase());
                let size: u64 = parts
                    .get(3)
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);

                let entry = HashDbEntry {
                    md5: md5.clone(),
                    sha1: sha1.clone(),
                    sha256: sha256.clone(),
                    file_size: size,
                    file_name: parts.get(4).map(|s| s.to_string()),
                    product_name: None,
                    product_version: None,
                };

                if let Some(ref m) = md5 {
                    db.md5_index.insert(m.clone(), entry.clone());
                }
                if let Some(ref s) = sha1 {
                    db.sha1_index.insert(s.clone(), entry.clone());
                }
                if let Some(ref s) = sha256 {
                    db.sha256_index.insert(s.clone(), entry.clone());
                }

                count += 1;
            }
        }

        db.loaded = true;
        db.entry_count = count;
        Ok(db)
    }

    pub fn from_file(path: &Path) -> Result<Self, std::io::Error> {
        let file = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::new(file);
        Self::load_nsrl(&mut reader)
    }

    pub fn lookup_md5(&self, hash: &str) -> Option<&HashDbEntry> {
        self.md5_index.get(&hash.to_lowercase())
    }

    pub fn lookup_sha1(&self, hash: &str) -> Option<&HashDbEntry> {
        self.sha1_index.get(&hash.to_lowercase())
    }

    pub fn lookup_sha256(&self, hash: &str) -> Option<&HashDbEntry> {
        self.sha256_index.get(&hash.to_lowercase())
    }

    pub fn is_known(&self, hash: &str) -> bool {
        let h = hash.to_lowercase();
        self.md5_index.contains_key(&h)
            || self.sha1_index.contains_key(&h)
            || self.sha256_index.contains_key(&h)
    }

    #[allow(dead_code)]
    pub fn is_known_evil(&self, hash: &str) -> bool {
        self.is_known(hash)
    }

    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }
}

impl Default for HashDatabase {
    fn default() -> Self {
        Self::new()
    }
}

pub fn check_hash_against_db(db: &HashDatabase, hash: &str) -> Option<HashDbEntry> {
    db.lookup_md5(hash)
        .or_else(|| db.lookup_sha1(hash))
        .or_else(|| db.lookup_sha256(hash))
        .cloned()
}
