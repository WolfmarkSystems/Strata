use std::collections::HashSet;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub struct BloomFilter {
    bits: Vec<bool>,
    size: usize,
    hash_count: usize,
}

impl BloomFilter {
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let size = (-(expected_items as f64) * false_positive_rate.ln() / (2.0_f64.ln().powi(2)))
            .ceil() as usize;
        let hash_count = ((size as f64 / expected_items as f64) * 2.0_f64.ln()).ceil() as usize;

        Self {
            bits: vec![false; size],
            size,
            hash_count: hash_count.max(1),
        }
    }

    pub fn insert(&mut self, item: &[u8]) {
        for i in 0..self.hash_count {
            let idx = self.hash(item, i) % self.size;
            self.bits[idx] = true;
        }
    }

    pub fn might_contain(&self, item: &[u8]) -> bool {
        for i in 0..self.hash_count {
            let idx = self.hash(item, i) % self.size;
            if !self.bits[idx] {
                return false;
            }
        }
        true
    }

    fn hash(&self, item: &[u8], seed: usize) -> usize {
        let mut h = 1469598103934665603u64;

        for (i, &byte) in item.iter().enumerate() {
            h ^= (byte as u64).wrapping_mul((i + seed + 1) as u64);
            h = h.wrapping_mul(1099511828211u64);
        }

        (h as usize).wrapping_mul(seed + 1) % self.size
    }

    pub fn false_positive_rate(&self, item_count: usize) -> f64 {
        let k = self.hash_count as f64;
        let m = self.size as f64;
        let n = item_count as f64;

        (1.0 - (-k * n / m).exp()).powf(k)
    }
}

pub struct HashBloomFilter {
    md5_filter: BloomFilter,
    sha1_filter: BloomFilter,
    sha256_filter: BloomFilter,
    md5_set: HashSet<String>,
    sha1_set: HashSet<String>,
    sha256_set: HashSet<String>,
}

impl HashBloomFilter {
    pub fn new(expected_items: usize) -> Self {
        Self {
            md5_filter: BloomFilter::new(expected_items, 0.01),
            sha1_filter: BloomFilter::new(expected_items, 0.01),
            sha256_filter: BloomFilter::new(expected_items, 0.01),
            md5_set: HashSet::new(),
            sha1_set: HashSet::new(),
            sha256_set: HashSet::new(),
        }
    }

    pub fn add_md5(&mut self, hash: &[u8]) {
        let hash_str = to_hex(hash);
        self.md5_filter.insert(hash.as_ref());
        self.md5_set.insert(hash_str);
    }

    pub fn add_sha1(&mut self, hash: &[u8]) {
        let hash_str = to_hex(hash);
        self.sha1_filter.insert(hash.as_ref());
        self.sha1_set.insert(hash_str);
    }

    pub fn add_sha256(&mut self, hash: &[u8]) {
        let hash_str = to_hex(hash);
        self.sha256_filter.insert(hash.as_ref());
        self.sha256_set.insert(hash_str);
    }

    pub fn might_contain_md5(&self, hash: &[u8]) -> bool {
        self.md5_filter.might_contain(hash)
    }

    pub fn might_contain_sha1(&self, hash: &[u8]) -> bool {
        self.sha1_filter.might_contain(hash)
    }

    pub fn might_contain_sha256(&self, hash: &[u8]) -> bool {
        self.sha256_filter.might_contain(hash)
    }

    pub fn contains_md5(&self, hash: &[u8]) -> bool {
        let hash_str = to_hex(hash);
        self.md5_set.contains(&hash_str)
    }

    pub fn contains_sha1(&self, hash: &[u8]) -> bool {
        let hash_str = to_hex(hash);
        self.sha1_set.contains(&hash_str)
    }

    pub fn contains_sha256(&self, hash: &[u8]) -> bool {
        let hash_str = to_hex(hash);
        self.sha256_set.contains(&hash_str)
    }

    pub fn check_and_confirm_md5(&self, hash: &[u8]) -> HashLookupResult {
        if !self.might_contain_md5(hash) {
            return HashLookupResult::NotFound;
        }

        if self.contains_md5(hash) {
            HashLookupResult::Found
        } else {
            HashLookupResult::PossibleMatch
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HashLookupResult {
    Found,
    NotFound,
    PossibleMatch,
}
