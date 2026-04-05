// hash/hashset.rs — NSRL / Project VIC / custom hash set matching.
// Full implementation in Task 1.6.

use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq)]
pub enum HashMatch {
    KnownGood,
    KnownBad,
    Notable,
    Unknown,
}

/// In-memory hash set for fast lookup.
#[derive(Debug, Default)]
pub struct HashSetManager {
    known_good: HashSet<String>,
    known_bad: HashSet<String>,
    notable: HashSet<String>,
}

impl HashSetManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load an NSRL RDS hashset (MD5-based, CSV format).
    pub fn load_nsrl(&mut self, path: &std::path::Path) -> anyhow::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0usize;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.to_ascii_lowercase().contains("sha-1")
                && trimmed.to_ascii_lowercase().contains("md5")
            {
                continue;
            }

            let cols = split_csv_like(trimmed);
            if cols.is_empty() {
                continue;
            }

            // NSRL commonly: SHA-1,MD5,CRC32,FileName,...
            // Prefer SHA-256 if present in newer datasets, otherwise MD5.
            let mut inserted = false;
            for col in &cols {
                if is_sha256(col) {
                    self.known_good.insert(col.to_lowercase());
                    count += 1;
                    inserted = true;
                    break;
                }
            }
            if inserted {
                continue;
            }
            for col in &cols {
                if is_md5(col) {
                    self.known_good.insert(col.to_lowercase());
                    count += 1;
                    break;
                }
            }
        }

        Ok(count)
    }

    /// Load a custom hash list from text/CSV formats.
    pub fn load_custom(&mut self, path: &std::path::Path, category: &str) -> anyhow::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0usize;
        let mut header_map: Option<std::collections::HashMap<String, usize>> = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let cols = split_csv_like(trimmed);
            if cols.is_empty() {
                continue;
            }

            if header_map.is_none() && looks_like_header(&cols) {
                let mut map = std::collections::HashMap::new();
                for (idx, col) in cols.iter().enumerate() {
                    map.insert(col.trim().to_ascii_lowercase(), idx);
                }
                header_map = Some(map);
                continue;
            }

            let mut hashes = Vec::new();
            if let Some(hmap) = &header_map {
                if let Some(idx) = hmap.get("sha256").copied() {
                    if let Some(v) = cols.get(idx).map(|v| v.trim()) {
                        if is_sha256(v) {
                            hashes.push(v.to_lowercase());
                        }
                    }
                }
                if let Some(idx) = hmap.get("md5").copied() {
                    if let Some(v) = cols.get(idx).map(|v| v.trim()) {
                        if is_md5(v) {
                            hashes.push(v.to_lowercase());
                        }
                    }
                }
            } else {
                for col in &cols {
                    let c = col.trim();
                    if is_sha256(c) || is_md5(c) {
                        hashes.push(c.to_lowercase());
                    }
                }
            }

            for h in hashes {
                let inserted = match category {
                    "KnownGood" => self.known_good.insert(h),
                    "KnownBad" => self.known_bad.insert(h),
                    _ => self.notable.insert(h),
                };
                if inserted {
                    count += 1;
                }
            }
        }

        // Fallback for one-hash-per-line files where CSV splitting returned one field.
        if count == 0 {
            for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let hash = line.trim_matches('"').to_lowercase();
                if !(is_md5(&hash) || is_sha256(&hash)) {
                    continue;
                }
                let inserted = match category {
                    "KnownGood" => self.known_good.insert(hash),
                    "KnownBad" => self.known_bad.insert(hash),
                    _ => self.notable.insert(hash),
                };
                if inserted {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Look up a hash and return its category.
    pub fn lookup(&self, hash: &str) -> HashMatch {
        let h = hash.trim().to_lowercase();
        if self.known_bad.contains(&h) {
            HashMatch::KnownBad
        } else if self.notable.contains(&h) {
            HashMatch::Notable
        } else if self.known_good.contains(&h) {
            HashMatch::KnownGood
        } else {
            HashMatch::Unknown
        }
    }

    pub fn clear(&mut self) {
        self.known_good.clear();
        self.known_bad.clear();
        self.notable.clear();
    }
}

fn split_csv_like(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ',' | '\t' if !in_quotes => {
                out.push(cur.trim().trim_matches('"').to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() || line.ends_with(',') || line.ends_with('\t') {
        out.push(cur.trim().trim_matches('"').to_string());
    }
    out
}

fn looks_like_header(cols: &[String]) -> bool {
    cols.iter().any(|c| {
        let lc = c.to_ascii_lowercase();
        lc == "sha256"
            || lc == "sha-256"
            || lc == "md5"
            || lc == "filename"
            || lc == "name"
            || lc == "known_bad"
            || lc == "category"
    })
}

fn is_md5(v: &str) -> bool {
    let s = v.trim();
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_sha256(v: &str) -> bool {
    let s = v.trim();
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}
