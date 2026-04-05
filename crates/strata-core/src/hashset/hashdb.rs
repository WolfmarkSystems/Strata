use crate::errors::ForensicError;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct HashSetDb {
    pub name: String,
    pub hashes: HashSet<String>,
    pub hash_type: HashType,
    pub entry_count: usize,
    pub known_bad: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
    Any,
}

pub fn load_nsrl_hashset(path: &Path) -> Result<HashSetDb, ForensicError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut hashes = HashSet::new();
    let mut count = 0;

    for line in reader.lines() {
        let line = line?;
        count += 1;

        if count == 1 && line.contains("SHA-1") {
            continue;
        }

        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split(',').collect();
        if parts.is_empty() {
            continue;
        }

        let hash = parts[0].trim().to_uppercase();
        if hash.len() >= 32 {
            hashes.insert(hash);
        }
    }

    Ok(HashSetDb {
        name: "NSRL".to_string(),
        hashes,
        hash_type: HashType::SHA1,
        entry_count: hashes.len(),
        known_bad: false,
    })
}

pub fn load_custom_hashset(
    path: &Path,
    hash_type: HashType,
    known_bad: bool,
) -> Result<HashSetDb, ForensicError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut hashes = HashSet::new();
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "Custom".to_string());

    for line in reader.lines() {
        let line = line?;

        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        let hash = line.trim().to_uppercase();

        match hash_type {
            HashType::MD5 => {
                if hash.len() == 32 {
                    hashes.insert(hash);
                }
            }
            HashType::SHA1 => {
                if hash.len() == 40 {
                    hashes.insert(hash);
                }
            }
            HashType::SHA256 => {
                if hash.len() == 64 {
                    hashes.insert(hash);
                }
            }
            HashType::Any => {
                if hash.len() == 32 || hash.len() == 40 || hash.len() == 64 {
                    hashes.insert(hash);
                }
            }
        }
    }

    Ok(HashSetDb {
        name,
        hashes,
        hash_type,
        entry_count: hashes.len(),
        known_bad,
    })
}

#[derive(Debug, Clone)]
pub struct HashMatch {
    pub hash: String,
    pub matched: bool,
    pub database_name: String,
    pub is_known_bad: bool,
}

pub fn check_hash(hash: &str, databases: &[HashSetDb]) -> Option<HashMatch> {
    let upper_hash = hash.to_uppercase();

    for db in databases {
        if db.hashes.contains(&upper_hash) {
            return Some(HashMatch {
                hash: upper_hash.clone(),
                matched: true,
                database_name: db.name.clone(),
                is_known_bad: db.known_bad,
            });
        }
    }

    None
}

pub fn find_duplicate_files(dir_path: &Path) -> Result<Vec<Vec<String>>, ForensicError> {
    use std::collections::HashMap;

    let mut hash_map: HashMap<String, Vec<String>> = HashMap::new();

    fn walk_dir(
        dir: &Path,
        hash_map: &mut HashMap<String, Vec<String>>,
    ) -> Result<(), ForensicError> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                walk_dir(&path, hash_map)?;
            } else if path.is_file() {
                if let Ok(hash) = sha256_file_hex(&path) {
                    hash_map
                        .entry(hash)
                        .or_default()
                        .push(path.display().to_string());
                }
            }
        }
        Ok(())
    }

    walk_dir(dir_path, &mut hash_map)?;

    let duplicates: Vec<Vec<String>> = hash_map
        .into_iter()
        .filter(|(_, files)| files.len() > 1)
        .map(|(_, files)| files)
        .collect();

    Ok(duplicates)
}

fn sha256_file_hex(path: &Path) -> Result<String, ForensicError> {
    use sha2::{Digest, Sha256};

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn find_duplicate_files_groups_same_content() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");
        let c = dir.path().join("c.bin");

        std::fs::write(&a, b"same-content").unwrap();
        std::fs::write(&b, b"same-content").unwrap();
        std::fs::write(&c, b"different-content").unwrap();

        let groups = find_duplicate_files(dir.path()).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);

        let mut dup_paths = groups[0].clone();
        dup_paths.sort();
        assert!(dup_paths.contains(&a.display().to_string()));
        assert!(dup_paths.contains(&b.display().to_string()));
    }
}
