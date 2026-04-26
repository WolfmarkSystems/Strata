//! Known-good hash set import and lookup.

use crate::store::get_evidence;
use crate::types::{AdapterError, AdapterResult, HashResult, HashSetInfo, HashSetStats};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet as StdHashSet;
use std::fs;
use std::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashSet {
    pub name: String,
    pub description: String,
    pub hash_count: usize,
    pub imported_at: i64,
    pub hashes: StdHashSet<String>,
}

pub static HASH_SET_STORE: Lazy<Mutex<Vec<HashSet>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn import_hash_set(name: &str, file_path: &str) -> AdapterResult<usize> {
    let raw = fs::read_to_string(file_path)?;
    let hashes = parse_hash_lines(&raw);
    let count = hashes.len();
    let set = HashSet {
        name: name.to_string(),
        description: format!("Imported from {file_path}"),
        hash_count: count,
        imported_at: crate::custody::now_unix(),
        hashes,
    };
    let mut store = HASH_SET_STORE
        .lock()
        .map_err(|e| AdapterError::EngineError(format!("hash set store poisoned: {e}")))?;
    store.retain(|existing| existing.name != name);
    store.push(set);
    Ok(count)
}

pub fn list_hash_sets() -> Vec<HashSetInfo> {
    HASH_SET_STORE
        .lock()
        .map(|store| store.iter().map(to_info).collect())
        .unwrap_or_default()
}

pub fn delete_hash_set(name: &str) -> bool {
    match HASH_SET_STORE.lock() {
        Ok(mut store) => {
            let before = store.len();
            store.retain(|set| set.name != name);
            before != store.len()
        }
        Err(_) => false,
    }
}

pub fn get_hash_set_stats(evidence_id: &str) -> HashSetStats {
    let (set_count, hash_count) = HASH_SET_STORE
        .lock()
        .map(|store| {
            (
                store.len(),
                store.iter().map(|set| set.hash_count).sum::<usize>(),
            )
        })
        .unwrap_or((0, 0));
    let (known_good, unknown) = get_evidence(evidence_id)
        .ok()
        .and_then(|arc| {
            arc.lock().ok().map(|guard| {
                (
                    guard.files.values().filter(|file| file.known_good).count() as u64,
                    guard.files.values().filter(|file| !file.known_good).count() as u64,
                )
            })
        })
        .unwrap_or((0, 0));
    HashSetStats {
        set_count,
        hash_count,
        known_good,
        unknown,
    }
}

pub fn lookup_hash_result(result: &HashResult) -> bool {
    HASH_SET_STORE
        .lock()
        .map(|store| {
            store.iter().any(|set| {
                set.hashes.contains(&result.sha256)
                    || set.hashes.contains(&result.sha1)
                    || set.hashes.contains(&result.md5)
            })
        })
        .unwrap_or(false)
}

pub fn mark_file_known_good(evidence_id: &str, file_id: &str, known_good: bool) {
    if let Ok(arc) = get_evidence(evidence_id) {
        if let Ok(mut guard) = arc.lock() {
            if let Some(file) = guard.files.get_mut(file_id) {
                file.known_good = known_good;
            }
        }
    }
}

fn parse_hash_lines(raw: &str) -> StdHashSet<String> {
    let mut hashes = StdHashSet::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("SHA-1") {
            continue;
        }
        for field in parse_csv_line(trimmed) {
            let candidate = field.trim().trim_matches('"').to_ascii_lowercase();
            if is_digest(&candidate) {
                hashes.insert(candidate);
            }
        }
    }
    hashes
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

fn is_digest(value: &str) -> bool {
    matches!(value.len(), 32 | 40 | 64) && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn to_info(set: &HashSet) -> HashSetInfo {
    HashSetInfo {
        name: set.name.clone(),
        description: set.description.clone(),
        hash_count: set.hash_count,
        imported_at: set.imported_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{insert_evidence, CachedFile};
    use std::path::PathBuf;

    fn clear_sets() {
        HASH_SET_STORE.lock().expect("hash set store").clear();
    }

    #[test]
    fn hash_set_import_single_line_format() {
        clear_sets();
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("known_good.txt");
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        fs::write(&path, format!("{hash}\n")).expect("write hash set");

        let count = import_hash_set("simple", path.to_string_lossy().as_ref()).expect("import");

        assert_eq!(count, 1);
        let imported = list_hash_sets()
            .into_iter()
            .find(|set| set.name == "simple")
            .expect("simple hash set");
        assert_eq!(imported.hash_count, 1);
    }

    #[test]
    fn hash_set_lookup_finds_known_good() {
        clear_sets();
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("nsrl.txt");
        fs::write(
            &path,
            "\"SHA-1\",\"MD5\",\"CRC32\",\"FileName\",\"FileSize\",\"ProductCode\",\"OpSystemCode\",\"SpecialCode\"\n\"a9993e364706816aba3e25717850c26c9cd0d89d\",\"900150983cd24fb0d6963f7d28e17f72\",\"00000000\",\"abc.txt\",\"3\",\"1\",\"1\",\"\"\n",
        )
        .expect("write nsrl");
        import_hash_set("nsrl", path.to_string_lossy().as_ref()).expect("import");

        let result = HashResult {
            file_id: "file-1".to_string(),
            md5: "900150983cd24fb0d6963f7d28e17f72".to_string(),
            sha1: "a9993e364706816aba3e25717850c26c9cd0d89d".to_string(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
            sha512: String::new(),
        };

        assert!(lookup_hash_result(&result));
    }

    #[test]
    fn hash_set_stats_accurate_after_hash_all() {
        clear_sets();
        let tmp = tempfile::tempdir().expect("tempdir");
        let set_path = tmp.path().join("known_good.txt");
        fs::write(
            &set_path,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n",
        )
        .expect("write hash set");
        import_hash_set("simple", set_path.to_string_lossy().as_ref()).expect("import");

        let evidence_dir = tmp.path().join("evidence");
        fs::create_dir(&evidence_dir).expect("mkdir");
        let file_path = evidence_dir.join("abc.txt");
        fs::write(&file_path, b"abc").expect("write file");
        let source = strata_fs::container::EvidenceSource::open(&evidence_dir).expect("source");
        let evidence_id = "hash-set-stats-test";
        let arc = insert_evidence(evidence_id.to_string(), source);
        {
            let mut guard = arc.lock().expect("evidence lock");
            guard.files.insert(
                "file-1".to_string(),
                CachedFile {
                    id: "file-1".to_string(),
                    vfs_path: PathBuf::from("abc.txt"),
                    name: "abc.txt".to_string(),
                    extension: "txt".to_string(),
                    size: 3,
                    modified: String::new(),
                    created: String::new(),
                    accessed: String::new(),
                    is_dir: false,
                    parent_node_id: String::new(),
                    mft_entry: None,
                    inode: None,
                    known_good: false,
                },
            );
        }

        let _ = crate::hashing::hash_all_files(evidence_id, |_done, _total| {}).expect("hash all");
        let stats = get_hash_set_stats(evidence_id);

        assert_eq!(stats.known_good, 1);
        assert_eq!(stats.unknown, 0);
        let _ = crate::store::drop_evidence(evidence_id);
    }
}
