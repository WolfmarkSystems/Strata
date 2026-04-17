use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct HashSetDB {
    md5: HashSet<String>,
    sha1: HashSet<String>,
    sha256: HashSet<String>,
}

impl HashSetDB {
    pub fn new() -> Self {
        Self {
            md5: HashSet::new(),
            sha1: HashSet::new(),
            sha256: HashSet::new(),
        }
    }

    pub fn load_from_file(path: &Path) -> Result<Self, std::io::Error> {
        let mut db = Self::new();
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.len() == 32 {
                db.md5.insert(line.to_lowercase());
            } else if line.len() == 40 {
                db.sha1.insert(line.to_lowercase());
            } else if line.len() == 64 {
                db.sha256.insert(line.to_lowercase());
            }
        }

        Ok(db)
    }

    pub fn load_nsrl_hashes(path: &Path) -> Result<Self, std::io::Error> {
        let mut db = Self::new();
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split(',').collect();

            if parts.len() >= 3 {
                if let Some(md5) = parts.first() {
                    if md5.len() == 32 {
                        db.md5.insert(md5.to_lowercase());
                    }
                }
                if let Some(sha1) = parts.get(1) {
                    if sha1.len() == 40 {
                        db.sha1.insert(sha1.to_lowercase());
                    }
                }
                if let Some(sha256) = parts.get(2) {
                    if sha256.len() == 64 {
                        db.sha256.insert(sha256.to_lowercase());
                    }
                }
            }
        }

        Ok(db)
    }

    pub fn contains_md5(&self, hash: &str) -> bool {
        self.md5.contains(&hash.to_lowercase())
    }

    pub fn contains_sha1(&self, hash: &str) -> bool {
        self.sha1.contains(&hash.to_lowercase())
    }

    pub fn contains_sha256(&self, hash: &str) -> bool {
        self.sha256.contains(&hash.to_lowercase())
    }

    pub fn contains_any(&self, hash: &str) -> bool {
        self.contains_md5(hash) || self.contains_sha1(hash) || self.contains_sha256(hash)
    }

    pub fn add_md5(&mut self, hash: &str) {
        self.md5.insert(hash.to_lowercase());
    }

    pub fn add_sha1(&mut self, hash: &str) {
        self.sha1.insert(hash.to_lowercase());
    }

    pub fn add_sha256(&mut self, hash: &str) {
        self.sha256.insert(hash.to_lowercase());
    }

    pub fn count(&self) -> usize {
        self.md5.len() + self.sha1.len() + self.sha256.len()
    }

    pub fn export_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        let mut file = std::fs::File::create(path)?;

        use std::io::Write;

        writeln!(file, "# Hash Database Export")?;
        writeln!(file, "# MD5 hashes")?;

        for hash in &self.md5 {
            writeln!(file, "{}", hash)?;
        }

        writeln!(file, "# SHA1 hashes")?;
        for hash in &self.sha1 {
            writeln!(file, "{}", hash)?;
        }

        writeln!(file, "# SHA256 hashes")?;
        for hash in &self.sha256 {
            writeln!(file, "{}", hash)?;
        }

        Ok(())
    }

    pub fn merge(&mut self, other: HashSetDB) {
        self.md5.extend(other.md5);
        self.sha1.extend(other.sha1);
        self.sha256.extend(other.sha256);
    }
}

impl Default for HashSetDB {
    fn default() -> Self {
        Self::new()
    }
}

pub mod bloom;
pub mod database;
pub mod malware_hashset;
pub mod nsrl;

pub use bloom::{BloomFilter, HashBloomFilter, HashLookupResult};
pub use database::{
    HashDatabase, HashDbStats, HashEntry, HashIndex, HashKey, HashSource, HashType,
};

use crate::hashing::{FileCategory, FileHashResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashSetError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Hash not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub filename: String,
    pub size: u64,
    pub first_seen: Option<DateTime<Utc>>,
}

pub struct HashSetManager {
    known_good: HashMap<String, FileMetadata>,
    known_bad: HashMap<String, FileMetadata>,
    os_artifacts: HashSet<String>,
}

impl HashSetManager {
    pub fn new() -> Self {
        Self {
            known_good: HashMap::new(),
            known_bad: HashMap::new(),
            os_artifacts: HashSet::new(),
        }
    }

    pub fn load_nsrl_sqlite(&mut self, _path: &Path) -> Result<(), HashSetError> {
        eprintln!("TODO: load real NSRL RDS v3 from SQLite - stub implementation");
        Ok(())
    }

    pub fn load_nsrl_csv(&mut self, path: &Path) -> Result<(), HashSetError> {
        use std::io::{BufRead, BufReader};

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split(',').collect();

            if parts.len() >= 3 {
                let sha256 = parts[2].trim().to_lowercase();
                if sha256.len() == 64 {
                    let filename = parts[1].trim().to_string();
                    let size: u64 = parts[3].trim().parse().unwrap_or(0);
                    self.known_good.insert(
                        sha256,
                        FileMetadata {
                            filename,
                            size,
                            first_seen: None,
                        },
                    );
                }
            }
        }

        Ok(())
    }

    pub fn load_malware_hashset(&mut self, path: &Path) -> Result<(), HashSetError> {
        let db = HashSetDB::load_from_file(path)?;
        for sha256 in db.sha256 {
            self.known_bad.insert(
                sha256,
                FileMetadata {
                    filename: String::new(),
                    size: 0,
                    first_seen: None,
                },
            );
        }
        Ok(())
    }

    pub fn add_known_good(&mut self, sha256: &str, metadata: FileMetadata) {
        self.known_good.insert(sha256.to_lowercase(), metadata);
    }

    pub fn add_known_bad(&mut self, sha256: &str, metadata: FileMetadata) {
        self.known_bad.insert(sha256.to_lowercase(), metadata);
    }

    pub fn add_os_artifact(&mut self, path_pattern: &str) {
        self.os_artifacts.insert(path_pattern.to_lowercase());
    }

    pub fn populate_default_os_artifacts(&mut self) {
        let patterns = [
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
            "$mft",
            "$bitmap",
            "$boot",
            "thumbs.db",
            "desktop.ini",
            "ntuser.dat",
            "ntuser.ini",
        ];
        for pattern in patterns {
            self.os_artifacts.insert(pattern.to_lowercase());
        }
    }

    pub fn categorize(&self, result: &FileHashResult) -> FileCategory {
        let path_lower = result.path.to_string_lossy().to_lowercase();
        let filename = result
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        if self.os_artifacts.contains(&filename)
            || self.os_artifacts.iter().any(|p| path_lower.ends_with(p))
        {
            return FileCategory::OSArtifact;
        }

        if self.known_bad.contains_key(&result.sha256) {
            return FileCategory::KnownBad;
        }

        if self.known_good.contains_key(&result.sha256) {
            return FileCategory::KnownGood;
        }

        FileCategory::Unknown
    }

    pub fn known_good_count(&self) -> usize {
        self.known_good.len()
    }

    pub fn known_bad_count(&self) -> usize {
        self.known_bad.len()
    }

    pub fn os_artifact_count(&self) -> usize {
        self.os_artifacts.len()
    }
}

impl Default for HashSetManager {
    fn default() -> Self {
        Self::new()
    }
}

use rusqlite::{params, Connection};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashCategory {
    KnownGood,
    KnownBad,
}

pub struct SqliteHashSetManager {
    conn: Mutex<Connection>,
    nsrl_loaded: Mutex<bool>,
    custom_loaded: Mutex<bool>,
    known_good_count: Mutex<usize>,
    known_bad_count: Mutex<usize>,
}

impl SqliteHashSetManager {
    pub fn new() -> Result<Self, HashSetError> {
        let conn =
            Connection::open_in_memory().map_err(|e| HashSetError::Database(e.to_string()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS known_good (
                sha256 TEXT PRIMARY KEY,
                filename TEXT,
                size INTEGER,
                first_seen TEXT
            );
            CREATE TABLE IF NOT EXISTS known_bad (
                sha256 TEXT PRIMARY KEY,
                filename TEXT,
                source TEXT,
                first_seen TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_kg_sha256 ON known_good(sha256);
            CREATE INDEX IF NOT EXISTS idx_kb_sha256 ON known_bad(sha256);",
        )
        .map_err(|e| HashSetError::Database(e.to_string()))?;

        Ok(Self {
            conn: Mutex::new(conn),
            nsrl_loaded: Mutex::new(false),
            custom_loaded: Mutex::new(false),
            known_good_count: Mutex::new(0),
            known_bad_count: Mutex::new(0),
        })
    }

    pub fn load_nsrl_sqlite(&self, db_path: &Path) -> Result<usize, HashSetError> {
        let nsrl_conn =
            Connection::open(db_path).map_err(|e| HashSetError::Database(e.to_string()))?;

        // Try to find any table with sha256 column
        let mut total_count = 0;

        // Get all tables
        let mut stmt = nsrl_conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .map_err(|e| HashSetError::Database(e.to_string()))?;

        let table_names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| HashSetError::Database(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        for table_name in table_names {
            // Check if table has sha256 column
            let has_sha256: bool = nsrl_conn
                .query_row(
                    &format!(
                        "SELECT COUNT(*) > 0 FROM pragma_table_info('{}') WHERE name='sha256'",
                        table_name
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(false);

            if !has_sha256 {
                continue;
            }

            // Try to insert from this table
            let insert_sql = format!(
                "INSERT OR IGNORE INTO known_good (sha256) SELECT sha256 FROM {}",
                table_name
            );

            if let Ok(local_conn) = self.conn.lock() {
                if let Ok(tx) = local_conn.unchecked_transaction() {
                    if let Ok(count) = tx.execute(&insert_sql, []) {
                        total_count += count;
                        let _ = tx.commit();
                        break;
                    }
                }
            }
        }

        if total_count > 0 {
            if let Ok(mut guard) = self.nsrl_loaded.lock() {
                *guard = true;
            }
            if let Ok(mut guard) = self.known_good_count.lock() {
                *guard += total_count;
            }
        }

        Ok(total_count)
    }

    pub fn load_custom_csv(
        &self,
        path: &Path,
        category: HashCategory,
    ) -> Result<usize, HashSetError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let table = match category {
            HashCategory::KnownGood => "known_good",
            HashCategory::KnownBad => "known_bad",
        };

        let mut count = 0;

        if let Ok(local_conn) = self.conn.lock() {
            if let Ok(tx) = local_conn.unchecked_transaction() {
                let sql = format!("INSERT OR IGNORE INTO {} (sha256) VALUES (?1)", table);
                if let Ok(mut stmt) = tx.prepare(&sql) {
                    for line in reader.lines().map_while(Result::ok) {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            continue;
                        }
                        let sha256 = if trimmed.len() == 64 {
                            trimmed.to_lowercase()
                        } else if trimmed.contains(',') {
                            trimmed
                                .split(',')
                                .next()
                                .unwrap_or("")
                                .trim()
                                .to_lowercase()
                        } else {
                            continue;
                        };

                        if sha256.len() == 64 && stmt.execute(params![sha256]).is_ok() {
                            count += 1;
                        }
                    }
                }
                let _ = tx.commit();
            }
        }

        if count > 0 {
            if category == HashCategory::KnownBad {
                if let Ok(mut guard) = self.custom_loaded.lock() {
                    *guard = true;
                }
                if let Ok(mut guard) = self.known_bad_count.lock() {
                    *guard += count;
                }
            } else if let Ok(mut guard) = self.known_good_count.lock() {
                *guard += count;
            }
        }

        Ok(count)
    }

    pub fn load_custom_sqlite(
        &self,
        path: &Path,
        category: HashCategory,
    ) -> Result<usize, HashSetError> {
        let ext_conn = Connection::open(path).map_err(|e| HashSetError::Database(e.to_string()))?;

        let table = match category {
            HashCategory::KnownGood => "known_good",
            HashCategory::KnownBad => "known_bad",
        };

        let mut count = 0;

        // Get all tables in external DB
        let mut stmt = ext_conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .map_err(|e| HashSetError::Database(e.to_string()))?;

        let table_names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| HashSetError::Database(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        for ext_table in table_names {
            let insert_sql = format!(
                "INSERT OR IGNORE INTO {} (sha256) SELECT sha256 FROM {}",
                table, ext_table
            );

            if let Ok(local_conn) = self.conn.lock() {
                if let Ok(tx) = local_conn.unchecked_transaction() {
                    if let Ok(c) = tx.execute(&insert_sql, []) {
                        count += c;
                        let _ = tx.commit();
                    }
                }
            }
        }

        if count > 0 && category == HashCategory::KnownBad {
            if let Ok(mut guard) = self.custom_loaded.lock() {
                *guard = true;
            }
            if let Ok(mut guard) = self.known_bad_count.lock() {
                *guard += count;
            }
        }

        Ok(count)
    }

    pub fn load_custom_hashset(
        &self,
        path: &Path,
        category: HashCategory,
    ) -> Result<usize, HashSetError> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "db" | "sqlite" | "sqlite3" => self.load_custom_sqlite(path, category),
            _ => self.load_custom_csv(path, category),
        }
    }

    pub fn categorize(&self, sha256: &str) -> FileCategory {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return FileCategory::Unknown,
        };

        let sha256_lower = sha256.to_lowercase();

        // Check known_bad first
        let bad_exists: bool = conn
            .query_row(
                "SELECT 1 FROM known_bad WHERE sha256 = ?1",
                params![sha256_lower],
                |_| Ok(true),
            )
            .unwrap_or(false);

        if bad_exists {
            return FileCategory::KnownBad;
        }

        // Check known_good
        let good_exists: bool = conn
            .query_row(
                "SELECT 1 FROM known_good WHERE sha256 = ?1",
                params![sha256_lower],
                |_| Ok(true),
            )
            .unwrap_or(false);

        if good_exists {
            return FileCategory::KnownGood;
        }

        FileCategory::Unknown
    }

    pub fn categorize_with_path(&self, result: &FileHashResult) -> FileCategory {
        let filename = result
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let os_artifacts = [
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
            "$mft",
            "$bitmap",
            "$boot",
            "thumbs.db",
            "desktop.ini",
            "ntuser.dat",
            "ntuser.ini",
        ];

        if os_artifacts
            .iter()
            .any(|&p| filename == p || filename.ends_with(p))
        {
            return FileCategory::OSArtifact;
        }

        self.categorize(&result.sha256)
    }

    pub fn is_loaded(&self) -> bool {
        self.nsrl_loaded.lock().map(|g| *g).unwrap_or(false)
            || self.custom_loaded.lock().map(|g| *g).unwrap_or(false)
    }

    pub fn stats(&self) -> HashSetStats {
        HashSetStats {
            known_good: self.known_good_count.lock().map(|g| *g).unwrap_or(0),
            known_bad: self.known_bad_count.lock().map(|g| *g).unwrap_or(0),
            nsrl_loaded: self.nsrl_loaded.lock().map(|g| *g).unwrap_or(false),
            custom_loaded: self.custom_loaded.lock().map(|g| *g).unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSetStats {
    pub known_good: usize,
    pub known_bad: usize,
    pub nsrl_loaded: bool,
    pub custom_loaded: bool,
}
