use crate::errors::ForensicError;
use blake3::Hasher as Blake3Hasher;
use chrono::{DateTime, Utc};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

pub fn hash_bytes(data: &[u8]) -> HashResults {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut blake3 = Blake3Hasher::new();

    md5.update(data);
    sha1.update(data);
    sha256.update(data);
    blake3.update(data);

    HashResults {
        md5: Some(format!("{:x}", md5.finalize())),
        sha1: Some(format!("{:x}", sha1.finalize())),
        sha256: Some(format!("{:x}", sha256.finalize())),
        blake3: Some(format!("{}", blake3.finalize())),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashResults {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub blake3: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHashResult {
    pub path: PathBuf,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: String,
    pub blake3: Option<String>,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
}

pub fn hash_file(path: &Path) -> Result<FileHashResult, ForensicError> {
    if !path.exists() {
        return Err(ForensicError::NotFound(path.display().to_string()));
    }

    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(ForensicError::MalformedData(format!(
            "Not a file: {}",
            path.display()
        )));
    }

    let mut file = File::open(path).map_err(ForensicError::Io)?;
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut blake3 = Blake3Hasher::new();
    let mut buffer = [0u8; 131072];

    let size = metadata.len();

    loop {
        let bytes_read = file.read(&mut buffer).map_err(ForensicError::Io)?;
        if bytes_read == 0 {
            break;
        }
        md5.update(&buffer[..bytes_read]);
        sha1.update(&buffer[..bytes_read]);
        sha256.update(&buffer[..bytes_read]);
        blake3.update(&buffer[..bytes_read]);
    }

    let md5_hex = format!("{:x}", md5.finalize());
    let sha1_hex = format!("{:x}", sha1.finalize());
    let sha256_hex = format!("{:x}", sha256.finalize());
    let blake3_hex = format!("{}", blake3.finalize());

    let modified = metadata.modified().ok().map(DateTime::<Utc>::from);

    Ok(FileHashResult {
        path: path.to_path_buf(),
        md5: Some(md5_hex),
        sha1: Some(sha1_hex),
        sha256: sha256_hex,
        blake3: Some(blake3_hex),
        size,
        modified,
    })
}
