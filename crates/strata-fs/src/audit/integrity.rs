use crate::errors::ForensicError;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct IntegrityCheck {
    pub file_path: String,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub matches: Option<bool>,
    pub verified_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ChainOfCustody {
    pub entries: Vec<CustodyEntry>,
}

#[derive(Debug, Clone)]
pub struct CustodyEntry {
    pub timestamp: i64,
    pub action: CustodyAction,
    pub user: String,
    pub hostname: String,
    pub hash: String,
    pub notes: String,
}

#[derive(Debug, Clone)]
pub enum CustodyAction {
    Acquired,
    Examined,
    Modified,
    Transferred,
    Returned,
    Archived,
}

pub fn verify_file_integrity(
    path: &Path,
    expected_hash: &str,
) -> Result<IntegrityCheck, ForensicError> {
    let actual = sha256_file_hex(path)?;

    let expected_clean = expected_hash
        .to_uppercase()
        .replace(" ", "")
        .replace("-", "");
    let actual_clean = actual.to_uppercase();

    Ok(IntegrityCheck {
        file_path: path.display().to_string(),
        expected_hash: Some(expected_clean.clone()),
        actual_hash: Some(actual_clean.clone()),
        matches: Some(expected_clean == actual_clean),
        verified_at: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        ),
    })
}

pub fn create_integrity_baseline(
    dir_path: &Path,
) -> Result<HashMap<String, String>, ForensicError> {
    use std::collections::HashMap;

    let mut baseline = HashMap::new();

    fn walk_dir(dir: &Path, baseline: &mut HashMap<String, String>) -> Result<(), ForensicError> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                walk_dir(&path, baseline)?;
            } else if path.is_file() {
                if let Ok(hash) = sha256_file_hex(&path) {
                    baseline.insert(path.display().to_string(), hash);
                }
            }
        }
        Ok(())
    }

    walk_dir(dir_path, &mut baseline)?;
    Ok(baseline)
}

pub fn verify_baseline(baseline: &HashMap<String, String>) -> Vec<IntegrityCheck> {
    let mut results = Vec::new();

    for (path_str, expected) in baseline {
        let path = Path::new(path_str);

        if !path.exists() {
            results.push(IntegrityCheck {
                file_path: path_str.clone(),
                expected_hash: Some(expected.clone()),
                actual_hash: None,
                matches: Some(false),
                verified_at: Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64,
                ),
            });
            continue;
        }

        if let Ok(actual) = sha256_file_hex(path) {
            let expected_clean = expected.to_uppercase().replace(" ", "").replace("-", "");
            let actual_clean = actual.to_uppercase();
            let matches = expected_clean == actual_clean;
            let expected_for_report = expected_clean.clone();
            let actual_for_report = actual_clean.clone();

            results.push(IntegrityCheck {
                file_path: path_str.clone(),
                expected_hash: Some(expected_for_report),
                actual_hash: Some(actual_for_report),
                matches: Some(matches),
                verified_at: Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64,
                ),
            });
        }
    }

    results
}

pub fn export_integrity_report(
    checks: &[IntegrityCheck],
    output_path: &Path,
) -> Result<(), ForensicError> {
    let mut report = String::from("File,Expected Hash,Actual Hash,Status,Verified At\n");

    for check in checks {
        let status = match check.matches {
            Some(true) => "OK",
            Some(false) => "MODIFIED",
            None => "ERROR",
        };

        report.push_str(&format!(
            "{},{},{},{},{}\n",
            check.file_path,
            check.expected_hash.as_deref().unwrap_or("N/A"),
            check.actual_hash.as_deref().unwrap_or("N/A"),
            status,
            check.verified_at.unwrap_or(0)
        ));
    }

    std::fs::write(output_path, report)?;
    Ok(())
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
    fn verify_file_integrity_matches_expected_hash() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, b"abc").unwrap();

        let expected = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        let result = verify_file_integrity(&path, expected).unwrap();

        assert_eq!(result.matches, Some(true));
        assert_eq!(result.expected_hash.as_deref(), Some(expected));
        assert_eq!(result.actual_hash.as_deref(), Some(expected));
    }

    #[test]
    fn verify_baseline_detects_modified_file() {
        let dir = TempDir::new().unwrap();
        let file_a = dir.path().join("a.txt");
        let file_b = dir.path().join("b.txt");

        std::fs::write(&file_a, b"one").unwrap();
        std::fs::write(&file_b, b"two").unwrap();

        let baseline = create_integrity_baseline(dir.path()).unwrap();
        std::fs::write(&file_b, b"two-modified").unwrap();

        let checks = verify_baseline(&baseline);
        let modified = checks
            .iter()
            .find(|c| c.file_path == file_b.display().to_string())
            .unwrap();
        assert_eq!(modified.matches, Some(false));
    }
}
