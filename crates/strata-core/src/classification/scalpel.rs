use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub const DEFAULT_BINARY_MAX_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_TEXT_MAX_BYTES: usize = 4 * 1024 * 1024;

pub fn read_prefix(path: &Path, default_limit: usize) -> io::Result<Vec<u8>> {
    let hard_cap = limit_from_env("FORENSIC_SCALPEL_MAX_BYTES", default_limit);
    read_prefix_with_limit(path, hard_cap)
}

pub fn read_text_prefix(path: &Path, default_limit: usize) -> io::Result<String> {
    let bytes = read_prefix(
        path,
        limit_from_env("FORENSIC_SCALPEL_TEXT_MAX_BYTES", default_limit),
    )?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn limit_from_env(key: &str, default_limit: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default_limit)
}

fn read_prefix_with_limit(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; limit];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn read_prefix_caps_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.bin");
        strata_fs::write(&path, vec![0x41u8; 1024]).unwrap();

        let out = read_prefix(&path, 100).unwrap();
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn read_text_prefix_reads_lossy_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.txt");
        strata_fs::write(&path, b"hello world").unwrap();

        let out = read_text_prefix(&path, 32).unwrap();
        assert_eq!(out, "hello world");
    }
}
