//! Filesystem walker for the Pulse plugin.
//!
//! Matches the pattern used by `strata-plugin-recon` and friends:
//! recursively list every file under the evidence root that was
//! supplied via `PluginContext::root_path`. Symlinks are not followed
//! and recursion is bounded to avoid run-away walks of pathological
//! filesystems.
//!
//! Walking the evidence as a plain directory tree works because the
//! strata host mounts/exposes each EvidenceSource at a concrete path
//! before invoking plugins. When Pulse is later integrated with the
//! VirtualFileSystem trait directly, this module is the only piece
//! that has to change.

use std::path::{Path, PathBuf};

const MAX_DEPTH: usize = 32;

/// Recursively walk a directory, returning every file path.
///
/// Returns an empty vec if the input is not a directory or if the
/// filesystem walk fails entirely. Individual per-entry errors are
/// swallowed — forensic parsers must never panic on a weird entry.
pub fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.is_file() {
        out.push(root.to_path_buf());
        return out;
    }
    if !root.is_dir() {
        return out;
    }
    walk_inner(root, 0, &mut out);
    out
}

fn walk_inner(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth >= MAX_DEPTH {
        return;
    }
    let iter = match std::fs::read_dir(dir) {
        Ok(i) => i,
        Err(_) => return,
    };
    for entry in iter.flatten() {
        let path = entry.path();
        // Do not follow symlinks — forensic integrity.
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            walk_inner(&path, depth + 1, out);
        } else if metadata.is_file() {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn walk_empty_dir_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(walk(tmp.path()).is_empty());
    }

    #[test]
    fn walk_finds_nested_files() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("a/b/c");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("leaf.txt"), b"x").unwrap();
        fs::write(tmp.path().join("root.txt"), b"y").unwrap();
        let mut got = walk(tmp.path());
        got.sort();
        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|p| p.ends_with("leaf.txt")));
        assert!(got.iter().any(|p| p.ends_with("root.txt")));
    }

    #[test]
    fn walk_on_file_returns_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let got = walk(tmp.path());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], tmp.path());
    }

    #[test]
    fn walk_on_missing_path_returns_empty() {
        let got = walk(Path::new("/definitely/not/a/real/path/xyz"));
        assert!(got.is_empty());
    }
}
