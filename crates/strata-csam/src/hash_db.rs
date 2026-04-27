//! CSAM hash database — exact-match lookup against examiner-imported
//! hash sets.
//!
//! Strata never bundles CSAM hash data. Examiners import their own
//! vetted hash sets through `CsamHashDb::import_from_file`. Three
//! input formats are supported:
//!
//! 1. **NCMEC-compatible** — line-oriented MD5 list, optional `#`
//!    comment header containing `NCMEC`, 32-hex-char body lines.
//! 2. **Project VIC VICS** — JSON document with `version` + `hashSets`.
//! 3. **Generic hash list** — line-oriented, format inferred from the
//!    length of the first non-comment line (32/40/64 = MD5/SHA1/SHA256).

use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use crate::MatchType;

#[derive(Debug)]
pub struct CsamHashDb {
    pub name: String,
    pub source_format: HashSetFormat,
    pub imported_at: chrono::DateTime<chrono::Utc>,
    pub imported_by: String,
    pub entry_count: usize,
    pub(crate) md5_set: HashSet<String>,
    pub(crate) sha1_set: HashSet<String>,
    pub(crate) sha256_set: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashSetFormat {
    NcmecMd5,
    ProjectVicVics,
    GenericMd5,
    GenericSha1,
    GenericSha256,
}

impl HashSetFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashSetFormat::NcmecMd5 => "NCMEC MD5",
            HashSetFormat::ProjectVicVics => "Project VIC VICS",
            HashSetFormat::GenericMd5 => "Generic MD5",
            HashSetFormat::GenericSha1 => "Generic SHA1",
            HashSetFormat::GenericSha256 => "Generic SHA256",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// VICS schema (subset — only fields we need)
// Real Project VIC files contain many more fields per hash entry
// (category, description, victim identifiers, etc.). We deliberately
// ignore those — Strata only consumes the hash columns. Unknown
// fields are silently dropped by serde.
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct VicsDocument {
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<String>,
    #[serde(default, rename = "hashSets")]
    hash_sets: Vec<VicsHashSet>,
}

#[derive(Debug, serde::Deserialize)]
struct VicsHashSet {
    #[serde(default)]
    #[allow(dead_code)]
    #[serde(rename = "hashSetId")]
    hash_set_id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
    #[serde(default)]
    hashes: Vec<VicsHashEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct VicsHashEntry {
    #[serde(default)]
    md5: Option<String>,
    #[serde(default)]
    sha1: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────
// Public import API
// ──────────────────────────────────────────────────────────────────────

impl CsamHashDb {
    /// Import a hash set from a file. Format is auto-detected.
    ///
    /// `examiner` is the human-readable name recorded for chain of
    /// custody. `name` is the display label for the hash set.
    pub fn import_from_file(path: &Path, examiner: &str, name: &str) -> Result<Self> {
        let mut file = File::open(path)
            .with_context(|| format!("opening hash set file {}", path.display()))?;

        // Sniff the first non-whitespace byte to decide JSON vs. line-based.
        // VICS files can be very large too, so we re-open for the actual
        // parse rather than buffering both attempts.
        let mut sniff = [0u8; 64];
        let n = file.read(&mut sniff).context("reading hash set header")?;
        let head = &sniff[..n];

        let first_non_ws = head.iter().find(|b| !b.is_ascii_whitespace()).copied();

        if first_non_ws == Some(b'{') {
            return Self::import_vics(path, examiner, name);
        }

        Self::import_line_based(path, examiner, name)
    }

    fn import_vics(path: &Path, examiner: &str, name: &str) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("opening VICS file {}", path.display()))?;
        let reader = BufReader::new(file);
        let doc: VicsDocument =
            serde_json::from_reader(reader).context("parsing VICS JSON document")?;

        let mut md5_set = HashSet::new();
        let mut sha1_set = HashSet::new();
        let mut sha256_set = HashSet::new();
        let mut entry_count = 0usize;

        for set in &doc.hash_sets {
            for entry in &set.hashes {
                let mut had_any = false;
                if let Some(h) = &entry.md5 {
                    let normalized = normalize_hash(h, 32)?;
                    md5_set.insert(normalized);
                    had_any = true;
                }
                if let Some(h) = &entry.sha1 {
                    let normalized = normalize_hash(h, 40)?;
                    sha1_set.insert(normalized);
                    had_any = true;
                }
                if let Some(h) = &entry.sha256 {
                    let normalized = normalize_hash(h, 64)?;
                    sha256_set.insert(normalized);
                    had_any = true;
                }
                if had_any {
                    entry_count += 1;
                }
            }
        }

        if entry_count == 0 {
            bail!("VICS document contained no hash entries");
        }

        Ok(Self {
            name: name.to_string(),
            source_format: HashSetFormat::ProjectVicVics,
            imported_at: chrono::Utc::now(),
            imported_by: examiner.to_string(),
            entry_count,
            md5_set,
            sha1_set,
            sha256_set,
        })
    }

    fn import_line_based(path: &Path, examiner: &str, name: &str) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("opening hash list {}", path.display()))?;
        let reader = BufReader::new(file);

        let mut md5_set = HashSet::new();
        let mut sha1_set = HashSet::new();
        let mut sha256_set = HashSet::new();
        let mut detected_len: Option<usize> = None;
        let mut comment_block_mentions_ncmec = false;
        let mut entry_count = 0usize;
        let mut still_in_header_comments = true;

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.with_context(|| format!("reading line {}", line_no + 1))?;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            if let Some(comment_body) = trimmed.strip_prefix('#') {
                if still_in_header_comments && comment_body.to_ascii_uppercase().contains("NCMEC") {
                    comment_block_mentions_ncmec = true;
                }
                continue;
            }

            still_in_header_comments = false;

            // Body line — must be a single hex hash, length consistent
            // with whatever the first line established.
            let len = trimmed.len();
            match detected_len {
                None => {
                    if !matches!(len, 32 | 40 | 64) {
                        bail!(
                            "line {}: hash length {} is not 32/40/64 (MD5/SHA1/SHA256)",
                            line_no + 1,
                            len
                        );
                    }
                    detected_len = Some(len);
                }
                Some(expected) if expected != len => {
                    bail!(
                        "line {}: mixed hash lengths in single file ({} vs {}). \
                         A single hash list must contain only one hash type.",
                        line_no + 1,
                        len,
                        expected
                    );
                }
                _ => {}
            }

            let normalized =
                normalize_hash(trimmed, len).with_context(|| format!("line {}", line_no + 1))?;

            match len {
                32 => {
                    md5_set.insert(normalized);
                }
                40 => {
                    sha1_set.insert(normalized);
                }
                64 => {
                    sha256_set.insert(normalized);
                }
                _ => unreachable!(),
            }
            entry_count += 1;
        }

        let detected_len =
            detected_len.ok_or_else(|| anyhow!("hash list contained no hash entries"))?;

        let format = match (detected_len, comment_block_mentions_ncmec) {
            (32, true) => HashSetFormat::NcmecMd5,
            (32, false) => HashSetFormat::GenericMd5,
            (40, _) => HashSetFormat::GenericSha1,
            (64, _) => HashSetFormat::GenericSha256,
            _ => unreachable!(),
        };

        Ok(Self {
            name: name.to_string(),
            source_format: format,
            imported_at: chrono::Utc::now(),
            imported_by: examiner.to_string(),
            entry_count,
            md5_set,
            sha1_set,
            sha256_set,
        })
    }

    // ──────────────────────────────────────────────────────────────
    // Lookup
    // ──────────────────────────────────────────────────────────────

    pub fn lookup_md5(&self, hash: &str) -> bool {
        self.md5_set.contains(&hash.to_ascii_lowercase())
    }

    pub fn lookup_sha1(&self, hash: &str) -> bool {
        self.sha1_set.contains(&hash.to_ascii_lowercase())
    }

    pub fn lookup_sha256(&self, hash: &str) -> bool {
        self.sha256_set.contains(&hash.to_ascii_lowercase())
    }

    /// Look up a file by all three hashes at once. Returns the
    /// strongest match found (SHA256 > SHA1 > MD5), or `None`.
    pub fn lookup_any(&self, md5: &str, sha1: &str, sha256: &str) -> Option<MatchType> {
        if !sha256.is_empty() && self.lookup_sha256(sha256) {
            Some(MatchType::ExactSha256)
        } else if !sha1.is_empty() && self.lookup_sha1(sha1) {
            Some(MatchType::ExactSha1)
        } else if !md5.is_empty() && self.lookup_md5(md5) {
            Some(MatchType::ExactMd5)
        } else {
            None
        }
    }
}

/// Validate that `hash` is `expected_len` ASCII hex characters and
/// return it lowercased. Whitespace inside the string is rejected —
/// callers should trim before calling.
fn normalize_hash(hash: &str, expected_len: usize) -> Result<String> {
    if hash.len() != expected_len {
        bail!(
            "hash length {} does not match expected {}",
            hash.len(),
            expected_len
        );
    }
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("hash contains non-hex characters: {}", hash);
    }
    Ok(hash.to_ascii_lowercase())
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn ncmec_md5_import() {
        let content = "\
# NCMEC Hash Set
# Generated: 2024-01-01
d41d8cd98f00b204e9800998ecf8427e
e2fc714c4727ee9395f324cd2e7f331f
";
        let f = write_temp(content);
        let db = CsamHashDb::import_from_file(f.path(), "examiner1", "ncmec_test").unwrap();
        assert_eq!(db.source_format, HashSetFormat::NcmecMd5);
        assert_eq!(db.entry_count, 2);
        assert!(db.lookup_md5("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(db.lookup_md5("D41D8CD98F00B204E9800998ECF8427E")); // case-insensitive
        assert!(!db.lookup_md5("00000000000000000000000000000000"));
    }

    #[test]
    fn generic_md5_import_no_ncmec_marker() {
        let content = "\
d41d8cd98f00b204e9800998ecf8427e
e2fc714c4727ee9395f324cd2e7f331f
";
        let f = write_temp(content);
        let db = CsamHashDb::import_from_file(f.path(), "ex", "g").unwrap();
        assert_eq!(db.source_format, HashSetFormat::GenericMd5);
        assert_eq!(db.entry_count, 2);
    }

    #[test]
    fn generic_sha1_import() {
        let content = "\
da39a3ee5e6b4b0d3255bfef95601890afd80709
2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
";
        let f = write_temp(content);
        let db = CsamHashDb::import_from_file(f.path(), "ex", "g").unwrap();
        assert_eq!(db.source_format, HashSetFormat::GenericSha1);
        assert_eq!(db.entry_count, 2);
        assert!(db.lookup_sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assert!(!db.lookup_md5("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }

    #[test]
    fn generic_sha256_import() {
        let content = "\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
";
        let f = write_temp(content);
        let db = CsamHashDb::import_from_file(f.path(), "ex", "g").unwrap();
        assert_eq!(db.source_format, HashSetFormat::GenericSha256);
        assert!(
            db.lookup_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn vics_json_import() {
        let content = r#"{
            "version": "1.3",
            "hashSets": [
                {
                    "hashSetId": "set-001",
                    "name": "Test Set",
                    "hashes": [
                        {
                            "md5": "d41d8cd98f00b204e9800998ecf8427e",
                            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        },
                        {
                            "md5": "e2fc714c4727ee9395f324cd2e7f331f"
                        }
                    ]
                }
            ]
        }"#;
        let f = write_temp(content);
        let db = CsamHashDb::import_from_file(f.path(), "ex", "vics_test").unwrap();
        assert_eq!(db.source_format, HashSetFormat::ProjectVicVics);
        assert_eq!(db.entry_count, 2);
        assert!(db.lookup_md5("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(db.lookup_sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assert!(
            db.lookup_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn lookup_any_prefers_strongest() {
        let content = "\
# NCMEC
d41d8cd98f00b204e9800998ecf8427e
";
        let f = write_temp(content);
        let db = CsamHashDb::import_from_file(f.path(), "ex", "n").unwrap();
        let m = db.lookup_any("d41d8cd98f00b204e9800998ecf8427e", "", "");
        assert_eq!(m, Some(MatchType::ExactMd5));
        assert_eq!(
            db.lookup_any("00000000000000000000000000000000", "", ""),
            None
        );
    }

    #[test]
    fn rejects_mixed_hash_lengths() {
        let content = "\
d41d8cd98f00b204e9800998ecf8427e
da39a3ee5e6b4b0d3255bfef95601890afd80709
";
        let f = write_temp(content);
        let err = CsamHashDb::import_from_file(f.path(), "ex", "x").unwrap_err();
        assert!(err.to_string().contains("mixed hash lengths"));
    }

    #[test]
    fn rejects_non_hex_characters() {
        let content = "zzzd8cd98f00b204e9800998ecf8427e\n";
        let f = write_temp(content);
        let err = CsamHashDb::import_from_file(f.path(), "ex", "x").unwrap_err();
        // anyhow's `Display` shows only the top-level context (the line
        // number wrap); the underlying "non-hex" message is in the chain.
        // `{:#}` walks the full chain.
        let full = format!("{:#}", err);
        assert!(full.contains("non-hex"), "got: {}", full);
    }

    #[test]
    fn rejects_empty_file() {
        let f = write_temp("# only comments\n# nothing else\n");
        let err = CsamHashDb::import_from_file(f.path(), "ex", "x").unwrap_err();
        assert!(err.to_string().contains("no hash entries"));
    }

    #[test]
    fn rejects_empty_vics() {
        let content = r#"{"version": "1.3", "hashSets": []}"#;
        let f = write_temp(content);
        let err = CsamHashDb::import_from_file(f.path(), "ex", "x").unwrap_err();
        assert!(err.to_string().contains("no hash entries"));
    }
}
