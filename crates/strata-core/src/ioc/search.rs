//! Global IOC Searcher — Sprint A-2.
//!
//! Complements the existing `crate::ioc` search facilities with three
//! additional capabilities:
//!
//! 1. **Load IOCs from a flat-text file** (one indicator per line, or
//!    `hash,name,category` CSV columns).
//! 2. **Reverse extract** — scan arbitrary artifact fields for common
//!    IOC patterns (IPv4, domain, SHA256/SHA1/MD5, email, URL).
//! 3. **Search** — confidence-ranked exact matching of loaded IOCs
//!    against the free-form text in every artifact field.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use strata_plugin_sdk::Artifact;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IocError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("regex: {0}")]
    Regex(#[from] regex::Error),
    #[error("invalid input: {0}")]
    Invalid(String),
}

/// Which IOC flavour a value was recognised as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum IocType {
    IpAddress,
    Domain,
    FileHash(HashType),
    FilePath,
    RegistryKey,
    Url,
    EmailAddress,
    Username,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
}

impl IocType {
    pub fn as_str(&self) -> &'static str {
        match self {
            IocType::IpAddress => "IpAddress",
            IocType::Domain => "Domain",
            IocType::FileHash(HashType::Md5) => "Hash/MD5",
            IocType::FileHash(HashType::Sha1) => "Hash/SHA1",
            IocType::FileHash(HashType::Sha256) => "Hash/SHA256",
            IocType::FilePath => "FilePath",
            IocType::RegistryKey => "RegistryKey",
            IocType::Url => "Url",
            IocType::EmailAddress => "Email",
            IocType::Username => "Username",
        }
    }
}

/// A single indicator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ioc {
    pub ioc_type: IocType,
    pub value: String,
    pub source: String,
    /// 0.0..=1.0. Hashes and URLs are high-confidence by default;
    /// usernames and short tokens are lower.
    pub confidence: f32,
    pub mitre_technique: Option<String>,
}

/// One match produced by [`IocSearcher::search`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IocMatch {
    pub ioc: Ioc,
    /// Index of the artifact in the slice the searcher was called with.
    pub artifact_index: usize,
    /// Field whose value matched (`"title"`, `"detail"`, …).
    pub field: String,
    /// The matched fragment.
    pub snippet: String,
}

/// Bulk indicator searcher.
pub struct IocSearcher {
    indicators: Vec<Ioc>,
}

impl IocSearcher {
    pub fn new(indicators: Vec<Ioc>) -> Self {
        Self { indicators }
    }

    pub fn indicators(&self) -> &[Ioc] {
        &self.indicators
    }

    /// Load IOCs from a newline-delimited text file.
    ///
    /// Supported line shapes:
    /// * `<value>` — type auto-detected.
    /// * `<value>,<name>` — name stored in `source`.
    /// * `<value>,<name>,<category>` — category appended to `source`.
    ///
    /// Lines starting with `#` are comments. Blank lines are skipped.
    pub fn load_from_file(path: &Path) -> Result<Self, IocError> {
        let contents = fs::read_to_string(path)?;
        let source_tag = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("iocfile")
            .to_string();
        let mut out = Vec::new();
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let mut parts = trimmed.splitn(3, ',');
            let value = parts.next().unwrap_or("").trim().to_string();
            if value.is_empty() {
                continue;
            }
            let name = parts.next().map(|s| s.trim().to_string());
            let category = parts.next().map(|s| s.trim().to_string());
            let Some(ioc_type) = classify_value(&value) else {
                continue;
            };
            let mut source = source_tag.clone();
            if let Some(n) = &name {
                if !n.is_empty() {
                    source = format!("{}: {}", source, n);
                }
            }
            if let Some(c) = &category {
                if !c.is_empty() {
                    source = format!("{} ({})", source, c);
                }
            }
            out.push(Ioc {
                ioc_type,
                value,
                source,
                confidence: default_confidence(ioc_type),
                mitre_technique: mitre_for_type(ioc_type).map(|s| s.to_string()),
            });
        }
        Ok(Self::new(out))
    }

    /// Search every artifact's fields for exact-value matches against
    /// any loaded indicator. Results are returned in input order.
    pub fn search(&self, artifacts: &[Artifact]) -> Vec<IocMatch> {
        let mut out = Vec::new();
        for (idx, a) in artifacts.iter().enumerate() {
            for (field, value) in &a.data {
                for ioc in &self.indicators {
                    if value.contains(&ioc.value) {
                        out.push(IocMatch {
                            ioc: ioc.clone(),
                            artifact_index: idx,
                            field: field.clone(),
                            snippet: snippet(value, &ioc.value),
                        });
                    }
                }
            }
        }
        out
    }

    /// Extract IOC-shaped tokens from every artifact's field values.
    /// Dedupes by (type, value). Useful for building IOC lists out of
    /// an existing evidence set.
    pub fn extract_from_artifacts(artifacts: &[Artifact]) -> Vec<Ioc> {
        let patterns = match CompiledPatterns::new() {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };
        let mut seen: HashMap<(IocType, String), ()> = HashMap::new();
        let mut out = Vec::new();
        for a in artifacts {
            for (field, value) in &a.data {
                patterns.scan(value, |ioc_type, matched| {
                    if seen.insert((ioc_type, matched.to_string()), ()).is_none() {
                        out.push(Ioc {
                            ioc_type,
                            value: matched.to_string(),
                            source: format!("artifact/{}", field),
                            confidence: default_confidence(ioc_type),
                            mitre_technique: mitre_for_type(ioc_type).map(|s| s.to_string()),
                        });
                    }
                });
            }
        }
        out
    }
}

fn default_confidence(t: IocType) -> f32 {
    match t {
        IocType::FileHash(_) => 1.0,
        IocType::Url | IocType::IpAddress | IocType::EmailAddress => 0.9,
        IocType::Domain => 0.8,
        IocType::FilePath | IocType::RegistryKey => 0.7,
        IocType::Username => 0.5,
    }
}

fn mitre_for_type(t: IocType) -> Option<&'static str> {
    match t {
        IocType::FileHash(_) => Some("T1588.001"),
        IocType::Url | IocType::Domain | IocType::IpAddress => Some("T1071"),
        IocType::EmailAddress => Some("T1566"),
        _ => None,
    }
}

fn snippet(haystack: &str, needle: &str) -> String {
    if let Some(pos) = haystack.find(needle) {
        let start = pos.saturating_sub(20);
        let end = (pos + needle.len() + 20).min(haystack.len());
        haystack[start..end].to_string()
    } else {
        String::new()
    }
}

/// Classify a single value into an [`IocType`]. Returns `None` for
/// values that match no known IOC pattern.
pub fn classify_value(v: &str) -> Option<IocType> {
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    // Hashes by length.
    if v.chars().all(|c| c.is_ascii_hexdigit()) {
        match v.len() {
            32 => return Some(IocType::FileHash(HashType::Md5)),
            40 => return Some(IocType::FileHash(HashType::Sha1)),
            64 => return Some(IocType::FileHash(HashType::Sha256)),
            _ => {}
        }
    }
    if v.starts_with("http://") || v.starts_with("https://") {
        return Some(IocType::Url);
    }
    if v.contains('@') && v.contains('.') {
        return Some(IocType::EmailAddress);
    }
    if is_ipv4(v) {
        return Some(IocType::IpAddress);
    }
    if v.starts_with("HKEY_") || v.starts_with("HKLM\\") || v.starts_with("HKCU\\") {
        return Some(IocType::RegistryKey);
    }
    if v.contains(':') && (v.contains('\\') || v.contains('/')) {
        return Some(IocType::FilePath);
    }
    if is_domain(v) {
        return Some(IocType::Domain);
    }
    None
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 3
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
    })
}

fn is_domain(s: &str) -> bool {
    if !s.contains('.') || s.contains(' ') {
        return false;
    }
    if s.chars()
        .next()
        .map(|c| !c.is_ascii_alphanumeric())
        .unwrap_or(true)
    {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Compiled regex pattern battery for extraction mode.
struct CompiledPatterns {
    ipv4: Regex,
    sha256: Regex,
    sha1: Regex,
    md5: Regex,
    email: Regex,
    url: Regex,
    domain: Regex,
}

impl CompiledPatterns {
    fn new() -> Result<Self, IocError> {
        Ok(Self {
            ipv4: Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")?,
            sha256: Regex::new(r"\b[0-9a-fA-F]{64}\b")?,
            sha1: Regex::new(r"\b[0-9a-fA-F]{40}\b")?,
            md5: Regex::new(r"\b[0-9a-fA-F]{32}\b")?,
            email: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")?,
            url: Regex::new(r#"https?://[^\s<>"{}|\\^\[\]]+"#)?,
            domain: Regex::new(
                r"\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}(?:\.[a-zA-Z0-9\-]{1,63})+\.[a-zA-Z]{2,24}\b",
            )?,
        })
    }

    fn scan<F>(&self, text: &str, mut cb: F)
    where
        F: FnMut(IocType, &str),
    {
        // Order: most specific → least specific. A SHA256 would also
        // match SHA1 / MD5 prefixes, so try 256 first.
        for m in self.sha256.find_iter(text) {
            cb(IocType::FileHash(HashType::Sha256), m.as_str());
        }
        for m in self.sha1.find_iter(text) {
            if m.as_str().len() == 40 {
                cb(IocType::FileHash(HashType::Sha1), m.as_str());
            }
        }
        for m in self.md5.find_iter(text) {
            if m.as_str().len() == 32 {
                cb(IocType::FileHash(HashType::Md5), m.as_str());
            }
        }
        for m in self.url.find_iter(text) {
            cb(IocType::Url, m.as_str());
        }
        for m in self.email.find_iter(text) {
            cb(IocType::EmailAddress, m.as_str());
        }
        for m in self.ipv4.find_iter(text) {
            if is_ipv4(m.as_str()) {
                cb(IocType::IpAddress, m.as_str());
            }
        }
        for m in self.domain.find_iter(text) {
            // Avoid double-reporting a URL's host as a bare domain.
            let v = m.as_str();
            if !text.contains(&format!("://{}", v)) {
                cb(IocType::Domain, v);
            }
        }
    }
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_value_recognises_common_shapes() {
        assert_eq!(classify_value("10.0.0.1"), Some(IocType::IpAddress));
        assert_eq!(
            classify_value("00112233445566778899aabbccddeeff"),
            Some(IocType::FileHash(HashType::Md5))
        );
        assert_eq!(
            classify_value(&"a".repeat(40)),
            Some(IocType::FileHash(HashType::Sha1))
        );
        assert_eq!(
            classify_value(&"a".repeat(64)),
            Some(IocType::FileHash(HashType::Sha256))
        );
        assert_eq!(classify_value("https://example.com/x"), Some(IocType::Url));
        assert_eq!(
            classify_value("user@example.com"),
            Some(IocType::EmailAddress)
        );
        assert_eq!(classify_value("example.com"), Some(IocType::Domain));
        assert_eq!(
            classify_value("C:\\Windows\\System32"),
            Some(IocType::FilePath)
        );
        assert_eq!(
            classify_value("HKLM\\Software\\Foo"),
            Some(IocType::RegistryKey)
        );
        assert_eq!(classify_value("not-an-ioc"), None);
    }

    #[test]
    fn load_from_file_parses_plain_hashes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("iocs.txt");
        std::fs::write(
            &path,
            concat!(
                "# comment\n",
                "00112233445566778899aabbccddeeff\n",
                "10.0.0.1,Known scanner,Scan\n",
                "\n",
                "evil.example.com\n",
            ),
        )
        .expect("write");
        let s = IocSearcher::load_from_file(&path).expect("load");
        assert_eq!(s.indicators().len(), 3);
        let types: Vec<IocType> = s.indicators().iter().map(|i| i.ioc_type).collect();
        assert!(types.contains(&IocType::FileHash(HashType::Md5)));
        assert!(types.contains(&IocType::IpAddress));
        assert!(types.contains(&IocType::Domain));
    }

    #[test]
    fn search_finds_exact_matches_in_artifact_fields() {
        let mut a = Artifact::new("PE File", "/evidence/x");
        a.add_field("title", "malware drop");
        a.add_field(
            "detail",
            "C2 contacted 10.0.0.5 and dropped file with SHA256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let iocs = vec![
            Ioc {
                ioc_type: IocType::IpAddress,
                value: "10.0.0.5".to_string(),
                source: "feed".to_string(),
                confidence: 1.0,
                mitre_technique: Some("T1071".to_string()),
            },
            Ioc {
                ioc_type: IocType::FileHash(HashType::Sha256),
                value: "a".repeat(64),
                source: "feed".to_string(),
                confidence: 1.0,
                mitre_technique: Some("T1588.001".to_string()),
            },
        ];
        let s = IocSearcher::new(iocs);
        let hits = s.search(&[a]);
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().any(|h| h.ioc.ioc_type == IocType::IpAddress));
        assert!(hits
            .iter()
            .any(|h| matches!(h.ioc.ioc_type, IocType::FileHash(HashType::Sha256))));
    }

    #[test]
    fn extract_from_artifacts_dedupes_across_fields() {
        let mut a = Artifact::new("Event", "/evidence/a");
        a.add_field("detail", "reach out to https://malicious.test/payload");
        a.add_field("note", "also seen at https://malicious.test/payload");
        let iocs = IocSearcher::extract_from_artifacts(&[a]);
        let urls: Vec<&Ioc> = iocs.iter().filter(|i| i.ioc_type == IocType::Url).collect();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].value, "https://malicious.test/payload");
    }

    #[test]
    fn extract_from_artifacts_pulls_ips_hashes_emails() {
        let mut a = Artifact::new("Event", "/evidence/a");
        a.add_field(
            "detail",
            &format!(
                "ip=192.0.2.55 hash={} email=bad@example.org",
                "b".repeat(64)
            ),
        );
        let iocs = IocSearcher::extract_from_artifacts(&[a]);
        assert!(iocs.iter().any(|i| i.value == "192.0.2.55"));
        assert!(iocs
            .iter()
            .any(|i| i.ioc_type == IocType::FileHash(HashType::Sha256) && i.value.len() == 64));
        assert!(iocs
            .iter()
            .any(|i| i.ioc_type == IocType::EmailAddress && i.value == "bad@example.org"));
    }

    #[test]
    fn default_confidence_ranks_hashes_highest() {
        assert!(
            default_confidence(IocType::FileHash(HashType::Sha256))
                > default_confidence(IocType::Domain)
        );
        assert!(default_confidence(IocType::Username) < default_confidence(IocType::IpAddress));
    }
}
