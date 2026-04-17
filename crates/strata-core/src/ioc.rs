//! Global IOC (Indicator of Compromise) search across all plugin outputs.
//!
//! The examiner enters one or more IOCs — IP addresses, domains, hashes,
//! emails, usernames, phone numbers, cryptocurrency addresses — and
//! Strata searches every artifact from every plugin simultaneously.

use serde::{Deserialize, Serialize};
use strata_plugin_sdk::{ArtifactRecord, PluginOutput};

pub mod feed_ui;
pub mod search;

/// Supported IOC types with automatic detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
    Username,
    Phone,
    BitcoinAddress,
    EthereumAddress,
    Unknown,
}

impl IocType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Domain => "Domain",
            Self::Url => "URL",
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Email => "Email",
            Self::Username => "Username",
            Self::Phone => "Phone",
            Self::BitcoinAddress => "Bitcoin",
            Self::EthereumAddress => "Ethereum",
            Self::Unknown => "Unknown",
        }
    }
}

/// A single IOC query with automatic type detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocQuery {
    pub raw_value: String,
    pub normalized: String,
    pub ioc_type: IocType,
}

impl IocQuery {
    /// Create a new IOC query with automatic type detection.
    pub fn new(value: &str) -> Self {
        let trimmed = value.trim().to_string();
        let ioc_type = detect_ioc_type(&trimmed);
        let normalized = normalize_ioc(&trimmed, &ioc_type);
        Self {
            raw_value: trimmed,
            normalized,
            ioc_type,
        }
    }

    /// Parse multiple IOCs from a multi-line string (one per line).
    pub fn parse_bulk(text: &str) -> Vec<Self> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(Self::new)
            .collect()
    }

    /// Parse IOCs from a CSV file (first column is the IOC value).
    pub fn parse_csv(text: &str) -> Vec<Self> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| l.split(',').next())
            .map(|v| v.trim().trim_matches('"'))
            .filter(|v| !v.is_empty() && !v.eq_ignore_ascii_case("indicator") && !v.eq_ignore_ascii_case("ioc"))
            .map(Self::new)
            .collect()
    }
}

/// A match result — one IOC matched in one artifact field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocHit {
    pub query: IocQuery,
    pub plugin_name: String,
    pub artifact_title: String,
    pub artifact_subcategory: String,
    pub matched_field: String,
    pub matched_value: String,
    pub context: String,
    pub source_path: String,
    pub timestamp: Option<i64>,
    pub is_suspicious: bool,
}

/// Configuration for IOC search.
#[derive(Debug, Clone)]
pub struct IocSearchConfig {
    pub case_sensitive: bool,
    pub fuzzy: bool,
    pub max_hits_per_ioc: usize,
}

impl Default for IocSearchConfig {
    fn default() -> Self {
        Self {
            case_sensitive: false,
            fuzzy: false,
            max_hits_per_ioc: 1000,
        }
    }
}

/// Search all plugin outputs for IOC matches.
pub fn search_artifacts(
    queries: &[IocQuery],
    outputs: &[PluginOutput],
    config: &IocSearchConfig,
) -> Vec<IocHit> {
    let mut hits = Vec::new();

    for query in queries {
        let mut query_hits = 0usize;
        let needle = if config.case_sensitive {
            query.normalized.clone()
        } else {
            query.normalized.to_lowercase()
        };

        for output in outputs {
            for record in &output.artifacts {
                if query_hits >= config.max_hits_per_ioc {
                    break;
                }

                let fields: [(&str, &str); 5] = [
                    ("title", &record.title),
                    ("detail", &record.detail),
                    ("subcategory", &record.subcategory),
                    ("source_path", &record.source_path),
                    ("raw_data", &record.raw_data.as_ref().map(|v| v.to_string()).unwrap_or_default()),
                ];

                for (field_name, field_value) in &fields {
                    let haystack = if config.case_sensitive {
                        field_value.to_string()
                    } else {
                        field_value.to_lowercase()
                    };

                    let matched = if config.fuzzy {
                        fuzzy_contains(&haystack, &needle)
                    } else {
                        haystack.contains(&needle)
                    };

                    if matched {
                        let context = extract_context(field_value, &query.normalized, 80);
                        hits.push(IocHit {
                            query: query.clone(),
                            plugin_name: output.plugin_name.clone(),
                            artifact_title: record.title.clone(),
                            artifact_subcategory: record.subcategory.clone(),
                            matched_field: field_name.to_string(),
                            matched_value: query.normalized.clone(),
                            context,
                            source_path: record.source_path.clone(),
                            timestamp: record.timestamp,
                            is_suspicious: record.is_suspicious,
                        });
                        query_hits += 1;
                        break;
                    }
                }
            }
        }
    }

    hits
}

/// Group hits by IOC query value.
pub fn group_by_ioc(hits: &[IocHit]) -> Vec<(&str, Vec<&IocHit>)> {
    let mut groups: std::collections::BTreeMap<&str, Vec<&IocHit>> =
        std::collections::BTreeMap::new();
    for hit in hits {
        groups
            .entry(hit.query.normalized.as_str())
            .or_default()
            .push(hit);
    }
    groups.into_iter().collect()
}

/// Export IOC search results as CSV.
pub fn export_csv(hits: &[IocHit]) -> String {
    let mut out = String::from("IOC,IOC_Type,Plugin,Artifact,Field,Context,Source,Timestamp,Suspicious\n");
    for h in hits {
        out.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            escape_csv(&h.query.normalized),
            h.query.ioc_type.label(),
            escape_csv(&h.plugin_name),
            escape_csv(&h.artifact_title),
            h.matched_field,
            escape_csv(&h.context),
            escape_csv(&h.source_path),
            h.timestamp.map(|t| t.to_string()).unwrap_or_default(),
            h.is_suspicious,
        ));
    }
    out
}

/// Export IOC search results as JSON.
pub fn export_json(hits: &[IocHit]) -> String {
    serde_json::to_string_pretty(hits).unwrap_or_else(|_| "[]".to_string())
}

// ── Type detection ──────────────────────────────────────────────────

fn detect_ioc_type(value: &str) -> IocType {
    let v = value.trim();

    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("ftp://") {
        return IocType::Url;
    }
    if is_ipv4(v) {
        return IocType::Ipv4;
    }
    if is_ipv6(v) {
        return IocType::Ipv6;
    }
    if is_email(v) {
        return IocType::Email;
    }
    if is_phone(v) {
        return IocType::Phone;
    }
    if is_bitcoin(v) {
        return IocType::BitcoinAddress;
    }
    if is_ethereum(v) {
        return IocType::EthereumAddress;
    }
    if is_hash(v) == Some(IocType::Sha256) {
        return IocType::Sha256;
    }
    if is_hash(v) == Some(IocType::Sha1) {
        return IocType::Sha1;
    }
    if is_hash(v) == Some(IocType::Md5) {
        return IocType::Md5;
    }
    if is_domain(v) {
        return IocType::Domain;
    }
    if v.starts_with('@') || (!v.contains(' ') && !v.contains('.') && v.len() >= 3) {
        return IocType::Username;
    }

    IocType::Unknown
}

fn is_ipv4(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn is_ipv6(v: &str) -> bool {
    if !v.contains(':') || v.contains('@') {
        return false;
    }
    let parts: Vec<&str> = v.split(':').collect();
    if parts.len() < 3 {
        return false;
    }
    parts.iter().all(|p| p.is_empty() || p.len() <= 4 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_email(v: &str) -> bool {
    let parts: Vec<&str> = v.split('@').collect();
    parts.len() == 2
        && !parts[0].is_empty()
        && parts[1].contains('.')
        && parts[1].len() >= 3
        && !parts[0].contains(' ')
}

fn is_phone(v: &str) -> bool {
    let digits: String = v.chars().filter(|c| c.is_ascii_digit()).collect();
    let cleaned = v.trim_start_matches('+');
    digits.len() >= 10
        && digits.len() <= 15
        && cleaned
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == ' ' || c == '(' || c == ')' || c == '+')
}

fn is_bitcoin(v: &str) -> bool {
    (v.starts_with('1') || v.starts_with('3') || v.starts_with("bc1"))
        && v.len() >= 26
        && v.len() <= 62
        && v.chars().all(|c| c.is_ascii_alphanumeric())
}

fn is_ethereum(v: &str) -> bool {
    v.starts_with("0x") && v.len() == 42 && v[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn is_hash(v: &str) -> Option<IocType> {
    if !v.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    match v.len() {
        64 => Some(IocType::Sha256),
        40 => Some(IocType::Sha1),
        32 => Some(IocType::Md5),
        _ => None,
    }
}

fn is_domain(v: &str) -> bool {
    if v.contains(' ') || v.starts_with('.') || v.starts_with('-') {
        return false;
    }
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let tld = parts.last().unwrap();
    tld.len() >= 2
        && tld.len() <= 12
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

fn normalize_ioc(value: &str, ioc_type: &IocType) -> String {
    let v = value.trim();
    match ioc_type {
        IocType::Md5 | IocType::Sha1 | IocType::Sha256 => v.to_lowercase(),
        IocType::Email => v.to_lowercase(),
        IocType::Domain => v.to_lowercase().trim_end_matches('.').to_string(),
        IocType::Url => v.to_string(),
        IocType::EthereumAddress => v.to_lowercase(),
        _ => v.to_string(),
    }
}

fn fuzzy_contains(haystack: &str, needle: &str) -> bool {
    if haystack.contains(needle) {
        return true;
    }
    if needle.len() < 4 {
        return false;
    }
    let prefix = &needle[..needle.len() * 3 / 4];
    haystack.contains(prefix)
}

fn extract_context(field_value: &str, needle: &str, window: usize) -> String {
    let lower = field_value.to_lowercase();
    let needle_lower = needle.to_lowercase();
    if let Some(pos) = lower.find(&needle_lower) {
        let start = pos.saturating_sub(window);
        let end = (pos + needle.len() + window).min(field_value.len());
        let mut ctx = String::new();
        if start > 0 {
            ctx.push_str("...");
        }
        ctx.push_str(&field_value[start..end]);
        if end < field_value.len() {
            ctx.push_str("...");
        }
        ctx
    } else {
        field_value.chars().take(200).collect()
    }
}

fn escape_csv(s: &str) -> String {
    s.replace('"', "\"\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_plugin_sdk::*;

    fn make_output(plugin: &str, title: &str, detail: &str) -> PluginOutput {
        PluginOutput {
            plugin_name: plugin.to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![ArtifactRecord {
                category: ArtifactCategory::NetworkArtifacts,
                subcategory: "test".to_string(),
                timestamp: Some(1700000000),
                title: title.to_string(),
                detail: detail.to_string(),
                source_path: "/evidence/test".to_string(),
                forensic_value: ForensicValue::High,
                mitre_technique: None,
                is_suspicious: false,
                raw_data: None,
                confidence: 0,
            }],
            summary: PluginSummary {
                total_artifacts: 1,
                suspicious_count: 0,
                categories_populated: vec![],
                headline: String::new(),
            },
            warnings: vec![],
        }
    }

    #[test]
    fn detect_ioc_types_correctly() {
        assert_eq!(IocQuery::new("192.168.1.1").ioc_type, IocType::Ipv4);
        assert_eq!(IocQuery::new("2001:db8::1").ioc_type, IocType::Ipv6);
        assert_eq!(IocQuery::new("evil.example.com").ioc_type, IocType::Domain);
        assert_eq!(IocQuery::new("https://evil.com/shell.php").ioc_type, IocType::Url);
        assert_eq!(
            IocQuery::new("d41d8cd98f00b204e9800998ecf8427e").ioc_type,
            IocType::Md5
        );
        assert_eq!(
            IocQuery::new("da39a3ee5e6b4b0d3255bfef95601890afd80709").ioc_type,
            IocType::Sha1
        );
        assert_eq!(
            IocQuery::new("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .ioc_type,
            IocType::Sha256
        );
        assert_eq!(IocQuery::new("user@evil.com").ioc_type, IocType::Email);
        assert_eq!(IocQuery::new("+1-555-867-5309").ioc_type, IocType::Phone);
        assert_eq!(
            IocQuery::new("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").ioc_type,
            IocType::BitcoinAddress
        );
        assert_eq!(
            IocQuery::new("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD10").ioc_type,
            IocType::EthereumAddress
        );
        assert_eq!(IocQuery::new("@threat_actor").ioc_type, IocType::Username);
    }

    #[test]
    fn search_finds_ip_in_artifact_detail() {
        let outputs = vec![make_output(
            "NetFlow",
            "Connection",
            "Outbound connection to 10.0.0.42 on port 443",
        )];
        let queries = vec![IocQuery::new("10.0.0.42")];
        let hits = search_artifacts(&queries, &outputs, &IocSearchConfig::default());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].plugin_name, "NetFlow");
        assert_eq!(hits[0].matched_field, "detail");
        assert!(hits[0].context.contains("10.0.0.42"));
    }

    #[test]
    fn search_finds_hash_case_insensitive() {
        let outputs = vec![make_output(
            "Vector",
            "Malware scan",
            "SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        )];
        let queries = vec![IocQuery::new(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )];
        let hits = search_artifacts(&queries, &outputs, &IocSearchConfig::default());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].query.ioc_type, IocType::Sha256);
    }

    #[test]
    fn search_returns_empty_for_no_match() {
        let outputs = vec![make_output("Trace", "Normal activity", "Nothing here")];
        let queries = vec![IocQuery::new("evil.example.com")];
        let hits = search_artifacts(&queries, &outputs, &IocSearchConfig::default());
        assert!(hits.is_empty());
    }

    #[test]
    fn bulk_parse_handles_comments_and_blanks() {
        let text = "# IOC list\n192.168.1.1\n\nevil.com\n# another comment\nuser@bad.com";
        let queries = IocQuery::parse_bulk(text);
        assert_eq!(queries.len(), 3);
        assert_eq!(queries[0].ioc_type, IocType::Ipv4);
        assert_eq!(queries[1].ioc_type, IocType::Domain);
        assert_eq!(queries[2].ioc_type, IocType::Email);
    }

    #[test]
    fn csv_parse_skips_header() {
        let text = "indicator,type,source\n192.168.1.1,ip,feed\nevil.com,domain,feed";
        let queries = IocQuery::parse_csv(text);
        assert_eq!(queries.len(), 2);
    }

    #[test]
    fn group_by_ioc_aggregates_hits() {
        let outputs = vec![
            make_output("Plugin1", "Title1", "Contact 10.0.0.1 seen"),
            make_output("Plugin2", "Title2", "Also 10.0.0.1 in log"),
        ];
        let queries = vec![IocQuery::new("10.0.0.1")];
        let hits = search_artifacts(&queries, &outputs, &IocSearchConfig::default());
        let groups = group_by_ioc(&hits);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "10.0.0.1");
        assert_eq!(groups[0].1.len(), 2);
    }

    #[test]
    fn export_csv_includes_headers() {
        let hits = vec![IocHit {
            query: IocQuery::new("10.0.0.1"),
            plugin_name: "Test".to_string(),
            artifact_title: "Title".to_string(),
            artifact_subcategory: "sub".to_string(),
            matched_field: "detail".to_string(),
            matched_value: "10.0.0.1".to_string(),
            context: "context".to_string(),
            source_path: "/test".to_string(),
            timestamp: Some(1700000000),
            is_suspicious: false,
        }];
        let csv = export_csv(&hits);
        assert!(csv.starts_with("IOC,IOC_Type,"));
        assert!(csv.contains("10.0.0.1"));
        assert!(csv.contains("IPv4"));
    }

    #[test]
    fn fuzzy_match_finds_partial() {
        let outputs = vec![make_output(
            "Browser",
            "Visit",
            "Connected to malicious-domain-variant.example.com",
        )];
        let queries = vec![IocQuery::new("malicious-domain")];
        let config = IocSearchConfig {
            fuzzy: true,
            ..Default::default()
        };
        let hits = search_artifacts(&queries, &outputs, &config);
        assert!(!hits.is_empty());
    }

    #[test]
    fn max_hits_per_ioc_is_respected() {
        let mut outputs = Vec::new();
        for i in 0..10 {
            outputs.push(make_output(
                &format!("Plugin{}", i),
                &format!("Title{}", i),
                "Contains 10.0.0.1 in every record",
            ));
        }
        let queries = vec![IocQuery::new("10.0.0.1")];
        let config = IocSearchConfig {
            max_hits_per_ioc: 3,
            ..Default::default()
        };
        let hits = search_artifacts(&queries, &outputs, &config);
        assert_eq!(hits.len(), 3);
    }
}
