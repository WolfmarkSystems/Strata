use serde::{Deserialize, Serialize};

pub const SCANNER_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocRule {
    pub id: i64,
    pub name: String,
    pub rule_type: IocRuleType,
    pub severity: IocSeverity,
    pub enabled: bool,
    pub pattern: String,
    pub hash_type: Option<String>,
    pub scope: IocScope,
    pub tags: Vec<String>,
    pub created_utc: String,
    pub updated_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IocRuleType {
    HASH,
    PATH,
    REGEX,
    KEYWORD,
}

impl std::fmt::Display for IocRuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocRuleType::HASH => write!(f, "HASH"),
            IocRuleType::PATH => write!(f, "PATH"),
            IocRuleType::REGEX => write!(f, "REGEX"),
            IocRuleType::KEYWORD => write!(f, "KEYWORD"),
        }
    }
}

impl std::str::FromStr for IocRuleType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "HASH" => Ok(IocRuleType::HASH),
            "PATH" => Ok(IocRuleType::PATH),
            "REGEX" => Ok(IocRuleType::REGEX),
            "KEYWORD" => Ok(IocRuleType::KEYWORD),
            _ => Err(format!("Unknown rule type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IocSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

impl std::fmt::Display for IocSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocSeverity::LOW => write!(f, "LOW"),
            IocSeverity::MEDIUM => write!(f, "MEDIUM"),
            IocSeverity::HIGH => write!(f, "HIGH"),
            IocSeverity::CRITICAL => write!(f, "CRITICAL"),
        }
    }
}

impl std::str::FromStr for IocSeverity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "LOW" => Ok(IocSeverity::LOW),
            "MEDIUM" => Ok(IocSeverity::MEDIUM),
            "HIGH" => Ok(IocSeverity::HIGH),
            "CRITICAL" => Ok(IocSeverity::CRITICAL),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

impl IocSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            IocSeverity::LOW => "LOW",
            IocSeverity::MEDIUM => "MEDIUM",
            IocSeverity::HIGH => "HIGH",
            IocSeverity::CRITICAL => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocScope {
    pub targets: Vec<String>,
    pub extensions: Vec<String>,
    pub max_size: Option<u64>,
}

impl Default for IocScope {
    fn default() -> Self {
        Self {
            targets: vec!["file_path".to_string(), "strings".to_string()],
            extensions: vec![],
            max_size: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocHit {
    pub id: i64,
    pub case_id: String,
    pub rule_id: i64,
    pub hit_utc: String,
    pub target_type: String,
    pub target_id: String,
    pub target_path: Option<String>,
    pub matched_field: String,
    pub matched_value: String,
    pub context: IocHitContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocHitContext {
    pub evidence_id: Option<String>,
    pub volume_id: Option<String>,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocScanOptions {
    pub include_files: bool,
    pub include_strings: bool,
    pub include_timeline: bool,
    pub severities: Option<Vec<String>>,
    pub rule_names: Option<Vec<String>>,
    pub path_prefix: Option<String>,
    pub max_hits: Option<u64>,
    pub emit_exhibits: bool,
    pub emit_timeline_events: bool,
    pub tag_hits: bool,
}

impl Default for IocScanOptions {
    fn default() -> Self {
        Self {
            include_files: true,
            include_strings: true,
            include_timeline: true,
            severities: None,
            rule_names: None,
            path_prefix: None,
            max_hits: Some(100000),
            emit_exhibits: true,
            emit_timeline_events: true,
            tag_hits: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocScanResult {
    pub rules_scanned: usize,
    pub hits_written: usize,
    pub exhibits_created: usize,
    pub timeline_events_added: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocRuleInput {
    pub name: String,
    pub rule_type: String,
    pub severity: String,
    pub pattern: String,
    pub hash_type: Option<String>,
    pub tags: Vec<String>,
    pub scope: Option<IocScope>,
}

pub fn create_ioc_rule(input: &IocRuleInput) -> IocRule {
    let now = chrono::Utc::now().to_rfc3339();
    let scope = input.scope.clone().unwrap_or_default();

    IocRule {
        id: 0,
        name: input.name.clone(),
        rule_type: input.rule_type.parse().unwrap_or(IocRuleType::KEYWORD),
        severity: input.severity.parse().unwrap_or(IocSeverity::MEDIUM),
        enabled: true,
        pattern: input.pattern.clone(),
        hash_type: input.hash_type.clone(),
        scope,
        tags: input.tags.clone(),
        created_utc: now.clone(),
        updated_utc: now,
    }
}

pub fn match_hash(rule: &IocRule, hash_value: &str) -> bool {
    if rule.rule_type != IocRuleType::HASH {
        return false;
    }

    let target_hash = hash_value.to_lowercase();
    let pattern = rule.pattern.to_lowercase();

    if let Some(hash_type) = &rule.hash_type {
        match hash_type.to_uppercase().as_str() {
            "MD5" => target_hash.len() == 32 && target_hash == pattern,
            "SHA1" => target_hash.len() == 40 && target_hash == pattern,
            "SHA256" => target_hash.len() == 64 && target_hash == pattern,
            _ => target_hash.contains(&pattern),
        }
    } else {
        target_hash.contains(&pattern)
    }
}

pub fn match_path(rule: &IocRule, path: &str) -> bool {
    if rule.rule_type != IocRuleType::PATH {
        return false;
    }

    let path_lower = path.to_lowercase();
    let pattern_lower = rule.pattern.to_lowercase();

    if rule.pattern.contains('*') {
        let pattern = pattern_lower.replace('*', "");
        path_lower.contains(&pattern)
    } else if rule.pattern.contains('?') {
        let pattern = pattern_lower.replace('?', ".");
        regex::Regex::new(&pattern)
            .map(|re| re.is_match(&path_lower))
            .unwrap_or(false)
    } else {
        path_lower.contains(&pattern_lower) || path_lower.ends_with(&pattern_lower)
    }
}

pub fn match_regex(rule: &IocRule, text: &str) -> bool {
    if rule.rule_type != IocRuleType::REGEX {
        return false;
    }

    regex::Regex::new(&rule.pattern)
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

pub fn match_keyword(rule: &IocRule, text: &str) -> bool {
    if rule.rule_type != IocRuleType::KEYWORD {
        return false;
    }

    let text_lower = text.to_lowercase();
    let pattern_lower = rule.pattern.to_lowercase();

    text_lower.contains(&pattern_lower)
}

pub fn scan_text_for_rule(rule: &IocRule, text: &str, max_len: usize) -> Vec<String> {
    let text_trunc = if text.len() > max_len {
        &text[..max_len]
    } else {
        text
    };

    let mut matches = Vec::new();

    match rule.rule_type {
        IocRuleType::HASH => {
            for hash in extract_hashes(text_trunc) {
                if match_hash(rule, &hash) {
                    matches.push(hash);
                }
            }
        }
        IocRuleType::PATH => {
            for path in extract_paths(text_trunc) {
                if match_path(rule, &path) {
                    matches.push(path);
                }
            }
        }
        IocRuleType::REGEX => {
            if let Ok(re) = regex::Regex::new(&rule.pattern) {
                for mat in re.find_iter(text_trunc) {
                    matches.push(mat.as_str().to_string());
                }
            }
        }
        IocRuleType::KEYWORD => {
            if match_keyword(rule, text_trunc) {
                matches.push(rule.pattern.clone());
            }
        }
    }

    matches
}

fn extract_hashes(text: &str) -> Vec<String> {
    let mut hashes = Vec::new();

    let md5_re = regex::Regex::new(r"\b([a-fA-F0-9]{32})\b").unwrap();
    let sha1_re = regex::Regex::new(r"\b([a-fA-F0-9]{40})\b").unwrap();
    let sha256_re = regex::Regex::new(r"\b([a-fA-F0-9]{64})\b").unwrap();

    for cap in md5_re.captures_iter(text) {
        hashes.push(cap[1].to_lowercase());
    }
    for cap in sha1_re.captures_iter(text) {
        hashes.push(cap[1].to_lowercase());
    }
    for cap in sha256_re.captures_iter(text) {
        hashes.push(cap[1].to_lowercase());
    }

    hashes
}

fn extract_paths(text: &str) -> Vec<String> {
    let mut paths = Vec::new();

    let win_path_re = regex::Regex::new(r#"[A-Za-z]:\\[^<>:*?"\/|]+"#).unwrap();
    let unix_path_re = regex::Regex::new(r#"(?:/[^/\x00]+)+"#).unwrap();

    for cap in win_path_re.captures_iter(text) {
        paths.push(cap[0].to_string());
    }
    for cap in unix_path_re.captures_iter(text) {
        if cap[0].len() > 3 {
            paths.push(cap[0].to_string());
        }
    }

    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_hash_sha256() {
        let rule = IocRule {
            id: 1,
            name: "Test SHA256".to_string(),
            rule_type: IocRuleType::HASH,
            severity: IocSeverity::HIGH,
            enabled: true,
            pattern: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            hash_type: Some("SHA256".to_string()),
            scope: IocScope::default(),
            tags: vec![],
            created_utc: "".to_string(),
            updated_utc: "".to_string(),
        };

        assert!(match_hash(
            &rule,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(!match_hash(
            &rule,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    #[test]
    fn test_match_hash_md5() {
        let rule = IocRule {
            id: 1,
            name: "Test MD5".to_string(),
            rule_type: IocRuleType::HASH,
            severity: IocSeverity::HIGH,
            enabled: true,
            pattern: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            hash_type: Some("MD5".to_string()),
            scope: IocScope::default(),
            tags: vec![],
            created_utc: "".to_string(),
            updated_utc: "".to_string(),
        };

        assert!(match_hash(&rule, "d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn test_match_path() {
        let rule = IocRule {
            id: 1,
            name: "Test Path".to_string(),
            rule_type: IocRuleType::PATH,
            severity: IocSeverity::MEDIUM,
            enabled: true,
            pattern: "malware.exe".to_string(),
            hash_type: None,
            scope: IocScope::default(),
            tags: vec![],
            created_utc: "".to_string(),
            updated_utc: "".to_string(),
        };

        assert!(match_path(&rule, "C:\\Users\\test\\malware.exe"));
        assert!(match_path(&rule, "/tmp/malware.exe"));
        assert!(!match_path(&rule, "C:\\Users\\test\\benign.exe"));
    }

    #[test]
    fn test_match_path_wildcard() {
        let rule = IocRule {
            id: 1,
            name: "Test Path Wildcard".to_string(),
            rule_type: IocRuleType::PATH,
            severity: IocSeverity::MEDIUM,
            enabled: true,
            pattern: "*\\temp\\*".to_string(),
            hash_type: None,
            scope: IocScope::default(),
            tags: vec![],
            created_utc: "".to_string(),
            updated_utc: "".to_string(),
        };

        assert!(match_path(&rule, "C:\\Users\\test\\temp\\file.exe"));
        assert!(match_path(&rule, "D:\\temp\\malware.exe"));
    }

    #[test]
    fn test_match_regex() {
        let rule = IocRule {
            id: 1,
            name: "Test Regex URL".to_string(),
            rule_type: IocRuleType::REGEX,
            severity: IocSeverity::HIGH,
            enabled: true,
            pattern: r"https?://[^\s]+".to_string(),
            hash_type: None,
            scope: IocScope::default(),
            tags: vec![],
            created_utc: "".to_string(),
            updated_utc: "".to_string(),
        };

        assert!(match_regex(&rule, "Visit https://evil.com for more"));
        assert!(match_regex(&rule, "http://test.org"));
        assert!(!match_regex(&rule, "no url here"));
    }

    #[test]
    fn test_match_keyword() {
        let rule = IocRule {
            id: 1,
            name: "Test Keyword".to_string(),
            rule_type: IocRuleType::KEYWORD,
            severity: IocSeverity::MEDIUM,
            enabled: true,
            pattern: "password".to_string(),
            hash_type: None,
            scope: IocScope::default(),
            tags: vec![],
            created_utc: "".to_string(),
            updated_utc: "".to_string(),
        };

        assert!(match_keyword(&rule, "Enter your password here"));
        assert!(match_keyword(&rule, "PASSWORD"));
        assert!(!match_keyword(&rule, "no match"));
    }

    #[test]
    fn test_scan_text_for_rule_regex() {
        let rule = IocRule {
            id: 1,
            name: "URL Scanner".to_string(),
            rule_type: IocRuleType::REGEX,
            severity: IocSeverity::HIGH,
            enabled: true,
            pattern: r"https?://[^\s]+".to_string(),
            hash_type: None,
            scope: IocScope::default(),
            tags: vec!["network".to_string()],
            created_utc: "".to_string(),
            updated_utc: "".to_string(),
        };

        let text = "Check https://evil.com and http://test.org for info";
        let matches = scan_text_for_rule(&rule, text, 1000);

        assert!(matches.len() >= 2);
    }

    #[test]
    fn test_scan_text_for_rule_hash() {
        let rule = IocRule {
            id: 1,
            name: "Hash Scanner".to_string(),
            rule_type: IocRuleType::HASH,
            severity: IocSeverity::HIGH,
            enabled: true,
            pattern: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            hash_type: Some("MD5".to_string()),
            scope: IocScope::default(),
            tags: vec![],
            created_utc: "".to_string(),
            updated_utc: "".to_string(),
        };

        let text = "Found hash: d41d8cd98f00b204e9800998ecf8427e in file";
        let matches = scan_text_for_rule(&rule, text, 1000);

        assert!(!matches.is_empty());
    }

    #[test]
    fn test_determinism() {
        let rule = IocRule {
            id: 1,
            name: "URL Scanner".to_string(),
            rule_type: IocRuleType::REGEX,
            severity: IocSeverity::HIGH,
            enabled: true,
            pattern: r"https?://[^\s]+".to_string(),
            hash_type: None,
            scope: IocScope::default(),
            tags: vec![],
            created_utc: "".to_string(),
            updated_utc: "".to_string(),
        };

        let text = "Check https://evil.com and http://test.org for info";

        let result1 = scan_text_for_rule(&rule, text, 1000);
        let result2 = scan_text_for_rule(&rule, text, 1000);

        assert_eq!(result1.len(), result2.len());
        assert_eq!(result1, result2);
    }
}
