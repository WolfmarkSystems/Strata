use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreWeights {
    pub ioc_hit: f64,
    pub high_entropy: f64,
    pub very_high_entropy: f64,
    pub suspicious_path: f64,
    pub suspicious_ext: f64,
    pub double_extension: f64,
    pub recent_modified: f64,
    pub recent_created: f64,
    pub from_carving: f64,
    pub has_urls_in_strings: f64,
    pub has_emails_in_strings: f64,
    pub has_ipv4_in_strings: f64,
    pub executable_in_user_dir: f64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            ioc_hit: 50.0,
            high_entropy: 20.0,
            very_high_entropy: 35.0,
            suspicious_path: 20.0,
            suspicious_ext: 15.0,
            double_extension: 10.0,
            recent_modified: 10.0,
            recent_created: 8.0,
            from_carving: 12.0,
            has_urls_in_strings: 8.0,
            has_emails_in_strings: 6.0,
            has_ipv4_in_strings: 6.0,
            executable_in_user_dir: 18.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreSignal {
    pub key: String,
    pub points: f64,
    pub evidence: String,
}

impl ScoreSignal {
    pub fn new(key: &str, points: f64, evidence: &str) -> Self {
        Self {
            key: key.to_string(),
            points,
            evidence: evidence.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreResult {
    pub score: f64,
    pub signals: Vec<ScoreSignal>,
}

impl ScoreResult {
    pub fn new(score: f64, signals: Vec<ScoreSignal>) -> Self {
        Self {
            score: score.clamp(0.0, 100.0),
            signals,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileTableRowLike {
    pub id: i64,
    pub source_type: String,
    pub source_id: String,
    pub evidence_id: Option<String>,
    pub volume_id: Option<String>,
    pub path: String,
    pub name: String,
    pub extension: Option<String>,
    pub size_bytes: Option<u64>,
    pub modified_utc: Option<String>,
    pub created_utc: Option<String>,
    pub entropy: Option<f64>,
    pub category: Option<String>,
    pub score: f64,
    pub tags: Vec<String>,
    pub summary_json: serde_json::Value,
}

impl FileTableRowLike {
    #[allow(clippy::too_many_arguments)]
    pub fn from_row(
        id: i64,
        source_type: String,
        source_id: String,
        evidence_id: Option<String>,
        volume_id: Option<String>,
        path: String,
        name: String,
        extension: Option<String>,
        size_bytes: Option<u64>,
        modified_utc: Option<String>,
        created_utc: Option<String>,
        entropy: Option<f64>,
        category: Option<String>,
        score: f64,
        tags: Vec<String>,
        summary_json: serde_json::Value,
    ) -> Self {
        Self {
            id,
            source_type,
            source_id,
            evidence_id,
            volume_id,
            path,
            name,
            extension,
            size_bytes,
            modified_utc,
            created_utc,
            entropy,
            category,
            score,
            tags,
            summary_json,
        }
    }
}

pub struct ScoringContext {
    pub case_id: String,
    pub reference_time: i64,
    pub ioc_hits_for_file: std::collections::HashMap<String, bool>,
    pub strings_data: std::collections::HashMap<String, StringsInfo>,
    pub recent_days: i64,
}

#[derive(Debug, Clone, Default)]
pub struct StringsInfo {
    pub url_count: usize,
    pub email_count: usize,
    pub ipv4_count: usize,
}

impl ScoringContext {
    pub fn new(case_id: &str, reference_time: i64) -> Self {
        Self {
            case_id: case_id.to_string(),
            reference_time,
            ioc_hits_for_file: std::collections::HashMap::new(),
            strings_data: std::collections::HashMap::new(),
            recent_days: 7,
        }
    }

    pub fn with_ioc_hits(mut self, hits: std::collections::HashMap<String, bool>) -> Self {
        self.ioc_hits_for_file = hits;
        self
    }

    pub fn with_strings(mut self, data: std::collections::HashMap<String, StringsInfo>) -> Self {
        self.strings_data = data;
        self
    }

    pub fn with_recent_days(mut self, days: i64) -> Self {
        self.recent_days = days;
        self
    }

    pub fn has_ioc_hit(&self, source_id: &str) -> bool {
        self.ioc_hits_for_file
            .get(source_id)
            .copied()
            .unwrap_or(false)
    }

    pub fn get_strings_info(&self, source_id: &str) -> Option<&StringsInfo> {
        self.strings_data.get(source_id)
    }
}

pub fn score_row(
    _case_id: &str,
    row: &FileTableRowLike,
    ctx: &ScoringContext,
    weights: &ScoreWeights,
) -> ScoreResult {
    let mut signals: Vec<ScoreSignal> = Vec::new();

    let path_lower = row.path.to_lowercase();
    let name_lower = row.name.to_lowercase();
    let ext_lower = row
        .extension
        .as_ref()
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    if ctx.has_ioc_hit(&row.source_id) {
        signals.push(ScoreSignal::new(
            "ioc_hit",
            weights.ioc_hit,
            "IOC match found for file",
        ));
    }

    if let Some(entropy) = row.entropy {
        if entropy >= 7.5 {
            signals.push(ScoreSignal::new(
                "very_high_entropy",
                weights.very_high_entropy,
                &format!("Entropy {:.2} >= 7.5", entropy),
            ));
        } else if entropy >= 6.8 {
            signals.push(ScoreSignal::new(
                "high_entropy",
                weights.high_entropy,
                &format!("Entropy {:.2} >= 6.8", entropy),
            ));
        }
    }

    if is_suspicious_path(&path_lower) {
        signals.push(ScoreSignal::new(
            "suspicious_path",
            weights.suspicious_path,
            "Path matches known suspicious location",
        ));
    }

    if is_suspicious_extension(&ext_lower) {
        signals.push(ScoreSignal::new(
            "suspicious_ext",
            weights.suspicious_ext,
            &format!("Extension '{}' is suspicious", ext_lower),
        ));
    }

    if has_double_extension(&name_lower) {
        signals.push(ScoreSignal::new(
            "double_extension",
            weights.double_extension,
            "File has double extension",
        ));
    }

    if is_recent_timestamp(&row.modified_utc, ctx.reference_time, ctx.recent_days) {
        signals.push(ScoreSignal::new(
            "recent_modified",
            weights.recent_modified,
            "Modified within recent days",
        ));
    }

    if is_recent_timestamp(&row.created_utc, ctx.reference_time, ctx.recent_days) {
        signals.push(ScoreSignal::new(
            "recent_created",
            weights.recent_created,
            "Created within recent days",
        ));
    }

    if row.source_type == "carved" {
        signals.push(ScoreSignal::new(
            "from_carving",
            weights.from_carving,
            "File recovered from carving",
        ));
    }

    if let Some(strings_info) = ctx.get_strings_info(&row.source_id) {
        if strings_info.url_count > 0 {
            signals.push(ScoreSignal::new(
                "has_urls_in_strings",
                weights.has_urls_in_strings,
                &format!("{} URLs found in strings", strings_info.url_count),
            ));
        }
        if strings_info.email_count > 0 {
            signals.push(ScoreSignal::new(
                "has_emails_in_strings",
                weights.has_emails_in_strings,
                &format!("{} emails found in strings", strings_info.email_count),
            ));
        }
        if strings_info.ipv4_count > 0 {
            signals.push(ScoreSignal::new(
                "has_ipv4_in_strings",
                weights.has_ipv4_in_strings,
                &format!(
                    "{} IPv4 addresses found in strings",
                    strings_info.ipv4_count
                ),
            ));
        }
    }

    if is_executable_in_user_dir(&path_lower, &ext_lower) {
        signals.push(ScoreSignal::new(
            "executable_in_user_dir",
            weights.executable_in_user_dir,
            "Executable in user directory",
        ));
    }

    signals.sort_by(|a, b| {
        b.points
            .partial_cmp(&a.points)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.key.cmp(&b.key))
    });

    let total_score: f64 = signals.iter().map(|s| s.points).sum();
    let final_score = (total_score * 100.0).round() / 100.0;

    ScoreResult::new(final_score, signals)
}

fn is_suspicious_path(path: &str) -> bool {
    let suspicious_patterns = [
        "\\users\\",
        "\\appdata\\roaming\\",
        "\\appdata\\local\\temp\\",
        "\\programdata\\",
        "\\windows\\temp\\",
        "\\startup\\",
        "\\recent\\",
        "\\downloads\\",
        "\\temp\\",
    ];

    for pattern in suspicious_patterns {
        if path.contains(pattern) {
            return true;
        }
    }
    false
}

fn is_suspicious_extension(ext: &str) -> bool {
    let suspicious_exts = [
        "exe",
        "dll",
        "ps1",
        "vbs",
        "js",
        "jse",
        "scr",
        "com",
        "bat",
        "cmd",
        "hta",
        "jar",
        "lnk",
        "iso",
        "img",
        "pif",
        "msi",
        "application",
        "gadget",
        "msh",
        "msh1",
        "msh2",
        "mshxml",
        "msh1xml",
        "msh2xml",
        "action",
        "apk",
        "elf",
        "sh",
        "bash",
        "zsh",
    ];

    suspicious_exts.contains(&ext)
}

fn has_double_extension(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 3 {
        return false;
    }

    let first = parts[parts.len() - 2].to_lowercase();
    let second = parts[parts.len() - 1].to_lowercase();
    {
        let suspicious_docs = ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "gif"];
        if suspicious_docs.contains(&first.as_str()) {
            let susp_exts = [
                "exe", "dll", "ps1", "vbs", "js", "scr", "bat", "cmd", "com", "jar", "lnk",
            ];
            return susp_exts.contains(&second.as_str());
        }
    }
    false
}

fn is_recent_timestamp(timestamp: &Option<String>, reference_time: i64, recent_days: i64) -> bool {
    if let Some(ts) = timestamp {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
            let diff_secs = reference_time - dt.timestamp();
            let days = diff_secs / 86400;
            return days >= 0 && days < recent_days;
        }
    }
    false
}

fn is_executable_in_user_dir(path: &str, ext: &str) -> bool {
    let exec_exts = ["exe", "dll", "ps1", "vbs", "js", "bat", "cmd", "com", "scr"];

    if !exec_exts.contains(&ext) {
        return false;
    }

    let has_users = path.contains("\\users\\") || path.contains("/users/");
    let is_system = path.contains("\\program files\\")
        || path.contains("/program files/")
        || path.contains("\\windows\\")
        || path.contains("/windows/");

    has_users && !is_system
}

pub fn get_suspicious_paths() -> Vec<&'static str> {
    vec![
        "\\users\\*\\appdata\\roaming\\",
        "\\users\\*\\appdata\\local\\temp\\",
        "\\programdata\\",
        "\\windows\\temp\\",
        "\\startup\\",
    ]
}

pub fn get_suspicious_extensions() -> Vec<&'static str> {
    vec![
        "exe", "dll", "ps1", "vbs", "js", "jse", "scr", "com", "bat", "cmd", "hta", "jar", "lnk",
        "iso", "img",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_row(
        path: &str,
        ext: Option<&str>,
        entropy: Option<f64>,
        source_type: &str,
    ) -> FileTableRowLike {
        FileTableRowLike {
            id: 1,
            source_type: source_type.to_string(),
            source_id: "test-1".to_string(),
            evidence_id: None,
            volume_id: None,
            path: path.to_string(),
            name: "test.exe".to_string(),
            extension: ext.map(|s| s.to_string()),
            size_bytes: Some(1024),
            modified_utc: Some("2024-01-15T10:00:00Z".to_string()),
            created_utc: Some("2024-01-10T08:00:00Z".to_string()),
            entropy,
            category: None,
            score: 0.0,
            tags: vec![],
            summary_json: serde_json::json!({}),
        }
    }

    #[test]
    fn test_ioc_hit_adds_points() {
        let row = create_test_row("C:\\test.exe", Some("exe"), None, "fs");
        let mut ctx = ScoringContext::new("case1", 1704067200);
        ctx.ioc_hits_for_file.insert("test-1".to_string(), true);

        let weights = ScoreWeights::default();
        let result = score_row("case1", &row, &ctx, &weights);

        assert!(result.signals.iter().any(|s| s.key == "ioc_hit"));
        assert!(result.score >= weights.ioc_hit);
    }

    #[test]
    fn test_high_entropy_tiers() {
        let row_high = create_test_row("C:\\test.dll", Some("dll"), Some(7.2), "fs");
        let row_very_high = create_test_row("C:\\test.dll", Some("dll"), Some(7.8), "fs");

        let ctx = ScoringContext::new("case1", 1704067200);
        let weights = ScoreWeights::default();

        let result_high = score_row("case1", &row_high, &ctx, &weights);
        let result_very_high = score_row("case1", &row_very_high, &ctx, &weights);

        assert!(result_high.signals.iter().any(|s| s.key == "high_entropy"));
        assert!(result_very_high
            .signals
            .iter()
            .any(|s| s.key == "very_high_entropy"));
        assert!(result_very_high.score > result_high.score);
    }

    #[test]
    fn test_suspicious_path() {
        let row = create_test_path_row("C:\\Users\\john\\AppData\\Roaming\\malware.exe");

        let ctx = ScoringContext::new("case1", 1704067200);
        let weights = ScoreWeights::default();
        let result = score_row("case1", &row, &ctx, &weights);

        assert!(result.signals.iter().any(|s| s.key == "suspicious_path"));
    }

    #[test]
    fn test_double_extension() {
        let row = FileTableRowLike {
            id: 1,
            source_type: "fs".to_string(),
            source_id: "test-1".to_string(),
            evidence_id: None,
            volume_id: None,
            path: "C:\\downloads\\document.pdf.exe".to_string(),
            name: "document.pdf.exe".to_string(),
            extension: Some("exe".to_string()),
            size_bytes: Some(1024),
            modified_utc: None,
            created_utc: None,
            entropy: None,
            category: None,
            score: 0.0,
            tags: vec![],
            summary_json: serde_json::json!({}),
        };

        let ctx = ScoringContext::new("case1", 1704067200);
        let weights = ScoreWeights::default();
        let result = score_row("case1", &row, &ctx, &weights);

        assert!(result.signals.iter().any(|s| s.key == "double_extension"));
    }

    #[test]
    fn test_strings_url_count() {
        let row = create_test_row("C:\\test.txt", Some("txt"), None, "fs");
        let mut ctx = ScoringContext::new("case1", 1704067200);
        ctx.strings_data.insert(
            "test-1".to_string(),
            StringsInfo {
                url_count: 5,
                email_count: 0,
                ipv4_count: 0,
            },
        );

        let weights = ScoreWeights::default();
        let result = score_row("case1", &row, &ctx, &weights);

        assert!(result
            .signals
            .iter()
            .any(|s| s.key == "has_urls_in_strings"));
    }

    #[test]
    fn test_determinism() {
        let row = create_test_row(
            "C:\\Users\\john\\AppData\\Roaming\\test.exe",
            Some("exe"),
            Some(7.2),
            "fs",
        );
        let ctx = ScoringContext::new("case1", 1704067200);
        let weights = ScoreWeights::default();

        let result1 = score_row("case1", &row, &ctx, &weights);
        let result2 = score_row("case1", &row, &ctx, &weights);

        assert_eq!(result1.score, result2.score);
        assert_eq!(result1.signals.len(), result2.signals.len());

        for (s1, s2) in result1.signals.iter().zip(result2.signals.iter()) {
            assert_eq!(s1.key, s2.key);
            assert_eq!(s1.points, s2.points);
        }
    }

    #[test]
    fn test_clamp_never_above_100() {
        let row = FileTableRowLike {
            id: 1,
            source_type: "fs".to_string(),
            source_id: "test-1".to_string(),
            evidence_id: None,
            volume_id: None,
            path: "C:\\Users\\john\\AppData\\Roaming\\malware.pdf.exe".to_string(),
            name: "malware.pdf.exe".to_string(),
            extension: Some("exe".to_string()),
            size_bytes: Some(1024),
            modified_utc: Some("2024-01-15T10:00:00Z".to_string()),
            created_utc: Some("2024-01-15T10:00:00Z".to_string()),
            entropy: Some(7.9),
            category: None,
            score: 0.0,
            tags: vec![],
            summary_json: serde_json::json!({}),
        };

        let mut ctx = ScoringContext::new("case1", 1704067200);
        ctx.ioc_hits_for_file.insert("test-1".to_string(), true);
        ctx.strings_data.insert(
            "test-1".to_string(),
            StringsInfo {
                url_count: 10,
                email_count: 5,
                ipv4_count: 5,
            },
        );

        let weights = ScoreWeights::default();
        let result = score_row("case1", &row, &ctx, &weights);

        assert!(result.score <= 100.0);
        assert!(result.score >= 0.0);
    }

    #[test]
    fn test_signals_sorted_by_points_desc_then_key_asc() {
        let row = create_test_row("C:\\test.exe", Some("exe"), Some(7.0), "carved");

        let ctx = ScoringContext::new("case1", 1704067200);
        let weights = ScoreWeights::default();
        let result = score_row("case1", &row, &ctx, &weights);

        for i in 1..result.signals.len() {
            assert!(
                result.signals[i - 1].points >= result.signals[i].points,
                "Signals not sorted by points desc"
            );
        }
    }

    fn create_test_path_row(path: &str) -> FileTableRowLike {
        FileTableRowLike {
            id: 1,
            source_type: "fs".to_string(),
            source_id: "test-1".to_string(),
            evidence_id: None,
            volume_id: None,
            path: path.to_string(),
            name: "test.exe".to_string(),
            extension: Some("exe".to_string()),
            size_bytes: Some(1024),
            modified_utc: None,
            created_utc: None,
            entropy: None,
            category: None,
            score: 0.0,
            tags: vec![],
            summary_json: serde_json::json!({}),
        }
    }
}
