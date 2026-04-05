use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewState {
    pub item_id: String,
    pub item_type: ReviewItemType,
    pub reviewed: bool,
    pub reviewer: Option<String>,
    pub reviewed_at: Option<u64>,
    pub auto_propagated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReviewItemType {
    BookmarkFolder,
    Bookmark,
    Note,
    Exhibit,
    Tag,
}

pub fn propagate_review_state(folder_id: &str, reviewed: bool, reviewer: &str) -> Vec<ReviewState> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let states = vec![ReviewState {
        item_id: folder_id.to_string(),
        item_type: ReviewItemType::BookmarkFolder,
        reviewed,
        reviewer: Some(reviewer.to_string()),
        reviewed_at: Some(now),
        auto_propagated: false,
    }];

    states
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHit {
    pub rule_id: String,
    pub rule_name: String,
    pub rule_description: String,
    pub severity: RuleSeverity,
    pub matched_value: String,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

pub fn explain_why_shown(file_path: &str, category: &str, rule_hits: Vec<RuleHit>) -> Explanation {
    let summary = if rule_hits.is_empty() {
        format!(
            "File '{}' appears in this list because it matches the '{}' filter criteria.",
            file_path, category
        )
    } else {
        let hit_summary: Vec<String> = rule_hits
            .iter()
            .map(|h| format!("{} ({:?})", h.rule_name, h.severity))
            .collect();
        format!(
            "File '{}' appears because: {}",
            file_path,
            hit_summary.join("; ")
        )
    };

    Explanation {
        file_path: file_path.to_string(),
        category: category.to_string(),
        summary,
        rule_hits: rule_hits.clone(),
        recommendation: generate_recommendation(&rule_hits),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Explanation {
    pub file_path: String,
    pub category: String,
    pub summary: String,
    pub rule_hits: Vec<RuleHit>,
    pub recommendation: String,
}

fn generate_recommendation(rule_hits: &[RuleHit]) -> String {
    if rule_hits.is_empty() {
        return "No specific action recommended.".to_string();
    }

    let high_severity_count = rule_hits
        .iter()
        .filter(|h| h.severity >= RuleSeverity::High)
        .count();

    if high_severity_count > 0 {
        return format!(
            "{} rule(s) with High/Critical severity detected. Consider marking as exhibit and investigating further.",
            high_severity_count
        );
    }

    "Review for context. May be benign or warrant further investigation.".to_string()
}

pub struct QuickExhibitBuilder {
    pub case_id: String,
    pub examiner: String,
    pub default_tags: Vec<String>,
}

impl QuickExhibitBuilder {
    pub fn new(case_id: &str, examiner: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            examiner: examiner.to_string(),
            default_tags: vec!["quick-exhibit".to_string()],
        }
    }

    pub fn with_default_tags(mut self, tags: Vec<String>) -> Self {
        self.default_tags = tags;
        self
    }

    pub fn create_from_selection(&self, file_paths: &[String], reason: &str) -> QuickExhibitResult {
        let exhibit_ids: Vec<String> = file_paths
            .iter()
            .map(|_path| uuid::Uuid::new_v4().to_string())
            .collect();

        QuickExhibitResult {
            success: true,
            exhibit_ids,
            file_count: file_paths.len(),
            reason: reason.to_string(),
            errors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickExhibitResult {
    pub success: bool,
    pub exhibit_ids: Vec<String>,
    pub file_count: usize,
    pub reason: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigatorBookmark {
    pub id: String,
    pub title: String,
    pub reason: String,
    pub file_paths: Vec<String>,
    pub category: String,
    pub tags: Vec<String>,
    pub created_by: String,
    pub created_at: u64,
}

impl InvestigatorBookmark {
    pub fn quick_bookmark(
        title: &str,
        reason: &str,
        file_paths: Vec<String>,
        category: &str,
        created_by: &str,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.to_string(),
            reason: reason.to_string(),
            file_paths,
            category: category.to_string(),
            tags: Vec::new(),
            created_by: created_by.to_string(),
            created_at: now,
        }
    }

    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterContext {
    pub filter_type: String,
    pub criteria: HashMap<String, String>,
    pub result_count: usize,
    pub applied_at: u64,
}

impl FilterContext {
    pub fn new(filter_type: &str) -> Self {
        Self {
            filter_type: filter_type.to_string(),
            criteria: HashMap::new(),
            result_count: 0,
            applied_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn with_criterion(mut self, key: &str, value: &str) -> Self {
        self.criteria.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_results(mut self, count: usize) -> Self {
        self.result_count = count;
        self
    }

    pub fn to_note_content(&self) -> String {
        let mut content = format!("Filter Applied: {}\n", self.filter_type);
        content.push_str("Criteria:\n");
        for (key, value) in &self.criteria {
            content.push_str(&format!("  - {}: {}\n", key, value));
        }
        content.push_str(&format!("\nResults: {} items\n", self.result_count));
        content
    }
}

pub fn create_quick_exhibit_packet(
    file_paths: Vec<String>,
    reason: &str,
    _category: &str,
    examiner: &str,
) -> QuickExhibitResult {
    let builder = QuickExhibitBuilder::new("current", examiner);
    builder.create_from_selection(&file_paths, reason)
}

pub fn create_investigator_bookmark(
    title: &str,
    reason: &str,
    files: Vec<String>,
    category: &str,
    examiner: &str,
    tags: Vec<String>,
) -> InvestigatorBookmark {
    let mut bookmark =
        InvestigatorBookmark::quick_bookmark(title, reason, files, category, examiner);
    for tag in tags {
        bookmark.add_tag(&tag);
    }
    bookmark
}
