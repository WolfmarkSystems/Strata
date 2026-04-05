use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedSearch {
    pub id: String,
    pub case_id: String,
    pub name: String,
    pub description: String,
    pub created_at: u64,
    pub modified_at: u64,
    pub created_by: String,
    pub last_used_at: Option<u64>,
    pub usage_count: u32,
    pub search_query: SearchQuery,
    pub is_global: bool,
    pub tags: Vec<String>,
}

impl SavedSearch {
    pub fn new(case_id: &str, created_by: &str, name: &str, query: SearchQuery) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            name: name.to_string(),
            description: String::new(),
            created_at: now,
            modified_at: now,
            created_by: created_by.to_string(),
            last_used_at: None,
            usage_count: 0,
            search_query: query,
            is_global: false,
            tags: Vec::new(),
        }
    }

    pub fn mark_used(&mut self) {
        self.last_used_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.usage_count += 1;
    }

    pub fn set_description(&mut self, description: &str) {
        self.description = description.to_string();
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
            self.modified_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
    }

    pub fn make_global(&mut self) {
        self.is_global = true;
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: Option<String>,
    pub path_filter: Option<String>,
    pub file_name_filter: Option<String>,
    pub extension_filter: Vec<String>,
    pub size_min: Option<u64>,
    pub size_max: Option<u64>,
    pub date_created_start: Option<u64>,
    pub date_created_end: Option<u64>,
    pub date_modified_start: Option<u64>,
    pub date_modified_end: Option<u64>,
    pub date_accessed_start: Option<u64>,
    pub date_accessed_end: Option<u64>,
    pub hash_filter: Option<HashFilter>,
    pub category_filter: Vec<String>,
    pub artifact_filter: Vec<String>,
    pub metadata_filters: HashMap<String, String>,
    pub logical_operator: LogicalOperator,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            text: None,
            path_filter: None,
            file_name_filter: None,
            extension_filter: Vec::new(),
            size_min: None,
            size_max: None,
            date_created_start: None,
            date_created_end: None,
            date_modified_start: None,
            date_modified_end: None,
            date_accessed_start: None,
            date_accessed_end: None,
            hash_filter: None,
            category_filter: Vec::new(),
            artifact_filter: Vec::new(),
            metadata_filters: HashMap::new(),
            logical_operator: LogicalOperator::And,
        }
    }
}

impl SearchQuery {
    pub fn text(text: &str) -> Self {
        Self {
            text: Some(text.to_string()),
            ..Default::default()
        }
    }

    pub fn with_extension(mut self, ext: &str) -> Self {
        self.extension_filter.push(ext.to_string());
        self
    }

    pub fn with_size_range(mut self, min: u64, max: u64) -> Self {
        self.size_min = Some(min);
        self.size_max = Some(max);
        self
    }

    pub fn with_date_range(mut self, created_start: u64, created_end: u64) -> Self {
        self.date_created_start = Some(created_start);
        self.date_created_end = Some(created_end);
        self
    }

    pub fn with_category(mut self, category: &str) -> Self {
        self.category_filter.push(category.to_string());
        self
    }

    pub fn with_artifact(mut self, artifact: &str) -> Self {
        self.artifact_filter.push(artifact.to_string());
        self
    }

    pub fn with_hash_filter(mut self, hash_filter: HashFilter) -> Self {
        self.hash_filter = Some(hash_filter);
        self
    }

    pub fn with_operator(mut self, operator: LogicalOperator) -> Self {
        self.logical_operator = operator;
        self
    }

    pub fn matches(&self, file_entry: &FileSearchEntry) -> bool {
        if let Some(ref text) = self.text {
            if !file_entry
                .name
                .to_lowercase()
                .contains(&text.to_lowercase())
                && !file_entry
                    .path
                    .to_lowercase()
                    .contains(&text.to_lowercase())
            {
                return false;
            }
        }

        if let Some(ref path_filter) = self.path_filter {
            if !file_entry.path.contains(path_filter) {
                return false;
            }
        }

        if let Some(ref name_filter) = self.file_name_filter {
            if !file_entry.name.contains(name_filter) {
                return false;
            }
        }

        if !self.extension_filter.is_empty() {
            let ext = file_entry.extension.to_lowercase();
            if !self
                .extension_filter
                .iter()
                .any(|e| e.to_lowercase() == ext)
            {
                return false;
            }
        }

        if let Some(min) = self.size_min {
            if file_entry.size < min {
                return false;
            }
        }

        if let Some(max) = self.size_max {
            if file_entry.size > max {
                return false;
            }
        }

        if let Some(start) = self.date_created_start {
            if file_entry.created_at < start {
                return false;
            }
        }

        if let Some(end) = self.date_created_end {
            if file_entry.created_at > end {
                return false;
            }
        }

        if let Some(ref hash_filter) = self.hash_filter {
            if let Some(ref file_hash) = file_entry.sha256 {
                let matches = match hash_filter.match_type {
                    HashMatchType::Exact => file_hash == &hash_filter.value,
                    HashMatchType::Prefix => file_hash.starts_with(&hash_filter.value),
                    HashMatchType::Contains => file_hash.contains(&hash_filter.value),
                };
                if !matches {
                    return false;
                }
            } else {
                return false;
            }
        }

        if !self.category_filter.is_empty()
            && !self
                .category_filter
                .iter()
                .any(|c| &file_entry.category == c)
        {
            return false;
        }

        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSearchEntry {
    pub path: String,
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub created_at: u64,
    pub modified_at: u64,
    pub accessed_at: u64,
    pub category: String,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub is_directory: bool,
    pub is_hidden: bool,
    pub is_system: bool,
    pub is_readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashFilter {
    pub value: String,
    pub match_type: HashMatchType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashMatchType {
    Exact,
    Prefix,
    Contains,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogicalOperator {
    And,
    Or,
}

pub struct SavedSearchManager {
    case_id: String,
    searches: HashMap<String, SavedSearch>,
    global_searches: HashMap<String, SavedSearch>,
}

impl SavedSearchManager {
    pub fn new(case_id: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            searches: HashMap::new(),
            global_searches: HashMap::new(),
        }
    }

    pub fn create_search(&mut self, created_by: &str, name: &str, query: SearchQuery) -> String {
        let search = SavedSearch::new(&self.case_id, created_by, name, query);
        let id = search.id.clone();
        self.searches.insert(id.clone(), search);
        id
    }

    pub fn get_search(&self, id: &str) -> Option<&SavedSearch> {
        self.searches
            .get(id)
            .or_else(|| self.global_searches.get(id))
    }

    pub fn get_search_mut(&mut self, id: &str) -> Option<&mut SavedSearch> {
        self.searches
            .get_mut(id)
            .or_else(|| self.global_searches.get_mut(id))
    }

    pub fn update_search(&mut self, id: &str, name: &str, query: SearchQuery) -> bool {
        if let Some(search) = self.searches.get_mut(id) {
            search.name = name.to_string();
            search.search_query = query;
            search.modified_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            return true;
        }
        false
    }

    pub fn delete_search(&mut self, id: &str) -> bool {
        self.searches.remove(id).is_some()
    }

    pub fn list_searches(&self) -> Vec<&SavedSearch> {
        self.searches.values().collect()
    }

    pub fn list_global_searches(&self) -> Vec<&SavedSearch> {
        self.global_searches.values().collect()
    }

    pub fn list_all_searches(&self) -> Vec<&SavedSearch> {
        let mut all: Vec<&SavedSearch> = self.searches.values().collect();
        all.extend(self.global_searches.values());
        all
    }

    pub fn search_by_name(&self, name: &str) -> Vec<&SavedSearch> {
        let name_lower = name.to_lowercase();
        self.searches
            .values()
            .filter(|s| s.name.to_lowercase().contains(&name_lower))
            .collect()
    }

    pub fn search_by_tag(&self, tag: &str) -> Vec<&SavedSearch> {
        self.searches
            .values()
            .filter(|s| s.tags.contains(&tag.to_string()))
            .collect()
    }

    pub fn get_most_used(&self, limit: usize) -> Vec<&SavedSearch> {
        let mut searches: Vec<&SavedSearch> = self.searches.values().collect();
        searches.sort_by(|a, b| b.usage_count.cmp(&a.usage_count));
        searches.truncate(limit);
        searches
    }

    pub fn get_recently_used(&self, limit: usize) -> Vec<&SavedSearch> {
        let mut searches: Vec<&SavedSearch> = self.searches.values().collect();
        searches.sort_by(|a, b| {
            let a_time = a.last_used_at.unwrap_or(0);
            let b_time = b.last_used_at.unwrap_or(0);
            b_time.cmp(&a_time)
        });
        searches.truncate(limit);
        searches
    }

    pub fn make_global(&mut self, id: &str) -> bool {
        if let Some(search) = self.searches.remove(id) {
            let mut global = search;
            global.make_global();
            self.global_searches.insert(global.id.clone(), global);
            return true;
        }
        false
    }

    pub fn import_global(&mut self, search: SavedSearch) {
        let id = search.id.clone();
        self.global_searches.insert(id, search);
    }
}
