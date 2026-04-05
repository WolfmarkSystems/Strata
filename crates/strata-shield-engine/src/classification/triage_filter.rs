use super::triage::{FileCategory, TriageEntry};

#[derive(Debug, Clone)]
pub struct TriageFilter {
    pub path_contains: Option<String>,
    pub path_excludes: Vec<String>,
    pub extension_includes: Vec<String>,
    pub extension_excludes: Vec<String>,
    pub category_includes: Vec<FileCategory>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub created_after: Option<u64>,
    pub created_before: Option<u64>,
    pub modified_after: Option<u64>,
    pub modified_before: Option<u64>,
    pub show_directories: bool,
    pub show_files: bool,
    pub show_hidden: bool,
    pub show_system: bool,
    pub known_only: bool,
    pub unknown_only: bool,
    pub high_entropy_only: bool,
    pub keyword_search: Option<String>,
}

impl Default for TriageFilter {
    fn default() -> Self {
        Self {
            path_contains: None,
            path_excludes: vec![],
            extension_includes: vec![],
            extension_excludes: vec![],
            category_includes: vec![],
            min_size: None,
            max_size: None,
            created_after: None,
            created_before: None,
            modified_after: None,
            modified_before: None,
            show_directories: true,
            show_files: true,
            show_hidden: false,
            show_system: false,
            known_only: false,
            unknown_only: false,
            high_entropy_only: false,
            keyword_search: None,
        }
    }
}

impl TriageFilter {
    pub fn matches(&self, entry: &TriageEntry) -> bool {
        if entry.is_directory && !self.show_directories {
            return false;
        }

        if !entry.is_directory && !self.show_files {
            return false;
        }

        if !self.show_hidden && entry.is_hidden {
            return false;
        }

        if !self.show_system && entry.is_system {
            return false;
        }

        if let Some(ref path_filter) = self.path_contains {
            if !entry
                .path
                .to_lowercase()
                .contains(&path_filter.to_lowercase())
            {
                return false;
            }
        }

        for exclude in &self.path_excludes {
            if entry.path.to_lowercase().contains(&exclude.to_lowercase()) {
                return false;
            }
        }

        if !self.extension_includes.is_empty() {
            if let Some(ref ext) = entry.extension {
                if !self
                    .extension_includes
                    .iter()
                    .any(|e| e.eq_ignore_ascii_case(ext))
                {
                    return false;
                }
            } else {
                return false;
            }
        }

        if !self.extension_excludes.is_empty() {
            if let Some(ref ext) = entry.extension {
                if self
                    .extension_excludes
                    .iter()
                    .any(|e| e.eq_ignore_ascii_case(ext))
                {
                    return false;
                }
            }
        }

        if !self.category_includes.is_empty()
            && !self.category_includes.contains(&entry.file_category)
        {
            return false;
        }

        if let Some(min) = self.min_size {
            if entry.size < min {
                return false;
            }
        }

        if let Some(max) = self.max_size {
            if entry.size > max {
                return false;
            }
        }

        if let Some(after) = self.created_after {
            if let Some(created) = entry.created {
                if created < after {
                    return false;
                }
            }
        }

        if let Some(before) = self.created_before {
            if let Some(created) = entry.created {
                if created > before {
                    return false;
                }
            }
        }

        if let Some(after) = self.modified_after {
            if let Some(modified) = entry.modified {
                if modified < after {
                    return false;
                }
            }
        }

        if let Some(before) = self.modified_before {
            if let Some(modified) = entry.modified {
                if modified > before {
                    return false;
                }
            }
        }

        if self.known_only && !entry.is_known {
            return false;
        }

        if self.unknown_only && entry.is_known {
            return false;
        }

        if self.high_entropy_only {
            if let Some(entropy) = entry.entropy {
                if entropy < 7.0 {
                    return false;
                }
            }
        }

        if let Some(ref keyword) = self.keyword_search {
            let search_lower = keyword.to_lowercase();
            if !entry.name.to_lowercase().contains(&search_lower)
                && !entry.path.to_lowercase().contains(&search_lower)
            {
                return false;
            }
        }

        true
    }
}

pub fn filter_entries<'a>(
    entries: &'a [TriageEntry],
    filter: &TriageFilter,
) -> Vec<&'a TriageEntry> {
    entries.iter().filter(|e| filter.matches(e)).collect()
}

pub fn create_default_noise_filter() -> TriageFilter {
    TriageFilter {
        path_excludes: vec![
            "\\Windows\\".to_string(),
            "\\Program Files\\".to_string(),
            "\\ProgramData\\".to_string(),
            "\\WinSxS\\".to_string(),
            "\\System32\\".to_string(),
            "/System/Library/".to_string(),
            "/Library/Caches/".to_string(),
            "/usr/lib/".to_string(),
            "/lib/".to_string(),
        ],
        extension_excludes: vec!["tmp".to_string(), "temp".to_string(), "log".to_string()],
        ..TriageFilter::default()
    }
}
