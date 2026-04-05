// search/filename.rs — Fast filename/path search against file_index.
// Full implementation in Task 1.7.

use anyhow::Result;

#[derive(Debug, Clone, Default)]
pub struct SearchOptions {
    pub case_sensitive: bool,
    pub regex: bool,
    pub include_paths: bool,
    pub include_deleted: bool,
    pub extension_filter: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SearchHitResult {
    pub file_id: String,
    pub file_path: String,
    pub file_name: String,
}

/// Search filenames in the in-memory file index.
/// Full implementation in Task 1.7.
pub fn search_filenames(
    query: &str,
    files: &[crate::state::IndexedFile],
    options: &SearchOptions,
) -> Result<Vec<SearchHitResult>> {
    let query_lc = if options.case_sensitive {
        query.to_string()
    } else {
        query.to_lowercase()
    };

    let results = files
        .iter()
        .filter(|f| options.include_deleted || !f.is_deleted)
        .filter(|f| {
            let haystack = if options.include_paths {
                let s = if options.case_sensitive { f.path.clone() } else { f.path.to_lowercase() };
                s
            } else {
                if options.case_sensitive { f.name.clone() } else { f.name.to_lowercase() }
            };
            haystack.contains(&query_lc)
        })
        .filter(|f| {
            if options.extension_filter.is_empty() {
                true
            } else {
                f.extension.as_deref().map(|e| options.extension_filter.contains(&e.to_lowercase())).unwrap_or(false)
            }
        })
        .map(|f| SearchHitResult {
            file_id: f.id.clone(),
            file_path: f.path.clone(),
            file_name: f.name.clone(),
        })
        .collect();

    Ok(results)
}
