// search/filters.rs — File filters for size, date, extension, category, hash flags.

use crate::state::IndexedFile;

#[derive(Debug, Clone, Default)]
pub struct FileFilter {
    pub min_size: Option<i64>,
    pub max_size: Option<i64>,
    pub modified_after: Option<String>,
    pub modified_before: Option<String>,
    pub extensions: Vec<String>,
    pub categories: Vec<String>,
    pub deleted_only: bool,
    pub has_hash: bool,
}

impl FileFilter {
    pub fn apply<'a>(&self, files: &'a [IndexedFile]) -> Vec<&'a IndexedFile> {
        files
            .iter()
            .filter(|f| {
                if self.deleted_only && !f.is_deleted {
                    return false;
                }
                if let Some(min) = self.min_size {
                    if f.size.unwrap_or(0) < min {
                        return false;
                    }
                }
                if let Some(max) = self.max_size {
                    if f.size.unwrap_or(i64::MAX) > max {
                        return false;
                    }
                }
                if !self.extensions.is_empty() {
                    let ext = f.extension.as_deref().unwrap_or("").to_lowercase();
                    if !self.extensions.contains(&ext) {
                        return false;
                    }
                }
                if !self.categories.is_empty() {
                    let cat = f.category.as_deref().unwrap_or("").to_lowercase();
                    if !self.categories.iter().any(|c| c.to_lowercase() == cat) {
                        return false;
                    }
                }
                if self.has_hash && f.sha256.is_none() && f.md5.is_none() {
                    return false;
                }
                true
            })
            .collect()
    }
}
