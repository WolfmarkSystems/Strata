//! vt-index: inverted index and search functionality.

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

pub struct InvertedIndex {
    index: HashMap<String, Vec<String>>,
}

impl Default for InvertedIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl InvertedIndex {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
        }
    }

    pub fn add_document(&mut self, doc_id: &str, content: &str) {
        for token in tokenize(content) {
            let bucket = self.index.entry(token).or_default();
            if !bucket.contains(&doc_id.to_string()) {
                bucket.push(doc_id.to_string());
            }
        }
    }

    pub fn search(&self, query: &str) -> Vec<String> {
        self.search_with_options(query, None, 0, 100, false)
    }

    pub fn search_with_options(
        &self,
        query: &str,
        prefix: Option<&str>,
        page: usize,
        page_size: usize,
        sort: bool,
    ) -> Vec<String> {
        let terms = tokenize(query);
        if terms.is_empty() {
            return vec![];
        }

        let mut results: Vec<String> = if let Some(first) = self.index.get(&terms[0]) {
            first.clone()
        } else {
            vec![]
        };

        for term in terms.iter().skip(1) {
            if let Some(other) = self.index.get(term) {
                results.retain(|id| other.contains(id));
            } else {
                results.clear();
                break;
            }
        }

        if let Some(prefix_term) = prefix {
            results.retain(|id| id.starts_with(prefix_term));
        }

        if sort {
            results.sort();
        }

        if page_size > 0 {
            let start = page.saturating_mul(page_size);
            return results.into_iter().skip(start).take(page_size).collect();
        }

        results
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let mut lines = vec![];
        for (token, docs) in &self.index {
            let line = format!("{}|{}", token, docs.join(","));
            lines.push(line);
        }
        strata_fs::write(path, lines.join("\n"))?;
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = strata_fs::read_to_string(path)?;
        let mut index = HashMap::new();
        for line in content.lines() {
            if let Some((token, docs)) = line.split_once('|') {
                let ids: Vec<String> = docs.split(',').map(|s| s.to_string()).collect();
                index.insert(token.to_string(), ids);
            }
        }
        Ok(Self { index })
    }
}

pub fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
}

pub fn self_test() -> Result<()> {
    let mut idx = InvertedIndex::new();
    idx.add_document("1", "password file secret");
    idx.add_document("2", "user secret key");
    let res = idx.search("secret");
    assert_eq!(res.len(), 2);

    let res2 = idx.search_with_options("secret", Some("user"), 0, 10, false);
    assert_eq!(res2.len(), 1);

    let res3 = idx.search_with_options("secret", None, 0, 1, true);
    assert_eq!(res3.len(), 1);

    Ok(())
}
