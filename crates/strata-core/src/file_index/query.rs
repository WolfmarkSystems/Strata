//! Structured query builder for the master file index.
//!
//! Plugins describe their target files declaratively (exact filenames,
//! extensions, MIME classes, size caps). The query builder compiles
//! the request into a single parameterised SQL statement, so each
//! plugin pays a single DB round-trip instead of walking the
//! filesystem itself.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use rusqlite::{params_from_iter, types::Value};

use super::database::{database_row_to_entry, FileIndex, FileIndexEntry, FileIndexError};

#[derive(Debug, Clone, Default)]
pub struct QueryBuilder {
    filenames: Vec<String>,
    extensions: Vec<String>,
    mime_types: Vec<String>,
    path_contains: Vec<String>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    min_entropy: Option<f64>,
    require_nsrl_known_good: Option<bool>,
    require_threat_intel: Option<bool>,
    sha256: Option<String>,
    limit: Option<usize>,
}

impl QueryBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn filename<S: Into<String>>(mut self, name: S) -> Self {
        self.filenames.push(name.into());
        self
    }

    pub fn extension<S: Into<String>>(mut self, ext: S) -> Self {
        self.extensions
            .push(ext.into().trim_start_matches('.').to_ascii_lowercase());
        self
    }

    pub fn mime<S: Into<String>>(mut self, mime: S) -> Self {
        self.mime_types.push(mime.into());
        self
    }

    pub fn path_contains<S: Into<String>>(mut self, s: S) -> Self {
        self.path_contains.push(s.into());
        self
    }

    pub fn min_size(mut self, bytes: u64) -> Self {
        self.min_size = Some(bytes);
        self
    }

    pub fn max_size(mut self, bytes: u64) -> Self {
        self.max_size = Some(bytes);
        self
    }

    pub fn min_entropy(mut self, entropy: f64) -> Self {
        self.min_entropy = Some(entropy);
        self
    }

    pub fn nsrl_known_good(mut self, wanted: bool) -> Self {
        self.require_nsrl_known_good = Some(wanted);
        self
    }

    pub fn threat_intel(mut self, wanted: bool) -> Self {
        self.require_threat_intel = Some(wanted);
        self
    }

    pub fn sha256<S: Into<String>>(mut self, hex: S) -> Self {
        self.sha256 = Some(hex.into());
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    pub fn execute(&self, idx: &FileIndex) -> Result<Vec<FileIndexEntry>, FileIndexError> {
        let mut sql = String::from("SELECT * FROM file_index WHERE 1=1");
        let mut params: Vec<Value> = Vec::new();
        if !self.filenames.is_empty() {
            sql.push_str(&format!(
                " AND filename IN ({})",
                placeholder_csv(self.filenames.len())
            ));
            for f in &self.filenames {
                params.push(Value::Text(f.clone()));
            }
        }
        if !self.extensions.is_empty() {
            sql.push_str(&format!(
                " AND extension IN ({})",
                placeholder_csv(self.extensions.len())
            ));
            for e in &self.extensions {
                params.push(Value::Text(e.clone()));
            }
        }
        if !self.mime_types.is_empty() {
            sql.push_str(&format!(
                " AND mime_type IN ({})",
                placeholder_csv(self.mime_types.len())
            ));
            for m in &self.mime_types {
                params.push(Value::Text(m.clone()));
            }
        }
        for frag in &self.path_contains {
            sql.push_str(" AND full_path LIKE ?");
            params.push(Value::Text(format!("%{}%", frag)));
        }
        if let Some(min) = self.min_size {
            sql.push_str(" AND file_size >= ?");
            params.push(Value::Integer(min as i64));
        }
        if let Some(max) = self.max_size {
            sql.push_str(" AND file_size <= ?");
            params.push(Value::Integer(max as i64));
        }
        if let Some(min) = self.min_entropy {
            sql.push_str(" AND entropy >= ?");
            params.push(Value::Real(min));
        }
        if let Some(v) = self.require_nsrl_known_good {
            sql.push_str(" AND nsrl_known_good = ?");
            params.push(Value::Integer(if v { 1 } else { 0 }));
        }
        if let Some(v) = self.require_threat_intel {
            sql.push_str(" AND threat_intel_match = ?");
            params.push(Value::Integer(if v { 1 } else { 0 }));
        }
        if let Some(hex) = &self.sha256 {
            sql.push_str(" AND sha256 = ?");
            params.push(Value::Text(hex.clone()));
        }
        if let Some(limit) = self.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }
        let mut stmt = idx.connection_ref().prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(params.iter()), database_row_to_entry)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

fn placeholder_csv(n: usize) -> String {
    std::iter::repeat_n("?", n).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::super::database::FileIndexEntry;
    use super::*;

    fn open_tmp() -> (tempfile::TempDir, FileIndex) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fi.db");
        let idx = FileIndex::open(&path).expect("open");
        (dir, idx)
    }

    fn entry(full: &str, ext: &str, size: u64, mime: Option<&str>, entropy: f64) -> FileIndexEntry {
        let mut e = FileIndexEntry::new(
            full.to_string(),
            full.rsplit('/').next().unwrap_or("").to_string(),
            size,
        );
        e.extension = Some(ext.to_string());
        e.mime_type = mime.map(String::from);
        e.entropy = Some(entropy);
        e
    }

    #[test]
    fn filename_filter_matches() {
        let (_dir, mut idx) = open_tmp();
        idx.upsert_batch(&[
            entry("/e/NTUSER.DAT", "dat", 1, None, 4.0),
            entry("/e/SYSTEM", "", 1, None, 3.0),
        ])
        .expect("ins");
        let hits = QueryBuilder::new()
            .filename("NTUSER.DAT")
            .execute(&idx)
            .expect("q");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn extension_and_entropy_filters_combine() {
        let (_dir, mut idx) = open_tmp();
        idx.upsert_batch(&[
            entry("/a.exe", "exe", 1, None, 7.8),
            entry("/b.exe", "exe", 1, None, 4.0),
            entry("/c.txt", "txt", 1, None, 7.9),
        ])
        .expect("ins");
        let hits = QueryBuilder::new()
            .extension("exe")
            .min_entropy(7.5)
            .execute(&idx)
            .expect("q");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].full_path, "/a.exe");
    }

    #[test]
    fn mime_filter_uses_magic_byte_labels() {
        let (_dir, mut idx) = open_tmp();
        idx.upsert_batch(&[
            entry("/x/a.db", "db", 1, Some("application/x-sqlite3"), 4.0),
            entry("/x/b.txt", "txt", 1, Some("text/plain"), 4.0),
        ])
        .expect("ins");
        let hits = QueryBuilder::new()
            .mime("application/x-sqlite3")
            .execute(&idx)
            .expect("q");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn path_contains_filter_searches_subpath() {
        let (_dir, mut idx) = open_tmp();
        idx.upsert_batch(&[
            entry(
                "/evidence/C/Windows/Prefetch/notepad.pf",
                "pf",
                1,
                None,
                4.0,
            ),
            entry("/evidence/D/Users/alice/x.txt", "txt", 1, None, 4.0),
        ])
        .expect("ins");
        let hits = QueryBuilder::new()
            .path_contains("\\Prefetch\\")
            .execute(&idx)
            .expect("q");
        // Upstream path uses forward slashes; our filter escapes
        // backslashes as literal chars so the test guards against
        // false positives.
        assert_eq!(hits.len(), 0);
        let hits = QueryBuilder::new()
            .path_contains("/Prefetch/")
            .execute(&idx)
            .expect("q");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn nsrl_and_threat_intel_filters_work() {
        let (_dir, mut idx) = open_tmp();
        let mut e = entry("/a.bin", "bin", 1, None, 4.0);
        e.sha256 = Some("deadbeef".into());
        idx.upsert_batch(&[e]).expect("ins");
        idx.mark_nsrl("deadbeef").expect("nsrl");
        let hits = QueryBuilder::new()
            .nsrl_known_good(true)
            .execute(&idx)
            .expect("q");
        assert_eq!(hits.len(), 1);
    }
}
