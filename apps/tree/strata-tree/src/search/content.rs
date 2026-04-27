//! Full-text content indexing via tantivy.
//! Indexes text-extractable files up to 10MB each.
//! Index stored in `<case_path>.index/` directory alongside the `.vtp` file.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Field, Schema, Value, STORED, TEXT};
use tantivy::{doc, Index, IndexWriter};

use crate::evidence::vfs_context::VfsReadContext;
use crate::state::FileEntry;

/// File extensions that can be text-extracted.
/// Expanded in Phase 2 to cover more forensically relevant formats.
const TEXT_EXTENSIONS: &[&str] = &[
    // Text and logs
    "txt",
    "log",
    "csv",
    "tsv",
    "xml",
    "html",
    "htm",
    "json",
    "jsonl",
    "ndjson",
    "eml",
    "msg",
    "mbox",
    "cfg",
    "ini",
    "conf",
    "config",
    "env",
    "properties",
    // Code and scripts
    "py",
    "js",
    "ts",
    "rs",
    "go",
    "c",
    "cpp",
    "cc",
    "cxx",
    "h",
    "hpp",
    "java",
    "kt",
    "kts",
    "swift",
    "m",
    "mm",
    "rb",
    "pl",
    "pm",
    "php",
    "cs",
    "fs",
    "vb",
    "vbs",
    "lua",
    "r",
    "scala",
    "groovy",
    "dart",
    // Shell and automation
    "bat",
    "cmd",
    "sh",
    "bash",
    "zsh",
    "fish",
    "ps1",
    "psm1",
    "psd1",
    // Data and markup
    "md",
    "rst",
    "tex",
    "yaml",
    "yml",
    "toml",
    "gradle",
    "cmake",
    "sql",
    "reg",
    "inf",
    "manifest",
    "plist",
    "strings",
    // Web
    "css",
    "scss",
    "less",
    "svg",
    "jsx",
    "tsx",
    "vue",
    "svelte",
    // DevOps and config
    "dockerfile",
    "vagrantfile",
    "makefile",
    "rakefile",
    "tf",
    "hcl",
    "bicep",
    "csproj",
    "sln",
    "vcxproj",
    // Forensic-specific
    "evtx_export",
    "timeline",
    "ioc",
    "yara",
    "sigma",
    "suricata",
    "rules",
    "snort",
    "zeek",
];

const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

pub struct ContentIndexSchema {
    pub schema: Schema,
    pub field_id: Field,
    pub field_path: Field,
    pub field_body: Field,
}

impl ContentIndexSchema {
    pub fn new() -> Self {
        let mut schema_builder = Schema::builder();
        let field_id = schema_builder.add_text_field("file_id", STORED);
        let field_path = schema_builder.add_text_field("path", STORED);
        let field_body = schema_builder.add_text_field("body", TEXT);
        let schema = schema_builder.build();
        Self {
            schema,
            field_id,
            field_path,
            field_body,
        }
    }
}

pub struct ContentIndexer {
    index_dir: PathBuf,
}

impl ContentIndexer {
    pub fn new(index_dir: impl AsRef<Path>) -> Self {
        Self {
            index_dir: index_dir.as_ref().to_path_buf(),
        }
    }

    /// Index directory for a .vtp case file.
    pub fn index_dir_for_case(vtp_path: &Path) -> PathBuf {
        let mut p = vtp_path.to_path_buf();
        let stem = p
            .file_stem()
            .map(|s| format!("{}.index", s.to_string_lossy()))
            .unwrap_or_else(|| "case.index".to_string());
        p.set_file_name(stem);
        p
    }

    /// Build or rebuild the tantivy index from file entries.
    pub fn build_index(
        &self,
        files: &[FileEntry],
        ctx: Option<&VfsReadContext>,
        progress_tx: Option<Sender<ContentIndexProgress>>,
    ) -> Result<ContentIndexStats> {
        std::fs::create_dir_all(&self.index_dir)
            .with_context(|| format!("Cannot create index dir: {}", self.index_dir.display()))?;

        let ci_schema = ContentIndexSchema::new();
        let index = match Index::open_in_dir(&self.index_dir) {
            Ok(idx) => idx,
            Err(_) => Index::create_in_dir(&self.index_dir, ci_schema.schema.clone())
                .context("Failed to create tantivy index")?,
        };

        let mut writer: IndexWriter = index
            .writer(50_000_000)
            .context("Failed to create index writer")?;
        writer
            .delete_all_documents()
            .context("Failed to clear existing index documents")?;

        let mut indexed = 0u64;
        let mut skipped = 0u64;
        let total = files.len() as u64;
        let mut scanned = 0u64;

        for entry in files {
            if entry.is_dir {
                continue;
            }
            scanned = scanned.saturating_add(1);

            // Check extension.
            let ext = entry
                .extension
                .as_deref()
                .map(|e| e.to_ascii_lowercase())
                .or_else(|| {
                    Path::new(&entry.path)
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.to_ascii_lowercase())
                })
                .unwrap_or_default();

            if !TEXT_EXTENSIONS.contains(&ext.as_str()) {
                skipped += 1;
                if scanned.is_multiple_of(100) {
                    if let Some(tx) = &progress_tx {
                        let _ = tx.send(ContentIndexProgress::Progress {
                            indexed: scanned,
                            total,
                        });
                    }
                }
                continue;
            }

            // Check size.
            let size = entry.size.unwrap_or_else(|| {
                std::fs::metadata(&entry.path)
                    .map(|m| m.len())
                    .unwrap_or(u64::MAX)
            });
            if size > MAX_FILE_SIZE_BYTES {
                skipped += 1;
                if scanned.is_multiple_of(100) {
                    if let Some(tx) = &progress_tx {
                        let _ = tx.send(ContentIndexProgress::Progress {
                            indexed: scanned,
                            total,
                        });
                    }
                }
                continue;
            }

            // Read content.
            let bytes = if let Some(read_ctx) = ctx {
                match read_ctx.read_file(entry) {
                    Ok(b) => b,
                    Err(_) => {
                        skipped += 1;
                        if scanned.is_multiple_of(100) {
                            if let Some(tx) = &progress_tx {
                                let _ = tx.send(ContentIndexProgress::Progress {
                                    indexed: scanned,
                                    total,
                                });
                            }
                        }
                        continue;
                    }
                }
            } else {
                match std::fs::read(&entry.path) {
                    Ok(b) => b,
                    Err(_) => {
                        skipped += 1;
                        if scanned.is_multiple_of(100) {
                            if let Some(tx) = &progress_tx {
                                let _ = tx.send(ContentIndexProgress::Progress {
                                    indexed: scanned,
                                    total,
                                });
                            }
                        }
                        continue;
                    }
                }
            };
            let content = String::from_utf8_lossy(&bytes).into_owned();

            let _ = writer.add_document(doc!(
                ci_schema.field_id   => entry.id.as_str(),
                ci_schema.field_path => entry.path.as_str(),
                ci_schema.field_body => content.as_str(),
            ));

            indexed += 1;
            if scanned.is_multiple_of(100) {
                if let Some(tx) = &progress_tx {
                    let _ = tx.send(ContentIndexProgress::Progress {
                        indexed: scanned,
                        total,
                    });
                }
            }
        }

        writer.commit().context("Failed to commit tantivy index")?;

        if let Some(tx) = &progress_tx {
            let _ = tx.send(ContentIndexProgress::Complete(ContentIndexStats {
                indexed,
                skipped,
            }));
        }

        Ok(ContentIndexStats { indexed, skipped })
    }

    /// Search the tantivy index.
    pub fn search(&self, query_str: &str, max_results: usize) -> Result<Vec<ContentSearchHit>> {
        let ci_schema = ContentIndexSchema::new();
        let index = Index::open_in_dir(&self.index_dir).context("Content index not built yet")?;

        let reader = index.reader().context("Failed to open reader")?;

        let searcher = reader.searcher();
        let query_parser = QueryParser::for_index(&index, vec![ci_schema.field_body]);
        let query = match query_parser.parse_query(query_str) {
            Ok(q) => q,
            Err(_) => {
                let escaped = query_str.replace('"', " ").trim().to_string();
                if escaped.is_empty() {
                    return Ok(Vec::new());
                }
                match query_parser.parse_query(&escaped) {
                    Ok(q) => q,
                    Err(_) => return Ok(Vec::new()),
                }
            }
        };

        let top_docs = searcher
            .search(&query, &TopDocs::with_limit(max_results))
            .context("Search failed")?;

        let mut hits = Vec::new();
        for (score, doc_addr) in top_docs {
            let doc: tantivy::TantivyDocument =
                searcher.doc(doc_addr).context("Failed to retrieve doc")?;
            let file_id = doc
                .get_first(ci_schema.field_id)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let file_path = doc
                .get_first(ci_schema.field_path)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            hits.push(ContentSearchHit {
                file_id,
                file_path,
                score,
            });
        }

        Ok(hits)
    }
}

#[derive(Debug, Clone)]
pub struct ContentSearchHit {
    pub file_id: String,
    pub file_path: String,
    pub score: f32,
}

#[derive(Debug)]
pub struct ContentIndexStats {
    pub indexed: u64,
    pub skipped: u64,
}

#[derive(Debug)]
pub enum ContentIndexProgress {
    Progress { indexed: u64, total: u64 },
    Complete(ContentIndexStats),
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::ContentIndexer;
    use crate::state::FileEntry;

    #[test]
    fn indexes_and_searches_text_content() {
        let root = std::env::temp_dir().join(format!(
            "strata_content_search_test_{}",
            uuid::Uuid::new_v4()
        ));
        let index_dir = root.join("case.index");
        std::fs::create_dir_all(&root).expect("create temp root");

        let file_path = root.join("notes.txt");
        std::fs::write(&file_path, b"mimikatz execution observed in temp directory")
            .expect("write test file");

        let file_entry = FileEntry {
            id: uuid::Uuid::new_v4().to_string(),
            evidence_id: "ev-test".to_string(),
            path: file_path.to_string_lossy().to_string(),
            vfs_path: file_path.to_string_lossy().to_string(),
            parent_path: root.to_string_lossy().to_string(),
            name: "notes.txt".to_string(),
            extension: Some("txt".to_string()),
            size: std::fs::metadata(&file_path).ok().map(|m| m.len()),
            ..Default::default()
        };

        let indexer = ContentIndexer::new(&index_dir);
        let stats = indexer
            .build_index(std::slice::from_ref(&file_entry), None, None)
            .expect("build index");
        assert_eq!(stats.indexed, 1);

        let hits = indexer.search("mimikatz", 10).expect("search index");
        assert!(!hits.is_empty(), "expected content hit");
        assert_eq!(hits[0].file_id, file_entry.id);

        let _ = std::fs::remove_dir_all(&root);
    }
}
