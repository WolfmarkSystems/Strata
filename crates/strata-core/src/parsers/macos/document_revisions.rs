//! Document Revisions parser.
//!
//! Reads the database that backs macOS document versioning:
//!   `/.DocumentRevisions-V100/db-V1/db.sqlite`
//!
//! macOS automatically maintains version snapshots for documents created by
//! versioned apps (TextEdit, Pages, Numbers, Preview, Keynote, ...). Each
//! original file has a row in `files` and one or more rows in `generations`.
//! `generations.generation_path` points at a hard-linked copy under
//! `/.DocumentRevisions-V100/PerUID/<uid>/<id>/com.apple.documentVersions/`.
//!
//! Forensic value:
//! When a user deletes or modifies a sensitive file, the *previous version*
//! often survives in DocumentRevisions. This parser surfaces every generation
//! with its filename, original file path, and creation timestamp so the
//! examiner can recover deleted content.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// CFAbsoluteTime epoch offset (2001-01-01 -> Unix).
const COREDATA_EPOCH_OFFSET: i64 = 978_307_200;
const REVISION_LIMIT: usize = 5000;

pub struct MacosDocumentRevisionsParser;

impl MacosDocumentRevisionsParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosDocumentRevisionsParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevisionFile {
    pub file_row_id: i64,
    pub file_name: Option<String>,
    pub file_path: Option<String>,
    pub file_inode: Option<i64>,
    pub file_last_seen: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevisionGeneration {
    pub generation_id: i64,
    pub file_row_id: i64,
    pub generation_path: Option<String>,
    pub generation_name: Option<String>,
    pub generation_add_time: Option<i64>,
}

impl ArtifactParser for MacosDocumentRevisionsParser {
    fn name(&self) -> &str {
        "macOS Document Revisions"
    }

    fn artifact_type(&self) -> &str {
        "user_activity"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".documentrevisions-v100/db-v1/db.sqlite", "documentrevisions"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let path_str = path.to_string_lossy().to_lowercase();
        let in_doc_revisions = path_str.contains(".documentrevisions-v100");
        let is_sqlite = path_str.ends_with("db.sqlite");
        if !(in_doc_revisions && is_sqlite) {
            return Ok(Vec::new());
        }

        let mut artifacts = Vec::new();
        let result = with_sqlite_connection(path, data, |conn| {
            let mut entries: Vec<ParsedArtifact> = Vec::new();

            // Files table — original file metadata.
            if table_exists(conn, "files") {
                let sql = format!(
                    "SELECT file_row_id, file_name, file_path, file_inode, file_last_seen \
                     FROM files LIMIT {}",
                    REVISION_LIMIT
                );
                if let Ok(mut stmt) = conn.prepare(&sql) {
                    let rows = stmt
                        .query_map([], |row| {
                            Ok(RevisionFile {
                                file_row_id: row.get::<_, i64>(0).unwrap_or(0),
                                file_name: row.get(1).ok(),
                                file_path: row.get(2).ok(),
                                file_inode: row.get(3).ok(),
                                file_last_seen: row
                                    .get::<_, f64>(4)
                                    .ok()
                                    .map(|d| d as i64 + COREDATA_EPOCH_OFFSET),
                            })
                        })
                        .map_err(|e| ParserError::Database(e.to_string()))?;
                    for entry in rows.flatten() {
                        entries.push(ParsedArtifact {
                            timestamp: entry.file_last_seen,
                            artifact_type: "user_activity".to_string(),
                            description: format!(
                                "DocumentRevisions tracked file: {}",
                                entry.file_name.as_deref().unwrap_or("(unknown)")
                            ),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::to_value(entry).unwrap_or_default(),
                        });
                    }
                }
            }

            // Generations table — actual snapshot copies.
            if table_exists(conn, "generations") {
                let sql = format!(
                    "SELECT generation_id, file_row_id, generation_path, generation_name, \
                     generation_add_time FROM generations LIMIT {}",
                    REVISION_LIMIT
                );
                if let Ok(mut stmt) = conn.prepare(&sql) {
                    let rows = stmt
                        .query_map([], |row| {
                            Ok(RevisionGeneration {
                                generation_id: row.get::<_, i64>(0).unwrap_or(0),
                                file_row_id: row.get::<_, i64>(1).unwrap_or(0),
                                generation_path: row.get(2).ok(),
                                generation_name: row.get(3).ok(),
                                generation_add_time: row
                                    .get::<_, f64>(4)
                                    .ok()
                                    .map(|d| d as i64 + COREDATA_EPOCH_OFFSET),
                            })
                        })
                        .map_err(|e| ParserError::Database(e.to_string()))?;
                    for entry in rows.flatten() {
                        entries.push(ParsedArtifact {
                            timestamp: entry.generation_add_time,
                            artifact_type: "user_activity".to_string(),
                            description: format!(
                                "DocumentRevisions snapshot #{} for file_row_id={}",
                                entry.generation_id, entry.file_row_id
                            ),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::to_value(entry).unwrap_or_default(),
                        });
                    }
                }
            }

            Ok(entries)
        });

        if let Ok(mut entries) = result {
            artifacts.append(&mut entries);
        }
        Ok(artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn doc_rev_path() -> PathBuf {
        PathBuf::from("/Volumes/Macintosh HD/.DocumentRevisions-V100/db-V1/db.sqlite")
    }

    fn build_test_db(dir: &TempDir) -> PathBuf {
        let db_path = dir.path().join("db.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE files (
                file_row_id INTEGER PRIMARY KEY,
                file_name TEXT,
                file_path TEXT,
                file_inode INTEGER,
                file_last_seen REAL
            );
            CREATE TABLE generations (
                generation_id INTEGER PRIMARY KEY,
                file_row_id INTEGER,
                generation_path TEXT,
                generation_name TEXT,
                generation_add_time REAL
            );
            INSERT INTO files VALUES
                (1, 'report.pages', '/Users/test/Documents/report.pages', 12345, 700000000.0),
                (2, 'budget.numbers', '/Users/test/Documents/budget.numbers', 67890, 700000100.0);
            INSERT INTO generations VALUES
                (1, 1, '/.DocumentRevisions-V100/PerUID/501/1/com.apple.documentVersions/abcdef.pages',
                 'abcdef.pages', 700000050.0),
                (2, 2, '/.DocumentRevisions-V100/PerUID/501/2/com.apple.documentVersions/123456.numbers',
                 '123456.numbers', 700000150.0);",
        )
        .unwrap();
        db_path
    }

    #[test]
    fn parses_files_and_generations() {
        let dir = TempDir::new().unwrap();
        let db_path = build_test_db(&dir);
        let data = std::fs::read(&db_path).unwrap();

        let parser = MacosDocumentRevisionsParser::new();
        // Use the realistic doc-rev path so the path-guard fires.
        let out = parser.parse_file(&doc_rev_path(), &data).unwrap();
        let file_count = out
            .iter()
            .filter(|a| {
                a.description
                    .starts_with("DocumentRevisions tracked file")
            })
            .count();
        let gen_count = out
            .iter()
            .filter(|a| a.description.starts_with("DocumentRevisions snapshot"))
            .count();
        assert_eq!(file_count, 2);
        assert_eq!(gen_count, 2);
    }

    #[test]
    fn rejects_unrelated_paths() {
        let parser = MacosDocumentRevisionsParser::new();
        let path = PathBuf::from("/Users/test/Documents/db.sqlite");
        let out = parser.parse_file(&path, b"SQLite format 3\0").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn timestamp_offset_applied() {
        let dir = TempDir::new().unwrap();
        let db_path = build_test_db(&dir);
        let data = std::fs::read(&db_path).unwrap();
        let parser = MacosDocumentRevisionsParser::new();
        let out = parser.parse_file(&doc_rev_path(), &data).unwrap();
        // 700_000_000 + 978_307_200 = 1_678_307_200
        let any_match = out.iter().any(|a| a.timestamp == Some(1_678_307_200));
        assert!(any_match, "expected at least one Mac->Unix timestamp");
    }

    #[test]
    fn target_patterns_mention_doc_revisions() {
        let parser = MacosDocumentRevisionsParser::new();
        let patterns = parser.target_patterns();
        assert!(patterns.iter().any(|p| p.contains("documentrevisions")));
    }
}
