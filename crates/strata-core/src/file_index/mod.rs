//! Master filesystem index — pre-scan foundation for all plugins.
//!
//! Walks a forensic image once, hashes every file in parallel, classifies
//! MIME types from magic bytes, computes entropy, and stores the result
//! in a SQLite database so every downstream plugin can query by
//! filename / extension / hash / size / MIME type rather than
//! re-walking the filesystem.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

pub mod database;
pub mod entropy;
pub mod indexer;
pub mod mime;
pub mod query;
pub mod ranking;

pub use database::{FileIndex, FileIndexEntry, FileIndexError};
pub use indexer::{IndexProgress, IndexerConfig, IndexerReport};
pub use query::QueryBuilder;
pub use ranking::{rank_artifacts, ScoredArtifact};
