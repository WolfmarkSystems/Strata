//! Case-scoped artifact persistence layer.
//!
//! PERSIST-1: every plugin artifact emitted during an ingest run
//! writes to a per-case SQLite database (`artifacts.sqlite`) so the
//! run can be closed, reopened, queried, and reported later. Replaces
//! the earlier "everything flows through memory and dies with the
//! CLI process" behaviour.

pub mod database;

pub use database::{ArtifactDatabase, StoredArtifact};
