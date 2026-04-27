//! SQLite-backed charge database.

use crate::schema::{ChargeEntry, ChargeSet, ChargeSeverity};
use rusqlite::{params, Connection};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ChargeError {
    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("Seed error: {0}")]
    Seed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct ChargeDatabase {
    conn: Connection,
}

impl ChargeDatabase {
    /// Open the charge database at path, creating and seeding if not present.
    pub fn open(path: &Path) -> Result<Self, ChargeError> {
        let needs_seed = !path.exists();
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let mut db = Self { conn };
        db.ensure_schema()?;
        if needs_seed {
            db.seed()?;
        }
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> Result<Self, ChargeError> {
        let conn = Connection::open_in_memory()?;
        let mut db = Self { conn };
        db.ensure_schema()?;
        db.seed()?;
        Ok(db)
    }

    fn ensure_schema(&self) -> Result<(), ChargeError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS charges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_set TEXT NOT NULL,
                title INTEGER,
                section TEXT NOT NULL,
                subsection TEXT,
                citation TEXT NOT NULL UNIQUE,
                short_title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                artifact_tags TEXT NOT NULL DEFAULT '[]',
                severity TEXT NOT NULL,
                state_code TEXT,
                max_penalty TEXT,
                notes TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_charges_code_set ON charges(code_set);
            CREATE INDEX IF NOT EXISTS idx_charges_category ON charges(category);
            CREATE INDEX IF NOT EXISTS idx_charges_citation ON charges(citation);",
        )?;
        Ok(())
    }

    /// Seed the database with all federal and UCMJ charges.
    pub fn seed(&mut self) -> Result<(), ChargeError> {
        let tx = self.conn.transaction()?;
        for entry in crate::federal::federal_charges() {
            insert_charge(&tx, &entry)?;
        }
        for entry in crate::ucmj::ucmj_charges() {
            insert_charge(&tx, &entry)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Full-text search across citation, short_title, description.
    pub fn search(&self, query: &str) -> Result<Vec<ChargeEntry>, ChargeError> {
        let pattern = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT * FROM charges WHERE citation LIKE ?1 OR short_title LIKE ?1 OR description LIKE ?1 OR category LIKE ?1 LIMIT 200",
        )?;
        collect_rows(&mut stmt, params![pattern])
    }

    /// Filter by code set (USC, UCMJ, State).
    pub fn by_code_set(&self, set: ChargeSet) -> Result<Vec<ChargeEntry>, ChargeError> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM charges WHERE code_set = ?1")?;
        collect_rows(&mut stmt, params![set.as_str()])
    }

    /// Filter by USC title number.
    pub fn by_title(&self, title: u32) -> Result<Vec<ChargeEntry>, ChargeError> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM charges WHERE title = ?1")?;
        collect_rows(&mut stmt, params![title])
    }

    /// Filter by category string.
    pub fn by_category(&self, category: &str) -> Result<Vec<ChargeEntry>, ChargeError> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM charges WHERE category = ?1")?;
        collect_rows(&mut stmt, params![category])
    }

    /// Get all unique categories.
    pub fn categories(&self) -> Result<Vec<String>, ChargeError> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT category FROM charges ORDER BY category")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.flatten().collect())
    }

    /// Get charges that map to a given artifact tag.
    pub fn by_artifact_tag(&self, tag: &str) -> Result<Vec<ChargeEntry>, ChargeError> {
        let pattern = format!("%\"{}%", tag);
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM charges WHERE artifact_tags LIKE ?1")?;
        collect_rows(&mut stmt, params![pattern])
    }

    /// Get a specific charge by its citation string.
    pub fn by_citation(&self, citation: &str) -> Result<Option<ChargeEntry>, ChargeError> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM charges WHERE citation = ?1")?;
        let mut rows = stmt.query_map(params![citation], row_to_entry)?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    /// Get total count of charges in database.
    pub fn count(&self) -> Result<usize, ChargeError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM charges", [], |row| row.get(0))?;
        Ok(n as usize)
    }
}

fn insert_charge(conn: &Connection, e: &ChargeEntry) -> Result<(), ChargeError> {
    let tags_json = serde_json::to_string(&e.artifact_tags).unwrap_or_else(|_| "[]".to_string());
    conn.execute(
        "INSERT OR IGNORE INTO charges (code_set, title, section, subsection, citation, \
         short_title, description, category, artifact_tags, severity, state_code, max_penalty, notes) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            e.code_set.as_str(),
            e.title,
            e.section,
            e.subsection,
            e.citation,
            e.short_title,
            e.description,
            e.category,
            tags_json,
            e.severity.as_str(),
            e.state_code,
            e.max_penalty,
            e.notes,
        ],
    )?;
    Ok(())
}

fn row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<ChargeEntry> {
    let code_set_str: String = row.get(1)?;
    let code_set = match code_set_str.as_str() {
        "UCMJ" => ChargeSet::UCMJ,
        "State" => ChargeSet::State,
        _ => ChargeSet::USC,
    };
    let severity_str: String = row.get(10)?;
    let severity = match severity_str.as_str() {
        "Misdemeanor" => ChargeSeverity::Misdemeanor,
        "UCMJ Article" => ChargeSeverity::UCMJArticle,
        "Infrastructure Offense" => ChargeSeverity::InfrastructureOffense,
        _ => ChargeSeverity::Felony,
    };
    let tags_str: String = row.get(9)?;
    let artifact_tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();

    Ok(ChargeEntry {
        id: row.get(0)?,
        code_set,
        title: row.get(2)?,
        section: row.get(3)?,
        subsection: row.get(4)?,
        citation: row.get(5)?,
        short_title: row.get(6)?,
        description: row.get(7)?,
        category: row.get(8)?,
        artifact_tags,
        severity,
        state_code: row.get(11)?,
        max_penalty: row.get(12)?,
        notes: row.get(13)?,
    })
}

fn collect_rows(
    stmt: &mut rusqlite::Statement,
    params: impl rusqlite::Params,
) -> Result<Vec<ChargeEntry>, ChargeError> {
    let rows = stmt.query_map(params, row_to_entry)?;
    Ok(rows.flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_opens_and_seeds_correctly() {
        let db = ChargeDatabase::open_memory().unwrap();
        let count = db.count().unwrap();
        assert!(count > 100, "expected >100 charges, got {}", count);
    }

    #[test]
    fn search_returns_results_for_csam() {
        let db = ChargeDatabase::open_memory().unwrap();
        let results = db.search("child exploitation").unwrap();
        let citations: Vec<&str> = results.iter().map(|c| c.citation.as_str()).collect();
        assert!(
            citations.iter().any(|c| c.contains("2252")),
            "expected § 2252 in results: {:?}",
            citations
        );
    }

    #[test]
    fn search_returns_results_for_ucmj() {
        let db = ChargeDatabase::open_memory().unwrap();
        let results = db.search("rape").unwrap();
        assert!(
            results
                .iter()
                .any(|c| c.code_set == ChargeSet::UCMJ && c.citation.contains("120")),
            "expected UCMJ Art. 120"
        );
    }

    #[test]
    fn search_by_citation_exact_match() {
        let db = ChargeDatabase::open_memory().unwrap();
        let entry = db.by_citation("18 U.S.C. § 1030").unwrap();
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.section, "1030");
        assert!(e.short_title.contains("Computer Fraud"));
    }

    #[test]
    fn categories_returns_non_empty_list() {
        let db = ChargeDatabase::open_memory().unwrap();
        let cats = db.categories().unwrap();
        assert!(
            cats.len() >= 10,
            "expected >=10 categories, got {}",
            cats.len()
        );
    }

    #[test]
    fn by_code_set_returns_only_usc() {
        let db = ChargeDatabase::open_memory().unwrap();
        let usc = db.by_code_set(ChargeSet::USC).unwrap();
        assert!(!usc.is_empty());
        assert!(usc.iter().all(|c| c.code_set == ChargeSet::USC));
    }

    #[test]
    fn by_code_set_returns_only_ucmj() {
        let db = ChargeDatabase::open_memory().unwrap();
        let ucmj = db.by_code_set(ChargeSet::UCMJ).unwrap();
        assert!(!ucmj.is_empty());
        assert!(ucmj.iter().all(|c| c.code_set == ChargeSet::UCMJ));
    }

    #[test]
    fn by_artifact_tag_finds_media() {
        let db = ChargeDatabase::open_memory().unwrap();
        let results = db.by_artifact_tag("Media").unwrap();
        assert!(!results.is_empty(), "expected charges with Media tag");
    }
}
