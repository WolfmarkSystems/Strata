use rusqlite::{params, Connection, Result as SqliteResult};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub id: i64,
    pub case_id: String,
    pub evidence_path: String,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub size: u64,
    pub sector_size: u64,
    pub disk_layout: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct VolumeRecord {
    pub id: i64,
    pub evidence_id: i64,
    pub index: u32,
    pub offset: u64,
    pub size: u64,
    pub filesystem: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub id: i64,
    pub volume_id: i64,
    pub record_number: u32,
    pub path: String,
    pub name: String,
    pub size: u64,
    pub is_directory: bool,
    pub created: Option<i64>,
    pub modified: Option<i64>,
}

pub struct EvidenceCatalog {
    conn: Connection,
}

impl EvidenceCatalog {
    pub fn create(path: &Path) -> SqliteResult<Self> {
        let conn = Connection::open(path)?;
        let catalog = Self { conn };
        catalog.init_schema()?;
        Ok(catalog)
    }

    pub fn create_in_memory() -> SqliteResult<Self> {
        let conn = Connection::open_in_memory()?;
        let catalog = Self { conn };
        catalog.init_schema()?;
        Ok(catalog)
    }

    fn init_schema(&self) -> SqliteResult<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                evidence_path TEXT NOT NULL,
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT,
                size INTEGER NOT NULL,
                sector_size INTEGER NOT NULL,
                disk_layout TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS volumes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL,
                volume_index INTEGER NOT NULL,
                offset INTEGER NOT NULL,
                size INTEGER NOT NULL,
                filesystem TEXT,
                FOREIGN KEY(evidence_id) REFERENCES evidence(id)
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                volume_id INTEGER NOT NULL,
                record_number INTEGER NOT NULL,
                path TEXT NOT NULL,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                is_directory INTEGER NOT NULL,
                created INTEGER,
                modified INTEGER,
                FOREIGN KEY(volume_id) REFERENCES volumes(id)
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)",
            [],
        )?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_evidence(
        &mut self,
        case_id: &str,
        path: &str,
        md5: Option<&str>,
        sha1: Option<&str>,
        sha256: Option<&str>,
        size: u64,
        sector_size: u64,
        disk_layout: &str,
    ) -> SqliteResult<i64> {
        let created_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();

        self.conn.execute(
            "INSERT INTO evidence (case_id, evidence_path, md5, sha1, sha256, size, sector_size, disk_layout, created_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![case_id, path, md5, sha1, sha256, size, sector_size, disk_layout, created_at],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn insert_volume(
        &mut self,
        evidence_id: i64,
        index: u32,
        offset: u64,
        size: u64,
        filesystem: Option<&str>,
    ) -> SqliteResult<i64> {
        self.conn.execute(
            "INSERT INTO volumes (evidence_id, volume_index, offset, size, filesystem) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![evidence_id, index, offset, size, filesystem],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_file(
        &mut self,
        volume_id: i64,
        record_number: u32,
        path: &str,
        name: &str,
        size: u64,
        is_directory: bool,
        created: Option<i64>,
        modified: Option<i64>,
    ) -> SqliteResult<i64> {
        self.conn.execute(
            "INSERT INTO files (volume_id, record_number, path, name, size, is_directory, created, modified) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![volume_id, record_number, path, name, size, is_directory as i32, created, modified],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_evidence_by_case(&self, case_id: &str) -> SqliteResult<Vec<EvidenceRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, case_id, evidence_path, md5, sha1, sha256, size, sector_size, disk_layout, created_at 
             FROM evidence WHERE case_id = ?1"
        )?;

        let records = stmt.query_map([case_id], |row| {
            Ok(EvidenceRecord {
                id: row.get(0)?,
                case_id: row.get(1)?,
                evidence_path: row.get(2)?,
                md5: row.get(3)?,
                sha1: row.get(4)?,
                sha256: row.get(5)?,
                size: row.get(6)?,
                sector_size: row.get(7)?,
                disk_layout: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;

        records.collect()
    }

    pub fn search_files_by_name(&self, name_pattern: &str) -> SqliteResult<Vec<FileRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, volume_id, record_number, path, name, size, is_directory, created, modified 
             FROM files WHERE name LIKE ?1"
        )?;

        let pattern = format!("%{}%", name_pattern);
        let records = stmt.query_map([pattern], |row| {
            Ok(FileRecord {
                id: row.get(0)?,
                volume_id: row.get(1)?,
                record_number: row.get(2)?,
                path: row.get(3)?,
                name: row.get(4)?,
                size: row.get(5)?,
                is_directory: row.get::<_, i32>(6)? != 0,
                created: row.get(7)?,
                modified: row.get(8)?,
            })
        })?;

        records.collect()
    }
}
