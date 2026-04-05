use crate::parser::ParserError;
use rusqlite::Connection;
use std::path::Path;
use uuid::Uuid;

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

pub(crate) fn looks_like_sqlite(data: &[u8]) -> bool {
    data.len() >= SQLITE_MAGIC.len() && &data[..SQLITE_MAGIC.len()] == SQLITE_MAGIC
}

pub(crate) fn with_sqlite_connection<T, F>(path: &Path, data: &[u8], f: F) -> Result<T, ParserError>
where
    F: FnOnce(&Connection) -> Result<T, ParserError>,
{
    if let Ok(conn) = Connection::open(path) {
        return f(&conn);
    }

    if !looks_like_sqlite(data) {
        return Err(ParserError::Database(
            "SQLite header not found in provided bytes".to_string(),
        ));
    }

    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!("forensic-suite-{}.db", Uuid::new_v4()));
    std::fs::write(&temp_path, data)?;

    // Heuristically look for and copy -wal and -shm files if they exist in the same source directory
    if let (Some(parent), Some(stem)) = (path.parent(), path.file_name()) {
        let wal_name = format!("{}-wal", stem.to_string_lossy());
        let shm_name = format!("{}-shm", stem.to_string_lossy());

        let wal_source = parent.join(&wal_name);
        if wal_source.exists() {
            let _ = std::fs::copy(&wal_source, temp_dir.join(&wal_name));
        }

        let shm_source = parent.join(&shm_name);
        if shm_source.exists() {
            let _ = std::fs::copy(&shm_source, temp_dir.join(&shm_name));
        }
    }

    let conn = Connection::open(&temp_path).map_err(|e| ParserError::Database(e.to_string()))?;
    let result = f(&conn);
    drop(conn);
    let _ = std::fs::remove_file(&temp_path);
    result
}

pub(crate) fn table_exists(conn: &Connection, table: &str) -> bool {
    let mut stmt = match conn.prepare(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND lower(name) = lower(?1) LIMIT 1",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return false,
    };
    match stmt.query_row([table], |_row| Ok(())) {
        Ok(_) => true,
        Err(rusqlite::Error::QueryReturnedNoRows) => false,
        Err(_) => false,
    }
}

pub(crate) fn list_tables(conn: &Connection) -> Vec<String> {
    let mut out = Vec::new();
    let mut stmt = match conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    {
        Ok(stmt) => stmt,
        Err(_) => return out,
    };

    let rows = stmt.query_map([], |row| row.get::<_, String>(0));
    let Ok(rows) = rows else {
        return out;
    };

    for row in rows.flatten() {
        out.push(row);
    }
    out
}

pub(crate) fn table_columns(conn: &Connection, table: &str) -> Vec<String> {
    let mut out = Vec::new();
    let sql = format!("PRAGMA table_info({})", quote_identifier(table));
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(_) => return out,
    };
    let rows = stmt.query_map([], |row| row.get::<_, String>(1));
    let Ok(rows) = rows else {
        return out;
    };
    for row in rows.flatten() {
        out.push(row);
    }
    out
}

pub(crate) fn quote_identifier(name: &str) -> String {
    let escaped = name.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}
