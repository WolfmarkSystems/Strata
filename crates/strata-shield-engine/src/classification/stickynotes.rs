use crate::errors::ForensicError;
use std::collections::HashMap;
use std::path::PathBuf;

use rusqlite::{Connection, Row};

#[derive(Debug, Clone, Default)]
pub struct StickyNote {
    pub id: String,
    pub text: String,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub position: (i32, i32),
    pub size: (i32, i32),
    pub color: String,
}

pub fn get_sticky_notes() -> Result<Vec<StickyNote>, ForensicError> {
    let mut out = Vec::new();
    for path in get_sticky_note_paths() {
        if let Ok(map) = parse_sticky_notes_database(&path) {
            out.extend(map.into_values());
        }
    }
    Ok(out)
}

pub fn get_sticky_note_paths() -> Vec<String> {
    let default = r"C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite".to_string();
    let user_profile = std::env::var("USERPROFILE").ok();
    let mut paths = Vec::new();

    if let Some(profile) = user_profile {
        let p = PathBuf::from(profile)
            .join("AppData")
            .join("Local")
            .join("Packages")
            .join("Microsoft.Windows.StickyNotes_8wekyb3d8bbwe")
            .join("LocalState")
            .join("plum.sqlite");
        paths.push(p.display().to_string());
    }

    if let Ok(custom) = std::env::var("FORENSIC_STICKY_DB") {
        paths.insert(0, custom);
    }

    if paths.is_empty() {
        paths.push(default);
    }
    paths
}

pub fn parse_sticky_notes_database(
    db_path: &str,
) -> Result<HashMap<String, StickyNote>, ForensicError> {
    let mut out = HashMap::new();
    let Ok(conn) = Connection::open(db_path) else {
        return Ok(out);
    };

    // Windows Sticky Notes schema has varied over builds.
    // Try known table/column variants and keep best-effort behavior.
    let mut loaded = load_notes_query(
        &conn,
        "SELECT Id, Text, CreatedAt, UpdatedAt FROM Note",
        &mut out,
    );
    if loaded == 0 {
        loaded += load_notes_query(
            &conn,
            "SELECT Id, Text, CreatedDateTime, UpdatedDateTime FROM Notes",
            &mut out,
        );
    }
    if loaded == 0 {
        let _ = load_notes_query(
            &conn,
            "SELECT Id, Text, DateCreated, DateModified FROM Notes",
            &mut out,
        );
    }

    Ok(out)
}

pub fn get_sticky_note_timestamps(note_id: &str) -> Result<NoteTimestamps, ForensicError> {
    let notes = get_sticky_notes()?;
    if let Some(note) = notes.into_iter().find(|n| n.id == note_id) {
        return Ok(NoteTimestamps {
            created: note.created,
            modified: note.modified,
            accessed: note.modified,
        });
    }

    Ok(NoteTimestamps {
        created: None,
        modified: None,
        accessed: None,
    })
}

#[derive(Debug, Clone, Default)]
pub struct NoteTimestamps {
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub accessed: Option<u64>,
}

fn load_notes_query(conn: &Connection, sql: &str, out: &mut HashMap<String, StickyNote>) -> usize {
    let mut loaded = 0usize;
    let Ok(mut stmt) = conn.prepare(sql) else {
        return loaded;
    };

    let rows = stmt.query_map([], parse_note_row);
    let Ok(iter) = rows else {
        return loaded;
    };
    for row in iter.flatten() {
        loaded += 1;
        out.insert(row.id.clone(), row);
    }

    loaded
}

fn parse_note_row(row: &Row<'_>) -> rusqlite::Result<StickyNote> {
    let id = row
        .get::<_, String>(0)
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    let text = row.get::<_, String>(1).unwrap_or_default();
    let created = coerce_time_to_u64(row.get_ref(2).ok());
    let modified = coerce_time_to_u64(row.get_ref(3).ok());

    Ok(StickyNote {
        id,
        text,
        created,
        modified,
        position: (0, 0),
        size: (320, 320),
        color: "yellow".to_string(),
    })
}

fn coerce_time_to_u64(value: Option<rusqlite::types::ValueRef<'_>>) -> Option<u64> {
    use rusqlite::types::ValueRef;
    match value {
        Some(ValueRef::Integer(v)) if v > 0 => Some(v as u64),
        Some(ValueRef::Real(v)) if v > 0.0 => Some(v as u64),
        Some(ValueRef::Text(t)) => {
            let s = String::from_utf8_lossy(t);
            s.trim().parse::<u64>().ok()
        }
        _ => None,
    }
}
