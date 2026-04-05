//! vt-snapshot: case and snapshot persistence store.

use anyhow::Result;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use vt_core::{FsType, Object, ObjectType};

pub fn init_db(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("\
        CREATE TABLE IF NOT EXISTS cases (id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);\
        CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, image_path TEXT NOT NULL, created_at TEXT NOT NULL);\
        CREATE TABLE IF NOT EXISTS objects (id INTEGER PRIMARY KEY, snapshot_id INTEGER NOT NULL, path TEXT NOT NULL, object_type TEXT NOT NULL, fs_type TEXT NOT NULL, size INTEGER NOT NULL, hashed INTEGER NOT NULL DEFAULT 0);\
        CREATE TABLE IF NOT EXISTS hashes (id INTEGER PRIMARY KEY, object_id INTEGER NOT NULL, hash_type TEXT NOT NULL, hash_value TEXT NOT NULL);\
    ")?;
    Ok(conn)
}

pub fn create_case(conn: &Connection, name: &str) -> Result<i64> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO cases (name, created_at) VALUES (?1, ?2)",
        params![name, now],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn create_snapshot(conn: &Connection, case_id: i64, image_path: &str) -> Result<i64> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO snapshots (case_id, image_path, created_at) VALUES (?1, ?2, ?3)",
        params![case_id, image_path, now],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn store_object(conn: &Connection, snapshot_id: i64, object: &Object) -> Result<i64> {
    let obj_type = format!("{:?}", object.object_type);
    let fs_type = format!("{:?}", object.fs_type);
    conn.execute(
        "INSERT INTO objects (snapshot_id, path, object_type, fs_type, size, hashed) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![snapshot_id, object.path, obj_type, fs_type, object.size as i64, 0],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn store_hash(
    conn: &Connection,
    object_id: i64,
    hash_type: &str,
    hash_value: &str,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO hashes (object_id, hash_type, hash_value) VALUES (?1, ?2, ?3)",
        params![object_id, hash_type, hash_value],
    )?;
    conn.execute(
        "UPDATE objects SET hashed = 1 WHERE id = ?1",
        params![object_id],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn list_snapshot_objects(conn: &Connection, snapshot_id: i64) -> Result<Vec<Object>> {
    let mut stmt = conn
        .prepare("SELECT path, object_type, fs_type, size FROM objects WHERE snapshot_id = ?1")?;
    let rows = stmt.query_map(params![snapshot_id], |row| {
        Ok(Object {
            path: row.get(0)?,
            object_type: match row.get::<_, String>(1)?.as_str() {
                "File" => ObjectType::File,
                "Directory" => ObjectType::Directory,
                "Unallocated" => ObjectType::Unallocated,
                "Slack" => ObjectType::Slack,
                "ArchiveMember" => ObjectType::ArchiveMember,
                _ => ObjectType::File,
            },
            fs_type: match row.get::<_, String>(2)?.as_str() {
                "Ntfs" => FsType::Ntfs,
                "Fat" => FsType::Fat,
                "Ext4" => FsType::Ext4,
                _ => FsType::Unknown,
            },
            size: row.get::<_, i64>(3)? as u64,
            inode: None,
            created_at: None,
            modified_at: None,
        })
    })?;

    Ok(rows.filter_map(Result::ok).collect())
}

pub fn diff_snapshots(
    conn: &Connection,
    old_snapshot: i64,
    new_snapshot: i64,
) -> Result<(Vec<Object>, Vec<Object>, Vec<Object>)> {
    let old_objects = list_snapshot_objects(conn, old_snapshot)?;
    let new_objects = list_snapshot_objects(conn, new_snapshot)?;

    let old_map: HashMap<String, Object> = old_objects
        .into_iter()
        .map(|o| (o.path.clone(), o))
        .collect();
    let new_map: HashMap<String, Object> = new_objects
        .into_iter()
        .map(|o| (o.path.clone(), o))
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    for (path, new_obj) in &new_map {
        if let Some(old_obj) = old_map.get(path) {
            if old_obj.size != new_obj.size || old_obj.object_type != new_obj.object_type {
                modified.push(new_obj.clone());
            }
        } else {
            added.push(new_obj.clone());
        }
    }

    for (path, old_obj) in &old_map {
        if !new_map.contains_key(path) {
            removed.push(old_obj.clone());
        }
    }

    Ok((added, removed, modified))
}

pub fn self_test() -> Result<()> {
    let conn = init_db(":memory:")?;
    let case_id = create_case(&conn, "test-case")?;
    let snapshot_id = create_snapshot(&conn, case_id, "test.img")?;
    let object = Object {
        path: "C:/test.txt".to_string(),
        object_type: ObjectType::File,
        fs_type: FsType::Ntfs,
        size: 10,
        inode: None,
        created_at: None,
        modified_at: None,
    };
    let object_id = store_object(&conn, snapshot_id, &object)?;
    store_hash(&conn, object_id, "sha256", "abcd")?;
    let objects = list_snapshot_objects(&conn, snapshot_id)?;
    assert_eq!(objects.len(), 1);

    let snapshot_id2 = create_snapshot(&conn, case_id, "test2.img")?;
    let object2 = Object {
        path: "C:/test2.txt".to_string(),
        object_type: ObjectType::File,
        fs_type: FsType::Ntfs,
        size: 20,
        inode: None,
        created_at: None,
        modified_at: None,
    };
    let _ = store_object(&conn, snapshot_id2, &object2)?;

    let (added, removed, modified) = diff_snapshots(&conn, snapshot_id, snapshot_id2)?;
    assert_eq!(added.len(), 1);
    assert_eq!(removed.len(), 1);
    assert_eq!(modified.len(), 0);

    Ok(())
}
