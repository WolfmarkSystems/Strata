use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityViolation {
    pub id: i64,
    pub case_id: String,
    pub occurred_utc: String,
    pub table_name: String,
    pub operation: String,
    pub row_key: Option<String>,
    pub actor: Option<String>,
    pub reason: String,
    pub details_json: String,
}

pub const PROTECTED_TABLES: &[&str] = &[
    "activity_log",
    "provenance",
    "exhibit_packets",
    "case_verifications",
    "case_replays",
    "evidence_timeline",
];

pub fn create_integrity_watchpoint_triggers(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        DROP TRIGGER IF EXISTS integrity_activity_log_insert;
        DROP TRIGGER IF EXISTS integrity_activity_log_update;
        DROP TRIGGER IF EXISTS integrity_activity_log_delete;
        DROP TRIGGER IF EXISTS integrity_provenance_insert;
        DROP TRIGGER IF EXISTS integrity_provenance_update;
        DROP TRIGGER IF EXISTS integrity_provenance_delete;
        DROP TRIGGER IF EXISTS integrity_exhibit_packets_insert;
        DROP TRIGGER IF EXISTS integrity_exhibit_packets_update;
        DROP TRIGGER IF EXISTS integrity_exhibit_packets_delete;
        DROP TRIGGER IF EXISTS integrity_case_verifications_insert;
        DROP TRIGGER IF EXISTS integrity_case_verifications_update;
        DROP TRIGGER IF EXISTS integrity_case_verifications_delete;
        DROP TRIGGER IF EXISTS integrity_case_replays_insert;
        DROP TRIGGER IF EXISTS integrity_case_replays_update;
        DROP TRIGGER IF EXISTS integrity_case_replays_delete;
        DROP TRIGGER IF EXISTS integrity_evidence_timeline_insert;
        DROP TRIGGER IF EXISTS integrity_evidence_timeline_update;
        DROP TRIGGER IF EXISTS integrity_evidence_timeline_delete;
        ",
    )?;

    if !table_exists(conn, "case_settings")? || !table_exists(conn, "integrity_violations")? {
        return Ok(());
    }

    for spec in trigger_specs() {
        if !table_exists(conn, spec.table)? {
            continue;
        }
        let sql = build_watchpoint_trigger_sql(spec);
        conn.execute_batch(&sql)?;
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct TriggerSpec {
    table: &'static str,
    row_key_new: &'static str,
    row_key_old: &'static str,
    details_insert: &'static str,
    details_update: &'static str,
    details_delete: &'static str,
}

fn trigger_specs() -> [TriggerSpec; 6] {
    [
        TriggerSpec {
            table: "activity_log",
            row_key_new: "NEW.id",
            row_key_old: "OLD.id",
            details_insert: "json_object('case_id', NEW.case_id, 'row_key', NEW.id, 'event_type', NEW.event_type, 'summary', NEW.summary)",
            details_update: "json_object('case_id', NEW.case_id, 'row_key', NEW.id, 'event_type', NEW.event_type)",
            details_delete: "json_object('case_id', OLD.case_id, 'row_key', OLD.id)",
        },
        TriggerSpec {
            table: "provenance",
            row_key_new: "NEW.id",
            row_key_old: "OLD.id",
            details_insert: "json_object('case_id', NEW.case_id, 'row_key', NEW.id, 'object_id', NEW.object_id, 'action', NEW.action)",
            details_update: "json_object('case_id', NEW.case_id, 'row_key', NEW.id)",
            details_delete: "json_object('case_id', OLD.case_id, 'row_key', OLD.id)",
        },
        TriggerSpec {
            table: "exhibit_packets",
            row_key_new: "NEW.id",
            row_key_old: "OLD.id",
            details_insert: "json_object('case_id', NEW.case_id, 'row_key', NEW.id, 'name', NEW.name)",
            details_update: "json_object('case_id', NEW.case_id, 'row_key', NEW.id)",
            details_delete: "json_object('case_id', OLD.case_id, 'row_key', OLD.id)",
        },
        TriggerSpec {
            table: "case_verifications",
            row_key_new: "CAST(NEW.id AS TEXT)",
            row_key_old: "CAST(OLD.id AS TEXT)",
            details_insert: "json_object('case_id', NEW.case_id, 'row_id', NEW.id, 'status', NEW.status)",
            details_update: "json_object('case_id', NEW.case_id, 'row_id', NEW.id)",
            details_delete: "json_object('case_id', OLD.case_id, 'row_id', OLD.id)",
        },
        TriggerSpec {
            table: "case_replays",
            row_key_new: "CAST(NEW.id AS TEXT)",
            row_key_old: "CAST(OLD.id AS TEXT)",
            details_insert: "json_object('case_id', NEW.case_id, 'row_id', NEW.id, 'status', NEW.status)",
            details_update: "json_object('case_id', NEW.case_id, 'row_id', NEW.id)",
            details_delete: "json_object('case_id', OLD.case_id, 'row_id', OLD.id)",
        },
        TriggerSpec {
            table: "evidence_timeline",
            row_key_new: "NEW.id",
            row_key_old: "OLD.id",
            details_insert: "json_object('case_id', NEW.case_id, 'row_key', NEW.id, 'event_type', NEW.event_type, 'artifact_id', NEW.artifact_id)",
            details_update: "json_object('case_id', NEW.case_id, 'row_key', NEW.id)",
            details_delete: "json_object('case_id', OLD.case_id, 'row_key', OLD.id)",
        },
    ]
}

fn build_watchpoint_trigger_sql(spec: TriggerSpec) -> String {
    format!(
        "
        CREATE TRIGGER integrity_{table}_insert AFTER INSERT ON {table}
        WHEN (SELECT value FROM case_settings WHERE case_id = NEW.case_id AND key = 'integrity_watchpoints_enabled') = '1'
        BEGIN
            INSERT INTO integrity_violations (case_id, occurred_utc, table_name, operation, row_key, actor, reason, details_json)
            VALUES (
                NEW.case_id,
                strftime('%Y-%m-%dT%H:%fZ', 'now'),
                '{table}',
                'INSERT',
                {row_key_new},
                (SELECT value FROM case_settings WHERE case_id = NEW.case_id AND key = 'current_actor'),
                'WATCHPOINT_TRIGGER',
                {details_insert}
            );
        END;

        CREATE TRIGGER integrity_{table}_update AFTER UPDATE ON {table}
        WHEN (SELECT value FROM case_settings WHERE case_id = NEW.case_id AND key = 'integrity_watchpoints_enabled') = '1'
        BEGIN
            INSERT INTO integrity_violations (case_id, occurred_utc, table_name, operation, row_key, actor, reason, details_json)
            VALUES (
                NEW.case_id,
                strftime('%Y-%m-%dT%H:%fZ', 'now'),
                '{table}',
                'UPDATE',
                {row_key_new},
                (SELECT value FROM case_settings WHERE case_id = NEW.case_id AND key = 'current_actor'),
                'WATCHPOINT_TRIGGER',
                {details_update}
            );
        END;

        CREATE TRIGGER integrity_{table}_delete AFTER DELETE ON {table}
        WHEN (SELECT value FROM case_settings WHERE case_id = OLD.case_id AND key = 'integrity_watchpoints_enabled') = '1'
        BEGIN
            INSERT INTO integrity_violations (case_id, occurred_utc, table_name, operation, row_key, actor, reason, details_json)
            VALUES (
                OLD.case_id,
                strftime('%Y-%m-%dT%H:%fZ', 'now'),
                '{table}',
                'DELETE',
                {row_key_old},
                (SELECT value FROM case_settings WHERE case_id = OLD.case_id AND key = 'current_actor'),
                'WATCHPOINT_TRIGGER',
                {details_delete}
            );
        END;
        ",
        table = spec.table,
        row_key_new = spec.row_key_new,
        row_key_old = spec.row_key_old,
        details_insert = spec.details_insert,
        details_update = spec.details_update,
        details_delete = spec.details_delete
    )
}

fn table_exists(conn: &Connection, table: &str) -> SqliteResult<bool> {
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )?;
    Ok(exists == 1)
}

pub fn drop_integrity_watchpoint_triggers(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        DROP TRIGGER IF EXISTS integrity_activity_log_insert;
        DROP TRIGGER IF EXISTS integrity_activity_log_update;
        DROP TRIGGER IF EXISTS integrity_activity_log_delete;
        DROP TRIGGER IF EXISTS integrity_provenance_insert;
        DROP TRIGGER IF EXISTS integrity_provenance_update;
        DROP TRIGGER IF EXISTS integrity_provenance_delete;
        DROP TRIGGER IF EXISTS integrity_exhibit_packets_insert;
        DROP TRIGGER IF EXISTS integrity_exhibit_packets_update;
        DROP TRIGGER IF EXISTS integrity_exhibit_packets_delete;
        DROP TRIGGER IF EXISTS integrity_case_verifications_insert;
        DROP TRIGGER IF EXISTS integrity_case_verifications_update;
        DROP TRIGGER IF EXISTS integrity_case_verifications_delete;
        DROP TRIGGER IF EXISTS integrity_case_replays_insert;
        DROP TRIGGER IF EXISTS integrity_case_replays_update;
        DROP TRIGGER IF EXISTS integrity_case_replays_delete;
        DROP TRIGGER IF EXISTS integrity_evidence_timeline_insert;
        DROP TRIGGER IF EXISTS integrity_evidence_timeline_update;
        DROP TRIGGER IF EXISTS integrity_evidence_timeline_delete;
        ",
    )?;
    Ok(())
}

pub fn enable_integrity_watchpoints(
    conn: &Connection,
    case_id: &str,
    enabled: bool,
) -> SqliteResult<()> {
    let value = if enabled { "1" } else { "0" };

    conn.execute(
        "INSERT INTO case_settings (id, case_id, key, value, modified_at)
         VALUES (
            COALESCE(
                (SELECT id FROM case_settings WHERE case_id = ?1 AND key = 'integrity_watchpoints_enabled'),
                lower(hex(randomblob(16)))
            ),
            ?1,
            'integrity_watchpoints_enabled',
            ?2,
            strftime('%s', 'now')
         )
         ON CONFLICT(case_id, key) DO UPDATE SET
            value = excluded.value,
            modified_at = excluded.modified_at",
        params![case_id, value],
    )?;

    if enabled {
        create_integrity_watchpoint_triggers(conn)?;
    } else {
        drop_integrity_watchpoint_triggers(conn)?;
    }

    Ok(())
}

pub fn get_integrity_watchpoints_enabled(conn: &Connection, case_id: &str) -> SqliteResult<bool> {
    let result: SqliteResult<String> = conn.query_row(
        "SELECT value FROM case_settings WHERE case_id = ?1 AND key = 'integrity_watchpoints_enabled'",
        [case_id],
        |row| row.get(0),
    );

    match result {
        Ok(value) => Ok(value == "1"),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e),
    }
}

pub fn set_current_actor(conn: &Connection, case_id: &str, actor: &str) -> SqliteResult<()> {
    conn.execute(
        "INSERT INTO case_settings (id, case_id, key, value, modified_at)
         VALUES (
            COALESCE(
                (SELECT id FROM case_settings WHERE case_id = ?1 AND key = 'current_actor'),
                lower(hex(randomblob(16)))
            ),
            ?1,
            'current_actor',
            ?2,
            strftime('%s', 'now')
         )
         ON CONFLICT(case_id, key) DO UPDATE SET
            value = excluded.value,
            modified_at = excluded.modified_at",
        params![case_id, actor],
    )?;
    Ok(())
}

pub fn clear_current_actor(conn: &Connection, case_id: &str) -> SqliteResult<()> {
    conn.execute(
        "DELETE FROM case_settings WHERE case_id = ?1 AND key = 'current_actor'",
        [case_id],
    )?;
    Ok(())
}

pub fn list_integrity_violations(
    conn: &Connection,
    case_id: &str,
    since_utc: Option<String>,
    limit: u64,
) -> SqliteResult<Vec<IntegrityViolation>> {
    let query = if since_utc.is_some() {
        "SELECT id, case_id, occurred_utc, table_name, operation, row_key, actor, reason, details_json
         FROM integrity_violations
         WHERE case_id = ?1 AND occurred_utc >= ?2
         ORDER BY occurred_utc DESC
         LIMIT ?3"
    } else {
        "SELECT id, case_id, occurred_utc, table_name, operation, row_key, actor, reason, details_json
         FROM integrity_violations
         WHERE case_id = ?1
         ORDER BY occurred_utc DESC
         LIMIT ?2"
    };

    let mut stmt = conn.prepare(query)?;

    let violations = if let Some(since) = since_utc {
        stmt.query_map(params![case_id, since, limit], |row| {
            Ok(IntegrityViolation {
                id: row.get(0)?,
                case_id: row.get(1)?,
                occurred_utc: row.get(2)?,
                table_name: row.get(3)?,
                operation: row.get(4)?,
                row_key: row.get(5)?,
                actor: row.get(6)?,
                reason: row.get(7)?,
                details_json: row.get(8)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect()
    } else {
        stmt.query_map(params![case_id, limit], |row| {
            Ok(IntegrityViolation {
                id: row.get(0)?,
                case_id: row.get(1)?,
                occurred_utc: row.get(2)?,
                table_name: row.get(3)?,
                operation: row.get(4)?,
                row_key: row.get(5)?,
                actor: row.get(6)?,
                reason: row.get(7)?,
                details_json: row.get(8)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect()
    };

    Ok(violations)
}

pub fn clear_integrity_violations(conn: &Connection, case_id: &str) -> SqliteResult<u64> {
    let deleted = conn.execute(
        "DELETE FROM integrity_violations WHERE case_id = ?1",
        [case_id],
    )?;
    Ok(deleted as u64)
}

pub fn get_integrity_violations_count(conn: &Connection, case_id: &str) -> SqliteResult<u64> {
    let count: u64 = conn.query_row(
        "SELECT COUNT(*) FROM integrity_violations WHERE case_id = ?1",
        [case_id],
        |row| row.get(0),
    )?;
    Ok(count)
}

pub fn fail_if_integrity_violations(case_id: &str, db_path: &Path) -> anyhow::Result<()> {
    let conn = Connection::open(db_path)?;
    fail_if_integrity_violations_with_conn(&conn, case_id)
}

pub fn fail_if_integrity_violations_with_conn(
    conn: &Connection,
    case_id: &str,
) -> anyhow::Result<()> {
    let enabled = get_integrity_watchpoints_enabled(conn, case_id)?;
    if !enabled {
        return Ok(());
    }

    let count = get_integrity_violations_count(conn, case_id)?;
    if count > 0 {
        return Err(anyhow::anyhow!(
            "Integrity violations detected: {} violations found for case {}. Run `forensic-cli violations --case {}` for details.",
            count, case_id, case_id
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_db(temp_dir: &TempDir) -> SqliteResult<(rusqlite::Connection, String)> {
        create_test_db_with_options(temp_dir, true)
    }

    fn create_test_db_without_uuid_fn(
        temp_dir: &TempDir,
    ) -> SqliteResult<(rusqlite::Connection, String)> {
        create_test_db_with_options(temp_dir, false)
    }

    fn create_test_db_with_options(
        temp_dir: &TempDir,
        register_uuid_fn: bool,
    ) -> SqliteResult<(rusqlite::Connection, String)> {
        let db_path = temp_dir.path().join("test_case.sqlite");
        let case_id = "test_case_001".to_string();

        let conn = rusqlite::Connection::open(&db_path)?;

        if register_uuid_fn {
            conn.create_scalar_function(
                "uuid4",
                0,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8
                    | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
                |_ctx| Ok(uuid::Uuid::new_v4().to_string()),
            )?;
        }

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                examiner TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                ts_utc INTEGER NOT NULL,
                ts_local TEXT NOT NULL,
                user_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL,
                schema_version TEXT NOT NULL DEFAULT '1.0'
            );

            CREATE TABLE IF NOT EXISTS provenance (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                object_type TEXT NOT NULL,
                action TEXT NOT NULL,
                user_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                ts_utc INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS exhibit_packets (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS case_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                finished_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                report_json TEXT
            );

            CREATE TABLE IF NOT EXISTS case_replays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                finished_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                report_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence_timeline (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_time INTEGER NOT NULL,
                artifact_id TEXT,
                source_module TEXT,
                source_record_id TEXT,
                UNIQUE(case_id, event_type, event_time, source_module, source_record_id)
            );

            CREATE TABLE IF NOT EXISTS case_settings (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                modified_at INTEGER NOT NULL,
                UNIQUE(case_id, key)
            );

            CREATE TABLE IF NOT EXISTS integrity_violations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                occurred_utc TEXT NOT NULL,
                table_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                row_key TEXT,
                actor TEXT,
                reason TEXT NOT NULL,
                details_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_integrity_violations_case_time 
                ON integrity_violations(case_id, occurred_utc);
            CREATE INDEX IF NOT EXISTS idx_integrity_violations_case_table 
                ON integrity_violations(case_id, table_name);
            ",
        )?;
        conn.execute(
            "INSERT INTO cases (id, name, examiner, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&case_id, "Test Case", "tester", 1700000000, 1700000000],
        )?;

        Ok((conn, case_id))
    }

    #[test]
    fn test_watchpoints_disabled_no_violations() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        enable_integrity_watchpoints(&conn, &case_id, false).unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "TestEvent", "Test", 1700000000, "2023", "user", "session", "hash123"],
        ).unwrap();

        let count = get_integrity_violations_count(&conn, &case_id).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_watchpoints_enabled_creates_violation() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        enable_integrity_watchpoints(&conn, &case_id, true).unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "TestEvent", "Test", 1700000000, "2023", "user", "session", "hash123"],
        ).unwrap();

        let count = get_integrity_violations_count(&conn, &case_id).unwrap();
        assert_eq!(count, 1);

        let violations = list_integrity_violations(&conn, &case_id, None, 10).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].table_name, "activity_log");
        assert_eq!(violations[0].operation, "INSERT");
    }

    #[test]
    fn test_watchpoint_settings_work_without_uuid_function() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db_without_uuid_fn(&temp_dir).unwrap();

        enable_integrity_watchpoints(&conn, &case_id, true).unwrap();
        set_current_actor(&conn, &case_id, "job:no-uuid").unwrap();
        assert!(get_integrity_watchpoints_enabled(&conn, &case_id).unwrap());
    }

    #[test]
    fn test_enable_watchpoints_with_partial_schema() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let case_id = "partial_case";

        conn.execute_batch(
            "
            CREATE TABLE case_settings (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                modified_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                UNIQUE(case_id, key)
            );
            CREATE TABLE integrity_violations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                occurred_utc TEXT NOT NULL,
                table_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                row_key TEXT,
                actor TEXT,
                reason TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE TABLE activity_log (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                ts_utc INTEGER NOT NULL,
                ts_local TEXT NOT NULL,
                user_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
            ",
        )
        .unwrap();

        enable_integrity_watchpoints(&conn, case_id, true).unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                uuid::Uuid::new_v4().to_string(),
                case_id,
                "TestEvent",
                "Test",
                1700000000,
                "2023",
                "user",
                "session",
                "hash123"
            ],
        )
        .unwrap();

        let count = get_integrity_violations_count(&conn, case_id).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_actor_attribution() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        enable_integrity_watchpoints(&conn, &case_id, true).unwrap();
        set_current_actor(&conn, &case_id, "job:123:import").unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "TestEvent", "Test", 1700000000, "2023", "user", "session", "hash123"],
        ).unwrap();

        let violations = list_integrity_violations(&conn, &case_id, None, 10).unwrap();
        assert_eq!(violations[0].actor, Some("job:123:import".to_string()));
    }

    #[test]
    fn test_multiple_tables_watchpoint() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        enable_integrity_watchpoints(&conn, &case_id, true).unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "TestEvent", "Test", 1700000000, "2023", "user", "session", "hash123"],
        ).unwrap();

        conn.execute(
            "INSERT INTO evidence_timeline (id, case_id, event_type, event_time, source_module, source_record_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "TestEvent", 1700000000, "test", "rec1"],
        ).unwrap();

        let count = get_integrity_violations_count(&conn, &case_id).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_enable_disable_watchpoints() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        enable_integrity_watchpoints(&conn, &case_id, true).unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "TestEvent", "Test", 1700000000, "2023", "user", "session", "hash123"],
        ).unwrap();

        let count1 = get_integrity_violations_count(&conn, &case_id).unwrap();
        assert_eq!(count1, 1);

        enable_integrity_watchpoints(&conn, &case_id, false).unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "TestEvent2", "Test2", 1700000001, "2023", "user", "session", "hash456"],
        ).unwrap();

        let count2 = get_integrity_violations_count(&conn, &case_id).unwrap();
        assert_eq!(count2, 1);
    }

    #[test]
    fn test_fail_if_violations() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        enable_integrity_watchpoints(&conn, &case_id, true).unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "TestEvent", "Test", 1700000000, "2023", "user", "session", "hash123"],
        ).unwrap();

        let result = fail_if_integrity_violations(
            &case_id,
            temp_dir.path().join("test_case.sqlite").as_path(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_clear_violations() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        enable_integrity_watchpoints(&conn, &case_id, true).unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "TestEvent", "Test", 1700000000, "2023", "user", "session", "hash123"],
        ).unwrap();

        let count1 = get_integrity_violations_count(&conn, &case_id).unwrap();
        assert_eq!(count1, 1);

        clear_integrity_violations(&conn, &case_id).unwrap();

        let count2 = get_integrity_violations_count(&conn, &case_id).unwrap();
        assert_eq!(count2, 0);
    }

    #[test]
    fn test_batch_insert_performance() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        enable_integrity_watchpoints(&conn, &case_id, true).unwrap();

        let start = std::time::Instant::now();

        let mut stmt = conn.prepare(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        ).unwrap();

        for i in 0..100 {
            stmt.execute(params![
                uuid::Uuid::new_v4().to_string(),
                &case_id,
                "TestEvent",
                "Test",
                1700000000 + i,
                "2023",
                "user",
                "session",
                format!("hash{}", i)
            ])
            .unwrap();
        }

        let elapsed = start.elapsed();

        let count = get_integrity_violations_count(&conn, &case_id).unwrap();
        assert_eq!(count, 100);

        assert!(
            elapsed.as_secs() < 10,
            "Batch insert took too long: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_different_cases_isolated() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id1) = create_test_db(&temp_dir).unwrap();
        let case_id2 = "test_case_002".to_string();

        conn.execute(
            "INSERT INTO cases (id, name, examiner, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&case_id2, "Test Case 2", "tester", 1700000000, 1700000000],
        ).unwrap();

        enable_integrity_watchpoints(&conn, &case_id1, true).unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![uuid::Uuid::new_v4().to_string(), &case_id1, "TestEvent", "Test", 1700000000, "2023", "user", "session", "hash123"],
        ).unwrap();

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![uuid::Uuid::new_v4().to_string(), &case_id2, "TestEvent", "Test", 1700000000, "2023", "user", "session", "hash456"],
        ).unwrap();

        let count1 = get_integrity_violations_count(&conn, &case_id1).unwrap();
        let count2 = get_integrity_violations_count(&conn, &case_id2).unwrap();

        assert_eq!(count1, 1);
        assert_eq!(count2, 0);
    }
}
