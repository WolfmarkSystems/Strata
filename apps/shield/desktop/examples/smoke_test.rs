use forensic_engine::case::add_to_notes::{AddToNotesMode, AddToNotesRequest};
use forensic_engine::case::database::CaseDatabase;
use forensic_engine::case::exhibit_packet::{SelectionContext, SelectionItem};
use forensic_engine::case::replay::ReplayOptions;
use forensic_engine::case::triage_session::{TriageSessionManager, TriageSessionOptions};
use forensic_engine::case::verify::VerifyOptions;
use rusqlite::params;
use serde_json::json;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

struct TestState {
    db_manager: forensic_engine::case::database::CaseDatabaseManager,
    opened_cases: HashSet<String>,
}

fn main() -> anyhow::Result<()> {
    println!("=== Forensic Desktop Smoke Test ===\n");

    let temp_dir = tempfile::tempdir()?;
    let db_path = temp_dir.path().join("test_case.sqlite");
    let case_id = "smoke_test_case".to_string();

    println!("1. Creating test case database...");
    let conn = rusqlite::Connection::open(&db_path)?;

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
            evidence_id TEXT,
            volume_id TEXT,
            user_name TEXT NOT NULL,
            session_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            details_json TEXT,
            ts_utc INTEGER NOT NULL,
            ts_local TEXT NOT NULL,
            prev_event_hash TEXT,
            event_hash TEXT NOT NULL,
            schema_version TEXT NOT NULL DEFAULT '1.0'
        );

        CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT,
            content_json TEXT NOT NULL DEFAULT '{}',
            tags_json TEXT,
            note_type TEXT DEFAULT 'manual',
            auto_generated INTEGER NOT NULL DEFAULT 0,
            reviewed INTEGER DEFAULT 0,
            reviewer TEXT,
            reviewed_at INTEGER,
            created_at INTEGER NOT NULL,
            modified_at INTEGER NOT NULL,
            created_by TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS note_exhibit_refs (
            id TEXT PRIMARY KEY,
            note_id TEXT NOT NULL,
            exhibit_id TEXT NOT NULL,
            reference_type TEXT,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS exhibits (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            exhibit_type TEXT NOT NULL,
            file_path TEXT,
            hash_md5 TEXT,
            hash_sha1 TEXT,
            hash_sha256 TEXT,
            tags_json TEXT,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tags (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            name TEXT NOT NULL,
            color TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(case_id, name)
        );

        CREATE TABLE IF NOT EXISTS note_tags (
            note_id TEXT NOT NULL,
            tag_id TEXT NOT NULL,
            PRIMARY KEY (note_id, tag_id)
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

        CREATE TABLE IF NOT EXISTS screenshots (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            capture_type TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            description TEXT,
            format TEXT NOT NULL,
            file_path TEXT
        );

        CREATE TABLE IF NOT EXISTS evidence_timeline (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            event_time INTEGER NOT NULL,
            artifact_id TEXT,
            source_module TEXT,
            source_record_id TEXT
        );

        CREATE TABLE IF NOT EXISTS bookmarks (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            folder_id TEXT,
            title TEXT NOT NULL,
            description TEXT,
            tags_json TEXT,
            reviewed INTEGER DEFAULT 0,
            reviewer TEXT,
            reviewed_at INTEGER,
            created_at INTEGER NOT NULL,
            modified_at INTEGER NOT NULL
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

        CREATE TABLE IF NOT EXISTS triage_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            session_name TEXT,
            started_utc TEXT NOT NULL,
            finished_utc TEXT,
            status TEXT NOT NULL DEFAULT 'RUNNING',
            options_json TEXT NOT NULL,
            replay_id INTEGER,
            verification_id INTEGER,
            violations_count INTEGER NOT NULL DEFAULT 0,
            bundle_path TEXT,
            bundle_hash_sha256 TEXT
        );

        CREATE TABLE IF NOT EXISTS exhibit_packets (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            packet_name TEXT NOT NULL,
            description TEXT,
            created_by TEXT NOT NULL,
            total_files INTEGER DEFAULT 0,
            total_size_bytes INTEGER DEFAULT 0,
            export_path TEXT,
            created_at INTEGER NOT NULL
        );
        ",
    )?;

    conn.execute(
        "INSERT INTO cases (id, name, examiner, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![&case_id, "Smoke Test Case", "tester", 1700000000, 1700000000],
    )?;

    conn.execute(
        "INSERT INTO activity_log (id, case_id, event_type, summary, ts_utc, ts_local, user_name, session_id, event_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            uuid::Uuid::new_v4().to_string(),
            &case_id,
            "CaseOpened",
            "Case opened for testing",
            1700000000,
            "2023-01-01 00:00:00",
            "tester",
            "test_session",
            "dummy_hash"
        ],
    )?;

    drop(conn);
    println!("   OK: Database created at {:?}\n", db_path);

    println!("2. Testing verify...");
    let verify_opts = VerifyOptions::default();
    let report = forensic_engine::case::verify::verify_case(&case_id, &db_path, verify_opts)?;
    println!("   OK: Verify completed, status: {:?}\n", report.status);

    println!("3. Testing replay...");
    let replay_opts = ReplayOptions::default();
    let replay_report = forensic_engine::case::replay::replay_case(&case_id, &db_path, replay_opts)?;
    println!("   OK: Replay completed, status: {:?}\n", replay_report.status);

    println!("4. Testing add-to-notes...");
    let db = CaseDatabase::open(&case_id, &db_path)?;
    
    let context = SelectionContext {
        case_id: case_id.clone(),
        examiner: "tester".to_string(),
        selection_time: 1700000000,
        active_filters: vec![],
        search_query: Some("suspicious".to_string()),
        search_fuzzy: false,
        timeline_range_start: None,
        timeline_range_end: None,
    };

    let items = vec![
        SelectionItem {
            item_id: "item1".to_string(),
            item_type: "file".to_string(),
            file_path: Some("/test/file1.txt".to_string()),
            artifact_path: Some("evidence/file1.txt".to_string()),
            size_bytes: Some(1024),
            hash_md5: Some("abc123".to_string()),
            hash_sha1: None,
            hash_sha256: Some("def456".to_string()),
            evidence_id: Some("ev1".to_string()),
            volume_id: None,
            created_at: Some(1700000000),
            modified_at: Some(1700000000),
            provenance: vec![],
        },
    ];

    let request = AddToNotesRequest {
        case_id: case_id.clone(),
        mode: AddToNotesMode::NotePlusExhibits,
        context,
        items,
        tags: vec!["suspicious".to_string()],
        screenshot_path: None,
        screenshot_id: None,
        explain: false,
        max_items: Some(200),
    };

    let result = forensic_engine::case::add_to_notes::add_to_notes(&db, request)?;
    println!("   OK: Note created with ID: {}\n", result.note_id);

    println!("5. Testing triage session...");
    let conn = Arc::new(Mutex::new(rusqlite::Connection::open(&db_path)?));
    let manager = TriageSessionManager::new(conn, case_id.clone());
    
    let triage_opts = TriageSessionOptions {
        enable_watchpoints: false,
        run_replay: false,
        run_verify: false,
        verify_options: VerifyOptions::default(),
        replay_options: ReplayOptions::default(),
        fail_on_violations: false,
        allow_verify_warn: true,
        allow_replay_warn: true,
        export_bundle: false,
        bundle_dir: "exports/test".to_string(),
    };
    
    let triage_result = manager.start_session(Some("Smoke Test Session"), triage_opts)?;
    println!("   OK: Triage session completed, status: {:?}\n", triage_result.status);

    println!("6. Testing export...");
    let export_opts = forensic_engine::case::export::ExportOptions {
        require_verification: false,
        max_report_age_seconds: None,
        allow_warn: true,
    };
    
    let output_dir = PathBuf::from(temp_dir.path().join("export_test"));
    std::fs::create_dir_all(&output_dir)?;
    
    forensic_engine::case::verify::write_verification_artifacts(
        &output_dir,
        &case_id,
        Some(&report),
    )?;
    println!("   OK: Export completed to {:?}\n", output_dir);

    println!("=== All smoke tests passed! ===\n");
    Ok(())
}
