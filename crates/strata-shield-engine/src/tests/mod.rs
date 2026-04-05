#[cfg(test)]
mod unit_tests {
    use crate::hashing::{HashOptions, HashResults};

    #[test]
    fn test_hash_options_default() {
        let opts = HashOptions::default();
        assert!(!opts.allow_partial_final);
    }

    #[test]
    fn test_hash_results_init() {
        let results = HashResults {
            md5: Some("abc123".to_string()),
            sha1: Some("def456".to_string()),
            sha256: Some("ghi789".to_string()),
            blake3: Some("jkl012".to_string()),
        };

        assert!(results.md5.is_some());
        assert!(results.sha1.is_some());
        assert!(results.sha256.is_some());
    }
}

#[cfg(test)]
mod fixture_harness;

#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod regression_phase4;

#[cfg(test)]
mod container_tests {
    use crate::container::{EvidenceContainerRO, RawContainer};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_raw_container_open() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&[0u8; 1024]).unwrap();

        let path = file.path();
        let container = RawContainer::open(path);

        assert!(container.is_ok());
        if let Ok(c) = container {
            assert_eq!(c.size(), 1024);
        }
    }

    #[test]
    fn test_sector_size_detection() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&[0u8; 512]).unwrap();

        let path = file.path();
        let container = RawContainer::open(path);

        assert!(container.is_ok());
    }
}

#[cfg(test)]
mod filesystem_tests {
    use crate::analysis::ntfs_timestamp_to_date;
    use crate::filesystem::TimelineEntry;

    #[test]
    fn test_ntfs_timestamp_conversion() {
        let ts = 133294504300000000i64;
        let date = ntfs_timestamp_to_date(ts);
        assert!(!date.is_empty());
    }

    #[test]
    fn test_timeline_entry() {
        let entry = TimelineEntry {
            timestamp: 1000,
            action: "FILE".to_string(),
            path: "/a".to_string(),
            size: Some(100),
            record_number: 1,
        };

        assert_eq!(entry.action, "FILE");
        assert_eq!(entry.timestamp, 1000);
    }
}

#[cfg(test)]
mod signature_tests {
    use crate::classification::detect_file_type;

    #[test]
    fn test_file_signature_detection() {
        let jpg_data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let matches = detect_file_type(&jpg_data);

        assert!(!matches.is_empty());
    }

    #[test]
    fn test_pdf_detection() {
        let pdf_data = b"%PDF-1.4".to_vec();
        let matches = detect_file_type(&pdf_data);

        assert!(!matches.is_empty());
    }
}

#[cfg(test)]
mod string_tests {
    use crate::classification::{extract_keywords, extract_strings};

    #[test]
    fn test_string_extraction_ascii() {
        let data = b"Hello World Test String\x00\x00\x00".to_vec();
        let strings = extract_strings(&data, 4);

        assert!(!strings.is_empty());
    }

    #[test]
    fn test_keyword_extraction() {
        let data = b"password username admin root test".to_vec();
        let keywords = extract_keywords(&data, 3, 10);

        assert!(!keywords.is_empty());
    }
}

#[cfg(test)]
mod verification_tests {
    use crate::case::verify::{
        CaseVerifier, CheckResult, VerificationStats, VerificationStatus, VerifyOptions,
    };
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn create_test_db() -> (NamedTempFile, Connection) {
        let db_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(db_file.path()).unwrap();

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS case_settings (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                modified_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS activity_log (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT,
                summary TEXT,
                details_json TEXT,
                ts_utc INTEGER,
                ts_local TEXT,
                user_name TEXT,
                session_id TEXT,
                prev_event_hash TEXT,
                event_hash TEXT,
                evidence_id TEXT,
                volume_id TEXT
            );
            CREATE TABLE IF NOT EXISTS exhibit_packets (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT,
                manifest_hash TEXT,
                total_files INTEGER
            );
            CREATE TABLE IF NOT EXISTS evidence_timeline (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_time INTEGER,
                event_type TEXT,
                artifact_id TEXT,
                source_module TEXT,
                source_record_id TEXT
            );
            CREATE TABLE IF NOT EXISTS fts_index_queue (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_id TEXT,
                processed INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS case_stats (
                case_id TEXT PRIMARY KEY,
                total_bookmarks INTEGER,
                total_notes INTEGER,
                total_exhibits INTEGER,
                total_jobs INTEGER,
                last_updated INTEGER
            );
            CREATE TABLE IF NOT EXISTS bookmarks (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS exhibits (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS case_verifications (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                started_utc TEXT,
                finished_utc TEXT,
                status TEXT,
                report_json TEXT
            );
            ",
        )
        .unwrap();

        (db_file, conn)
    }

    #[test]
    fn test_verify_options_default() {
        let opts = VerifyOptions::default();

        assert!(opts.verify_activity_hash_chain);
        assert!(opts.verify_packet_manifests);
        assert!(opts.verify_db_integrity);
        assert!(opts.verify_read_models_rebuild);
        assert!(opts.verify_timeline_idempotency);
        assert!(!opts.verify_fts_queue_empty);
        assert!(opts.sample_limit.is_none());
    }

    #[test]
    fn test_verify_options_with_sample_limit() {
        let opts = VerifyOptions {
            sample_limit: Some(100),
            ..Default::default()
        };

        assert_eq!(opts.sample_limit, Some(100));
    }

    #[test]
    fn test_case_verifier_new() {
        let db_file = NamedTempFile::new().unwrap();
        let result = CaseVerifier::new(db_file.path(), "test_case", VerifyOptions::default());

        assert!(result.is_ok());
    }

    #[test]
    fn test_verification_status_ordering() {
        let fail = VerificationStatus::Fail;
        let warn = VerificationStatus::Warn;
        let pass = VerificationStatus::Pass;

        assert!(fail != pass);
        assert!(warn != pass);
    }

    #[test]
    fn test_check_result_creation() {
        let check = CheckResult {
            name: "test_check".to_string(),
            status: VerificationStatus::Pass,
            message: "Test passed".to_string(),
            details_json: None,
            started_utc: "2024-01-01T00:00:00Z".to_string(),
            finished_utc: "2024-01-01T00:00:01Z".to_string(),
        };

        assert_eq!(check.name, "test_check");
        assert_eq!(check.status, VerificationStatus::Pass);
    }

    #[test]
    fn test_verification_stats_defaults() {
        let stats = VerificationStats {
            activity_events_checked: 0,
            packets_checked: 0,
            exhibits_checked: 0,
            read_models_rebuilt: false,
            timeline_events_checked: 0,
            fts_queue_depth: 0,
        };

        assert_eq!(stats.activity_events_checked, 0);
        assert!(!stats.read_models_rebuilt);
    }

    #[test]
    fn test_db_integrity_check_passes() {
        let (db_file, mut conn) = create_test_db();

        let result = CaseVerifier::new(db_file.path(), "test_case", VerifyOptions::default());
        assert!(result.is_ok());

        let verifier = result.unwrap();
        let report = verifier.verify_case(&mut conn);

        assert!(report.is_ok());
        let report = report.unwrap();

        assert!(report.checks.iter().any(|c| c.name == "db_integrity"));
    }

    #[test]
    fn test_packet_manifest_check_with_empty_packets() {
        let (db_file, mut conn) = create_test_db();

        let result = CaseVerifier::new(db_file.path(), "test_case", VerifyOptions::default());
        assert!(result.is_ok());

        let verifier = result.unwrap();
        let report = verifier.verify_case(&mut conn);

        assert!(report.is_ok());
        let report = report.unwrap();

        let packet_check = report.checks.iter().find(|c| c.name == "packet_manifests");
        assert!(packet_check.is_some());
        assert_eq!(packet_check.unwrap().status, VerificationStatus::Pass);
    }

    #[test]
    fn test_fts_queue_check() {
        let (db_file, mut conn) = create_test_db();

        let verifier =
            CaseVerifier::new(db_file.path(), "test_case", VerifyOptions::default()).unwrap();
        let report = verifier.verify_case(&mut conn);

        assert!(report.is_ok());
        let report = report.unwrap();

        let fts_check = report.checks.iter().find(|c| c.name == "fts_queue");
        assert!(fts_check.is_some());
        assert_eq!(fts_check.unwrap().status, VerificationStatus::Pass);
    }

    #[test]
    fn test_read_models_check() {
        let (db_file, mut conn) = create_test_db();

        let verifier =
            CaseVerifier::new(db_file.path(), "test_case", VerifyOptions::default()).unwrap();
        let report = verifier.verify_case(&mut conn);

        assert!(report.is_ok());
        let report = report.unwrap();

        let read_models_check = report
            .checks
            .iter()
            .find(|c| c.name == "read_models_consistency");
        assert!(read_models_check.is_some());
    }

    #[test]
    fn test_timeline_idempotency_check() {
        let (db_file, mut conn) = create_test_db();

        let verifier =
            CaseVerifier::new(db_file.path(), "test_case", VerifyOptions::default()).unwrap();
        let report = verifier.verify_case(&mut conn);

        assert!(report.is_ok());
        let report = report.unwrap();

        let timeline_check = report
            .checks
            .iter()
            .find(|c| c.name == "timeline_idempotency");
        assert!(timeline_check.is_some());
    }

    #[test]
    fn test_activity_hash_chain_check_with_empty_log() {
        let (db_file, mut conn) = create_test_db();

        let verifier =
            CaseVerifier::new(db_file.path(), "test_case", VerifyOptions::default()).unwrap();
        let report = verifier.verify_case(&mut conn);

        assert!(report.is_ok());
        let report = report.unwrap();

        let hash_check = report
            .checks
            .iter()
            .find(|c| c.name == "activity_hash_chain");
        assert!(hash_check.is_some());
    }

    #[test]
    fn test_report_contains_all_check_types() {
        let (db_file, mut conn) = create_test_db();

        let verifier =
            CaseVerifier::new(db_file.path(), "test_case", VerifyOptions::default()).unwrap();
        let report = verifier.verify_case(&mut conn).unwrap();

        let check_names: Vec<&str> = report.checks.iter().map(|c| c.name.as_str()).collect();

        assert!(check_names.contains(&"db_integrity"));
        assert!(check_names.contains(&"activity_hash_chain"));
        assert!(check_names.contains(&"packet_manifests"));
        assert!(check_names.contains(&"read_models_consistency"));
        assert!(check_names.contains(&"timeline_idempotency"));
        assert!(check_names.contains(&"fts_queue"));
    }

    #[test]
    fn test_sample_limit_option() {
        let opts = VerifyOptions {
            sample_limit: Some(50),
            ..Default::default()
        };

        assert_eq!(opts.sample_limit, Some(50));
    }

    #[test]
    fn test_strict_fts_option() {
        let opts = VerifyOptions {
            verify_fts_queue_empty: true,
            ..Default::default()
        };

        assert!(opts.verify_fts_queue_empty);
    }
}

#[cfg(test)]
mod global_search_tests {
    use crate::case::database::{GlobalSearchHit, GlobalSearchQuery};

    #[test]
    fn test_global_search_query_default() {
        let query = GlobalSearchQuery {
            case_id: "test-case".to_string(),
            q: "test query".to_string(),
            entity_types: None,
            date_start_utc: None,
            date_end_utc: None,
            category: None,
            tags_any: None,
            path_prefix: None,
            limit: 20,
            after_rank: None,
            after_rowid: None,
        };

        assert_eq!(query.case_id, "test-case");
        assert_eq!(query.q, "test query");
        assert_eq!(query.limit, 20);
    }

    #[test]
    fn test_global_search_hit_serialization() {
        let hit = GlobalSearchHit {
            entity_type: "note".to_string(),
            entity_id: "note-123".to_string(),
            title: "Test Note".to_string(),
            snippet: "This is a test note...".to_string(),
            path: None,
            category: Some("manual".to_string()),
            ts_utc: Some("2024-01-01T00:00:00Z".to_string()),
            rank: -1.5,
            json: serde_json::json!({"content": "test content"}),
        };

        let serialized = serde_json::to_string(&hit).unwrap();
        assert!(serialized.contains("note"));
        assert!(serialized.contains("Test Note"));

        let deserialized: GlobalSearchHit = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.entity_type, "note");
        assert_eq!(deserialized.title, "Test Note");
    }

    #[test]
    fn test_global_search_query_with_filters() {
        let query = GlobalSearchQuery {
            case_id: "test-case".to_string(),
            q: "password".to_string(),
            entity_types: Some(vec!["note".to_string(), "bookmark".to_string()]),
            date_start_utc: Some("2024-01-01T00:00:00Z".to_string()),
            date_end_utc: Some("2024-12-31T23:59:59Z".to_string()),
            category: Some("important".to_string()),
            tags_any: Some(vec!["evidence".to_string(), "suspicious".to_string()]),
            path_prefix: Some("/home".to_string()),
            limit: 50,
            after_rank: Some(-2.0),
            after_rowid: Some(100),
        };

        assert_eq!(query.entity_types.as_ref().unwrap().len(), 2);
        assert!(query.date_start_utc.is_some());
        assert!(query.tags_any.is_some());
        assert_eq!(query.after_rank, Some(-2.0));
    }
}

#[cfg(test)]
mod file_table_tests {
    use crate::case::database::{
        FileTableFilter, FileTableQuery, FileTableResult, FileTableRow, SortDir, SortField,
    };

    #[test]
    fn test_file_table_query_default() {
        let filter = FileTableFilter {
            case_id: "test-case".to_string(),
            source_types: None,
            path_prefix: None,
            name_contains: None,
            ext_in: None,
            category_in: None,
            min_size: None,
            max_size: None,
            date_start_utc: None,
            date_end_utc: None,
            min_entropy: None,
            max_entropy: None,
            hash_sha256: None,
            tags_any: None,
            score_min: None,
        };

        let query = FileTableQuery {
            filter,
            sort_field: SortField::Name,
            sort_dir: SortDir::Asc,
            limit: 100,
            cursor: None,
        };

        assert_eq!(query.limit, 100);
        assert_eq!(query.sort_field, SortField::Name);
        assert!(query.cursor.is_none());
    }

    #[test]
    fn test_file_table_query_with_filters() {
        let filter = FileTableFilter {
            case_id: "test-case".to_string(),
            source_types: Some(vec!["fs".to_string(), "carved".to_string()]),
            path_prefix: Some("/home".to_string()),
            name_contains: Some("document".to_string()),
            ext_in: Some(vec!["pdf".to_string(), "docx".to_string()]),
            category_in: Some(vec!["document".to_string()]),
            min_size: Some(1024),
            max_size: Some(10485760),
            date_start_utc: Some("2024-01-01T00:00:00Z".to_string()),
            date_end_utc: Some("2024-12-31T23:59:59Z".to_string()),
            min_entropy: None,
            max_entropy: None,
            hash_sha256: Some("abc123".to_string()),
            tags_any: Some(vec!["important".to_string()]),
            score_min: Some(0.5),
        };

        let query = FileTableQuery {
            filter,
            sort_field: SortField::Size,
            sort_dir: SortDir::Desc,
            limit: 50,
            cursor: None,
        };

        assert_eq!(query.filter.source_types.as_ref().unwrap().len(), 2);
        assert_eq!(query.filter.ext_in.as_ref().unwrap().len(), 2);
        assert_eq!(query.sort_field, SortField::Size);
    }

    #[test]
    fn test_file_table_row_creation() {
        let row = FileTableRow {
            id: 1,
            source_type: "fs".to_string(),
            source_id: "mft-123".to_string(),
            evidence_id: Some("ev-001".to_string()),
            volume_id: Some("vol-001".to_string()),
            path: "/home/user/document.pdf".to_string(),
            name: "document.pdf".to_string(),
            extension: Some("pdf".to_string()),
            size_bytes: Some(1024000),
            modified_utc: Some("2024-01-15T10:30:00Z".to_string()),
            created_utc: Some("2024-01-10T08:00:00Z".to_string()),
            entropy: Some(7.2),
            category: Some("document".to_string()),
            score: 0.85,
            tags: vec!["important".to_string(), "evidence".to_string()],
            summary: serde_json::json!({"type": "PDF", "pages": 10}),
        };

        assert_eq!(row.source_type, "fs");
        assert_eq!(row.extension, Some("pdf".to_string()));
        assert_eq!(row.tags.len(), 2);
        assert!(row.score > 0.5);
    }

    #[test]
    fn test_file_table_result_with_pagination() {
        let row1 = FileTableRow {
            id: 1,
            source_type: "fs".to_string(),
            source_id: "mft-1".to_string(),
            evidence_id: None,
            volume_id: None,
            path: "/a.txt".to_string(),
            name: "a.txt".to_string(),
            extension: Some("txt".to_string()),
            size_bytes: Some(100),
            modified_utc: None,
            created_utc: None,
            entropy: None,
            category: None,
            score: 0.0,
            tags: vec![],
            summary: serde_json::json!({}),
        };

        let row2 = FileTableRow {
            id: 2,
            source_type: "fs".to_string(),
            source_id: "mft-2".to_string(),
            evidence_id: None,
            volume_id: None,
            path: "/b.txt".to_string(),
            name: "b.txt".to_string(),
            extension: Some("txt".to_string()),
            size_bytes: Some(200),
            modified_utc: None,
            created_utc: None,
            entropy: None,
            category: None,
            score: 0.0,
            tags: vec![],
            summary: serde_json::json!({}),
        };

        let result = FileTableResult {
            rows: vec![row1, row2],
            next_cursor: None,
            total_count: Some(2),
        };

        assert_eq!(result.rows.len(), 2);
        assert!(result.next_cursor.is_none());
        assert_eq!(result.total_count, Some(2));
    }

    #[test]
    fn test_file_table_result_with_next_cursor() {
        let row1 = FileTableRow {
            id: 1,
            source_type: "fs".to_string(),
            source_id: "mft-1".to_string(),
            evidence_id: None,
            volume_id: None,
            path: "/a.txt".to_string(),
            name: "a.txt".to_string(),
            extension: Some("txt".to_string()),
            size_bytes: Some(100),
            modified_utc: None,
            created_utc: None,
            entropy: None,
            category: None,
            score: 0.0,
            tags: vec![],
            summary: serde_json::json!({}),
        };

        let cursor = crate::case::database::FileTableCursor {
            last_sort_value: Some("a.txt".to_string()),
            last_id: Some(1),
        };

        let result = FileTableResult {
            rows: vec![row1],
            next_cursor: Some(cursor),
            total_count: Some(100),
        };

        assert!(result.next_cursor.is_some());
        assert!(result.next_cursor.as_ref().unwrap().last_id.is_some());
    }

    #[test]
    fn test_sort_field_variants() {
        assert!(matches!(SortField::Name, SortField::Name));
        assert!(matches!(SortField::Path, SortField::Path));
        assert!(matches!(SortField::Size, SortField::Size));
        assert!(matches!(SortField::ModifiedUtc, SortField::ModifiedUtc));
        assert!(matches!(SortField::CreatedUtc, SortField::CreatedUtc));
        assert!(matches!(SortField::Entropy, SortField::Entropy));
        assert!(matches!(SortField::Category, SortField::Category));
        assert!(matches!(SortField::Score, SortField::Score));
        assert!(matches!(SortField::Extension, SortField::Extension));
    }

    #[test]
    fn test_sort_dir_variants() {
        assert!(matches!(SortDir::Asc, SortDir::Asc));
        assert!(matches!(SortDir::Desc, SortDir::Desc));
    }

    #[test]
    fn test_file_table_filter_serialization() {
        let filter = FileTableFilter {
            case_id: "test-case".to_string(),
            source_types: Some(vec!["fs".to_string()]),
            path_prefix: Some("/home".to_string()),
            name_contains: Some("test".to_string()),
            ext_in: Some(vec!["pdf".to_string()]),
            category_in: None,
            min_size: Some(1000),
            max_size: None,
            date_start_utc: None,
            date_end_utc: None,
            min_entropy: None,
            max_entropy: None,
            hash_sha256: None,
            tags_any: None,
            score_min: None,
        };

        let serialized = serde_json::to_string(&filter).unwrap();
        assert!(serialized.contains("test-case"));
        assert!(serialized.contains("fs"));
        assert!(serialized.contains("pdf"));

        let deserialized: FileTableFilter = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.case_id, "test-case");
    }
}
