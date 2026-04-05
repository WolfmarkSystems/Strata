use chrono::{TimeZone, Utc};
use clap::Parser;
use forensic_engine::report::generator::{CourtReadyReportInput, ReportGenerator};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "report-skeleton",
    about = "Generate a court-ready digital forensic examination report"
)]
pub struct ReportSkeletonArgs {
    #[arg(long = "case", short = 'c', help = "Case ID")]
    pub case: String,

    #[arg(long = "examiner", default_value = "Examiner", help = "Examiner name")]
    pub examiner: String,

    #[arg(
        long = "output",
        short = 'o',
        visible_alias = "out",
        help = "Output HTML report path"
    )]
    pub output: Option<PathBuf>,

    #[arg(long = "hash", help = "Evidence SHA-256 hash override")]
    pub hash: Option<String>,
}

#[derive(Debug, Default)]
struct CaseReportMetrics {
    evidence_source_path: Option<String>,
    sha256_hash: Option<String>,
    first_loaded_utc: Option<String>,
    total_files_indexed: usize,
    total_artifacts_extracted: usize,
    timeline_event_count: usize,
    notable_items_count: usize,
}

pub fn execute(args: ReportSkeletonArgs) {
    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| default_output_path(&args.case));
    let db_path = PathBuf::from("./forensic.db");
    let db_metrics = read_case_report_metrics(&args.case, &db_path);
    let sha256_hash = normalized_optional(args.hash.as_deref()).or(db_metrics.sha256_hash.clone());

    let report = CourtReadyReportInput {
        case_id: args.case.clone(),
        examiner: args.examiner.clone(),
        evidence_source_path: db_metrics
            .evidence_source_path
            .unwrap_or_else(|| "Not available".to_string()),
        sha256_hash: sha256_hash.clone(),
        hash_verified: sha256_hash.is_some(),
        first_loaded_utc: db_metrics.first_loaded_utc,
        total_files_indexed: db_metrics.total_files_indexed,
        total_artifacts_extracted: db_metrics.total_artifacts_extracted,
        timeline_event_count: db_metrics.timeline_event_count,
        notable_items_count: db_metrics.notable_items_count,
    };

    let generator = ReportGenerator::new();
    let html = match generator.generate_court_ready_report(&report) {
        Ok(html) => html,
        Err(e) => {
            eprintln!("Error generating report: {}", e);
            std::process::exit(1);
        }
    };

    if let Some(parent) = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "Error preparing output directory {}: {}",
                parent.display(),
                e
            );
            std::process::exit(1);
        }
    }

    if let Err(e) = std::fs::write(&output_path, html) {
        eprintln!("Error writing report to {}: {}", output_path.display(), e);
        std::process::exit(1);
    }

    println!("Court-ready report generated:");
    println!("  Case: {}", args.case);
    println!("  Examiner: {}", args.examiner);
    println!("  Output: {}", output_path.display());
    if db_path.exists() {
        println!("  Case database: {}", db_path.display());
    } else {
        println!("  Case database: not found, report generated with defaults");
    }
}

fn default_output_path(case_id: &str) -> PathBuf {
    PathBuf::from(format!("./report_{}.html", sanitize_case_id(case_id)))
}

fn sanitize_case_id(case_id: &str) -> String {
    let sanitized: String = case_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();

    if sanitized.trim_matches('_').is_empty() {
        "case".to_string()
    } else {
        sanitized
    }
}

fn read_case_report_metrics(case_id: &str, db_path: &Path) -> CaseReportMetrics {
    if !db_path.exists() {
        return CaseReportMetrics::default();
    }

    let Ok(conn) = Connection::open(db_path) else {
        return CaseReportMetrics::default();
    };

    let evidence_source_path = query_optional_string(
        &conn,
        "SELECT file_path FROM evidence WHERE case_id = ?1 ORDER BY COALESCE(acquired_at, created_at), created_at, id LIMIT 1",
        case_id,
    )
    .or_else(|| {
        query_optional_string(
            &conn,
            "SELECT source_path FROM ingest_manifests WHERE case_id = ?1 ORDER BY created_at, id LIMIT 1",
            case_id,
        )
    });

    let sha256_hash = query_optional_string(
        &conn,
        "SELECT hash_sha256 FROM evidence WHERE case_id = ?1 AND hash_sha256 IS NOT NULL AND TRIM(hash_sha256) <> '' ORDER BY created_at, id LIMIT 1",
        case_id,
    )
    .or_else(|| {
        query_optional_string(
            &conn,
            "SELECT source_hash_sha256 FROM ingest_manifests WHERE case_id = ?1 AND source_hash_sha256 IS NOT NULL AND TRIM(source_hash_sha256) <> '' ORDER BY created_at, id LIMIT 1",
            case_id,
        )
    });

    let first_loaded_utc = query_optional_i64(
        &conn,
        "SELECT MIN(ts_utc) FROM activity_log WHERE case_id = ?1 AND event_type = 'EvidenceOpened'",
        case_id,
    )
    .or_else(|| {
        query_optional_i64(
            &conn,
            "SELECT MIN(created_at) FROM evidence WHERE case_id = ?1",
            case_id,
        )
    })
    .or_else(|| {
        query_optional_i64(
            &conn,
            "SELECT MIN(created_at) FROM ingest_manifests WHERE case_id = ?1",
            case_id,
        )
    })
    .and_then(unix_to_rfc3339);

    let total_files_indexed = query_count(
        &conn,
        "SELECT COUNT(*) FROM file_table_rows WHERE case_id = ?1",
        case_id,
    );

    let total_artifacts_extracted = query_optional_i64(
        &conn,
        "SELECT total_artifacts FROM case_stats WHERE case_id = ?1 ORDER BY last_updated DESC LIMIT 1",
        case_id,
    )
    .and_then(|value| usize::try_from(value).ok())
    .unwrap_or_else(|| {
        query_count(
            &conn,
            "SELECT COALESCE(SUM(count), 0) FROM artifact_summary WHERE case_id = ?1",
            case_id,
        )
    });

    let timeline_event_count = query_count(
        &conn,
        "SELECT COUNT(*) FROM evidence_timeline WHERE case_id = ?1",
        case_id,
    );

    let notable_items_count = query_optional_i64(
        &conn,
        "SELECT COALESCE(total_bookmarks, 0) + COALESCE(total_notes, 0) + COALESCE(total_exhibits, 0) FROM case_stats WHERE case_id = ?1 ORDER BY last_updated DESC LIMIT 1",
        case_id,
    )
    .and_then(|value| usize::try_from(value).ok())
    .unwrap_or_else(|| {
        query_count(&conn, "SELECT COUNT(*) FROM bookmarks WHERE case_id = ?1", case_id)
            + query_count(&conn, "SELECT COUNT(*) FROM notes WHERE case_id = ?1", case_id)
            + query_count(&conn, "SELECT COUNT(*) FROM exhibits WHERE case_id = ?1", case_id)
    });

    CaseReportMetrics {
        evidence_source_path,
        sha256_hash,
        first_loaded_utc,
        total_files_indexed,
        total_artifacts_extracted,
        timeline_event_count,
        notable_items_count,
    }
}

fn query_optional_string(conn: &Connection, sql: &str, case_id: &str) -> Option<String> {
    conn.query_row(sql, params![case_id], |row| row.get::<_, Option<String>>(0))
        .optional()
        .ok()
        .flatten()
        .flatten()
        .and_then(|value| normalized_optional(Some(value.as_str())))
}

fn query_optional_i64(conn: &Connection, sql: &str, case_id: &str) -> Option<i64> {
    conn.query_row(sql, params![case_id], |row| row.get::<_, Option<i64>>(0))
        .optional()
        .ok()
        .flatten()
        .flatten()
}

fn query_count(conn: &Connection, sql: &str, case_id: &str) -> usize {
    conn.query_row(sql, params![case_id], |row| row.get::<_, i64>(0))
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0)
}

fn normalized_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn unix_to_rfc3339(timestamp: i64) -> Option<String> {
    Utc.timestamp_opt(timestamp, 0)
        .single()
        .map(|value| value.to_rfc3339())
}
