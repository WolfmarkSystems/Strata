// Extracted from main.rs - run_artifacts_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "artifacts",
    about = "Query case artifact summary from database"
)]
pub struct ArtifactsArgs {
    #[arg(long = "case", short = 'c')]
    pub case: String,

    #[arg(long = "db", short = 'd')]
    pub db: PathBuf,

    #[arg(long = "limit", short = 'l')]
    pub limit: Option<usize>,

    #[arg(long = "category")]
    pub category: Option<String>,

    #[arg(long = "json")]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(long = "quiet", short = 'q')]
    pub quiet: bool,
}

pub fn execute(args: ArtifactsArgs, original_args: Vec<String>) {
    let start_time = std::time::Instant::now();

    let case_id = args.case;
    let db_path = args.db;
    let limit = args.limit.unwrap_or(100);
    let category_filter = args.category;
    let json_output = args.json;
    let json_result_path = args.json_result;
    let quiet = args.quiet;

    let conn = open_case_db(&db_path);

    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='artifact_summary'",
            [],
            |row| row.get::<_, i32>(0),
        )
        .unwrap_or(0)
        > 0;

    if !table_exists {
        let data_obj = serde_json::Map::new();
        let data = serde_json::Value::Object(data_obj);

        if json_output {
            if !quiet {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_default()
                );
            }
        } else if !quiet {
            println!("No artifact_summary table present in database.");
        }

        if let Some(ref json_path) = json_result_path {
            let envelope = CliResultEnvelope::new(
                "artifacts",
                original_args,
                EXIT_OK,
                start_time.elapsed().as_millis() as u64,
            )
            .with_data(data)
            .warn("artifact_summary table missing; returning empty result".to_string());
            let _ = envelope.write_to_file(json_path);
        }

        std::process::exit(EXIT_OK);
    }

    let mut query = String::from(
        "SELECT category, total_count, latest_timestamp_utc, latest_timestamp_unix FROM artifact_summary",
    );
    let params = if let Some(cat) = &category_filter {
        query.push_str(" WHERE category = ?1");
        query.push_str(" ORDER BY total_count DESC LIMIT ?2");
        rusqlite::params![cat.clone(), limit as i64]
    } else {
        query.push_str(" ORDER BY total_count DESC LIMIT ?1");
        rusqlite::params![limit as i64]
    };

    let mut stmt = conn.prepare(&query).unwrap();
    let rows = stmt
        .query_map(params, |row| {
            Ok(serde_json::json!({
                "category": row.get::<_, String>(0)?,
                "total_count": row.get::<_, i64>(1)?,
                "latest_timestamp_utc": row.get::<_, Option<String>>(2)?,
                "latest_timestamp_unix": row.get::<_, Option<i64>>(3)?,
            }))
        })
        .unwrap();

    let mut records = Vec::new();
    for r in rows.flatten() {
        records.push(r);
    }

    let data = serde_json::json!({
        "case_id": case_id,
        "db_path": db_path.to_string_lossy(),
        "limit": limit,
        "category": category_filter,
        "total_returned": records.len(),
        "records": records,
    });

    if json_output {
        if !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            );
        }
    } else if !quiet {
        println!("=== Artifact Summary ===");
        println!("Returned: {}", data["total_returned"].as_u64().unwrap_or(0));
        if let Some(cat) = data["category"].as_str() {
            println!("Category filter: {}", cat);
        }
    }

    if let Some(ref json_path) = json_result_path {
        let envelope = CliResultEnvelope::new(
            "artifacts",
            original_args,
            EXIT_OK,
            start_time.elapsed().as_millis() as u64,
        )
        .with_data(data);
        let _ = envelope.write_to_file(json_path);
    }

    std::process::exit(EXIT_OK);
}
