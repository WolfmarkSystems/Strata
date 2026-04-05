// Extracted from main.rs - run_filetable_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "filetable",
    about = "Query file table rows from a case database"
)]
pub struct FiletableArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<String>,

    #[arg(short = 's', long = "source")]
    pub source: Option<String>,

    #[arg(long, default_value = "name")]
    pub sort: String,

    #[arg(long = "sort-dir", default_value = "asc")]
    pub sort_dir: String,

    #[arg(short, long, default_value_t = 100u32)]
    pub limit: u32,

    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    #[arg(short = 'e', long = "ext")]
    pub ext: Option<String>,

    #[arg(long)]
    pub category: Option<String>,

    #[arg(long = "min-size")]
    pub min_size: Option<u64>,

    #[arg(long = "max-size")]
    pub max_size: Option<u64>,

    #[arg(short, long)]
    pub json: bool,
}

pub fn execute(args: FiletableArgs) {
    use forensic_engine::case::database::{FileTableFilter, FileTableQuery, SortDir, SortField};

    let case_id = match args.case {
        Some(id) => id,
        None => {
            eprintln!("Error: --case is required");
            std::process::exit(1);
        }
    };

    let db_path = args.db.unwrap_or_else(|| "./forensic.db".to_string());
    let db_path_buf = std::path::PathBuf::from(&db_path);

    if !db_path_buf.exists() {
        eprintln!("Error: Database not found at {}", db_path);
        std::process::exit(1);
    }

    let source_types = args
        .source
        .as_deref()
        .map(|s| s.split(',').map(|v| v.to_string()).collect());
    let ext_filter = args
        .ext
        .as_deref()
        .map(|s| s.split(',').map(|v| v.to_lowercase()).collect());
    let category_filter = args
        .category
        .as_deref()
        .map(|s| s.split(',').map(|v| v.to_string()).collect());

    let sort_field = match args.sort.as_str() {
        "name" => SortField::Name,
        "path" => SortField::Path,
        "size" => SortField::Size,
        "modified" => SortField::ModifiedUtc,
        "created" => SortField::CreatedUtc,
        "entropy" => SortField::Entropy,
        "category" => SortField::Category,
        "score" => SortField::Score,
        "ext" | "extension" => SortField::Extension,
        _ => SortField::Name,
    };

    let sort_dir = match args.sort_dir.as_str() {
        "desc" => SortDir::Desc,
        _ => SortDir::Asc,
    };

    let filter = FileTableFilter {
        case_id: case_id.clone(),
        source_types,
        path_prefix: None,
        name_contains: args.name,
        ext_in: ext_filter,
        category_in: category_filter,
        min_size: args.min_size,
        max_size: args.max_size,
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
        sort_field,
        sort_dir,
        limit: args.limit,
        cursor: None,
    };

    match CaseDatabase::open(&case_id, &db_path_buf) {
        Ok(db) => match db.get_file_table_rows(&query) {
            Ok(result) => {
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result).unwrap_or_default()
                    );
                } else {
                    println!("=== File Table ===");
                    println!("Case: {}", case_id);
                    println!(
                        "Showing {} of {} results",
                        result.rows.len(),
                        result.total_count.unwrap_or(-1)
                    );
                    println!();
                    println!(
                        "{:>6} {:>10} {:<40} {:>12} {:<10} {:<8} {:>6}",
                        "ID", "Source", "Name", "Size", "Ext", "Category", "Score"
                    );
                    println!("{}", "-".repeat(100));

                    for row in &result.rows {
                        let ext = row.extension.as_deref().unwrap_or("-");
                        let cat = row.category.as_deref().unwrap_or("-");
                        let size = row
                            .size_bytes
                            .map(format_size)
                            .unwrap_or_else(|| "-".to_string());
                        let name = if row.name.len() > 40 {
                            format!("...{}", &row.name[row.name.len() - 37..])
                        } else {
                            row.name.clone()
                        };

                        println!(
                            "{:>6} {:>10} {:<40} {:>12} {:<10} {:<8} {:>6.2}",
                            row.id, row.source_type, name, size, ext, cat, row.score
                        );
                    }

                    if result.next_cursor.is_some() {
                        println!();
                        println!("(More results available - use cursor pagination)");
                    }
                }
            }
            Err(e) => {
                eprintln!("Error querying file table: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Error opening database: {}", e);
            std::process::exit(1);
        }
    }
}
