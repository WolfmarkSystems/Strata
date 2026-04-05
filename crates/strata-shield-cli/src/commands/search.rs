// Extracted from main.rs - run_search_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "search", about = "Run global search against case entities")]
pub struct SearchArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<PathBuf>,

    #[arg(short = 'q', long = "query")]
    pub query: Option<String>,

    #[arg(index = 1)]
    pub query_text: Option<String>,

    #[arg(short = 't', long = "type")]
    pub entity_types: Vec<String>,

    #[arg(short, long, default_value_t = 20u32)]
    pub limit: u32,

    #[arg(short, long)]
    pub json: bool,
}

pub fn execute(args: SearchArgs) {
    let query = match args.query.or(args.query_text) {
        Some(q) => q,
        None => {
            eprintln!("Error: No query provided. Use --query <query>");
            std::process::exit(1);
        }
    };

    let case_id = match args.case {
        Some(id) => id,
        None => {
            eprintln!("Error: No case ID provided. Use --case <id>");
            std::process::exit(1);
        }
    };

    let db_path = args
        .db
        .unwrap_or_else(|| PathBuf::from(format!("./{}.db", case_id)));

    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error opening database: {}", e);
            std::process::exit(1);
        }
    };

    let _entity_types_ref: Option<Vec<&str>> = if args.entity_types.is_empty() {
        None
    } else {
        Some(args.entity_types.iter().map(|s| s.as_str()).collect())
    };

    let results = match conn.query_row(
        "SELECT case_id FROM cases WHERE id = ?1",
        [&case_id],
        |_| Ok(()),
    ) {
        Ok(_) => {
            let sql = "SELECT e.entity_type, e.entity_id, e.title, e.path, e.category, e.ts_utc, e.json_data,
                      f.rowid, bm25(global_search_fts) as rank
               FROM global_search_fts f
               JOIN global_search_entities e ON f.entity_id = e.entity_id AND f.entity_type = e.entity_type AND f.case_id = e.case_id
               WHERE f.case_id = ?1 AND global_search_fts MATCH ?2
               ORDER BY rank, f.rowid
               LIMIT ?3";

            let mut stmt = match conn.prepare(sql) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error preparing query: {}", e);
                    std::process::exit(1);
                }
            };

            let rows = stmt.query_map(params![case_id, query, args.limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, f64>(8)?,
                ))
            });

            match rows {
                Ok(rows) => {
                    let mut results = Vec::new();
                    for row in rows.filter_map(|r| r.ok()) {
                        let json: serde_json::Value =
                            serde_json::from_str(&row.6).unwrap_or(serde_json::Value::Null);
                        let title = row.2;
                        results.push(forensic_engine::case::database::GlobalSearchHit {
                            entity_type: row.0,
                            entity_id: row.1,
                            title: title.clone(),
                            snippet: title.chars().take(200).collect(),
                            path: row.3,
                            category: row.4,
                            ts_utc: row.5,
                            rank: row.8,
                            json,
                        });
                    }
                    results
                }
                Err(e) => {
                    eprintln!("Search error: {}", e);
                    Vec::new()
                }
            }
        }
        Err(_) => {
            eprintln!("Case not found: {}", case_id);
            Vec::new()
        }
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&results).unwrap_or_default()
        );
    } else {
        println!("=== Global Search Results ===");
        println!("Query: {}", query);
        println!("Case: {}", case_id);
        println!("Results: {}\n", results.len());

        for (i, hit) in results.iter().enumerate() {
            println!("{}. [{}] {}", i + 1, hit.entity_type, hit.title);
            println!("   Rank: {:.4}", hit.rank);
            if let Some(ref cat) = hit.category {
                println!("   Category: {}", cat);
            }
            if let Some(ref ts) = hit.ts_utc {
                println!("   Time: {}", ts);
            }
            if !hit.snippet.is_empty() {
                println!("   Snippet: {}", hit.snippet);
            }
            println!();
        }
    }
}
