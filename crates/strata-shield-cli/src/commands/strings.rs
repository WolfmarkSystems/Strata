// Extracted from main.rs - run_strings_command

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "strings", about = "Read extracted strings from case database")]
pub struct StringsArgs {
    #[arg(short, long)]
    pub case: Option<String>,

    #[arg(short, long)]
    pub db: Option<PathBuf>,

    #[arg(short = 'f', long = "file-id")]
    pub file_id: Option<String>,

    #[arg(long)]
    pub inline: bool,

    #[arg(short, long)]
    pub json: bool,
}

pub fn execute(args: StringsArgs) {
    let db_path = match args.db {
        Some(p) => p,
        None => {
            let case_id = match args.case {
                Some(ref id) => id,
                None => {
                    eprintln!("Error: No case ID provided. Use --case <id>");
                    std::process::exit(1);
                }
            };
            PathBuf::from(format!("./{}.db", case_id))
        }
    };

    let case_id = match args.case {
        Some(id) => id,
        None => {
            eprintln!("Error: No case ID provided");
            std::process::exit(1);
        }
    };

    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error opening database: {}", e);
            std::process::exit(1);
        }
    };

    if let Some(fid) = args.file_id {
        match conn.query_row(
            "SELECT file_id, file_path, sha256, size_bytes, extracted_utc, flags, strings_text, strings_json
             FROM file_strings WHERE case_id = ?1 AND file_id = ?2",
            params![case_id, fid],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        ) {
            Ok((file_id, file_path, sha256, size, extracted, flags, strings_text, strings_json)) => {
                if args.json {
                    let result = serde_json::json!({
                        "file_id": file_id,
                        "file_path": file_path,
                        "sha256": sha256,
                        "size_bytes": size,
                        "extracted_utc": extracted,
                        "flags": flags,
                        "strings_text": strings_text.chars().take(1000).collect::<String>(),
                        "strings_json": strings_json
                    });
                    println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
                } else {
                    println!("=== File Strings ===");
                    println!("File ID: {}", file_id);
                    println!("Path: {}", file_path);
                    println!("SHA256: {:?}", sha256);
                    println!("Size: {:?} bytes", size);
                    println!("Extracted: {}", extracted);
                    println!("Flags: {}", flags);
                    println!();
                    println!("=== Strings (first 1000 chars) ===");
                    println!("{}", strings_text.chars().take(1000).collect::<String>());
                }
            }
            Err(e) => {
                eprintln!("Error getting file strings: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match conn.query_row(
            "SELECT case_id FROM cases WHERE id = ?1",
            [&case_id],
            |_| Ok(()),
        ) {
            Ok(_) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT file_id, file_path, sha256, size_bytes, extracted_utc, flags
                     FROM file_strings WHERE case_id = ?1 ORDER BY extracted_utc DESC LIMIT 20",
                    )
                    .unwrap();

                type FileStringsRow = (String, String, Option<String>, Option<i64>, String, i64);
                let results: Vec<FileStringsRow> = stmt
                    .query_map([&case_id], |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    })
                    .unwrap()
                    .filter_map(|r| r.ok())
                    .collect();

                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&results).unwrap_or_default()
                    );
                } else {
                    println!("=== File Strings (recent 20) ===");
                    for (file_id, path, _sha256, size, extracted, _flags) in results {
                        println!("{} - {} bytes - {}", path, size.unwrap_or(0), extracted);
                        println!("  ID: {}", file_id);
                        println!();
                    }
                }
            }
            Err(_) => {
                eprintln!("Case not found: {}", case_id);
                std::process::exit(1);
            }
        }
    }
}
