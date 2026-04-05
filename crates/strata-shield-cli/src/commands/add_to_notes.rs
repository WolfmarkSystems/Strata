// Extracted from main.rs — run_add_to_notes_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "add-to-notes",
    about = "Add selected items into case notes/exhibits"
)]
pub struct AddToNotesArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn execute(args: AddToNotesArgs) {
    let mut command_args = vec!["add-to-notes".to_string()];
    command_args.extend(args.args);
    execute_legacy(command_args);
}

fn execute_legacy(mut args: Vec<String>) {
    args.remove(0);

    let mut case_id: Option<String> = None;
    let mut db_path: Option<PathBuf> = None;
    let mut mode = AddToNotesMode::NoteOnly;
    let mut from_json: Option<PathBuf> = None;
    let mut screenshot_path: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();
    let mut explain = false;
    let max_items: Option<u64> = Some(200);

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--case" | "-c" => {
                if i + 1 < args.len() {
                    case_id = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--db" | "-d" => {
                if i + 1 < args.len() {
                    db_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--mode" | "-m" => {
                if i + 1 < args.len() {
                    mode = match args[i + 1].as_str() {
                        "note" => AddToNotesMode::NoteOnly,
                        "exhibits" => AddToNotesMode::NotePlusExhibits,
                        "packet" => AddToNotesMode::NotePlusSinglePacket,
                        _ => {
                            println!("Error: mode must be note, exhibits, or packet");
                            std::process::exit(1);
                        }
                    };
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--from-json" | "-f" => {
                if i + 1 < args.len() {
                    from_json = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--screenshot" | "-s" => {
                if i + 1 < args.len() {
                    screenshot_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--tag" | "-t" => {
                if i + 1 < args.len() {
                    tags.push(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--explain" | "-e" => {
                explain = true;
                i += 1;
            }
            "--max-items" => {
                if i + 1 < args.len() {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--help" | "-h" => {
                print_help_and_exit();
            }
            _ => {
                i += 1;
            }
        }
    }

    let case_id = case_id.unwrap_or_else(|| {
        println!("Error: --case <id> is required");
        std::process::exit(1);
    });

    let db_path = db_path.unwrap_or_else(|| {
        println!("Error: --db <path> is required");
        std::process::exit(1);
    });

    let from_json = from_json.unwrap_or_else(|| {
        println!("Error: --from-json <path> is required");
        std::process::exit(1);
    });

    let input: SelectionJsonInput =
        match read_json_file_with_limit(Path::new(&from_json), CLI_JSON_INPUT_MAX_BYTES) {
            Ok(i) => i,
            Err(e) => {
                println!("Error reading/parsing JSON file: {}", e);
                std::process::exit(1);
            }
        };

    let request = AddToNotesRequest {
        case_id: case_id.clone(),
        mode,
        context: input.context,
        items: input.items,
        tags,
        screenshot_path,
        screenshot_id: None,
        explain,
        max_items,
    };

    let db = match CaseDatabase::open(&case_id, &db_path) {
        Ok(db) => db,
        Err(e) => {
            println!("Error opening database: {}", e);
            std::process::exit(1);
        }
    };

    println!("Adding selection to notes for case: {}", case_id);
    println!("Mode: {}", request.mode);

    match add_to_notes(&db, request) {
        Ok(result) => {
            println!();
            println!("=== Add to Notes Results ===");
            println!("Note ID: {}", result.note_id);
            println!("Exhibit IDs: {}", result.exhibit_ids.len());
            if let Some(ref packet_id) = result.exhibit_packet_id {
                println!("Packet ID: {}", packet_id);
            }
            if let Some(ref ss_id) = result.screenshot_id {
                println!("Screenshot ID: {}", ss_id);
            }
            if let Some(ref event_id) = result.activity_event_id {
                println!("Activity Event ID: {}", event_id);
            }
        }
        Err(e) => {
            println!("Error adding to notes: {}", e);
            std::process::exit(1);
        }
    }
}
