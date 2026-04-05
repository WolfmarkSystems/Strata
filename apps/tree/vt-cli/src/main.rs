use clap::{Parser, Subcommand};
use std::path::Path;
use std::sync::{atomic::AtomicBool, Arc};
use vt_core::{self_test, HashType};
use vt_index::InvertedIndex;
use vt_snapshot::{
    create_case, create_snapshot, init_db, list_snapshot_objects, store_hash, store_object,
};

#[derive(Parser)]
#[command(author, version, about = "Strata CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Show {
        image: String,
    },
    Hash {
        image: String,
        #[arg(long, default_value_t = String::from("sha256"))]
        r#type: String,
    },
    Snapshot {
        image: String,
        db: String,
        case_name: String,
    },
    Index {
        image: String,
        target: String,
    },
    Search {
        index: String,
        q: String,
    },
    Api {
        action: String,
        image: String,
        #[arg(long)]
        query: Option<String>,
        #[arg(long, default_value_t = 0)]
        page: usize,
        #[arg(long, default_value_t = 100)]
        size: usize,
        #[arg(long)]
        prefix: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    self_test()?;

    match cli.command {
        Commands::Show { image } => {
            println!("vt show {}", image);
            let entries = vt_core::scan_fs_image(&image)?;
            for entry in entries {
                println!("{} ({:?})", entry.path, entry.object_type);
            }
        }
        Commands::Hash { image, r#type } => {
            println!("vt hash {} --type {}", image, r#type);
            let algo = match r#type.as_str() {
                "sha256" => HashType::Sha256,
                _ => {
                    eprintln!("Unsupported hash type: {}", r#type);
                    return Ok(());
                }
            };
            let result = vt_core::hash_file(Path::new(&image), algo)?;
            println!("{}  {}", result, image);
        }
        Commands::Snapshot {
            image,
            db,
            case_name,
        } => {
            println!("vt snapshot {} --db {} --case {}", image, db, case_name);
            let conn = init_db(&db)?;
            let case_id = create_case(&conn, &case_name)?;
            let snapshot_id = create_snapshot(&conn, case_id, &image)?;

            let objects = vt_core::scan_fs_image(&image)?;
            for object in objects {
                let object_id = store_object(&conn, snapshot_id, &object)?;
                if object.object_type == vt_core::ObjectType::File
                    && Path::new(&object.path).exists()
                {
                    if let Ok(hash) = vt_core::hash_file(Path::new(&object.path), HashType::Sha256)
                    {
                        let _ = store_hash(&conn, object_id, "sha256", &hash);
                    }
                }
            }
            let snapshot_objects = list_snapshot_objects(&conn, snapshot_id)?;
            println!("Saved {} objects", snapshot_objects.len());
        }
        Commands::Index { image, target } => {
            println!("vt index {} --target {}", image, target);
            let objects = vt_core::scan_fs_image(&image)?;
            let mut index = InvertedIndex::new();
            for object in objects {
                index.add_document(&object.path, &object.path);
            }
            index.save_to_file(Path::new(&target))?;
            println!("Index written to {}", target);
        }
        Commands::Search { index, q } => {
            println!("vt search {} --q '{}'", index, q);
            let idx = InvertedIndex::load_from_file(Path::new(&index))?;
            let matches = idx.search(&q);
            for m in matches {
                println!("{}", m);
            }
        }
        Commands::Api {
            action,
            image,
            query,
            page,
            size,
            prefix,
        } => match action.as_str() {
            "scan" => {
                let cancel = Arc::new(AtomicBool::new(false));
                let opts = vt_core::ScanOptions {
                    progress: Some(Arc::new(move |processed, total| {
                        eprintln!("progress {} / {}", processed, total);
                    })),
                    cancel: Some(cancel),
                };
                let entries = vt_core::scan_fs_image_with_options(&image, Some(opts))?;
                println!("{}", serde_json::to_string(&entries)?);
            }
            "scanstream" => {
                let cancel = Arc::new(AtomicBool::new(false));
                let opts = vt_core::ScanOptions {
                    progress: Some(Arc::new(move |processed, total| {
                        eprintln!("stream progress {} / {}", processed, total);
                    })),
                    cancel: Some(cancel),
                };
                let entries = vt_core::scan_fs_image_chunked(&image, 32 * 1024 * 1024, Some(opts))?;
                println!("{}", serde_json::to_string(&entries)?);
            }
            "search" => {
                let q = query.unwrap_or_default();
                let idx = InvertedIndex::load_from_file(Path::new(&image))?;
                let matches = idx.search_with_options(&q, prefix.as_deref(), page, size, true);
                println!("{}", serde_json::to_string(&matches)?);
            }
            _ => {
                eprintln!("Unknown api action: {}", action);
            }
        },
    }

    Ok(())
}
