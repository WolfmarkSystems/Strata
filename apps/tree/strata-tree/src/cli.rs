use clap::{error::ErrorKind, Parser, Subcommand};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use strata_license::{generate_machine_id, LicenseTier};

use crate::carve::engine::CarveEngine;
use crate::evidence::hasher::{spawn_hash_worker, HashMessage};
use crate::evidence::loader;
use crate::evidence::vfs_context::VfsReadContext;
use crate::license_state::AppLicenseState;
use crate::search::content::ContentIndexer;
use crate::state::{
    ActiveCase, AppState, EvidenceSource, FileEntry, IndexBatch, TimelineEntry, TimelineEventType,
};

pub enum CliAction {
    RunGui,
    Exit(i32),
}

#[derive(Parser, Debug)]
#[command(name = "strata")]
#[command(about = "Strata forensic workbench")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Info {
        evidence_file: PathBuf,
    },
    Hash {
        evidence_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Carve {
        evidence_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Report {
        evidence_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Search {
        evidence_file: PathBuf,
        #[arg(long)]
        query: String,
    },
    Fingerprint,
}

struct IndexedEvidence {
    source: EvidenceSource,
    files: Vec<FileEntry>,
    vfs_context: Arc<VfsReadContext>,
    volumes: Vec<String>,
}

pub fn dispatch_from_env() -> CliAction {
    match Cli::try_parse_from(std::env::args_os()) {
        Ok(cli) => {
            let Some(command) = cli.command else {
                return CliAction::RunGui;
            };

            match run_command(command) {
                Ok(()) => CliAction::Exit(0),
                Err(err) => {
                    eprintln!("{}", err);
                    CliAction::Exit(1)
                }
            }
        }
        Err(err) => {
            if matches!(
                err.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                println!("{}", err);
                CliAction::Exit(0)
            } else {
                eprintln!("{}", err);
                CliAction::Exit(1)
            }
        }
    }
}

fn run_command(command: Commands) -> Result<(), String> {
    match command {
        Commands::Info { evidence_file } => run_info(&evidence_file),
        Commands::Hash {
            evidence_file,
            output,
        } => run_hash(&evidence_file, &output),
        Commands::Carve {
            evidence_file,
            output,
        } => run_carve(&evidence_file, &output),
        Commands::Report {
            evidence_file,
            output,
        } => run_report(&evidence_file, &output),
        Commands::Search {
            evidence_file,
            query,
        } => run_search(&evidence_file, &query),
        Commands::Fingerprint => run_fingerprint(),
    }
}

fn run_info(evidence_file: &Path) -> Result<(), String> {
    let indexed = index_evidence(evidence_file)?;

    let file_count = indexed.files.iter().filter(|entry| !entry.is_dir).count();
    let deleted_count = indexed
        .files
        .iter()
        .filter(|entry| entry.is_deleted)
        .count();
    let size_bytes = indexed
        .files
        .iter()
        .filter(|entry| !entry.is_dir)
        .map(|entry| entry.size.unwrap_or(0))
        .sum::<u64>();

    let size_gb = (size_bytes as f64) / (1024.0_f64 * 1024.0_f64 * 1024.0_f64);
    println!(
        "Files: {} | Deleted: {} | Size: {:.2} GB",
        file_count, deleted_count, size_gb
    );
    println!("Volumes: [{}]", indexed.volumes.join(", "));
    Ok(())
}

fn run_hash(evidence_file: &Path, output: &Path) -> Result<(), String> {
    ensure_output_path_present(output)?;
    let indexed = index_evidence(evidence_file)?;
    ensure_output_path_safe(&indexed.source, output)?;

    let files_to_hash: Vec<FileEntry> = indexed
        .files
        .iter()
        .filter(|entry| !entry.is_dir)
        .cloned()
        .collect();

    let total = files_to_hash.len() as u64;
    let mut rows = Vec::new();
    if total > 0 {
        let (tx, rx) = std::sync::mpsc::channel();
        let _worker =
            spawn_hash_worker(files_to_hash.clone(), Some(indexed.vfs_context.clone()), tx);

        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(HashMessage::Result(result)) => {
                    rows.push(result);
                }
                Ok(HashMessage::Progress { completed, total }) => {
                    render_progress(completed, total)?;
                }
                Ok(HashMessage::Done { .. }) => {
                    render_progress(total, total)?;
                    eprintln!();
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("Hash worker disconnected unexpectedly".to_string());
                }
            }
        }
    }

    let mut path_by_id = HashMap::new();
    for entry in &files_to_hash {
        path_by_id.insert(entry.id.clone(), normalize_path(&entry.path));
    }

    let mut csv = std::fs::File::create(output)
        .map_err(|err| format!("Failed to create output file {}: {}", output.display(), err))?;
    writeln!(csv, "id,path,md5,sha256,error")
        .map_err(|err| format!("Failed to write CSV header: {}", err))?;

    for row in &rows {
        let path = path_by_id
            .get(&row.file_id)
            .cloned()
            .unwrap_or_else(|| "".to_string());
        writeln!(
            csv,
            "{},{},{},{},{}",
            csv_escape(&row.file_id),
            csv_escape(&path),
            csv_escape(row.md5.as_deref().unwrap_or("")),
            csv_escape(row.sha256.as_deref().unwrap_or("")),
            csv_escape(row.error.as_deref().unwrap_or("")),
        )
        .map_err(|err| format!("Failed to write CSV row: {}", err))?;
    }

    println!(
        "Hashing complete: {} file(s) processed -> {}",
        files_to_hash.len(),
        output.display()
    );
    Ok(())
}

fn run_carve(evidence_file: &Path, output: &Path) -> Result<(), String> {
    let license = AppLicenseState::load();
    ensure_license_feature(
        &license,
        "file_carving",
        "File carving requires Pro license",
    )?;

    ensure_output_path_present(output)?;
    let source = build_evidence_source(evidence_file, "cli-carve-source".to_string())?;
    ensure_output_path_safe(&source, output)?;

    let engine = CarveEngine::new(evidence_file, output);
    let stats = engine
        .carve(None)
        .map_err(|err| format!("Carve failed: {}", err))?;

    println!("Files found: {}", stats.files_carved);
    Ok(())
}

fn run_report(evidence_file: &Path, output: &Path) -> Result<(), String> {
    let license = AppLicenseState::load();
    ensure_license_feature(
        &license,
        "report_export",
        "Report export requires Pro license",
    )?;
    if matches!(license.tier, LicenseTier::Free) {
        return Err("HTML report export requires Pro license".to_string());
    }

    ensure_output_path_present(output)?;
    let indexed = index_evidence(evidence_file)?;
    ensure_output_path_safe(&indexed.source, output)?;

    let mut state = AppState {
        examiner_name: current_examiner_name(),
        ..AppState::default()
    };
    state.evidence_sources.push(indexed.source.clone());
    state.file_index = indexed.files;
    state.vfs_context = Some(indexed.vfs_context);
    state.case = Some(ActiveCase {
        name: evidence_file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("CLI Case")
            .to_string(),
        id: uuid::Uuid::new_v4().to_string(),
        agency: String::new(),
        path: evidence_file.to_string_lossy().to_string(),
    });
    state.timeline_entries = build_cli_timeline(&state.file_index);
    state.suspicious_event_count = state
        .timeline_entries
        .iter()
        .filter(|entry| entry.suspicious)
        .count();

    crate::ui::export::export_case_html(&state, output)
        .map_err(|err| format!("Report generation failed: {}", err))?;

    println!("Report written: {}", output.display());
    Ok(())
}

fn run_search(evidence_file: &Path, query: &str) -> Result<(), String> {
    let license = AppLicenseState::load();
    ensure_license_feature(
        &license,
        "content_search",
        "Content search requires Pro license",
    )?;

    if query.trim().is_empty() {
        return Err("Search query cannot be empty".to_string());
    }

    let indexed = index_evidence(evidence_file)?;
    let index_dir =
        std::env::temp_dir().join(format!("strata-cli-index-{}", uuid::Uuid::new_v4()));

    let indexer = ContentIndexer::new(&index_dir);
    let stats = indexer
        .build_index(&indexed.files, Some(indexed.vfs_context.as_ref()), None)
        .map_err(|err| format!("Content index failed: {}", err))?;

    eprintln!(
        "Indexed {} file(s), skipped {}",
        stats.indexed, stats.skipped
    );

    let hits = indexer
        .search(query, 500)
        .map_err(|err| format!("Search failed: {}", err))?;

    if hits.is_empty() {
        println!("No matches.");
    } else {
        for hit in &hits {
            println!("{}", normalize_path(&hit.file_path));
        }
    }

    let _ = std::fs::remove_dir_all(&index_dir);
    Ok(())
}

fn run_fingerprint() -> Result<(), String> {
    let machine_id = generate_machine_id().map_err(|err| format!("Fingerprint failed: {}", err))?;
    println!("{}", machine_id);
    Ok(())
}

fn index_evidence(evidence_file: &Path) -> Result<IndexedEvidence, String> {
    if !evidence_file.exists() {
        return Err(format!(
            "Evidence file does not exist: {}",
            evidence_file.display()
        ));
    }

    let evidence_id = uuid::Uuid::new_v4().to_string();
    let source = build_evidence_source(evidence_file, evidence_id.clone())?;
    let volumes = detect_volumes(evidence_file);

    let receiver = loader::start_indexing(
        evidence_file
            .to_str()
            .ok_or_else(|| "Evidence path is not valid UTF-8".to_string())?,
        &evidence_id,
    )
    .map_err(|err| format!("Failed to start indexing: {}", err))?;

    let mut files = Vec::new();
    let mut completed = false;

    loop {
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(IndexBatch::Files(batch)) => {
                files.extend(batch);
            }
            Ok(IndexBatch::Done { .. }) => {
                completed = true;
                break;
            }
            Ok(IndexBatch::Error(err)) => {
                if err.to_ascii_lowercase().contains("falling back") {
                    eprintln!("Indexer warning: {}", err);
                    continue;
                }
                return Err(format!("Indexing failed: {}", err));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    if !completed {
        return Err("Indexer ended before completion".to_string());
    }

    let vfs_context = Arc::new(VfsReadContext::from_sources(std::slice::from_ref(&source)));

    Ok(IndexedEvidence {
        source,
        files,
        vfs_context,
        volumes,
    })
}

fn detect_volumes(evidence_file: &Path) -> Vec<String> {
    if evidence_file.is_dir() {
        return vec!["[DIR] Host directory".to_string()];
    }

    match strata_fs::container::EvidenceSource::open(evidence_file) {
        Ok(source) => {
            if let Some(vfs) = source.vfs_ref() {
                let mut volumes = Vec::new();
                for volume in vfs.get_volumes() {
                    let fs = volume.filesystem.as_str();
                    let label = volume
                        .label
                        .clone()
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or_else(|| format!("Volume {}", volume.volume_index + 1));
                    volumes.push(format!("[{}] {}", fs, label));
                }
                if volumes.is_empty() {
                    vec!["[Unknown] No volumes detected".to_string()]
                } else {
                    volumes
                }
            } else {
                vec!["[Unknown] No VFS view available".to_string()]
            }
        }
        Err(err) => vec![format!("[Unknown] {}", err)],
    }
}

fn build_evidence_source(evidence_file: &Path, id: String) -> Result<EvidenceSource, String> {
    let metadata = std::fs::metadata(evidence_file)
        .map_err(|err| format!("Failed to read evidence metadata: {}", err))?;
    let format = if evidence_file.is_dir() {
        "DIR".to_string()
    } else {
        evidence_file
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_uppercase())
            .unwrap_or_else(|| "RAW".to_string())
    };

    Ok(EvidenceSource {
        id,
        path: evidence_file.to_string_lossy().to_string(),
        format,
        sha256: None,
        hash_verified: false,
        loaded_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        size_bytes: Some(metadata.len()),
    })
}

fn ensure_output_path_safe(source: &EvidenceSource, output: &Path) -> Result<(), String> {
    let mut guard = AppState::default();
    guard.evidence_sources.push(source.clone());
    guard.ensure_output_path_safe(output)
}

fn ensure_output_path_present(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("Output directory required".to_string());
    }
    Ok(())
}

fn ensure_license_feature(
    license: &AppLicenseState,
    feature: &str,
    message: &str,
) -> Result<(), String> {
    if license.is_trial_expired() {
        return Err("Trial Expired — Purchase required".to_string());
    }
    if !license.has_feature(feature) {
        return Err(message.to_string());
    }
    Ok(())
}

fn current_examiner_name() -> String {
    if let Ok(username) = std::env::var("USERNAME") {
        if !username.trim().is_empty() {
            return username;
        }
    }
    "CLI Examiner".to_string()
}

fn render_progress(completed: u64, total: u64) -> Result<(), String> {
    let width = 30usize;
    let ratio = if total == 0 {
        0.0
    } else {
        (completed as f64 / total as f64).clamp(0.0, 1.0)
    };
    let filled = (ratio * width as f64).round() as usize;
    let bar = format!(
        "[{}{}]",
        "#".repeat(filled),
        "-".repeat(width.saturating_sub(filled))
    );

    eprint!("\rHashing {} {}/{}", bar, completed, total);
    std::io::stderr()
        .flush()
        .map_err(|err| format!("Failed to update progress output: {}", err))?;
    Ok(())
}

fn build_cli_timeline(files: &[FileEntry]) -> Vec<TimelineEntry> {
    let mut entries = Vec::new();

    for file in files {
        if file.is_dir {
            continue;
        }

        if let Some(timestamp) = parse_timestamp(file.created_utc.as_deref()) {
            entries.push(TimelineEntry {
                timestamp,
                event_type: TimelineEventType::FileCreated,
                path: normalize_path(&file.path),
                evidence_id: file.evidence_id.clone(),
                detail: "File created".to_string(),
                file_id: Some(file.id.clone()),
                suspicious: is_suspicious_path(&file.path),
            });
        }

        if let Some(timestamp) = parse_timestamp(file.modified_utc.as_deref()) {
            entries.push(TimelineEntry {
                timestamp,
                event_type: TimelineEventType::FileModified,
                path: normalize_path(&file.path),
                evidence_id: file.evidence_id.clone(),
                detail: "File modified".to_string(),
                file_id: Some(file.id.clone()),
                suspicious: is_suspicious_path(&file.path),
            });
        }

        if let Some(timestamp) = parse_timestamp(file.accessed_utc.as_deref()) {
            entries.push(TimelineEntry {
                timestamp,
                event_type: TimelineEventType::FileAccessed,
                path: normalize_path(&file.path),
                evidence_id: file.evidence_id.clone(),
                detail: "File accessed".to_string(),
                file_id: Some(file.id.clone()),
                suspicious: is_suspicious_path(&file.path),
            });
        }
    }

    entries.sort_by_key(|entry| entry.timestamp);
    entries
}

fn parse_timestamp(value: Option<&str>) -> Option<chrono::DateTime<Utc>> {
    let text = value?;
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn is_suspicious_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_lowercase();
    normalized.contains("/appdata/local/temp/")
        || normalized.contains("/downloads/")
        || normalized.contains("mimikatz")
        || normalized.contains("meterpreter")
        || normalized.contains("cobalt")
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
