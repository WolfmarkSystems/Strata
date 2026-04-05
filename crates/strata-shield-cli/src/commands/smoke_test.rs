// Extracted from main.rs — run_smoke_test_command
// TODO: Convert to clap derive args in a future pass

use crate::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "smoke-test", about = "Run lightweight evidence smoke analysis")]
pub struct SmokeTestArgs {
    #[arg(long)]
    pub image: Option<PathBuf>,

    #[arg(long)]
    pub out: Option<PathBuf>,

    #[arg(long, default_value_t = 50u32)]
    pub mft: u32,

    #[arg(long = "no-timeline")]
    pub no_timeline: bool,

    #[arg(long = "no-audit")]
    pub no_audit: bool,

    #[arg(long)]
    pub quiet: bool,

    #[arg(long = "json-summary")]
    pub json_summary: Option<PathBuf>,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,
}

pub fn execute(args: SmokeTestArgs, original_args: Vec<String>) {
    let image_path = args.image;
    let out_dir = args.out;
    let mft_count = args.mft;
    let timeline_enabled = !args.no_timeline;
    let audit_enabled = !args.no_audit;
    let quiet = args.quiet;
    let json_summary_path = args.json_summary;
    let json_result_path = args.json_result;

    let start_time = std::time::Instant::now();

    let image_path = image_path.unwrap_or_else(|| {
        eprintln!("Error: --image <path> is required");
        std::process::exit(1);
    });

    if !image_path.exists() {
        let summary = SmokeTestResult {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            platform: "windows".to_string(),
            image_path: image_path.to_string_lossy().to_string(),
            out_dir: out_dir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            mft_count,
            timeline_enabled,
            audit_enabled,
            did_open_image: false,
            evidence_size_bytes: 0,
            bytes_actually_read: 0,
            sample_sha256: None,
            container_type: None,
            filesystem_detected: None,
            mft_records_attempted: 0,
            mft_records_emitted: 0,
            analysis_mode: "none".to_string(),
            analysis_valid: false,
            warning: None,
            outputs: SmokeTestOutputs {
                summary_txt: None,
                timeline_csv: None,
                audit_json: None,
                json_summary: None,
            },
            sizes: SmokeTestSizes {
                summary_txt: 0,
                timeline_csv: 0,
                audit_json: 0,
                json_summary: 0,
            },
            elapsed_ms: start_time.elapsed().as_millis() as u64,
            status: "error".to_string(),
            error: Some(format!("Image file not found: {}", image_path.display())),
        };
        let out_dir = out_dir.unwrap_or_else(|| PathBuf::from(".\\exports\\smoke_test"));
        let json_summary_path =
            json_summary_path.unwrap_or_else(|| out_dir.join("smoke_summary.json"));
        if let Some(parent) = json_summary_path.parent() {
            let _ = strata_fs::create_dir_all(parent);
        }
        let _ = strata_fs::write(
            &json_summary_path,
            serde_json::to_string_pretty(&summary).unwrap_or_default(),
        );
        eprintln!("Error: Image file not found: {}", image_path.display());
        std::process::exit(1);
    }

    let out_dir = out_dir.unwrap_or_else(|| PathBuf::from(".\\exports\\smoke_test"));
    let json_summary_path = json_summary_path.unwrap_or_else(|| out_dir.join("smoke_summary.json"));

    if let Err(e) = strata_fs::create_dir_all(&out_dir) {
        eprintln!("Error creating output directory: {}", e);
        std::process::exit(1);
    }

    if !quiet {
        println!("Running smoke test...");
        println!("  Image: {}", image_path.display());
        println!("  Out: {}", out_dir.display());
        println!("  MFT count: {}", mft_count);
    }

    let summary_path = out_dir.join("summary.txt");
    let timeline_path = out_dir.join("timeline.csv");
    let audit_path = out_dir.join("audit.json");

    // Real analysis: open container and read data
    let mut did_open_image = false;
    let mut evidence_size_bytes: u64 = 0;
    let mut bytes_actually_read: u64 = 0;
    let sample_sha256: Option<String> = None;
    let mut container_type: Option<String> = None;
    let filesystem_detected: Option<String> = None;
    let mft_records_attempted: u32 = 0;
    let mft_records_emitted: u32 = 0;
    let mut analysis_mode: String = "none".to_string();
    let mut analysis_valid: bool = false;
    let mut analysis_warning: Option<String> = None;
    let analysis_error: Option<String> = None;

    // Try to open based on extension
    let ext = image_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "e01" | "E01" => {
            // First, try to detect if it's actually EVF format (not EWF)
            let mut header_bytes = [0u8; 64];
            if let Ok(mut file) = std::fs::File::open(&image_path) {
                use std::io::Read;
                if file.read(&mut header_bytes).is_ok() && &header_bytes[0..3] == b"EVF" {
                    // This is EVF format, not E01
                    container_type = Some("EVF".to_string());
                    evidence_size_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);

                    // EVF decompression not supported - mark as container_only
                    did_open_image = true;
                    analysis_mode = "container_only".to_string();
                    analysis_valid = false;
                    analysis_warning = Some(
                        "EVF format detected but decompression is not supported. Cannot perform disk analysis.".to_string()
                    );

                    // Read just header bytes to prove we opened the file
                    bytes_actually_read = 64;

                    // Write warning JSON and exit with code 2
                    let result = SmokeTestResult {
                        tool_version: env!("CARGO_PKG_VERSION").to_string(),
                        timestamp_utc: chrono::Utc::now().to_rfc3339(),
                        platform: "windows".to_string(),
                        image_path: image_path.to_string_lossy().to_string(),
                        out_dir: out_dir.to_string_lossy().to_string(),
                        mft_count,
                        timeline_enabled,
                        audit_enabled,
                        did_open_image,
                        evidence_size_bytes,
                        bytes_actually_read,
                        sample_sha256: None,
                        container_type,
                        filesystem_detected: None,
                        mft_records_attempted: 0,
                        mft_records_emitted: 0,
                        analysis_mode,
                        analysis_valid,
                        warning: analysis_warning.clone(),
                        outputs: SmokeTestOutputs {
                            summary_txt: None,
                            timeline_csv: None,
                            audit_json: None,
                            json_summary: Some(json_summary_path.to_string_lossy().to_string()),
                        },
                        sizes: SmokeTestSizes {
                            summary_txt: 0,
                            timeline_csv: 0,
                            audit_json: 0,
                            json_summary: 0,
                        },
                        elapsed_ms: start_time.elapsed().as_millis() as u64,
                        status: "error".to_string(),
                        error: Some("EVF decompression not supported".to_string()),
                    };

                    if let Err(e) = strata_fs::write(
                        &json_summary_path,
                        serde_json::to_string_pretty(&result).unwrap_or_default(),
                    ) {
                        eprintln!("Error writing smoke_summary.json: {}", e);
                    }

                    if let Some(json_path) = json_result_path {
                        let smoke_test_data =
                            serde_json::to_value(&result).unwrap_or(serde_json::Value::Null);
                        let envelope = CliResultEnvelope::new(
                            "smoke-test",
                            original_args.clone(),
                            EXIT_UNSUPPORTED,
                            start_time.elapsed().as_millis() as u64,
                        )
                        .warn(analysis_warning.clone().unwrap_or_default())
                        .error("EVF decompression not supported".to_string())
                        .with_data(smoke_test_data);

                        if let Err(e) = envelope.write_to_file(&json_path) {
                            eprintln!("Error writing JSON result: {}", e);
                        }
                    }

                    std::process::exit(EXIT_UNSUPPORTED);
                }
            }
        }
        _ => {
            // Unknown format - treat as raw
        }
    }

    let elapsed = start_time.elapsed().as_millis() as u64;

    // Determine truthful status based on actual evidence processing
    // status = "ok" ONLY when real evidence was actually opened and processed
    let (truthful_status, truthful_exit_code, truthful_warning) =
        if did_open_image && bytes_actually_read > 0 && analysis_valid {
            // Evidence was actually opened and meaningfully processed
            ("ok".to_string(), EXIT_OK, None)
        } else if did_open_image {
            // Image was opened but analysis is not valid (e.g., format not supported)
            let warning_msg = analysis_warning.clone().unwrap_or_else(|| {
                "Image opened but evidence analysis was not successful".to_string()
            });
            ("warn".to_string(), EXIT_UNSUPPORTED, Some(warning_msg))
        } else {
            // Image was NOT opened or no bytes were read - this is a failure
            let warning_msg = if bytes_actually_read == 0 && did_open_image {
                "Image opened but zero bytes read - evidence analysis not performed".to_string()
            } else {
                "Failed to open evidence image".to_string()
            };
            ("warn".to_string(), EXIT_UNSUPPORTED, Some(warning_msg))
        };

    let result = SmokeTestResult {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        platform: "windows".to_string(),
        image_path: image_path.to_string_lossy().to_string(),
        out_dir: out_dir.to_string_lossy().to_string(),
        mft_count,
        timeline_enabled,
        audit_enabled,
        did_open_image,
        evidence_size_bytes,
        bytes_actually_read,
        sample_sha256,
        container_type,
        filesystem_detected,
        mft_records_attempted,
        mft_records_emitted,
        analysis_mode,
        analysis_valid,
        warning: truthful_warning.or(analysis_warning),
        outputs: SmokeTestOutputs {
            summary_txt: Some(summary_path.to_string_lossy().to_string()),
            timeline_csv: if timeline_enabled {
                Some(timeline_path.to_string_lossy().to_string())
            } else {
                None
            },
            audit_json: if audit_enabled {
                Some(audit_path.to_string_lossy().to_string())
            } else {
                None
            },
            json_summary: Some(json_summary_path.to_string_lossy().to_string()),
        },
        sizes: SmokeTestSizes {
            summary_txt: strata_fs::metadata(&summary_path)
                .map(|m| m.len())
                .unwrap_or(0),
            timeline_csv: if timeline_enabled {
                strata_fs::metadata(&timeline_path)
                    .map(|m| m.len())
                    .unwrap_or(0)
            } else {
                0
            },
            audit_json: if audit_enabled {
                strata_fs::metadata(&audit_path)
                    .map(|m| m.len())
                    .unwrap_or(0)
            } else {
                0
            },
            json_summary: 0,
        },
        elapsed_ms: elapsed,
        status: truthful_status.clone(),
        error: analysis_error,
    };

    if let Err(e) = strata_fs::write(
        &json_summary_path,
        serde_json::to_string_pretty(&result).unwrap_or_default(),
    ) {
        eprintln!("Error writing smoke_summary.json: {}", e);
        std::process::exit(EXIT_ERROR);
    }

    if let Some(json_path) = json_result_path {
        let smoke_test_data = serde_json::to_value(&result).unwrap_or(serde_json::Value::Null);

        // Build envelope with truthful status and any warnings
        let mut envelope =
            CliResultEnvelope::new("smoke-test", original_args, truthful_exit_code, elapsed)
                .with_data(smoke_test_data);

        // Add warning if status is not "ok"
        if truthful_status != "ok" {
            envelope = envelope.warn(
                result
                    .warning
                    .clone()
                    .unwrap_or_else(|| "Evidence processing incomplete".to_string()),
            );
        }

        envelope = envelope
            .with_output(
                "smoke_summary",
                Some(json_summary_path.to_string_lossy().to_string()),
            )
            .with_size(
                "smoke_summary",
                strata_fs::metadata(&json_summary_path)
                    .map(|m| m.len())
                    .unwrap_or(0),
            )
            .with_output(
                "summary_txt",
                Some(summary_path.to_string_lossy().to_string()),
            )
            .with_size(
                "summary_txt",
                strata_fs::metadata(&summary_path)
                    .map(|m| m.len())
                    .unwrap_or(0),
            );

        if let Err(e) = envelope.write_to_file(&json_path) {
            eprintln!("Error writing JSON result: {}", e);
            std::process::exit(EXIT_ERROR);
        }
    }

    if !quiet {
        println!("Smoke test complete in {}ms", elapsed);
        println!("  Status: {}", truthful_status);
        if truthful_status != "ok" {
            if let Some(warning) = &result.warning {
                println!("  Warning: {}", warning);
            }
        }
        println!("  summary.txt: {} bytes", result.sizes.summary_txt);
        if timeline_enabled {
            println!("  timeline.csv: {} bytes", result.sizes.timeline_csv);
        }
        if audit_enabled {
            println!("  audit.json: {} bytes", result.sizes.audit_json);
        }
        println!(
            "  smoke_summary.json: {} bytes",
            strata_fs::metadata(&json_summary_path)
                .map(|m| m.len())
                .unwrap_or(0)
        );
    }

    // Exit with truthful exit code
    std::process::exit(truthful_exit_code);
}
