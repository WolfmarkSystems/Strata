use forensic_engine::case::database::CaseDatabase;
use rusqlite::params;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "json_contract_golden.rs"]
mod json_contract_golden;

fn unique_test_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    let dir = PathBuf::from(format!("tests_temp_{}_{}", label, nanos));
    let _ = strata_fs::remove_dir_all(&dir);
    strata_fs::create_dir_all(&dir).expect("create test directory");
    dir
}

fn run_cli_owned(args: &[String]) -> Output {
    Command::new("cargo")
        .args(["run", "-p", "strata-shield-cli", "--"])
        .args(args)
        .output()
        .expect("failed to execute forensic_cli")
}

fn run_cli_json_result_owned(
    args: Vec<String>,
    json_result_path: &Path,
) -> (Output, serde_json::Value) {
    let mut full_args = Vec::new();
    if args.is_empty() {
        panic!("run_cli_json_result_owned requires at least a command argument");
    }

    // Put envelope-output flags immediately after the command token so
    // command-level validation paths still know where to write JSON results.
    full_args.push(args[0].clone());
    full_args.push("--json-result".to_string());
    full_args.push(json_result_path.to_string_lossy().to_string());
    full_args.push("--quiet".to_string());
    full_args.extend(args.into_iter().skip(1));

    let _ = strata_fs::remove_file(json_result_path);
    let output = run_cli_owned(&full_args);
    let content =
        strata_fs::read_to_string(json_result_path).expect("json result should be readable");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("json result should parse");
    (output, parsed)
}

fn create_case_db(test_dir: &Path, case_id: &str) -> PathBuf {
    let db_path = test_dir.join("case.sqlite");
    let _db = CaseDatabase::create(case_id, &db_path).expect("create case db");
    let conn = rusqlite::Connection::open(&db_path).expect("open case db");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs() as i64;
    conn.execute(
        "INSERT OR IGNORE INTO cases (id, name, examiner, status, created_at, modified_at) VALUES (?1, ?2, ?3, 'open', ?4, ?5)",
        params![case_id, format!("Case {}", case_id), "smoke-test", now, now],
    )
    .expect("seed cases row");
    db_path
}

fn write_prefetch_jumplist_shortcuts_fixture(test_dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let prefetch_dir = test_dir.join("prefetch");
    let jumplist_file = test_dir.join("sample.automaticdestinations-ms");
    let shortcuts_base = test_dir.join("shortcuts");
    strata_fs::create_dir_all(&prefetch_dir).unwrap();
    strata_fs::create_dir_all(&shortcuts_base).unwrap();

    let prefetch_path = prefetch_dir.join("CMD.EXE-11111111.pf");
    let mut pf_data = vec![0u8; 512];
    pf_data[0..4].copy_from_slice(b"SCCA");
    pf_data[4..8].copy_from_slice(&0x1Eu32.to_le_bytes());
    let ft = (11_644_473_600u64 + 1_700_000_000u64) * 10_000_000u64;
    pf_data[0x80..0x88].copy_from_slice(&ft.to_le_bytes());
    strata_fs::write(&prefetch_path, pf_data).unwrap();

    strata_fs::write(
        &jumplist_file,
        b"DestList\0C:\\Windows\\System32\\cmd.exe\0",
    )
    .unwrap();

    (prefetch_dir, jumplist_file, shortcuts_base)
}

fn assert_envelope_command(parsed: &serde_json::Value, command: &str) {
    assert_eq!(
        parsed.get("command").and_then(|v| v.as_str()),
        Some(command),
        "envelope.command should be '{}'",
        command
    );
}

fn assert_invalid_input_envelope(parsed: &serde_json::Value, command: &str) {
    assert_envelope_command(parsed, command);
    assert_eq!(
        parsed.get("error_type").and_then(|v| v.as_str()),
        Some("invalid_input"),
        "error_type should be invalid_input for command '{}'",
        command
    );
}

#[test]
fn test_capabilities_json_result_flag() {
    let test_dir = unique_test_dir("capabilities_json_result_flag");
    let json_result = test_dir.join("capabilities_result.json");
    let (output, parsed) =
        run_cli_json_result_owned(vec!["capabilities".to_string()], &json_result);

    assert_eq!(output.status.code(), Some(0), "capabilities should succeed");
    assert_envelope_command(&parsed, "capabilities");
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("capabilities"))
            .and_then(|v| v.as_array())
            .is_some(),
        "capabilities data should include capabilities array"
    );

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_doctor_json_result_flag() {
    let test_dir = unique_test_dir("doctor_json_result_flag");
    let json_result = test_dir.join("doctor_result.json");
    let (output, parsed) = run_cli_json_result_owned(vec!["doctor".to_string()], &json_result);

    assert_eq!(output.status.code(), Some(0), "doctor should succeed");
    assert_envelope_command(&parsed, "doctor");
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("platform"))
            .and_then(|v| v.as_str())
            .is_some(),
        "doctor data should include platform"
    );

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_smoke_test_json_result_flag() {
    let test_dir = unique_test_dir("smoke_test_json_result_flag");
    let image_path = test_dir.join("tiny.dd");
    let out_dir = test_dir.join("smoke_out");
    strata_fs::write(&image_path, b"raw smoke bytes").unwrap();

    let json_result = test_dir.join("smoke_test_result.json");
    let args = vec![
        "smoke-test".to_string(),
        "--image".to_string(),
        image_path.to_string_lossy().to_string(),
        "--out".to_string(),
        out_dir.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);

    // Raw files not supported yet - should return EXIT_UNSUPPORTED (2)
    assert_eq!(
        output.status.code(),
        Some(2),
        "smoke-test returns unsupported for raw files"
    );
    assert_envelope_command(&parsed, "smoke-test");

    // Status should NOT be "ok" when image not actually processed
    assert_eq!(
        parsed.get("status").and_then(|v| v.as_str()),
        Some("warn"),
        "smoke-test status should be 'warn' when evidence not processed"
    );

    // Verify warning is present
    assert!(
        parsed.get("warning").and_then(|v| v.as_str()).is_some(),
        "smoke-test should include warning when evidence not processed"
    );

    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("image_path"))
            .and_then(|v| v.as_str())
            .is_some(),
        "smoke-test data should include image_path"
    );

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_smoke_test_missing_image_exits_nonzero() {
    let test_dir = unique_test_dir("smoke_test_missing_image");
    let missing_path = test_dir.join("missing.dd");

    let args = vec![
        "smoke-test".to_string(),
        "--image".to_string(),
        missing_path.to_string_lossy().to_string(),
    ];
    let output = run_cli_owned(&args);
    // Missing file should exit with error (1), not success (0)
    assert_eq!(
        output.status.code(),
        Some(1),
        "smoke-test with missing image should exit with error"
    );

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_smoke_test_status_warn_when_not_opened() {
    // Verify that smoke-test NEVER returns status="ok" when image wasn't actually processed
    let test_dir = unique_test_dir("smoke_test_status_warn");
    let image_path = test_dir.join("test.dd");
    let out_dir = test_dir.join("out");
    strata_fs::write(&image_path, b"test data").unwrap();

    let json_result = test_dir.join("result.json");
    // Note: Don't include --json-result in args - the helper adds it
    let args = vec![
        "smoke-test".to_string(),
        "--image".to_string(),
        image_path.to_string_lossy().to_string(),
        "--out".to_string(),
        out_dir.to_string_lossy().to_string(),
    ];
    let (_output, parsed) = run_cli_json_result_owned(args, &json_result);

    // Envelope status must NOT be "ok" when evidence wasn't processed
    assert_ne!(
        parsed.get("status").and_then(|v| v.as_str()),
        Some("ok"),
        "Envelope status must NOT be 'ok' when evidence was not processed"
    );

    // Should be "warn" since the command completed but didn't process evidence
    assert_eq!(
        parsed.get("status").and_then(|v| v.as_str()),
        Some("warn"),
        "Status should be 'warn' when evidence not processed"
    );

    // Inner data should also reflect the truth
    let data = parsed.get("data").expect("data should exist");
    assert_eq!(
        data.get("did_open_image").and_then(|v| v.as_bool()),
        Some(false),
        "did_open_image should be false"
    );

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_smoke_test_never_false_success() {
    // This is the core truthfulness test: verify that status="ok" is only returned
    // when evidence was actually opened AND bytes were actually read
    let test_dir = unique_test_dir("smoke_test_truthfulness");
    let image_path = test_dir.join("fake.e01");
    let out_dir = test_dir.join("out");

    // Create a file that looks like EVF header but isn't real
    let mut fake_evf = vec![0u8; 512];
    fake_evf[0..3].copy_from_slice(b"EVF");
    strata_fs::write(&image_path, fake_evf).unwrap();

    let json_result = test_dir.join("result.json");
    // Note: Don't include --json-result in args - the helper adds it
    let args = vec![
        "smoke-test".to_string(),
        "--image".to_string(),
        image_path.to_string_lossy().to_string(),
        "--out".to_string(),
        out_dir.to_string_lossy().to_string(),
    ];
    let (_output, parsed) = run_cli_json_result_owned(args, &json_result);

    // Even though did_open_image might be true, if analysis_valid is false,
    // status should NOT be "ok" - it should be "warn"
    let envelope_status = parsed.get("status").and_then(|v| v.as_str());
    let data_status = parsed
        .get("data")
        .and_then(|d| d.get("status"))
        .and_then(|v| v.as_str());
    let analysis_valid = parsed
        .get("data")
        .and_then(|d| d.get("analysis_valid"))
        .and_then(|v| v.as_bool());

    // If analysis_valid is false, status must NOT be "ok"
    if analysis_valid == Some(false) {
        assert_ne!(
            envelope_status,
            Some("ok"),
            "Envelope status must not be 'ok' when analysis_valid is false"
        );
        assert_ne!(
            data_status,
            Some("ok"),
            "Data status must not be 'ok' when analysis_valid is false"
        );
    }

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_smoke_test_small_raw_file() {
    let test_dir = unique_test_dir("smoke_test_small_raw_file");
    let image_path = test_dir.join("small.dd");
    let out_dir = test_dir.join("out");
    strata_fs::write(&image_path, b"small raw").unwrap();

    let json_summary = test_dir.join("summary.json");
    let args = vec![
        "smoke-test".to_string(),
        "--image".to_string(),
        image_path.to_string_lossy().to_string(),
        "--out".to_string(),
        out_dir.to_string_lossy().to_string(),
        "--json-summary".to_string(),
        json_summary.to_string_lossy().to_string(),
        "--quiet".to_string(),
    ];

    let output = run_cli_owned(&args);
    // Raw files not supported yet - should return EXIT_UNSUPPORTED (2), NOT 0
    assert_eq!(
        output.status.code(),
        Some(2),
        "smoke-test should return EXIT_UNSUPPORTED for unsupported raw files"
    );
    assert!(
        json_summary.exists(),
        "smoke-test should write json summary even for unsupported files"
    );

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_verify_json_result_success_writes_envelope() {
    let test_dir = unique_test_dir("verify_json_result_success");
    let case_id = "verify_case";
    let db_path = create_case_db(&test_dir, case_id);
    let json_result = test_dir.join("verify_result.json");

    let args = vec![
        "verify".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    let exit_code = output.status.code();
    assert!(
        matches!(exit_code, Some(0) | Some(1)),
        "verify should return a deterministic CLI exit status with an envelope"
    );
    assert_envelope_command(&parsed, "verify");
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("checks"))
            .and_then(|v| v.as_array())
            .is_some(),
        "verify data should include checks array"
    );
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("status"))
            .and_then(|v| v.as_str())
            .map(|s| matches!(s, "pass" | "warn" | "fail"))
            .unwrap_or(false),
        "verify data.status should be one of pass|warn|fail"
    );

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_verify_missing_case_exits_validation_error() {
    let test_dir = unique_test_dir("verify_missing_case");
    let db_path = test_dir.join("case.sqlite");
    let json_result = test_dir.join("verify_missing_case.json");
    let args = vec![
        "verify".to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);

    assert_eq!(
        output.status.code(),
        Some(3),
        "verify should fail validation when --case is missing"
    );
    assert_invalid_input_envelope(&parsed, "verify");

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_verify_missing_db_exits_validation_error() {
    let test_dir = unique_test_dir("verify_missing_db");
    let json_result = test_dir.join("verify_missing_db.json");
    let args = vec![
        "verify".to_string(),
        "--case".to_string(),
        "missing-db-case".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);

    assert_eq!(
        output.status.code(),
        Some(3),
        "verify should fail validation when --db is missing"
    );
    assert_invalid_input_envelope(&parsed, "verify");

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_triage_session_json_result_success() {
    let test_dir = unique_test_dir("triage_session_success");
    let case_id = "triage_case";
    let db_path = create_case_db(&test_dir, case_id);
    let json_result = test_dir.join("triage_result.json");

    let args = vec![
        "triage-session".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
        "--no-watchpoints".to_string(),
        "--no-replay".to_string(),
        "--no-verify".to_string(),
        "--no-bundle".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);

    assert_eq!(
        output.status.code(),
        Some(0),
        "triage-session should succeed with minimal flags"
    );
    assert_envelope_command(&parsed, "triage-session");
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("result"))
            .and_then(|v| v.get("session_id"))
            .map(|v| v.is_string() || v.is_number())
            .unwrap_or(false),
        "triage-session data should include result.session_id (string or numeric)"
    );

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_triage_session_missing_case_exits_validation() {
    let test_dir = unique_test_dir("triage_missing_case");
    let db_path = test_dir.join("case.sqlite");
    let json_result = test_dir.join("triage_missing_case.json");
    let args = vec![
        "triage-session".to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "triage-session");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_triage_session_missing_db_exits_validation() {
    let test_dir = unique_test_dir("triage_missing_db");
    let json_result = test_dir.join("triage_missing_db.json");
    let args = vec![
        "triage-session".to_string(),
        "--case".to_string(),
        "triage".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "triage-session");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_examine_json_result_success() {
    let test_dir = unique_test_dir("examine_json_success");
    let case_id = "examine_case";
    let db_path = create_case_db(&test_dir, case_id);
    let json_result = test_dir.join("examine_result.json");
    let args = vec![
        "examine".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);

    let exit_code = output.status.code();
    assert!(
        matches!(exit_code, Some(0) | Some(1)),
        "examine should return a deterministic CLI exit status with an envelope"
    );
    assert_envelope_command(&parsed, "examine");
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("result"))
            .and_then(|v| v.get("session_id"))
            .map(|v| v.is_string() || v.is_number())
            .unwrap_or(false),
        "examine should include result.session_id (string or numeric)"
    );
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("result"))
            .and_then(|v| v.get("status"))
            .and_then(|v| v.as_str())
            .is_some(),
        "examine should include result.status"
    );
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_examine_missing_case_exits_validation() {
    let test_dir = unique_test_dir("examine_missing_case");
    let db_path = test_dir.join("case.sqlite");
    let json_result = test_dir.join("examine_missing_case.json");
    let args = vec![
        "examine".to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "examine");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_examine_missing_db_exits_validation() {
    let test_dir = unique_test_dir("examine_missing_db");
    let json_result = test_dir.join("examine_missing_db.json");
    let args = vec![
        "examine".to_string(),
        "--case".to_string(),
        "examine".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "examine");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_examine_preset_not_found_exits_error() {
    let test_dir = unique_test_dir("examine_preset_not_found");
    let case_id = "examine_missing_preset";
    let db_path = create_case_db(&test_dir, case_id);
    let json_result = test_dir.join("examine_not_found.json");
    let args = vec![
        "examine".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
        "--preset".to_string(),
        "does-not-exist".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(1));
    assert_envelope_command(&parsed, "examine");
    assert_eq!(
        parsed.get("error_type").and_then(|v| v.as_str()),
        Some("not_found")
    );
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_watchpoints_enable_success() {
    let test_dir = unique_test_dir("watchpoints_enable");
    let case_id = "watch_case";
    let db_path = create_case_db(&test_dir, case_id);
    let json_result = test_dir.join("watch_enable.json");
    let args = vec![
        "watchpoints".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
        "--enable".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(0));
    assert_envelope_command(&parsed, "watchpoints");
    assert_eq!(
        parsed
            .get("data")
            .and_then(|v| v.get("watchpoints_enabled"))
            .and_then(|v| v.as_bool()),
        Some(true)
    );
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_watchpoints_status_success() {
    let test_dir = unique_test_dir("watchpoints_status");
    let case_id = "watch_status_case";
    let db_path = create_case_db(&test_dir, case_id);
    let json_result = test_dir.join("watch_status.json");
    let args = vec![
        "watchpoints".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
        "--status".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(0));
    assert_envelope_command(&parsed, "watchpoints");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_watchpoints_missing_case() {
    let test_dir = unique_test_dir("watchpoints_missing_case");
    let json_result = test_dir.join("watch_missing_case.json");
    let args = vec![
        "watchpoints".to_string(),
        "--db".to_string(),
        test_dir.join("case.sqlite").to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "watchpoints");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_watchpoints_missing_db() {
    let test_dir = unique_test_dir("watchpoints_missing_db");
    let json_result = test_dir.join("watch_missing_db.json");
    let args = vec![
        "watchpoints".to_string(),
        "--case".to_string(),
        "watch_case".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "watchpoints");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_violations_success() {
    let test_dir = unique_test_dir("violations_success");
    let case_id = "viol_case";
    let db_path = create_case_db(&test_dir, case_id);
    let json_result = test_dir.join("violations.json");
    let args = vec![
        "violations".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(0));
    assert_envelope_command(&parsed, "violations");
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("total_returned"))
            .and_then(|v| v.as_u64())
            .is_some(),
        "violations data should include total_returned"
    );
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_violations_missing_case() {
    let test_dir = unique_test_dir("violations_missing_case");
    let json_result = test_dir.join("viol_missing_case.json");
    let args = vec![
        "violations".to_string(),
        "--db".to_string(),
        test_dir.join("case.sqlite").to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "violations");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_violations_missing_db() {
    let test_dir = unique_test_dir("violations_missing_db");
    let json_result = test_dir.join("viol_missing_db.json");
    let args = vec![
        "violations".to_string(),
        "--case".to_string(),
        "viol_case".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "violations");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_violations_clear_missing_case() {
    let test_dir = unique_test_dir("violations_clear_missing_case");
    let json_result = test_dir.join("viol_clear_missing_case.json");
    let args = vec![
        "violations-clear".to_string(),
        "--db".to_string(),
        test_dir.join("case.sqlite").to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "violations-clear");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_violations_clear_success() {
    let test_dir = unique_test_dir("violations_clear_success");
    let case_id = "clear_case";
    let db_path = create_case_db(&test_dir, case_id);
    let json_result = test_dir.join("viol_clear.json");
    let args = vec![
        "violations-clear".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(0));
    assert_envelope_command(&parsed, "violations-clear");
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("cleared"))
            .and_then(|v| v.as_u64())
            .is_some(),
        "violations-clear data should include cleared count"
    );
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_execution_correlation_json_result_success() {
    let test_dir = unique_test_dir("execution_correlation_success");
    let (prefetch_dir, jumplist_file, shortcuts_base) =
        write_prefetch_jumplist_shortcuts_fixture(&test_dir);
    let json_result = test_dir.join("execution_correlation.json");

    let args = vec![
        "execution-correlation".to_string(),
        "--prefetch-dir".to_string(),
        prefetch_dir.to_string_lossy().to_string(),
        "--jumplist-path".to_string(),
        jumplist_file.to_string_lossy().to_string(),
        "--shortcuts-base".to_string(),
        shortcuts_base.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(0));
    assert_envelope_command(&parsed, "execution-correlation");
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("correlations"))
            .and_then(|v| v.as_array())
            .map(|rows| !rows.is_empty())
            .unwrap_or(false),
        "execution-correlation should return at least one row"
    );
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_recent_execution_json_result_success() {
    let test_dir = unique_test_dir("recent_execution_success");
    let (prefetch_dir, jumplist_file, shortcuts_base) =
        write_prefetch_jumplist_shortcuts_fixture(&test_dir);
    let json_result = test_dir.join("recent_execution.json");

    let args = vec![
        "recent-execution".to_string(),
        "--prefetch-dir".to_string(),
        prefetch_dir.to_string_lossy().to_string(),
        "--jumplist-path".to_string(),
        jumplist_file.to_string_lossy().to_string(),
        "--shortcuts-base".to_string(),
        shortcuts_base.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(0));
    assert_envelope_command(&parsed, "recent-execution");
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("correlations"))
            .and_then(|v| v.as_array())
            .is_some(),
        "recent-execution should include correlations array"
    );
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_execution_correlation_evtx_security_enrichment() {
    let test_dir = unique_test_dir("execution_corr_evtx_security");
    let (prefetch_dir, jumplist_file, shortcuts_base) =
        write_prefetch_jumplist_shortcuts_fixture(&test_dir);
    let evtx_input = test_dir.join("Security.evtx");
    strata_fs::write(
        &evtx_input,
        r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><Level>4</Level><EventRecordID>9</EventRecordID><TimeCreated SystemTime="2026-03-10T12:05:00.000Z"/><Computer>WIN11LAB</Computer></System><EventData><Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data><Data Name="TargetUserName">alice</Data><Data Name="WorkstationName">LAB-WS1</Data></EventData></Event>"#,
    )
    .unwrap();

    let json_result = test_dir.join("execution_correlation_evtx_security.json");
    let args = vec![
        "execution-correlation".to_string(),
        "--prefetch-dir".to_string(),
        prefetch_dir.to_string_lossy().to_string(),
        "--jumplist-path".to_string(),
        jumplist_file.to_string_lossy().to_string(),
        "--shortcuts-base".to_string(),
        shortcuts_base.to_string_lossy().to_string(),
        "--evtx-security-input".to_string(),
        evtx_input.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(0));
    let first = parsed
        .get("data")
        .and_then(|v| v.get("correlations"))
        .and_then(|v| v.as_array())
        .and_then(|rows| rows.first())
        .expect("expected first correlation row");
    assert!(
        first
            .get("observed_users")
            .and_then(|v| v.as_array())
            .map(|items| items.iter().any(|v| v.as_str() == Some("alice")))
            .unwrap_or(false),
        "expected observed_users to include alice"
    );
    assert!(
        first
            .get("observed_devices")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .any(|v| matches!(v.as_str(), Some("WIN11LAB") | Some("LAB-WS1")))
            })
            .unwrap_or(false),
        "expected observed_devices to include Security.evtx machine/workstation context"
    );
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_execution_correlation_logfile_recycle_enrichment() {
    let test_dir = unique_test_dir("execution_corr_logfile_recycle");
    let (prefetch_dir, jumplist_file, shortcuts_base) =
        write_prefetch_jumplist_shortcuts_fixture(&test_dir);
    let logfile_input = test_dir.join("logfile.json");
    let recycle_input = test_dir.join("recycle.json");

    strata_fs::write(
        &logfile_input,
        r#"{"signals":[{"offset":12,"signal":"file_delete","context":"Delete C:\\Temp\\cmd.exe","timestamp_unix":1700001234,"process_path":"C:/Windows/System32/cmd.exe","sid":"S-1-5-21-9999","user":"analyst","device":"LABWIN11"}]}"#,
    )
    .unwrap();
    strata_fs::write(
        &recycle_input,
        r#"{"entries":[{"file_name":"cmd.exe","deleted_time":1700002000,"file_size":128,"original_path":"C:/Windows/System32/cmd.exe","owner_sid":"S-1-5-21-1000"}]}"#,
    )
    .unwrap();

    let json_result = test_dir.join("execution_correlation_logfile_recycle.json");
    let args = vec![
        "execution-correlation".to_string(),
        "--prefetch-dir".to_string(),
        prefetch_dir.to_string_lossy().to_string(),
        "--jumplist-path".to_string(),
        jumplist_file.to_string_lossy().to_string(),
        "--shortcuts-base".to_string(),
        shortcuts_base.to_string_lossy().to_string(),
        "--logfile-input".to_string(),
        logfile_input.to_string_lossy().to_string(),
        "--recycle-input".to_string(),
        recycle_input.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(0));
    let first = parsed
        .get("data")
        .and_then(|v| v.get("correlations"))
        .and_then(|v| v.as_array())
        .and_then(|rows| rows.first())
        .expect("expected first row");
    assert!(
        first
            .get("observed_users")
            .and_then(|v| v.as_array())
            .map(|items| items.iter().any(|v| v.as_str() == Some("analyst")))
            .unwrap_or(false),
        "expected observed_users to include logfile user"
    );
    assert!(
        first
            .get("observed_devices")
            .and_then(|v| v.as_array())
            .map(|items| items.iter().any(|v| v.as_str() == Some("LABWIN11")))
            .unwrap_or(false),
        "expected observed_devices to include logfile device"
    );
    assert!(
        first
            .get("observed_sids")
            .and_then(|v| v.as_array())
            .map(|items| items.iter().any(|v| v.as_str() == Some("S-1-5-21-1000")))
            .unwrap_or(false),
        "expected observed_sids to include recycle owner sid"
    );
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_timeline_json_result_success_writes_envelope() {
    let test_dir = unique_test_dir("timeline_json_result_success");
    let case_id = "timeline_case";
    let db_path = create_case_db(&test_dir, case_id);
    let json_result = test_dir.join("timeline_result.json");

    let args = vec![
        "timeline".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
        "--limit".to_string(),
        "50".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(0));
    assert_envelope_command(&parsed, "timeline");
    assert!(
        parsed
            .get("data")
            .and_then(|v| v.get("events"))
            .and_then(|v| v.as_array())
            .is_some(),
        "timeline data should include events array"
    );
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_timeline_missing_case_exits_validation() {
    let test_dir = unique_test_dir("timeline_missing_case");
    let db_path = test_dir.join("case.sqlite");
    let json_result = test_dir.join("timeline_missing_case.json");
    let args = vec![
        "timeline".to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "timeline");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_timeline_missing_db_exits_validation() {
    let test_dir = unique_test_dir("timeline_missing_db");
    let json_result = test_dir.join("timeline_missing_db.json");
    let args = vec![
        "timeline".to_string(),
        "--case".to_string(),
        "timeline".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "timeline");
    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn test_timeline_invalid_severity_exits_validation() {
    let test_dir = unique_test_dir("timeline_invalid_severity");
    let case_id = "timeline_invalid_severity";
    let db_path = create_case_db(&test_dir, case_id);
    let json_result = test_dir.join("timeline_invalid_severity.json");
    let args = vec![
        "timeline".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "--db".to_string(),
        db_path.to_string_lossy().to_string(),
        "--severity".to_string(),
        "definitely-invalid".to_string(),
    ];
    let (output, parsed) = run_cli_json_result_owned(args, &json_result);
    assert_eq!(output.status.code(), Some(3));
    assert_invalid_input_envelope(&parsed, "timeline");
    let _ = strata_fs::remove_dir_all(test_dir);
}

macro_rules! invalid_limit_command_test {
    ($name:ident, $command:expr) => {
        #[test]
        fn $name() {
            let test_dir = unique_test_dir(stringify!($name));
            let json_result = test_dir.join("invalid_limit.json");
            let args = vec![
                $command.to_string(),
                "--limit".to_string(),
                "bad_limit".to_string(),
            ];
            let (output, parsed) = run_cli_json_result_owned(args, &json_result);
            assert_eq!(
                output.status.code(),
                Some(3),
                "{} should fail with validation on invalid --limit",
                $command
            );
            assert_invalid_input_envelope(&parsed, $command);
            let _ = strata_fs::remove_dir_all(test_dir);
        }
    };
}

invalid_limit_command_test!(
    test_amcache_deep_invalid_limit_exits_validation,
    "amcache-deep"
);
invalid_limit_command_test!(
    test_bam_dam_activity_invalid_limit_exits_validation,
    "bam-dam-activity"
);
invalid_limit_command_test!(
    test_browser_forensics_invalid_limit_exits_validation,
    "browser-forensics"
);
invalid_limit_command_test!(
    test_evtx_security_invalid_limit_exits_validation,
    "evtx-security"
);
invalid_limit_command_test!(
    test_evtx_sysmon_invalid_limit_exits_validation,
    "evtx-sysmon"
);
invalid_limit_command_test!(
    test_jumplist_fidelity_invalid_limit_exits_validation,
    "jumplist-fidelity"
);
invalid_limit_command_test!(
    test_lnk_shortcut_fidelity_invalid_limit_exits_validation,
    "lnk-shortcut-fidelity"
);
invalid_limit_command_test!(
    test_ntfs_logfile_signals_invalid_limit_exits_validation,
    "ntfs-logfile-signals"
);
invalid_limit_command_test!(
    test_ntfs_mft_fidelity_invalid_limit_exits_validation,
    "ntfs-mft-fidelity"
);
invalid_limit_command_test!(
    test_powershell_artifacts_invalid_limit_exits_validation,
    "powershell-artifacts"
);
invalid_limit_command_test!(
    test_prefetch_fidelity_invalid_limit_exits_validation,
    "prefetch-fidelity"
);
invalid_limit_command_test!(
    test_rdp_remote_access_invalid_limit_exits_validation,
    "rdp-remote-access"
);
invalid_limit_command_test!(
    test_recycle_bin_artifacts_invalid_limit_exits_validation,
    "recycle-bin-artifacts"
);
invalid_limit_command_test!(
    test_registry_core_user_hives_invalid_limit_exits_validation,
    "registry-core-user-hives"
);
invalid_limit_command_test!(
    test_scheduled_tasks_artifacts_invalid_limit_exits_validation,
    "scheduled-tasks-artifacts"
);
invalid_limit_command_test!(
    test_services_drivers_artifacts_invalid_limit_exits_validation,
    "services-drivers-artifacts"
);
invalid_limit_command_test!(
    test_shimcache_deep_invalid_limit_exits_validation,
    "shimcache-deep"
);
invalid_limit_command_test!(test_srum_invalid_limit_exits_validation, "srum");
invalid_limit_command_test!(
    test_timeline_correlation_qa_invalid_limit_exits_validation,
    "timeline-correlation-qa"
);
invalid_limit_command_test!(
    test_usb_device_history_invalid_limit_exits_validation,
    "usb-device-history"
);
invalid_limit_command_test!(
    test_user_activity_mru_invalid_limit_exits_validation,
    "user-activity-mru"
);
invalid_limit_command_test!(
    test_usn_journal_fidelity_invalid_limit_exits_validation,
    "usn-journal-fidelity"
);
invalid_limit_command_test!(
    test_wmi_persistence_activity_invalid_limit_exits_validation,
    "wmi-persistence-activity"
);
