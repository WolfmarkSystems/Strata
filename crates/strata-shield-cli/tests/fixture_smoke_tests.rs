use forensic_engine::case::database::CaseDatabase;
use rusqlite::params;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn fixture_base() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("apps")
        .join("shield")
        .join("fixtures")
        .join("parsers")
}

fn run_cli(args: &[String]) -> Output {
    if let Some(binary) = std::env::var_os("CARGO_BIN_EXE_strata") {
        Command::new(binary)
            .args(args)
            .output()
            .expect("failed to execute strata binary")
    } else {
        Command::new("cargo")
            .args(["run", "-p", "strata-shield-cli", "--"])
            .args(args)
            .output()
            .expect("failed to execute strata via cargo run")
    }
}

fn run_cli_json_result(args: Vec<String>, json_result_path: &Path) -> (Output, serde_json::Value) {
    let mut full_args = Vec::new();
    if args.is_empty() {
        panic!("run_cli_json_result requires at least one CLI argument");
    }

    full_args.push(args[0].clone());
    full_args.extend(args.into_iter().skip(1));
    full_args.push("--json-result".to_string());
    full_args.push(json_result_path.to_string_lossy().to_string());

    let _ = strata_fs::remove_file(json_result_path);
    let output = run_cli(&full_args);
    let content = strata_fs::read_to_string(json_result_path).expect("json result should exist");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("json result should parse");
    (output, parsed)
}

fn assert_no_panic(output: &Output) {
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("thread panicked") && !combined.contains("unwrap failed"),
        "CLI output should not contain panic markers: {}",
        combined
    );
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
        params![case_id, format!("Case {}", case_id), "fixture-smoke", now, now],
    )
    .expect("seed cases row");
    db_path
}

#[test]
#[ignore = "requires built forensic_cli binary"]
fn test_evtx_empty_fixture() {
    let test_dir = unique_test_dir("evtx_empty_fixture");
    let json_result = test_dir.join("evtx_result.json");
    let fixture = fixture_base().join("evtx").join("empty.evtx");

    let (output, parsed) = run_cli_json_result(
        vec![
            "evtx-security".to_string(),
            "--input".to_string(),
            fixture.to_string_lossy().to_string(),
            "--json".to_string(),
            "--quiet".to_string(),
        ],
        &json_result,
    );

    assert_no_panic(&output);
    let status = parsed.get("status").and_then(|value| value.as_str());
    assert!(matches!(status, Some("ok") | Some("warn")));
    assert_eq!(
        parsed
            .get("data")
            .and_then(|value| value.get("total_returned"))
            .and_then(|value| value.as_u64()),
        Some(0)
    );

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
#[ignore = "requires built forensic_cli binary"]
fn test_registry_empty_fixture() {
    let test_dir = unique_test_dir("registry_empty_fixture");
    let json_result = test_dir.join("registry_result.json");
    let fixture = fixture_base().join("registry").join("empty.reg");

    let (output, parsed) = run_cli_json_result(
        vec![
            "registry-core-user-hives".to_string(),
            "--runmru-reg".to_string(),
            fixture.to_string_lossy().to_string(),
            "--json".to_string(),
            "--quiet".to_string(),
        ],
        &json_result,
    );

    assert_no_panic(&output);
    assert!(parsed.is_object(), "registry envelope should be valid JSON");

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
#[ignore = "requires built forensic_cli binary"]
fn test_lnk_fixture() {
    let test_dir = unique_test_dir("lnk_fixture");
    let json_result = test_dir.join("lnk_result.json");
    let fixture = fixture_base().join("lnk").join("minimal.lnk");

    let (output, parsed) = run_cli_json_result(
        vec![
            "lnk-shortcut-fidelity".to_string(),
            "--input".to_string(),
            fixture.to_string_lossy().to_string(),
            "--json".to_string(),
            "--quiet".to_string(),
        ],
        &json_result,
    );

    assert_no_panic(&output);
    assert!(parsed.is_object(), "lnk envelope should be valid JSON");

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
#[ignore = "requires built forensic_cli binary"]
fn test_json_timeline_fixture() {
    let test_dir = unique_test_dir("timeline_fixture");
    let json_result = test_dir.join("timeline_result.json");
    let db_path = create_case_db(&test_dir, "fixture-smoke");

    let (output, parsed) = run_cli_json_result(
        vec![
            "timeline".to_string(),
            "--case".to_string(),
            "fixture-smoke".to_string(),
            "--db".to_string(),
            db_path.to_string_lossy().to_string(),
            "--source".to_string(),
            "all".to_string(),
            "--json".to_string(),
            "--quiet".to_string(),
        ],
        &json_result,
    );

    assert_no_panic(&output);
    assert!(parsed.is_object(), "timeline envelope should be valid JSON");

    let _ = strata_fs::remove_dir_all(test_dir);
}
