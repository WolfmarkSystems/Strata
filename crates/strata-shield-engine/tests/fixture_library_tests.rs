use std::path::PathBuf;

use forensic_engine::classification::eventlog::parse_security_log;
use forensic_engine::classification::lnk::{detect_lnk_input_shape, parse_lnk, LnkInputShape};
use forensic_engine::classification::prefetch::{
    detect_prefetch_input_shape, parse_prefetch, PrefetchInputShape,
};
use forensic_engine::classification::registry::parse_ntuser_dat;
use forensic_engine::classification::userassist::get_user_assist_data_from_reg;

fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("artifacts")
}

#[test]
fn test_fixture_evtx_parse() {
    let fixture_path = artifacts_dir().join("test.evtx");
    if !fixture_path.exists() {
        return;
    }
    let evtx_bytes = strata_fs::read(&fixture_path).expect("read evtx fixture");
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("fixture_security.evtx");
    strata_fs::write(&path, evtx_bytes).expect("write evtx fixture");

    let summary = parse_security_log(&path).expect("parse security log");
    assert_eq!(summary.logon_events, 1);
    assert_eq!(summary.failed_logons, 1);
    assert!(summary.entries.iter().any(|entry| entry.event_id == 4688));
}

#[test]
fn test_fixture_prefetch_parse() {
    let path = artifacts_dir().join("TESTAPP.EXE-12345678.pf");
    if !path.exists() {
        return;
    }
    assert_eq!(
        detect_prefetch_input_shape(&path),
        PrefetchInputShape::BinaryPf
    );

    let info = parse_prefetch(&path).expect("parse prefetch fixture");
    assert_eq!(info.program_name, "TESTAPP.EXE");
    assert_eq!(info.run_count, 3);
}

#[test]
fn test_fixture_lnk_parse() {
    let path = artifacts_dir().join("test_shortcut.lnk");
    if !path.exists() {
        return;
    }
    assert_eq!(detect_lnk_input_shape(&path), LnkInputShape::LnkFile);

    let lnk = parse_lnk(&path).expect("parse lnk fixture");
    assert!(lnk.target_path.is_none());
}

#[test]
fn test_fixture_ntuser_parse() {
    let path = artifacts_dir().join("NTUSER.DAT");
    if !path.exists() {
        return;
    }
    let keys = parse_ntuser_dat(&path).expect("parse ntuser fixture");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].name, "NTUSER.DAT");
}

#[test]
fn test_fixture_userassist_parse() {
    let path = artifacts_dir().join("test_userassist.reg");
    if !path.exists() {
        return;
    }
    let entries = get_user_assist_data_from_reg(&path);
    assert_eq!(entries.len(), 1);
    assert!(entries[0]
        .name
        .to_ascii_lowercase()
        .contains("\\windows\\notepad.exe"));
    assert_eq!(entries[0].run_count, 7);
}
