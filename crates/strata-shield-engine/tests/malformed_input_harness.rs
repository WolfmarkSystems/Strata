use forensic_engine::classification::autorun::get_auto_run_keys_from_reg;
use forensic_engine::classification::regbam::get_bam_state_from_reg;
use forensic_engine::classification::{
    parse_application_log, parse_security_log, parse_system_log,
};

fn fuzz_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        out.push((state & 0xFF) as u8);
    }
    out
}

#[test]
fn malformed_registry_exports_do_not_panic() {
    let dir = tempfile::tempdir().expect("tempdir should create");

    for i in 0..96usize {
        let path = dir.path().join(format!("malformed_{i}.reg"));
        let len = (i * 37 % 1024) + 1;
        let bytes = fuzz_bytes((i as u64) + 0xA11CE, len);
        strata_fs::write(&path, bytes).expect("should write malformed reg fixture");

        // Harness contract: malformed data may return empty vectors, but must not panic.
        let _autoruns = get_auto_run_keys_from_reg(&path);
        let _bam = get_bam_state_from_reg(&path);
    }
}

#[test]
fn malformed_event_logs_do_not_panic() {
    let dir = tempfile::tempdir().expect("tempdir should create");

    for i in 0..96usize {
        let path = dir.path().join(format!("malformed_{i}.evtx"));
        let len = (i * 53 % 2048) + 1;
        let bytes = fuzz_bytes((i as u64) + 0xE17A, len);
        strata_fs::write(&path, bytes).expect("should write malformed evtx fixture");

        // Harness contract: parser may return Err for malformed input, but must not panic.
        let _ = parse_security_log(&path);
        let _ = parse_system_log(&path);
        let _ = parse_application_log(&path);
    }
}
