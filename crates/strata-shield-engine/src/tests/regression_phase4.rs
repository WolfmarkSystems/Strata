#[cfg(test)]
mod regression_phase4_tests {
    use serde_json::Value;
    use std::path::PathBuf;

    fn workspace_fixture(path: &str) -> PathBuf {
        let mut dir = std::env::current_dir().expect("cwd");
        for _ in 0..8 {
            let candidate = dir.join(path);
            if candidate.exists() {
                return candidate;
            }
            if !dir.pop() {
                break;
            }
        }
        PathBuf::from(path)
    }

    #[test]
    fn ingest_manifest_fixture_is_parseable() {
        let path = workspace_fixture("tests/fixtures/ingest_manifest_sample.json");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(path).expect("ingest fixture should be readable");
        let json: Value = serde_json::from_slice(&bytes).expect("valid json");
        assert!(json.get("parser_name").is_some());
        assert!(json.get("parser_version").is_some());
    }

    #[test]
    fn canonical_record_fixture_is_parseable() {
        let path = workspace_fixture("tests/fixtures/canonical_record_sample.json");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(path).expect("canonical fixture should be readable");
        let json: Value = serde_json::from_slice(&bytes).expect("valid json");
        assert!(json.get("record_type").is_some());
        assert!(json.get("confidence_score").is_some());
    }
}
