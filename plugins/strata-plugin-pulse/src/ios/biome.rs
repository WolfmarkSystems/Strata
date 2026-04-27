//! iOS Biome / DuetExpertCenter streams.
//!
//! Biome is the iOS 15+ replacement for the older CoreDuet stream
//! pipeline. It records app launches, hardware events, and user
//! activity in append-only protobuf segment files under
//! `Library/Biome/streams/public/<stream-name>/local/<segment>`.
//!
//! Pulse v1.0 reports per-stream presence — segment-level decoding
//! requires Apple's protobuf schema which is not publicly stable.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "/biome/streams/")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 || !path.is_file() {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();

    // Pull the stream name out of the path: .../streams/public/<NAME>/local/<segment>
    let stream_name = source
        .split("/streams/")
        .nth(1)
        .and_then(|tail| tail.split('/').nth(1))
        .unwrap_or("(unknown)")
        .to_string();

    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: format!("Biome stream: {}", stream_name),
        timestamp: None,
        title: format!("iOS Biome stream `{}`", stream_name),
        detail: format!(
            "Biome segment file present at {} ({} bytes) — protobuf payload, Apple-private schema",
            source, size
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_segment(dir: &Path, stream: &str, name: &str) -> std::io::Result<std::path::PathBuf> {
        let p = dir
            .join("Library")
            .join("Biome")
            .join("streams")
            .join("public")
            .join(stream)
            .join("local")
            .join(name);
        std::fs::create_dir_all(p.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
        })?)?;
        std::fs::write(&p, b"protobuf-payload")?;
        Ok(p)
    }

    #[test]
    fn matches_biome_stream_paths() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Biome/streams/public/_DKEventBundle/local/segment-001"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn extracts_stream_name_into_subcategory() {
        let dir = tempdir().expect("tempdir creation failed");
        let p = write_segment(dir.path(), "_DKEventBundle", "segment-001")
            .expect("write_segment failed");
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].subcategory, "Biome stream: _DKEventBundle");
    }

    #[test]
    fn empty_file_returns_no_records() {
        let dir = tempdir().expect("tempdir creation failed");
        let p = dir.path().join("Library/Biome/streams/public/x/local/seg");
        std::fs::create_dir_all(p.parent().expect("path has no parent"))
            .expect("create_dir_all failed");
        std::fs::write(&p, b"").expect("write failed");
        assert!(parse(&p).is_empty());
    }
}
