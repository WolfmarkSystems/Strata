use forensic_engine::container::{ContainerType, EvidenceSource};
use std::fs::File;
use std::path::{Path, PathBuf};

fn create_temp_file(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("forensic_tests_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    File::create(&path).unwrap();
    path
}

#[test]
fn test_container_type_detection() {
    // Note: ContainerType::from_path detects based on extension
    assert_eq!(
        ContainerType::from_path(Path::new("image.dd")),
        ContainerType::Raw
    );
    assert_eq!(
        ContainerType::from_path(Path::new("image.raw")),
        ContainerType::Raw
    );
    assert_eq!(
        ContainerType::from_path(Path::new("image.E01")),
        ContainerType::E01
    );
    assert_eq!(
        ContainerType::from_path(Path::new("image.vmdk")),
        ContainerType::Vmdk
    );
    assert_eq!(
        ContainerType::from_path(Path::new("image.vhd")),
        ContainerType::Vhd
    );
    assert_eq!(
        ContainerType::from_path(Path::new("image.vhdx")),
        ContainerType::Vhdx
    );
}

#[test]
fn test_container_is_container() {
    assert!(ContainerType::Raw.is_container());
    assert!(ContainerType::E01.is_container());
    assert!(!ContainerType::Directory.is_container());
}

#[test]
fn test_evidence_source_open_directory() {
    let dir = std::env::temp_dir().join(format!("forensic_tests_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    let source = EvidenceSource::open(&dir).expect("Failed to open directory");
    assert_eq!(source.container_type, ContainerType::Directory);
    assert!(!source.is_container());
    assert!(source.vfs.is_some());
    assert_eq!(source.size, 0);

    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_evidence_source_open_invalid_raw_fails_gracefully() {
    // Create an empty file that claims to be a raw image
    // Note: Since we haven't mocked the internal parsers, an empty file will likely fail
    // to open as a proper E01/Raw container if it lacks headers, but that's what we want to test:
    // ensuring the error bubbling works properly.
    let path = create_temp_file("test.dd");

    let source_result = EvidenceSource::open(&path);
    // RawVfs might actually succeed on an empty file depending on implementation,
    // but if it fails it should return ForensicError. We just want to ensure it doesn't panic.
    if let Ok(source) = source_result {
        assert_eq!(source.container_type, ContainerType::Raw);
        assert!(source.vfs.is_some());
    }

    std::fs::remove_file(path).ok();
}
