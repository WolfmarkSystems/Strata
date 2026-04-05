use forensic_engine::container::open_evidence_container;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_split_raw_assembly() {
    let dir = tempdir().unwrap();
    let file1_path = dir.path().join("image.001");
    let file2_path = dir.path().join("image.002");

    let mut f1 = std::fs::File::create(&file1_path).unwrap();
    let data1 = vec![0xAAu8; 1024];
    f1.write_all(&data1).unwrap();

    let mut f2 = std::fs::File::create(&file2_path).unwrap();
    let data2 = vec![0xBBu8; 1024];
    f2.write_all(&data2).unwrap();

    let source = open_evidence_container(&file1_path).expect("Failed to open split RAW");
    assert_eq!(source.size, 2048);

    // Read across boundary
    // Global offset 1000, read 48 bytes (to 1048, which is 24 bytes into file2)
    let mut buf = vec![0u8; 48];
    source
        .vfs
        .as_ref()
        .unwrap()
        .read_volume_at(1000, 48)
        .unwrap()
        .copy_to_slice(&mut buf);

    // First 24 bytes should be 0xAA (from data1)
    assert_eq!(buf[0], 0xAA);
    assert_eq!(buf[23], 0xAA);
    // Next 24 bytes should be 0xBB (from data2)
    assert_eq!(buf[24], 0xBB);
    assert_eq!(buf[47], 0xBB);
}

#[test]
fn test_split_raw_alpha_suffix_assembly() {
    let dir = tempdir().unwrap();
    let file1_path = dir.path().join("capture.aa");
    let file2_path = dir.path().join("capture.ab");

    let mut f1 = std::fs::File::create(&file1_path).unwrap();
    let data1 = vec![0x10u8; 512];
    f1.write_all(&data1).unwrap();

    let mut f2 = std::fs::File::create(&file2_path).unwrap();
    let data2 = vec![0x20u8; 512];
    f2.write_all(&data2).unwrap();

    let source = open_evidence_container(&file1_path).expect("Failed to open alpha split RAW");
    assert_eq!(source.size, 1024);

    let mut buf = vec![0u8; 24];
    source
        .vfs
        .as_ref()
        .unwrap()
        .read_volume_at(500, 24)
        .unwrap()
        .copy_to_slice(&mut buf);

    assert_eq!(buf[0], 0x10);
    assert_eq!(buf[11], 0x10);
    assert_eq!(buf[12], 0x20);
    assert_eq!(buf[23], 0x20);
}

trait CopyToSlice {
    fn copy_to_slice(self, dest: &mut [u8]);
}
impl CopyToSlice for Vec<u8> {
    fn copy_to_slice(self, dest: &mut [u8]) {
        dest.copy_from_slice(&self);
    }
}
