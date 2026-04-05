use flate2::write::ZlibEncoder;
use flate2::Compression;
use forensic_engine::container::open_evidence_container;
use std::io::{Seek, SeekFrom, Write};

#[test]
fn test_qcow2_read() {
    let mut file = tempfile::Builder::new()
        .suffix(".qcow2")
        .tempfile()
        .expect("Failed to create temp qcow2");

    // QCOW2 Header (72 bytes)
    let mut header = [0u8; 72];
    header[0..4].copy_from_slice(b"QFI\xfb");
    header[4..8].copy_from_slice(&2u32.to_be_bytes()); // version 2
    header[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits (64KB)
    header[24..32].copy_from_slice(&(1024u64 * 1024).to_be_bytes()); // size (1MB)
    header[36..40].copy_from_slice(&1u32.to_be_bytes()); // l1_size (1 entry)
    header[40..48].copy_from_slice(&1024u64.to_be_bytes()); // l1_table_offset (offset 1024)

    file.write_all(&header).unwrap();

    // L1 Table at offset 1024
    file.seek(SeekFrom::Start(1024)).unwrap();
    let mut l1 = [0u8; 8];
    // Offset to L2 table is 2048, mark as 'copied' (bit 63)
    let l2_offset: u64 = 2048 | (1u64 << 63);
    l1.copy_from_slice(&l2_offset.to_be_bytes());
    file.write_all(&l1).unwrap();

    // L2 Table at offset 2048
    file.seek(SeekFrom::Start(2048)).unwrap();
    let mut l2 = [0u8; 8];
    // Offset to data cluster is 65536, mark as 'copied' (bit 63)
    let data_offset: u64 = 65536 | (1u64 << 63);
    l2.copy_from_slice(&data_offset.to_be_bytes());
    file.write_all(&l2).unwrap();

    // Data at offset 65536
    file.seek(SeekFrom::Start(65536)).unwrap();
    let data = [0x55u8; 512];
    file.write_all(&data).unwrap();

    let source = open_evidence_container(file.path()).expect("Failed to open QCOW2");
    assert_eq!(source.size, 1024 * 1024);

    let mut buf = vec![0u8; 512];
    source
        .vfs
        .as_ref()
        .unwrap()
        .read_volume_at(0, 512)
        .unwrap()
        .copy_to_slice(&mut buf);
    assert_eq!(buf[0], 0x55);
}

#[test]
fn test_qcow2_compressed_cluster_read() {
    let mut file = tempfile::Builder::new()
        .suffix(".qcow2")
        .tempfile()
        .expect("Failed to create temp qcow2");

    let mut header = [0u8; 72];
    header[0..4].copy_from_slice(b"QFI\xfb");
    header[4..8].copy_from_slice(&2u32.to_be_bytes());
    header[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits (64KB)
    header[24..32].copy_from_slice(&(1024u64 * 1024).to_be_bytes());
    header[36..40].copy_from_slice(&1u32.to_be_bytes()); // l1_size
    header[40..48].copy_from_slice(&1024u64.to_be_bytes()); // l1_table_offset
    file.write_all(&header).unwrap();

    file.seek(SeekFrom::Start(1024)).unwrap();
    let l2_offset: u64 = 2048 | (1u64 << 63);
    file.write_all(&l2_offset.to_be_bytes()).unwrap();

    file.seek(SeekFrom::Start(2048)).unwrap();
    let compressed_data_offset: u64 = 131072;
    let l2_entry: u64 =
        (compressed_data_offset & 0x00fffffffffffe00u64) | (1u64 << 63) | (1u64 << 62);
    file.write_all(&l2_entry.to_be_bytes()).unwrap();

    let cluster_payload = vec![0x77u8; 65536];
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&cluster_payload).unwrap();
    let compressed = encoder.finish().unwrap();

    file.seek(SeekFrom::Start(compressed_data_offset)).unwrap();
    file.write_all(&compressed).unwrap();

    let source = open_evidence_container(file.path()).expect("Failed to open QCOW2");
    let read = source
        .vfs
        .as_ref()
        .unwrap()
        .read_volume_at(0, 512)
        .expect("QCOW2 compressed read failed");
    assert_eq!(read[0], 0x77);
    assert_eq!(read[511], 0x77);
}

trait CopyToSlice {
    fn copy_to_slice(self, dest: &mut [u8]);
}
impl CopyToSlice for Vec<u8> {
    fn copy_to_slice(self, dest: &mut [u8]) {
        dest.copy_from_slice(&self);
    }
}
