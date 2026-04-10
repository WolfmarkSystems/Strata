use forensic_engine::container::open_evidence_container;
use forensic_engine::container::vhd::{VhdContainer, VhdType, VhdxContainer};
use forensic_engine::container::EvidenceContainerRO;
use std::io::Write;

#[test]
fn test_vhd_fixed_open() {
    let mut file = tempfile::Builder::new().suffix(".vhd").tempfile().unwrap();
    let size: u64 = 1024 * 1024; // 1MB

    // Fill with some data
    let zeroes = vec![0u8; size as usize];
    file.write_all(&zeroes).unwrap();

    // Create 512-byte footer at the end
    let mut footer = [0u8; 512];
    footer[0..8].copy_from_slice(b"conectix");
    footer[12..16].copy_from_slice(&0x00010000u32.to_be_bytes()); // version
    footer[16..24].copy_from_slice(&0xFFFFFFFFFFFFFFFFu64.to_be_bytes()); // data_offset
    footer[48..56].copy_from_slice(&size.to_be_bytes()); // current_size
    footer[60..64].copy_from_slice(&2u32.to_be_bytes()); // disk_type: Fixed

    file.write_all(&footer).unwrap();

    let container = VhdContainer::open(file.path()).expect("Failed to open VHD Fixed");
    assert_eq!(container.size, size);
    assert!(matches!(container.vhd_type, VhdType::Fixed));
    assert_eq!(container.description(), "VHD Fixed Disk");

    // Test read
    let mut buf = [0u8; 1024];
    container.read_into(0, &mut buf).expect("Read failed");
    assert_eq!(buf, [0u8; 1024]);

    let source =
        open_evidence_container(file.path()).expect("Failed to open VHD via EvidenceSource");
    assert_eq!(source.container_type.as_str(), "VHD");
    let vols = source.vfs.as_ref().unwrap().get_volumes();
    assert!(!vols.is_empty());
}

#[test]
fn test_vhd_dynamic_open() {
    let mut file = tempfile::Builder::new().suffix(".vhd").tempfile().unwrap();
    let virtual_size: u64 = 10 * 1024 * 1024; // 10MB

    // Footer at offset 0
    let mut footer = [0u8; 512];
    footer[0..8].copy_from_slice(b"conectix");
    footer[16..24].copy_from_slice(&512u64.to_be_bytes()); // data_offset -> Dynamic Header
    footer[48..56].copy_from_slice(&virtual_size.to_be_bytes()); // current_size
    footer[60..64].copy_from_slice(&3u32.to_be_bytes()); // disk_type: Dynamic
    file.write_all(&footer).unwrap();

    // Dynamic Header at offset 512
    let mut dyn_header = [0u8; 1024];
    dyn_header[0..8].copy_from_slice(b"cxsparse");
    dyn_header[16..24].copy_from_slice(&1536u64.to_be_bytes()); // table_offset -> BAT
    dyn_header[28..32].copy_from_slice(&10u32.to_be_bytes()); // max_table_entries
    dyn_header[32..36].copy_from_slice(&2097152u32.to_be_bytes()); // block_size (2MB)
    file.write_all(&dyn_header).unwrap();

    // BAT at offset 1536 (10 entries * 4 bytes = 40 bytes)
    let bat = [0xFFu8; 512]; // All unallocated (0xFFFFFFFF)
    file.write_all(&bat).unwrap();

    let container = VhdContainer::open(file.path()).expect("Failed to open VHD Dynamic");
    assert_eq!(container.size, virtual_size);
    assert!(matches!(container.vhd_type, VhdType::Dynamic));
    assert_eq!(container.description(), "VHD Dynamic Disk");

    // Read from unallocated block
    let mut buf = [0u8; 1024];
    container.read_into(0, &mut buf).expect("Read failed");
    assert_eq!(buf, [0u8; 1024]);
}

#[test]
fn test_vhdx_basic_open() {
    let mut file = tempfile::Builder::new().suffix(".vhdx").tempfile().unwrap();

    // Write VHDX magic
    file.write_all(b"vhdxfile").unwrap();
    // VHDX open will fail later (it scans 192KB region table),
    // but we can at least check magic detection if we provide enough padding
    let padding = vec![0u8; 1024 * 1024];
    file.write_all(&padding).unwrap();

    // VhdxContainer::open will fail because we didn't write a real region table,
    // but the error should be from missing region table, not "InvalidImageFormat"
    let result = VhdxContainer::open(file.path());
    if let Err(e) = result {
        let msg = e.to_string();
        // Should fail with VHDX missing/unsupported region table instead of magic failure
        assert!(
            msg.contains("VHDX") || msg.contains("Region Table"),
            "Unexpected error: {}",
            msg
        );
    }
}
