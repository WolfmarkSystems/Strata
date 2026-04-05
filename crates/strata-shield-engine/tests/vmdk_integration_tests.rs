use forensic_engine::container::open_evidence_container;
use forensic_engine::container::vmdk::VmdkContainer;
use forensic_engine::container::EvidenceContainerRO;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_vmdk_flat_monolithic_open() {
    let mut file = tempfile::Builder::new().suffix(".vmdk").tempfile().unwrap();
    let extent_file = NamedTempFile::new().unwrap();
    let extent_name = extent_file.path().file_name().unwrap().to_str().unwrap();
    let size_sectors: u64 = 2048; // 1MB

    // Write descriptor-style VMDK
    let descriptor = format!(
        "# Disk DescriptorFile\n\
        version=1\n\
        encoding=\"UTF-8\"\n\
        CID=fffffffe\n\
        parentCID=ffffffff\n\
        createType=\"monolithicFlat\"\n\
        \n\
        # Extent description\n\
        RW {} FLAT \"{}\" 0\n",
        size_sectors, extent_name
    );
    file.write_all(descriptor.as_bytes()).unwrap();

    // Create the extent file filled with zeros
    let mut ext_f = std::fs::File::create(extent_file.path()).unwrap();
    ext_f
        .write_all(&vec![0u8; (size_sectors * 512) as usize])
        .unwrap();

    let container = VmdkContainer::open(file.path()).expect("Failed to open VMDK Flat");
    assert_eq!(container.size, size_sectors * 512);
    assert_eq!(container.description(), "VMDK Virtual Disk");
    assert!(container.verify_chain().unwrap());
}

#[test]
fn test_vmdk_sparse_binary_open() {
    let mut file = tempfile::Builder::new().suffix(".vmdk").tempfile().unwrap();

    // Write Sparse (KDMV) Header (512 bytes)
    let mut header = [0u8; 512];
    header[0..4].copy_from_slice(b"KDMV");
    header[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
    header[8..12].copy_from_slice(&3u32.to_le_bytes()); // flags (validating sparse)
    header[12..20].copy_from_slice(&2048u64.to_le_bytes()); // capacity (1MB)
    header[20..28].copy_from_slice(&128u64.to_le_bytes()); // grainSize (128 sectors = 64KB)
    header[32..40].copy_from_slice(&1u64.to_le_bytes()); // descriptorOffset
    header[40..44].copy_from_slice(&1u32.to_le_bytes()); // descriptorSize
    header[44..48].copy_from_slice(&1u32.to_le_bytes()); // numGTEsPerGTE
    header[64..72].copy_from_slice(&2u64.to_le_bytes()); // gdOffset (sector 2)

    file.write_all(&header).unwrap();

    // Descriptor at sector 1 (offset 512)
    let file_name = file.path().file_name().unwrap().to_str().unwrap();
    let descriptor = format!(
        "# Disk Descriptor\nversion=1\nCID=fffffffe\nparentCID=ffffffff\nRW 2048 SPARSE \"{}\"\n",
        file_name
    );
    let mut desc_buf = [0u8; 512];
    desc_buf[0..descriptor.len()].copy_from_slice(descriptor.as_bytes());
    file.write_all(&desc_buf).unwrap();

    // GD (Grain Directory) at sector 2 (offset 1024)
    // capacity (2048) / grain_size (128) = 16 grains.
    // 16 grains / numGTEsPerGTE (1) = 16 GD entries.
    let mut gd = [0u8; 512];
    // Entry 0 points to sector 3 (Grain Table)
    gd[0..4].copy_from_slice(&3u32.to_le_bytes());
    file.write_all(&gd).unwrap();

    // GT (Grain Table) at sector 3 (offset 1536)
    let mut gt = [0u8; 512];
    // Entry 0 points to sector 4 (Actual data)
    gt[0..4].copy_from_slice(&4u32.to_le_bytes());
    file.write_all(&gt).unwrap();

    // Grain data at sector 4 (offset 2048)
    let grain_data = [0xAAu8; 512];
    file.write_all(&grain_data).unwrap();

    let container = VmdkContainer::open(file.path()).expect("Failed to open VMDK Sparse");
    assert_eq!(container.size, 2048 * 512);
    assert!(container.verify_chain().unwrap());

    // Test read from allocated grain
    let mut buf = [0u8; 512];
    container.read_into(0, &mut buf).expect("Read failed");
    assert_eq!(buf[0], 0xAA);

    let source =
        open_evidence_container(file.path()).expect("Failed to open VMDK via EvidenceSource");
    let read = source
        .vfs
        .as_ref()
        .unwrap()
        .read_volume_at(0, 512)
        .expect("VMDK VFS read failed");
    assert_eq!(read[0], 0xAA);
}
