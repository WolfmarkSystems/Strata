use forensic_engine::container::open_evidence_container;
use std::io::{Seek, SeekFrom, Write};

#[test]
fn test_iso_traversal() {
    let mut file = tempfile::Builder::new()
        .suffix(".iso")
        .tempfile()
        .expect("Failed to create temp iso");

    // ISO 9660 PVD at sector 16 (0x8000)
    let pvd_offset = 16 * 2048;
    file.seek(SeekFrom::Start(pvd_offset)).unwrap();

    let mut pvd = [0u8; 2048];
    pvd[0] = 1; // Type: PVD
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1; // Version

    // Root Directory Entry at 156
    // Len: 34 bytes
    let root_lba: u32 = 17;
    let root_size: u32 = 2048;
    let mut root_entry = [0u8; 34];
    root_entry[0] = 34; // entry len
    root_entry[2..6].copy_from_slice(&root_lba.to_le_bytes());
    root_entry[10..14].copy_from_slice(&root_size.to_le_bytes());
    root_entry[25] = 2; // Flags: directory
    pvd[156..156 + 34].copy_from_slice(&root_entry);

    file.write_all(&pvd).unwrap();

    // Root Directory at sector 17 (0x8800)
    file.seek(SeekFrom::Start(17 * 2048)).unwrap();
    let mut dir_block = [0u8; 2048];

    // Self entry (.)
    dir_block[0] = 34;
    dir_block[2..6].copy_from_slice(&17u32.to_le_bytes());
    dir_block[25] = 2;
    dir_block[32] = 1;
    dir_block[33] = 0; // name .

    // Parent entry (..)
    dir_block[34] = 34;
    dir_block[36..40].copy_from_slice(&17u32.to_le_bytes());
    dir_block[34 + 25] = 2;
    dir_block[34 + 32] = 1;
    dir_block[34 + 33] = 1; // name ..

    // A real file entry
    let file_start = 68;
    let file_name = b"README.TXT";
    let entry_len = 33 + file_name.len();
    dir_block[file_start] = entry_len as u8;
    dir_block[file_start + 2..file_start + 6].copy_from_slice(&18u32.to_le_bytes());
    dir_block[file_start + 10..file_start + 14].copy_from_slice(&5u32.to_le_bytes());
    dir_block[file_start + 25] = 0; // flags: file
    dir_block[file_start + 32] = file_name.len() as u8;
    dir_block[file_start + 33..file_start + 33 + file_name.len()].copy_from_slice(file_name);

    file.write_all(&dir_block).unwrap();

    // File content at sector 18
    file.seek(SeekFrom::Start(18 * 2048)).unwrap();
    file.write_all(b"HELLO").unwrap();

    let source = open_evidence_container(file.path()).expect("Failed to open ISO");
    let entries = source
        .vfs
        .as_ref()
        .unwrap()
        .read_dir(std::path::Path::new("/vol0"))
        .unwrap();

    println!("Entries found: {:?}", entries);
    assert!(entries.iter().any(|e| e.name == "README.TXT"));

    let data = source
        .vfs
        .as_ref()
        .unwrap()
        .open_file(std::path::Path::new("/vol0/README.TXT"))
        .expect("Failed to read ISO file");
    assert_eq!(data, b"HELLO");
}

#[test]
fn test_iso_joliet_name_decode() {
    let mut file = tempfile::Builder::new()
        .suffix(".iso")
        .tempfile()
        .expect("Failed to create temp iso");

    // Primary Volume Descriptor (required baseline)
    file.seek(SeekFrom::Start(16 * 2048)).unwrap();
    let mut pvd = [0u8; 2048];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    let root_lba: u32 = 18;
    let root_size: u32 = 2048;
    let mut root_entry = [0u8; 34];
    root_entry[0] = 34;
    root_entry[2..6].copy_from_slice(&root_lba.to_le_bytes());
    root_entry[10..14].copy_from_slice(&root_size.to_le_bytes());
    root_entry[25] = 2;
    pvd[156..190].copy_from_slice(&root_entry);
    file.write_all(&pvd).unwrap();

    // Supplementary Volume Descriptor with Joliet escape sequence %/E
    file.seek(SeekFrom::Start(17 * 2048)).unwrap();
    let mut svd = [0u8; 2048];
    svd[0] = 2;
    svd[1..6].copy_from_slice(b"CD001");
    svd[6] = 1;
    svd[88..91].copy_from_slice(b"%/E");
    svd[156..190].copy_from_slice(&root_entry);
    file.write_all(&svd).unwrap();

    // Root directory entries
    file.seek(SeekFrom::Start(18 * 2048)).unwrap();
    let mut dir_block = [0u8; 2048];
    dir_block[0] = 34;
    dir_block[2..6].copy_from_slice(&18u32.to_le_bytes());
    dir_block[25] = 2;
    dir_block[32] = 1;
    dir_block[33] = 0;

    dir_block[34] = 34;
    dir_block[36..40].copy_from_slice(&18u32.to_le_bytes());
    dir_block[34 + 25] = 2;
    dir_block[34 + 32] = 1;
    dir_block[34 + 33] = 1;

    // Joliet UCS-2BE name "HELLO.TXT"
    let name_utf16_be: [u8; 18] = [
        0x00, 0x48, 0x00, 0x45, 0x00, 0x4C, 0x00, 0x4C, 0x00, 0x4F, 0x00, 0x2E, 0x00, 0x54, 0x00,
        0x58, 0x00, 0x54,
    ];
    let file_start = 68usize;
    let entry_len = 33 + name_utf16_be.len();
    dir_block[file_start] = entry_len as u8;
    dir_block[file_start + 2..file_start + 6].copy_from_slice(&19u32.to_le_bytes());
    dir_block[file_start + 10..file_start + 14].copy_from_slice(&5u32.to_le_bytes());
    dir_block[file_start + 25] = 0;
    dir_block[file_start + 32] = name_utf16_be.len() as u8;
    dir_block[file_start + 33..file_start + 33 + name_utf16_be.len()]
        .copy_from_slice(&name_utf16_be);
    file.write_all(&dir_block).unwrap();

    // File content at sector 19
    file.seek(SeekFrom::Start(19 * 2048)).unwrap();
    file.write_all(b"WORLD").unwrap();

    let source = open_evidence_container(file.path()).expect("Failed to open Joliet ISO");
    let entries = source
        .vfs
        .as_ref()
        .unwrap()
        .read_dir(std::path::Path::new("/vol0"))
        .unwrap();
    assert!(entries.iter().any(|e| e.name == "HELLO.TXT"));

    let data = source
        .vfs
        .as_ref()
        .unwrap()
        .open_file(std::path::Path::new("/vol0/HELLO.TXT"))
        .expect("Failed to read Joliet file");
    assert_eq!(data, b"WORLD");
}
