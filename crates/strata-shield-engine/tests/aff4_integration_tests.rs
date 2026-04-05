use forensic_engine::container::open_evidence_container;
use std::io::Write;

#[test]
fn test_aff4_open() {
    let file = tempfile::Builder::new()
        .suffix(".aff4")
        .tempfile()
        .expect("Failed to create temp aff4");

    // Create a valid Zip archive as a skeleton AFF4
    let mut zip = zip::ZipWriter::new(std::fs::File::create(file.path()).unwrap());
    zip.start_file(
        "information.turtle",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zip.write_all(b"@prefix aff4: <http://aff4.org/ontology#> .")
        .unwrap();
    zip.start_file("data/stream.bin", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(&[0x11u8, 0x22, 0x33, 0x44, 0x55]).unwrap();
    zip.finish().unwrap();

    let source = open_evidence_container(file.path()).expect("Failed to open AFF4");
    assert_eq!(source.container_type.as_str(), "AFF");

    let bytes = source
        .vfs
        .as_ref()
        .unwrap()
        .read_volume_at(0, 5)
        .expect("AFF4 read failed");
    assert_eq!(bytes, vec![0x11u8, 0x22, 0x33, 0x44, 0x55]);
}
