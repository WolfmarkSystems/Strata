// Sprint 9 P3 verification: confirm an archive path is classified as
// `ArchiveZip` / `ArchiveTar` and (optionally, with `--unpack`) start
// the extraction so we can observe layered scratch growth.

use std::path::Path;
use strata_fs::container::{ContainerType, EvidenceSource, IngestRegistry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path_arg = args.next().ok_or("usage: p3_archive_check <path> [--unpack]")?;
    let do_unpack = args.any(|a| a == "--unpack");

    let path = Path::new(&path_arg);
    let descriptor = IngestRegistry::detect(path);
    println!(
        "[P3] detected: container={:?} adapter={}",
        descriptor.container_type, descriptor.parser_adapter
    );

    if !matches!(
        descriptor.container_type,
        ContainerType::ArchiveZip | ContainerType::ArchiveTar
    ) {
        eprintln!("[P3] not an archive — exiting after detection");
        return Ok(());
    }

    if !do_unpack {
        println!("[P3] detection-only mode (pass --unpack to extract). exiting.");
        return Ok(());
    }

    println!("[P3] running EvidenceSource::open (full extraction) ...");
    let started = std::time::Instant::now();
    let src = EvidenceSource::open(path)?;
    println!(
        "[P3] EvidenceSource opened in {:?}: container={} size={}",
        started.elapsed(),
        src.container_type.as_str(),
        src.size
    );
    Ok(())
}
