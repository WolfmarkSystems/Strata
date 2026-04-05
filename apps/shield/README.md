# ForensicSuite

[![Rust](https://img.shields.io/badge/Rust-1.70+-b7410e.svg)](https://www.rust-lang.org)
[![Tauri](https://img.shields.io/badge/Tauri-2.0-ffc107.svg)](https://tauri.app)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build](https://github.com/forensic-suite/actions/workflows/build.yml/badge.svg)](https://github.com/forensic-suite/actions)

A professional-grade digital forensics toolkit inspired by X-Ways Forensics and Magnet AXIOM. Designed for investigators who need fast, scalable evidence processing with complete chain-of-custody tracking.

## Features

### Phase 1: Evidence Container Support
- E01 (EnCase) image mounting and parsing
- VHD and VMDK virtual disk support
- RAW/dd image handling
- AFF4 forensic container format
- Split image assembly

### Phase 2: NTFS Analysis
- Master File Table (MFT) parsing and recovery
- USN Journal analysis for file timeline reconstruction
- Resident and non-resident attribute handling
- Alternate Data Streams (ADS) detection
- Deleted file recovery from MFT indicators

### Phase 3: Carving Engine
- Signature-based file carving
- Header/footer matching for 50+ file types
- Slack space analysis
- Unallocated region scanning
- Confidence scoring for recovered files

### Phase 4: Hash-based Triage
- Multi-algorithm hashing: MD5, SHA1, SHA256
- NSRL (National Software Reference Library) integration
- Custom hashset support (KnownGood, KnownBad)
- Automatic categorization: Known, Unknown, Changed, New
- SQLite-backed hash database for large datasets

### Phase 5: Timeline Generation
- SQLite timeline database
- Artifact-based event reconstruction
- Timestamp normalization (UTC)
- Filter by artifact type, date range, source path

### Phase 6: Virtual File System
- Abstract VFS layer for evidence sources
- Unified file access API across container types
- Memory-mapped I/O for large images
- Lazy loading for performance

### Phase 7: Memory Acquisition & Analysis
- Live RAM acquisition (Windows)
- Memory dump parsing (CrashDump, Hibernation, LiME)
- Process list extraction (pslist)
- DLL enumeration
- Network connection reconstruction
- Strings extraction from memory

### Phase 8: Report Generation
- HTML professional reports with embedded data
- JSONL export for Timesketch integration
- Full case bundle (ZIP) with manifest
- Hash chain-of-custody verification
- Summary statistics and categorization

### Phase 9: Plugin System
- Dynamic plugin loading (.dll/.so)
- Custom parser registration
- Artifact type extension
- Version-controlled plugin API
- Isolated execution for stability

## Screenshots

> *Screenshots coming in v1.1*

## Quick Start

### Prerequisites
- Rust 1.70+
- Windows 10/11 or Linux (for cross-compilation)
- 8GB RAM minimum (16GB recommended for large images)

### Building

```bash
# Clone the repository
git clone https://github.com/forensic-suite/forensic-suite.git
cd forensic-suite

# Build with parallel processing support
cargo build --features parallel

# Run the GUI
cargo run --features parallel --bin forensic-suite-gui

# Or run the CLI
cargo run --features parallel --bin forensic_cli
```

### Basic Workflow

1. **Load Evidence**
   - Click "Load Evidence" or use drag-drop
   - Supports: E01, VHD, VMDK, RAW, folder paths
   - Memory dumps: .dmp, .mem, .vmem, .raw

2. **Configure Hashsets** (optional)
   - Load NSRL for known-good filtering
   - Add custom bad hashsets (HashMyFiles, etc.)

3. **Run Analysis**
   - Enable artifact parsers for timeline generation
   - Enable carving for deleted file recovery
   - Memory analysis for live acquisition/dumps

4. **Generate Report**
   - Export HTML report for stakeholders
   - Export JSONL for Timesketch timeline import
   - Full ZIP bundle for case archival

## Plugin Guide

ForensicSuite supports extensible plugins for custom artifact parsers.

### Writing a Plugin

Create a new Rust crate with cdylib output:

```rust
// src/lib.rs
use forensic_engine::parser::{ArtifactParser, ParsedArtifact, ParserError};
use forensic_engine::plugin::{Plugin, PluginInfo};
use std::path::Path;

const PLUGIN_VERSION: &str = "0.1.0";

#[no_mangle]
pub extern "C" fn plugin_name() -> *const std::ffi::c_char {
    // Return your plugin name as C string
}

#[no_mangle]
pub extern "C" fn plugin_version() -> *const std::ffi::c_char {
    // Return version "0.1.0"
}

#[no_mangle]
pub extern "C" fn plugin_create() -> *mut dyn Plugin {
    // Return Box::new(YourPlugin::new()) as *mut dyn Plugin
}

struct YourParser;

impl ArtifactParser for YourParser {
    fn name(&self) -> &str { "Your Parser" }
    fn artifact_type(&self) -> &str { "your_artifact" }
    fn target_patterns(&self) -> Vec<&str> { vec![".yourext"] }
    
    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        // Your parsing logic
        Ok(vec![])
    }
}
```

### Building

```bash
# Build for Windows
cargo build --release

# Output: target/release/your_plugin.dll

# Build for Linux
cargo build --release
# Output: target/release/libyour_plugin.so
```

### Deployment

Drop compiled plugins into the `plugins/` directory next to the executable:

```
forensic-suite-gui.exe
plugins/
  ├── my_custom_parser.dll
  └── another_plugin.dll
```

Plugins are auto-discovered on startup and their artifacts integrate seamlessly with timeline and reports.

## Hashset Instructions

### NSRL (Known-Good)

Download from NIST: https://www.nist.gov/software-quality-group/national-software-reference-library-nsrl

Convert to SQLite format:
```bash
# NSRL provides RDS files - use the provided tooling or community converters
```

### Custom Hashsets

Create CSV with hash column:
```csv
hash
a1b2c3d4e5f6...
deadbeef1234...
```

Or use existing formats:
- HashMyFiles output
- FTK hash databases
- Custom Python/Rust hash generators

## Performance Notes

### Parallel Processing
Enable the `parallel` feature for multi-threaded processing:
```bash
cargo build --features parallel
```

This enables:
- Parallel file hashing (rayon)
- Concurrent artifact parsing
- Multi-threaded carving

### Large Image Handling
Tested configurations:
| Image Size | Time (parallel) | Memory |
|------------|-----------------|--------|
| 100 GB     | ~45 minutes     | 4 GB   |
| 500 GB     | ~3.5 hours      | 8 GB   |
| 1 TB       | ~8 hours        | 16 GB  |

### Optimization Tips
- Use SSD for temp/working directory
- Increase hash database cache size for repeated scans
- Enable NSRL filtering early to skip known files

## License

Licensed under either of:
- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Roadmap

### v1.1 (Q3 2026)
- [ ] macOS forensic support (APFS parsing)
- [ ] Registry hive analysis (SAM, SECURITY, SOFTWARE)
- [ ] Browser artifact extraction (Chrome, Firefox, Edge)
- [ ] Email parser (PST, OST, MBOX)
- [ ] SQLite forensic carving
- [ ] GUI screenshot integration
- [ ] Plugin marketplace

### v1.2 (Q4 2026)
- [ ] Linux filesystem support (ext4, XFS)
- [ ] Volatility 3 integration for memory
- [ ] YARA rule scanning
- [ ] IOC detection engine
- [ ] Cloud acquisition (OneDrive, Google Drive)
- [ ] Mobile device acquisition (iOS/Android)

### v2.0 (2027)
- [ ] Distributed processing cluster
- [ ] Enterprise case management
- [ ] Multi-user collaboration
- [ ] SQL-based reporting backend

---

**For questions, issues, or contributions, please open an issue on GitHub.**
