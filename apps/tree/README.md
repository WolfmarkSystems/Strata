# Strata Tree
### Forensic Analysis Workbench — v0.3.0

Strata Tree is a Rust/egui forensic workbench for examiners who need local, repeatable evidence analysis without cloud services. It exists to give practitioners a single desktop tool for opening disk evidence, parsing high-value Windows artifacts, building timelines, and exporting case output in formats that are easy to review and defend.

## What It Does
- Opens E01/EWF forensic containers
- NTFS file system analysis
- Registry hive viewer (SOFTWARE, SYSTEM, NTUSER.DAT)
- Windows event log parser (EVTX) with high-value event ID focus
- Prefetch parser (versions 17, 23, 26, 30) with MAM decompression support
- LNK parser aligned to MS-SHLLINK fields (target path, drive type, machine ID)
- Browser history parsing for Chrome, Edge, and Firefox, including downloads
- Shellbag parsing (BagMRU walk and path reconstruction)
- File carving with 26 signatures in a background worker
- Hash set matching workflows for NSRL, KnownBad, and KnownGood sets
- Full-text content indexing and search via Tantivy
- Timeline generation with automatic 5-minute case auto-save
- Court-oriented HTML and CSV export output
- SHA-256 chained audit log integrity checks
- Local/offline Forge integration support

## Platform Support
| Platform | Status |
|---|---|
| Windows x86_64 | Current release |
| macOS aarch64 | In development |
| macOS x86_64 | In development |
| Linux x86_64 | Planned |

## Download
Download the latest release binary from the repository Releases page:

https://github.com/wolfmark-systems/strata/releases

A free tier is available. Pro licensing unlocks additional features.

## Quick Start
1. Download the latest `strata-tree` release archive from the Releases page.
2. Extract it to a local folder you control.
3. Run `strata-tree.exe`.
4. Create a new case when prompted.
5. Open evidence and select your E01/EWF file.
6. Wait for indexing to complete.
7. Use the left navigation to move between Explorer, Registry, Timeline, and other views.
8. Select files to inspect metadata/hex/text/image previews.
9. Export results with CSV/HTML report actions.

## Free vs Pro
| Capability | Free Tier | Pro / Trial |
|---|---|---|
| Hex editor | Yes (read-only scope) | Yes |
| CSV export | Yes | Yes |
| Registry viewer | No | Yes |
| Timeline analysis | No | Yes |
| File carving | No | Yes |
| Hash sets | No | Yes |
| Content search indexing | No | Yes |
| HTML report export | No | Yes |
| Plugins panel | No | Yes (tier dependent) |

To request a trial, copy your machine ID from Settings > License and email it to `wolfmarksystems@proton.me`.

## Built With
- Rust (2021 edition)
- egui / eframe UI framework
- No cloud dependencies
- No telemetry
- Air-gapped by design

## Background
This project was built by a working forensic practitioner who wanted a local-first tool that emphasizes evidence handling, artifact visibility, and reproducible output. The design choices favor straightforward workflows and explicit technical behavior over opaque automation. If something is limited, it is documented directly.

## Contributing
- Bug reports: open a GitHub issue
- Feature requests: open a GitHub issue and label it `enhancement`
- Code pull requests are not being accepted at this time (solo development)

## License
Strata Tree source is proprietary.

A free-tier binary is available for community use, and Pro licensing is available for expanded feature access.
