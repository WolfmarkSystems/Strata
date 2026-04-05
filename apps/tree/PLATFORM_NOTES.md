# Strata Tree Platform Notes

## Feature Parity
- Windows, macOS, and Linux use the same Rust/egui codepaths for case handling, indexing, timeline, registry, gallery, hashing, and export.
- Case format (`.vtp` SQLite) is portable across all supported platforms.
- Cross-platform CI builds are defined in `.github/workflows/tree-build.yml` for Windows, macOS, and Linux.

## Physical Disk and Evidence Access
- Default workflow is read-only analysis of evidence files (E01/RAW/VHD/VMDK) and mounted directories.
- Direct physical disk access may require elevated permissions depending on OS and workstation policy.
- Evidence sources are never written by Tree; output paths are guarded to block writes under evidence paths.

## Windows PE/FE Notes
- Tree is a standalone native executable and does not require a browser runtime.
- In PE/FE environments, ensure required storage drivers are loaded and target media is visible before opening evidence.
- Plugin and report paths should point to writable external media (for example, examiner USB workspace), not evidence media.

## Known Platform Limitations
- Code signing is not applied in-repo and depends on external certificate infrastructure.
- Installer packaging is environment/tooling dependent (NSIS/WiX availability on build host).
- Some plugin binaries may be platform-specific and must be built for the target OS/arch.
- Full GUI smoke testing still requires interactive execution on each target OS (not fully automatable via headless CI).

## Operational Guidance
- Use release builds for examiner workflows (`cargo build -p strata-tree --release`).
- Keep timestamps in UTC throughout exports and audit trails.
- Validate `.vtp` integrity hash and audit chain before report generation.
