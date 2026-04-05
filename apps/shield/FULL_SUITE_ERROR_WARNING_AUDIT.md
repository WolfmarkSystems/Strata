# Forensic Suite - Complete Error/Warning/Audit Report

**Generated:** 2026-03-22  
**Repository Root:** D:\forensic-suite  
**GUI Root:** D:\forensic-suite\gui-tauri

---

## SECTION A - Executive Summary

| Category | Count |
|----------|-------|
| Build Errors | 1 (test compilation) |
| Test Failures | 1 |
| Compiler Warnings | 18 |
| Clippy Errors (strict) | 25+ |
| Runtime/Config Issues | 3 |
| Feature Gaps/Stubs | 12 |
| Architectural Risks | 4 |

**Verdict:** UNSTABLE (due to test failures and multiple stubs)

---

## SECTION B - Build and Test Results

### B.1 - Debug Build
- Command: cargo build --workspace
- Result: COMPILED WITH WARNINGS
- Duration: ~85 seconds
- forensic_engine: 16 warnings
- stratashield: 2 warnings

### B.2 - Release Build
- Command: cargo build --workspace --release
- Result: TIMEOUT (exceeded 5 minutes)

### B.3 - Test Build
- Command: cargo test --workspace
- Result: FAILED
- error[E0063]: missing field blake3 in HashResults
- Location: engine/src/tests/mod.rs:13

### B.4 - Clippy Check
- Command: cargo clippy --workspace -- -D warnings
- Result: FAILED - All warnings promoted to errors
- 3 structs lack Default impl
- clippy::type-complexity, needless_lifetimes, unnecessary_lazy_evaluations

### B.5 - Frontend Build
- Command: npm run build (in gui-tauri)
- Result: FAILED - esbuild platform mismatch

### B.6 - CLI Help
- Command: cargo run -p forensic_cli -- --help
- Result: SUCCESS (exit code 0)

---

## SECTION C - Claim Verification

### C.1 - Container Formats (8 declared, only 3 functional)
**Status:** VERIFIED (clarified)

Evidence: engine/src/container/mod.rs:131-149

| Format | VFS | Data Reading | Status |
|--------|-----|--------------|--------|
| RAW/DD | Yes | Yes | COMPLETE |
| E01 | Yes | Yes | COMPLETE |
| Directory | Yes | Yes | COMPLETE |
| VHD | Yes | Partial | PARTIAL |
| VHDX | No | Error | STUB |
| VMDK | No | Partial | STUB |
| AFF4 | No | Zeros | STUB |
| LUKS | No | Zeros | STUB |
| QCOW2 | No | Zeros | STUB |
| VDI | No | Zeros | STUB |
| LVM | No | Zeros | STUB |
| L01 | No | Zeros | STUB |
| FileVault | No | Zeros | STUB |
| Storage Spaces | No | Zeros | STUB |

### C.2 - Silent VHD/VMDK Failures
**Status:** PARTIAL
- VHDX: Explicit error message
- VMDK: Silent failure (returns None VFS)

### C.3 - VFS Not Utilized
**Status:** FALSE (refuted)
- VFS IS used for Directory, E01, Raw, VHD
- NOT used for AFF, VMDK, VHDX

### C.4 - CLI Manual Parsing (38 of 40)
**Status:** VERIFIED
- All commands use manual string matching
- No clap derive macros

### C.5 - Hidden GUI Issues
**Status:** VERIFIED
1. Sidecar binary missing (src-tauri/bin/ empty)
2. esbuild platform mismatch
3. Tauri config references sidecar

### C.6 - CLI/GUI Mismatch
**Status:** PARTIAL
- Only 3 of 40+ commands integrated

---

## SECTION D - Detailed Issues

### HIGH SEVERITY

| # | Issue | File | Line | Confidence |
|---|-------|------|------|------------|
| 1 | Test fails - missing blake3 | tests/mod.rs | 13 | HIGH |
| 2 | 8 containers return zeros | container/*.rs | multiple | HIGH |
| 3 | Sidecar binary missing | gui-tauri/src-tauri/bin/ | - | HIGH |
| 4 | VMDK/AFF4 no VFS | container/mod.rs | 148 | HIGH |

### MEDIUM SEVERITY

| # | Issue | File | Line | Confidence |
|---|-------|------|------|------------|
| 5 | VHDX not implemented | vhd.rs | 17-21 | HIGH |
| 6 | esbuild mismatch | gui-tauri | - | HIGH |
| 7 | CLI manual parsing | main.rs | all | HIGH |
| 8 | Missing Default impl | analysis/*.rs | multiple | HIGH |

### LOW SEVERITY (Code Health)

| # | Issue | File | Count |
|---|-------|------|-------|
| 9 | Unused imports | vmdk.rs, knowledgec.rs | 3 |
| 10 | Unused offset var | container/*.rs | 8 |
| 11 | Unused path var | vhd.rs | 1 |
| 12 | Unused blake3 var | hashing/mod.rs | 1 |
| 13 | Unnecessary mut | scripting/mod.rs | 1 |
| 14 | Dead code CHUNK_SIZE | ntfs.rs | 1 |
| 15 | Unused Tauri vars | lib.rs | 2 |
| 16 | Hardcoded Windows paths | virtualization/mod.rs | multiple |

---

## SECTION E - Warning Inventory

### Compiler Warnings (18 total)
- container/vmdk.rs:2 - unused imports
- parsers/ios/knowledgec.rs:2 - unused imports
- 8 files - unused offset variable
- container/vhd.rs:17 - unused path
- hashing/mod.rs:490 - unused blake3
- scripting/mod.rs:11 - unnecessary mut
- scripting/mod.rs:21 - unused ext_str
- filesystem/ntfs.rs:696 - dead code
- gui/src-tauri/src/lib.rs:1819,1821 - unused vars

### Clippy Strict Issues (6)
- analysis/credentials.rs:7 - new_without_default
- analysis/sqlite_viewer.rs:7 - new_without_default
- analysis/yara.rs:6 - new_without_default
- carving/mod.rs:391 - type_complexity
- classification/jumplist.rs:715 - needless_lifetimes
- classification/prefetch.rs:392 - unnecessary_lazy_evaluations

---

## SECTION F - Feature Gap / Stub Inventory

### Container Formats (14 total)

| Format | VFS | read_into | Functional |
|--------|-----|-----------|------------|
| RAW/DD | Yes | Yes | Yes |
| E01 | Yes | Yes | Yes |
| Directory | Yes | Yes | Yes |
| VHD | Yes | Partial | Partial |
| VHDX | No | Error | No |
| VMDK | No | Partial | No |
| AFF4 | No | Zeros | No |
| LUKS | No | Zeros | No |
| QCOW2 | No | Zeros | No |
| VDI | No | Zeros | No |
| LVM | No | Zeros | No |
| L01 | No | Zeros | No |
| FileVault | No | Zeros | No |
| Storage Spaces | No | Zeros | No |

### GUI Integration

Only 3 commands integrated: capabilities, doctor, smoke-test

---

## SECTION G - Top 10 Issues by Impact

| Rank | Issue | Severity | Impact | Effort |
|------|-------|----------|--------|--------|
| 1 | Test compilation failure | HIGH | Blocks CI | LOW |
| 2 | 8 container stubs | HIGH | Data loss | HIGH |
| 3 | VMDK/AFF4 no VFS | HIGH | Silent failures | HIGH |
| 4 | Sidecar binary missing | HIGH | GUI broken | LOW |
| 5 | VHDX not implemented | MEDIUM | Missing | HIGH |
| 6 | esbuild mismatch | MEDIUM | Cannot rebuild | LOW |
| 7 | 18 unused warnings | LOW | Cleanliness | LOW |
| 8 | CLI manual parsing | MEDIUM | Tech debt | HIGH |
| 9 | Hardcoded Windows paths | LOW | Portability | LOW |
| 10 | Clippy strict failures | MEDIUM | Blocks CI | MEDIUM |

---

## SECTION H - Safe Next Steps

### Do First (Safe Fixes)

1. Fix test - add blake3 field to HashResults (tests/mod.rs:13)
2. Remove unused imports (vmdk.rs, knowledgec.rs)
3. Prefix unused variables with underscore
4. Run sync-sidecar.ps1 to copy CLI binary
5. Rebuild node_modules to fix esbuild

### Do NOT Change Yet

1. Architecture refactoring
2. Container implementations
3. VFS abstraction
4. GUI state management
5. Test suite expansion

---

**Report Generated:** 2026-03-22
**Confidence:** HIGH for verified claims, MEDIUM for partial