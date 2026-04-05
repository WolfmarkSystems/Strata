# Rust Build Warning Report - forensic-suite

**Generated:** 2026-02-25  
**Build Command:** `cargo build --workspace`

---

## A) What is Working Now

### Build Status
- **cargo build --workspace**: ✓ SUCCESS (0 errors)
- **Total Warnings**: 271

### Crates
| Crate | Status | Warnings |
|-------|--------|----------|
| forensic_engine | ✓ Builds | ~230 |
| forensic_cli | ✓ Builds | ~41 |

### Working Modules
- All core functionality compiles successfully
- Database operations work
- Container handling (E01) works
- Carving signatures work

---

## B) Warning Summary by Category

| Category | Count | Description |
|----------|-------|-------------|
| unused_variables | 204 | Parameters/variables never used |
| unused_imports | 29 | Imports not referenced in code |
| unused_mut | 8 | Variables marked mutable but never mutated |
| unreachable_patterns | 4 | Match patterns that can never execute |
| unused_assignments | 1 | Value assigned but never read |
| **TOTAL** | **271** | |

### Top 10 Most Frequent Warning Types
1. `unused variable: data` - ~80 occurrences (scaffold parsers)
2. `unused variable: case_id` - ~15 occurrences
3. `unused variable: backup_path` - ~10 occurrences  
4. `unused variable: db_path` - ~8 occurrences
5. `unused variable: path` - ~7 occurrences
6. `unused variable: _` (various) - ~6 occurrences
7. `variable does not need to be mutable` - 8 occurrences

---

## C) Warning Summary by File (Top Offenders)

### Top 30 Files by Warning Count

| Rank | File | Warnings | Warning Types |
|------|------|----------|----------------|
| 1 | classification/mobile.rs | ~15 | unused variables (backup_path), unused imports |
| 2 | classification/archive.rs | ~12 | unused variables (data, entry_name) |
| 3 | classification/audio.rs | ~8 | unused variables (data) |
| 4 | classification/image.rs | ~8 | unused variables (data) |
| 5 | classification/video.rs | ~8 | unused variables (data) |
| 6 | classification/pdf.rs | ~7 | unused variables (data) |
| 7 | classification/office.rs | ~7 | unused variables (data, file_path) |
| 8 | classification/font.rs | ~7 | unused variables (data, glyph_id) |
| 9 | classification/certificate.rs | ~6 | unused variables (cert, data) |
| 10 | classification/dropbox.rs | ~5 | unused variables (config_path, db_path) |
| 11 | classification/jet.rs | ~5 | unused variables (db, record, column) |
| 12 | classification/onedrive.rs | ~5 | unused variables (config_path, db_path, log_path) |
| 13 | classification/registryhive.rs | ~5 | unused variables (data, hive, key_offset) |
| 14 | classification/prefetchdata.rs | ~4 | unused variables (data) |
| 15 | classification/windowsimage.rs | ~6 | unused variables (data, image_index) |
| 16 | case/database.rs | ~12 | unused variables (params_json, regions, since), unused mut |
| 17 | case/exhibit_packet.rs | ~8 | unused variables (case_id, examiner, case_name, classification) |
| 18 | case/replay.rs | ~6 | unused variables (e, id, id_col) |
| 19 | case/mod.rs | ~6 | unused variables (case_id, evidence, format) |
| 20 | classification/wintimeline.rs | ~4 | unused variables (start, end, query, group_id) |
| 21 | classification/etw.rs | ~3 | unused variables (volume, etl_path) |
| 22 | classification/firewall.rs | ~3 | unused variables (log_path) |
| 23 | classification/installer.rs | ~3 | unused variables (log_path) |
| 24 | classification/filetype.rs | ~2 | unreachable patterns |
| 25 | classification/eventlog.rs | ~1 | unreachable pattern |
| 26 | classification/triage.rs | ~1 | unreachable pattern |
| 27 | analysis/hash.rs | ~1 | unused import (ForensicError) |
| 28 | analysis/timeline.rs | ~1 | unused import (ForensicError) |
| 29 | carving/mod.rs | ~3 | unused imports (RegionSet, ScanRegion, HashMap) |
| 30 | classification/errorcodes.rs | ~1 | unused import (ForensicError) |

### forensic_cli Warnings (~41)
- Primarily dead_code and unused imports in CLI parsing modules
- Non-camel case naming for CLI commands

---

## D) Action Plan (Mechanical Fixes Only)

### 1. unused_variables (204 warnings)
**Approach**: Prefix unused parameters with underscore `_`

Files with most impact:
- `classification/*.rs` - Add `_` prefix to unused function params (data, path, db_path, backup_path, etc.)
- `case/database.rs` - Add `_` prefix to params_json, regions, since

**Risk**: LOW - Only adds underscore prefix, no logic changes

### 2. unused_imports (29 warnings)
**Approach**: Remove unused import statements

Files:
- `analysis/hash.rs` - Remove ForensicError import (used in return type)
- `analysis/timeline.rs` - Check if ForensicError is used
- `carving/mod.rs` - Remove RegionSet, ScanRegion, HashMap imports
- `case/repository.rs` - Check if JobParams is used

**Risk**: LOW - Simple removal of unused imports

### 3. unused_mut (8 warnings)
**Approach**: Remove `mut` keyword from variables

Files:
- `case/database.rs` (2 occurrences) - Remove mut from conn
- `case/examiner_presets.rs` - Remove mut from result
- `classification/network.rs` - Remove mut from key_material, last_updated
- `classification/search.rs` - Remove mut from index
- `filesystem/apfs.rs` - Remove mut from reader

**Risk**: LOW - Just removes unnecessary mut keyword

### 4. unreachable_patterns (4 warnings)
**Approach**: Remove unreachable match arms

Files:
- `classification/filetype.rs` - Remove duplicate pattern matches
- `classification/eventlog.rs` - Remove duplicate 4625 pattern
- `classification/triage.rs` - Remove duplicate html/htm pattern

**Risk**: MEDIUM - Need to verify the logic is correct before removing

### 5. unused_assignments (1 warning)
**Approach**: Check if variable is needed

File:
- `classification/lnk.rs` - Check if local_base_path_offset is used

**Risk**: LOW - Verify and either use or prefix with underscore

---

## Summary for Next Cleanup Pass

### Quick Wins (High Count, Low Risk)
1. **Unused variables in classification scaffolds** (~150 warnings)
   - Pattern: `data`, `path`, `backup_path`, `db_path` parameters
   - Fix: Add `_` prefix to each unused parameter
   - Could be automated with a script

2. **Unused imports** (~29 warnings)
   - Mostly ForensicError that was removed but is still needed
   - Need to carefully check each file

3. **Unused mut** (~8 warnings)
   - Simple mechanical fix - remove mut keyword

### Requires Review (Medium Risk)
1. **unreachable_patterns** (~4 warnings)
   - Need to understand match logic before removing
   - Could be dead code or logic error

2. **Some case/ module stubs**
   - May need actual implementation vs just stub removal

---

## Files Created
- `build_warn_full.txt` - Full cargo build output
- `WARNINGS_REPORT.md` - This report

**Report Location**: `D:\forensic-suite\WARNINGS_REPORT.md`
