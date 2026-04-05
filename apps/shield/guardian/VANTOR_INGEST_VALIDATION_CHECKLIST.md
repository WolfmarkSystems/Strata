# Strata Ingest Validation Checklist

**Document Type:** Evidence Ingest Testing Checklist  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Purpose:** Systematic validation of evidence processing from container open to GUI display

---

## Purpose

This checklist validates that evidence processing works correctly at each layer, from container open through filesystem enumeration to artifact extraction and GUI display. Strata uses this to verify both real evidence and synthetic test cases.

---

## Pre-Test Setup

Before beginning ingest validation:

1. **Identify the test case type:** Real evidence, synthetic image, or edge case
2. **Document expected outcomes:** What should succeed, what should fail gracefully
3. **Note known gaps:** Reference KNOWN_GAPS.md for expected limitations
4. **Clear old state:** Ensure no stale data from previous tests

---

## Layer 1: Container Opened

### 1.1: Container Type Recognition
**Check:** Does the system correctly identify the container type?  
**Command:** `forensic_cli open-evidence <path> --json-result <temp>`  
**Expected:** `container_type` matches actual type (raw, e01, directory)  
**Pass Criteria:** Container type field matches reality  
**On Fail:** Check container detection code, verify file header parsing

### 1.2: Container Opens Without Panic
**Check:** Does container open complete without crash?  
**Expected:** Command returns envelope with status "ok" or "warn", not error  
**Pass Criteria:** No panic, no segfault, exit code 0  
**On Fail:** Document crash location, flag as critical bug

### 1.3: Container Size Reported Correctly
**Check:** Does reported container size match actual file size?  
**Expected:** `container_size` field in envelope matches `stat` output  
**Pass Criteria:** Sizes match within 1MB tolerance for sparse files  
**On Fail:** Document size discrepancy, check size calculation code

### 1.4: Container Hash Verification
**Check:** Are evidence hashes computed and recorded?  
**Expected:** `hash` field contains md5, sha1, sha256  
**Pass Criteria:** All three hashes present, non-zero  
**On Fail:** Check hash computation code, verify hash function calls

---

## Layer 2: Partition/Volume Discovered

### 2.1: Partition Table Parsed
**Check:** Are partitions/volumes detected?  
**Expected:** `volumes` or `partitions` array in output  
**Pass Criteria:** Array present, entries match expected partition count  
**On Fail:** Check partition detection code, verify GPT/MBR parsing

### 2.2: Partition Offset Accuracy
**Check:** Do partition offsets match actual disk layout?  
**Expected:** Offset matches expected value for test image  
**Pass Criteria:** Offset within expected range (±sector_size tolerance)  
**On Fail:** Document offset discrepancy

### 2.3: Partition Type Recognition
**Check:** Is partition type (NTFS, FAT32, etc.) correctly identified?  
**Expected:** `fs_type` or similar field shows filesystem type  
**Pass Criteria:** Matches filesystem actually present in partition  
**On Fail:** Check filesystem signature detection code

### 2.4: Encrypted Volume Detection
**Check:** Are encrypted volumes (BitLocker) detected?  
**Expected:** Encryption status flagged if present  
**Pass Criteria:** BitLocker detected and marked, or documented as limitation  
**On Fail:** Document per KNOWN_GAPS.md section B.1

---

## Layer 3: Filesystem Detected

### 3.1: Filesystem Signature Verification
**Check:** Does detected filesystem match actual filesystem?  
**Command:** `forensic_cli doctor` or `smoke-test`  
**Expected:** Detected filesystem type is correct  
**Pass Criteria:** Correct type reported  
**On Fail:** Check filesystem detection heuristics

### 3.2: Filesystem Open Success
**Check:** Does filesystem open without error?  
**Expected:** No filesystem-level errors in envelope  
**Pass Criteria:** Filesystem accessible, ready for enumeration  
**On Fail:** Document filesystem open failure, check VFS implementation

### 3.3: Filesystem Metadata Parsed
**Check:** Are filesystem metadata fields populated?  
**Expected:** Fields like `cluster_size`, `total_clusters`, `free_clusters` present  
**Pass Criteria:** Metadata fields present (may be partial for some filesystems)  
**On Fail:** Document missing metadata fields

---

## Layer 4: Enumeration Succeeded

### 4.1: File Count Reasonable
**Check:** Does file enumeration count match expected scale?  
**Command:** `forensic_cli filetable <evidence> --json-result <temp>`  
**Expected:** File count plausible for evidence size and type  
**Pass Criteria:** Count within reasonable range (not 0 for populated disk, not millions for small image)  
**On Fail:** Flag as enumeration failure, check filesystem enumeration code

### 4.2: Enumeration Speed Plausible
**Check:** Is enumeration time reasonable for evidence size?  
**Expected:** `elapsed_ms` plausible (not <100ms for GB-scale evidence)  
**Pass Criteria:** Time proportional to evidence size  
**On Fail:** Flag as potential instant-enumeration pattern per RUNTIME_FAILURE_PATTERNS.md

### 4.3: Directory Structure Preserved
**Check:** Are directories created with correct hierarchy?  
**Expected:** Directory entries have `isDirectory: true`, correct paths  
**Pass Criteria:** Directory structure matches expected layout  
**On Fail:** Document directory structure issues

### 4.4: Empty Files Handled
**Check:** Are empty files enumerated correctly?  
**Expected:** Empty files appear with size 0, not omitted  
**Pass Criteria:** Zero-length files present in enumeration  
**On Fail:** Document empty file handling

---

## Layer 5: Indexing Succeeded

### 5.1: Parser Registration Verified
**Check:** Are parsers registered for expected file types?  
**Command:** `forensic_cli capabilities --json-result <temp>`  
**Expected:** Parser list includes expected artifact parsers  
**Pass Criteria:** Relevant parsers present and marked "implemented"  
**On Fail:** Check parser registration in `parser.rs`

### 5.2: File-Parser Matching
**Check:** Are files matched to appropriate parsers?  
**Expected:** Files match `target_patterns()` for relevant parsers  
**Pass Criteria:** Matched file count > 0 for test evidence  
**On Fail:** Check `ParserRegistry::find_matching_parsers`

### 5.3: Parse Execution Confirmed
**Check:** Did parsers actually execute?  
**Expected:** Parser execution logged or traceable  
**Pass Criteria:** Evidence of parser runs in logs or output  
**On Fail:** Check parser invocation code in EvidenceAnalyzer

### 5.4: Artifact Count Reasonable
**Check:** Does artifact count match expected scale?  
**Expected:** Artifact count proportional to evidence complexity  
**Pass Criteria:** Not 0 for evidence with known artifacts, not implausibly high  
**On Fail:** Flag per RUNTIME_FAILURE_PATTERNS.md Pattern 1

---

## Layer 6: Tree Populated

### 6.1: Tree Structure Present
**Check:** Does evidence tree show populated structure?  
**Command:** GUI tree view or `load_evidence_and_build_tree`  
**Expected:** Non-empty tree with directory hierarchy  
**Pass Criteria:** Tree has root, branches, and leaf nodes  
**On Fail:** Check tree building code

### 6.2: Tree Depth Appropriate
**Check:** Does tree depth match expected directory depth?  
**Expected:** Depth proportional to evidence complexity  
**Pass Criteria:** Maximum depth reasonable for test evidence  
**On Fail:** Document depth discrepancy

### 6.3: Empty Tree Warning
**Check:** If tree is empty, is warning shown?  
**Expected:** Warning or status indicating empty tree  
**Pass Criteria:** Non-empty tree OR warning present  
**On Fail:** Flag per RUNTIME_FAILURE_PATTERNS.md Pattern 3

---

## Layer 7: Filetable Populated

### 7.1: Filetable Entry Count
**Check:** Does filetable entry count match enumeration count?  
**Command:** `forensic_cli filetable <evidence> --json-result <temp>`  
**Expected:** `total_count` matches enumeration  
**Pass Criteria:** Counts within small tolerance (1-2% for reserved system files)  
**On Fail:** Document count discrepancy

### 7.2: File Metadata Accuracy
**Check:** Are file metadata fields accurate?  
**Expected:** Size, timestamps, attributes match actual files  
**Pass Criteria:** Metadata matches `stat` output for sampled files  
**On Fail:** Document metadata accuracy issues

### 7.3: Path Correctness
**Check:** Are file paths correct and absolute?  
**Expected:** Paths start with evidence root, not working directory  
**Pass Criteria:** All paths reference evidence container  
**On Fail:** Flag as path provenance issue

### 7.4: Pagination Working
**Check:** Does cursor-based pagination work for large filetable?  
**Expected:** Subsequent pages return different entries  
**Pass Criteria:** Pagination tokens valid, no duplicates across pages  
**On Fail:** Check pagination implementation

---

## Layer 8: Artifact/Timeline Population

### 8.1: Timeline Entry Count
**Check:** Does timeline entry count match parser output?  
**Command:** `forensic_cli timeline --case <case> --json-result <temp>`  
**Expected:** `total_count` matches parsed artifacts  
**Pass Criteria:** Timeline count roughly equals parsed artifact count  
**On Fail:** Document timeline population discrepancy

### 8.2: Artifact Type Distribution
**Check:** Does artifact type distribution match evidence content?  
**Expected:** Browser artifacts in browser cache evidence, registry artifacts in registry hives, etc.  
**Pass Criteria:** Expected artifact types present, unexpected types explained  
**On Fail:** Document unexpected type distribution

### 8.3: Zero-Artifact Result Handling
**Check:** If no artifacts found, is result labeled correctly?  
**Expected:** `warning` field explains empty result OR evidence genuinely has no artifacts  
**Pass Criteria:** Empty result has warning OR verified empty evidence  
**On Fail:** Flag per TRUTHFULNESS_RULES.md Rule 4

### 8.4: Placeholder Row Check
**Check:** Are there any placeholder, TBD, or STUB rows?  
**Expected:** No placeholder content in timeline/artifacts  
**Pass Criteria:** Zero placeholder strings in data  
**On Fail:** Flag as evidence fabrication per TRUTHFULNESS_RULES.md

---

## Layer 9: GUI Status Correctness

### 9.1: Evidence Loaded Indicator
**Check:** Does GUI show evidence as loaded?  
**Expected:** Status indicator shows "loaded" or similar  
**Pass Criteria:** Visual confirmation of loaded evidence  
**On Fail:** Check GUI status binding

### 9.2: File Count Display
**Check:** Does GUI file count match filetable count?  
**Expected:** UI shows correct enumeration count  
**Pass Criteria:** GUI count matches CLI count  
**On Fail:** Document GUI/CLI count mismatch

### 9.3: Artifact Count Display
**Check:** Does GUI artifact count match timeline count?  
**Expected:** UI shows correct artifact count  
**Pass Criteria:** GUI count matches CLI count  
**On Fail:** Document GUI/CLI count mismatch

### 9.4: Warning Visibility
**Check:** Are warnings visible in GUI?  
**Expected:** Any CLI warnings surfaced in UI  
**Pass Criteria:** Warning text or icon displayed  
**On Fail:** Flag per TRUTHFULNESS_RULES.md Rule 7

### 9.5: Partial Result Labeling
**Check:** If results are partial, is this labeled?  
**Expected:** Partial status clearly indicated  
**Pass Criteria:** "Partial" or "Incomplete" label visible  
**On Fail:** Flag per TRUTHFULNESS_RULES.md Rule 9

---

## Special Test Cases

### Test Case A: E01 Real Image
**Purpose:** Validate EnCase format handling with real evidence

| Check | Expected | Pass/Fail |
|-------|----------|-----------|
| Container opens | E01 type recognized | |
| Evidence hashes | SHA256 matches expected | |
| Enumeration | Files recovered | |
| Artifacts | Expected artifact types found | |

---

### Test Case B: Minimal Synthetic Image
**Purpose:** Validate edge case with minimal test data

| Check | Expected | Pass/Fail |
|-------|----------|-----------|
| Container opens | RAW type recognized | |
| Files enumerated | 1-10 test files | |
| Parsers run | Targeted parser matches test files | |
| Artifacts extracted | Known fixture artifacts | |

---

### Test Case C: APFS Partial Validation
**Purpose:** Validate APFS handling with known limitations

| Check | Expected | Pass/Fail |
|-------|----------|-----------|
| Container opens | APFS recognized | |
| Enumeration count | May be partial per KNOWN_GAPS.md | |
| Warning present | Partial enumeration warning | |
| Files present | At least some files enumerated | |

---

### Test Case D: XFS Partial Validation
**Purpose:** Validate XFS handling with known limitations

| Check | Expected | Pass/Fail |
|-------|----------|-----------|
| Container opens | XFS recognized | |
| Enumeration count | May be partial per KNOWN_GAPS.md | |
| Warning present | Partial enumeration warning | |
| Files present | At least some files enumerated | |

---

### Test Case E: Zero-Row Result (Empty Evidence)
**Purpose:** Validate truthful handling of empty results

| Check | Expected | Pass/Fail |
|-------|----------|-----------|
| Container opens | Opens successfully | |
| Enumeration | 0 files | |
| Timeline | 0 entries | |
| Warning present | Explains empty result | |
| UI display | Shows "0" not "Analysis Complete" | |

---

### Test Case F: Placeholder Row Detection
**Purpose:** Verify no synthetic placeholders in results

| Check | Expected | Pass/Fail |
|-------|----------|-----------|
| No TBD strings | Search results for "TBD" | |
| No TODO strings | Search results for "TODO" | |
| No STUB strings | Search results for "STUB" | |
| No Default artifacts | No `Default::default()` output | |

---

### Test Case G: GUI "Indexed/Completed" State Verification
**Purpose:** Validate GUI progress states are accurate

| Check | Expected | Pass/Fail |
|-------|----------|-----------|
| Loading state | Shown during processing | |
| Progress updates | Count increases as processed | |
| Completion state | Only shown when actually complete | |
| Error state | Shown on failure, not ignored | |

---

## Ingest Validation Summary

| Layer | Checks | Passed | Failed | Skipped |
|-------|--------|--------|--------|---------|
| 1. Container | 4 | | | |
| 2. Partition | 4 | | | |
| 3. Filesystem | 3 | | | |
| 4. Enumeration | 4 | | | |
| 5. Indexing | 4 | | | |
| 6. Tree | 3 | | | |
| 7. Filetable | 4 | | | |
| 8. Artifacts | 4 | | | |
| 9. GUI | 5 | | | |
| Special Cases | 7 | | | |
| **Total** | **42** | | | |

### Overall Ingest Status
- [ ] **PASS** — All critical layers functional, no truthfulness violations
- [ ] **PARTIAL** — Known gaps present, all warnings surfaced
- [ ] **FAIL** — Critical layer failures or truthfulness violations

### Test Evidence
Evidence Used: _________________  
Date: _________________  
Tester: Strata  
Status: _________________

---

## Document Maintenance

Update this checklist when:
- New ingest layers are added
- Known gaps are resolved
- New test cases are discovered

Location: `D:\forensic-suite\guardian\STRATA_INGEST_VALIDATION_CHECKLIST.md`
