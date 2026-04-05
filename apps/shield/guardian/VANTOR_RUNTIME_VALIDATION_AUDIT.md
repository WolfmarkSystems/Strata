# Strata Shield - Runtime Validation Audit
## AUDIT-20260324-002

### A. Metadata
- **Audit Date**: 2026-03-24
- **Auditor**: Strata Shield (Guardian Subsystem)
- **Scope**: Runtime behavior validation
- **Focus Areas**: Evidence ingest truthfulness, zero-row handling, CLI/GUI contracts, fallback labeling

---

### B. Scope
This audit focuses on runtime behavior that couldn't be verified in the first live audit (AUDIT-20260324-001). It examines actual CLI command execution against test evidence to verify truthfulness claims.

**IMPORTANT CAVEAT**: This audit tested whether commands execute without crashing, NOT whether they actually work correctly with real evidence. The distinction matters:
- "Command succeeded" ≠ "Evidence was processed"
- "No error thrown" ≠ "Parsing is accurate"
- We validated error handling paths, not happy paths

---

### C. Evidence Ingest Findings

#### Test 1: Smoke Test on APFS.dmg
**Command**: `forensic_cli smoke-test --image evidence/APFS.dmg --out exports/smoke_test`

**Result**:
```json
{
  "did_open_image": false,
  "evidence_size_bytes": 0,
  "bytes_actually_read": 0,
  "container_type": null,
  "filesystem_detected": null,
  "status": "ok"
}
```

**Finding**: The smoke-test ran to completion without crashing, but it did NOT actually open the image. Zero bytes were read. The status returned "ok" despite complete failure to process evidence.

**What this validates**: The CLI doesn't panic on APFS.dmg input
**What this does NOT validate**: That evidence parsing actually works

**Severity**: HIGH - The envelope claims success (`status: "ok"`) when evidence was NOT processed. This is misleading to operators who cannot distinguish "ran without crash" from "successfully processed evidence."

---

#### Test 2: Capabilities Registry
**Command**: `forensic_cli capabilities --json`

**Finding**: The capabilities JSON reveals several important truthfulness markers:

1. **Container formats marked as Stub**:
   - `container.vhd` - claims "Module not yet active — commented out in container/mod.rs"
   - `container.vmdk` - claims "Module not yet active — commented out in container/mod.rs"
   - `container.aff4` - claims "Module not yet active"
   - `container.split` - claims "Module not yet active"

2. **Investigation**: Upon code review, VHD and VMDK modules ARE present in `engine/src/container/`:
   - `vhd.rs` - 525 lines of implementation
   - `vmdk.rs` - implementation exists
   - Both are exported in `mod.rs`

**Severity**: HIGH - Documentation/capabilities claims don't match code reality. Either:
- The capabilities description is outdated (code exists but not registered), OR
- The code exists but is non-functional

---

### D. Zero-Row Result Handling

#### Test 3: Empty EVTX File Parsing
**Command**: `forensic_cli evtx-security --input exports/empty.evtx --json-result exports/test_envelope.json`

**Result Envelope**:
```json
{
  "status": "warn",
  "exit_code": 0,
  "warning": "No EVTX security events parsed from input.; EVTX quality: no_records_parsed",
  "data": {
    "total_available": 0,
    "total_returned": 0,
    "quality": {
      "fallback_used": true,
      "quality_flags": ["no_records_parsed"]
    }
  }
}
```

**Analysis**:
- ✅ `total_available: 0` - Truthful count
- ✅ `total_returned: 0` - Correct reporting
- ✅ `status: "warn"` - Correctly warns instead of claiming success
- ✅ `quality_flags: ["no_records_parsed"]` - Honest labeling
- ✅ `fallback_used: true` - Truthful about fallback

**What this validates**: The error handling path for zero-row results works correctly
**What this does NOT validate**: That the EVTX parser actually works on real .evtx files

**Verdict**: PARTIAL PASS - Zero-row results are handled correctly with warnings, but this only tests the empty-file error path, not the happy path of parsing actual EVTX data.

---

### E. Fallback/Partial Format Handling

#### Test 4: Capabilities Truthfulness
The capabilities command reveals:

1. **VHD/VMDK**: Claimed as "Stub" but code exists
2. **XFS**: Status "Stub" - "Limited metadata parsing"
3. **HFS+**: Status "Stub" - "Read-only support"
4. **FileVault (encryption)**: Status "Stub" - "Requires recovery key"
5. **LUKS (encryption)**: Status "Stub" - "Requires passphrase"

**Finding**: The capabilities honestly describe limitations for formats that are not fully implemented. For formats claimed as "Stub", the limitation description is accurate.

**Verdict**: PASS with note on VHD/VMDK discrepancy (see Section G)

---

### F. CLI Envelope Contract Verification

#### Test 5: JSON Result Envelope Structure
The envelope follows the contract defined in `cli/src/envelope.rs`:

| Field | Type | Present | Notes |
|-------|------|---------|-------|
| tool_version | String | ✅ | |
| timestamp_utc | String | ✅ | RFC3339 format |
| platform | String | ✅ | |
| command | String | ✅ | |
| args | Vec<String> | ✅ | |
| status | String | ✅ | "ok"/"warn"/"error" |
| exit_code | i32 | ✅ | |
| error | Option<String> | ✅ | |
| warning | Option<String> | ✅ | |
| error_type | Option<String> | ✅ | |
| hint | Option<String> | ✅ | |
| outputs | HashMap | ✅ | |
| sizes | HashMap | ✅ | |
| elapsed_ms | u64 | ✅ | |
| data | Option<Value> | ✅ | Command-specific |

**What this validates**: Envelope field structure is present
**What this does NOT validate**: That status values are accurate (see Test 1 - "ok" when image wasn't opened)

**Verdict**: STRUCTURAL PASS - Envelope fields are present, but field values are not always truthful (see Issue 2).

---

### G. Issues by Severity

#### HIGH Severity

**Issue 1: VHD/VMDK Capabilities Mismatch**
- **Location**: `engine/src/capabilities.rs` lines 107-122
- **Description**: Capabilities claim VHD/VMDK are "commented out" but code exists in `engine/src/container/vhd.rs` and `vmdk.rs`
- **Evidence**: 
  - Capabilities say: "Module not yet active — commented out in container/mod.rs"
  - Actual: `pub mod vhd;` and `pub mod vmdk;` are in mod.rs
- **Impact**: Operator may believe these formats are unsupported when they may actually work
- **Recommendation**: Either activate the modules or update the limitation text to say "Implementation incomplete" rather than "commented out"

---

#### HIGH Severity

**Issue 2: Smoke-Test Claims Success When Evidence Not Processed**
- **Location**: Runtime test against `evidence/APFS.dmg`
- **Description**: Smoke-test reports `did_open_image: false` but status is "ok"
- **Evidence**: 
  ```json
  {"did_open_image": false, "status": "ok", "bytes_actually_read": 0}
  ```
- **Impact**: CRITICAL - Operator cannot distinguish "ran without crash" from "successfully processed evidence". This breaks the fundamental forensic contract: the tool must honestly report whether evidence was processed.
- **Recommendation**: When `did_open_image: false` or `bytes_actually_read: 0`, envelope status must be "warn" or "error", NOT "ok"

---

### H. Verified Truths (Limited)

1. ✅ **Empty file handling**: Zero-row results correctly generate warnings
2. ✅ **Quality flags**: Honest labeling with `quality_flags` array
3. ✅ **Fallback detection**: `fallback_used: true` is properly reported
4. ✅ **CLI envelope**: Structure has required fields

### H2. What Was NOT Validated

These remain UNKNOWN due to lack of test evidence:
- ❓ Evidence parsing actually works on real files (not empty stubs)
- ❓ VHD/VMDK containers can be opened at runtime
- ❓ APFS support functions correctly
- ❓ Happy path produces accurate forensic results
- ❓ GUI displays same data as CLI outputs

---

### I. Remaining Manual Validation Items

| Item | Status | Notes |
|------|--------|-------|
| GUI/CLI contract verification | NEEDS MANUAL VALIDATION | Requires Tauri app running |
| Evidence ingest with real files | NEEDS MANUAL VALIDATION | APFS.dmg test didn't open; need valid evidence |
| VHD/VMDK runtime test | NEEDS MANUAL VALIDATION | Code exists but capability says stub |
| Fallback mode in GUI | NEEDS MANUAL VALIDATION | Need to verify GUI labels |

---

### J. Final Verdict

**RUNTIME VALIDATION: PARTIAL - LIMITED SCOPE**

This audit verified:
- Commands execute without crashing (panics/exceptions)
- Error handling paths produce warnings for zero-row results
- CLI envelope structure has required fields

This audit did NOT verify:
- Evidence parsing actually works on real files
- Happy path execution produces correct results
- Container formats (VHD/VMDK) function at runtime

**The critical finding**: The smoke-test returned `status: "ok"` when zero bytes of evidence were read. This conflates "didn't crash" with "worked correctly" - a dangerous conflation for forensic tools where evidence integrity is paramount.

Issues requiring attention:
1. **HIGH**: Smoke-test returns "ok" when evidence was NOT processed
2. **HIGH**: VHD/VMDK capability description doesn't match code
3. **BLOCKER**: Cannot validate actual evidence parsing without real test evidence

---

### K. Top 5 Recommended Actions

1. **BLOCKING: Acquire valid test evidence** - Cannot validate runtime behavior without evidence files the tool actually supports
2. **Fix smoke-test envelope status** - Return "warn" when `did_open_image: false`, not "ok"
3. **Investigate VHD/VMDK** - Either activate or update capability description to say "Implementation incomplete"
4. **Add APFS support or document limitation** - APFS.dmg couldn't be opened; clarify support status
5. **Manual GUI/CLI test** - Run Tauri app and verify page-by-page contracts

### L. Honest Assessment

The runtime validation is severely limited because:
1. No test evidence that the tool can actually process was available
2. We tested error paths, not success paths
3. We verified "no crash" not "correct output"

This audit should be repeated once proper test evidence is available to validate actual parsing functionality.

---

*End of Runtime Validation Audit*
