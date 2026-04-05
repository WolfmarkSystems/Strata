# Strata Runtime Audit Checklist

**Document Type:** Operational Audit Checklist  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Purpose:** Repeatable runtime truthfulness and health review for the ForensicSuite

---

## How to Use This Checklist

Run this checklist during:
- Pre-release validation
- Post-build verification
- Runtime health checks
- Integration testing

For each item:
1. **Check:** What to verify
2. **Where:** File, command, or log location
3. **Pass Criteria:** What "success" looks like
4. **On Fail:** What Strata does when it fails

---

## Section 1: Build Validation

### 1.1: Cargo Workspace Build
**Check:** Does `cargo build --workspace` complete without errors?  
**Where:** `D:\forensic-suite\` root  
**Pass Criteria:** Exit code 0, no `error[E` compilation errors  
**On Fail:** Document errors in `build_errors.txt`, escalate to architect

### 1.2: Warning Audit
**Check:** Are there any new warnings since last build?  
**Where:** `D:\forensic-suite\target\` build output  
**Pass Criteria:** No new `warning:` lines, existing warnings documented in `WARNINGS_REPORT.md`  
**On Fail:** Classify warning type (deprecated, unused, unsafe), determine if blocking

### 1.3: Release Build Feasibility
**Check:** Does `cargo build --workspace --release` complete within acceptable time?  
**Where:** `D:\forensic-suite\` root  
**Pass Criteria:** Completes successfully (timeout threshold is environment-dependent)  
**On Fail:** Document build time, flag if it exceeds documented threshold

### 1.4: Dependency Integrity
**Check:** Does `Cargo.lock` match `Cargo.toml` workspace members?  
**Where:** `D:\forensic-suite\Cargo.lock`  
**Pass Criteria:** All workspace crates have matching lock entries  
**On Fail:** Run `cargo update`, verify no unexpected version changes

---

## Section 2: Test Validation

### 2.1: Test Compilation
**Check:** Do all tests compile without `error[E` failures?  
**Where:** `cargo test --workspace --no-run`  
**Pass Criteria:** Exit code 0, no compilation errors  
**On Fail:** Document the specific `error[E` and affected test file

### 2.2: Unit Test Execution
**Check:** Do all unit tests pass?  
**Where:** `cargo test --workspace`  
**Pass Criteria:** All tests pass, exit code 0  
**On Fail:** Document failing test names, classify as regression or pre-existing

### 2.3: Clippy Compliance
**Check:** Does the code pass `cargo clippy --workspace -- -D warnings`?  
**Where:** `clippy_latest.txt` or fresh clippy run  
**Pass Criteria:** No clippy errors, all warnings promoted to errors pass  
**On Fail:** Document clippy error categories (type_complexity, unwrap_used, etc.)

### 2.4: Known Gap Test Coverage
**Check:** Are there tests for stubbed/partial features that verify they fail gracefully?  
**Where:** `engine/src/tests/`  
**Pass Criteria:** Stubbed parsers return `Ok(vec![])` explicitly, not silently  
**On Fail:** Flag parsers that panic or return fake artifacts on unimplemented paths

---

## Section 3: Sidecar/Runtime Validation

### 3.1: Sidecar Binary Presence
**Check:** Does `forensic_cli-x86_64-pc-windows-msvc.exe` exist in expected location?  
**Where:** `D:\forensic-suite\target\debug\` or `release\`  
**Pass Criteria:** File exists, non-zero size  
**On Fail:** Rebuild CLI, verify Cargo workspace includes `forensic_cli`

### 3.2: Sidecar Version Match
**Check:** Does CLI version match documented version in capabilities?  
**Where:** `forensic_cli --version` or `capabilities` output  
**Pass Criteria:** Version matches `Cargo.toml` workspace version (0.1.0)  
**On Fail:** Rebuild, verify no version mismatch between workspace crates

### 3.3: Sidecar Health
**Check:** Does `forensic_cli doctor` return status "ok"?  
**Where:** `forensic_cli doctor --json-result <temp>`  
**Pass Criteria:** Envelope status "ok", all diagnostic checks pass  
**On Fail:** Document failing checks, determine if blocking for release

### 3.4: Llama Server Binary
**Check:** Does `llama-server.exe` exist?  
**Where:** `D:\DFIR Coding AI\bin\llama\`  
**Pass Criteria:** File exists, non-zero size  
**On Fail:** Document missing binary, verify download/installation procedure

### 3.5: Llama Model Validation
**Check:** Is the correct Llama model configured and present?  
**Where:** `scripts/start_llama_server.bat`, `models/gguf/`  
**Pass Criteria:** Primary model path points to `Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf` or fallback `Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf`  
**On Fail:** Update model paths per LLAMA_MIGRATION_CHECKLIST.md

### 3.6: KB Bridge Presence
**Check:** Does `dfir_kb_bridge.py` exist and is it the current version?  
**Where:** `D:\DFIR Coding AI\bin\kb\`  
**Pass Criteria:** File exists, contains `ThreadingHTTPServer`, no references to Qwen  
**On Fail:** Verify correct version is in use, check for duplicate old versions

### 3.7: KB Bridge Health
**Check:** Does KB bridge respond on port 8090?  
**Where:** `http://127.0.0.1:8090/health`  
**Pass Criteria:** Returns `{"status":"ok",...}` with document counts  
**On Fail:** Restart via `scripts/start_kb_bridge.bat`, check logs in `logs/`

---

## Section 4: Command Validation

### 4.1: CLI Help
**Check:** Does `forensic_cli --help` display all commands?  
**Where:** `forensic_cli --help`  
**Pass Criteria:** All 40+ documented commands appear  
**On Fail:** Document missing commands, verify command registration in `main.rs`

### 4.2: Envelope-Backed Commands
**Check:** Do commands return valid `CliResultEnvelope` JSON?  
**Where:** `forensic_cli <command> --json-result <temp>`  
**Pass Criteria:** Valid JSON with all required fields (tool_version, timestamp_utc, status, etc.)  
**On Fail:** Document command name and envelope parsing error

### 4.3: Envelope Status Truthfulness
**Check:** Do commands with errors return `status: "error"` not `status: "ok"`?  
**Where:** Run commands with invalid inputs  
**Pass Criteria:** Invalid evidence paths return status "error", not "ok"  
**On Fail:** Flag as truthfulness violation, document affected commands

### 4.4: Warning Preservation
**Check:** Do commands with warnings return `warning` field?  
**Where:** Commands expected to produce warnings (e.g., partial parses)  
**Pass Criteria:** `warning` field present with meaningful message  
**On Fail:** Flag as warning suppression, escalate

### 4.5: Instant Completion Check (Instant Indexing Pattern)
**Check:** Do commands that process evidence return reasonable elapsed time?  
**Where:** Envelope `elapsed_ms` field  
**Pass Criteria:** elapsed_ms is plausible for evidence size (not <100ms for GB-scale evidence)  
**On Fail:** Flag as potential instant-indexing-with-no-data pattern per RUNTIME_FAILURE_PATTERNS.md

### 4.6: Zero-Row Result Handling
**Check:** Do commands with zero results have explicit warning or empty-by-design context?  
**Where:** Envelope data payloads for timeline, artifacts, filetable  
**Pass Criteria:** Zero-row results have `warning` field or documented empty-by-design  
**On Fail:** Flag as success-with-zero-rows pattern, escalate

---

## Section 5: History/Log Validation

### 5.1: Historical Log Currency
**Check:** Do current logs reflect current runtime state, not stale data?  
**Where:** `logs/` directory, `DFIR Coding AI/logs/`  
**Pass Criteria:** Most recent log entries match current date/time  
**On Fail:** Clear old logs, verify new operations are logging

### 5.2: Qwen Reference Cleanup
**Check:** Do current logs contain any Qwen references that indicate stale state?  
**Where:** `logs/llama_stderr.log`, `logs/server_stderr.log`  
**Pass Criteria:** No references to Qwen2.5-Coder in current logs  
**On Fail:** Clear old logs, restart services for fresh state

### 5.3: Stale Model File Awareness
**Check:** Do old model files exist that could be accidentally loaded?  
**Where:** `models/gguf/`  
**Pass Criteria:** Old Qwen files moved to `backup_qwen_20260323/` or deleted  
**On Fail:** Document old files, recommend deletion after backup confirmation

### 5.4: KB Bridge Log Accuracy
**Check:** Does KB bridge log show correct startup state?  
**Where:** `logs/kb_bridge_stdout.log`  
**Pass Criteria:** Shows "Strata KB Bridge" not "Wolf Sentinel Bridge", correct vault path  
**On Fail:** Verify correct bridge version is running

---

## Section 6: Packaging Validation

### 6.1: Required Binaries Present
**Check:** Are all required binaries included in package?  
**Where:** Package output directory  
**Pass Criteria:** `forensic_cli.exe`, `llama-server.exe`, all engine DLLs present  
**On Fail:** Document missing files, verify build output

### 6.2: Sidecar Sync
**Check:** Does packaged `forensic_cli` match source-built version?  
**Where:** Package vs `target/debug/`  
**Pass Criteria:** Binary hashes match or are from same build  
**On Fail:** Rebuild CLI, verify package sync process

### 6.3: Model Files Not Bundled
**Check:** Are large model files excluded from package?  
**Where:** Package directory  
**Pass Criteria:** No `.gguf` files in package (they are downloaded separately)  
**On Fail:** Document model file locations, verify they are downloaded at runtime

### 6.4: Configuration File Integrity
**Check:** Are configuration files present and valid?  
**Where:** Package config directory  
**Pass Criteria:** Required configs exist, no hardcoded secrets  
**On Fail:** Document missing configs, verify paths are relative

---

## Section 7: Truthfulness Validation

### 7.1: No Fabricated Evidence
**Check:** Do parsers produce evidence-derived artifacts only?  
**Where:** Parser implementations in `engine/src/parsers/`  
**Pass Criteria:** No parsers return `Default::default()`, placeholder strings, or invented data  
**On Fail:** Flag parser per PARSER_CONVENTIONS.md, escalate immediately

### 7.2: Container Support Truth
**Check:** Do GUI/CLI claims about container support match KNOWN_GAPS.md?  
**Where:** Documentation, capability output  
**Pass Criteria:** Only RAW, E01, Directory marked as complete; VHD/VMDK partial; others stubbed  
**On Fail:** Update claims or update KNOWN_GAPS.md to match reality

### 7.3: Fallback Mode Labeling
**Check:** Are fallback modes visibly labeled in UI?  
**Where:** KB bridge health endpoint, GUI displays  
**Pass Criteria:** `embedding_backend` shows "(fallback)" when using regex-token  
**On Fail:** Document where fallback labeling is missing

### 7.4: No Overclaimed Capabilities
**Check:** Do capability claims match implementation?  
**Where:** `capabilities` command output  
**Pass Criteria:** All "implemented" capabilities have actual code  
**On Fail:** Update capability registry or implementation

---

## Section 8: Fallback/Partial-State Validation

### 8.1: VHD Behavior Check
**Check:** Does VHD container open without claiming full support?  
**Where:** Open VHD evidence, check `open-evidence` output  
**Pass Criteria:** Returns partial data with appropriate warning  
**On Fail:** Flag per KNOWN_GAPS.md section A.2

### 8.2: VMDK Silent Failure Detection
**Check:** Does VMDK produce visible error or empty result, not silently fake data?  
**Where:** Open VMDK evidence  
**Pass Criteria:** Empty tree with warning OR explicit error, not silent empty  
**On Fail:** Flag as dangerous silent failure per RUNTIME_FAILURE_PATTERNS.md

### 8.3: Stubbed Parser Behavior
**Check:** Do stubbed parsers return explicit empty results?  
**Where:** Run artifact command on files matching stubbed parser patterns  
**Pass Criteria:** `Ok(vec![])` returned explicitly, not panic or fake artifact  
**On Fail:** Flag parser per PARSER_CONVENTIONS.md

### 8.4: APFS/XFS Partial Enumeration
**Check:** Do APFS/XFS enumerations warn about partial status?  
**Where:** Open APFS/XFS evidence, check `filetable` output  
**Pass Criteria:** Warning present if enumeration count seems low, or explicit partial label  
**On Fail:** Document limitation per KNOWN_GAPS.md section B.2

### 8.5: Hashset Read-Only Awareness
**Check:** Do hashset pages warn about read-only status?  
**Where:** GUI hashset interface  
**Pass Criteria:** Clear indication that editing is not yet implemented  
**On Fail:** Document where read-only warning is missing

---

## Audit Completion Summary

| Section | Items | Passed | Failed | Skipped |
|---------|-------|--------|--------|---------|
| 1. Build | 4 | | | |
| 2. Test | 4 | | | |
| 3. Sidecar/Runtime | 7 | | | |
| 4. Command | 6 | | | |
| 5. History/Log | 4 | | | |
| 6. Packaging | 4 | | | |
| 7. Truthfulness | 4 | | | |
| 8. Fallback | 5 | | | |
| **Total** | **38** | | | |

### Overall Status
- [ ] **PASS** — All critical items passed, no blocking issues
- [ ] **CONDITIONAL** — Non-blocking issues found, documented
- [ ] **FAIL** — Blocking issues found, must resolve before release

### Sign-Off
Auditor: Strata  
Date: _________________  
Status: _________________

---

## Document Maintenance

Update this checklist when:
- New validation items are discovered
- Known gaps are resolved or added
- New commands are integrated
- Runtime patterns change

Location: `D:\forensic-suite\guardian\STRATA_RUNTIME_AUDIT_CHECKLIST.md`
