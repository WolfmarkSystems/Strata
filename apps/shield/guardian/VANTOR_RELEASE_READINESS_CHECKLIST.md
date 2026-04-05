# Strata Release Readiness Checklist

**Document Type:** Pre-Release Validation Checklist  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Purpose:** Final validation before portable and workstation-ready builds

---

## Purpose

This checklist defines the final validation steps before releasing a ForensicSuite build. It combines build validation, runtime health checks, and truthfulness verification into a single release gate.

Strata runs this checklist:
- Before portable package creation
- Before workstation deployment
- After any significant change
- Before handing off to operators

---

## Pre-Check Setup

Before beginning release readiness:

1. **Identify build type:** Portable package, workstation install, or both
2. **Document expected audience:** Operators, auditors, or developers
3. **Note build environment:** Windows version, tools available
4. **Clear old state:** Fresh validation, no cached results

---

## Section 1: Workspace Build and Tests

### 1.1: Debug Build Success
**Check:** Does `cargo build --workspace` complete successfully?  
**Command:** `cd D:\forensic-suite && cargo build --workspace`  
**Pass Criteria:** Exit code 0, no `error[E` compilation errors  
**On Fail:** Block release until build succeeds

### 1.2: Warning Baseline
**Check:** Are there any new warnings since last release?  
**Expected:** Warnings match baseline in `WARNINGS_REPORT.md`  
**Pass Criteria:** No new warnings introduced  
**On Fail:** Document new warnings, classify as acceptable or blocking

### 1.3: Test Compilation
**Check:** Do all tests compile?  
**Command:** `cargo test --workspace --no-run`  
**Pass Criteria:** Exit code 0, no test compilation errors  
**On Fail:** Fix test compilation errors (known: `missing field blake3 in HashResults`)

### 1.4: Unit Test Pass
**Check:** Do all unit tests pass?  
**Command:** `cargo test --workspace`  
**Pass Criteria:** All tests pass, exit code 0  
**On Fail:** Document failing tests, classify as regression or pre-existing

### 1.5: Clippy Compliance
**Check:** Does code pass clippy checks?  
**Command:** `cargo clippy --workspace -- -D warnings`  
**Pass Criteria:** Exit code 0, no clippy violations  
**On Fail:** Fix clippy errors or document acceptable violations

---

## Section 2: Tauri Build and Package

### 2.1: Tauri Development Build
**Check:** Does Tauri app build in development mode?  
**Command:** `cd D:\forensic-suite\gui-tauri && npm run tauri dev` or `cargo tauri build`  
**Pass Criteria:** Build completes, executable launches  
**On Fail:** Document build errors, check Node.js and Rust versions

### 2.2: Tauri Release Build
**Check:** Does Tauri produce release executable?  
**Command:** `cargo tauri build --release`  
**Pass Criteria:** Executable produced in expected location  
**On Fail:** Document release build failures

### 2.3: Frontend Build
**Check:** Does frontend build successfully?  
**Command:** `cd D:\forensic-suite\gui-tauri && npm run build`  
**Pass Criteria:** Build completes, assets generated  
**On Fail:** Document frontend build errors (known: esbuild platform mismatch)

### 2.4: Package Contents Verified
**Check:** Are all required files in package?  
**Expected:** Executable, resources, configs all present  
**Pass Criteria:** No missing required files  
**On Fail:** Document missing files, add to package script

### 2.5: Bundle Size Reasonable
**Check:** Is package size within expectations?  
**Expected:** ~50-200MB for core, varies by configuration  
**Pass Criteria:** Size within documented range  
**On Fail:** Document size anomaly

---

## Section 3: Sidecar Sync and Hash Verification

### 3.1: Sidecar Binary Built
**Check:** Is `forensic_cli.exe` built?  
**Command:** Check `target/debug/forensic_cli.exe` or `target/release/forensic_cli.exe`  
**Pass Criteria:** File exists, size > 1MB  
**On Fail:** Rebuild CLI crate

### 3.2: Sidecar Version Match
**Check:** Does CLI version match workspace version?  
**Command:** `forensic_cli --version`  
**Pass Criteria:** Version matches `Cargo.toml` (0.1.0)  
**On Fail:** Rebuild, verify workspace version consistency

### 3.3: Sidecar Hash Recorded
**Check:** Is CLI binary hash recorded for verification?  
**Expected:** Hash computed and stored (for audit trail)  
**Pass Criteria:** Hash documented in release notes  
**On Fail:** Document hash for this build

### 3.4: Engine Version Recorded
**Check:** Is `forensic_engine` version recorded?  
**Command:** Check `forensic_engine` crate version  
**Pass Criteria:** Version documented in release notes  
**On Fail:** Document version for this build

---

## Section 4: Model and Runtime Validation

### 4.1: Llama Server Binary Present
**Check:** Does `llama-server.exe` exist?  
**Command:** Check `D:\DFIR Coding AI\bin\llama\llama-server.exe`  
**Pass Criteria:** File exists, non-zero size  
**On Fail:** Verify download from official source

### 4.2: Llama Model Path Configured
**Check:** Are model paths in scripts correct?  
**Command:** Review `scripts/start_llama_server.bat`  
**Pass Criteria:** Paths point to `Meta-Llama-3.1-*.gguf`, not Qwen  
**On Fail:** Update paths per LLAMA_MIGRATION_CHECKLIST.md

### 4.3: Model Hash Verification
**Check:** Is Llama model hash recorded?  
**Expected:** SHA256 of GGUF file documented  
**Pass Criteria:** Hash in release documentation  
**On Fail:** Document model hash for provenance

### 4.4: KB Bridge Version Correct
**Check:** Is KB bridge the current version?  
**Command:** Review `bin/kb/dfir_kb_bridge.py` startup log  
**Pass Criteria:** Shows "Strata KB Bridge", not "Wolf Sentinel"  
**On Fail:** Ensure correct bridge version deployed

### 4.5: No Qwen References in Runtime
**Check:** Do current logs contain Qwen references?  
**Command:** Check recent log entries in `logs/`  
**Pass Criteria:** No Qwen model references in active logs  
**On Fail:** Clear old logs, restart services

---

## Section 5: Local-Only Mode Verification

### 5.1: Offline Operation Works
**Check:** Does the suite work without network?  
**Command:** Disable network, run basic commands  
**Pass Criteria:** Container open, enumeration, timeline work offline  
**On Fail:** Document any network dependencies

### 5.2: No Cloud Dependencies
**Check:** Are there any hardcoded cloud service calls?  
**Expected:** All operations work from local evidence and models  
**Pass Criteria:** No cloud service calls in critical paths  
**On Fail:** Document cloud dependencies, add offline fallback

### 5.3: Local Model Loading
**Check:** Does Llama model load from local file?  
**Command:** Run `start_llama_server.bat`, check logs  
**Pass Criteria:** Model loads from local GGUF file, not remote  
**On Fail:** Verify `--model` path points to local file

### 5.4: Local KB Vault
**Check:** Does KB bridge use local vault?  
**Command:** Check `VAULT` path in bridge logs  
**Pass Criteria:** Vault points to local `knowledge/vault` directory  
**On Fail:** Verify `ROOT` and `VAULT` paths

---

## Section 6: Settings and History Folder Behavior

### 6.1: Config Files Isolated
**Check:** Are settings stored in app data, not working directory?  
**Expected:** Config in `%APPDATA%` or `~/.forensic-suite/`  
**Pass Criteria:** No config files in evidence directories  
**On Fail:** Update config path handling

### 6.2: History Files Managed
**Check:** Is history stored appropriately?  
**Expected:** History in app data, not in evidence  
**Pass Criteria:** No history contamination between cases  
**On Fail:** Document history path handling

### 6.3: Temp Files Cleaned
**Check:** Are temp files handled correctly?  
**Expected:** Temp files in system temp, cleaned on exit  
**Pass Criteria:** No temp file accumulation  
**On Fail:** Verify temp file cleanup code

### 6.4: Settings Persistence
**Check:** Do settings persist across sessions?  
**Command:** Set a preference, restart app, verify persistence  
**Pass Criteria:** Settings persist correctly  
**On Fail:** Document settings persistence issues

---

## Section 7: Package Artifact Verification

### 7.1: Required Binaries Included
**Check:** Are all binaries in package?  
**Expected:** forensic_cli, forensic_engine libs, llama-server, tesseract, ripgrep  
**Pass Criteria:** All required binaries present  
**On Fail:** Add missing binaries to package

### 7.2: Model Files Excluded
**Check:** Are large GGUF files excluded from package?  
**Expected:** Models downloaded separately  
**Pass Criteria:** No `.gguf` files in package  
**On Fail:** Verify models are downloaded at runtime

### 7.3: Documentation Included
**Check:** Are docs included in package?  
**Expected:** README, LICENSE, guardian documents  
**Pass Criteria:** Docs present and accurate  
**On Fail:** Add missing documentation

### 7.4: Scripts Validated
**Check:** Do included scripts work in package context?  
**Expected:** Scripts use relative paths, no hardcoded paths  
**Pass Criteria:** Scripts work from package directory  
**On Fail:** Update scripts to use relative paths

### 7.5: Package Runs from Any Location
**Check:** Can package run from different install path?  
**Command:** Run from `C:\Tools\`, `D:\Forensics\`, USB drive  
**Pass Criteria:** Package works from any path  
**On Fail:** Find hardcoded paths, update to relative

---

## Section 8: GUI Sanity Pass

### 8.1: App Launches
**Check:** Does the GUI application start?  
**Command:** Launch built executable  
**Pass Criteria:** Window opens, no immediate crash  
**On Fail:** Document launch failure

### 8.2: Splash/Loading Screen
**Check:** Does loading screen appear?  
**Expected:** Visual feedback during startup  
**Pass Criteria:** Loading indicator visible  
**On Fail:** Document loading state issues

### 8.3: Menu Navigation
**Check:** Do all menu items work?  
**Expected:** All menu items respond, no dead links  
**Pass Criteria:** Navigation works, no errors  
**On Fail:** Document broken navigation

### 8.4: Status Indicators
**Check:** Do status indicators update correctly?  
**Expected:** LLAMA and KB status dots reflect actual state  
**Pass Criteria:** Status matches actual service state  
**On Fail:** Document status indicator issues

### 8.5: Window Controls
**Check:** Do minimize/maximize/close work?  
**Expected:** All window controls functional  
**Pass Criteria:** Window controls work correctly  
**On Fail:** Document window control issues

---

## Section 9: Command Sanity Pass

### 9.1: All Commands Listed
**Check:** Does `forensic_cli --help` show all commands?  
**Command:** `forensic_cli --help`  
**Pass Criteria:** All 40+ documented commands present  
**On Fail:** Document missing commands

### 9.2: Envelope Output Works
**Check:** Do commands produce valid envelopes?  
**Command:** `forensic_cli doctor --json-result <temp>`  
**Pass Criteria:** Valid JSON with all required fields  
**On Fail:** Document envelope generation issues

### 9.3: Error Handling
**Check:** Do commands handle errors gracefully?  
**Command:** Run commands with invalid inputs  
**Pass Criteria:** Error messages are helpful, not raw panics  
**On Fail:** Document error handling issues

### 9.4: Performance Baseline
**Check:** Are command times reasonable?  
**Command:** Time basic commands  
**Pass Criteria:** Times proportional to operation complexity  
**On Fail:** Document performance anomalies

---

## Section 10: Truthfulness Sanity Pass

### 10.1: No Fabricated Evidence
**Check:** Do parsers produce only evidence-derived data?  
**Expected:** No placeholder or synthetic artifacts in output  
**Pass Criteria:** Zero fabrication violations  
**On Fail:** Immediate escalation per PARSER_CONVENTIONS.md

### 10.2: Container Claims Accurate
**Check:** Do capability claims match implementation?  
**Expected:** Only documented containers are claimed complete  
**Pass Criteria:** RAW, E01, Directory as complete; others labeled  
**On Fail:** Update capabilities or documentation

### 10.3: Fallback Modes Labeled
**Check:** Are fallback modes visible in UI?  
**Expected:** Regex-token fallback shows "(fallback)" label  
**Pass Criteria:** Fallback indicators visible  
**On Fail:** Add fallback labeling

### 10.4: No Overclaimed Capabilities
**Check:** Do capabilities command output match actual code?  
**Expected:** All "implemented" items have working code  
**Pass Criteria:** No phantom capabilities  
**On Fail:** Update capability registry

### 10.5: Warning Preservation
**Check:** Do commands with warnings preserve them?  
**Expected:** CLI warnings appear in GUI  
**Pass Criteria:** Warnings not dropped  
**On Fail:** Fix warning propagation

---

## Section 11: Operator-Facing Warning Review

### 11.1: Known Gap Documentation
**Check:** Are operators warned about known limitations?  
**Expected:** UI or docs mention partial/stubbed features  
**Pass Criteria:** Operators informed of limitations  
**On Fail:** Add gap warnings to UI/docs

### 11.2: Cryptographic Disclaimer
**Check:** Is BitLocker/encryption handling clarified?  
**Expected:** Operators informed about encryption detection limits  
**Pass Criteria:** Encryption caveats documented  
**On Fail:** Add encryption handling notes

### 11.3: Evidence Integrity Note
**Check:** Is hash verification procedure documented?  
**Expected:** Operators know to run `verify` for integrity  
**Pass Criteria:** Integrity verification documented  
**On Fail:** Add integrity verification guidance

### 11.4: Model Disclaimer
**Check:** Is Llama model role clarified?  
**Expected:** Operators understand AI assistant role vs forensic engine  
**Pass Criteria:** Model purpose documented  
**On Fail:** Add model role clarification

### 11.5: Unsupported Format Warning
**Check:** Do unsupported container formats show warnings?  
**Expected:** VHD/VMDK/AFF4 show partial support warnings  
**Pass Criteria:** Format limitations visible  
**On Fail:** Add format support warnings

---

## Section 12: Startup Script Validation

### 12.1: Llama Server Startup
**Check:** Does `start_llama_server.bat` work?  
**Command:** Run script, check logs  
**Pass Criteria:** Llama server starts, model loads  
**On Fail:** Document startup script issues

### 12.2: KB Bridge Startup
**Check:** Does `start_kb_bridge.bat` work?  
**Command:** Run script, check health endpoint  
**Pass Criteria:** KB bridge starts, health returns OK  
**On Fail:** Document KB bridge startup issues

### 12.3: Service Health Check
**Check:** Does `health_dfir_coding_ai.bat` work?  
**Command:** Run health script  
**Pass Criteria:** Reports all services healthy  
**On Fail:** Document health check issues

### 12.4: Graceful Shutdown
**Check:** Does `stop_*` scripts work?  
**Command:** Run stop scripts  
**Pass Criteria:** Services stop cleanly  
**On Fail:** Document shutdown issues

---

## Release Readiness Summary

| Section | Checks | Passed | Failed | Skipped |
|---------|--------|--------|--------|---------|
| 1. Build/Tests | 5 | | | |
| 2. Tauri Package | 5 | | | |
| 3. Sidecar Sync | 4 | | | |
| 4. Model/Runtime | 5 | | | |
| 5. Local-Only | 4 | | | |
| 6. Settings/History | 4 | | | |
| 7. Package Contents | 5 | | | |
| 8. GUI Sanity | 5 | | | |
| 9. Command Sanity | 4 | | | |
| 10. Truthfulness | 5 | | | |
| 11. Operator Warnings | 5 | | | |
| 12. Startup Scripts | 4 | | | |
| **Total** | **55** | | | |

### Blocking Issues
| Issue | Section | Severity | Resolution |
|-------|---------|----------|------------|
| | | | |
| | | | |

### Non-Blocking Issues
| Issue | Section | Notes |
|-------|---------|-------|
| | | |
| | | | |

### Overall Release Status
- [ ] **RELEASE APPROVED** — All critical items passed, no blocking issues
- [ ] **RELEASE WITH WARNINGS** — Non-blocking issues documented, acceptable
- [ ] **RELEASE BLOCKED** — Critical issues must be resolved

### Build Information
Build Version: _________________  
Build Date: _________________  
Build Environment: _________________  
Build Artifacts: _________________

### Sign-Off
Auditor: Strata  
Date: _________________  
Status: _________________  
Approved By: _________________

---

## Post-Release Tasks

After successful release:

- [ ] Update version documentation
- [ ] Archive build artifacts
- [ ] Update release notes with known limitations
- [ ] Notify operators of new version
- [ ] Schedule follow-up validation

---

## Document Maintenance

Update this checklist when:
- New validation items are discovered
- Known limitations change
- Build process evolves
- New warnings become necessary

Location: `D:\forensic-suite\guardian\STRATA_RELEASE_READINESS_CHECKLIST.md`
