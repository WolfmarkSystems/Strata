# Strata Suite Audit — Master Operating Runbook

**Document Type:** Operational Runbook  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Authority:** Strata — Suite Guardian  
**Audience:** Strata (autonomous operation), Human reviewers (oversight)

---

## Purpose

This runbook defines the canonical procedure for Strata to conduct a complete, repeatable, auditable audit of the ForensicSuite. It establishes when audits are triggered, how they are structured, what evidence must be collected, and how verdicts are rendered.

### What This Runbook Is For

Strata uses this runbook to:
- Conduct full suite audits on a defined schedule or trigger
- Validate that the suite remains truthful after code changes
- Surface capability gaps and runtime failures before they reach operators
- Provide human reviewers with a traceable audit trail

### When to Run an Audit

| Trigger | Audit Mode | Expected Duration |
|---------|-----------|------------------|
| Pre-release validation | Full Guardian Audit | 60-120 minutes |
| Post-significant code change | Build/Test + Runtime Audit | 20-40 minutes |
| Pre-deployment to new environment | Release Readiness Audit | 30-60 minutes |
| Operator reports unexpected behavior | Targeted mode based on report | Variable |
| Weekly health check | Quick Health Audit | 5-10 minutes |
| New parser or CLI command added | Ingest Validation + Parser Review | 30-45 minutes |

### What Verdict Should Be Produced

Every audit concludes with one of four verdicts:

| Verdict | Meaning |
|---------|---------|
| **PASS** | All critical checks passed. Suite is trustworthy. |
| **PASS WITH WARNINGS** | Suite is functional, but known limitations or non-blocking issues documented. |
| **PARTIAL / NOT READY** | Significant gaps or failures present. Manual review required before proceeding. |
| **FAIL** | Critical truthfulness violations or failures detected. Operation must not proceed. |

### Relationship to Other Guardian Documents

This runbook orchestrates the existing guardian knowledge base:

| Document | Role in Audit |
|----------|--------------|
| `SUITE_GUARDIAN_PROFILE.md` | Defines Strata's authority, operating principles, and boundaries |
| `TRUTHFULNESS_RULES.md` | The non-negotiable contracts that checks must validate against |
| `KNOWN_GAPS.md` | The baseline of documented limitations that must not be exceeded |
| `RUNTIME_FAILURE_PATTERNS.md` | Patterns to recognize and respond to during runtime checks |
| `COMMAND_CONTRACTS.md` | CLI-to-GUI contracts to validate during integration checks |
| `PARSER_CONVENTIONS.md` | Parser quality standards to validate during parser review |
| `STRATA_RUNTIME_AUDIT_CHECKLIST.md` | 38-item runtime health checklist (referenced in Phase 3) |
| `STRATA_INGEST_VALIDATION_CHECKLIST.md` | 42-item ingest pipeline checklist (referenced in Phase 4) |
| `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` | 30-item GUI-CLI contract checklist (referenced in Phase 5) |
| `STRATA_PARSER_REVIEW_CHECKLIST.md` | 21-item parser review checklist (referenced in Phase 6) |
| `STRATA_RELEASE_READINESS_CHECKLIST.md` | 55-item release gate checklist (referenced in Full Guardian mode) |

Strata does not repeat every item from these checklists verbatim. Strata references them by phase and synthesizes findings into the audit verdict.

---

## Preconditions

Before running any audit, Strata must verify:

### Repository Access
- [ ] Read access to `D:\forensic-suite\` workspace root
- [ ] Read access to `D:\forensic-suite\guardian\` knowledge base
- [ ] Read access to `D:\forensic-suite\gui-tauri\` frontend/backend

### Build Tools
- [ ] Rust toolchain accessible via `cargo --version` (expected: 1.70+)
- [ ] Node.js accessible via `node --version` (expected: 18+)
- [ ] npm accessible via `npm --version` (expected: 9+)

### Runtime Dependencies
- [ ] `forensic_cli.exe` built or buildable from `cargo build --workspace`
- [ ] `forensic_engine` library buildable
- [ ] `gui-tauri` buildable via `cargo tauri build`
- [ ] `llama-server.exe` accessible at expected path (or documented location)
- [ ] KB bridge (`dfir_kb_bridge.py`) accessible

### Evidence Fixtures (if running full audit)
- [ ] Test evidence image available (RAW, E01, or directory)
- [ ] Synthetic test files for parser targeting
- [ ] Known-gap test cases (VHD, VMDK) if validating partial support

### Prior State
- [ ] Access to previous audit reports (if any) for delta comparison
- [ ] `KNOWN_GAPS.md` current version reviewed
- [ ] `WARNINGS_REPORT.md` baseline (if exists) reviewed

---

## Audit Modes

### Mode 1: Quick Health Audit

**Purpose:** Rapid sanity check that the suite is not obviously broken.

**Scope:**
- Build compiles without errors
- CLI binary exists and responds
- Doctor command returns OK
- No obvious runtime failures in last-run logs

**Expected Duration:** 5-10 minutes

**When to Use:**
- Before beginning development session
- After minor edits to verify nothing broke
- Daily standup readiness check

**Exit Criteria:** Must reach verdict. If health checks fail, escalate to Build/Test Audit.

---

### Mode 2: Build/Test Audit

**Purpose:** Validate that the workspace builds cleanly and tests pass.

**Scope:**
- `cargo build --workspace` completes without errors
- `cargo test --workspace` passes
- Clippy passes (`cargo clippy --workspace -- -D warnings`)
- No new warnings introduced since baseline
- Package builds successfully (if release mode)

**Expected Duration:** 20-40 minutes (depending on build cache)

**When to Use:**
- After any code change
- Before commit
- During CI validation

**Exit Criteria:** FAIL if build errors or test failures. PASS WITH WARNINGS if warnings exist but are documented.

---

### Mode 3: Ingest Validation Audit

**Purpose:** Validate evidence processing from container open through artifact extraction.

**Scope:**
- Container type recognition (RAW, E01, Directory)
- Partition/volume discovery
- Filesystem detection and enumeration
- Parser matching and execution
- Tree and filetable population
- Artifact and timeline generation
- GUI status correctness (via Tauri commands)

**Expected Duration:** 30-45 minutes (with evidence fixtures)

**When to Use:**
- After container/filesystem/parser code changes
- When adding new evidence format support
- Pre-release validation of ingest pipeline

**Exit Criteria:** FAIL if any truthfulness rules violated (see `TRUTHFULNESS_RULES.md`). See `STRATA_INGEST_VALIDATION_CHECKLIST.md` for item-level criteria.

---

### Mode 4: GUI/CLI Contract Audit

**Purpose:** Validate that GUI pages do not claim capabilities beyond what CLI commands return.

**Scope:**
- Dashboard, Case Overview, Evidence Sources, File Explorer pages
- Timeline, Artifacts, Hash Sets pages
- Logs, Settings, Integrity Watchpoints pages
- Warning and error preservation
- Count and value truthfulness
- Fallback mode visibility

**Expected Duration:** 30-45 minutes

**When to Use:**
- After adding new GUI pages
- After modifying CLI command output shapes
- Pre-release validation of GUI integration

**Exit Criteria:** FAIL if GUI claims exceed CLI reality. See `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` for page-by-page criteria.

---

### Mode 5: Release Readiness Audit

**Purpose:** Final gate before packaging and deployment.

**Scope:**
- All Mode 2 (Build/Test) checks
- Tauri package builds
- Sidecar binary sync and hash verification
- Model and KB bridge validation
- Local-only mode verification
- Package artifact completeness
- GUI sanity pass
- Command sanity pass
- Operator-facing warnings review
- Startup script validation

**Expected Duration:** 60-90 minutes

**When to Use:**
- Before portable package creation
- Before deployment to new workstation
- Pre-release final gate

**Exit Criteria:** FAIL if blocking issues. See `STRATA_RELEASE_READINESS_CHECKLIST.md` for 55-item criteria and blocking issue classification.

---

### Mode 6: Full Guardian Audit

**Purpose:** Comprehensive end-to-end validation combining all modes.

**Scope:**
- Mode 1 through Mode 5 (all sections)
- Full suite from build through runtime through GUI
- All 10 guardian checklists referenced and findings synthesized
- Parser-specific review (new or modified parsers)
- Known gap re-verification
- Historical delta comparison (if prior audits exist)

**Expected Duration:** 2-4 hours (with full evidence fixtures)

**When to Use:**
- Major release milestones
- Periodic comprehensive review (quarterly recommended)
- After significant architectural changes
- When assuming new guardian responsibilities

**Exit Criteria:** FAIL if any critical truthfulness violation. PARTIAL if known gaps expand or new gaps discovered.

---

## Standard Audit Sequence

Strata follows this canonical order for every Full Guardian Audit. Sub-modes follow the applicable phases.

### Phase 1 — Establish Current Reality

**Objective:** Understand the current state before testing anything.

1. **Review guardian documents**
   - Read current `KNOWN_GAPS.md`
   - Read current `WARNINGS_REPORT.md` (if exists)
   - Confirm which checklist versions are current

2. **Review recent changes**
   - Check for unreviewed commits since last audit
   - Identify code areas that changed (parsers, CLI, GUI, build)
   - Note any documented blockers from prior audits

3. **Verify architecture assumptions**
   - Confirm workspace structure matches `SUITE_GUARDIAN_PROFILE.md`
   - Confirm CLI command inventory matches `COMMAND_CONTRACTS.md`
   - Confirm container/filesystem support matches `KNOWN_GAPS.md` Section A and B

4. **Document baseline**
   - Record the audit date, environment, and scope
   - Note any pre-existing issues from prior audits
   - Set expected outcomes for this audit

---

### Phase 2 — Build/Test Validation

**Objective:** Verify the suite compiles and tests pass.

1. **Workspace build**
   - Run `cargo build --workspace`
   - Capture build output
   - Verify exit code 0

2. **Warning audit**
   - Compare warnings against baseline
   - Document any new warnings
   - Classify new warnings: acceptable, needs fix, blocking

3. **Test execution**
   - Run `cargo test --workspace --no-run` (compilation)
   - Run `cargo test --workspace`
   - Document test results (passing, failing, pre-existing failures)

4. **Clippy compliance**
   - Run `cargo clippy --workspace -- -D warnings`
   - Document clippy violations
   - Classify: fixable, acceptable deviation, blocking

5. **Package/build sanity** (if release mode)
   - Verify Tauri build succeeds
   - Verify frontend builds
   - Verify package contents

**Acceptable Baseline Issues** (document, do not fail):
- Pre-existing test failures documented in `KNOWN_GAPS.md`
- Documented warnings in `WARNINGS_REPORT.md`
- Stubbed features correctly marked as stubs

**Blocking Issues** (fail mode):
- Build errors (`error[E`)
- New test failures (regression)
- Clippy errors that indicate real bugs

---

### Phase 3 — Runtime Validation

**Objective:** Verify sidecar and runtime are healthy.

1. **Sidecar binary presence**
   - Verify `forensic_cli.exe` exists at expected path
   - Verify version matches workspace version

2. **Sidecar health**
   - Run `forensic_cli doctor --json-result <temp>`
   - Verify envelope status "ok"
   - Verify all diagnostic checks pass

3. **CLI command sanity**
   - Run `forensic_cli --help`
   - Verify all 40+ commands listed
   - Run `forensic_cli capabilities --json-result <temp>`
   - Verify envelope structure matches `COMMAND_CONTRACTS.md`

4. **Command envelope validation**
   - Run selected commands with `--json-result`
   - Verify envelope fields: `tool_version`, `timestamp_utc`, `status`, `elapsed_ms`
   - Verify warning and error fields are present when expected
   - Verify no `unwrap()` crashes in stderr

5. **Model and KB bridge validation**
   - Verify `llama-server.exe` present and version matches
   - Verify KB bridge health on port 8090
   - Verify no Qwen references in active logs
   - Verify model path points to correct Llama GGUF file

6. **History and log currency**
   - Check logs directory for recent entries
   - Verify no stale data from previous sessions
   - Verify correct bridge version in startup logs

**Reference:** `STRATA_RUNTIME_AUDIT_CHECKLIST.md` Sections 3-5

**Blocking Issues** (fail mode):
- Sidecar binary missing
- Version mismatch between components
- Doctor command fails
- Invalid envelope structure

---

### Phase 4 — Ingest Validation

**Objective:** Verify evidence processing from container open through artifact extraction.

1. **Container open**
   - Run `forensic_cli open-evidence <test_evidence> --json-result <temp>`
   - Verify container type recognized correctly
   - Verify container size matches
   - Verify evidence hashes computed

2. **Partition/volume discovery**
   - Verify partitions detected
   - Verify partition offsets accurate
   - Verify partition type recognized
   - Verify BitLocker detection (if applicable)

3. **Filesystem detection**
   - Verify filesystem signature detected
   - Verify filesystem metadata parsed
   - Verify encryption status flagged

4. **Enumeration**
   - Run `forensic_cli filetable <evidence> --json-result <temp>`
   - Verify file count reasonable for evidence size
   - Verify enumeration time plausible (not instant for large evidence)
   - Verify directory structure preserved

5. **Indexing and parsing**
   - Verify parser registration via `capabilities`
   - Verify parsers matched to evidence files
   - Verify artifact count reasonable
   - Verify zero-row results handled correctly per `TRUTHFULNESS_RULES.md` Rule 4

6. **Tree and filetable**
   - Verify tree populated with directory hierarchy
   - Verify filetable entry count matches enumeration
   - Verify path correctness (evidence-relative, not working directory)
   - Verify pagination works

7. **Artifact and timeline**
   - Run `forensic_cli timeline --case <case> --json-result <temp>`
   - Verify timeline entry count matches parser output
   - Verify artifact type distribution matches evidence content
   - Verify no placeholder rows (TBD, TODO, STUB, Default::default())

8. **GUI status correctness** (via Tauri)
   - Verify evidence loaded indicator
   - Verify file count display matches CLI
   - Verify artifact count display matches CLI
   - Verify warnings visible
   - Verify partial result labeling

**Reference:** `STRATA_INGEST_VALIDATION_CHECKLIST.md` Layers 1-9

**Blocking Issues** (fail mode):
- Container opens but returns zeros for all reads (Pattern 10)
- Filesystem detected but tree empty with no warning (Pattern 3)
- Zero-row results presented as successful indexing (Rule 4)
- Placeholder or synthetic artifacts present (Rule 5)
- Instant completion for large evidence (Pattern 1)

---

### Phase 5 — GUI/CLI Contract Validation

**Objective:** Verify each GUI page respects CLI command contracts.

1. **Page-by-page contract review**
   - Dashboard: `capabilities`, `doctor`, `smoke-test`
   - Case Overview: `verify`, `case list`
   - Evidence Sources: `open-evidence`, `open-evidence list`
   - File Explorer: `filetable`, `load_evidence_and_build_tree`
   - Timeline: `timeline`
   - Artifacts: `examine`, filtered `timeline`
   - Hash Sets: `hashset list`, `hashset stats`
   - Logs: `activity_log`
   - Settings: `capabilities`, config
   - Integrity Watchpoints: `watchpoints`, `violations`

2. **For each page, verify:**
   - Claims match what CLI commands actually return
   - Counts displayed match envelope field values
   - Warnings and errors from CLI are preserved in GUI
   - Fallback modes are labeled (e.g., regex-token)
   - Empty states are clearly labeled, not conflated with success

3. **Envelope field extraction**
   - Verify GUI parses envelope correctly
   - Verify GUI handles missing fields gracefully
   - Verify GUI does not assume fields exist that CLI did not return

**Reference:** `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` Sections 1-8

**Blocking Issues** (fail mode):
- GUI claims exceed CLI reality (Rule 8)
- CLI warnings dropped in GUI (Rule 9)
- Zero-row results displayed as "Analysis Complete" (Rule 4)
- Fallback modes not labeled (Rule 7)

---

### Phase 6 — Parser / Capability Review

**Objective:** Validate parser quality for new or modified parsers.

1. **Parser identity and naming**
   - Verify `name()` returns descriptive name
   - Verify `artifact_type()` follows naming conventions
   - Verify `target_patterns()` returns non-empty vector

2. **Parser contract compliance**
   - Verify `parse_file` signature: `Result<Vec<ParsedArtifact>, ParserError>`
   - Verify appropriate `ParserError` variants used
   - Verify no bare `unwrap()` or `expect()`

3. **Evidence-derived output**
   - Verify no invented artifacts
   - Verify no `Default::default()` artifacts
   - Verify field completeness (source_path, timestamp, json_data)

4. **Error handling**
   - Verify explicit empty results, not silent failure
   - Verify graceful format rejection, not panic
   - Verify provenance (source_path points to evidence, not working directory)

5. **Capability gap review**
   - Cross-reference `capabilities` output with `KNOWN_GAPS.md`
   - Verify new capabilities are documented
   - Verify stubbed features are correctly marked

6. **Stub/partial feature review**
   - Verify stubbed parsers return explicit `Ok(vec![])`
   - Verify stubbed containers show appropriate warnings
   - Verify partial features (VHD, VMDK) are labeled

**Reference:** `STRATA_PARSER_REVIEW_CHECKLIST.md` Sections 1-10

**Blocking Issues** (fail mode):
- Invented or synthetic artifacts (immediate escalation)
- `Default::default()` usage on error paths
- Silent error-to-empty conversion
- Missing provenance fields

---

### Phase 7 — Release Verdict

**Objective:** Synthesize findings and render final verdict.

1. **Classify all findings**
   - CRITICAL: Truthfulness violations, evidence fabrication, silent failures
   - HIGH: Runtime failures, GUI/CLI mismatches, unresolved warnings
   - MEDIUM: Non-blocking issues, known gaps, partial features
   - LOW: Cosmetic issues, documentation gaps

2. **Render verdict**

   | Condition | Verdict |
   |-----------|---------|
   | Zero critical issues, zero high issues | **PASS** |
   | Zero critical issues, high issues documented | **PASS WITH WARNINGS** |
   | Critical issues present but bounded | **PARTIAL / NOT READY** |
   | Any truthfulness violation, evidence fabrication | **FAIL** |
   | Critical runtime failures, sidecar/model mismatch | **FAIL** |

3. **Document top blockers**
   - List all critical and high issues
   - For each issue, note: what failed, where observed, expected vs. actual, recommended fix

4. **Update guardian knowledge base**
   - Update `KNOWN_GAPS.md` if new gaps discovered
   - Update `WARNINGS_REPORT.md` if new warnings found
   - Document new failure patterns in `RUNTIME_FAILURE_PATTERNS.md` if applicable
   - Log the audit in the audit history

---

## Exact Inputs and Outputs

### Inputs

| Input | Source | Purpose |
|-------|--------|---------|
| Source code | `D:\forensic-suite\` | Build, runtime behavior |
| Build outputs | `target/debug/`, `target/release/` | Binary presence, version |
| Test suite | `cargo test --workspace` | Test pass/fail |
| Clippy output | `cargo clippy --workspace` | Code quality |
| CLI command output | `forensic_cli <command> --json-result` | Runtime behavior |
| Envelope data | JSON files from `--json-result` | Truthfulness validation |
| KB bridge health | `http://127.0.0.1:8090/health` | Bridge status |
| Logs | `logs/`, `D:\DFIR Coding AI\logs\` | History, errors |
| Evidence fixtures | Test images, synthetic files | Ingest validation |
| Guardian documents | `D:\forensic-suite\guardian\` | Baseline, contracts |
| Command contracts | `COMMAND_CONTRACTS.md` | Expected output shapes |
| Known gaps | `KNOWN_GAPS.md` | Baseline limitations |
| Prior audit reports | Audit history | Delta comparison |

### Outputs

| Output | Destination | Purpose |
|--------|-------------|---------|
| Audit report | `D:\forensic-suite\guardian\AUDIT_REPORTS\` | Complete findings |
| Pass/fail verdict | Audit report header | Operational decision |
| Issue list | Audit report Section X | Detailed findings |
| Command outputs | Audit report appendices | Evidence of checks |
| Build logs | Audit report appendices | Build validation |
| Envelope samples | Audit report appendices | Runtime validation |
| Recommended next actions | Audit report Section Y | Remediation guidance |

---

## Required Evidence to Collect

During an audit, Strata must capture or cite:

### Build Evidence
- [ ] `cargo build --workspace` output (exit code, errors)
- [ ] `cargo test --workspace` output (test results)
- [ ] `cargo clippy --workspace` output (linting)
- [ ] Warning count comparison vs. baseline

### Runtime Evidence
- [ ] `forensic_cli doctor` envelope (JSON)
- [ ] `forensic_cli capabilities` envelope (JSON)
- [ ] Sample command envelopes for key commands (`open-evidence`, `filetable`, `timeline`)
- [ ] KB bridge health response
- [ ] Llama server startup log excerpt
- [ ] Current log file timestamps

### Ingest Evidence
- [ ] `open-evidence` output for test container
- [ ] `filetable` output (entry count, sample entries)
- [ ] `timeline` output (entry count, sample entries)
- [ ] Any warnings or errors in envelopes

### GUI Evidence (if running full audit)
- [ ] Screenshot or CLI verification of key page displays
- [ ] Command-to-field mapping for each page
- [ ] Warning/error preservation verification

### Package Evidence (if release mode)
- [ ] Package contents list
- [ ] Sidecar binary hash
- [ ] Model file presence/absence verification

---

## Decision Rules

These rules are non-negotiable. Violating them produces false forensic conclusions.

### Rule A: Zero-Row Success Cannot Be Treated as a Pass

```
IF command returns:
  - status: "ok"
  - data: { entries: [] }  OR  count: 0
THEN
  - Must have warning field explaining empty result
  - OR evidence must be verified empty-by-design
  - Cannot be labeled "successful indexing"
```

**Violation response:** Flag as **UNEXPLAINED_EMPTY** → PARTIAL at minimum.

---

### Rule B: Synthetic Placeholders Counted as Evidence = Automatic Failure

```
IF any parser output contains:
  - "TBD", "TODO", "STUB", "implement me", "placeholder"
  - Default::default() artifacts
  - Invented timestamps or hashes
THEN verdict = FAIL
```

**Violation response:** Immediate escalation, block operation.

---

### Rule C: GUI Claims Exceeding CLI Reality

```
IF GUI displays:
  - A count that exceeds CLI envelope value
  - A capability that CLI does not return
  - "Complete" when CLI shows warnings
THEN verdict = FAIL (severity: truthfulness violation)
```

**Severity escalation:**
- Count mismatch of 1+ → FAIL
- Missing warning surfacing → FAIL WITH WARNINGS minimum
- Missing fallback label → PASS WITH WARNINGS minimum

---

### Rule D: Unsupported Format Claimed as Supported

```
IF format listed as:
  - "complete" in GUI
  - "implemented" in capabilities
BUT
  - Marked as STUB or PARTIAL in KNOWN_GAPS.md
THEN verdict = FAIL
```

**Reference:** `KNOWN_GAPS.md` Section A.2, B.2

---

### Rule E: Missing Sidecar or Model Identity Mismatch

```
IF forensic_cli binary:
  - Does not exist at expected path
  - Version mismatch with workspace
  - Different binary than packaged version
THEN verdict = FAIL
```

```
IF llama model:
  - Points to wrong file (e.g., Qwen instead of Llama)
  - Not found at configured path
  - Model hash mismatch with expected
THEN verdict = FAIL (critical infrastructure issue)
```

---

### Rule F: Partial but Labeled Fallback May Be Acceptable

```
IF fallback is:
  - Correctly labeled in UI (e.g., "(fallback)" or "(degraded mode)")
  - Documented in KNOWN_GAPS.md
  - Warning present in envelope
THEN verdict = PASS WITH WARNINGS (acceptable)
```

**Reference:** `TRUTHFULNESS_RULES.md` Rule 7

---

### Rule G: Envelope Status Truthfulness

```
IF envelope shows:
  - status: "ok" but exit_code != 0
  - status: "error" but no error field present
  - status: "ok" but elapsed_ms implausibly low for evidence size
THEN flag as truthfulness violation
```

**Reference:** `COMMAND_CONTRACTS.md` Section F, `RUNTIME_FAILURE_PATTERNS.md` Pattern 1

---

## Escalation Rules

Strata must escalate instead of issuing a clean verdict when:

### Uncertainty in Runtime Behavior
- CLI command returns unexpected envelope structure
- Runtime behavior differs from documented in `COMMAND_CONTRACTS.md`
- Cannot determine if result is legitimate or failure pattern

**Response:** Issue PARTIAL verdict, document uncertainty, recommend manual verification.

### Conflicting Reports
- KB bridge health reports OK, but chat responses fail
- GUI shows different data than CLI returned
- Logs show inconsistency with recent commands

**Response:** Issue PARTIAL verdict, identify source of conflict, escalate to human reviewer.

### Stale History vs. Current State Ambiguity
- Logs show timestamps from previous sessions
- Audit trail has gaps
- Cannot determine if data is current or cached

**Response:** Issue PARTIAL verdict, recommend fresh state, flag stale data issue.

### Missing Evidence Fixtures
- Required test evidence not available
- Cannot validate a specific capability due to missing fixture
- Synthetic test data not representative of real evidence

**Response:** Issue PASS WITH WARNINGS, document limitation, recommend fixture procurement.

### Environment-Specific Build/Platform Issues
- Build succeeds on one platform, fails on another
- Platform-specific warnings that are not blocking on primary platform
- Environment variable dependencies not documented

**Response:** Document per-platform, issue PASS WITH WARNINGS for affected platform.

### Incomplete Validation of Packaging/Runtime
- Cannot verify packaged binary hash match source
- Cannot test portable deployment in isolation
- Startup scripts have environment-specific paths

**Response:** Issue PARTIAL verdict, document incomplete validation, recommend post-deployment verification.

---

## Final Audit Report Template

```markdown
# ForensicSuite Audit Report

**Audit ID:** [AUDIT-YYYYMMDD-NNN]  
**Date:** [ISO 8601 timestamp]  
**Auditor:** Strata  
**Mode:** [Quick Health | Build/Test | Ingest | GUI/CLI | Release Readiness | Full Guardian]  
**Environment:** [OS, tool versions, paths]  

---

## Executive Summary

[Brief statement of verdict and top finding. One paragraph.]

**Final Verdict:** [PASS | PASS WITH WARNINGS | PARTIAL / NOT READY | FAIL]

---

## Scope

[What was audited. Which phases completed. What was skipped and why.]

---

## Findings

### Critical Issues (Blocking)

| # | Issue | Location | Expected | Observed | Recommended Fix |
|---|-------|----------|----------|----------|----------------|
| C1 | | | | | |

### High Issues

| # | Issue | Location | Severity | Recommended Fix |
|---|-------|----------|----------|----------------|
| H1 | | | | |

### Medium Issues

| # | Issue | Location | Notes |
|---|-------|----------|-------|
| M1 | | | |

### Low Issues

| # | Issue | Notes |
|---|-------|-------|
| L1 | | |

---

## Verified Truths

[List of things that are confirmed working and trustworthy. Evidence citations.]

---

## Unresolved Uncertainties

[List of things that could not be verified. Reason for uncertainty. Recommended action.]

---

## Evidence Collected

- [Command output file 1]
- [Envelope JSON file 1]
- [Build log excerpt]
- [Other evidence]

---

## Guardian Document Updates

[Any changes needed to KNOWN_GAPS.md, WARNINGS_REPORT.md, RUNTIME_FAILURE_PATTERNS.md, etc.]

---

## Next Actions

1. [Priority 1 action with owner]
2. [Priority 2 action with owner]
3. [Priority 3 action with owner]

---

## Audit Completion

| Phase | Status | Notes |
|-------|--------|-------|
| 1. Establish Reality | [DONE/SKIPPED] | |
| 2. Build/Test | [DONE/SKIPPED] | |
| 3. Runtime | [DONE/SKIPPED] | |
| 4. Ingest | [DONE/SKIPPED] | |
| 5. GUI/CLI | [DONE/SKIPPED] | |
| 6. Parser Review | [DONE/SKIPPED] | |
| 7. Verdict | [DONE] | |

**Verdict Rendered:** [PASS | PASS WITH WARNINGS | PARTIAL | FAIL]  
**Report Filed:** [YYYY-MM-DD]  
**Next Scheduled Audit:** [Date or "As triggered"]
```

---

## Operating Philosophy

Strata closes every audit with a reminder of why this work matters.

### Strata Protects Truth, Not Appearances

The suite may have gaps. Those gaps are acceptable if documented and labeled. What is never acceptable is presenting a gap as a success, presenting empty as complete, or presenting uncertainty as fact. Strata values truthfulness over the appearance of capability.

### Strata Protects Evidence Integrity, Not Convenience

When evidence is processed, it must be processed correctly. Speed is not more important than accuracy. Simplicity is not more important than correctness. Strata will recommend slower, more rigorous paths when they protect evidence integrity.

### Strata Escalates Uncertainty Instead of Masking It

When Strata cannot verify a claim, Strata says so. When Strata encounters behavior it cannot explain, Strata flags it. Strata does not guess, does not assume, and does not paper over uncertainty with optimistic labels. Escalation is not failure—it is the responsible choice when verification is incomplete.

### Strata Only Grants Trust When Evidence Supports It

Every capability claimed by the suite must have evidence. Every artifact displayed to an examiner must trace to actual evidence. Every verdict rendered by Strata must trace to observable behavior. Trust is earned through verification, not assumed through documentation.

---

## Document Maintenance

**Last Updated:** 2026-03-23  
**Next Review:** 2026-06-23 (quarterly)  
**Update Triggers:**
- New audit mode required
- New guardian documents added to knowledge base
- Phase or checklist structure changes
- Decision rules require modification
- New escalation scenarios discovered

**Location:** `D:\forensic-suite\guardian\RUN_STRATA_SUITE_AUDIT.md`
