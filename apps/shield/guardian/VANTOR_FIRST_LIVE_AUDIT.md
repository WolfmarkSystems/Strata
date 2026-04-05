# Strata Shield — First Live Audit Walkthrough

**Document Type:** First Live Audit Runbook  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Authority:** Strata — Suite Guardian  
**Audience:** Strata and human operator conducting first real audit  
**Status:** Execute Now — This is the first real validation of the suite

---

> **What this document is:** This is your "execute this now" guide to running the first real, end-to-end audit of the ForensicSuite in its current state.  
> **What it isn't:** This is not a tutorial on what Strata is (see `STRATA_OPERATOR_QUICKSTART.md`). It's not a reference document (see `STRATA_SHIELD_MASTER_INDEX.md`). It is the operational walkthrough for executing the audit.  
> **Prerequisite:** Before running this audit, you should be familiar with how Strata works. If not, start with the quickstart.

---

## Section 1 — Purpose

### What This First Live Audit Is

This is the first comprehensive audit of the ForensicSuite using Strata Shield's full operational capability. Unlike unit tests or manual checks, this audit validates the entire stack — from build through runtime through GUI — against the guardian doctrine.

### Why It Matters

The guardian knowledge base exists, but it hasn't been validated against the live system yet. This first audit:
- Validates that the documentation matches reality
- Establishes the current trust boundaries
- Identifies what's working vs. what's broken
- Provides a baseline for all future audits
- Proves that Strata can execute its mission

### What Success Looks Like

A successful first live audit produces:
- A completed audit report using `STRATA_AUDIT_REPORT_TEMPLATE.md`
- A clear verdict: PASS / PASS WITH WARNINGS / PARTIAL / NOT READY / FAIL
- A list of verified truths (what works)
- A list of failures and gaps (what doesn't work)
- A list of unresolved uncertainties (what needs more investigation)
- Prioritized next actions for engineering

### What Kind of Verdict/Report Should Come Out

Given this is the first audit of an unfinished system (per `KNOWN_GAPS.md` there are known test failures, clippy errors, and stubbed features), the expected verdict is **PASS WITH WARNINGS** or **PARTIAL / NOT READY**. A clean PASS would be suspicious — the system has documented gaps.

The report should honestly document what's working, what's not, and what remains uncertain.

---

## Section 2 — Audit Scope for the First Live Run

This first audit covers the full stack:

### Build and Test State
- [ ] `cargo build --workspace` compiles without errors
- [ ] `cargo test --workspace` test results (known failures expected per `KNOWN_GAPS.md` Section G)
- [ ] `cargo clippy --workspace` results (known violations expected)

### GUI-Tauri Build/Package State
- [ ] `cargo tauri build` succeeds (or documented limitations)
- [ ] Frontend builds if possible (per `KNOWN_GAPS.md` Section E, esbuild may have issues)
- [ ] Package contains required artifacts

### Sidecar/Runtime Health
- [ ] `forensic_cli.exe` binary exists and is runnable
- [ ] `forensic_cli doctor` returns valid envelope
- [ ] KB bridge (`dfir_kb_bridge.py`) is running
- [ ] Llama server (`llama-server.exe`) is running (if AI features used)

### Model/Runtime Identity
- [ ] Correct model loaded (Llama, not Qwen)
- [ ] Model path matches configuration
- [ ] No stale model references in logs

### Evidence Ingest Truthfulness
- [ ] Container open produces valid envelopes
- [ ] Partition/filesystem detection works (or is honestly labeled partial)
- [ ] Enumeration produces real file counts (not instant-zero)
- [ ] Parsers produce evidence-derived output (not placeholders)
- [ ] Timeline contains real artifacts (not synthetic)

### GUI/CLI Contract Truthfulness
- [ ] Dashboard matches CLI reality
- [ ] Evidence Sources page matches CLI reality
- [ ] File Explorer page matches CLI reality
- [ ] Timeline page matches CLI reality
- [ ] Artifacts page matches CLI reality
- [ ] Hash Sets page matches CLI reality
- [ ] Warnings from CLI are surfaced in GUI
- [ ] Partial results are labeled in GUI

### Current Known Gaps Validation
- [ ] Verify VHD/VMDK partial status matches `KNOWN_GAPS.md`
- [ ] Verify BitLocker detection-only status matches docs
- [ ] Verify stubbed parsers are correctly marked
- [ ] Verify hashset read-only status is honest

---

## Section 3 — Preconditions

Before starting the first live audit, verify these are available:

### Repository Access
- [ ] Read access to `D:\forensic-suite\` workspace root
- [ ] Read access to `D:\forensic-suite\guardian\` knowledge base
- [ ] Read access to `D:\forensic-suite\gui-tauri\` frontend

### Build Tools
- [ ] Rust toolchain accessible via `cargo --version` (expected 1.70+)
- [ ] Node.js accessible via `node --version` (expected 18+)
- [ ] npm accessible via `npm --version` (expected 9+)

### GUI-Tauri
- [ ] Tauri build tools accessible
- [ ] `gui-tauri/src-tauri/` directory exists

### DFIR Coding AI / Strata Runtime
- [ ] Llama server accessible at expected path (or documented location)
- [ ] KB bridge (`dfir_kb_bridge.py`) accessible
- [ ] Model files in expected location (or documented)

### Evidence Fixtures
- [ ] Test evidence available (RAW, E01, or directory)
- [ ] Evidence path is valid

### Guardian Docs
- [ ] `SUITE_GUARDIAN_PROFILE.md` readable
- [ ] `TRUTHFULNESS_RULES.md` readable
- [ ] `KNOWN_GAPS.md` readable
- [ ] `RUN_STRATA_SUITE_AUDIT.md` readable
- [ ] `STRATA_AUDIT_REPORT_TEMPLATE.md` readable

### Audit Template
- [ ] Empty audit report template available at `STRATA_AUDIT_REPORT_TEMPLATE.md`
- [ ] Output directory `D:\forensic-suite\guardian\AUDIT_REPORTS\` exists or can be created

---

## Section 4 — First Live Audit Sequence

Follow this exact sequence for the first live audit:

---

### Phase 1 — Establish Current Branch/Environment Reality

**Objective:** Understand what version of the suite you're auditing.

1. **Check git status**
   ```bash
   cd D:\forensic-suite
   git status
   git log --oneline -10
   git branch
   ```
   - Record branch name and commit hash
   - Note if you're on main or a feature branch

2. **Review `KNOWN_GAPS.md` Section G (Test Coverage)**
   - Confirm the known failures: `missing field blake3 in HashResults`, clippy errors
   - These are expected — don't treat them as new findings

3. **Check for recent changes**
   - Look at recent commits
   - Identify what code areas changed recently

**What to collect:**
- Branch name, commit hash
- Recent commit list
- Any uncommitted changes

**Pass criteria:** You know what version you're testing. Known gaps are accounted for.

**Fail condition:** Can't determine version — escalate.

---

### Phase 2 — Run Build/Test Checks

**Objective:** Verify the workspace builds and tests.

1. **Run workspace build**
   ```bash
   cd D:\forensic-suite
   cargo build --workspace 2>&1 | tee build_output.txt
   ```
   - Capture output
   - Note any `error[E` compilation errors

2. **Run test compilation (no execution)**
   ```bash
   cargo test --workspace --no-run 2>&1 | tee test_compile_output.txt
   ```

3. **Run clippy**
   ```bash
   cargo clippy --workspace -- -D warnings 2>&1 | tee clippy_output.txt
   ```

4. **Compare against baseline**
   - Check `WARNINGS_REPORT.md` if it exists
   - Count current warnings vs. baseline

**What to collect:**
- Build output file
- Test compilation output
- Clippy output
- Warning count comparison

**Reference:** `STRATA_RUNTIME_AUDIT_CHECKLIST.md` Section 1 (Build Validation)

**Pass criteria:** Build completes (errors are known from `KNOWN_GAPS.md`). Test compilation may fail (known). Clippy failures expected (known).

**Fail condition:** New compilation errors not in `KNOWN_GAPS.md` — this is a finding.

---

### Phase 3 — Validate Sidecar/Runtime/Model State

**Objective:** Verify the Strata Shield runtime components are healthy.

1. **Check KB bridge health**
   ```bash
   curl http://127.0.0.1:8090/health
   ```
   - Verify `status: ok`
   - Verify shows "Strata KB Bridge" (not old name)
   - Note `embedding_backend` status

2. **Check Llama server**
   ```bash
   curl http://127.0.0.1:8080/api/tags
   ```
   - Verify model loaded
   - Verify correct model (Llama, not Qwen)

3. **Check forensic_cli doctor**
   ```bash
   forensic_cli doctor --json-result doctor_envelope.json
   type doctor_envelope.json
   ```
   - Verify status is "ok"
   - Check all diagnostic fields

4. **Check forensic_cli capabilities**
   ```bash
   forensic_cli capabilities --json-result capabilities_envelope.json
   type capabilities_envelope.json
   ```
   - Note capability count
   - Verify structure matches `COMMAND_CONTRACTS.md`

**What to collect:**
- KB bridge health response (JSON)
- Llama server tags response
- Doctor envelope (JSON)
- Capabilities envelope (JSON)

**Reference:** `STRATA_RUNTIME_AUDIT_CHECKLIST.md` Sections 3-4 (Sidecar/Runtime Validation)

**Pass criteria:** All services respond, correct model loaded, doctor passes.

**Fail condition:** Wrong model (Qwen instead of Llama), wrong bridge name, doctor fails — escalate immediately.

---

### Phase 4 — Validate Command Health

**Objective:** Verify CLI commands produce truthful envelopes.

1. **Run sample commands and verify envelopes**
   ```bash
   # Test a command that should return data
   forensic_cli capabilities --json-result cmd_cap.json
   
   # Test a command with --help
   forensic_cli --help > help_output.txt
   ```
   - Verify envelope structure matches `COMMAND_CONTRACTS.md`
   - Verify status fields are accurate

2. **Check for instant completion pattern**
   - Look at `elapsed_ms` in envelopes
   - Flag any that are implausibly fast (<100ms for significant work)

3. **Verify envelope status truthfulness**
   - Run a command with invalid input
   - Verify status is "error" not "ok"

**What to collect:**
- Sample command envelopes
- Help output
- Any envelope anomalies

**Reference:** `STRATA_RUNTIME_AUDIT_CHECKLIST.md` Section 4 (Command Validation)

**Pass criteria:** Envelopes match contracts, status fields accurate, no instant-completion anomalies.

**Fail condition:** Envelope structure doesn't match contract, status inaccurate — this is a finding.

---

### Phase 5 — Perform Ingest Validation on Current Evidence

**Objective:** Verify evidence processing produces truthful output.

1. **Run open-evidence on test fixture**
   ```bash
   forensic_cli open-evidence "<test_evidence_path>" --json-result open_evidence.json
   ```
   - Verify container type detected
   - Verify container size
   - Check for warning field
   - Verify `filesystems` field (may be empty if enumeration failed)

2. **Run filetable**
   ```bash
   forensic_cli filetable "<test_evidence_path>" --json-result filetable.json
   ```
   - Check entry count
   - Verify count is proportional to evidence size
   - Check `elapsed_ms` is plausible

3. **Run timeline (if case exists)**
   ```bash
   forensic_cli timeline --case <case_name> --json-result timeline.json
   ```
   - Check entry count
   - Verify no placeholder rows ("TBD", "STUB", etc.)
   - Verify `source_path` present on artifacts
   - Check for warning field

**What to collect:**
- Open-evidence envelope
- Filetable envelope
- Timeline envelope (if applicable)
- Any warnings/errors

**Reference:** `STRATA_INGEST_VALIDATION_CHECKLIST.md` Layers 1-9

**Pass criteria:** No truthfulness violations. Zero-row results have warnings or are verified empty-by-design. No placeholders in output.

**Fail condition:** Zero-row without warning, placeholders in output, instant completion — escalate immediately.

---

### Phase 6 — Validate GUI Truthfulness Page by Page

**Objective:** Verify GUI doesn't claim more than CLI returns.

For each major GUI page, compare what the page displays against what the CLI returns:

1. **Dashboard** — Compare page claims vs. `capabilities` and `doctor` output
2. **Evidence Sources** — Compare page claims vs. `open-evidence` output
3. **File Explorer** — Compare page claims vs. `filetable` output
4. **Timeline** — Compare page claims vs. `timeline` output
5. **Artifacts** — Compare page claims vs. timeline/artifacts output
6. **Hash Sets** — Compare page claims vs. `hashset list` output

**Key checks:**
- Are counts in GUI matching CLI envelope values?
- Are warnings from CLI visible in GUI?
- Are partial results labeled?
- Are empty results clearly labeled (not "Analysis Complete")?

**What to collect:**
- Page-by-page comparison notes
- Any mismatches identified
- Warning preservation check results

**Reference:** `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` Section 6 (Page-by-Page Contract Review)

**Pass criteria:** No overclaiming. Warnings preserved. Partial states labeled.

**Fail condition:** GUI claims exceed CLI reality — this is a SEV-2 finding.

---

### Phase 7 — Check Fallback/Partial Behaviors

**Objective:** Verify partial implementations are honestly labeled.

1. **Check embedding backend**
   - From KB bridge health, check `embedding_backend` field
   - If "regex-token", verify labeled as "(fallback)" in UI

2. **Check container format behavior**
   - If VHD/VMDK tested, verify partial warning shown
   - Verify not labeled as "complete"

3. **Check hashset behavior**
   - Verify hashset page shows "Read-Only" if editing not implemented

4. **Check BitLocker**
   - If BitLocker detected, verify labeled as "detection only"

**What to collect:**
- Fallback labeling status
- Partial format behavior notes

**Reference:** `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` Section 4 (Fallback Mode Visibility)

**Pass criteria:** Fallbacks labeled. Partial formats not claimed as complete.

**Fail condition:** Fallbacks not labeled — document as issue.

---

### Phase 8 — Produce Final Verdict/Report

**Objective:** Document everything and render verdict.

1. **Use `STRATA_AUDIT_REPORT_TEMPLATE.md`**
   - Fill in all sections
   - Document all findings

2. **Classify findings by severity:**
   - CRITICAL — Truthfulness violations
   - HIGH — Significant issues affecting trust
   - MEDIUM — Non-blocking issues
   - LOW — Cosmetic/minor issues

3. **Render verdict:**
   | Condition | Verdict |
   |-----------|---------|
   | Zero critical issues | PASS WITH WARNINGS |
   | Critical issues, bounded | PARTIAL / NOT READY |
   | Any truthfulness violation | FAIL |

4. **Identify next actions:**
   - Top 5 engineering actions prioritized

**What to produce:**
- Completed audit report
- Final verdict
- Issue list
- Verified truths list
- Unresolved uncertainties list
- Next actions list

**Reference:** `STRATA_AUDIT_REPORT_TEMPLATE.md` (full template)

---

## Section 5 — High-Priority Checks for This First Audit

These are the most important checks for this first live audit. They are your "don't miss these" list:

### Check 1: No Instant Indexing with No Real Data
- Run evidence commands, check `elapsed_ms`
- If <100ms for evidence processing, flag as suspicious

### Check 2: Zero Rows Are Not Mislabeled as Success
- Check any command returning 0 entries
- Verify warning field present OR source verified empty
- Flag if labeled as "successful indexing"

### Check 3: Placeholders Not Counted as Evidence
- Search timeline/artifacts for "TBD", "TODO", "STUB"
- Check for `Default::default()` in outputs

### Check 4: Timeline Real/Fallback Mode Truthful
- Verify timeline shows actual artifact count
- Check for fallback labels if applicable

### Check 5: Artifacts Page Real Data Only
- Verify artifacts have `source_path`
- Verify no placeholder descriptions

### Check 6: Hashset Page Honest About No Loaded Sets
- Verify if no hashsets loaded, it's labeled as such
- Not claiming "analyzed" when nothing loaded

### Check 7: File Explorer Shows Real Data Only
- Verify file counts match CLI
- Verify no fake directories

### Check 8: Sidecar/Model/Runtime Identity Correct
- Verify correct model (Llama, not Qwen)
- Verify correct bridge ("Strata KB Bridge")
- Verify doctor passes

### Check 9: Package Assumptions Honest
- If release build, verify what's actually included
- Don't assume package is complete — check it

---

## Section 6 — Expected Outputs

The first live audit should produce:

### Filled Audit Report
- Complete all sections of `STRATA_AUDIT_REPORT_TEMPLATE.md`
- Document evidence for all findings

### Final Verdict
- Expected: **PASS WITH WARNINGS** or **PARTIAL / NOT READY**
- (Clean PASS would be suspicious given known gaps)

### Prioritized Issue List
- All findings classified by severity
- Top issues flagged for immediate attention

### Verified Truths
- What actually works
- What's been validated against runtime

### Unresolved Uncertainties
- What couldn't be verified
- What needs more evidence or fixtures

### Recommended Next Engineering Actions
- Top 5 actions prioritized
- What to fix next

---

## Section 7 — Failure / Escalation Conditions

These conditions should immediately escalate the first live audit:

### Build/Test Failure Affecting Trustworthiness
- New compilation errors not in `KNOWN_GAPS.md`
- Test failures indicating regression

### Ingest False-Success Behavior
- Zero-row with "ok" status and no warning
- Instant completion pattern
- Placeholder artifacts in output

### GUI Overclaiming Beyond CLI Reality
- GUI shows fields CLI doesn't return
- Counts don't match
- Warnings suppressed

### Model/Runtime Mismatch
- Wrong model loaded (Qwen instead of Llama)
- Wrong bridge version
- Doctor fails

### Sidecar/Package Mismatch
- Binary version doesn't match source
- Package missing critical components

### Inability to Reproduce Current Truth State
- Can't verify known gaps against runtime
- Can't determine what's actually working

---

## Section 8 — Final Report Instructions

To finish the first live audit:

### Use the Template
Open `STRATA_AUDIT_REPORT_TEMPLATE.md` and fill in every section.

### Summarize Verified Truths
List what's working — what Strata validated and confirmed.

### Summarize Failures and Gaps
List what's broken or missing — what's not working.

### Classify Final Verdict
Choose one:

| Verdict | When |
|---------|------|
| **PASS** | Everything critical works, no truthfulness violations |
| **PASS WITH WARNINGS** | Critical works, some non-blocking issues |
| **PARTIAL / NOT READY** | Significant gaps, manual review needed |
| **FAIL** | Critical truthfulness violations |

Given the known gaps (test compilation, clippy), expect **PASS WITH WARNINGS** or **PARTIAL**.

### Identify Top 5 Next Actions
1. Most important fix
2. Second most important
3. Third most important
4. Fourth most important
5. Fifth most important

---

## Section 9 — First Live Audit Doctrine

When conducting this first live audit, remember:

### The First Audit Is About Truth, Not Appearances

The goal is to establish what actually works, not to make the suite look good. Document reality — even if reality is partial.

### Unresolved Uncertainty Must Be Preserved in the Report

If you can't verify something, say so. Don't assume it's fine. Don't guess. Document the uncertainty — that's a finding.

### A Truthful Partial Verdict Is Better Than a False Pass

If the suite is partially broken, say it's partially broken. Calling it "ready" when it's not would betray the guardian mission.

### The First Live Audit Establishes Trust Boundaries for Everything That Comes After

This audit becomes the baseline. Everything after this is measured against this. If you miss something now, it won't be caught later. Be thorough. Be honest. Document everything.

---

> **Remember:** You are validating the guardian system against the live suite for the first time. This is proof that Strata can do its job. The output of this audit is what proves the guardian is operational. Be thorough. Be truthful. Trust the evidence.

---

**Start date:** 2026-03-23  
**Execute by:** As soon as preconditions are met  
**Location:** `D:\forensic-suite\guardian\STRATA_FIRST_LIVE_AUDIT.md`