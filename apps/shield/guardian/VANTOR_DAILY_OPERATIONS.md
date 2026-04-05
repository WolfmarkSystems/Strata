# Strata Shield — Daily Operations Playbook

**Document Type:** Operations Playbook  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Audience:** Developers, auditors, maintainers using Strata Shield  
**Status:** Practical daily-use guide

---

> **Use this document when:** You are working on the ForensicSuite day-to-day and need to know what Strata checks to run, when to run them, and how to respond to what you find. For a shorter intro, see `STRATA_OPERATOR_QUICKSTART.md`. For full procedures, see `RUN_STRATA_SUITE_AUDIT.md` and `RUN_STRATA_PARSER_REVIEW.md`.

---

## Section 1 — Purpose

This playbook describes how Strata Shield is used in day-to-day operation. It tells you what to check each day, which mode to run, what to do when you see warning signs, and how to document your findings.

### Who Uses This

| Role | Primary Use |
|------|------------|
| **Developer** | Quick health checks before/after coding, parser review before merge |
| **Auditor** | Daily validation during review cycles |
| **Maintainer** | Runtime health checks, model/bridge updates |
| **Release reviewer** | Pre-release sanity checks |

### When to Use This

Use this playbook during:
- Daily development sessions
- Parser code reviews
- Evidence processing troubleshooting
- GUI/CLI contract validation
- Pre-release checks
- Post-change validation

### How This Differs From Other Docs

| Document | Focus | Length |
|----------|-------|--------|
| `STRATA_OPERATOR_QUICKSTART.md` | What Strata is, what it can help with | ~350 lines |
| `STRATA_DAILY_OPERATIONS.md` | What to do day-to-day, step-by-step | ~400 lines |
| `RUN_STRATA_SUITE_AUDIT.md` | Full audit procedures | ~900 lines |
| `RUN_STRATA_PARSER_REVIEW.md` | Parser review SOP | ~600 lines |

This playbook is the middle ground: more actionable than the quickstart, lighter than the full runbooks.

---

## Section 2 — Daily Startup Routine

Every day, before you start coding, validating, or reviewing, run through this routine:

### Step 1: Check Current Branch / Workspace State

```bash
cd D:\forensic-suite
git status
git log --oneline -5  # recent commits
```

**What to look for:**
- Are you on a feature branch or main?
- What's been changed recently?
- Any merge conflicts or uncommitted changes?

**Why:** You need to know what you're working with before deciding what Strata checks to run.

### Step 2: Review Recent Known Gaps

Open `KNOWN_GAPS.md` and check:
- Any new gaps added since your last session?
- Any gaps marked as resolved that might affect your work?
- Section G (Test Coverage) status — are tests still failing?

**Why:** Gaps change the baseline for what you can trust.

### Step 3: Review Recent Audit Findings

Check `AUDIT_REPORTS/` (if it exists) for:
- Last audit date and verdict
- Any unresolved issues from prior audits
- Any blockers that might affect today's work

**Why:** You don't want to repeat work or miss issues already identified.

### Step 4: Verify Current Runtime/Model Identity

```bash
# Check KB bridge health
curl http://127.0.0.1:8090/health

# Check Llama model
curl http://127.0.0.1:8080/api/tags

# Check forensic_cli
forensic_cli doctor --json-result temp.json
```

**What to look for:**
- KB bridge shows "Strata KB Bridge" (not old name)
- Model is the expected Llama (not Qwen)
- CLI doctor returns status "ok"
- No new errors in logs

**Why:** A wrong model or stale bridge can produce incorrect validation results.

### Step 5: Decide Today's Mode

Based on what you're doing today, pick a mode from Section 3.

---

## Section 3 — Standard Daily Modes

Strata supports five standard daily modes. Pick the one that matches your work.

### Mode 1: Normal Development Day

**Typical goals:**
- Check that changes don't break the build
- Verify CLI still works
- Confirm runtime health

**Minimum Strata checks:**
1. Quick Health Audit (`RUN_STRATA_SUITE_AUDIT.md` Mode 1)
2. Check for new warnings in build (`cargo build --workspace`)
3. Run `forensic_cli doctor` to verify runtime

**Documents to use:**
- `STRATA_RUNTIME_AUDIT_CHECKLIST.md` (Sections 1-4)
- `RUN_STRATA_SUITE_AUDIT.md` (Mode 1)

**Expected output:** PASS / CONDITIONAL status, no new build errors.

---

### Mode 2: Parser Development / Parser Review Day

**Typical goals:**
- Review new parser code before merge
- Validate that parser produces evidence-derived output
- Check for dangerous patterns

**Minimum Strata checks:**
1. Run `RUN_STRATA_PARSER_REVIEW.md` (all 7 phases)
2. Complete `STRATA_PARSER_REVIEW_CHECKLIST.md` (21 items)
3. Verify test fixtures exist for the parser

**Documents to use:**
- `PARSER_CONVENTIONS.md`
- `TRUTHFULNESS_RULES.md` (Rules 3, 4, 5, 10)
- `RUNTIME_FAILURE_PATTERNS.md` (Patterns 1, 2, 8)
- `RUN_STRATA_PARSER_REVIEW.md`

**Expected output:** Parser review report with APPROVED / APPROVED WITH WARNINGS / REJECTED verdict.

---

### Mode 3: Ingest Troubleshooting Day

**Typical goals:**
- Figure out why evidence processing isn't working
- Check if parsing failed silently
- Verify that zero-row results are labeled correctly

**Minimum Strata checks:**
1. Ingest Validation Audit (`RUN_STRATA_SUITE_AUDIT.md` Mode 3)
2. Run `STRATA_INGEST_VALIDATION_CHECKLIST.md` (Layers 4-8)
3. Check for dangerous patterns in `RUNTIME_FAILURE_PATTERNS.md`

**Documents to use:**
- `STRATA_INGEST_VALIDATION_CHECKLIST.md`
- `TRUTHFULNESS_RULES.md` (Rules 1, 4, 9, 10)
- `RUNTIME_FAILURE_PATTERNS.md` (Patterns 1, 2, 3, 8)

**Expected output:** Issue list by severity, overall status PASS/PARTIAL/FAIL.

---

### Mode 4: GUI/CLI Validation Day

**Typical goals:**
- Verify that GUI pages don't claim more than CLI returns
- Check that warnings are preserved
- Confirm that counts match

**Minimum Strata checks:**
1. GUI/CLI Contract Audit (`RUN_STRATA_SUITE_AUDIT.md` Mode 4)
2. Run `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` (page-by-page)
3. Verify envelope fields match GUI expectations

**Documents to use:**
- `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md`
- `COMMAND_CONTRACTS.md`
- `TRUTHFULNESS_RULES.md` (Rule 8)

**Expected output:** Contract status PASS / ISSUES FOUND / CRITICAL.

---

### Mode 5: Release Prep Day

**Typical goals:**
- Validate the suite is ready for packaging
- Check all dependencies and integrations
- Document known limitations

**Minimum Strata checks:**
1. Release Readiness Audit (`RUN_STRATA_SUITE_AUDIT.md` Mode 5)
2. Run `STRATA_RELEASE_READINESS_CHECKLIST.md` (55 items)
3. Update `KNOWN_GAPS.md` if any new gaps discovered

**Documents to use:**
- `STRATA_RELEASE_READINESS_CHECKLIST.md`
- `KNOWN_GAPS.md`
- `STRATA_SHIELD_CHANGE_CONTROL.md` (if any changes since last release)

**Expected output:** Release verdict RELEASE APPROVED / RELEASE WITH WARNINGS / RELEASE BLOCKED.

---

## Section 4 — Required Daily Checks

Even if you're not running a full audit, these checks should be run regularly:

### Check 1: Build Sanity

**What to verify:** `cargo build --workspace` completes without errors

**Pass criteria:** Exit code 0, no `error[E` compilation errors

**When to skip:** Not applicable — this is a baseline check

**When to escalate:** Any new compilation errors → stop, fix before proceeding

---

### Check 2: Warning Drift

**What to verify:** New warnings haven't been introduced since baseline

**Pass criteria:** Warning count matches `WARNINGS_REPORT.md` baseline

**When to skip:** Minor documentation-only changes

**When to escalate:** New warnings in core modules (engine, CLI) → evaluate before proceeding

---

### Check 3: Command/Runtime Sanity

**What to verify:** CLI and runtime respond correctly

**Pass criteria:**
- `forensic_cli doctor` returns status "ok"
- KB bridge health returns `status: ok`
- Llama model loads and responds

**When to skip:** When making non-runtime changes (e.g., documentation only)

**When to escalate:** Doctor fails → check which diagnostic check failed; bridge fails → restart services

---

### Check 4: Truthful Fallback Review

**What to verify:** Fallback modes are labeled in UI

**Pass criteria:**
- KB bridge shows `embedding_backend` field in health
- Partial formats (VHD, VMDK) have warnings in output
- BitLocker shows as "detection only" not "decrypted"

**When to skip:** When not touching any fallback-related code

**When to escalate:** Fallbacks not labeled → document as issue, do not proceed as if full capability

---

### Check 5: Ingest Truthfulness Checks

**What to verify:** Evidence processing produces truthful output

**Pass criteria:**
- Zero-row results have warning field or verified empty-by-design
- No placeholder text in timeline/artifacts
- File counts proportional to evidence size

**When to skip:** When not touching ingest/parser code

**When to escalate:** Any truthfulness rule violation → stop, do not proceed

---

### Check 6: Recent History/Log Sanity

**What to verify:** Logs show current state, not stale data

**Pass criteria:**
- Logs have recent timestamps (today's date)
- No Qwen model references in current logs
- Correct vault path in KB bridge

**When to skip:** When not checking runtime components

**When to escalate:** Stale logs → clear, restart services; Qwen reference → wrong model loaded

---

### Check 7: Stale/Known Issue Awareness

**What to verify:** You're aware of known issues that might affect your work

**Pass criteria:** You've reviewed `KNOWN_GAPS.md` Section I (Resolution Tracking) and know what's open

**When to skip:** Rarely — this is a quick awareness check

**When to escalate:** Working on a known-blocked feature → don't waste time; check for workarounds first

---

## Section 5 — Common Daily Workflows

### Workflow A: "I changed parser code"

**Step 1:** Review your changes
- Did you add a new parser or modify an existing one?

**Step 2:** Run parser review
- Use `RUN_STRATA_PARSER_REVIEW.md`
- Complete `STRATA_PARSER_REVIEW_CHECKLIST.md` (21 items)

**Step 3:** Verify output
- Parser returns evidence-derived artifacts only
- No `Default::default()` returns
- No placeholders in descriptions

**Step 4:** Document
- Fill out parser review report (template in `RUN_STRATA_PARSER_REVIEW.md` Section 8)
- Issue verdict: APPROVED / APPROVED WITH WARNINGS / REJECTED

**Expected output:** Parser review report with clear verdict.

---

### Workflow B: "I changed CLI command behavior"

**Step 1:** Check the change
- Did you modify output shape? New envelope fields?

**Step 2:** Validate envelope structure
- Run `forensic_cli <command> --json-result temp.json`
- Verify envelope matches `COMMAND_CONTRACTS.md` spec

**Step 3:** Check GUI impact
- If GUI uses this command, run `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` (page-by-page)
- Verify GUI doesn't assume new fields exist

**Step 4:** Document
- Note change in audit findings
- If significant, update `COMMAND_CONTRACTS.md`

**Expected output:** Envelope validation pass, GUI contract validation (if applicable).

---

### Workflow C: "I changed GUI page logic"

**Step 1:** Identify affected commands
- Which CLI commands does this page use?

**Step 2:** Run GUI/CLI contract validation
- Use `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md`
- Verify page claims match CLI reality

**Step 3:** Check warning preservation
- Ensure CLI warnings are surfaced in the page

**Step 4:** Document
- Note contract validation results
- Flag any mismatches

**Expected output:** Contract validation pass or issues found with specific page.

---

### Workflow D: "I changed model/bridge/watchdog/runtime"

**Step 1:** Classify change (per `STRATA_SHIELD_CHANGE_CONTROL.md`)
- Is it minor or major?

**Step 2:** Follow maintenance procedure
- Use relevant section of `STRATA_SHIELD_MAINTENANCE.md`

**Step 3:** Run required revalidation
- Quick Health Audit (Mode 1) for minor
- Full Guardian Audit (Mode 6) for major

**Step 4:** Log change
- Add entry to `STRATA_SHIELD_CHANGE_LOG.md`

**Expected output:** Change validated, logged, and approved.

---

### Workflow E: "I'm testing a new evidence image"

**Step 1:** Verify container support
- Check `KNOWN_GAPS.md` for container type status

**Step 2:** Run ingest validation
- Use `STRATA_INGEST_VALIDATION_CHECKLIST.md`
- Walk through Layers 1-9

**Step 3:** Check for dangerous patterns
- Look for instant indexing, zero rows with success
- See `RUNTIME_FAILURE_PATTERNS.md`

**Step 4:** Document findings
- Add to audit report if this is part of a larger audit

**Expected output:** Ingest validation pass/fail, issue list if problems found.

---

### Workflow F: "I saw an instant-success / no-data scenario"

**Step 1:** This is a warning trigger — escalate immediately

**Step 2:** Identify the command
- Which command completed instantly with no data?

**Step 3:** Check for patterns
- See `RUNTIME_FAILURE_PATTERNS.md` Patterns 1, 2

**Step 4:** Run targeted validation
- Ingest Validation Audit (Mode 3) if evidence-related
- Check envelope status and warning fields

**Step 5:** Document
- Log as issue in audit report
- Do not proceed as if analysis was successful

**Expected output:** Pattern identification, issue logged, escalation noted.

---

### Workflow G: "I'm about to merge / ship something"

**Step 1:** Run release readiness checks
- Use Mode 5: Release Readiness Audit

**Step 2:** Check blocking issues
- Are any critical/high issues unresolved?

**Step 3:** Verify known gaps documented
- Update `KNOWN_GAPS.md` if new gaps discovered

**Step 4:** Document for handoff
- Use `STRATA_AUDIT_REPORT_TEMPLATE.md`
- Include sign-off if blocking issues exist

**Expected output:** Release verdict with blocking issues documented.

---

## Section 6 — Warning and Escalation Triggers

These specific findings should immediately trigger a deeper audit. Do not proceed past them:

### Trigger 1: Zero Rows with Success
**What:** Status is "ok" but data is empty (0 timeline entries, 0 artifacts, 0 files)  
**Why:** Silent failure or empty evidence presented as successful  
**Response:** Stop, run Ingest Validation Audit

### Trigger 2: Placeholders Counted as Real Data
**What:** Output contains "TBD", "TODO", "STUB", or `Default::default()` artifacts  
**Why:** Fabricated evidence being treated as real  
**Response:** Immediate escalation, critical issue

### Trigger 3: Unsupported Format Presented as Supported
**What:** VHD, VMDK, AFF4 shown as "complete" in UI  
**Why:** Partial/stubbed formats overclaimed  
**Response:** Check `KNOWN_GAPS.md`, flag as high issue

### Trigger 4: GUI Page Richer Than CLI Data
**What:** GUI shows fields or counts that CLI doesn't return  
**Why:** GUI claiming beyond CLI contract  
**Response:** Run GUI/CLI Contract Audit

### Trigger 5: Stale History Misleading Current Truth
**What:** Logs or cache show old data; current state is different  
**Why:** Stale data being presented as current  
**Response:** Clear logs, restart services, re-validate

### Trigger 6: Model/Runtime Identity Mismatch
**What:** Logs show wrong model (Qwen instead of Llama), wrong version  
**Why:** Incorrect inference being used  
**Response:** Stop, fix model loading, re-validate

### Trigger 7: Parser Outputs Without Provenance
**What:** Artifacts have no `source_path` or working-directory paths  
**Why:** No evidence trace for artifacts  
**Response:** Run Parser Review, reject if unfixable

### Trigger 8: Partial Parse Without Warning
**What:** Some records parsed, others failed, but no warning in envelope  
**Why:** Silent data loss  
**Response:** Flag as high issue, document in report

### Trigger 9: Sidecar/Runtime Build Mismatch
**What:** CLI binary version doesn't match source version  
**Why:** Running old code, changes not deployed  
**Response:** Rebuild, re-deploy, re-validate

---

## Section 7 — End-of-Day Routine

Before you finish for the day, do these:

### Step 1: Capture Unresolved Issues
- Note any issues you found but didn't resolve
- Document them so they're not forgotten

### Step 2: Update Known Gaps If Necessary
- Did you discover a new gap?
- Update `KNOWN_GAPS.md` with new findings

### Step 3: Record Any New Dangerous Patterns
- Did you see a pattern not in `RUNTIME_FAILURE_PATTERNS.md`?
- Add it so others know to look for it

### Step 4: Note Whether a Full Audit Is Needed Next
- Was today a coding day, or did you find issues that need full audit?
- Schedule a full audit if needed

### Step 5: Identify Whether Release-Readiness Is Affected
- Did you find issues that would block a release?
- Flag for next release review

---

## Section 8 — Practical Boundaries

### Daily Operations Are Not Full Release Audits
- Quick checks are for awareness, not completeness
- Don't use Mode 1 (Quick Health) as the only validation before a release

### Quick Checks Do Not Replace Real Ingest Validation
- Checking build is not the same as checking evidence processing
- If you're touching ingest code, run Mode 3

### Documentation Does Not Replace Runtime Proof
- `KNOWN_GAPS.md` says something is implemented doesn't mean it actually works
- Verify with runtime checks before trusting

### Strata Must Escalate Uncertainty Rather Than Smooth It Over
- If you can't verify something, say so
- Don't assume it's fine because you can't prove it's broken

---

## Section 9 — Operating Doctrine for Daily Use

Keep these four principles in mind every day:

### Every Day, Protect Truth Before Speed

Fast is good. Correct is mandatory. When there's a conflict between fast and correct, choose correct. The suite exists to help investigators — if we give them wrong data, we hurt their work.

### Partial but Honest Beats Complete but Misleading

A timeline with 0 entries and a warning is better than a timeline with 0 entries and a "complete" label. Partial results honestly surfaced are useful. Complete results that are actually empty are dangerous.

### Evidence Integrity Outranks Convenience

It's more work to trace every artifact back to its source file. It's more work to verify that zero-row results are legitimately empty. It's more work to label fallback modes. That work protects the integrity of every forensic conclusion. Do the work.

### Uncertainty Must Be Surfaced Early

If you see something you can't explain, flag it. If you can't verify a claim, say so. If you don't have the fixtures to test something, document that. The cost of flagging a false positive is low. The cost of missing a real problem is high.

---

> **Remember:** Every day you work with Strata Shield, you are protecting the integrity of forensic evidence. The checks you run, the issues you flag, and the verdicts you render all serve to ensure that the ForensicSuite tells the truth about what it has found.

---

**Start date:** 2026-03-23  
**Next review:** 2026-06-23 (quarterly)  
**Location:** `D:\forensic-suite\guardian\STRATA_DAILY_OPERATIONS.md`