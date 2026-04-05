# Strata Shield — Operator Quickstart

**Document Type:** Quickstart Guide  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Audience:** Operators, developers, auditors working with Strata Shield  
**Status:** Start here for day-to-day use

---

> **Not sure where to start?** Read this document first. It tells you what Strata Shield does, when to use it, and where to find the detailed procedures if you need them.

---

## Section 1 — What Strata Shield Is

Strata Shield is the guardian layer of the ForensicSuite. Think of it as the quality assurance and truthfulness enforcement system for your forensic tools.

Strata Shield does five things:
1. **Protects truthfulness** — Ensures no fabricated or synthetic data is presented as real evidence
2. **Protects evidence integrity** — Ensures every artifact traces back to its source file
3. **Protects parser quality** — Catches bad parsers (fake defaults, swallowed errors, missing provenance)
4. **Protects runtime safety** — Detects silent failures, instant indexing, empty results claimed as success
5. **Protects GUI/CLI consistency** — Ensures the GUI doesn't claim more than the CLI actually returns

**Strata Shield is advisory and validating first.** It observes what the suite produces, validates the output against documented contracts, and tells you what it found. It does not make forensic decisions. It does not conduct investigations. It protects the tools so that investigators can use them with confidence.

---

## Section 2 — What It Can Help With Right Now

Strata Shield is ready to help with these real use cases:

### Build and Runtime Health
- Check if the workspace compiles without errors
- Verify the CLI and engine are healthy (`forensic_cli doctor`)
- Confirm the KB bridge and Llama server are running
- Detect version mismatches between components

### Parser Quality
- Review new parser modules before integration
- Check for dangerous patterns (fake defaults, placeholder artifacts, missing provenance)
- Validate that parsers return evidence-derived data only

### Ingest Validation
- Verify evidence processing works end-to-end (container → filesystem → enumeration → parsing → timeline)
- Check that zero-row results are labeled correctly (not claimed as "successful indexing")
- Confirm file counts and artifact counts are proportional to evidence size

### GUI/CLI Contract Truthfulness
- Verify GUI page claims match what CLI commands actually return
- Check that warnings from CLI are preserved in the GUI
- Confirm partial results are labeled, not presented as complete

### Release Readiness
- Run the full pre-release validation before packaging
- Document all known gaps in the suite
- Confirm the system is ready for deployment

### Dangerous Pattern Detection
- Spot instant indexing with no data (completes in <100ms for GB-scale evidence)
- Identify success envelopes with zero real rows
- Detect unsupported formats being treated as supported
- Catch fallback modes that aren't labeled in the UI

---

## Section 3 — What It Must NOT Be Trusted To Do

Strata Shield has clear boundaries. Do not rely on it for:

### It Must NOT Invent Evidence
If evidence does not exist in the source data, Strata must not create it. This is the highest priority. If you see synthetic placeholders ("TBD", "TODO", "STUB", "implement me") in output, that's a critical failure.

### It Must NOT Silently Alter Evidence
Strata validates and reports. It does not modify evidence files, case databases, or artifact stores. Any change to evidence must be operator-initiated, not automated by Strata.

### It Must NOT Treat Synthetic Placeholders as Real Data
`Default::default()` artifacts, placeholder strings, and invented timestamps are not evidence. Strata must flag these as violations, not count them in success metrics.

### It Must NOT Overrule Missing Runtime Validation
Some things can't be verified from documentation alone:
- Parser output on real evidence (requires test fixtures)
- Performance at scale (requires live testing)
- Model response quality (requires empirical testing)

If validation can't be done, Strata must say so, not assume everything is fine.

### It Must NOT Declare Success Where Real Enumeration/Indexing Did Not Occur
Zero rows is not a success. A timeline with 0 entries in 47ms is not "analyzed." Strata must distinguish between "indexed N artifacts" and "parsed file with 0 results (could be empty, wrong format, or parser failure)."

### It Must Escalate Uncertainty Instead of Hiding It
If Strata can't verify something, it must escalate. It must not paper over uncertainty with confident labels. "I don't know" is better than a confident wrong answer.

---

## Section 4 — Quick Start Workflow

Follow this path for any Strata Shield task:

### Step 1: Read the Master Index
Start here: `STRATA_SHIELD_MASTER_INDEX.md`
- Gives you the lay of the land
- Shows all available documents
- Points you to the right reading path for your role

### Step 2: Check the Guardian Profile and Truthfulness Rules
- `SUITE_GUARDIAN_PROFILE.md` — Understand what Strata is and isn't allowed to do
- `TRUTHFULNESS_RULES.md` — The 11 non-negotiable evidence contracts

### Step 3: Pick the Correct Audit Mode
Based on `RUN_STRATA_SUITE_AUDIT.md`:

| Mode | Use When |
|------|----------|
| **Quick Health** (5-10 min) | Daily check, before development, after minor changes |
| **Build/Test** (20-40 min) | After code changes, before commit |
| **Ingest Validation** (30-45 min) | After container/filesystem/parser changes |
| **GUI/CLI Contract** (30-45 min) | After adding GUI pages or changing CLI output |
| **Release Readiness** (60-90 min) | Before packaging, before deployment |
| **Full Guardian** (2-4 hr) | Major milestones, periodic review, significant changes |

### Step 4: Use the Relevant Checklist/Runbook
- `RUN_STRATA_SUITE_AUDIT.md` — Master audit procedure (orchestrates checklists)
- `STRATA_*_CHECKLIST.md` — 5 validation checklists (38-55 items each)
- `RUN_STRATA_PARSER_REVIEW.md` — For parser-specific reviews

### Step 5: Produce an Audit Report
Use `STRATA_AUDIT_REPORT_TEMPLATE.md` to document findings.

### Step 6: Escalate If Uncertain
If you encounter ambiguous behavior, missing fixtures, or patterns you can't explain:
- Don't guess
- Don't assume
- Document the uncertainty
- Escalate to human reviewer

---

## Section 5 — Common Use Cases

### "I changed parser code"

**What to read first:** `RUN_STRATA_PARSER_REVIEW.md` + `PARSER_CONVENTIONS.md`

**What checklist to use:** `STRATA_PARSER_REVIEW_CHECKLIST.md` (21 items)

**What result to expect:** Parser approval verdict: APPROVED / APPROVED WITH WARNINGS / REJECTED

**Why:** The parser review procedure validates that your code meets quality standards, returns evidence-derived data only, handles errors correctly, and doesn't use placeholders as real artifacts.

---

### "A build succeeded but the suite behaves strangely"

**What to read first:** `RUN_STRATA_SUITE_AUDIT.md` (Mode 2: Build/Test)

**What checklist to use:** `STRATA_RUNTIME_AUDIT_CHECKLIST.md` (Sections 1-4)

**What result to expect:** List of issues by severity, overall status PASS/CONDITIONAL/FAIL

**Why:** The runtime audit checks for things the build system can't catch — version mismatches, missing binaries, command failures, envelope structure problems.

---

### "Ingest says complete but no data appears"

**What to read first:** `TRUTHFULNESS_RULES.md` (Rules 1, 4, 10) + `RUNTIME_FAILURE_PATTERNS.md` (Patterns 1, 2, 3)

**What checklist to use:** `STRATA_INGEST_VALIDATION_CHECKLIST.md` (Layers 4-8)

**What result to expect:** Identification of where the ingest pipeline broke, status PASS/PARTIAL/FAIL

**Why:** This is a classic failure pattern — the system claims success but produces no data. The checklist walks through container open, partition discovery, filesystem detection, enumeration, indexing, and timeline generation.

---

### "A GUI page seems to claim too much"

**What to read first:** `COMMAND_CONTRACTS.md` + `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md`

**What checklist to use:** `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` (Page-by-page review)

**What result to expect:** Identification of which pages have contract mismatches, overall contract status PASS/ISSUES_FOUND/CRITICAL

**Why:** The GUI must never claim more than what the CLI actually returns. This checklist verifies each page against the underlying CLI commands.

---

### "I'm preparing a release"

**What to read first:** `RUN_STRATA_SUITE_AUDIT.md` (Mode 5: Release Readiness)

**What checklist to use:** `STRATA_RELEASE_READINESS_CHECKLIST.md` (55 items across 12 sections)

**What result to expect:** Release verdict: RELEASE APPROVED / RELEASE WITH WARNINGS / RELEASE BLOCKED, with blocking issues table

**Why:** This is the final gate. It checks build, tests, packaging, runtime health, operator warnings, and startup scripts.

---

## Section 6 — Warning Signs Operators Should Notice

These are red flags. If you see them, investigate before proceeding:

### Instant Indexing with No Data
- **What:** Command completes in <100ms for GB-scale evidence
- **Why:** Implausible — evidence wasn't actually processed
- **See:** `RUNTIME_FAILURE_PATTERNS.md` Pattern 1

### Zero Rows but Success Shown
- **What:** Timeline shows 0 entries, status is "ok"
- **Why:** Either evidence is genuinely empty, or parsing failed silently
- **See:** `TRUTHFULNESS_RULES.md` Rule 4

### Placeholders Appearing as Evidence
- **What:** Output contains "TBD", "TODO", "STUB", "implement me", or `Default::default()`
- **Why:** This is fabricated data, not evidence
- **See:** `TRUTHFULNESS_RULES.md` Rule 5

### Unsupported Formats Treated as Supported
- **What:** VHD, VMDK, AFF4 shown as "complete" when they are partial/stubbed
- **Why:** The suite is claiming more than it can actually do
- **See:** `KNOWN_GAPS.md` Section A.2

### Mismatched Model/Runtime Identity
- **What:** Llama model shows "Qwen" in logs when "Llama" is expected
- **Why:** Wrong model loaded — inference results may be wrong
- **See:** `STRATA_SHIELD_DEPENDENCY_MAP.md` Model Dependencies

### Bridge or Sidecar Healthy but UI Wrong
- **What:** KB bridge health returns OK, but GUI shows wrong data
- **Why:** Either stale data, or GUI parsing doesn't match CLI output shape
- **See:** `RUNTIME_FAILURE_PATTERNS.md` Patterns 4, 7

### Warnings Hidden Behind "Complete" States
- **What:** GUI shows "Analysis Complete" but CLI had warnings
- **Why:** Warnings were dropped; partial results not labeled
- **See:** `TRUTHFULNESS_RULES.md` Rule 9

---

## Section 7 — Where To Go Next

Depending on what you need, here's your best next read:

| Need | Go To |
|------|-------|
| I want to understand the whole system | `STRATA_SHIELD_MASTER_INDEX.md` |
| I want to know what Strata is and isn't allowed to do | `SUITE_GUARDIAN_PROFILE.md` |
| I want to know the evidence contracts | `TRUTHFULNESS_RULES.md` |
| I want to run an audit | `RUN_STRATA_SUITE_AUDIT.md` |
| I want to review a parser | `RUN_STRATA_PARSER_REVIEW.md` |
| I want to file an audit report | `STRATA_AUDIT_REPORT_TEMPLATE.md` |
| I want to understand parser quality standards | `PARSER_CONVENTIONS.md` |
| I want to know what the suite can and can't do | `KNOWN_GAPS.md` |
| I want to update the model or bridge safely | `STRATA_SHIELD_MAINTENANCE.md` |
| I want to change something and need change control | `STRATA_SHIELD_CHANGE_CONTROL.md` |
| I want to see what Strata Shield is building toward | `STRATA_SHIELD_ROADMAP.md` |

---

## Section 8 — Operator Doctrine

Keep this in mind every time you use Strata Shield:

### Trust Evidence Over Appearances
If the documentation says something works but the runtime shows it doesn't, trust the runtime. Documentation can be stale; evidence is current.

### Trust Verified Runtime Behavior Over Assumptions
Don't assume a capability works because it's documented. Verify it. Run the checklist. Check the envelope.

### Trust Warnings and Partial States When They Are Honestly Surfaced
A system that says "partial" or "warning" is more trustworthy than one that says "complete" when the evidence doesn't support it. Honest uncertainty is better than confident lies.

### Escalate Uncertainty Rather Than Suppress It
If you can't verify something, say so. Don't guess. Don't assume. Document what you couldn't verify and escalate. It's better to pause and ask than to proceed with unverified assumptions.

---

> **Remember:** Strata Shield protects truth, not appearances. It protects evidence integrity, not convenience. It escalates uncertainty, it doesn't mask it. It only grants trust when evidence supports it.

---

**Start date:** 2026-03-23  
**Next review:** 2026-06-23 (quarterly)  
**Location:** `D:\forensic-suite\guardian\STRATA_OPERATOR_QUICKSTART.md`