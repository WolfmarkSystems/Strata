# Strata Shield — Incident Response Playbook

**Document Type:** Incident Response SOP  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Authority:** Strata — Suite Guardian  
**Audience:** Operators, developers, auditors responding to incidents  
**Status:** Active — Use when suite behavior is suspicious, dangerous, or misleading

---

> **Use this document when:** The ForensicSuite shows dangerous behavior, fails truthfulness checks, or produces inconsistent results. For routine checks, see `STRATA_DAILY_OPERATIONS.md`. For full audits, see `RUN_STRATA_SUITE_AUDIT.md`.

---

## Section 1 — Purpose

### What Counts as an Incident

An incident in the Strata Shield context is any event where the ForensicSuite behaves in a way that could produce false forensic conclusions, mislead operators, or compromise evidence integrity.

This includes:
- Truthfulness violations (fabricated data, placeholders as evidence)
- Dangerous runtime patterns (instant indexing, zero-row success)
- GUI/CLI contract failures (claims exceeding reality)
- Runtime failures (service crashes, model mismatches)
- Packaging failures (wrong binaries, missing components)

### Why Incident Response Matters

When an incident occurs, the cost of the wrong response is high:
- False conclusions in forensic reports
- Evidence integrity compromised
- Operator trust eroded
- Investigation validity questioned

The right response contains the damage, preserves the evidence of failure, and leads to a fix.

### How This Differs From Routine Work

| Mode | When | Focus |
|------|------|-------|
| **Daily Operations** | Normal work | Awareness, quick checks, routine |
| **Audit** | Scheduled validation | Comprehensive, full verdict |
| **Incident Response** | When something is wrong | Containment, triage, resolution |

This playbook is for when things break. It assumes you already know what Strata is and how it works. If not, start with `STRATA_OPERATOR_QUICKSTART.md`.

---

## Section 2 — Incident Severity Levels

### SEV-1: Critical Integrity Incident

**Definition:** Evidence fabrication, fabricated conclusions, or behavior that directly produces false forensic results.

**Examples:**
- Parser returns invented artifacts as evidence
- Timeline contains placeholder rows ("TBD", "STUB") counted as real data
- `Default::default()` artifacts present in output
- Evidence hash computed on wrong data

**Expected response urgency:** Immediate. Stop all work. Escalate to human reviewer. Do not proceed until resolved.

---

### SEV-2: High-Risk Truthfulness Incident

**Definition:** Truthfulness rules violated in ways that could lead to incorrect conclusions if not caught.

**Examples:**
- Zero-row results presented as successful indexing
- Unsupported format (VHD, VMDK) shown as "complete"
- GUI claims exceed CLI reality (counts, capabilities)
- Missing provenance on artifacts
- Partial results presented as complete

**Expected response urgency:** Within 1 hour. Run targeted validation. Document findings. Escalate if unresolved.

---

### SEV-3: Runtime / Validation Incident

**Definition:** Runtime failures that affect Strata Shield's ability to validate the suite.

**Examples:**
- KB bridge health returns OK but responses malformed
- Llama model loaded is wrong (Qwen instead of Llama)
- Sidecar binary version mismatch
- CLI returns success envelope with implausibly fast timing
- Warnings dropped from GUI display

**Expected response urgency:** Within 4 hours. Check runtime health. Restart services if needed. Verify model identity.

---

### SEV-4: Minor Operational Incident

**Definition:** Non-critical issues that don't affect forensic validity but reduce confidence or require workarounds.

**Examples:**
- Build warnings increased (not blocking but notable)
- Non-critical test failures
- Minor documentation gaps
- Log files showing stale data
- New dependency without update to change control

**Expected response urgency:** Within 1 day. Document, track, address during next development cycle.

---

## Section 3 — What Counts as an Incident

If you observe any of the following, treat it as an incident:

### Truthfulness Violations
- **Instant indexing with no data** — Command completes in <100ms for GB-scale evidence
- **Zero-row success** — Status "ok" returned with 0 entries, no warning
- **Synthetic placeholders** — Output contains "TBD", "TODO", "STUB", `Default::default()`
- **Parser emits unsupported conclusions** — Parser claims more detail than evidence supports
- **Missing provenance** — Artifacts without source_path

### GUI/CLI Contract Failures
- **GUI richer than CLI truth** — Page shows fields or counts that CLI doesn't return
- **Unsupported format as supported** — VHD/VMDK/AFF4 shown as complete
- **Warnings hidden** — CLI warnings not surfaced in GUI

### Runtime Failures
- **Sidecar/model mismatch** — Wrong binary or model loaded (Qwen instead of Llama)
- **Bridge healthy but responses malformed** — Health OK but API responses invalid
- **Stale history** — Logs show old session data, current state different
- **Release artifact issues** — Missing sidecar, wrong runtime in package

### Build/Test Issues
- **Build failures** — Compilation errors in core modules
- **Test failures** — New test regressions
- **Verification drift** — Binary hash doesn't match expected version

---

## Section 4 — Immediate Containment Steps

When you first suspect an incident:

### Step 1: Stop Claiming Trustworthiness
Do not tell anyone the system is working correctly until the incident is understood. If a user asks if the suite is healthy, say "under investigation" — don't say "fine."

### Step 2: Preserve Evidence
- Capture command outputs: `forensic_cli <command> --json-result incident_001.json`
- Save logs: Copy `logs/` directory to safe location
- Note timestamps: When did you first notice the issue?
- Document environment: OS, tool versions, paths

### Step 3: Identify the Affected Layer
Is the issue in:
- **Engine** (forensic_engine) → Parser behavior, artifact generation
- **CLI** (forensic_cli) → Command output, envelope structure
- **GUI** (gui-tauri) → Display claims, contract violations
- **Runtime** (llama-server) → Model loading, inference quality
- **Bridge** (dfir_kb_bridge) → API responses, health endpoint
- **Watchdog** → Service monitoring failures
- **Packaging** → Missing files, wrong binaries

### Step 4: Determine Work Continuation
- **SEV-1/2:** Stop work. Do not run new evidence through the suite.
- **SEV-3:** Pause release-prep work. Verify runtime before continuing.
- **SEV-4:** Note the issue. Continue work but track it.

### Step 5: Avoid Assumptions
- Don't assume the issue is already in `KNOWN_GAPS.md`
- Don't assume it's environment-specific until proven
- Don't assume it's been reported
- Don't assume a quick fix is safe without revalidation

---

## Section 5 — Incident Triage Workflow

Follow this step-by-step process:

### Step 1: Classify the Incident
- Determine SEV level (1-4)
- Check against Section 3 criteria

### Step 2: Identify Affected Layer(s)
- Engine / CLI / GUI / Runtime / Bridge / Watchdog / Packaging
- Multiple layers may be affected

### Step 3: Gather Evidence
- Command outputs (JSON envelopes)
- Build/test outputs
- Log files
- Screenshots (if GUI issue)
- Model/runtime identity
- Package contents (if packaging issue)

### Step 4: Compare Against Truth Rules
- Check `TRUTHFULNESS_RULES.md` — which rules are violated?
- Check `PARSER_CONVENTIONS.md` — are there quality violations?
- Check `KNOWN_GAPS.md` — is this a known gap behaving badly?

### Step 5: Check Known Failure Patterns
- Compare against `RUNTIME_FAILURE_PATTERNS.md`
- Which pattern matches (if any)?

### Step 6: Run Targeted Checklist/Runbook
- **Ingest issue:** `STRATA_INGEST_VALIDATION_CHECKLIST.md`
- **Parser issue:** `STRATA_PARSER_REVIEW_CHECKLIST.md`
- **GUI/CLI issue:** `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md`
- **Runtime issue:** `STRATA_RUNTIME_AUDIT_CHECKLIST.md`

### Step 7: Determine Issue Characteristics

| Question | Answers |
|----------|---------|
| Is it reproducible? | Yes / No / Unknown |
| Is it environment-specific? | Yes / No / Unknown |
| Is it related to stale history? | Yes / No / Unknown |
| Is it active/current? | Yes / No / Unknown |

### Step 8: Decide Escalation Path
- **SEV-1:** Immediate escalation, human reviewer required
- **SEV-2:** Escalation if unresolved in 1 hour
- **SEV-3:** Escalation if unresolved in 4 hours
- **SEV-4:** Track for next cycle

---

## Section 6 — Incident Types and Responses

### A) Ingest / Indexing Incident

**Symptoms:**
- Zero-row result but status "ok"
- Instant completion (<100ms for large evidence)
- Enumeration count suspiciously low
- No files found in populated evidence

**Likely causes:**
- Parser silently failed
- Container opened but filesystem not enumerated
- Wrong format recognition
- Evidence is empty/corrupted

**Immediate checks:**
1. Run `forensic_cli open-evidence <evidence> --json-result temp.json`
2. Check `filesystems` field in envelope
3. Check `elapsed_ms` — is it implausibly fast?
4. Run `forensic_cli filetable <evidence> --json-result temp.json`

**Follow-up checks:**
- Compare against `RUNTIME_FAILURE_PATTERNS.md` Patterns 1, 2, 3
- Check `TRUTHFULNESS_RULES.md` Rules 1, 4, 9
- Run `STRATA_INGEST_VALIDATION_CHECKLIST.md` Layers 1-9

**What Strata should verify:**
- Evidence is genuinely empty OR warning is present
- File count is proportional to evidence size
- Enumeration time is plausible

**What must never be assumed:**
- "The evidence is just empty" without verifying
- "The enumeration works, just nothing found" without checking counts

---

### B) Parser Incident

**Symptoms:**
- Parser returns artifacts with placeholder text
- Parser returns `Default::default()` artifacts
- Parser has no source_path on output
- Parser silently swallows errors (empty return on failure)

**Likely causes:**
- Parser not fully implemented
- Error path returns empty instead of error
- Parser uses `Default::default()` as fallback
- Parser generates artifacts when data is missing

**Immediate checks:**
1. Review parser code — look for `Default::default()`, placeholder strings
2. Run parser against test fixture
3. Check `source_path` field on all artifacts

**Follow-up checks:**
- Run `RUN_STRATA_PARSER_REVIEW.md` (all 7 phases)
- Complete `STRATA_PARSER_REVIEW_CHECKLIST.md` (21 items)
- Check `PARSER_CONVENTIONS.md` Section 8 (Signs of Bad Parser)

**What Strata should verify:**
- All artifacts are evidence-derived
- No `Default::default()` in output
- No placeholder strings
- source_path is present and correct

**What must never be assumed:**
- Empty result means no data — verify with warning
- `Ok(vec![])` on error path is intentional — check the code

---

### C) GUI/CLI Contract Incident

**Symptoms:**
- GUI shows more data than CLI returns
- GUI shows different counts than CLI
- CLI warnings not visible in GUI
- GUI shows "Complete" but CLI had warnings
- GUI shows capability not in CLI

**Likely causes:**
- GUI parses wrong field from envelope
- GUI assumes field exists that CLI didn't return
- Warning field dropped
- Cache displays stale data

**Immediate checks:**
1. Run CLI command, save envelope
2. Compare GUI display against envelope fields
3. Check for warning field in envelope

**Follow-up checks:**
- Run `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` (page-by-page)
- Check `COMMAND_CONTRACTS.md` Section F (Error Handling Contract)
- Verify envelope field mapping

**What Strata should verify:**
- GUI counts match CLI envelope values
- Warnings present in CLI are visible in GUI
- Missing fields handled gracefully (not crash)

**What must never be assumed:**
- GUI is correct — CLI is the ground truth
- Stale cache is obvious — some failures are silent

---

### D) Runtime / Model / Bridge Incident

**Symptoms:**
- KB bridge health returns OK but chat fails
- Llama model loaded is wrong (Qwen vs Llama)
- Model inference produces nonsensical output
- Sidecar binary version doesn't match expected

**Likely causes:**
- Model file misconfigured
- Bridge restart didn't pick up new version
- Wrong startup script used
- Watchdog failed to detect issue

**Immediate checks:**
```bash
curl http://127.0.0.1:8090/health
curl http://127.0.0.1:8080/api/tags
forensic_cli --version
```

**Follow-up checks:**
- Check startup script paths
- Verify model file SHA256
- Check logs for Qwen references
- Run `STRATA_RUNTIME_AUDIT_CHECKLIST.md` Section 3

**What Strata should verify:**
- Health endpoint shows correct status
- Model list shows expected model
- No Qwen references in logs
- Binary hash matches expected version

**What must never be assumed:**
- Health OK means everything is fine — check the response shape
- Last-used model is still loaded — verify explicitly

---

### E) Packaging / Release Incident

**Symptoms:**
- Package missing required binaries
- Sidecar in package different from source-built
- Model files included (should be downloaded separately)
- Package doesn't run from different install path

**Likely causes:**
- Package build script incomplete
- Package sync failed
- Wrong binaries copied
- Hardcoded paths in scripts

**Immediate checks:**
1. List package contents
2. Compare against source-built binaries
3. Test running from different path

**Follow-up checks:**
- Run `STRATA_RELEASE_READINESS_CHECKLIST.md` Sections 6-7
- Check package script for hardcoded paths
- Verify binary hashes

**What Strata should verify:**
- All required binaries present
- No model files in package
- Scripts use relative paths
- Package runs from any location

**What must never be assumed:**
- Package build succeeded means it worked — verify contents
- Package works on dev machine means it works everywhere

---

### F) Documentation / Doctrine Drift Incident

**Symptoms:**
- `KNOWN_GAPS.md` doesn't match actual capability
- `COMMAND_CONTRACTS.md` doesn't match CLI output
- Truthfulness rules don't match actual behavior
- Runbooks assume outdated system state

**Likely causes:**
- Changes made without updating docs
- Docs not validated against runtime
- Doctrinal assumptions became stale

**Immediate checks:**
1. Compare doc claims against runtime behavior
2. Run CLI commands to verify actual output
3. Check if new capabilities are undocumented

**Follow-up checks:**
- Update affected doc
- Check for other drift in same area
- Run full audit to validate completeness

**What Strata should verify:**
- Docs match runtime (not the reverse)
- No phantom capabilities in docs
- New changes reflected in relevant docs

**What must never be assumed:**
- Doc is correct — always verify against runtime
- "We documented it so it's done" — check actual behavior

---

## Section 7 — Required Evidence Collection

During an incident, collect all of the following:

### Command Outputs
- [ ] `forensic_cli doctor --json-result`
- [ ] `forensic_cli capabilities --json-result`
- [ ] Any relevant command envelopes (open-evidence, timeline, filetable, etc.)

### Build/Test Output
- [ ] `cargo build --workspace` output
- [ ] `cargo test --workspace` output (if relevant)
- [ ] `cargo clippy --workspace` output (if relevant)

### Logs
- [ ] KB bridge stdout (`logs/kb_bridge_stdout.log`)
- [ ] KB bridge stderr (`logs/kb_bridge_stderr.log`)
- [ ] Llama server stderr (`logs/llama_stderr.log`)
- [ ] Server logs (`logs/server_stderr.log`)

### JSON Envelopes
- [ ] Relevant command envelopes saved as JSON
- [ ] Error/warning fields captured

### UI Observations (if GUI issue)
- [ ] Screenshots of problematic display
- [ ] Console errors (if accessible)

### Model/Runtime Identity
- [ ] Output of `curl http://127.0.0.1:8080/api/tags`
- [ ] Output of `curl http://127.0.0.1:8090/health`
- [ ] Startup script contents

### Package Artifacts (if packaging issue)
- [ ] Package contents list
- [ ] Binary hashes (for comparison)

### Reproduction Steps
- [ ] Exact command sequence that triggers issue
- [ ] Evidence file paths (if applicable)
- [ ] Environment details

### Environment Notes
- [ ] OS version
- [ ] Rust/cargo version
- [ ] Node/npm version
- [ ] Paths in use

---

## Section 8 — Escalation and Decision Rules

### Escalate Immediately If:
- Evidence of SEV-1 or SEV-2 behavior
- Issue is reproducible across environments
- Fix requires code changes beyond docs
- Release is blocked

### Block Release If:
- Any unresolved SEV-1 incident
- Unresolved SEV-2 with high-risk truthfulness violation
- Build/test failures in core modules
- Sidecar/model mismatch

### Mark Feature/Page/Command as Partial/Untrusted If:
- Partial support but labeled complete in UI
- Warnings suppressed from display
- Zero-row results not properly labeled

### Stop Further Testing If:
- SEV-1 truthfulness violation confirmed
- Evidence fabrication detected
- Parser returns placeholder data as real

### Acceptable Quick Workarounds If:
- Issue is SEV-4 only
- Workaround is documented in comments
- Full fix scheduled within 1 week
- No release until resolved

### Only Full Audit Acceptable If:
- Any change to model, bridge, or core runtime
- Any new parser integration
- Any CLI command output shape change
- Release readiness evaluation

---

## Section 9 — Communication / Reporting Pattern

When documenting an incident, use this pattern:

### Header
- **Incident ID:** `INC-YYYYMMDD-NNN`
- **Date/Time:** [When first observed]
- **Severity:** [SEV-1/2/3/4]
- **Status:** [OPEN / IN PROGRESS / RESOLVED / CLOSED]

### Section: Concise Description
[What happened in 2-3 sentences. No jargon for non-technical readers.]

### Section: Severity and Rationale
[Why this severity level. What made it critical/high/etc.]

### Section: Affected Components
- Engine: [YES/NO — if yes, which]
- CLI: [YES/NO — if yes, which]
- GUI: [YES/NO — if yes, which]
- Runtime: [YES/NO — if yes, which]
- Bridge: [YES/NO — if yes, which]
- Packaging: [YES/NO — if yes, which]

### Section: Evidence
- Command outputs attached: [list]
- Logs attached: [list]
- Screenshots attached: [list]

### Section: Current Impact
[What is broken, what doesn't work, what is misleading]

### Section: What Remains Uncertain
[What you don't know yet]

### Section: Next Safe Actions
1. [What can still be done safely]
2. [What must not be done]

---

> **Tip:** Use `STRATA_AUDIT_REPORT_TEMPLATE.md` as the format for formal incident reports. Incident findings can be captured in the audit report format with SEV classification in the findings table.

---

## Section 10 — Resolution and Recovery

### Verify Fix
- Reproduce the original issue
- Verify it no longer occurs
- Run relevant checklist again

### Rerun Appropriate Checklist/Runbook
- Ingest issue → `STRATA_INGEST_VALIDATION_CHECKLIST.md`
- Parser issue → `RUN_STRATA_PARSER_REVIEW.md`
- GUI/CLI issue → `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md`
- Runtime issue → `STRATA_RUNTIME_AUDIT_CHECKLIST.md`

### Update Known Gaps If Needed
- Did the incident reveal a new gap?
- Update `KNOWN_GAPS.md`

### Update Failure Patterns If New
- Is this a new pattern not in `RUNTIME_FAILURE_PATTERNS.md`?
- Document it

### Decide Release Readiness Impact
- Does this affect release readiness?
- Update status accordingly

### Record Final Status
- Incident ID
- Resolution date
- Root cause (if known)
- Prevention measures

---

## Section 11 — Incident Doctrine

When responding to an incident, remember:

### Protect Truth First

Whatever else you do — contain the damage, call the experts, fix the code — ensure that the truth about what happened is preserved. Don't hide failures behind "resolved" labels. Don't minimize issues to make the report look better.

### Preserve Evidence of Failure

Keep the logs, save the envelopes, capture the screenshots. The evidence of what went wrong is what prevents it from happening again. Don't clean up before understanding.

### Never Hide Misleading Behavior Behind Success Language

A zero-row result is not a success. A silent failure is not an achievement. If something went wrong, call it wrong. "Complete" means complete, "partial" means partial, "failed" means failed. Don't use success words to describe failure states.

### Uncertainty Is Itself an Operational Signal

If you can't verify something, that's a finding. If you don't know what caused it, that's a finding. Uncertainty is not something to hide — it's information. The right response to uncertainty is investigation, not assumption.

### No Incident Is Resolved Until the Suite Is Truthful Again

A fix is not complete until the output is honest. The suite doesn't work if it tells lies, even pretty lies, even well-intentioned lies. Verify the fix produces truthful output, not just that it doesn't crash.

---

> **Remember:** When an incident occurs, you are the guardian of truth. Preserve the evidence. Call the issues what they are. Don't minimize. Don't assume. Verify the fix produces honest output. No incident is truly resolved until the suite tells the truth again.

---

**Start date:** 2026-03-23  
**Next review:** 2026-06-23 (quarterly)  
**Location:** `D:\forensic-suite\guardian\STRATA_INCIDENT_RESPONSE_PLAYBOOK.md`