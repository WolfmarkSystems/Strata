# Strata Shield — Change Control

**Document Type:** Change Management Procedure  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Authority:** Strata — Suite Guardian  
**Audience:** All contributors to Strata Shield

---

## Overview

Strata Shield is a protective system. Changes to its components — model, bridge, watchdog, doctrine, or integration — must be controlled to prevent accidental breakage of the guardian function.

This document defines:
- What counts as a change to Strata Shield
- How changes are classified (minor vs. major)
- What reviews are required before changes are accepted
- What revalidation steps are required after changes
- How approvals and sign-offs are documented

All changes must be logged in the **Strata Shield Incident and Change Log** (see Appendix A).

---

## What Counts as a Change to Strata Shield

A change is any modification to the following components:

| Component | Examples of Changes |
|-----------|---------------------|
| Llama model | New model version, model file replacement, model configuration change |
| llama-server.exe | Binary update, CLI argument changes, port configuration |
| KB bridge | Script changes, endpoint changes, envelope validation logic |
| Watchdog | Monitoring logic changes, restart thresholds, alert rules |
| Startup scripts | Model paths, port assignments, environment variables |
| Guardian doctrine | Truthfulness rules, operating principles, boundaries |
| Guardian runbooks | Audit procedures, parser review SOPs |
| Guardian checklists | Validation criteria, pass/fail thresholds |
| Guardian inventories | Known gaps, warnings, failure patterns |
| Suite integration | CLI command changes, envelope structure changes, GUI contract changes |

**Changes also include:**
- Adding new components
- Removing existing components
- Changing component locations
- Changing dependencies between components
- Changing operating environment (OS version, tool versions)

---

## Change Classification

### Minor Changes

Minor changes are low-risk modifications that do not affect the guardian function's reliability or truthfulness.

**Examples:**
- Fixing typos in guardian documentation
- Adding comments to code without changing behavior
- Updating log file locations (if already documented)
- Adding non-critical monitoring to watchdog
- Improving error messages in startup scripts
- Minor documentation updates (formatting, links)
- Adding new test cases to existing test suites

**Required review:** Strata self-review  
**Required revalidation:** Quick Health Audit (Mode 1)  
**Approval required:** Strata automated approval (documented in log)  
**Escalation:** None required

---

### Major Changes

Major changes are modifications that could affect the guardian function's correctness, reliability, or safety.

**Examples:**
- Changing the Llama model (new model file, different model tier)
- Modifying KB bridge response handling or envelope validation
- Changing startup script default paths or ports
- Adding new guardian doctrine rules
- Modifying truthfulness rules
- Changing CLI command output shapes (envelope structure)
- Adding new CLI commands used by Strata
- Changing integration points between components
- Modifying watchdog restart thresholds or failure detection
- Updating known gaps (new gaps or resolved gaps)
- Changing evidence-preserving behaviors

**Required review:** Strata review + Human reviewer  
**Required revalidation:** Full Guardian Audit (Mode 6) or relevant sub-mode  
**Approval required:** Human reviewer sign-off  
**Escalation:** Required — must document rationale

---

## Change Review Requirements

### Model Changes

| Change Type | Strata Review | Human Review | Revalidation |
|-------------|--------------|--------------|--------------|
| Model file replacement (same model) | Yes | No | Quick Health Audit |
| Model tier change (70B → 8B) | Yes | Yes | Full Guardian Audit |
| New model family (different model) | Yes | Yes | Full Guardian Audit |
| Model configuration change | Yes | Yes | Build/Test + Runtime |

**Review criteria:**
- Model file SHA256 verified
- Model loads correctly
- Response quality meets standards (test queries)
- Guardian doctrine test queries return correct responses
- No regression in validation outcomes

---

### Prompt / Doctrine Changes

| Change Type | Strata Review | Human Review | Revalidation |
|-------------|--------------|--------------|--------------|
| Adding examples to existing rules | Yes | Yes | Quick Health Audit |
| Clarifying existing rules | Yes | Yes | Quick Health Audit |
| Adding new truthfulness rules | Yes | Yes | Full Guardian Audit |
| Removing truthfulness rules | Yes | Yes | Full Guardian Audit |
| Changing operating boundaries | Yes | Yes | Full Guardian Audit |

**Review criteria:**
- New rules are consistent with existing doctrine
- New rules are enforceable (can be validated)
- Removing rules does not create gaps
- Change rationale documented

---

### Bridge Changes

| Change Type | Strata Review | Human Review | Revalidation |
|-------------|--------------|--------------|--------------|
| Bug fix (no behavior change) | Yes | No | Quick Health Audit |
| New logging | Yes | No | Quick Health Audit |
| New endpoint | Yes | Yes | Build/Test + Runtime |
| Envelope validation logic change | Yes | Yes | Full Guardian Audit |
| Response handling change | Yes | Yes | Full Guardian Audit |

**Review criteria:**
- Health endpoint still returns correct structure
- Chat completions still work correctly
- Envelope validation unchanged or improved
- No new security issues introduced
- Backward compatibility maintained

---

### Watchdog Changes

| Change Type | Strata Review | Human Review | Revalidation |
|-------------|--------------|--------------|--------------|
| Log improvement | Yes | No | Quick Health Audit |
| Alert threshold change | Yes | Yes | Runtime validation |
| Restart logic change | Yes | Yes | Full Guardian Audit |
| New monitored service | Yes | Yes | Full Guardian Audit |

**Review criteria:**
- Services still restart correctly on failure
- No false alarms introduced
- Failure storm detection still works
- Logging is adequate for debugging

---

### Guardian Doctrine Changes

| Change Type | Strata Review | Human Review | Revalidation |
|-------------|--------------|--------------|--------------|
| Adding new failure pattern | Yes | Yes | Quick Health Audit |
| Updating known gaps | Yes | Yes | Quick Health Audit |
| Clarifying existing rules | Yes | Yes | Quick Health Audit |
| Adding new operating principle | Yes | Yes | Full Guardian Audit |
| Removing operating principle | Yes | Yes | Full Guardian Audit |

**Review criteria:**
- Change is consistent with guardian identity
- Change does not conflict with other doctrine documents
- Change is actionable (can be validated)
- Change rationale documented

---

### Suite Integration Changes

| Change Type | Strata Review | Human Review | Revalidation |
|-------------|--------------|--------------|--------------|
| New CLI command (Strata uses it) | Yes | Yes | Full Guardian Audit |
| CLI output shape change | Yes | Yes | Full Guardian Audit |
| GUI page addition | Yes | Yes | GUI/CLI Contract Audit |
| GUI contract change | Yes | Yes | GUI/CLI Contract Audit |
| New parser added | Yes | Yes | Parser Review + Ingest Validation |

**Review criteria:**
- New commands have documented envelopes
- Output shapes match GUI expectations
- CLI-GUI contracts are maintained
- New parsers meet quality standards

---

## Required Revalidation Steps

After any major change, Strata must run revalidation steps appropriate to the change type.

### Quick Health Audit (Mode 1)

**When:** Minor changes, after any change that doesn't affect core function  
**Duration:** 5-10 minutes  
**Checks:**
- `cargo build --workspace` compiles without errors
- `forensic_cli doctor` returns OK
- KB bridge health returns OK
- Llama server responds
- No new errors in logs

### Build/Test Audit (Mode 2)

**When:** Changes to suite code, CLI commands, or parser implementations  
**Duration:** 20-40 minutes  
**Checks:**
- `cargo build --workspace` passes
- `cargo test --workspace` passes
- `cargo clippy --workspace` passes
- Package builds successfully

### Ingest Validation Audit (Mode 3)

**When:** New container support, new parsers, filesystem changes  
**Duration:** 30-45 minutes  
**Checks:**
- Evidence processing pipeline verified end-to-end
- Parser outputs validated
- Truthfulness rules confirmed

### GUI/CLI Contract Audit (Mode 4)

**When:** New GUI pages, CLI output shape changes  
**Duration:** 30-45 minutes  
**Checks:**
- GUI claims match CLI reality
- Warnings preserved
- Counts accurate
- Fallback modes labeled

### Parser Review (per `RUN_STRATA_PARSER_REVIEW.md`)

**When:** New or modified parsers  
**Duration:** 30-45 minutes per parser  
**Checks:**
- Parser passes all review phases
- Verdict: APPROVED / APPROVED WITH WARNINGS / REJECTED

### Full Guardian Audit (Mode 6)

**When:** Major changes to model, bridge, doctrine, or core integration  
**Duration:** 2-4 hours  
**Checks:**
- All validation modes complete
- All checklists passed or documented
- Verdict: PASS / PASS WITH WARNINGS / FAIL

---

## Approval and Sign-Off

### Minor Change Approval

| Role | Responsibility |
|------|---------------|
| **Strata** | Self-review, document in change log, run Quick Health Audit |
| **Human reviewer** | Not required (Strata automated) |

### Major Change Approval

| Role | Responsibility |
|------|---------------|
| **Strata** | Full review, recommend approval/rejection, run revalidation |
| **Technical reviewer** | Validate technical correctness |
| **Guardian reviewer** | Validate doctrine consistency |
| **Release approver** | Final approval before deployment |

### Approval Criteria

For a major change to be approved:

1. [ ] Strata review completed and issues documented
2. [ ] All required revalidation steps passed
3. [ ] Human reviewer sign-off obtained
4. [ ] Change rationale documented
5. [ ] Rollback procedure documented
6. [ ] Change logged in incident log

### Rejection Criteria

A major change is rejected if:

1. [ ] Any truthfulness rule would be violated
2. [ ] Any critical functionality would break
3. [ ] Strata cannot validate the change
4. [ ] Change creates undocumented gaps
5. [ ] Change conflicts with existing doctrine
6. [ ] Required revalidation steps cannot be completed

---

## Post-Change Monitoring

After any major change, monitor for 24-72 hours:

- [ ] Quick Health Audit runs daily
- [ ] No new errors in logs
- [ ] Audit verdicts are consistent
- [ ] No increase in escalation frequency
- [ ] No regression in test results

### Regression Detection

If after a change:
- Audit verdicts become inconsistent
- New errors appear in logs
- Services fail more frequently
- False alarms increase

**Action:** Roll back the change immediately. Investigate root cause. Do not re-deploy until root cause is resolved and change is re-approved.

---

## Rollback Procedure

If a change causes problems:

1. **Stop services**
   ```batch
   stop_all.bat
   ```

2. **Restore previous versions**
   - Restore model from backup
   - Restore bridge script from backup
   - Restore startup scripts from backup
   - Restore guardian docs from git

3. **Start services**
   ```batch
   start_llama_server.bat
   start_kb_bridge.bat
   ```

4. **Verify rollback**
   ```bash
   curl http://127.0.0.1:8090/health
   forensic_cli doctor
   ```

5. **Document rollback**
   - Note in incident log: what was rolled back, why, when
   - Report to reviewers

---

## Change Log Format

All changes must be logged in the **Strata Shield Incident and Change Log** at `D:\forensic-suite\guardian\STRATA_SHIELD_CHANGE_LOG.md`.

### Log Entry Format

```markdown
## [YYYY-MM-DD] — [Change Title]

**Change ID:** [CC-YYYYMMDD-NNN]  
**Date:** [YYYY-MM-DD]  
**Type:** [MINOR | MAJOR]  
**Component:** [model | bridge | watchdog | script | doctrine | integration]  
**Author:** [Name or "Strata"]  
**Reviewer:** [Name or "N/A"]  

### Summary
[Brief description of what changed]

### Rationale
[Why this change was made]

### Validation Performed
- [ ] Quick Health Audit
- [ ] Full Guardian Audit
- [ ] [Other checks]

### Issues Found
[Any issues discovered during validation]

### Approval
- [ ] Strata approved
- [ ] Human reviewer approved
- [ ] Release approver approved

### Rollback Procedure
[How to undo this change if needed]

### Status
[APPLIED | ROLLED BACK | PENDING]
```

---

## Emergency Changes

Emergency changes are changes required to restore service that cannot wait for full review.

### Emergency Change Process

1. **Notify** — Alert reviewers that an emergency change is in progress
2. **Implement** — Make the minimum change necessary to restore service
3. **Document** — Log the change immediately with "EMERGENCY" prefix
4. **Validate** — Run Quick Health Audit
5. **Review** — Full review within 48 hours of emergency change
6. **Close** — Document resolution and lessons learned

### Emergency Change Criteria

An emergency change is justified only when:
- Service is completely down
- Critical functionality is unavailable
- Security vulnerability requires immediate fix
- Data loss is occurring

An emergency change is NOT justified when:
- Change is convenient but not necessary
- Review process is slow but service is functional
- Change would improve quality but isn't critical

---

## Document Maintenance

**Last Updated:** 2026-03-23  
**Next Review:** 2026-06-23 (quarterly)  
**Update Triggers:**
- New change categories discovered
- Approval process changes
- Revalidation requirements change
- New component added to Strata Shield

**Location:** `D:\forensic-suite\guardian\STRATA_SHIELD_CHANGE_CONTROL.md`

---

## Appendix A — Incident and Change Log

**Log file:** `D:\forensic-suite\guardian\STRATA_SHIELD_CHANGE_LOG.md`

**Sample entries from current system:**

| Change ID | Date | Type | Component | Summary |
|-----------|------|------|-----------|---------|
| CC-20260323-001 | 2026-03-23 | MAJOR | doctrine | Initial guardian doctrine established |
| CC-20260323-002 | 2026-03-23 | MAJOR | integration | KB bridge integration with ForensicSuite |
| CC-20260323-003 | 2026-03-23 | MINOR | documentation | Guardian knowledge base organized |
| — | — | — | — | Add new entries above this line |

*[New entries added as changes occur]*
