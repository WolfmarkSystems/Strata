# Strata Shield — Roadmap

**Document Type:** Strategic Roadmap  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Authority:** Strata — Suite Guardian  
**Status:** Active Development

---

## Executive Summary

Strata Shield is a protective subsystem for the ForensicSuite built around a Llama-based AI runtime, structured guardian doctrine, and enforceable validation procedures. The foundation is operational: the model server runs, the bridge responds, the watchdog monitors, and the guardian knowledge base encodes doctrine. The short-term roadmap focuses on closing known gaps in test infrastructure and validation automation. The medium-term roadmap focuses on deeper integration with the evidence processing pipeline. The long-term roadmap envisions Strata Shield as an always-on workstation protector that validates evidence integrity continuously.

---

## Completed Foundation

As of 2026-03-23, the following foundation is in place and operational:

### Runtime Infrastructure ✅

| Component | Status | Details |
|-----------|--------|---------|
| Llama server | ✅ Operational | `llama-server.exe` on port 8080 |
| Model files | ✅ In place | Llama 3.1 70B primary, 8B fallback |
| KB bridge | ✅ Operational | `dfir_kb_bridge.py` on port 8090 |
| Health endpoint | ✅ Operational | `http://127.0.0.1:8090/health` |
| Watchdog | ✅ Basic | Service monitoring and restart |
| Local-only operation | ✅ Enforced | No cloud inference dependencies |

### Guardian Knowledge Base ✅

| Document | Status | Purpose |
|---------|--------|---------|
| `SUITE_GUARDIAN_PROFILE.md` | ✅ Complete | Identity, authority, boundaries |
| `TRUTHFULNESS_RULES.md` | ✅ Complete | 11 non-negotiable evidence contracts |
| `PARSER_CONVENTIONS.md` | ✅ Complete | Parser quality standards |
| `KNOWN_GAPS.md` | ✅ Complete | Honest capability inventory |
| `RUNTIME_FAILURE_PATTERNS.md` | ✅ Complete | Dangerous pattern catalog |
| `COMMAND_CONTRACTS.md` | ✅ Complete | CLI-to-GUI contract reference |
| `RUN_STRATA_SUITE_AUDIT.md` | ✅ Complete | Master audit procedure |
| `RUN_STRATA_PARSER_REVIEW.md` | ✅ Complete | Parser review SOP |
| `STRATA_AUDIT_REPORT_TEMPLATE.md` | ✅ Complete | Standardized report format |
| `STRATA_*_CHECKLIST.md` (5) | ✅ Complete | Validation checklists |
| `STRATA_SHIELD_*.md` (4) | ✅ Complete | System documentation |

### Operational Procedures ✅

| Procedure | Status | Details |
|-----------|--------|---------|
| Audit runbooks | ✅ 6 modes | Quick Health → Full Guardian |
| Parser review SOP | ✅ 7 phases | VERIFIED → REJECTED |
| Maintenance procedures | ✅ Complete | `STRATA_SHIELD_MAINTENANCE.md` |
| Change control | ✅ Complete | Minor/Major classification |
| Dependency map | ✅ Complete | `STRATA_SHIELD_DEPENDENCY_MAP.md` |

### Integration Points ✅

| Integration | Status | Details |
|-------------|--------|---------|
| CLI envelope reading | ✅ Operational | `forensic_cli doctor`, `capabilities`, etc. |
| KB bridge → Llama | ✅ Operational | Chat completions forwarding |
| Health monitoring | ✅ Basic | Health endpoint and watchdog |
| Guardian → Suite | ✅ Basic | Strata validates CLI outputs |

---

## Current Operational Capabilities

Strata Shield can currently:

### Observing and Validating

- [x] Read CLI command envelopes and validate structure
- [x] Verify envelope status fields (`ok`, `warn`, `error`) against actual outcomes
- [x] Check for placeholder text (TBD, TODO, STUB) in outputs
- [x] Validate parser output quality through code inspection
- [x] Run structured audits with PASS/FAIL verdicts
- [x] Review new parsers with VERIFIED/REJECTED verdicts
- [x] Maintain known gaps inventory as evidence processing changes
- [x] Document runtime failure patterns as they are discovered

### Protecting Against

- [x] Evidence fabrication (invented artifacts presented as real)
- [x] Placeholder artifacts counted as evidence
- [x] Silent error suppression (failures returned as empty success)
- [x] Zero-row results labeled as successful indexing
- [x] GUI claims exceeding CLI reality
- [x] Unsupported format formats claimed as supported
- [x] Missing source path provenance on artifacts
- [x] Sidecar/model identity mismatch

### Advisory Functions

- [x] Recommend parser approval or rejection
- [x] Issue suite release readiness verdicts
- [x] Escalate uncertain findings to human reviewers
- [x] Maintain audit trail of all verdicts and findings
- [x] Provide remediation guidance for identified issues

---

## Short-Term Next Steps (0-3 Months)

The short-term roadmap focuses on closing the test infrastructure gaps documented in `KNOWN_GAPS.md` and improving validation automation.

### Priority 1: Fix Test Compilation

**Blocker:** `missing field blake3 in HashResults` test compilation error

**Required action:**
- Update `HashResults` struct to include `blake3` field
- Add `Default` implementations to structs flagged by clippy
- Run `cargo test --workspace --no-run` to verify compilation

**Estimated effort:** 1-2 days  
**Validation:** All tests compile, all tests pass

---

### Priority 2: Resolve Clippy Errors

**Blocker:** 25+ clippy errors (structs without Default impl)

**Required action:**
- Add `#[derive(Default)]` to appropriate structs
- Fix any legitimate clippy warnings
- Run `cargo clippy --workspace -- -D warnings`

**Estimated effort:** 1-3 days  
**Validation:** `cargo clippy` passes with zero errors

---

### Priority 3: Automated Gap Tracking

**Current state:** `KNOWN_GAPS.md` maintained manually  
**Goal:** Automated gap detection and tracking

**Required action:**
- Script that scans code for `// STUB:` annotations
- Script that compares `capabilities` output against documented gaps
- Automated update to `KNOWN_GAPS.md` on stub discovery
- Report new gaps in audit reports

**Estimated effort:** 1-2 weeks  
**Validation:** Script detects all documented stubs, reports new ones

---

### Priority 4: Automated Envelope Validation

**Current state:** Envelope validation done manually per checklist  
**Goal:** Automated validation of envelope structure

**Required action:**
- JSON schema for `CliResultEnvelope`
- Script to validate envelopes against schema
- Automated check in audit runbooks
- Fail-fast on envelope structure violations

**Estimated effort:** 1-2 weeks  
**Validation:** All envelope checks in checklists automated

---

### Priority 5: Evidence Fixture Library

**Current state:** No centralized test evidence  
**Goal:** Representative evidence fixtures for all validation modes

**Required action:**
- Create synthetic test images (RAW, E01, directory)
- Create synthetic parser target files (EVTX, registry hives, prefetch)
- Create edge case fixtures (empty files, truncated files, corrupted headers)
- Document expected outputs for each fixture
- Store in `D:\forensic-suite\fixtures\`

**Estimated effort:** 2-4 weeks  
**Validation:** All ingest validation checks use fixtures, results match expected

---

## Medium-Term Integration Goals (3-12 Months)

The medium-term roadmap focuses on deeper integration with the evidence processing pipeline and extending the guardian's observational range.

### Goal M1: Real-Time Evidence Validation

**Current state:** Evidence validation runs on-demand via audits  
**Goal:** Continuous validation during evidence processing

**Proposed capability:**
- Guardian observes evidence processing in real-time
- Validates each CLI command envelope as it is produced
- Flags failures immediately, not after the fact
- Operators see warnings during processing, not after

**Required work:**
- Integration with Tauri backend (observe command invocations)
- Real-time envelope validation (vs. post-hoc)
- Alerting system for truthfulness violations
- Operator notification channel

**Estimated effort:** 2-3 months  
**Risk:** Performance impact on evidence processing must be minimal

---

### Goal M2: Automated Parser Regression Detection

**Current state:** Parser review runs manually per `RUN_STRATA_PARSER_REVIEW.md`  
**Goal:** Automated detection of parser regression in CI

**Proposed capability:**
- Parser tests run on every commit
- Automated comparison of parser output against baseline
- Detection of output quality regression (fewer artifacts, wrong types)
- Automated filing of parser issues

**Required work:**
- Parser test fixture library (Goal M5)
- Baseline output snapshots for each parser
- Diffing engine for artifact comparison
- CI integration for automated runs

**Estimated effort:** 1-2 months  
**Risk:** False positives from fixture sensitivity

---

### Goal M3: GUI/CLI Contract Automation

**Current state:** GUI/CLI contract validation runs manually per checklist  
**Goal:** Automated contract validation with every GUI or CLI change

**Proposed capability:**
- Automated schema validation of CLI command outputs
- Automated checking of GUI page claims against CLI reality
- Diff detection when CLI output shapes change
- Automated flagging of broken contracts

**Required work:**
- JSON schemas for all CLI command outputs
- GUI claim extraction (parse GUI code for claim patterns)
- Diffing and validation scripts
- CI integration

**Estimated effort:** 1-2 months  
**Risk:** Schema maintenance overhead as commands evolve

---

### Goal M4: Fallback Mode Instrumentation

**Current state:** KB bridge exposes `embedding_backend`; other fallbacks not instrumented  
**Goal:** All fallback modes are instrumented and visible

**Proposed capability:**
- Detection when VHD/VMDK partial mode is active
- Detection when APFS/XFS partial enumeration is active
- Detection when BitLocker detection-only mode is active
- Unified fallback status panel in GUI
- Fallback activation logged in audit trail

**Required work:**
- Instrument each fallback point in engine code
- Expose fallback status via envelope fields
- GUI panel for fallback status
- Fallback logging in audit trail

**Estimated effort:** 1-2 months  
**Risk:** Instrumenting too many points adds complexity

---

### Goal M5: Guardian Reporting Dashboard

**Current state:** Audit reports filed as markdown documents  
**Goal:** Visual dashboard of suite health and guardian activity

**Proposed capability:**
- Dashboard showing current audit verdicts
- Trend charts of issue counts over time
- Open issues with resolution status
- Upcoming audit schedule
- Guardian activity feed

**Required work:**
- Dashboard frontend (React + Tauri)
- Data aggregation from audit reports
- Issue tracking integration
- Alert notification system

**Estimated effort:** 1-2 months  
**Risk:** Dashboard maintenance becomes a burden

---

## Long-Term Workstation Protector Goals (12+ Months)

The long-term vision is for Strata Shield to operate as an always-on protective layer that continuously monitors the ForensicSuite and workstation environment.

### Vision: Always-On Guardian

**Concept:** Strata Shield runs continuously, not just during audits. It monitors:
- Suite runtime health
- Evidence processing integrity
- Operator actions for accidental evidence contamination
- Workstation state (disk space, memory, process health)
- Configuration drift from known-good state

### Proposed Capabilities

| Capability | Description | Priority |
|------------|-------------|----------|
| Continuous health monitoring | Watchdog runs 24/7, alerts on anomalies | HIGH |
| Evidence contamination detection | Detect accidental modification of evidence files | HIGH |
| Configuration drift detection | Alert when suite config diverges from baseline | MEDIUM |
| Audit scheduling automation | Run full audits on schedule (weekly, pre-release) | MEDIUM |
| Operator behavior monitoring | Warn when evidence paths are writable | LOW |
| Cross-case contamination detection | Warn when case files overlap | LOW |

### Prerequisites for Long-Term Vision

Before Strata Shield can operate as an always-on protector:

1. **Validation maturity** — All short-term and medium-term goals must be complete
2. **False positive rate** — Must be low enough that operators trust alerts
3. **Performance overhead** — Must be negligible on workstation resources
4. **Operational acceptance** — Operators must understand and accept guardian role
5. **Incident response** — Clear procedures for when guardian alerts fire
6. **Human oversight** — Guardian remains advisory; operators retain authority

---

## Known Risks and Limiting Assumptions

### Risk 1: Model Quality Uncertainty

**Risk:** Llama model responses may be inconsistent or incorrect, leading to wrong verdicts.

**Mitigation:**
- Strata verdicts are traceable to evidence, not model confidence
- All verdicts can be audited and reviewed by humans
- Model is advisory; humans retain final authority

**Limiting assumption:** Model is trusted for advisory functions only, not for evidence evaluation.

---

### Risk 2: Fixture Representativeness

**Risk:** Test fixtures may not represent real forensic evidence, leading to missed failures.

**Mitigation:**
- Prioritize real evidence fixtures where possible
- Document fixture limitations in validation reports
- Require runtime validation on real evidence before final approval

**Limiting assumption:** Automated validation is incomplete without real evidence testing.

---

### Risk 3: Validation Overhead

**Risk:** Comprehensive validation takes too long, creating bottlenecks in development.

**Mitigation:**
- Tiered validation (Quick → Full) based on change type
- Automated checks in CI for common issues
- Manual review reserved for complex changes

**Limiting assumption:** Some validation requires human judgment that cannot be automated.

---

### Risk 4: Doctrine Drift

**Risk:** Guardian doctrine may diverge from actual suite behavior over time.

**Mitigation:**
- Doctrine is validated against suite on every audit
- Known gaps are updated when new gaps are discovered
- Change control requires doctrine consistency review

**Limiting assumption:** Doctrine maintenance requires discipline and human oversight.

---

### Risk 5: Environment Dependencies

**Risk:** Validation results may vary across environments (OS, RAM, disk speed).

**Mitigation:**
- Document environment for each audit
- Establish baseline for primary environment
- Test on secondary environments before deployment

**Limiting assumption:** Validation is authoritative for the tested environment only.

---

## Trust Thresholds for Production Deployment

Strata Shield is not yet ready for unsupervised production use. The following thresholds must be met before Strata Shield can be trusted in a real forensic workstation:

### Required Before Production

| Threshold | Current Status | Required Status |
|-----------|---------------|----------------|
| All tests compile | ❌ FAILING | ✅ PASSING |
| Clippy clean | ❌ FAILING | ✅ PASSING |
| Test fixtures exist | ❌ MISSING | ✅ EXISTS |
| Parser regression detection | ❌ MANUAL | ✅ AUTOMATED |
| Envelope validation | ❌ MANUAL | ✅ AUTOMATED |
| Known gap tracking | ❌ MANUAL | ✅ AUTOMATED |
| GUI/CLI contract automation | ❌ MANUAL | ✅ AUTOMATED |
| False positive rate | ❌ UNKNOWN | ✅ <5% |
| Human review process | ✅ EXISTS | ✅ EXISTS |
| Change control | ✅ EXISTS | ✅ EXISTS |

### Estimated Timeline to Production Readiness

| Phase | Target | Dependencies |
|-------|--------|--------------|
| Test infrastructure fixed | 1 month | Priority 1-2 complete |
| Automated gap tracking | 2 months | Priority 3 complete |
| Automated envelope validation | 3 months | Priority 4 complete |
| Evidence fixture library | 4 months | Priority 5 complete |
| Parser regression automation | 5 months | Goal M2 complete |
| GUI/CLI contract automation | 6 months | Goal M3 complete |
| **Production ready** | **6-12 months** | **All above** |

---

## Roadmap Maintenance

**Last Updated:** 2026-03-23  
**Next Review:** 2026-06-23 (quarterly)  
**Update Triggers:**
- Short-term goals completed
- New goals discovered
- Risks materialized or mitigated
- Dependencies change
- Production readiness thresholds updated

**Change process:** See `STRATA_SHIELD_CHANGE_CONTROL.md`

**Location:** `D:\forensic-suite\guardian\STRATA_SHIELD_ROADMAP.md`
