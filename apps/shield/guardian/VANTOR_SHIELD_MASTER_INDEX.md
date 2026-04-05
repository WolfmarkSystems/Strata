# Strata Shield — Master Index

**Document Type:** Documentation Index  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Authority:** Strata — Suite Guardian  
**Location:** `D:\forensic-suite\guardian\STRATA_SHIELD_MASTER_INDEX.md`

---

> **Start here.** This is the entry point to the entire Strata Shield documentation system. If you are new to Strata Shield, or if you need to find a specific document, this index tells you where to go and why.

---

## Section 1 — Purpose of This Index

### What Strata Shield Is

Strata Shield is the guardian subsystem of the ForensicSuite. It is a layered protective architecture built around a Llama-based AI runtime, a structured knowledge base encoding doctrine, and enforceable validation procedures. Its purpose is to ensure that every piece of evidence processed by the ForensicSuite is handled with integrity, every result presented to an examiner is truthful, and every automated decision is auditable and reversible.

Strata Shield does not conduct investigations. It observes what the suite produces, validates output against documented contracts, flags when reality diverges from documentation, and protects against silent failures propagating as successes.

### Why This Master Index Exists

The Strata Shield knowledge base contains 22 documents across 6 functional categories: doctrine, truth rules, parser standards, operational checklists, runbooks, and system documentation. This index provides a single authoritative entry point so that Strata and human operators can:
- Understand what documents exist and what each one is for
- Find the right document for the current task
- Trace how documents relate to each other
- Follow recommended reading paths for specific roles

### Who Should Use This Index

| Role | Primary Use |
|------|------------|
| **Strata** | Autonomous operation: find the right checklist or runbook for any audit task |
| **New operator** | Learning: follow the "New Operator" reading path in Section 7 |
| **Developer (parser)** | Development: follow the "Parser Developer" reading path in Section 7 |
| **Developer (runtime)** | Development: follow the "Runtime Developer" reading path in Section 7 |
| **Auditor** | Validation: follow the "Auditor" reading path in Section 7 |
| **Release reviewer** | Deployment: follow the "Release Reviewer" reading path in Section 7 |
| **Human reviewer** | Oversight: understand what Strata validates and how |

### How to Use This Index

1. **Start with Section 2** — Understand the six documentation layers
2. **Jump to your role's reading path** (Section 7) — Know what to read in what order
3. **Use individual sections** — Go directly to Section 3-6 for specific document categories
4. **Reference the workflow** (Section 8) — See how the pieces fit together operationally
5. **Check scope boundaries** (Section 9) — Know what still requires live runtime validation

---

## Section 2 — Documentation System Overview

The Strata Shield knowledge base is organized into six layers, from foundational doctrine to operational execution.

### Layer 1: Core Doctrine

**What it is:** The identity, authority, and boundaries of Strata, plus AI governance documents that define capability scope, audit requirements, and data sovereignty for government and law enforcement deployments.

**Documents:**
- `SUITE_GUARDIAN_PROFILE.md`
- `AI_SCOPE_AND_LIMITATIONS.md`
- `AI_AUDIT_TRAIL.md`
- `AI_SOVEREIGNTY_STATEMENT.md`

**Purpose:** Foundational reference. Strata and human reviewers return here when there is ambiguity about role or authority, AI capability boundaries, audit logging requirements, or data sovereignty compliance.

---

### Layer 2: Truth Rules and Standards

**What it is:** The non-negotiable contracts that govern evidence handling. These documents define what truthful, evidence-derived output looks like and what patterns are prohibited.

**Documents:**
- `TRUTHFULNESS_RULES.md`
- `PARSER_CONVENTIONS.md`

**Purpose:** Standards against which all parser outputs, CLI envelopes, and GUI displays are validated. If something in the suite violates these rules, Strata flags it.

---

### Layer 3: Capability and Failure Inventories

**What it is:** Honest accounting of what the suite can and cannot do, and a catalog of dangerous runtime patterns Strata must recognize.

**Documents:**
- `KNOWN_GAPS.md`
- `RUNTIME_FAILURE_PATTERNS.md`
- `COMMAND_CONTRACTS.md`

**Purpose:** Strata uses these to verify that capability claims match implementation, and to recognize and respond to dangerous failure patterns before they produce false conclusions.

---

### Layer 4: Validation Checklists

**What it is:** Itemized, repeatable validation procedures covering runtime health, ingest pipeline, GUI/CLI contracts, parser quality, and release readiness.

**Documents:**
- `STRATA_RUNTIME_AUDIT_CHECKLIST.md` — 38 items
- `STRATA_INGEST_VALIDATION_CHECKLIST.md` — 42 items
- `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` — 30 items
- `STRATA_PARSER_REVIEW_CHECKLIST.md` — 21 items
- `STRATA_RELEASE_READINESS_CHECKLIST.md` — 55 items

**Purpose:** Strata runs these during audits to ensure no check is skipped. Each checklist maps to a specific validation domain.

---

### Layer 5: Operational Runbooks

**What it is:** Step-by-step procedures for conducting audits and parser reviews. Runbooks orchestrate checklists and produce structured outputs.

**Documents:**
- `RUN_STRATA_SUITE_AUDIT.md` — Master audit procedure
- `RUN_STRATA_PARSER_REVIEW.md` — Parser review SOP
- `STRATA_AUDIT_REPORT_TEMPLATE.md` — Standardized report format

**Purpose:** Strata follows these procedures to produce consistent, auditable results. Reports filed using the template are comparable across audits.

---

### Layer 6: Strata Shield System Documentation

**What it is:** Architecture, maintenance, dependency, change control, and roadmap for the Strata Shield runtime subsystem itself (Llama server, KB bridge, watchdog, model).

**Documents:**
- `STRATA_SHIELD_ARCHITECTURE.md`
- `STRATA_SHIELD_MAINTENANCE.md`
- `STRATA_SHIELD_DEPENDENCY_MAP.md`
- `STRATA_SHIELD_CHANGE_CONTROL.md`
- `STRATA_SHIELD_ROADMAP.md`

**Purpose:** Governs how the Strata Shield runtime is built, maintained, changed, and evolved. Operators and developers reference these to understand system dependencies and maintenance procedures.

---

## Section 3 — Core Doctrine Documents

### SUITE_GUARDIAN_PROFILE.md

| Property | Value |
|----------|-------|
| **Purpose** | Defines Strata's identity, authority, and operating boundaries |
| **When to read** | First time using Strata Shield; whenever role or authority is ambiguous |
| **What decisions it informs** | What Strata is allowed to do; what Strata must not do; escalation triggers |

**Key contents:**
- Identity statement: "Strata does not conduct investigations. Strata protects the tools."
- Five core protection responsibilities: truthfulness, evidence integrity, parser quality, runtime safety, GUI/CLI contract consistency
- Guardian operating principles: conservative, auditable, explainable
- Explicit prohibitions: never fabricate evidence, never count placeholders as evidence, never call zero-row results successful

---

### AI_SCOPE_AND_LIMITATIONS.md

| Property | Value |
|----------|-------|
| **Purpose** | Authoritative capability boundary statement for government and LE deployment. Answers what the AI can and cannot do, CJIS alignment, and what examiners can say under oath. |
| **When to read** | Before any government, LE, or national security deployment; when legal counsel asks about AI scope |
| **What decisions it informs** | What AI capabilities can be claimed; what must be disclosed; courtroom testimony boundaries |

**Key contents:**
- Two-tier AI architecture (Tier 1: Knowledge Retrieval, Tier 2: Summarization)
- Explicit capability boundaries and prohibitions
- CJIS Security Policy alignment matrix
- What an examiner can truthfully state under oath about the AI

---

### AI_AUDIT_TRAIL.md

| Property | Value |
|----------|-------|
| **Purpose** | Complete logging specification for all AI interactions. Covers what is logged, where it is stored, how to retrieve it, and what a supervisor or court can verify. |
| **When to read** | When responding to discovery requests; when configuring audit logging; during CJIS audits |
| **What decisions it informs** | What fields are in the audit log; how to export AI interaction records; what supervisors and courts can verify |

**Key contents:**
- 14-field log entry specification (entry_id, case_id, examiner_id, timestamp, operation type, query text, results, etc.)
- Examiner action tracking (reviewed_only, used_as_reference, discarded, no_action)
- Dual storage: case SQLite database + append-only JSONL file
- Immutability requirements (no UPDATE/DELETE on log entries)
- Retrieval procedures for legal discovery

---

### AI_SOVEREIGNTY_STATEMENT.md

| Property | Value |
|----------|-------|
| **Purpose** | One-page procurement and court declaration of local-only deployment with nine verifiable sovereignty properties |
| **When to read** | RFP responses, procurement packages, court filings, agency policy submissions |
| **What decisions it informs** | Data sovereignty claims; air-gap compatibility; procurement compliance statements |

**Key contents:**
- Nine verifiable sovereignty properties (local inference, no network calls, no telemetry, static model, etc.)
- Verification procedures for each property
- Suitable for inclusion in RFP responses and court declarations

---

### TRUTHFULNESS_RULES.md

| Property | Value |
|----------|-------|
| **Purpose** | 11 non-negotiable evidence contracts that must never be violated |
| **When to read** | Before validating any parser, CLI output, or GUI display |
| **What decisions it informs** | Whether output is truthful or fabricated; when to escalate |

**Key contents:**
- Rule 1: Container opened ≠ filesystem parsed
- Rule 4: Zero rows ≠ success (unless explicitly empty by design)
- Rule 5: Synthetic/debug placeholders ≠ real evidence
- Rule 8: GUI claims ≤ CLI reality
- Rule 10: Missing data must not be fabricated
- Rule 11: Sidecar health ≠ bridge health

---

### PARSER_CONVENTIONS.md

| Property | Value |
|----------|-------|
| **Purpose** | Quality standards and anti-patterns for ArtifactParser implementations |
| **When to read** | Before reviewing or writing a parser; during parser approval |
| **What decisions it informs** | Whether a parser meets quality standards; when to reject a parser |

**Key contents:**
- Required parser behavior (deterministic, evidence-derived, explicit error handling)
- Signs of a bad parser (fake defaults, swallowed errors, missing provenance, placeholder artifacts)
- Stubbed parser requirements
- Parser error type taxonomy

---

### KNOWN_GAPS.md

| Property | Value |
|----------|-------|
| **Purpose** | Honest capability inventory: what the suite can and cannot do |
| **When to read** | Before validating capability claims; during release readiness |
| **What decisions it informs** | Whether a capability claim matches implementation; what limitations must be disclosed |

**Key contents:**
- Section A: Container format support (RAW, E01 complete; VHD, VMDK partial; VHDX, AFF4, LUKS stubbed)
- Section B: Filesystem support (NTFS, FAT32, ext4 complete; APFS, XFS partial)
- Section C: Parser coverage (stubbed classification modules, partial parsers)
- Section D: Hash and hashset workflows
- Section G: Test coverage status
- Section H: Strata-specific gaps (automated gap tracking not yet implemented)

---

### RUNTIME_FAILURE_PATTERNS.md

| Property | Value |
|----------|-------|
| **Purpose** | Catalog of dangerous runtime patterns Strata must recognize and respond to |
| **When to read** | During runtime validation; when investigating unexplained failures |
| **What decisions it informs** | Whether observed behavior is a known failure pattern; how to respond |

**Key contents:**
- Pattern 1: Instant indexing with no data (implausibly fast, zero rows)
- Pattern 2: Success envelope with zero real rows (status ok, data empty)
- Pattern 3: Filesystem detected but tree/filetable empty
- Pattern 5: Sidecar missing / wrong model / wrong path
- Pattern 9: Evidence integrity chain broken
- Pattern 10: Container opens but returns zeros for all reads

---

### COMMAND_CONTRACTS.md

| Property | Value |
|----------|-------|
| **Purpose** | Documents CLI command output shapes and how GUI must handle them |
| **When to read** | When validating GUI/CLI contracts; when adding new CLI commands |
| **What decisions it informs** | Whether GUI claims match CLI reality; what envelope fields are required |

**Key contents:**
- `CliResultEnvelope` contract (all fields, status values, envelope rules)
- Command inventory (capabilities, doctor, smoke-test, verify, triage-session, examine, timeline, hashset commands, open-evidence, filetable)
- Safe integration rules (don't assume output shape, don't overclaim, preserve warnings)
- Tauri command mapping
- Error handling contract

---

## Section 4 — Operational Checklists

### STRATA_RUNTIME_AUDIT_CHECKLIST.md

| Property | Value |
|----------|-------|
| **Coverage** | 38 validation items across 8 sections |
| **Sections** | Build validation, test validation, sidecar/runtime validation, command validation, history/log validation, packaging validation, truthfulness validation, fallback/partial-state validation |
| **When to run** | During Phase 3 (Runtime Validation) of the Full Guardian Audit |
| **Output** | Pass/fail per item, overall status, sign-off |
| **Verdict it supports** | PASS / CONDITIONAL / FAIL |

---

### STRATA_PARSER_REVIEW_CHECKLIST.md

| Property | Value |
|----------|-------|
| **Coverage** | 21 validation items across 10 sections |
| **Sections** | Identity/naming, contract review, evidence output, error handling, provenance, timestamp handling, timeline suitability, placeholder review, test fixtures, performance/safety |
| **When to run** | During Phase 6 (Parser Review) of the Full Guardian Audit; whenever a new or modified parser is submitted |
| **Output** | Per-section pass/fail, review status: APPROVED / APPROVED WITH CONDITIONS / REQUIRES REVISION / REJECTED |
| **Verdict it supports** | Parser integration approval |

---

### STRATA_INGEST_VALIDATION_CHECKLIST.md

| Property | Value |
|----------|-------|
| **Coverage** | 42 validation items across 9 layers + 7 special test cases |
| **Layers** | Container opened, partition/volume discovered, filesystem detected, enumeration succeeded, indexing succeeded, tree populated, filetable populated, artifact/timeline populated, GUI status correctness |
| **When to run** | During Phase 4 (Ingest Validation) of the Full Guardian Audit; after container/filesystem/parser changes |
| **Output** | Per-layer pass/fail, overall ingest status |
| **Verdict it supports** | PASS / PARTIAL / FAIL |

---

### STRATA_GUI_CLI_CONTRACT_CHECKLIST.md

| Property | Value |
|----------|-------|
| **Coverage** | 30 validation items across 8 sections + page-by-page review (10 pages) |
| **Sections** | Adapter mode checks, required context checks, empty/error state review, fallback mode visibility, count/value truthfulness, page-by-page contract review, command-to-field mapping, warning/error preservation |
| **When to run** | During Phase 5 (GUI/CLI Contract Validation) of the Full Guardian Audit; after adding new GUI pages or changing CLI output shapes |
| **Output** | Per-page contract status, overall contract status |
| **Verdict it supports** | PASS / ISSUES FOUND / CRITICAL |

---

### STRATA_RELEASE_READINESS_CHECKLIST.md

| Property | Value |
|----------|-------|
| **Coverage** | 55 validation items across 12 sections |
| **Sections** | Workspace build/tests, Tauri build/package, sidecar sync, model/runtime validation, local-only mode, settings/history, package artifact verification, GUI sanity, command sanity, truthfulness sanity, operator-facing warnings, startup scripts |
| **When to run** | Pre-release final gate; before portable package creation; before deployment to new workstation |
| **Output** | Blocking issues table, non-blocking issues table, overall release status |
| **Verdict it supports** | RELEASE APPROVED / RELEASE WITH WARNINGS / RELEASE BLOCKED |

---

## Section 5 — Runbooks

### RUN_STRATA_SUITE_AUDIT.md

| Property | Value |
|----------|-------|
| **Type** | Master operational runbook |
| **Purpose** | Canonical procedure for conducting complete, repeatable, auditable suite audits |
| **Operator use case** | Running any type of audit (Quick Health → Full Guardian); rendering verdicts |
| **How it connects to checklists** | Orchestrates all 5 checklists by phase; synthesizes findings into verdict |

**Key contents:**
- 6 audit modes: Quick Health, Build/Test, Ingest Validation, GUI/CLI, Release Readiness, Full Guardian
- 7-phase standard sequence: Establish Reality → Build/Test → Runtime → Ingest → GUI/CLI → Parser Review → Verdict
- Decision rules (7 non-negotiable rules)
- Escalation rules (6 scenarios requiring escalation)
- Inputs/outputs specification
- Required evidence to collect

---

### RUN_STRATA_PARSER_REVIEW.md

| Property | Value |
|----------|-------|
| **Type** | Focused SOP for parser review |
| **Purpose** | Standardized procedure for reviewing new or modified parser modules |
| **Operator use case** | Pre-merge review of parser submissions; incident review of suspicious parsers |
| **How it connects to checklists** | References `STRATA_PARSER_REVIEW_CHECKLIST.md` (21 items); adds procedural sequence, red flags, escalation rules, and report template |

**Key contents:**
- 7-phase review sequence: Identity → Contract → Truthfulness → Quality → Failure Modes → Test/Fixtures → Verdict
- 14 red flags with severity levels (CRITICAL/HIGH/MEDIUM)
- Escalation rules (6 scenarios requiring escalation)
- Required evidence for approval (6 categories)
- Built-in parser review report template

---

### STRATA_AUDIT_REPORT_TEMPLATE.md

| Property | Value |
|----------|-------|
| **Type** | Standardized report template |
| **Purpose** | Uniform output format for all audit types |
| **Operator use case** | Filing completed audit reports; comparing audits over time |
| **How it connects to checklists** | Maps findings to severity classifications; references checklist pass rates |

**Key contents:**
- 11 required sections + 3 appendices
- Severity classification: CRITICAL / HIGH / MEDIUM / LOW
- Claim verification matrix (VERIFIED / PARTIAL / STUBBED / FALSE / UNVERIFIABLE)
- Verdict: PASS / PASS WITH WARNINGS / PARTIAL / FAIL
- Sign-off with human approval for release-blocking audits
- Prior audit delta comparison appendix

---

## Section 6 — Strata Shield System Documentation

### STRATA_SHIELD_ARCHITECTURE.md

| Property | Value |
|----------|-------|
| **Purpose** | Documents the Strata Shield runtime subsystem: Llama server, KB bridge, watchdog, knowledge base, suite integration |
| **When to use** | Understanding how Strata Shield is built; understanding what each layer does |
| **What decisions it informs** | System boundaries; what Strata Shield can and cannot observe; trust model |

**Key contents:**
- Layered architecture diagram
- Component descriptions (Llama runtime, bridge, watchdog, guardian KB, suite integration)
- Operating boundaries (what Strata Shield can observe, advise on, must not do)
- Trust model (local-only, auditable, conservative, evidence-preserving)
- Suite integration points (CLI envelope reading, engine observation, GUI validation)

---

### STRATA_SHIELD_MAINTENANCE.md

| Property | Value |
|----------|-------|
| **Purpose** | Safe procedures for updating each Strata Shield component |
| **When to use** | Before updating model, bridge, scripts, or guardian docs; after any component change |
| **What decisions it informs** | How to update safely; how to validate after changes; how to roll back |

**Key contents:**
- Model update procedure (with backup and rollback)
- Primary/fallback model rotation
- KB bridge update procedure
- Startup script update procedure
- Guardian document update procedure
- Standard validation sequence after changes
- Post-upgrade checklist (immediate, short-term, long-term)
- Emergency rollback triggers

---

### STRATA_SHIELD_DEPENDENCY_MAP.md

| Property | Value |
|----------|-------|
| **Purpose** | Maps all Strata Shield dependencies, failure modes, and recovery paths |
| **When to use** | When diagnosing failures; planning maintenance; understanding cascading failures |
| **What decisions it informs** | Recovery priority order; what to restore first; graceful degradation paths |

**Key contents:**
- Runtime dependencies (Llama server, KB bridge, watchdog)
- File/path dependencies (model files, configs, logs)
- Startup dependencies (service order, port map)
- Model dependencies (primary, fallback)
- Suite repo dependencies (ForensicSuite workspace, Tauri GUI)
- Documentation dependencies (19 guardian documents, what breaks if each is missing)
- Single-point failures and cascading failure chains
- Recovery priority order

---

### STRATA_SHIELD_CHANGE_CONTROL.md

| Property | Value |
|----------|-------|
| **Purpose** | Governs how changes to Strata Shield are proposed, reviewed, approved, and logged |
| **When to use** | Before making any change to model, bridge, doctrine, or integration; during incident response |
| **What decisions it informs** | Whether a change is minor or major; what reviews are required; approval criteria |

**Key contents:**
- Change classification (minor vs. major) with examples for each component type
- Review requirements by change type (model, prompt/doctrine, bridge, watchdog, integration)
- Required revalidation steps by audit mode (Quick Health → Full Guardian)
- Approval criteria and sign-off requirements
- Post-change monitoring (24-72 hour observation)
- Rollback procedure
- Emergency change process
- Change log format

---

### STRATA_SHIELD_ROADMAP.md

| Property | Value |
|----------|-------|
| **Purpose** | Documents completed foundation, current capabilities, and future goals |
| **When to use** | Understanding what Strata Shield can do today; planning near-term work; setting expectations |
| **What decisions it informs** | What to prioritize next; what is blocking production readiness; what risks exist |

**Key contents:**
- Completed foundation catalog (runtime infrastructure, knowledge base, procedures, integration)
- Current operational capabilities (what Strata Shield can observe, protect against, advise on)
- Short-term next steps (0-3 months): fix test compilation, resolve clippy, automate gap tracking, automate envelope validation, build evidence fixture library
- Medium-term goals (3-12 months): real-time validation, parser regression detection, GUI/CLI contract automation, fallback instrumentation, reporting dashboard
- Long-term vision: always-on workstation protector
- Known risks and limiting assumptions
- Trust thresholds for production deployment (with current status and estimated timeline)

---

## Section 7 — Recommended Usage Paths

### Path 1: New Operator

**Goal:** Understand what Strata Shield is and how to work with it.

| Order | Document | Purpose |
|-------|---------|---------|
| 1 | `SUITE_GUARDIAN_PROFILE.md` | Understand Strata's identity and role |
| 2 | `TRUTHFULNESS_RULES.md` | Understand the evidence contracts |
| 3 | `STRATA_SHIELD_ARCHITECTURE.md` | Understand the system structure |
| 4 | `STRATA_SHIELD_MAINTENANCE.md` (Section 1-2) | Understand how to start and maintain the system |
| 5 | `RUN_STRATA_SUITE_AUDIT.md` (Sections 1-4) | Understand how auditing works |
| 6 | `STRATA_AUDIT_REPORT_TEMPLATE.md` (Sections 1-2) | Understand what audit reports look like |

**Expected outcome:** Understand Strata Shield's purpose, components, and how to run an audit.

---

### Path 2: Developer Changing Parser Code

**Goal:** Get a new or modified parser approved for integration.

| Order | Document | Purpose |
|-------|---------|---------|
| 1 | `PARSER_CONVENTIONS.md` | Understand quality standards |
| 2 | `TRUTHFULNESS_RULES.md` (Rules 3, 4, 5, 10) | Understand evidence-derived requirements |
| 3 | `RUNTIME_FAILURE_PATTERNS.md` (Patterns 1, 2, 8) | Understand dangerous patterns to avoid |
| 4 | `STRATA_PARSER_REVIEW_CHECKLIST.md` | Know what will be checked |
| 5 | `RUN_STRATA_PARSER_REVIEW.md` (Sections 1-7) | Follow the review procedure |
| 6 | `RUN_STRATA_PARSER_REVIEW.md` (Section 8) | Fill out the parser review report |

**Expected outcome:** A completed parser review report with APPROVED / APPROVED WITH WARNINGS / REJECTED verdict.

---

### Path 3: Developer Changing Runtime/Model/Bridge/Watchdog

**Goal:** Make changes to Strata Shield infrastructure safely and with proper review.

| Order | Document | Purpose |
|-------|---------|---------|
| 1 | `STRATA_SHIELD_ARCHITECTURE.md` | Understand current structure |
| 2 | `STRATA_SHIELD_DEPENDENCY_MAP.md` | Understand what depends on the component |
| 3 | `STRATA_SHIELD_CHANGE_CONTROL.md` (Section 2) | Classify the change |
| 4 | `STRATA_SHIELD_MAINTENANCE.md` (relevant section) | Follow update procedure |
| 5 | `STRATA_SHIELD_CHANGE_CONTROL.md` (Section 4) | Run required revalidation |
| 6 | `RUN_STRATA_SUITE_AUDIT.md` (Mode 1) | Run Quick Health Audit |
| 7 | `STRATA_SHIELD_CHANGE_CONTROL.md` (Section 6) | Log the change |

**Expected outcome:** Change applied safely, validated, and logged in the change log.

---

### Path 4: Auditor Validating the Suite

**Goal:** Conduct a complete suite audit and produce a report.

| Order | Document | Purpose |
|-------|---------|---------|
| 1 | `RUN_STRATA_SUITE_AUDIT.md` | Choose audit mode, follow 7-phase sequence |
| 2 | `STRATA_*_CHECKLIST.md` (5 files) | Execute relevant validation items |
| 3 | `TRUTHFULNESS_RULES.md` | Validate against evidence contracts |
| 4 | `KNOWN_GAPS.md` | Verify capability claims |
| 5 | `RUNTIME_FAILURE_PATTERNS.md` | Check for known failure patterns |
| 6 | `COMMAND_CONTRACTS.md` | Validate CLI output shapes |
| 7 | `STRATA_AUDIT_REPORT_TEMPLATE.md` | File the completed report |

**Expected outcome:** A completed audit report with PASS / PASS WITH WARNINGS / PARTIAL / FAIL verdict.

---

### Path 5: Release Reviewer Preparing a Workstation-Ready Build

**Goal:** Validate that the suite is ready for packaging and deployment.

| Order | Document | Purpose |
|-------|---------|---------|
| 1 | `STRATA_SHIELD_MAINTENANCE.md` (Section 9) | Run post-upgrade checklist if changes were made |
| 2 | `RUN_STRATA_SUITE_AUDIT.md` (Mode 5) | Run Release Readiness Audit |
| 3 | `STRATA_RELEASE_READINESS_CHECKLIST.md` | Execute all 55 validation items |
| 4 | `KNOWN_GAPS.md` | Verify all limitations are documented |
| 5 | `STRATA_SHIELD_ROADMAP.md` | Check production readiness thresholds |
| 6 | `STRATA_AUDIT_REPORT_TEMPLATE.md` | File the release audit report |
| 7 | `STRATA_SHIELD_CHANGE_CONTROL.md` (Section 6) | Log the release decision |

**Expected outcome:** A completed release audit report with RELEASE APPROVED / RELEASE WITH WARNINGS / RELEASE BLOCKED verdict and human sign-off.

---

## Section 8 — Guardian Workflow Summary

The Strata Shield documentation system is coherent. Here is how the pieces fit together operationally.

### The Validation Loop

```
┌─────────────────────────────────────────────────────┐
│  1. DOCTRINE (Layers 1-3)                          │
│     SUITE_GUARDIAN_PROFILE + TRUTHFULNESS_RULES +  │
│     PARSER_CONVENTIONS + KNOWN_GAPS +               │
│     RUNTIME_FAILURE_PATTERNS + COMMAND_CONTRACTS     │
│     ↓                                               │
│  2. RUNBOOKS (Layer 5)                               │
│     RUN_STRATA_SUITE_AUDIT / RUN_STRATA_PARSER_     │
│     REVIEW                                           │
│     ↓ Orchestrates ↓                                 │
│  3. CHECKLISTS (Layer 4)                            │
│     5 checklists × 186 total items                   │
│     ↓ Produces ↓                                    │
│  4. REPORT (Layer 5)                                 │
│     STRATA_AUDIT_REPORT_TEMPLATE                    │
│     ↓ Documents ↓                                   │
│  5. SYSTEM DOCS (Layer 6)                           │
│     Maintenance + Dependencies + Change Control       │
└─────────────────────────────────────────────────────┘
```

### What Happens During an Audit

1. **Strata reads doctrine** — Reviews `TRUTHFULNESS_RULES.md` and relevant `KNOWN_GAPS.md` sections to establish what to validate
2. **Strata follows runbook** — Executes `RUN_STRATA_SUITE_AUDIT.md` phase by phase
3. **Strata runs checklists** — Applies the 5 validation checklists across the appropriate phases
4. **Strata renders verdict** — Classifies findings by severity and issues PASS / PASS WITH WARNINGS / PARTIAL / FAIL
5. **Strata files report** — Uses `STRATA_AUDIT_REPORT_TEMPLATE.md` to document findings
6. **Strata updates system** — If gaps are new, updates `KNOWN_GAPS.md`; if patterns are new, updates `RUNTIME_FAILURE_PATTERNS.md`

### What Happens During Parser Review

1. **Strata reads standards** — Reviews `PARSER_CONVENTIONS.md` and `TRUTHFULNESS_RULES.md`
2. **Strata follows runbook** — Executes `RUN_STRATA_PARSER_REVIEW.md` phase by phase
3. **Strata applies checklist** — Runs `STRATA_PARSER_REVIEW_CHECKLIST.md` (21 items)
4. **Strata renders verdict** — Issues APPROVED / APPROVED WITH WARNINGS / REJECTED
5. **Strata files report** — Uses the built-in parser review report template

### What Happens During Maintenance

1. **Operator reads architecture** — Reviews `STRATA_SHIELD_ARCHITECTURE.md` and `STRATA_SHIELD_DEPENDENCY_MAP.md`
2. **Operator classifies change** — Uses `STRATA_SHIELD_CHANGE_CONTROL.md` to determine review requirements
3. **Operator executes maintenance** — Follows procedures in `STRATA_SHIELD_MAINTENANCE.md`
4. **Operator validates** — Runs Quick Health Audit or Full Guardian Audit as required
5. **Operator logs change** — Files change log entry in `STRATA_SHIELD_CHANGE_LOG.md`

---

## Section 9 — Scope Boundaries

### What These Documents Cover

The Strata Shield knowledge base covers:
- The guardian subsystem of the ForensicSuite
- Parser quality standards and validation procedures
- Evidence processing validation (container → filesystem → enumeration → parsing → GUI display)
- CLI-to-GUI contract validation
- Runtime health monitoring and watchdog procedures
- Model, bridge, and startup script maintenance
- Audit procedures and report formats
- Change control for the guardian subsystem

### What Still Requires Live Runtime Validation

These documents cannot replace live runtime validation in the following areas:

| Gap | Why Documentation Is Insufficient |
|-----|----------------------------------|
| **Parser output on real evidence** | Test fixtures may not represent real forensic files; timestamp epoch accuracy requires known-value test data |
| **Performance at scale** | GB-scale evidence behavior cannot be verified from code alone; streaming vs. full-load requires live testing |
| **Environment-specific issues** | Platform differences (Windows/Linux/macOS), RAM/VRAM constraints, disk speed affect behavior |
| **GUI rendering behavior** | Some GUI behaviors require the application running in a display environment |
| **Model response quality** | AI output correctness cannot be fully verified from documentation; requires empirical testing |
| **Fixture representativeness** | Whether synthetic fixtures accurately represent real-world evidence files cannot be determined from code alone |

### What Remains Environment-Specific

The following areas vary by deployment environment and cannot be fully characterized by documentation:
- Build timing thresholds (release build duration is environment-dependent)
- esbuild platform compatibility (currently broken on some Windows configurations)
- Frontend build requirements (React integration status depends on environment)
- Memory requirements for Llama model loading (varies by hardware)

### What Must Not Be Assumed from Documentation Alone

Do not assume:
- A capability is implemented because it is documented — verify against `KNOWN_GAPS.md` and runtime checks
- A parser is correct because its code looks right — run the parser review procedure
- A GUI page is truthful because it looks correct — run the GUI/CLI contract checklist
- The system is healthy because no errors are visible — run the Quick Health Audit
- A change is safe because it is minor — check `STRATA_SHIELD_CHANGE_CONTROL.md`

---

## Section 10 — Operating Doctrine Statement

Strata Shield is built on five non-negotiable principles that govern every validation, every verdict, and every decision in this knowledge base.

### Strata Shield Is Truth-First

The sole purpose of Strata Shield is to ensure that the ForensicSuite tells the truth about what it has found. Every document in this knowledge base serves that purpose. Gaps, failures, and limitations are acceptable — they are expected and can be worked around. False confidence is not acceptable. Fabricated evidence is a critical failure. Strata Shield will always prefer an honest "I don't know" over a confident lie.

### Strata Shield Is Conservative

Strata Shield errs on the side of under-reporting rather than over-reporting. When Strata cannot determine whether a capability is real or a stub, it treats it as unavailable until verified. When Strata cannot verify evidence quality, it escalates. False negatives — flagging something as untrustworthy when it is trustworthy — are acceptable. False positives — trusting something that is untrustworthy — are not.

### Strata Shield Is Auditable

Every verdict Strata Shield renders can be traced to specific evidence: the CLI output received, the envelope status, the parser behavior observed, the known gaps documented. Audit reports are filed with full evidence citations. The knowledge base is maintained with change control. The system is designed so that any human reviewer can independently verify any guardian finding.

### Strata Shield Is Evidence-Preserving

Strata Shield prioritizes evidence integrity over speed, convenience, and appearance. When evidence processing can be done faster but less safely, Strata recommends the safer path. When partial results are available but complete results are possible, Strata recommends completing the analysis before drawing conclusions. Evidence provenance — the chain from source file to artifact to timeline — is non-negotiable. An artifact without a source path is not acceptable.

### Strata Shield Is Escalation-Oriented When Uncertain

When Strata encounters uncertainty — ambiguous output, unverifiable claims, missing fixtures, or behavior that cannot be explained — Strata escalates rather than guessing. Strata does not paper over uncertainty with optimistic labels. Strata does not assume. Strata does not fill gaps with synthetic data. Strata logs the uncertainty and recommends manual review. Escalation is not a failure — it is the responsible choice when verification is incomplete.

---

## Document Index

All 22 documents in the Strata Shield knowledge base:

| # | Document | Layer | Lines |
|---|----------|-------|-------|
| 1 | `SUITE_GUARDIAN_PROFILE.md` | 1: Doctrine | 181 |
| 2 | `AI_SCOPE_AND_LIMITATIONS.md` | 1: Doctrine | — |
| 3 | `AI_AUDIT_TRAIL.md` | 1: Doctrine | 312 |
| 4 | `AI_SOVEREIGNTY_STATEMENT.md` | 1: Doctrine | — |
| 5 | `TRUTHFULNESS_RULES.md` | 2: Truth Rules | 280 |
| 6 | `PARSER_CONVENTIONS.md` | 2: Truth Rules | 373 |
| 7 | `KNOWN_GAPS.md` | 3: Inventories | 248 |
| 8 | `RUNTIME_FAILURE_PATTERNS.md` | 3: Inventories | 362 |
| 9 | `COMMAND_CONTRACTS.md` | 3: Inventories | 546 |
| 10 | `STRATA_RUNTIME_AUDIT_CHECKLIST.md` | 4: Checklists | 320 |
| 11 | `STRATA_PARSER_REVIEW_CHECKLIST.md` | 4: Checklists | 629 |
| 12 | `STRATA_INGEST_VALIDATION_CHECKLIST.md` | 4: Checklists | 403 |
| 13 | `STRATA_GUI_CLI_CONTRACT_CHECKLIST.md` | 4: Checklists | 615 |
| 14 | `STRATA_RELEASE_READINESS_CHECKLIST.md` | 4: Checklists | 480 |
| 15 | `RUN_STRATA_SUITE_AUDIT.md` | 5: Runbooks | 911 |
| 16 | `RUN_STRATA_PARSER_REVIEW.md` | 5: Runbooks | 628 |
| 17 | `STRATA_AUDIT_REPORT_TEMPLATE.md` | 5: Runbooks | 350 |
| 18 | `STRATA_SHIELD_ARCHITECTURE.md` | 6: System | 285 |
| 19 | `STRATA_SHIELD_MAINTENANCE.md` | 6: System | 430 |
| 20 | `STRATA_SHIELD_DEPENDENCY_MAP.md` | 6: System | 430 |
| 21 | `STRATA_SHIELD_CHANGE_CONTROL.md` | 6: System | 430 |
| 22 | `STRATA_SHIELD_ROADMAP.md` | 6: System | 430 |

**Total:** 22 documents

---

## Maintenance

**Last Updated:** 2026-03-23  
**Next Review:** 2026-06-23 (quarterly)  
**Update Triggers:**
- New documents added to the knowledge base
- Documents removed or reorganized
- New roles or use cases identified
- Reading paths change based on operational experience

**Location:** `D:\forensic-suite\guardian\STRATA_SHIELD_MASTER_INDEX.md`
