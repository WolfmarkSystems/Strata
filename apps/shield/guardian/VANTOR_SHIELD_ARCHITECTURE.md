# Strata Shield — System Architecture
**Document Type:** Architecture Reference
**Version:** 2.0
**Effective Date:** 2026-03-26
**Authority:** Strata — Suite Guardian
**Status:** Active Operational System

---

> **DEPLOYMENT MODEL: LOCAL-ONLY — AIR-GAP COMPATIBLE**
> All AI inference, evidence processing, and case management operates
> exclusively on this workstation. No data leaves this system during
> any operational mode. Network connectivity is not required.
> This system is validated for air-gapped deployment.

---

## What Is Strata Shield

Strata Shield is the guardian subsystem of the Strata Forensics ecosystem.
It is a layered protective architecture that combines a local AI inference
runtime, structured knowledge management, and an enforceable doctrine to
ensure that every piece of evidence processed by the suite is handled with
integrity, every result presented to an examiner is truthful, and every
automated decision is auditable and reversible.

Strata Shield is not a forensic tool. It does not analyze evidence. It does
not draw conclusions. It observes what the suite produces, validates that
output against documented contracts, flags when reality diverges from
documentation, and protects against silent failures propagating as successes.

**For government, national security, and law enforcement deployments:**
Strata Shield is a local quality-assurance system. The AI component is a
knowledge retrieval tool — not an analyst. All forensic conclusions are made
by the examiner. The AI cannot access, modify, or influence evidence data.

---

## Forge AI Layer — Two-Tier Architecture

Forge, the AI-assisted reference system within Strata Shield, operates in
two distinct tiers. Understanding this separation is essential for proper
deployment and legal use.

```
┌─────────────────────────────────────────────────────────────────┐
│                    FORGE AI LAYER                               │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  TIER 1: KNOWLEDGE RETRIEVAL (Courtroom-Safe)           │   │
│  │                                                         │   │
│  │  • Natural language search of guardian knowledge base   │   │
│  │  • Returns: source document + passage + relevance score │   │
│  │  • Every result is traceable to a human-authored doc    │   │
│  │  • Trust level: HIGH — fully explainable and auditable  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  TIER 2: SUMMARIZATION (Advisory Only)                  │   │
│  │                                                         │   │
│  │  • Plain-language summaries of examiner-selected text   │   │
│  │  • Output clearly marked as AI-generated                │   │
│  │  • Never inserted into evidence records automatically    │   │
│  │  • Trust level: ADVISORY — examiner must verify         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  BOTH TIERS:                                                    │
│  • Run entirely on local hardware                              │
│  • Log every interaction before inference executes            │
│  • Require explicit examiner action                           │
│  • Cannot access evidence data without examiner input         │
│  • Do not connect to external networks or services            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Major System Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│                    STRATA SHIELD — PROTECTIVE LAYER                │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              GUARDIAN KNOWLEDGE BASE                         │   │
│  │   Suite Guardian Profile · Truthfulness Rules · Conventions  │   │
│  │   Known Gaps · Failure Patterns · Command Contracts          │   │
│  │   AI Scope & Limitations · AI Audit Trail                    │   │
│  │   AI Sovereignty Statement · Audit Runbooks                  │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                               │                                     │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │                    GUARDIAN DOCTRINE                          │   │
│  │   Truthfulness: No fabrication, no placeholder artifacts      │   │
│  │   Integrity: Hash chains, provenance, chain-of-custody        │   │
│  │   Sovereignty: Local-only, air-gap compatible, no callbacks   │   │
│  │   Auditability: Every AI operation logged before execution    │   │
│  │   Examiner Control: No autonomous AI action                   │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                               │                                     │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │                   FORGE AI SUBSYSTEM                          │   │
│  │                                                             │   │
│  │   ┌─────────────────────────────────────────────────────┐   │   │
│  │   │              Phi-4 Mini (Local Model)                │   │   │
│  │   │   • Static weights — never updated from case data   │   │   │
│  │   │   • Hash-verified at startup                        │   │   │
│  │   │   • No network access during inference              │   │   │
│  │   │   • 3-second hard timeout on all operations        │   │   │
│  │   └─────────────────────────────────────────────────────┘   │   │
│  │                                                             │   │
│  │   ┌─────────────────────────────────────────────────────┐   │   │
│  │   │              KB Bridge (Python)                      │   │   │
│  │   │   • HTTP bridge on 127.0.0.1:8090 (loopback only)  │   │   │
│  │   │   • Serves /health, /search, /summarize endpoints  │   │   │
│  │   │   • All requests logged before forwarding          │   │   │
│  │   │   • No external network calls                      │   │   │
│  │   └─────────────────────────────────────────────────────┘   │   │
│  │                                                             │   │
│  │   ┌─────────────────────────────────────────────────────┐   │   │
│  │   │              Watchdog                                │   │   │
│  │   │   • Monitors bridge and model health                │   │   │
│  │   │   • Restarts on failure without examiner action     │   │   │
│  │   │   • Logs all state transitions                     │   │   │
│  │   └─────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                               │
                    Examiner-initiated
                    queries only — no
                    autonomous access
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    FORENSIC SUITE — PROTECTED LAYER                 │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    React UI (Desktop)                        │   │
│  │        Status displays, evidence browser, timeline           │   │
│  │        Methodology Search (Tier 1) · Summarize (Tier 2)      │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                               │ Tauri IPC                          │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │                  Tauri Backend (Rust)                        │   │
│  │    CliResultEnvelope parsing, sidecar spawning, truth-first │   │
│  │    AI interaction logging (writes before inference call)     │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                               │ JSON envelope / stdout_json         │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │              forensic_cli Sidecar (Rust)                     │   │
│  │    60+ commands, envelope-backed output, case management      │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                               │ Engine calls                        │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │                 forensic_engine (Rust)                       │   │
│  │  ArtifactParser, TimelineManager, CaseDatabase, HashSetDB    │   │
│  │                                                              │   │
│  │  ◄── AI has NO direct access to this layer ──►              │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow — AI Operations

The following diagram shows exactly how data moves during an AI-assisted
operation. This is the critical diagram for legal and compliance review.

```
EXAMINER
   │
   │  Types a methodology question
   │  OR selects artifact text to summarize
   ▼
FORGE UI (React)
   │
   │  Examiner clicks Search or Summarize
   │  (no automatic triggers exist)
   ▼
TAURI BACKEND (Rust)
   │
   │  1. WRITE audit log entry (before inference)
   │  2. Validate: is a case open? Is examiner identified?
   │  3. Send query to KB Bridge
   ▼
KB BRIDGE (127.0.0.1:8090)
   │
   │  Local HTTP call — loopback interface only
   │  No external network traffic generated
   ▼
PHI-4 MINI (Local Model)
   │
   │  Processes query using only:
   │  - The knowledge base documents (for search)
   │  - The text the examiner provided (for summarize)
   │
   │  The evidence container, case database, and
   │  file system tree are NEVER accessible to the model
   ▼
KB BRIDGE
   │
   │  Returns results with source citations (Tier 1)
   │  or summary text (Tier 2)
   ▼
TAURI BACKEND
   │
   │  Updates audit log entry with result count
   │  Returns results to UI
   ▼
FORGE UI
   │
   │  Displays results to examiner
   │  Examiner decides what to do with them
   ▼
EXAMINER DECISION
   │
   ├── Use as methodology reference (Tier 1) → Examiner applies judgment
   ├── Review summary, re-author for report (Tier 2) → Examiner owns output
   └── Discard → No impact on case
```

---

## Operating Boundaries

### What Strata Shield Can Observe

- Build outputs and test results
- CLI command envelopes (via `--json-result` output)
- Parser output quality (via code inspection and test execution)
- GUI display claims (via CLI-to-GUI contract validation)
- Runtime health (via `doctor`, health endpoints)
- AI interaction logs
- KB bridge health endpoint responses

### What Strata Shield Can Advise On

- Whether a parser is ready for integration
- Whether the suite is ready for release
- Whether a capability claim is truthful
- Whether a GUI page respects CLI contracts
- Whether a runtime failure pattern is dangerous
- Whether AI output is properly scoped and labeled

### What Strata Shield Must NOT Do Automatically

- Modify forensic_engine or forensic_cli source code
- Conduct autonomous evidence handling or investigation
- Create synthetic artifacts to fill gaps
- Suppress or hide integrity violations
- Claim a capability is implemented when it is stubbed
- Recommend AI output as conclusive when it is advisory
- Allow AI operations to proceed without an active case context
- Allow AI operations to proceed without examiner identity

---

## Trust Model

### Local-Only

All inference happens locally. No forensic data leaves the workstation
during AI-assisted operations. Model files are stored locally. No cloud
services are used for inference. The system operates identically whether
the network is connected or disconnected.

### Auditable

Every verdict Strata Shield renders can be traced to specific evidence.
Every AI interaction is logged before it executes. Audit reports are filed
to `D:\Strata\apps\shield\guardian\AUDIT_REPORTS\` with full evidence citations.

### Conservative

Strata Shield errs on the side of under-reporting rather than over-reporting.
If Strata cannot determine whether an AI result is reliable, it labels it
as advisory and surfaces the uncertainty to the examiner.

### Examiner-First

The examiner is the forensic authority. Strata Shield and Forge exist to
support examiner work, not to substitute for it. Every AI feature requires
examiner initiation. Every AI result requires examiner review before use.
The system has no mechanism to override examiner judgment.

### Evidence-Preserving

Strata Shield prioritizes evidence integrity over speed and convenience.
The AI layer has no write access to the case database. It cannot modify,
annotate, or delete evidence records. The chain of custody is entirely
within the evidence processing pipeline, which the AI cannot access.

---

## Related Documents

| Document | Purpose |
|----------|---------|
| `AI_SCOPE_AND_LIMITATIONS.md` | Complete capability boundary statement |
| `AI_AUDIT_TRAIL.md` | Logging specification and compliance reference |
| `AI_SOVEREIGNTY_STATEMENT.md` | One-page procurement and court declaration |
| `SUITE_GUARDIAN_PROFILE.md` | Guardian identity and authority |
| `TRUTHFULNESS_RULES.md` | Evidence contracts |
| `KNOWN_GAPS.md` | Honest capability inventory |
| `STRATA_SHIELD_DEPENDENCY_MAP.md` | Component dependencies and model provenance |
| `STRATA_SHIELD_MAINTENANCE.md` | Safe update procedures |

---

## Document Maintenance

**Last Updated:** 2026-03-26
**Next Review:** 2026-06-26 (quarterly)
**Update Triggers:**
- New AI capabilities added
- Model changed (new version or family)
- New integration points added
- Legal guidance on AI in forensics changes
- Government deployment feedback received

**Location:** `D:\Strata\apps\shield\guardian\STRATA_SHIELD_ARCHITECTURE.md`
