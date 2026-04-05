# Strata Forge — AI Scope and Limitations
**Document Type:** Authoritative Capability Boundary Statement
**Classification:** Guardian Doctrine — Non-Negotiable
**Audience:** Examiners, Supervisors, Legal Counsel, Procurement Officers, Court
**Effective Date:** 2026-03-26
**Maintained By:** Strata Guardian Subsystem

---

> **DEPLOYMENT MODEL: LOCAL-ONLY INFERENCE**
> All AI operations run exclusively on this workstation.
> No evidence data, query text, or results are transmitted outside this system.
> No internet connection is required or used during AI-assisted operations.
> This system is suitable for air-gapped deployment.

---

## Section 1 — What Forge Is

Forge is the knowledge retrieval and reference system embedded in Strata Forensics.
It provides examiners with rapid access to documented forensic methodology,
guardian standards, and operational guidance using a natural language interface.

Forge is best understood as an **intelligent reference database** — not an
analyst, not a decision-maker, and not an autonomous agent. It retrieves
pre-vetted knowledge the same way a senior examiner would pull a reference
document from a shelf. The model does not reason about your evidence. It
surfaces documented knowledge that the examiner then applies using their
own professional judgment.

### What Forge Is Not

Forge is not:
- A forensic analyst
- An evidence processing system
- An autonomous decision-maker
- A replacement for examiner expertise or judgment
- A system that learns from or retains examiner queries
- Connected to any external AI provider, cloud service, or API

---

## Section 2 — Capability Boundaries

### 2.1 What Forge Can Do

| Capability | Description | Tier |
|------------|-------------|------|
| Methodology search | Retrieve relevant passages from guardian knowledge base using natural language query | Knowledge Retrieval |
| Standard recall | Surface SWGDE, NIST, and internal policy documentation relevant to an examiner's question | Knowledge Retrieval |
| Guardian doc lookup | Find specific sections of operating procedures, parser conventions, or truthfulness rules | Knowledge Retrieval |
| Artifact summarization | Generate plain-language summaries of artifact descriptions for readability | Advisory Only |
| IOC scoring | Apply pre-defined scoring rules to flag artifacts matching known suspicious patterns | Deterministic |

### 2.2 What Forge Cannot Do — Hard Limits

The following are architectural prohibitions, not policy preferences.
They cannot be enabled by configuration, user override, or administrative action.

**Forge cannot:**

- Draw forensic conclusions or make evidentiary determinations
- Modify, create, delete, or annotate evidence records in the case database
- Access evidence container data, file contents, or raw evidence bytes
- Access evidence data without explicit examiner action for each operation
- Connect to external networks, APIs, model providers, or update services
- Operate autonomously — every AI interaction requires an examiner-initiated action
- Store, retain, or learn from examiner queries between sessions
- Insert AI-generated text into evidence records, case notes, or official reports
  without explicit examiner review and deliberate inclusion
- Provide output that is automatically treated as forensic fact by any downstream system

---

## Section 3 — Two-Tier Architecture

Forge operates in two distinct tiers with different trust levels.

### Tier 1 — Knowledge Retrieval (Courtroom-Safe)

**What it does:** Retrieves documented passages from the Strata knowledge
base in response to examiner queries. Returns source document title,
passage text, and relevance score. The examiner reads the passage and
applies it using their own judgment.

**Trust level:** High. Output is traceable to specific source documents
that were authored and reviewed by humans. Every result includes its
source so the examiner can verify the original document independently.

**Audit status:** Every Tier 1 query is logged with timestamp, query text,
source documents retrieved, and examiner identity. See AI_AUDIT_TRAIL.md.

**Appropriate for:** Methodology reference during active examinations,
training and procedure recall, standards compliance verification.

### Tier 2 — Summarization (Advisory Only)

**What it does:** Generates plain-language summaries of artifact
descriptions that the examiner explicitly selects and passes to the system.
The model receives only what the examiner provides — it does not access
the case database independently.

**Trust level:** Advisory. Output is clearly marked as AI-generated.
Summaries are convenience aids for the examiner and are never automatically
inserted into evidence records or included in court reports.

**Audit status:** Every Tier 2 operation is logged with timestamp,
operation type, character count of input provided, and examiner identity.
Input text is not logged by default to protect case data.

**Appropriate for:** Rapid orientation to a large artifact set,
internal briefing preparation, preliminary triage notes.

**Not appropriate for:** Court submissions, official case reports,
or any output that will be attributed as forensic finding without
full examiner review and re-authorship.

---

## Section 4 — Evidence Data Handling

### 4.1 What the AI Model Receives

The AI model (Phi-4 Mini, running locally) receives only what the examiner
explicitly passes to it. It does not have access to:

- The case database
- Evidence container contents
- File system tree data
- Hash values or integrity records
- Any data the examiner has not explicitly selected and submitted

When an examiner uses the Methodology Search feature, the query text
is sent to the local model. The evidence being examined is not.

When an examiner uses the Summarization feature, only the artifact
descriptions that the examiner explicitly selects are sent to the model.
The underlying evidence bytes, file paths, and case metadata are not.

### 4.2 Data Isolation Architecture

```
Evidence Container (read-only)
         │
         ▼
Strata Engine (forensic processing)
         │
         ▼
Case Database (examiner-controlled)
         │
    Examiner selects
    specific text to
    pass to Forge
         │
         ▼
Forge / Phi-4 Mini (local inference)
         │
    Returns text
    suggestion only
         │
         ▼
Examiner reviews,
decides whether to use,
re-authors for any
official purpose
```

The AI layer sits outside the evidence processing pipeline.
It receives only what the examiner deliberately hands to it.

---

## Section 5 — CJIS and Federal Compliance Alignment

The following architectural properties are relevant to CJIS Security Policy
compliance and federal procurement evaluation.

| Requirement | Strata Forge Status |
|-------------|---------------------|
| Data sovereignty | ✅ All inference local — no data leaves the workstation |
| Network isolation | ✅ No network calls during AI operations — air-gap compatible |
| Audit logging | ✅ All AI interactions logged with timestamp and examiner identity |
| No persistent learning | ✅ Model weights are static — examiner input never modifies the model |
| No telemetry | ✅ No usage reporting, no analytics, no external callbacks |
| Examiner control | ✅ Every AI operation is examiner-initiated — no autonomous processing |
| Evidence separation | ✅ AI model cannot access evidence data without explicit examiner action |
| Explainability | ✅ Tier 1 results include source document for independent verification |
| Auditability | ✅ Complete interaction log available for discovery and review |

### 5.1 Air-Gapped Deployment

Strata Forge is designed to operate in air-gapped environments.
The model file is loaded from local storage at startup.
No DNS lookups, no certificate validation calls, no update checks occur
during operation. Network interfaces may be disabled without affecting
any AI functionality.

### 5.2 Model Provenance

The AI model used by Forge (Phi-4 Mini) is:
- Loaded from a local file on this workstation
- Verified by SHA-256 hash at startup against a recorded baseline
- A static inference model — it does not update, retrain, or change
- Documented in STRATA_SHIELD_DEPENDENCY_MAP.md with version and hash

---

## Section 6 — Use in Legal Proceedings

### 6.1 What Can Be Disclosed

The following may be disclosed in legal proceedings without concern:

- That Strata Forensics was used to examine evidence
- That Forge's Tier 1 (Knowledge Retrieval) was used to reference methodology
- The specific methodology documents that were retrieved
- The complete AI interaction log (see AI_AUDIT_TRAIL.md)
- The model name, version, and hash used during examination

### 6.2 AI Output in Reports

**Tier 1 output** (methodology passages retrieved from knowledge base)
may be cited in reports with attribution to the source document.
The examiner should cite the underlying guardian document, not "the AI said."

**Tier 2 output** (AI-generated summaries) must not appear in court reports
unless the examiner has:
1. Read the summary
2. Verified it against the underlying artifacts
3. Re-authored the relevant content in their own words
4. Taken professional responsibility for its accuracy

AI-generated text that has not been reviewed and re-authored by the
examiner must never appear verbatim in any official submission.

### 6.3 Expert Witness Considerations

An examiner using Forge can truthfully state:
- "I used a local reference system to recall documented methodology."
- "The AI tool did not access the evidence directly."
- "I reviewed all AI suggestions before using any in my analysis."
- "Every AI interaction during this examination is logged and available."

An examiner using Forge cannot truthfully state that Forge independently
validated forensic findings, because Forge does not have that capability.

---

## Section 7 — Limitations Requiring Disclosure

The following limitations must be understood before operational deployment.

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Phi-4 Mini is a small model | May miss nuance in complex methodology questions | Examiner reviews all output; source documents available for direct reference |
| Knowledge base reflects docs at index time | May not reflect most recent standards updates | Regular knowledge base refresh recommended; check source document dates |
| Summarization is not verified | AI summaries may contain inaccuracies | Tier 2 is advisory only; examiner must verify before any official use |
| No validation against OSAC/SWGDE test corpus | Methodology retrieval accuracy is not formally certified | Use as reference aid; do not substitute for examiner training and judgment |
| Language model hallucination risk | Model may generate plausible but inaccurate text | Tier 2 output always labeled; source citation required for Tier 1 use |

---

## Section 8 — Document Maintenance

This document must be reviewed and updated when:
- The AI model is changed (new version, different model family)
- New AI capabilities are added to Forge
- Legal guidance on AI in forensics changes
- An evaluator identifies a gap in this statement

**Review frequency:** Quarterly minimum, or upon any change to the AI layer.

**Authority to update:** Changes to Sections 2 and 4 require Guardian review.
Changes to Section 5 require legal review before publication.

**Location:** `D:\Strata\apps\shield\guardian\AI_SCOPE_AND_LIMITATIONS.md`
