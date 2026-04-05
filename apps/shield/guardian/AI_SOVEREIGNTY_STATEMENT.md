# Strata Forge — Sovereignty and Deployment Statement
**Document Type:** Official Deployment Declaration
**Classification:** Public-Facing Compliance Document
**Audience:** Procurement Officers, Legal Counsel, Oversight Bodies, Court
**Effective Date:** 2026-03-26
**Version:** 1.0

---

## Declaration

Strata Forge, the AI-assisted reference system embedded in Strata Forensics,
is designed and verified to operate under the following non-negotiable conditions.
This statement may be included in procurement documentation, RFP responses,
court filings, and agency policy submissions.

---

## 1. Local-Only Inference

All AI inference operations execute exclusively on the examiner's workstation
using locally installed model files. At no point during normal operation does
Strata Forge transmit evidence data, query text, case metadata, or any other
information to an external system, cloud service, or remote AI provider.

This property holds regardless of network connectivity. Strata Forge operates
identically whether the workstation has an active internet connection or is
fully air-gapped.

**Verifiable by:** Monitoring network traffic during AI operations.
Expected result: zero outbound connections.

---

## 2. No Cloud Dependency

Strata Forge has no dependency on any cloud-hosted AI service. It does not
use OpenAI, Anthropic, Google, Microsoft Azure AI, Amazon Bedrock, or any
other external model provider. The inference model (Phi-4 Mini) is a static
file stored on the local workstation. It is loaded once at startup and does
not require network access to function.

**Verifiable by:** Disabling all network interfaces and confirming full
AI functionality is retained.

---

## 3. Evidence Data Separation

The AI model does not have access to evidence containers, case databases,
or any forensic data unless the examiner explicitly selects specific text
and passes it to the system. The AI operates outside the evidence processing
pipeline. It receives only what the examiner deliberately provides.

**Verifiable by:** Reviewing the data isolation architecture in
STRATA_SHIELD_ARCHITECTURE.md and AI_SCOPE_AND_LIMITATIONS.md.

---

## 4. No Autonomous Operation

Every AI-assisted operation in Strata Forge requires an explicit, deliberate
action by the examiner. The system does not automatically process evidence,
generate findings, or take any action without examiner initiation. There are
no background AI processes, scheduled AI tasks, or automatic AI triggers.

**Verifiable by:** Code review of the Forge integration layer confirming
all AI entry points require explicit UI action.

---

## 5. Complete Audit Trail

Every AI interaction is logged immediately before the inference call executes.
The log is immutable — the application cannot modify or delete log entries.
The complete AI interaction history for any case is available for discovery,
supervisory review, or court submission at any time.

The log records: examiner identity, timestamp, operation type, query text
(for search operations), result count, source documents referenced, and
what the examiner did with the result.

**Verifiable by:** Reviewing the AI interaction log specification in
AI_AUDIT_TRAIL.md and inspecting the case database schema.

---

## 6. No Persistent Learning

The AI model does not learn from, retain, or be influenced by examiner
queries or case data. The model weights are static. They are identical
at the end of an examination as they were at the start. One examiner's
use of the system has no effect on any other examiner's results.

**Verifiable by:** Comparing the SHA-256 hash of the model file before
and after an examination session. The hash must be identical.

---

## 7. Model Provenance and Verification

The AI model used by Strata Forge is documented with:
- Model name and version
- Publisher and source
- SHA-256 hash of the model file
- Date of installation

The running model is verified against this hash at startup. If the hash
does not match, the system alerts the examiner and logs the discrepancy
before allowing AI features to be used.

Model documentation is maintained in STRATA_SHIELD_DEPENDENCY_MAP.md.

---

## 8. Examiner Remains the Decision-Maker

Strata Forge provides information to examiners. It does not make forensic
determinations, draw conclusions, or produce findings. All AI output is
advisory. The examiner is solely responsible for all forensic conclusions,
and the AI system has no authority to override, validate, or certify any
examiner determination.

AI-generated text that has not been reviewed, verified, and re-authored
by the examiner must not appear in any official forensic report, court
submission, or evidentiary record.

---

## Compliance Summary Table

| Property | Status | Verification Method |
|----------|--------|---------------------|
| Local-only inference | ✅ Architectural | Network traffic monitoring |
| No cloud dependency | ✅ Architectural | Disable network, test functionality |
| Evidence data separation | ✅ Architectural | Code review of data flow |
| No autonomous operation | ✅ Architectural | Code review of all AI entry points |
| Complete audit trail | ✅ Implemented | Review AI_AUDIT_TRAIL.md |
| No persistent learning | ✅ Architectural | Model hash comparison |
| Model provenance | ✅ Documented | Review STRATA_SHIELD_DEPENDENCY_MAP.md |
| Examiner controls all decisions | ✅ Policy + Architecture | Review AI_SCOPE_AND_LIMITATIONS.md |
| Air-gap compatible | ✅ Architectural | Functional test in isolated environment |
| CJIS alignment | ✅ Documented | Review AI_SCOPE_AND_LIMITATIONS.md Section 5 |

---

## Point of Contact for Technical Verification

Technical questions regarding this statement should be directed to the
Strata Forensics development team. Supporting documentation is available
in the guardian knowledge base at `D:\Strata\apps\shield\guardian\`.

All claims in this statement are verifiable through the architecture
documentation, source code, and runtime behavior of the deployed system.

---

**Document Location:** `D:\Strata\apps\shield\guardian\AI_SOVEREIGNTY_STATEMENT.md`
**Related Documents:**
- `AI_SCOPE_AND_LIMITATIONS.md`
- `AI_AUDIT_TRAIL.md`
- `STRATA_SHIELD_ARCHITECTURE.md`
- `STRATA_SHIELD_DEPENDENCY_MAP.md`
- `SUITE_GUARDIAN_PROFILE.md`
