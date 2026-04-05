# Strata Forge — AI Interaction Audit Trail
**Document Type:** Logging Specification and Compliance Reference
**Classification:** Guardian Doctrine
**Audience:** Examiners, Legal Counsel, CJIS Auditors, Court
**Effective Date:** 2026-03-26
**Maintained By:** Strata Guardian Subsystem

---

> **AUDIT PRINCIPLE**
> Every AI-assisted operation in Strata Forge produces an immutable log entry.
> The complete audit trail is available for discovery, court review, and
> supervisory oversight at all times.

---

## Section 1 — Purpose

This document specifies what is logged when an examiner uses any Forge
AI feature, how that log is stored, what it contains, and how it can
be retrieved for legal or administrative review.

The audit trail exists to answer the question any court, supervisor,
or auditor may ask: **"What exactly did the AI do during this examination,
and what did the examiner do with it?"**

---

## Section 2 — What Is Logged

Every Forge AI interaction produces a log entry. No AI operation
occurs without a corresponding log entry. This is architecturally
enforced — the logging call precedes the inference call in all code paths.

### 2.1 Log Entry Fields

Every log entry contains the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `entry_id` | UUID | Unique identifier for this log entry |
| `case_id` | String | Active case identifier at time of operation |
| `examiner_id` | String | Examiner name or identifier from session profile |
| `timestamp_utc` | ISO 8601 | Exact UTC timestamp of operation initiation |
| `operation_type` | Enum | One of: `kb_search`, `summarize`, `health_check` |
| `tier` | Integer | 1 (Knowledge Retrieval) or 2 (Summarization) |
| `query_text` | String | For `kb_search`: the examiner's query text |
| `input_char_count` | Integer | For `summarize`: character count of input provided |
| `result_count` | Integer | Number of results or passages returned |
| `source_documents` | Array | For `kb_search`: list of source document titles referenced |
| `kb_available` | Boolean | Whether the KB bridge was reachable |
| `elapsed_ms` | Integer | Time from query initiation to result delivery |
| `fallback_used` | Boolean | Whether a local fallback was used instead of the model |
| `examiner_action` | Enum | What examiner did with the result (see Section 2.2) |

### 2.2 Examiner Action Values

The `examiner_action` field records what the examiner did after receiving
AI output. This field is updated when the examiner takes action, or
marked `no_action` after a session timeout.

| Value | Meaning |
|-------|---------|
| `reviewed_only` | Examiner read the result, took no further action |
| `used_as_reference` | Examiner used the methodology passage to inform their work |
| `discarded` | Examiner dismissed the result as not relevant |
| `no_action` | Session ended without recorded examiner action |

### 2.3 What Is NOT Logged

The following are intentionally excluded from the audit log to protect
case data and examiner privacy:

- The full text of AI-generated summaries (Tier 2 output)
- The specific artifact descriptions passed to the summarization feature
- File paths, hash values, or evidence metadata

The character count of summarization input is logged (to establish
scope) but not the content. This balances auditability against
the risk of the audit log itself becoming a secondary evidence repository.

---

## Section 3 — Log Storage

### 3.1 Location

AI interaction logs are stored in the case database alongside other
case activity records:

```
Table: ai_interaction_log
Database: <case_id>.sqlite
Location: D:\Strata\apps\shield\cases\<case_id>.sqlite
```

They are also written to the structured tracing log:
```
D:\Strata\logs\strata_ai_audit.jsonl
```

The `.jsonl` file is append-only. Entries are never modified or deleted
by the application. One JSON object per line.

### 3.2 Immutability

Log entries are written once and never modified. The application has
no delete or update operation for AI log entries. The SQLite table
does not grant DELETE permission to the application connection.

If a case database is exported using `forensic_cli export`, the
AI interaction log is included in the export bundle automatically.

### 3.3 Retention

AI interaction logs are retained for the lifetime of the case database.
They are included in all case exports and backups.
They are not automatically purged on session end or case close.

---

## Section 4 — Log Entry Examples

### 4.1 Knowledge Retrieval (Tier 1)

```json
{
  "entry_id": "7f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "case_id": "CASE-2026-0147",
  "examiner_id": "SA_J_SMITH",
  "timestamp_utc": "2026-03-26T14:23:11Z",
  "operation_type": "kb_search",
  "tier": 1,
  "query_text": "NTFS MFT timestamp manipulation detection methods",
  "input_char_count": null,
  "result_count": 3,
  "source_documents": [
    "PARSER_CONVENTIONS.md",
    "TRUTHFULNESS_RULES.md",
    "KNOWN_GAPS.md"
  ],
  "kb_available": true,
  "elapsed_ms": 847,
  "fallback_used": false,
  "examiner_action": "used_as_reference"
}
```

### 4.2 Summarization (Tier 2)

```json
{
  "entry_id": "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6",
  "case_id": "CASE-2026-0147",
  "examiner_id": "SA_J_SMITH",
  "timestamp_utc": "2026-03-26T14:31:44Z",
  "operation_type": "summarize",
  "tier": 2,
  "query_text": null,
  "input_char_count": 2847,
  "result_count": 1,
  "source_documents": [],
  "kb_available": true,
  "elapsed_ms": 3241,
  "fallback_used": false,
  "examiner_action": "reviewed_only"
}
```

### 4.3 KB Bridge Unavailable (Fallback)

```json
{
  "entry_id": "b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e",
  "case_id": "CASE-2026-0147",
  "examiner_id": "SA_J_SMITH",
  "timestamp_utc": "2026-03-26T15:02:33Z",
  "operation_type": "kb_search",
  "tier": 1,
  "query_text": "prefetch file execution count interpretation",
  "input_char_count": null,
  "result_count": 0,
  "source_documents": [],
  "kb_available": false,
  "elapsed_ms": 3001,
  "fallback_used": true,
  "examiner_action": "discarded"
}
```

---

## Section 5 — Retrieving the Audit Trail

### 5.1 CLI Export

```powershell
# From D:\Strata
# Export AI interaction log for a specific case
forensic_cli export --case <case_id> --db .\cases\<case_id>.sqlite --output .\exports\<case_id>
# The export bundle includes ai_interaction_log.jsonl
```

### 5.2 Direct Query

```powershell
# From D:\Strata
# Query the AI log directly from SQLite
forensic_cli artifacts --case <case_id> --db .\cases\<case_id>.sqlite --json
# Filter output for ai_interaction entries
```

### 5.3 Log File Access

The raw append-only log is at:
```
D:\Strata\logs\strata_ai_audit.jsonl
```

It can be read with any text editor or JSON processing tool.
Filter by `case_id` to isolate a specific case's AI interactions.

### 5.4 For Legal Discovery

When responding to a discovery request for AI interaction records:

1. Export the case bundle using the CLI export command above
2. The bundle contains `ai_interaction_log.jsonl` with complete records
3. The log file at `D:\Strata\logs\strata_ai_audit.jsonl` contains
   all AI interactions across all cases on this workstation
4. Both files are human-readable JSON — no special tools required to review

---

## Section 6 — Supervisor and Auditor Access

### 6.1 What a Supervisor Can Verify

From the audit trail, a supervisor can verify:

- Every AI operation performed during an examination
- Which examiner initiated each operation
- The exact text of every knowledge base query
- Which source documents were surfaced by each query
- Whether the KB bridge was available or a fallback was used
- How long each AI operation took
- What the examiner did with each AI result

### 6.2 What a Supervisor Cannot Determine From the Log Alone

- The specific artifact descriptions passed to summarization
- The exact text of AI-generated summaries
- Whether the examiner found the AI result accurate or useful
  (only whether they recorded an action)

### 6.3 CJIS Audit Support

For CJIS compliance audits, provide:
1. This document (AI_AUDIT_TRAIL.md)
2. AI_SCOPE_AND_LIMITATIONS.md
3. The case export bundle containing ai_interaction_log.jsonl
4. STRATA_SHIELD_ARCHITECTURE.md (confirms local-only deployment)

---

## Section 7 — Implementation Requirements

This section specifies requirements for the Strata engineering team.
All AI interaction paths must comply before any government or LE deployment.

### 7.1 Logging Must Precede Inference

The log entry must be written to the database **before** the inference
call is made. If inference fails, the log entry is updated with the
failure. This ensures that attempted AI operations are always recorded
even if they do not produce a result.

### 7.2 No AI Operation Without Active Case

AI operations must require an active case context. If no case is loaded,
Forge features are disabled and the methodology search returns a message:
"Open a case to use AI-assisted methodology search."

This ensures every AI interaction is associated with a case ID in the log.

### 7.3 Examiner Identity Required

The examiner profile must be set before AI features are accessible.
The default "Examiner" identity is acceptable for testing but must
be flagged in the log as `examiner_id: "DEFAULT_UNSET"` to distinguish
it from a named examiner session.

### 7.4 Log Integrity

The AI interaction log table must have:
- No UPDATE permissions granted to the application connection
- No DELETE permissions granted to the application connection
- A check constraint that timestamp_utc is always populated
- A check constraint that operation_type is always one of the defined values

---

## Section 8 — Document Maintenance

Review this document when:
- New AI features are added to Forge
- Log fields are added, removed, or changed
- Legal guidance on AI logging in forensics changes
- A discovery request reveals gaps in the current log specification

**Location:** `D:\Strata\apps\shield\guardian\AI_AUDIT_TRAIL.md`
