# Strata Forensics — Technical Evaluation Guide

**Document Type:** Evaluation Procedures for Technical Assessors
**Audience:** Technical Evaluators, IT Security Staff, Lab Administrators
**Effective Date:** 2026-03-27

---

## 1. System Requirements

### Minimum Hardware
| Component | Requirement |
|-----------|-------------|
| RAM | 8 GB |
| Storage | SSD recommended for working directory |
| OS | Windows 10/11 or Linux |
| Network | Not required — system is fully air-gap compatible |

### Recommended Hardware
| Component | Requirement |
|-----------|-------------|
| RAM | 16 GB (for evidence images above 500 GB) |
| Storage | NVMe SSD for temp/working directory |
| CPU | Multi-core x86-64 processor |

### Performance Reference
| Evidence Image Size | Approximate Processing Time | RAM Usage |
|--------------------|-----------------------------|-----------|
| 100 GB | ~45 minutes | ~4 GB |
| 500 GB | ~3.5 hours | ~8 GB |
| 1 TB | ~8 hours | ~16 GB |

---

## 2. Verifying Local-Only Operation

To confirm that Strata makes no external network connections:

1. **Disconnect the network** — Remove Ethernet cable or disable Wi-Fi
2. **Open a case and run a full triage session** using the CLI or GUI
3. **Use the on-device Intelligent Reference System** — perform a methodology search
4. **Verify all operations complete successfully** with no connection errors
5. **Optional: Use a network monitor** (e.g., Wireshark, Windows Resource Monitor) during operation to confirm zero outbound connections from the Strata process

**Expected result:** All forensic processing, on-device AI queries, and report generation complete normally with no network access.

---

## 3. Verifying Model Integrity

The local AI model file has a documented SHA-256 hash. To verify:

1. Navigate to the model directory referenced in `STRATA_SHIELD_ARCHITECTURE.md`
2. Compute the SHA-256 hash of the model file:
   ```powershell
   Get-FileHash -Path <model_file_path> -Algorithm SHA256
   ```
3. Compare against the documented hash in the architecture document
4. Strata also verifies the model hash at startup automatically — check startup logs for the verification message

**Expected result:** Hash matches the documented value. If it does not match, the model file has been modified and should not be used.

---

## 4. Accessing the AI Interaction Audit Log

Every on-device AI operation is logged before execution. To access the audit trail:

### Global Log (All Cases)
```
D:\Strata\logs\strata_ai_audit.jsonl
```
This append-only file contains one JSON object per line for every AI interaction across all cases on this workstation.

### Per-Case Log (SQLite)
```
D:\Strata\apps\shield\cases\<case_id>.sqlite
Table: ai_interaction_log
```
Query directly with any SQLite tool or export via the CLI.

### Log Entry Contents
Each entry records: unique ID, case ID, examiner identity, UTC timestamp, operation type, query text (for searches), result count, source documents referenced, whether the knowledge base was available, response time, whether a fallback was used, and what the examiner did with the result.

For full field definitions, see `AI_AUDIT_TRAIL.md` in the guardian documentation.

---

## 5. Running the Guardian Audit

The guardian system provides built-in validation of the entire platform:

```powershell
# From D:\Strata
forensic_cli doctor
```

This runs 28+ diagnostic checks covering:
- CLI binary health and version
- Evidence container support verification
- Filesystem parser status
- Database integrity
- On-device AI model availability and hash verification
- Knowledge base bridge connectivity

**Expected result:** All checks pass with status "ok". Any "warn" or "error" results include remediation hints in the output.

### Full Guardian Audit
For a comprehensive platform validation (recommended before deployment):
- Follow the procedures in `RUNTIME_AUDIT_CHECKLIST.md`
- The full audit covers 186+ validation items across five integrated checklists
- Estimated time: 2-4 hours for complete validation

---

## 6. Generating a Court-Ready Report

```powershell
# Run a triage session and generate the case bundle
forensic_cli triage-session --case <case_id> --evidence <path_to_image>

# Export the complete case bundle
forensic_cli export --case <case_id> --db .\cases\<case_id>.sqlite --output .\exports\<case_id>
```

The export bundle includes:
- Professional HTML report with embedded artifact data
- Timeline in JSONL format (compatible with Timesketch)
- AI interaction audit log (`ai_interaction_log.jsonl`)
- Hash chain-of-custody verification
- Case manifest with integrity checksums

---

## 7. Key Files and Locations

| File/Directory | Purpose |
|---------------|---------|
| `D:\Strata\apps\shield\guardian\` | Guardian doctrine documents (authoritative reference) |
| `D:\Strata\apps\shield\cases\` | Case databases (SQLite) |
| `D:\Strata\logs\strata_ai_audit.jsonl` | Global AI interaction audit log |
| `D:\Strata\apps\shield\guardian\AI_AUDIT_TRAIL.md` | AI logging specification |
| `D:\Strata\apps\shield\guardian\AI_SCOPE_AND_LIMITATIONS.md` | AI capability boundaries |
| `D:\Strata\apps\shield\guardian\AI_SOVEREIGNTY_STATEMENT.md` | Local-only deployment declaration |
| `D:\Strata\apps\shield\guardian\KNOWN_GAPS.md` | Documented capability limitations |
| `D:\Strata\apps\shield\guardian\STRATA_SHIELD_ARCHITECTURE.md` | System architecture and trust model |

---

## 8. Evaluation Questions and Expected Answers

Use these questions during your evaluation to verify Strata's claims:

| Question | Expected Answer |
|----------|----------------|
| Does the system make any external network connections during evidence processing? | No. All processing is local. Verifiable with a network monitor or by operating in air-gap mode. |
| Can the on-device AI access evidence data without examiner action? | No. All AI operations require explicit examiner initiation. The AI model has no direct access to the forensic engine or case database. |
| Does the AI model learn from examiner queries? | No. Model weights are static and hash-verified at startup. No training or fine-tuning occurs. |
| Is every AI interaction logged? | Yes. A log entry is written before each AI operation executes. The complete audit trail is available for discovery. |
| Can the AI automatically modify evidence records or reports? | No. AI output is never inserted into case data without explicit examiner action. |
| What happens if the AI knowledge base is unavailable? | The system falls back gracefully, logs the failure (kb_available: false, fallback_used: true), and does not block the examiner's work. |
| Can the system operate in a classified/air-gapped environment? | Yes. No network connectivity is required for any function. |
| What can an examiner say under oath about the AI? | That all AI interactions are logged with timestamps and examiner identity; that AI output was reviewed before use; that no data left the workstation; and that the AI did not independently modify any evidence. |
| Where are the documented capability limitations? | In `KNOWN_GAPS.md` within the guardian documentation. All limitations are disclosed transparently. |
| How do I verify the integrity of the AI model? | Compare the SHA-256 hash of the model file against the documented value in the architecture document. The system also verifies automatically at startup. |

---

*This guide references procedures documented in the Strata Guardian doctrine. For authoritative specifications, consult the documents in `D:\Strata\apps\shield\guardian\`.*
