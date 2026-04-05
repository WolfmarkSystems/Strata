# Strata Forensics — Compliance Matrix

**Document Type:** Compliance Reference for Procurement and Audit
**Audience:** Procurement Officers, Compliance Auditors, Legal Counsel, CJIS Auditors
**Effective Date:** 2026-03-27

---

## CJIS Security Policy Alignment

| Requirement | Strata Status | Verification Method |
|-------------|---------------|---------------------|
| **Data Sovereignty** — Criminal justice information must not leave the agency's control | Compliant. All data processing and on-device AI inference occurs on the local workstation. No data is transmitted externally. | Operate with network disconnected; use network monitor to confirm zero outbound connections. |
| **Audit Logging** — All access to criminal justice information must be logged | Compliant. Every AI interaction is logged before execution with examiner identity, timestamp, operation type, and result disposition. Evidence processing commands produce envelope-backed output with full metadata. | Review `ai_interaction_log` table in case database and `strata_ai_audit.jsonl`. Run `forensic_cli doctor` to verify logging infrastructure. |
| **Access Control** — Access restricted to authorized personnel | Supported. Examiner identity is recorded in all audit entries. Sessions without a named examiner profile are flagged as `DEFAULT_UNSET` in the log. | Review audit log entries for examiner_id field. Verify no `DEFAULT_UNSET` entries appear in production case logs. |
| **Encryption at Rest** — Sensitive data must be encrypted when stored | Supported via OS-level encryption (BitLocker, LUKS). Case databases use standard SQLite format compatible with full-disk encryption. | Verify full-disk encryption is enabled on the workstation. Case databases reside on the encrypted volume. |
| **Media Protection** — Digital media must be protected during transport | Supported. Case export bundles include hash chain-of-custody verification. Integrity can be verified after transport. | Export a case bundle and verify manifest checksums at the destination. |
| **Personnel Security** — Background checks for personnel accessing CJI | Organizational responsibility. Strata logs examiner identity for all AI operations to support personnel accountability. | Review audit logs to confirm named examiner identity is captured for all operations. |

---

## Federal Procurement Considerations

| Requirement | Strata Status | Verification Method |
|-------------|---------------|---------------------|
| **No Foreign Service Dependencies** | Compliant. No external APIs, cloud services, or third-party inference endpoints are used. All processing is local. | Inspect network traffic during full operational cycle. Review architecture documentation (`STRATA_SHIELD_ARCHITECTURE.md`). |
| **Air-Gap Deployment** | Compliant. The system operates identically with or without network connectivity. No online activation or license validation required. | Install and operate on a fully disconnected workstation. Run all evidence processing and on-device AI functions. |
| **Complete Audit Trail** | Compliant. All AI interactions produce pre-execution log entries. All CLI commands produce envelope-backed output with timestamps, status, and metadata. | Export case bundle; verify `ai_interaction_log.jsonl` is included. Review `AI_AUDIT_TRAIL.md` for field definitions. |
| **Documented Capability Boundaries** | Compliant. All capabilities and known limitations are documented in guardian doctrine. No undocumented capabilities are claimed. | Review `KNOWN_GAPS.md` and `AI_SCOPE_AND_LIMITATIONS.md` in the guardian documentation. |
| **No Telemetry or Usage Reporting** | Compliant. No analytics, telemetry, crash reporting, or usage data is collected or transmitted. | Monitor network traffic during extended use. Inspect application configuration for any reporting endpoints. |
| **Model Provenance** | Compliant. On-device AI model name, version, and SHA-256 hash are documented. Hash is verified at startup. | Verify model hash using `Get-FileHash` and compare against the value documented in `STRATA_SHIELD_ARCHITECTURE.md`. |
| **Supply Chain Transparency** | Supported. All dependencies are documented. The forensic engine and CLI are built in Rust with auditable dependency trees. | Review `Cargo.toml` and `Cargo.lock` for dependency inventory. |

---

## Chain of Custody Support

| Requirement | Strata Status | Verification Method |
|-------------|---------------|---------------------|
| **Evidence Integrity Verification** | Compliant. Multi-algorithm hashing (MD5, SHA-1, SHA-256) is computed at evidence ingest and preserved through the analysis lifecycle. | Compare hash values at ingest against original acquisition hashes. Use `forensic_cli verify` to re-verify case integrity. |
| **Immutable Processing Record** | Compliant. Case databases record all processing stages. AI audit log is append-only with no application-level update or delete operations. | Inspect `ai_interaction_log` table schema for absence of DELETE/UPDATE grants. Verify JSONL file is append-only. |
| **Reproducible Analysis** | Supported. CLI commands produce deterministic, envelope-backed output. Re-running the same command against the same evidence produces the same artifacts. | Re-run a triage session on the same evidence image and compare artifact counts and hash values. |
| **Export Bundle Integrity** | Compliant. Case export bundles include manifest files with checksums for every included file. | Export a case and verify each file in the bundle against its manifest checksum. |
| **Timestamp Provenance** | Compliant. All timestamps are normalized to UTC. AI audit entries use ISO 8601 format with timezone designation. | Review audit log timestamps. Verify they are UTC-consistent across entries. |

---

## Expert Witness Support

| Requirement | Strata Status | Verification Method |
|-------------|---------------|---------------------|
| **Examiner Can Testify to Tool Behavior** | Supported. The complete audit trail documents every AI interaction, including what the examiner queried, what was returned, and what action the examiner took. | Review the `examiner_action` field in audit log entries for each relevant AI interaction. |
| **On-Device AI Results Are Explainable** | Supported. Tier 1 (Knowledge Retrieval) results include the source document and passage, allowing independent verification. | For any AI search result, trace the cited source document in the guardian knowledge base to verify the passage exists. |
| **AI Did Not Independently Modify Evidence** | Verifiable. The on-device AI has no write access to the forensic engine, case database, or evidence files. | Review `AI_SCOPE_AND_LIMITATIONS.md` architecture separation. Inspect code paths to confirm AI output is read-only. |
| **No Data Left the Workstation** | Verifiable. The system makes no external network calls. Air-gap operation confirms this absolutely. | Network monitoring during operation, or air-gap deployment verification. |
| **What an Examiner Can Say Under Oath** | The examiner can truthfully state: all AI interactions are logged with timestamps; AI output was reviewed before any use in the examination; no evidence data left the workstation; the AI did not autonomously modify any case data or evidence; and the complete interaction log is available for court review. | Produce the audit log. Cross-reference AI interaction entries with examination timeline to demonstrate examiner oversight. |

---

*All compliance claims in this matrix are verifiable using the procedures described in the Technical Evaluation Guide included in this procurement package. For authoritative technical specifications, refer to the guardian doctrine documents at `D:\Strata\apps\shield\guardian\`.*
