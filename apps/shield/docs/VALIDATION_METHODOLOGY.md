# Strata Shield Validation Methodology

Document owner: Strata Shield forensic engineering
Version: 1.0
Effective date: 2026-03-25
Scope baseline: ForensicSuite workspace at D:\forensic-suite

## 1. Scope

This methodology defines how Strata Shield validates forensic outputs for evidence defensibility.

The validation scope includes:
- Evidence source recognition and read-only open flow
- Hash generation and hash persistence for evidence and report artifacts
- Chain-of-custody event logging with hash-link continuity
- Artifact parser output integrity and envelope shape validation
- Report-generation integrity (examiner metadata, integrity statements, methodology statements)

The scope does not assert that every parser has complete semantic coverage for every OS version. Coverage claims are bounded by documented capability status and known limitations.

## 2. Hash Verification (MD5, SHA1, SHA256, BLAKE3)

### 2.1 Algorithms and intended use
- MD5: compatibility hash for legacy interoperability and reference matching
- SHA1: compatibility hash for legacy systems and historical hash sets
- SHA256: primary integrity hash for evidence and report artifacts
- BLAKE3: high-performance supplemental hash where available in report payloads

### 2.2 Standards alignment
- NIST SP 800-86 guidance for integrity preservation and repeatability
- SWGDE forensic process expectations for evidence handling and documentation
- ISO/IEC 27037 principles for identification, collection, acquisition, and preservation

### 2.3 Verification procedure
1. Compute hashes at acquisition/open time when supported by source pipeline.
2. Persist hash values into case records and report payload structures.
3. Recompute hashes before export/report finalization if required by workflow.
4. Compare previous and current values.
5. Mark status as `ok`, `warn`, or `error` in command envelope and report integrity section.

### 2.4 Acceptance criteria
- At least one strong hash (SHA256) must be present for every evidentiary source in a report.
- Hash mismatches must never be silently ignored.
- Missing hashes must be explicitly labeled as `not_provided`.

## 3. Chain-of-Custody Validation (`activity_log` hash chain)

### 3.1 Data model expectation
The case database records activity events in `activity_log` with chain linkage fields such as:
- `prev_event_hash`
- `event_hash`
- event metadata (case_id, user/session, action, timestamps)

### 3.2 Chain verification process
1. Order events deterministically (case + sequence/time basis used by verifier).
2. Recompute event hash from canonical event payload.
3. Verify `prev_event_hash` references prior event hash.
4. Detect missing links, reorder anomalies, and content tampering.
5. Produce verification status with explicit warning/error list.

### 3.3 Chain acceptance criteria
- No broken hash links in validated range.
- No duplicate hash identifiers in event chain.
- Any verification gap is emitted as warning/error and surfaced to CLI/GUI/report.

## 4. Evidence Handling and Read-Only Policy

### 4.1 Policy
Strata Shield evidence access is read-only by design.

### 4.2 Required controls
- Evidence opens through read-only container/VFS interfaces.
- No in-place writes to source evidence images or source directories.
- Exports, derived artifacts, and reports are written to separate output paths.
- User-visible workflow states must distinguish source evidence from derived outputs.

### 4.3 Non-compliance conditions
Any workflow that writes to original evidence media, or cannot prove separation of output paths, is considered a critical validation failure.

## 5. Known Limitations (must be stated in reports)

Known limitations must be treated as first-class forensic disclosures, not hidden implementation details.

Examples from current capability baseline include:
- Some container adapters and filesystems are marked `Experimental`, `Beta`, or `Stub`.
- Parser depth can vary by artifact format version and source completeness.
- Some unallocated-space maps are best-effort or not yet implemented for specific filesystems.
- Optional AI/guardian runtime components may operate in degraded mode when offline.

Every case report must include a limitations section tailored to artifacts actually processed.

## 6. Validation Test Results Template

Use this template for each benchmark, regression fixture, or case verification run.

| Field | Value |
|---|---|
| Test ID | VAL-YYYYMMDD-### |
| Examiner | |
| Date (UTC) | |
| Tool version | |
| Case ID | |
| Evidence source path | |
| Evidence format | |
| Evidence baseline hashes (MD5/SHA1/SHA256/BLAKE3) | |
| Command/workflow executed | |
| Expected result | |
| Actual result | |
| Chain verification status | |
| Warnings | |
| Errors | |
| Verdict (`PASS`, `PASS_WITH_WARNINGS`, `FAIL`) | |
| Notes / follow-up actions | |

### 6.1 Minimum test pack
- Positive validation: known-good fixture with expected parser output
- Negative validation: malformed/missing artifact input
- Integrity validation: tamper simulation or chain mismatch detection
- Report validation: output contains examiner, integrity, methodology, and signature placeholder sections

## 7. References

- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- SWGDE best-practice documents for digital evidence handling and reporting
- ISO/IEC 27037: Guidelines for identification, collection, acquisition, and preservation of digital evidence

## 8. Change Control

Any change to this methodology must include:
- Date and author
- Reason for change
- Backward-compatibility impact assessment
- Revalidation requirement for impacted workflows
