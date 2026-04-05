# Chain of Custody Guide

1. Create case and record examiner identity.
2. Load evidence and record source hashes.
3. Keep evidence read-only throughout analysis.
4. Preserve audit trail and verify chain status before reporting.
5. Export audit artifacts (CSV/JSON/PDF) with report package.
6. Re-open `.vtp` and re-verify integrity hash + audit chain.

## Integrity Signals
- Case integrity hash match on load
- Audit chain status `VERIFIED`
- Evidence source hash values present in report
