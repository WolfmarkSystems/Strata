# Windows Registry Core User Hives Coverage Limits

Status date: 2026-03-11

Current `registry-core-user-hives` support is intentionally conservative:

1. Ingests RunMRU, OpenSaveMRU, UserAssist, and RecentDocs registry exports.
2. Uses strict input-shape detection (`json|csv|reg|txt|binary|unknown`) for quality metadata.
3. Keeps timestamps nullable where source values are not available.
4. Applies deterministic ordering (`has_timestamp`, newest-first timestamp, tie-key).
5. Applies dedupe with explicit `dedupe_reason` and count metadata.
6. Provides fallback text parsing for sparse/broken exports where direct parser output is empty.

Known limits:

1. No raw hive parsing in this command; current scope is export-driven.
2. RunMRU/OpenSave rows generally have no authoritative execution timestamp.
3. Identity attribution is best-effort (`executable_name`) and not full SID/session mapping.
4. UserAssist decode relies on available encoded value structure and may skip malformed blobs.
