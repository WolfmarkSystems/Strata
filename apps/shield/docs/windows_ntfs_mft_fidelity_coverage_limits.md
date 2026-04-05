# Windows NTFS MFT Fidelity Coverage Limits

Status date: 2026-03-11

Current `ntfs-mft-fidelity` support is intentionally conservative:

1. Supports binary MFT-style inputs plus exported JSON/CSV/text rows.
2. Emits normalized record metadata, path reconstruction hints, and timestamp fields when available.
3. Provides deterministic dedupe/sort, timeline mapping (`--source ntfs-mft`), and execution-correlation enrichment.

Known limits:

1. Full raw `$MFT` parsing beyond basic record extraction is not included in this command.
2. Path reconstruction quality depends on parent-chain coverage in the provided export.
3. SID/user/device/process identity fields are often absent in MFT-only exports.

