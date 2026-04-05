# Windows Defender Artifacts Coverage Limits

Status date: 2026-03-11
Command: `forensic_cli defender-artifacts`

## Current Coverage

- Windows Defender status via existing registry-backed config helpers.
- Defender AV product summary and exclusion values.
- Defender quarantine and scan-history text logs (CSV/pipe style line parsing).
- Defender Endpoint JSON artifacts:
- `alerts.json`
- `indicators.json`
- `file_profiles.json`
- `machine_actions.json`

## Explicit Limits (Current)

- No direct EVTX channel parsing in this command; it consumes configured text/JSON artifact exports only.
- No full Defender signature/version intelligence timeline yet beyond available fields in source artifacts.
- Source quality depends on provided logs/exports; missing files are reported as warnings.
- Endpoint records are normalized from provided JSON fields only; unsupported fields are not inferred.
- Timestamps are normalized to UTC where numeric unix values are present.

## Truth-First Behavior

- Missing artifact files do not crash command execution.
- Invalid `--limit` returns `EXIT_VALIDATION` with error envelope when `--json-result` is provided.
- Output is deterministic (sort + capped collection size) and envelope-compatible with existing GUI paths.
