# Windows CLI Snapshot Runbook

Purpose: keep deterministic command-output baselines for key CLI entry points used by GUI and regression checks.

## Generate a Snapshot

From repo root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_cli_snapshot.ps1
```

Outputs are written under `_run/windows_roadmap/snapshots/<utc_stamp>/`.

## Commands Currently Snapshotted

1. `capabilities --json`
2. `doctor --json`
3. `timeline --help`
4. `registry-persistence --help`
5. `execution-correlation --help`
6. `recent-execution --help`
7. `violations --help`

Each run writes:

1. One `.out` file per command.
2. `cli_snapshot_summary.json` with exit codes and SHA256 checksums.

## Update Procedure When Output Intentionally Changes

1. Run a new snapshot with `scripts/windows_cli_snapshot.ps1`.
2. Compare prior and new `cli_snapshot_summary.json` hashes.
3. If a hash changed, inspect corresponding `.out` diff for expected behavior.
4. Record the reason in `docs/windows_regression_notes_template.md` format.
5. Keep the latest snapshot directory as the new baseline reference.

## Failure Policy

1. Any non-zero command exit code blocks baseline acceptance.
2. Unexpected hash drift requires triage before advancing week goals.
