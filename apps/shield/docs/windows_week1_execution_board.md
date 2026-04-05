# Week 1 Execution Board (2026-03-10 to 2026-03-15)

Goal: establish reproducible baseline metrics and daily quality gates before deeper Windows parser expansion.

## Hard Goal

By end of week, we must have:

1. Deterministic baseline snapshot scripts committed and runnable.
2. Stored baseline outputs under `_run/windows_roadmap/`.
3. Daily gate command documented and in use.
4. Workspace build/test status tracked in machine-readable output.

## Day Plan

## Tuesday 2026-03-10

- [x] Inventory parser/test baseline.
- [x] Add roadmap and Week 1 board docs.
- [x] Add baseline snapshot script.
- [x] Run first baseline snapshot.

## Wednesday 2026-03-11

- [x] Add daily gate script with pass/fail summary.
- [x] Add regression notes template for failing tests.
- [x] Run daily gate once and store output.

## Thursday 2026-03-12

- [x] Add CLI snapshot check script for key Windows commands.
- [x] Store command output baselines in `_run/windows_roadmap/snapshots/`.
- [x] Document update procedure when outputs intentionally change.

## Friday 2026-03-13

- [x] Gather first weekly metrics summary.
- [x] Triage top failing/flaky areas.
- [x] Lock Week 2 backlog based on actual metrics.

## Saturday 2026-03-14

- [x] Re-run full baseline + gate.
- [x] Confirm hard goal complete.
- [x] Publish week close-out status.

## Sunday 2026-03-15 (Buffer)

- [x] Cleanup, backlog prep, and fixture manifest tuning.

## Current Notes

- 2026-03-10: Week 1 board + 90-day roadmap created.
- 2026-03-10: Baseline snapshot script created and validated.
- 2026-03-10: Daily gate script created and validated.
- 2026-03-10: Regression notes template added (`docs/windows_regression_notes_template.md`).
- 2026-03-10: Latest run directory `_run/windows_roadmap/2026-03-10_035743`.
- 2026-03-10 metrics: build/tests/clippy/fixture harness all passing; clippy warnings: 170; failed tests: 0.
- 2026-03-10: CLI snapshot script added and first snapshot stored at `_run/windows_roadmap/snapshots/2026-03-10_035904`.
- 2026-03-10: all snapshot commands exited 0 (`capabilities --json`, `doctor --json`, `timeline --help`, `violations --help`).
- 2026-03-10: snapshot update procedure documented in `docs/windows_cli_snapshot_runbook.md`.
- 2026-03-10: warning-reduction batch landed (`hashing`, `hashset`, `report/json`, `strings`).
- 2026-03-10: latest baseline run `_run/windows_roadmap/2026-03-10_041053`.
- 2026-03-10 metrics: build/tests/clippy/fixture harness passing; clippy warnings `151` (down from `170`, delta `-19`); failed tests `0`.
- 2026-03-10: weekly metrics summary added (`docs/windows_week1_metrics_summary_2026-03-10.md`).
- 2026-03-10: triage added (`docs/windows_week1_triage_2026-03-10.md`).
- 2026-03-10: Week 2 backlog locked (`docs/windows_week2_backlog_locked.md`).
- 2026-03-10: second cleanup batch landed (`discordchat`, `exchange_parse`, `googledrive` path API cleanup).
- 2026-03-10: latest baseline run `_run/windows_roadmap/2026-03-10_041545` and matching daily gate pass.
- 2026-03-10 metrics update: clippy warnings `142` (down from `170`, delta `-28`), failed tests `0`.
- 2026-03-10: full baseline rerun completed (`_run/windows_roadmap/2026-03-10_211945`).
- 2026-03-10: daily gate rerun passed (`_run/windows_roadmap/2026-03-10_212019/daily_gate_result.json`).
- 2026-03-10: CLI snapshot refresh captured (`_run/windows_roadmap/snapshots/2026-03-10_212040`).
- 2026-03-10: fixture manifest audit + corpus harness pass confirmed in gate/baseline runs.
- 2026-03-10: week close-out published (`docs/windows_week2_closeout_2026-03-10.md`) and Week 3 kickoff locked (`docs/windows_week3_kickoff_locked.md`).
