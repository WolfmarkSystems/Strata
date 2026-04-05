# Windows Timeline Benchmark Runbook

Purpose: record repeatable timeline query runtime measurements across key source/limit combinations.

## Run

From repo root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_timeline_benchmark.ps1 -CaseId <case_id> -DbPath <path_to_case_db>
```

Optional range window:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_timeline_benchmark.ps1 -CaseId <case_id> -DbPath <path_to_case_db> -FromUtc 2026-03-01T00:00:00Z -ToUtc 2026-03-10T23:59:59Z
```

## Output

Results are written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/timeline_benchmark_summary.json`

Each run records:

1. `source`
2. `limit`
3. `exit_code`
4. `elapsed_ms`
