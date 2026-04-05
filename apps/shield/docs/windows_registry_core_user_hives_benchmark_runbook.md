# Windows Registry Core User Hives Benchmark Runbook

Use this runbook to collect repeatable runtime metrics for `registry-core-user-hives`.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_registry_core_user_hives_benchmark.ps1 -RunMruRegPath <runmru.reg> -OpenSaveRegPath <mru2.reg> -UserAssistRegPath <userassist.reg> -RecentDocsRegPath <recentdocs.reg>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/registry_core_user_hives_benchmark_summary.json`

## Notes

- Provide at least one real registry export path to avoid all-missing warnings.
- Use the same fixture set across runs for apples-to-apples comparisons.
- Benchmark is command-level (`forensic_cli registry-core-user-hives`) and includes process memory peak.
