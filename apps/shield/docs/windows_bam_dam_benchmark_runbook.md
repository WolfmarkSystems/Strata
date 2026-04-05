# Windows BAM/DAM Benchmark Runbook

Use this runbook to collect repeatable runtime metrics for `bam-dam-activity`.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_bam_dam_benchmark.ps1 -BamRegPath <bam.reg>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/bam_dam_benchmark_summary.json`

## Notes

- Use stable fixture corpora for run-to-run comparisons.
- Benchmark is command-level (`forensic_cli bam-dam-activity`) and includes process memory peak.
