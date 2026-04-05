# Windows PowerShell Artifacts Benchmark Runbook

Use this runbook to collect repeatable runtime metrics for `powershell-artifacts`.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_powershell_benchmark.ps1 -HistoryPath <history.txt> -ScriptLogPath <script_block.log> -EventsPath <ps_events.json> -TranscriptsDir <TranscriptsDir> -ModulesPath <modules.txt>
```

## Output

Summary JSON is written under:

`_run/windows_roadmap/benchmarks/<utc_stamp>/powershell_benchmark_summary.json`

## Notes

- Provide at least one real input path to avoid all-missing warnings.
- Use the same fixture set across runs to compare parser changes.
- Benchmark is command-level (`forensic_cli powershell-artifacts`) and includes process memory peak.
