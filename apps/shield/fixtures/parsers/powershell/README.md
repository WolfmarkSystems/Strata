# PowerShell Artifact Fixtures

This fixture set supports Workstream 4 (`powershell-artifacts`) CLI/parser regression.

- Total labeled samples: 30
- Windows 10 samples: history + script log
- Windows 11 samples: events + transcripts + modules

Sample groups:

1. `win10/history`: line-based `ConsoleHost_history.txt` style input.
2. `win10/script_log`: pipe-delimited script log rows with unix timestamps.
3. `win11/events`: JSON `records` payloads with mixed timestamp fields.
4. `win11/transcripts`: transcript text files with `PS` prompt lines.
5. `win11/modules`: module inventory in pipe/csv mixed formats.

Use `manifest.json` for deterministic fixture auditing.
