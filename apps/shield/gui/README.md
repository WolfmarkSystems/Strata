# GUI/CLI Integration Workspace

This directory contains the canonical folder structure and baseline templates for GUI/CLI integration testing.

## Directory Structure

| Path | Purpose |
|------|---------|
| `gui/config/` | Runtime configuration (paths to CLI, exports, databases) |
| `gui/fixtures/` | JSON request templates for smoke tests |
| `gui/schemas/` | JSON schema definitions for validation |
| `gui/runs/` | Output directory for CLI JSON envelopes |
| `exports/` | Root for case data, smoke outputs, and run artifacts |
| `exports/smoke/` | Smoke test outputs |
| `exports/cases/` | SQLite case databases |
| `exports/runs/` | Run artifacts and logs |

## JSON Envelope Output

By default, CLI commands with `--json-result` flag will write their JSON envelopes to `gui/runs/`. This allows the GUI to:

1. Execute CLI commands via child process
2. Parse the JSON envelope from `gui/runs/` for results
3. Display status, errors, or data to the user

## Request Templates

The `gui/fixtures/` directory contains deterministic request templates:
- `smoke_test_request.json` - Smoke test inputs
- `capabilities_request.json` - CLI capabilities check
- `doctor_request.json` - System health check
- `triage_session_request.json` - Triage session example
- `verify_request.json` - Case verification
- `export_request.json` - Case export

These files use relative paths (e.g., `./exports/`, `./gui/runs/`) that are resolved relative to the repo root.
