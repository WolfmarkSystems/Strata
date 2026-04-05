# Forensic CLI + GUI Standard Locations

## Standard Directories

### exports/
Root for all case data and generated outputs.

Subdirectories:
- exports/smoke/        → Smoke test outputs
- exports/cases/        → SQLite case databases
- exports/runs/         → Run artifacts and logs
- exports/defensibility/ → Bundle exports (triage / examine)

---

### gui/
GUI integration workspace.

Subdirectories:
- gui/config/     → Runtime configuration (gui_runtime.json)
- gui/fixtures/   → JSON request templates
- gui/schemas/    → JSON schema definitions
- gui/runs/       → JSON envelope outputs (where --json-result writes)

---

## Evidence Location

Primary evidence directory:
D:\forensic-suite\evidence

Purpose:
- Keeps raw evidence isolated from case databases
- Used by smoke-test and image analysis
- Avoid mixing evidence with export artifacts

---

## JSON Envelope Output Location

All CLI commands using:

  --json-result <path>

Should write JSON envelopes to:

  gui/runs/

Example:
  forensic_cli.exe capabilities --json-result gui/runs/capabilities_result.json --quiet

This ensures:
- Base44 GUI reads predictable locations
- Integration tests are deterministic
- No collision with case artifacts

---

## Standard CliResultEnvelope Output Keys

| Command | Output Keys | Notes |
|----------|------------|-------|
| capabilities | (none) | Uses data field only |
| doctor | (none) | Uses data field only |
| smoke-test | smoke_summary, summary_txt | File paths |
| verify | (none) | Uses data field only |
| replay | (none) | Uses data field only |
| examine | bundle_zip | Present if bundle created |
| triage-session | bundle_zip | Present if bundle created |
| watchpoints | (none) | Uses data field only |
| violations | (none) | Uses data field only |
| violations-clear | (none) | Uses data field only |

---

## Standard Example Commands

Capabilities:
  forensic_cli.exe capabilities --json-result gui/runs/capabilities_result.json --quiet

Doctor:
  forensic_cli.exe doctor --json-result gui/runs/doctor_result.json --quiet

Smoke Test:
  forensic_cli.exe smoke-test --image evidence/Stack001_Surface_HDD.E01 --out exports/smoke/surface_smoke --mft 50 --json-result gui/runs/smoke_result.json --quiet

Verify:
  forensic_cli.exe verify --case demo_case_001 --db exports/cases/demo_case.sqlite --sample 50 --json-result gui/runs/verify_result.json --quiet

Triage Session:
  forensic_cli.exe triage-session --case demo_case_001 --db exports/cases/demo_case.sqlite --bundle-dir exports/defensibility --json-result gui/runs/triage_result.json --quiet

Export:
  forensic_cli.exe export --case demo_case_001 --db exports/cases/demo_case.sqlite --output exports/export_demo_case_001 --no-verify --json-result gui/runs/export_result.json --quiet

Verify-Export:
  forensic_cli.exe verify-export --case demo_case_001 --db exports/cases/demo_case.sqlite --output exports/export_demo_case_001 --json-result gui/runs/verify_export_result.json --quiet

---

## Integration Rule

1. CLI never assumes GUI exists.
2. GUI always consumes JSON envelopes.
3. All integration paths must be relative to repo root when possible.
4. Never write GUI data into engine modules.
5. forensic_engine must remain untouched.

End of document.
