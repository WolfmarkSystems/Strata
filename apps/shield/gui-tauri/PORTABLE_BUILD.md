# Portable/Release Build Guide (Tauri GUI)

This guide is for `D:\forensic-suite\gui-tauri`.

The runtime architecture remains:

`React UI -> Tauri backend -> forensic_cli sidecar -> forensic_engine`

## Prerequisites

- Windows build host
- Node + npm installed
- Rust toolchain installed (`cargo`)
- WebView2 runtime available on test machine

## Deterministic Build Steps

Run from `D:\forensic-suite\gui-tauri`.

1. Sync and verify sidecar:

```powershell
.\scripts\sync-sidecar.ps1
```

This script:
- builds `forensic_cli` from workspace root when needed
- copies to `src-tauri\bin\forensic_cli-x86_64-pc-windows-msvc.exe`
- verifies source/destination SHA256 match
- probes sidecar execution with `--help`

2. Build frontend:

```powershell
npm run build
```

3. Build Tauri bundle:

```powershell
npm run tauri build
```

## Sidecar Packaging Notes

- Tauri bundle config includes sidecar resources via:
  - `src-tauri/tauri.conf.json` -> `"bundle.resources": ["bin/*"]`
- Sidecar filename expected by app:
  - `forensic_cli-x86_64-pc-windows-msvc.exe`
- Sidecar source in repo:
  - `src-tauri/bin/forensic_cli-x86_64-pc-windows-msvc.exe`

## Runtime Sidecar Resolution (Hardened)

At runtime, the app resolves sidecar candidates in this order:

1. `FORENSIC_CLI_SIDECAR_PATH` (if set)
2. Packaged resource paths (`resource_dir/bin`, `resource_dir`)
3. Portable/unpacked executable-relative paths (`exe_dir/bin`, `exe_dir`, parent variants)
4. Development fallbacks (`src-tauri/bin`, cwd-based fallbacks)

If none are valid files, the app returns a clear error with all checked paths.

## Packaged App Verification Steps

After `npm run tauri build`:

1. Install/run the packaged app from `src-tauri\target\release\bundle\...`.
2. Open the app.
3. Trigger a known command from UI:
   - Dashboard -> `Capabilities`
4. Confirm command success:
   - Logs page shows a completed job with valid envelope/result.
5. If command fails with sidecar error, use troubleshooting below.

## First-Run Storage Behavior

The app now attempts to create required app-data folders safely on startup:

- app data root
- `gui/runs` history folder

Additional behavior:

- Command history envelopes are persisted under app data `gui/runs`.
- `run_cli` also writes per-run envelope JSON files in app data and returns parsed envelope.
- Frontend settings are stored in localStorage (WebView profile), not a database.

## Data/Settings Location Notes (Windows)

Expected app-data base (Tauri app data dir):

- `%APPDATA%\com.korbynrandolph.forensicsuite\` (exact resolved path may vary by environment)

Within app data:

- `gui\runs\` -> durable job history JSON files

Frontend localStorage keys include:

- `forensic-suite.app-settings.v1`
- `forensic-suite.lastCaseId`
- `forensic-suite.lastCaseDbPath`
- `forensic-suite.lastEvidencePath`
- `forensic-suite.lastActivePage`

## Troubleshooting

### Sidecar Not Found

Symptom:
- Commands fail with a message listing sidecar lookup paths.

Fix:
1. Run `.\scripts\sync-sidecar.ps1`
2. Rebuild with `npm run tauri build`
3. Re-run app and verify `Capabilities`

### Sidecar Exists But Fails To Execute

Symptom:
- Command exits with execution error.

Fix:
1. Run `src-tauri\bin\forensic_cli-x86_64-pc-windows-msvc.exe --help`
2. Re-run `.\scripts\sync-sidecar.ps1 -ForceRebuild`
3. Check endpoint protection/AV quarantine

### App-Data Folder Creation Fails

Symptom:
- History/log persistence warnings, missing result files.

Fix:
1. Ensure user account can write app-data directory
2. Run app from normal user context (or grant permissions)
3. Re-test command execution and Logs refresh

### WebView2 Issues

Symptom:
- Blank UI window or startup render failures.

Fix:
- Install/update Microsoft WebView2 runtime.
