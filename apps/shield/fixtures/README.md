# Fixture Library (Phase 4.3)

This folder contains a compact synthetic fixture set for parser regression tests.
The fixtures are intentionally minimal and deterministic so test expectations stay stable.

## Artifact Fixtures (`fixtures/artifacts`)

1. `test.evtx`
- Format: XML-based synthetic security log sample.
- Contains exactly 3 event records with IDs `4624`, `4625`, and `4688`.
- Expected parse output:
  - `logon_events = 1` (ID 4624)
  - `failed_logons = 1` (ID 4625 with failure status)
  - includes process-creation event `4688`

2. `TESTAPP.EXE-12345678.pf`
- Format: synthetic Prefetch binary (`SCCA` header).
- Expected parse output:
  - detected as binary prefetch
  - `program_name = "TESTAPP.EXE"`
  - `run_count = 3`

3. `test_shortcut.lnk`
- Format: minimal shell-link header (`0x4C000000` signature).
- Expected parse output:
  - detected as LNK input
  - parsed without format errors

4. `NTUSER.DAT`
- Format: minimal registry hive header (`regf`) with 512-byte payload.
- Expected parse output:
  - recognized by `parse_ntuser_dat()`
  - returns one `RegistryKey` marker for NTUSER

5. `test_userassist.reg`
- Format: synthetic UserAssist registry export.
- Expected parse output:
  - decoded path includes `C:\Windows\notepad.exe`
  - `run_count = 7`

## Container Fixture Generator (`fixtures/containers/create_test_fixtures.ps1`)

The PowerShell script creates:
- `test_ntfs.dd` (sparse RAW image placeholder)
- `test.vhd` (VHD, if Hyper-V cmdlets are available)
- `test.vmdk` (minimal descriptor text fixture)

Run from repo root:

```powershell
powershell -ExecutionPolicy Bypass -File .\fixtures\containers\create_test_fixtures.ps1
```
