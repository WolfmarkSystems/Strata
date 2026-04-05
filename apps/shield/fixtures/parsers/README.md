# Parser Smoke Fixtures

These fixtures are synthetic parser smoke inputs created for regression-safe testing. They contain no real user data, no real evidence, and no real hashes.

## Fixtures

1. `evtx/empty.evtx`
- Target parser: EVTX / event log input detection.
- Type: Synthetic header-only EVTX placeholder.
- Notes: Starts with `ElfFile\0` magic and a minimal 4 KB header block.
- Expected result: Zero-record or header-only smoke-path handling; suitable for empty-log fixture wiring.

2. `prefetch/NOTEPAD.EXE-XXXXXXXX.pf`
- Target parser: Prefetch fidelity parser.
- Type: Synthetic binary stub reused from the existing fixture library.
- Notes: Contains `SCCA` header bytes for a minimal Windows 10-style prefetch sample.
- Expected result: Parse without crash; minimal/partial metadata only.

3. `registry/empty.reg`
- Target parser: Registry export / MRU-style text parsers.
- Type: Synthetic text export.
- Notes: Valid `Windows Registry Editor Version 5.00` header with no records.
- Expected result: Empty result set, not a parser panic.

4. `lnk/minimal.lnk`
- Target parser: LNK / shortcut parser.
- Type: Synthetic binary stub reused from the existing fixture library.
- Notes: 76-byte shell-link header with `0x4C000000` signature and zero-filled remainder.
- Expected result: Recognized as a minimal LNK fixture and handled without crash.

5. `json_artifacts/sample_timeline.json`
- Target parser: Timeline / JSON artifact import workflows.
- Type: Synthetic JSON fixture.
- Notes: Contains three sample timeline rows with deterministic timestamps and sources.
- Expected result: Three records loaded successfully.

## Provenance

- `prefetch/NOTEPAD.EXE-XXXXXXXX.pf` is copied from `fixtures/artifacts/TESTAPP.EXE-12345678.pf`.
- `lnk/minimal.lnk` is copied from `fixtures/artifacts/test_shortcut.lnk`.
- The EVTX, registry, and JSON fixtures are generated specifically for parser smoke testing.
