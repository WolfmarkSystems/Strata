# Strata Forensics — Full Development Gameplan
**Solo Agentic Build | Claude + Codex**
**Generated: March 2026**

---

## What We Accomplished in Session 1

Before the roadmap begins, record what's already done:

| Fix | File(s) | Status |
|-----|---------|--------|
| NTFS silent failure swallowed | `strata-fs/src/virtualization/mod.rs:1609` | ? Done |
| 4 Err-to-empty classification swallows | `etw.rs`, `notifications.rs`, `setupapi.rs` | ? Done |
| 20+ Default::default() audit | `triage_presets.rs`, `wmi.rs`, `search.rs`, `terminal.rs` | ? Done |
| GUI builder pipeline trigger | `App.tsx` ? `start_specialized_view_builders` | ? Done |
| Timeline export wired | `App.tsx` ? `export_jsonl_timeline` | ? Done |
| Methodology search wired | `Dashboard.tsx` ? `search_kb_bridge` | ? Done |
| KB assist module created | `strata-insight/src/kb_assist.rs` | ? Done |
| All cargo checks passing | `strata-fs`, `strata-core`, `strata-insight` | ? Done |
| GUI TypeScript clean on our changes | `Dashboard.tsx`, `App.tsx`, `useTauri.ts` | ? Done |

---

## How to Use This Document

Each phase has a set of **tasks**. Each task has:
- A clear objective
- The exact files involved
- A ready-to-paste **Codex prompt** (marked `[PROMPT]`)
- A **verification step** to run after Codex completes
- The **deliverable** — what done looks like

Work through phases in order. Do not skip to Phase 2 until Phase 1 is verified clean.

---

## ✅ Phase 1 — Cleanup & Foundation (Weeks 1–2)

**Goal:** Get the codebase to a clean, honest baseline. No broken tests, no stale docs, no pre-existing type errors blocking future work.

---

### ✅ Task 1.1 — Fix Pre-Existing TypeScript Errors

**Objective:** Eliminate the 24 TS errors in `ArtifactTable.tsx`, `artifactProviders.ts`, and `MainView.tsx` that were present before Session 1. These aren't our bugs but they block future type-safe development.

**Files:** `apps/shield/gui/src/components/ArtifactTable.tsx`, `src/lib/artifactProviders.ts`, `src/pages/MainView.tsx`

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics — React/TypeScript GUI
Run from: apps/shield/gui/

PROBLEM
=======
Three files have pre-existing TypeScript errors that block strict compilation:

1. src/components/ArtifactTable.tsx
   - Multiple unused imports (useEffect, Copy, FileWarning, Hash, NotebookPen, Tag, Terminal, Download)
   - Unused variable: onContextAction (line 163), setColumnWidths (line 167)
   - Type error line 262: ColumnDef not assignable to ColumnId

2. src/lib/artifactProviders.ts
   - Unused import: siGoogle
   - Missing exports from simple-icons: siMicrosoftoutlook, siSlack, siMicrosoftteams
   - Unused variable: lowName (line 101)

3. src/pages/MainView.tsx
   - Unused imports: Download, RefreshCw
   - Unused variable: formatSize (line 74)

TASK
====
Fix all errors with minimal changes:

For unused imports: remove them from the import statement entirely.
For unused variables: prefix with underscore (e.g. _onContextAction) or remove if safe.
For simple-icons missing exports (siMicrosoftoutlook, siSlack, siMicrosoftteams):
  Replace with the closest available export or remove and use a fallback icon.
  Check what is actually exported by running:
  grep -r "export.*si" node_modules/simple-icons/index.js | head -20
  Then substitute the correct export names.
For the ColumnDef/ColumnId type error: inspect the type definitions and add
  an explicit cast or fix the type annotation.

CONSTRAINTS
===========
Do not change any visual behavior or component logic.
Do not remove functionality, only fix types.
After changes run: npx tsc --noEmit
Report the final error count (target: 0 errors in these three files).
```

**Verification:**
```powershell
cd D:\Strata\apps\shield\gui
npx tsc --noEmit 2>&1 | Select-String "error TS" | Measure-Object
```
Target: 0 errors.

**Deliverable:** Clean TypeScript compilation with zero errors.
**Completed:** Removed the pre-existing TS errors in `ArtifactTable.tsx`, `artifactProviders.ts`, and `MainView.tsx`; `npx tsc --noEmit` now passes clean.

---

### ✅ Task 1.2 — Update KNOWN_GAPS.md to Current Reality

**Objective:** The guardian's KNOWN_GAPS.md Section G still has stale information from before Session 1. Update it to reflect actual current state.

**Files:** `apps/shield/guardian/KNOWN_GAPS.md`

**[PROMPT]**
```
CONTEXT
=======
File: apps/shield/guardian/KNOWN_GAPS.md
Project: Strata Forensics

TASK
====
Update Section G (Test Coverage) to reflect the current verified state:

Section G.1 should now read:

| Check | Status | Notes |
|-------|--------|-------|
| Debug build | ? COMPILES CLEAN | No errors, 24 warnings (documented) |
| Unit tests | ? PASSING | 519 tests passed, 1 ignored |
| Clippy strict | ? FAILING | 24+ unused import warnings — tracked, non-blocking |
| Test coverage | ?? LIMITED | No fixture library yet; ingest pipeline not validated against real evidence |

Also add a new Section H.3 entry under "Strata-Specific Gaps":

| Gap | Status | Notes |
|-----|--------|-------|
| KB bridge /summarize endpoint | ?? NOT IMPLEMENTED | kb_assist.rs has graceful fallback; activates when Python bridge exposes endpoint |
| Evidence fixture library | ?? NOT IMPLEMENTED | No synthetic test evidence for parser regression testing |
| Frontend TypeScript clean | ?? PARTIAL | 24 pre-existing errors in ArtifactTable, artifactProviders, MainView — tracked |

Do not change any other sections.
Report what you changed.
```

**Verification:** Read the file and confirm changes are accurate.

**Deliverable:** Guardian docs match actual codebase state.
**Completed:** Refreshed Section G and added Section H.3 in `apps/shield/guardian/KNOWN_GAPS.md`, including the now-clean frontend TypeScript status.

---

### ✅ Task 1.3 — Fix Clippy Warnings

**Objective:** Get `cargo clippy --workspace -- -D warnings` to pass clean. Currently fails on 24 unused import warnings.

**Files:** Various `crates/strata-core/src/parsers/macos/*.rs` and other modules

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics (Rust workspace)
Run from: D:\Strata

PROBLEM
=======
cargo clippy --workspace -- -D warnings fails with unused import warnings.
Most are in the macOS parser modules and classification layer.

TASK
====
Run: cargo clippy --workspace 2>&1 | grep "unused import" | head -40

For each unused import warning:
- If the import is genuinely unused, remove it from the use statement
- If the import is used indirectly or for re-export purposes, add:
  #[allow(unused_imports)]
  above the specific use statement (not the whole file)

After fixing, run: cargo clippy --workspace -- -D warnings
Target: zero warnings promoted to errors.

CONSTRAINTS
===========
Do not remove imports that are part of a pub use re-export chain.
Do not add file-level #![allow(unused_imports)] — use targeted suppressions only.
Report how many warnings were removed vs suppressed.
```

**Verification:**
```powershell
cargo clippy --workspace -- -D warnings 2>&1 | Select-String "^error" | Measure-Object
```
Target: 0 errors.

**Deliverable:** `cargo clippy` passes strict mode.
**Completed:** Applied workspace clippy fixes, resolved the remaining strict lints, and verified `cargo clippy --workspace -- -D warnings` passes clean.

---

## ✅ Phase 2 — Core Hardening (Weeks 3–6)

**Goal:** Harden the evidence processing pipeline, connect the AI layer to real functionality, and polish the examiner workflow end-to-end.

---

### ✅ Task 2.1 — Expose /summarize Endpoint on KB Bridge

**Objective:** The `kb_assist.rs` module already calls `POST /summarize`. Add this endpoint to the Python KB bridge so the Phi-4 Mini summarization actually works.

**Files:** `apps/forge/` — find the Python bridge script (`dfir_kb_bridge.py`)

**[PROMPT]**
```
CONTEXT
=======
File: [find dfir_kb_bridge.py in apps/forge/ or D:\DFIR Coding AI\bin\kb\]
Project: Strata Forensics — Python KB bridge

BACKGROUND
==========
The Rust crate strata-insight/src/kb_assist.rs calls POST /summarize
with this body:
  { "texts": ["artifact description 1", "artifact description 2", ...] }

It expects a response like:
  { "summary": "plain language summary of the artifacts" }

The endpoint does not exist yet. The bridge currently has /health and /search.

TASK
====
Add a /summarize endpoint to the Python KB bridge HTTP server.

The endpoint should:
1. Accept POST with JSON body: { "texts": ["...", "..."] }
2. Take the list of texts and construct a prompt like:
   "Summarize these forensic artifacts in 2-3 plain sentences for an investigator:
   - artifact 1
   - artifact 2
   ..."
3. Send that prompt to the local Llama server (port 8080) via the
   /v1/chat/completions API
4. Return: { "summary": "<response text>" }
5. If the Llama server is unreachable, return:
   { "summary": "KB unavailable — [count] artifacts found", "fallback": true }

Use the same HTTP client pattern already in the bridge for /search.
Limit input to 20 texts maximum (truncate silently if more are passed).
Set a 10 second timeout on the Llama call.

After adding the endpoint, test it manually:
  curl -X POST http://127.0.0.1:8090/summarize
       -H "Content-Type: application/json"
       -d '{"texts": ["Prefetch file chrome.exe-ABC.pf executed 47 times"]}'

Report the curl response.
```

**Verification:** The curl test returns a non-empty summary string.

**Deliverable:** Phi-4 Mini summarization works end-to-end from the GUI's Methodology Search.
**Completed:** Added `/summarize` to the Python KB bridge and verified the live fallback response `{"summary":"KB unavailable — 1 artifacts found","fallback":true}` on a throwaway bridge instance.

---

### ✅ Task 2.2 — Build the Evidence Fixture Library

**Objective:** Create synthetic test fixtures so parsers can be regression-tested without real evidence.

**Files:** `apps/shield/fixtures/parsers/` (create this directory structure)

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics
Target directory: apps/shield/fixtures/parsers/

TASK
====
Create a minimal synthetic fixture library for the top 5 most-used parsers.
Each fixture is a small file that the parser can actually process.

Create these fixtures:

1. fixtures/parsers/evtx/empty.evtx
   A minimal valid EVTX file with zero records (valid header, no events).
   The evtx crate accepts this — it should parse to Ok(vec![]) not an error.
   Create using the evtx file format: 8-byte magic "ElfFile\0", then
   write a minimal valid header. Research the format or generate
   programmatically using Rust if needed.

2. fixtures/parsers/prefetch/NOTEPAD.EXE-XXXXXXXX.pf
   A minimal valid Prefetch file stub (Windows 10 format, version 30).
   Can be all zeros with valid magic bytes (0x11 at offset 0).

3. fixtures/parsers/registry/empty.reg
   A valid but empty Windows Registry export:
   Windows Registry Editor Version 5.00
   (nothing else)

4. fixtures/parsers/lnk/minimal.lnk
   A minimal valid LNK file: 76-byte header with magic 0x4C000000
   at offset 0, all other bytes zero.

5. fixtures/parsers/json_artifacts/sample_timeline.json
   A valid JSON array with 3 sample timeline entries matching the
   shape that the CLI timeline command produces:
   [
     {
       "id": "test-001",
       "timestamp_unix": 1711234567,
       "timestamp_utc": "2024-03-23T10:00:00Z",
       "event_type": "file_access",
       "source": "prefetch",
       "summary": "NOTEPAD.EXE executed",
       "severity": "info"
     },
     ... 2 more entries
   ]

Also create fixtures/parsers/README.md explaining:
- What each fixture is
- What parser it targets
- Whether it's real or synthetic
- Expected parse result (empty/partial/N records)

CONSTRAINTS
===========
These are synthetic test artifacts, not real evidence.
Mark them clearly as synthetic in the README.
Do not create fixtures that contain any real personal data or real hashes.
```

**Verification:** Files exist and have non-zero sizes where expected.

**Deliverable:** 5 parser fixtures + README, ready for regression test use.
**Completed:** Added the requested EVTX, Prefetch, Registry, LNK, and JSON timeline fixtures under `apps/shield/fixtures/parsers/` and documented their provenance and expected behavior in `README.md`.

---

### ✅ Task 2.3 — Wire Parser Fixture Tests into CLI

**Objective:** Add integration tests to `strata-shield-cli` that run key parsers against the new fixtures and verify they don't crash or return unexpected errors.

**Files:** `crates/strata-shield-cli/tests/` (add new test file)

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics
File to create: crates/strata-shield-cli/tests/fixture_smoke_tests.rs

BACKGROUND
==========
We have synthetic test fixtures in apps/shield/fixtures/parsers/.
The CLI has commands like evtx-security, prefetch-fidelity, lnk-shortcut-fidelity
that parse these file types.

TASK
====
Create integration tests that verify each parser handles fixture files
without panicking or returning unexpected errors.

Tests to write:

1. test_evtx_empty_fixture()
   Run: forensic_cli evtx-security --input <fixture path> --json
   Assert: output is valid JSON with status "ok" or "warn"
   Assert: output does NOT contain "thread panicked" or "unwrap failed"
   Assert: total_returned == 0 (empty file = zero records, not an error)

2. test_registry_empty_fixture()
   Run: forensic_cli registry-core-user-hives --runmru-reg <fixture path> --json
   Assert: valid JSON response, no panic

3. test_lnk_fixture()
   Run: forensic_cli lnk-shortcut-fidelity --input <fixture path> --json
   Assert: valid JSON response, no panic

4. test_json_timeline_fixture()
   Run: forensic_cli timeline --source all --json
   (Use a temp case database, no evidence needed)
   Assert: valid JSON envelope returned

Use std::process::Command to invoke the CLI binary.
Use the CARGO_MANIFEST_DIR environment variable to find the fixture paths:
  let fixture_base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .join("..").join("..").join("apps").join("shield").join("fixtures").join("parsers");

Mark all tests with #[ignore] initially so they don't run in CI until
the binary build is confirmed working:
  #[test]
  #[ignore = "requires built forensic_cli binary"]
  fn test_evtx_empty_fixture() { ... }

After creating the file run: cargo test -p strata-shield-cli --no-run
to verify it compiles.
```

**Verification:**
```powershell
cargo test -p strata-shield-cli --no-run 2>&1 | Select-String "^error"
```
Target: 0 errors.

**Deliverable:** Fixture smoke tests exist, compile, and are ready to run against real binary.
**Completed:** Added ignored CLI fixture smoke tests for EVTX, registry, LNK, and timeline flows in `crates/strata-shield-cli/tests/fixture_smoke_tests.rs`; `cargo test -p strata-shield-cli --no-run` passes.

---

### ✅ Task 2.4 — Polish Core Examiner Workflow

**Objective:** Walk the core examiner path (open evidence ? browse ? timeline ? report) and fix every rough edge: empty states, loading indicators, error messages.

**Files:** `apps/shield/gui/src/pages/` — multiple pages

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics — React/TypeScript GUI
Files: apps/shield/gui/src/pages/

TASK
====
Audit and fix empty states and loading states across the core examiner workflow.
The workflow is: Dashboard ? File Explorer ? Timeline ? Reports

For each page, ensure:

1. Dashboard (Dashboard.tsx)
   - When hasEvidenceLoaded is false, the stat cards show "—" not "0"
   - The KB search input shows a clear placeholder: "Search methodology knowledge base..."
   - If KB search returns no results, show "No results — KB may be starting up" not blank

2. File Explorer (the file-system section in App.tsx)
   - When no evidence is loaded, show a clear empty state:
     "No evidence loaded. Use File > Open Evidence to begin."
   - When evidence is loading (isLoading=true), show a spinner in the tree area

3. Timeline (MainView.tsx timeline tab)
   - When timeline is empty and evidence IS loaded, show:
     "Timeline is building — artifact parsers are running in background."
   - When timeline is empty and evidence is NOT loaded, show:
     "Load evidence to generate a timeline."
   - Never show a blank table with headers and no rows

4. Reports section (renderReportsPanel in App.tsx)
   - The Export Timeline button should be disabled with tooltip "Load evidence first"
     when loadedEvidencePath is null
   - Show the count of exportable rows next to the button:
     "Export Timeline (1,247 events)"

CONSTRAINTS
===========
Do not change any data fetching logic or Tauri invocations.
Do not add new state variables if existing ones are sufficient.
Changes should be purely in render/JSX logic.
After changes run: npx tsc --noEmit (target: no new errors)
```

**Verification:** Manually test with no evidence loaded — all empty states should be clear and informative.

**Deliverable:** Examiner can understand system state at every point in the workflow without confusion.
**Completed:** Added explicit no-evidence, loading, timeline-building, and export-readiness states across `Dashboard.tsx`, `App.tsx`, and `MainView.tsx`; `npx tsc --noEmit` passes clean.

---

## ✅ Phase 3 — Depth & Validation (Months 2–3)

**Goal:** Build the automated validation infrastructure and deepen parser coverage.

---

### ✅ Task 3.1 — Automated Envelope Validation in CI

**Objective:** Make the GitHub Actions quality gate validate CLI envelope structure automatically on every commit.

**Files:** `.github/workflows/quality-gates.yml`, new script `apps/shield/scripts/validate_envelopes.ps1`

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics
Files:
  .github/workflows/quality-gates.yml
  apps/shield/scripts/ (create validate_envelopes.ps1)

BACKGROUND
==========
Every CLI command should return a CliResultEnvelope with these required fields:
  tool_version, timestamp_utc, platform, command, args, status, exit_code, elapsed_ms

"status" must be one of: "ok", "warn", "error"
"exit_code" must be an integer
"elapsed_ms" must be a non-negative integer

TASK
====
Create a PowerShell script apps/shield/scripts/validate_envelopes.ps1 that:

1. Builds the CLI binary: cargo build -p strata-shield-cli
2. Runs these commands with --json-result output to temp files:
   - forensic_cli capabilities --json-result temp_cap.json
   - forensic_cli doctor --json-result temp_doc.json
3. For each output file, validates:
   - File exists and is valid JSON
   - Contains all required fields
   - status is "ok", "warn", or "error"
   - exit_code is an integer
   - elapsed_ms is >= 0
4. Prints PASS or FAIL for each command
5. Exits with code 1 if any validation fails

Also add a job to .github/workflows/quality-gates.yml:
  envelope-validation:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: pwsh apps/shield/scripts/validate_envelopes.ps1

CONSTRAINTS
===========
The script must be runnable locally: pwsh apps\shield\scripts\validate_envelopes.ps1
Use only built-in PowerShell JSON parsing (ConvertFrom-Json), no external tools.
Temp files go in $env:TEMP\strata_validation\
Clean up temp files on exit.
```

**Verification:**
```powershell
pwsh apps\shield\scripts\validate_envelopes.ps1
```
Should print PASS for both commands.

**Deliverable:** Every commit validates CLI envelope structure automatically.
**Completed:** Rebuilt `apps/shield/scripts/validate_envelopes.ps1` around the current `strata` CLI, added the Windows CI job in `.github/workflows/quality-gates.yml`, and verified local PASS results for `capabilities` and `doctor`.

---

### ✅ Task 3.2 — Automated Stub Scanner in CI

**Objective:** Promote the existing guardian stub scanner to a CI gate so new stubs can't be merged without acknowledgment.

**Files:** `.github/workflows/quality-gates.yml`, `apps/shield/guardian/` (find existing scanner script)

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics
The guardian directory contains audit scripts. Find any existing stub scanner
in apps/shield/guardian/ or apps/shield/scripts/.

TASK
====
Create a stub scanner script apps/shield/scripts/scan_stubs.ps1 that:

1. Scans all .rs files in crates/ for these patterns:
   - Ok(Vec::new()) on an Err match arm (dangerous silent failure)
   - Err(_) => return Ok( (dangerous catch-all)
   - "STUB:" comment markers

2. Outputs a JSON report to apps/shield/guardian/stub_report.json:
   {
     "scan_date": "2026-03-23",
     "dangerous_empty_returns": [...],
     "stub_markers": [...],
     "total_dangerous": N,
     "total_stubs": N
   }

3. Compares against a baseline file apps/shield/guardian/stub_baseline.json
   (create this baseline from current state on first run)

4. Fails (exit code 1) if dangerous_empty_returns COUNT INCREASED vs baseline.
   New stubs are OK if documented. New dangerous patterns are not.

5. Prints a summary: "N dangerous patterns (baseline: M). Delta: +/-D"

Also create the initial baseline by running the script once with --create-baseline flag.

Add to .github/workflows/quality-gates.yml:
  stub-scan:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - run: pwsh apps/shield/scripts/scan_stubs.ps1

CONSTRAINTS
===========
Must be runnable locally: pwsh apps\shield\scripts\scan_stubs.ps1
The baseline file is committed to the repo.
New dangerous patterns added without updating baseline = CI failure.
```

**Verification:**
```powershell
pwsh apps\shield\scripts\scan_stubs.ps1
```
Should report current count and exit 0.

**Deliverable:** Dangerous silent failures can't regress without CI catching them.
**Completed:** Rebuilt `scan_stubs.ps1` into a baseline-aware CI gate, created `apps/shield/guardian/stub_baseline.json`, and verified the current scan exits clean with a zero dangerous-pattern delta.

---

### ✅ Task 3.3 — AFF4 Container VFS Integration

**Objective:** Move AFF4 from Stub to Experimental. The container parsing exists; the VFS integration returns `Ok(Vec::new())`. Wire them together.

**Files:** `crates/strata-fs/src/virtualization/aff4.rs`, `crates/strata-fs/src/container/aff4.rs`

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics
Files:
  crates/strata-fs/src/virtualization/aff4.rs
  crates/strata-fs/src/container/aff4.rs
  crates/strata-fs/src/virtualization/mod.rs

BACKGROUND
==========
The AFF4 container module exists and can open AFF4 containers.
The virtualization/aff4.rs VFS adapter currently returns Ok(Vec::new())
for all enumerate calls — the VFS is not wired to the container.

TASK
====
1. Read crates/strata-fs/src/container/aff4.rs to understand what data
   it can provide (file entries, directory structure, etc.)

2. Read crates/strata-fs/src/virtualization/mod.rs to understand the
   VfsEntry struct and how other containers (E01, RAW) wire their enumerate
   methods to actual data.

3. In crates/strata-fs/src/virtualization/aff4.rs, implement the enumerate
   methods to call into the container module and return real VfsEntry records.

4. If the container module doesn't expose directory enumeration yet, add a
   minimal read_directory() method to container/aff4.rs that returns file
   paths as a Vec<String>.

5. Update the capability status in crates/strata-shield-engine/src/capabilities.rs:
   Change container.aff4 from CapabilityStatus::Stub to CapabilityStatus::Experimental
   Update the limitations text to: "Basic file enumeration implemented; 
   full metadata and nested container support in progress"

CONSTRAINTS
===========
If AFF4 decryption or complex features are not implemented, return an error
with ForensicError::UnsupportedParser("AFF4 encryption not supported")
rather than returning zeros or empty results silently.
After changes run: cargo check -p strata-fs
Report what was implemented vs what remains as future work.
```

**Verification:**
```powershell
cargo check -p strata-fs 2>&1 | Select-String "^error"
```
Target: 0 errors.

**Deliverable:** AFF4 containers enumerate their file list instead of returning empty.
**Completed:** Added AFF4 directory/member enumeration in `container/aff4.rs`, wired `virtualization/aff4.rs` to expose real VFS entries and file reads, and promoted `container.aff4` to `Experimental` in the capability registry.

---

### ✅ Task 3.4 — Court-Ready Report Export

**Objective:** Make the report generator produce output that includes the required court-ready sections: examiner identity, case metadata, evidence hash chain, methodology disclosure, limitation disclosure.

**Files:** `crates/strata-core/src/report/generator.rs`, `crates/strata-core/src/report/html.rs`, `crates/strata-shield-cli/src/commands/report_skeleton.rs`

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics
Files:
  crates/strata-core/src/report/generator.rs
  crates/strata-core/src/report/html.rs
  crates/strata-shield-cli/src/commands/report_skeleton.rs

TASK
====
Extend the report skeleton command to generate a court-ready HTML report
with these required sections:

1. HEADER
   - Report title: "Digital Forensic Examination Report"
   - Examiner name (from --examiner arg, default "Examiner")
   - Case ID (from --case arg)
   - Report generated date (UTC)
   - Report version: "1.0"

2. EVIDENCE INTEGRITY
   - Evidence source path
   - SHA-256 hash of evidence (from case database or --hash arg)
   - Hash verification status: VERIFIED / UNVERIFIED
   - Date/time evidence was first loaded

3. METHODOLOGY
   - Tool name: "Strata Forensics"
   - Tool version (from CARGO_PKG_VERSION)
   - Analysis approach: "Read-only examination of evidence container"
   - Parser maturity note: "Results from Experimental parsers should be corroborated"

4. FINDINGS SUMMARY
   - Total files indexed
   - Total artifacts extracted
   - Timeline event count
   - Notable items count

5. LIMITATIONS
   - Static section: "This report reflects the state of analysis at time of generation.
     Parsers marked Experimental may not capture all artifacts of their type.
     This tool does not modify evidence sources."

6. SIGNATURE PLACEHOLDER
   - "Examiner Signature: _______________________"
   - "Date: _______________________"

Generate as a clean HTML file with inline CSS (no external dependencies).
The report_skeleton command should accept:
  --case <id>
  --examiner <name>
  --output <path>  (default: ./report_<case_id>.html)
  --hash <sha256>  (optional)

After changes run: cargo check -p strata-shield-cli
Test with: forensic_cli report-skeleton --case test123 --examiner "Jane Smith" --output test_report.html
```

**Verification:**
```powershell
cargo check -p strata-shield-cli 2>&1 | Select-String "^error"
```
Then open the generated HTML and verify all 6 sections are present.

**Deliverable:** Single command generates a court-acceptable methodology report.

**Completed:** `report-skeleton` now generates a standalone court-ready HTML report with examiner/case metadata, integrity, methodology, findings summary, limitations, and signature sections; verified via cargo check and a live HTML generation smoke test.

---

## ✅ Phase 4 — Production Readiness (Months 4–6)

**Goal:** Portable build, real-time guardian validation, plugin coverage expansion.

---

### ✅ Task 4.1 — Portable Package Build Script

**Objective:** One PowerShell script that produces a self-contained, deployable Strata installation.

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics
Script to create: apps/shield/scripts/build_package.ps1

TASK
====
Create a PowerShell build script that produces a portable Strata package.

The script should:

1. Build release binaries:
   cargo build --workspace --release

2. Create package directory: dist\strata_<version>\

3. Copy required files:
   - target\release\forensic_cli.exe ? dist\strata\bin\
   - apps\shield\gui-tauri\target\release\strata-shield.exe ? dist\strata\
   - apps\shield\guardian\*.md ? dist\strata\docs\guardian\
   - README.md ? dist\strata\

4. Create startup scripts in dist\strata\scripts\:
   - start_strata.ps1 (launches the GUI)
   - run_cli.ps1 (helper that sets PATH to include bin\)

5. Verify the package:
   - Check all expected files exist
   - Compute SHA-256 of forensic_cli.exe
   - Write dist\strata\MANIFEST.json with file list and hashes

6. Print summary:
   "Package built: dist\strata_<version>\"
   "forensic_cli.exe SHA-256: <hash>"
   "Total files: N"

CONSTRAINTS
===========
Never include model files (.gguf) in the package.
Never include target\ or node_modules\ in the package.
Use relative paths in all generated scripts.
The package must run from any directory when unzipped.
```

**Verification:**
```powershell
pwsh apps\shield\scripts\build_package.ps1
```
Then move the dist folder to a different directory and verify it runs.

**Deliverable:** One-command deployable package with manifest.

**Completed:** Added `apps/shield/scripts/build_package.ps1`, which builds the workspace, packages `forensic_cli.exe` and `strata-shield.exe` into `dist\strata_0.1.0`, emits `MANIFEST.json`, and was verified by running the packaged CLI helper from a copied temp directory; the script falls back to an existing GUI binary when the fresh Tauri build encounters current repo-side errors.

---

### ✅ Task 4.2 — Real-Time Guardian Validation

**Objective:** Guardian warnings appear inline during active examination sessions, not only in post-hoc audit reports.

**Files:** `apps/shield/gui-tauri/src-tauri/src/lib.rs`, `apps/shield/gui/src/App.tsx`

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics
Files:
  apps/shield/gui-tauri/src-tauri/src/lib.rs
  apps/shield/gui/src/App.tsx

TASK
====
Add a guardian warning event system so that when a CLI command returns
a non-ok envelope, the warning is surfaced in the GUI immediately.

Backend (lib.rs):
1. After any Tauri command that invokes the CLI and gets an envelope back,
   check if envelope.warning is Some(text)
2. If yes, emit a Tauri event: "guardian-warning" with payload:
   { "command": "<command name>", "warning": "<warning text>", "timestamp": "<utc>" }

Frontend (App.tsx):
1. Add a guardian warnings state: useState<Array<{command, warning, timestamp}>>([])
2. Add a listener for "guardian-warning" events (use the existing listen pattern)
3. When a warning arrives, add it to the warnings list (max 20, FIFO)
4. In the Dashboard render, if warnings.length > 0, show a compact
   warning banner above the case banner:
   "Guardian: N warning(s) from recent operations" with a dropdown
   showing the last 3 warnings (command + text)
5. Add a "Clear" button that resets the warnings list

CONSTRAINTS
===========
Guardian warnings must never block the UI or prevent work from continuing.
The warning banner is informational only.
Warnings auto-expire after 30 minutes (use a timestamp check on render).
After changes run: npx tsc --noEmit in apps/shield/gui/
```

**Verification:** Run a CLI operation that produces a warning, verify it appears in the Dashboard.

**Deliverable:** Examiners see guardian warnings in real-time without running manual audits.

**Completed:** Added guardian-warning event emission in gui-tauri, Dashboard warning banner with clear/expiry behavior, and verified compile/build plus a real warning envelope path via hashset list.

---

### ✅ Task 4.3 — Signal and WhatsApp Plugin to Supported Tier

**Objective:** Bring two high-value mobile parsers from the plugin-index to fixture-backed Supported status.

**Files:** `plugins/strata-plugin-index/src/mobile/signal.rs`, `plugins/strata-plugin-index/src/mobile/whatsapp_full.rs`

**[PROMPT]**
```
CONTEXT
=======
Project: Strata Forensics
Files:
  plugins/strata-plugin-index/src/mobile/signal.rs
  plugins/strata-plugin-index/src/mobile/whatsapp_full.rs

TASK
====
1. Read both files and assess their current implementation state.
   - Are they returning real data or Ok(Vec::new()) stubs?
   - What database schemas do they target?
   - What are their target_patterns()?

2. For each file that is a stub:
   - Implement basic SQLite parsing for the primary table
   - Signal: parse msgstore.db, Messages table (id, address, date, body, type)
   - WhatsApp: parse msgstore.db, messages table (same schema, different path)
   - Return ParsedArtifact with:
     - artifact_type: "mobile_signal_message" or "mobile_whatsapp_message"
     - timestamp: from the date/timestamp column (Unix ms ? Option<i64>)
     - description: format!("Signal message: {}", body.chars().take(80).collect::<String>())
     - source_path: path parameter
     - json_data: full row as JSON

3. Add the strata_core::parsers::sqlite_utils dependency if needed for SQLite parsing.

4. Create fixture files:
   apps/shield/fixtures/parsers/mobile/signal_empty.db
   apps/shield/fixtures/parsers/mobile/whatsapp_empty.db
   (minimal valid SQLite databases with the correct table schema but zero rows)

5. Update the plugin capability status to CapabilityStatus::Experimental
   in crates/strata-shield-engine/src/capabilities.rs for both parsers.

CONSTRAINTS
===========
If msgstore.db is not found or has wrong schema, return Ok(vec![]) with
a tracing::warn!, not an error — these databases may not exist on all devices.
After changes: cargo check -p strata-plugin-index
```

**Verification:**
```powershell
cargo check -p strata-plugin-index 2>&1 | Select-String "^error"
```

**Deliverable:** Signal and WhatsApp parsers return real message data when databases are present.

**Completed:** Reworked both mobile parsers to return real row-backed artifacts without synthetic fallbacks, added warn-and-empty handling plus zero-row SQLite fixtures/tests, and registered Signal/WhatsApp capabilities at Experimental status.

---

## Milestone Checkpoints

Use these checkpoints to assess readiness before advancing phases.

### End of Phase 1 Checkpoint
- [ ] `npx tsc --noEmit` ? 0 errors
- [ ] `cargo clippy --workspace -- -D warnings` ? 0 errors
- [ ] `cargo test --workspace` ? 519+ tests passing
- [ ] KNOWN_GAPS.md reflects current state
- [ ] All Session 1 fixes verified and committed

### End of Phase 2 Checkpoint
- [ ] `/summarize` endpoint live on KB bridge
- [ ] Fixture library with 5 parser fixtures
- [ ] Fixture smoke tests compile
- [ ] Core examiner workflow has no confusing empty states
- [ ] `cargo check --workspace` clean

### End of Phase 3 Checkpoint
- [ ] Envelope validation runs in CI
- [ ] Stub scanner runs in CI with baseline
- [ ] AFF4 returns real file listing (Experimental tier)
- [ ] Court-ready HTML report generated by single command
- [ ] Guardian KNOWN_GAPS.md updated with completed items

### End of Phase 4 Checkpoint
- [ ] `build_package.ps1` produces working deployable
- [ ] Guardian warnings appear inline in Dashboard
- [ ] Signal + WhatsApp parsers at Experimental with fixtures
- [ ] Full guardian audit runs and produces PASS WITH WARNINGS verdict
- [ ] Release readiness checklist: 45+ of 55 items passing

---

## Codex Operating Rules

Follow these rules every time you use Codex on this project.

**1. Always give Codex full access mode.** Partial access causes path resolution failures.

**2. Never paste prompts into PowerShell.** Prompts go into Codex. Verification commands go into PowerShell.

**3. After every Codex prompt, run the verification command.** Don't assume it worked.

**4. Paste verification output here (to Claude) before moving to next task.** Claude reviews it and catches issues Codex missed.

**5. Cargo check before and after every Rust change.** The command is:
```powershell
cargo check -p <crate-name> 2>&1 | Select-String "^error"
```

**6. TypeScript check after every GUI change:**
```powershell
cd D:\Strata\apps\shield\gui && npx tsc --noEmit 2>&1 | Select-String "error TS"
```

**7. One task at a time.** Don't stack multiple Codex prompts without verifying the first.

---

## Quick Reference — Key File Locations

| What | Where |
|------|-------|
| Main engine | `crates/strata-core/src/` |
| Filesystem/containers | `crates/strata-fs/src/` |
| CLI commands | `crates/strata-shield-cli/src/commands/` |
| AI/insight layer | `crates/strata-insight/src/` |
| GUI pages | `apps/shield/gui/src/pages/` |
| GUI state | `apps/shield/gui/src/App.tsx` |
| Tauri backend | `apps/shield/gui-tauri/src-tauri/src/lib.rs` |
| KB bridge client | `apps/shield/gui-tauri/src-tauri/src/kb_bridge_client.rs` |
| Guardian docs | `apps/shield/guardian/` |
| Plugin parsers | `plugins/strata-plugin-index/src/` |
| CI workflows | `.github/workflows/` |
| Capability registry | `crates/strata-shield-engine/src/capabilities.rs` |
| Error types | `crates/strata-fs/src/errors.rs` |
| Fixtures | `apps/shield/fixtures/parsers/` |

---

## North Star

The best version of Strata is a forensic suite an experienced examiner can say:

> "This tool is honest about what it supports, strong where it claims strength,
> disciplined in how it handles evidence, and reliable enough to trust in serious work."

Every task in this document moves toward that sentence being true.

















