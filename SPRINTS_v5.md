# SPRINTS_v5.md — STRATA ARCHITECTURAL FIXES + FIELD VALIDATION
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md and SPRINTS_v5.md. Execute all incomplete sprints in order.
#         For each sprint: implement, test, commit, then move to the next."
# Last updated: 2026-04-17
# Prerequisite: SPRINTS.md, SPRINTS_v2.md, SPRINTS_v3.md, SPRINTS_v4.md complete
# Current state: 3,337 tests, 22 plugins registered, clean build
# Focus: Close the gap between "compiles clean" and "actually usable end-to-end"

# Source of punch list: FIELD_TEST_REPORT_2026-04-17.md from Opus audit session
# Items identified when attempting to ingest real Android 14 + iOS 15 Cellebrite images.

---

## HOW TO EXECUTE

Read CLAUDE.md first. Then execute each sprint below in order.
For each sprint:
1. Implement exactly as specified
2. Run `cargo test --workspace` — all 3,337+ tests must pass
3. Run `cargo clippy --workspace -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!`
5. Commit with message: "feat: [sprint-id] [description]" or "fix: [sprint-id] [description]"
6. Move to next sprint immediately

If a sprint is marked COMPLETE — skip it.

---

## COMPLETED SPRINTS (skip these)

None yet — this is v5.

---

# ═══════════════════════════════════════════════════════
# PART 1 — ARCHITECTURAL FIXES (from FIELD_TEST_REPORT)
# ═══════════════════════════════════════════════════════

## SPRINT FIX-1 — CLI Plugin Runner

**Problem identified in field test:**
`strata-shield-cli` has no CLI entry point for the plugin pipeline.
`run_plugin` is only referenced from `strata-engine-adapter` (Tauri GUI) and
legacy `strata-tree`. Air-gapped examiners running headless cannot currently
use Strata's full plugin chain from the command line.

This is a shipping blocker. Every federal examiner in a SCIF needs CLI access.

**Implementation:**

Create `crates/strata-shield-cli/src/commands/ingest.rs`:

```rust
pub fn run_ingest(args: IngestArgs) -> Result<(), CliError> {
    // 1. Validate source path exists and is readable
    // 2. Initialize case directory structure (same as GUI does)
    // 3. Run file_index pre-scan (from v5 audit work)
    // 4. Run NSRL + threat intel prefilter
    // 5. Execute all registered plugins in order
    // 6. Run cross-plugin correlation
    // 7. Compute artifact ranking
    // 8. Generate report output
    // 9. Print summary: files indexed, plugins run, artifacts emitted,
    //    correlations found, errors encountered
}
```

CLI args structure:
```rust
pub struct IngestArgs {
    pub source: PathBuf,
    pub case_dir: PathBuf,
    pub case_name: String,
    pub examiner: String,
    pub plugins: Option<Vec<String>>,  // None = all plugins
    pub output_format: OutputFormat,   // Html/Json/Csv
    pub triage_mode: bool,
    pub quiet: bool,
}
```

Wire into main CLI:
```bash
strata ingest --source /path/to/image --case-dir ./cases/case-001 \
              --case-name "Case 001" --examiner "SA Randolph"
```

**Progress reporting:**
- Print progress every 5 seconds: files indexed, bytes indexed, files/sec
- Print plugin execution: "[Phantom] Starting..." "[Phantom] Complete — 1,247 artifacts"
- Print correlation pass status
- Print final summary table

**Error handling:**
- Plugin errors must not crash the CLI — log and continue
- Report summary at end listing any plugins that errored
- Return exit code 0 on success, 1 on any plugin error, 2 on fatal error

**Tests required:**
- Small synthetic image ingestion test
- Plugin error handling (inject a failing plugin, verify CLI continues)
- JSON output schema validation
- Exit code correctness

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT FIX-2 — UFED Container Support

**Problem identified in field test:**
Cellebrite UFED tarballs contain `EXTRACTION_FFS.zip` as the actual payload.
UFED container type isn't registered in `strata-fs::container::ingest_registry`,
so the CLI cannot recognize and unwrap these archives.

The existing `parsers/ufdr.rs` and `parsers/ios/cellebrite.rs` are in the
codebase but not wired into the container ingestion pipeline.

**Implementation:**

Register UFED as a container type in `crates/strata-fs/src/container/mod.rs`:

```rust
pub enum ContainerType {
    RawImage,
    DD,
    E01,
    AFF4,
    UFED,          // NEW — Cellebrite UFED wrapper
    UFDR,          // NEW — Cellebrite UFDR report package
    Tarball,
    ZipArchive,
    AndroidBackup, // AND-4 already implemented this
}
```

Detection logic:
- UFED: tarball containing `EXTRACTION_FFS.zip` at root, or `.ufd` file present
- UFDR: `.ufdr` extension, or directory containing `report.xml` with Cellebrite signature

Ingestion flow:
1. Detect container type from magic bytes/file structure
2. For UFED: extract outer tarball, detect `EXTRACTION_FFS.zip`, extract that
3. For UFDR: parse `report.xml` for metadata, unwrap payload directory
4. Pass resulting filesystem tree to file_index

Wire the existing `parsers/ufdr.rs` and `parsers/ios/cellebrite.rs`:
- `ufdr.rs` parses the report.xml metadata
- `cellebrite.rs` handles iOS-specific Cellebrite artifacts
- Both must emit `Artifact` records through the normal plugin interface

**Critical requirement:**
After UFED/UFDR unwrapping, the examiner should see a clean filesystem
tree — no indication they need to manually extract anything. Strata handles
the container layers transparently.

**Tests required:**
- Synthetic UFED tarball ingestion
- Synthetic UFDR directory ingestion
- Nested container handling (tarball → EXTRACTION_FFS.zip → files)
- Metadata extraction from report.xml

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT FIX-3 — integrity_violations Migration on Case Init

**Problem identified in field test:**
The `integrity_violations` table needs to be created when a case is initialized
but the migration isn't running on fresh case directories.

**Implementation:**

In `crates/strata-core/src/case/init.rs` (or wherever case init lives):

Ensure migration runs on case creation. The table schema:
```sql
CREATE TABLE IF NOT EXISTS integrity_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,              -- ISO 8601 UTC
    violation_type TEXT NOT NULL,         -- HashMismatch/TimestampAnomaly/
                                          -- SizeMismatch/TamperDetected
    expected_value TEXT NOT NULL,
    actual_value TEXT NOT NULL,
    affected_path TEXT NOT NULL,
    severity TEXT NOT NULL,               -- Low/Medium/High/Critical
    examiner_notified INTEGER DEFAULT 0,
    acknowledged_by TEXT,
    acknowledgment_timestamp TEXT
);

CREATE INDEX idx_integrity_timestamp ON integrity_violations(timestamp);
CREATE INDEX idx_integrity_type ON integrity_violations(violation_type);
CREATE INDEX idx_integrity_severity ON integrity_violations(severity);
```

Verify the migration runs in this order on case init:
1. Case metadata table
2. Chain of custody audit log (from COC-1)
3. File index database (from v5 audit)
4. Timeline database
5. Integrity violations table ← ADD THIS
6. Artifact storage tables
7. Correlation findings table

Add migration version tracking so existing cases can be upgraded safely.

**Tests required:**
- Fresh case init creates all required tables
- Existing case upgrade adds integrity_violations without data loss
- Integrity violation recording + query works end-to-end

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT FIX-4 — Bundle Path Specification Correction

**Problem identified in field test:**
Build output path documentation is incorrect. Opus found the actual bundle
location differs from what's specified in build instructions.

**Implementation:**

Audit the build output paths for all three platforms:
- macOS: confirm `Strata.app` and `.dmg` locations
- Windows: confirm `Strata.exe` and installer locations
- Linux: confirm `strata` binary location

Update these files with correct paths:
- `CLAUDE.md` — build instructions section
- `README.md` — build section
- `.github/workflows/release.yml` — artifact upload paths
- Any build documentation in `docs/`

**Verify with actual build:**
Run `cargo tauri build` on macOS, confirm the exact bundle paths,
document them canonically, and ensure CI artifact upload matches.

**Load-bearing requirement to add to CLAUDE.md:**

Add this rule to CLAUDE.md under "Hard Rules":

> **Build artifact requirement:**
> Every Strata release must produce a working clickable application:
> - macOS: `Strata.app` bundle and `.dmg` installer
> - Windows: `Strata.exe` and installer
> - Linux: `strata` binary
>
> The CI must verify these artifacts exist and are runnable.
> A version that does not produce a clickable application is not shippable.
> The CLI is the fallback for headless/air-gapped contexts — the GUI is
> the primary tool for day-to-day casework.

Zero code changes required except doc fixes.

---

## SPRINT FIX-5 — strata-plugin-index Crate-Type Decision

**Problem identified in field test:**
`strata-plugin-index` is cdylib-only by design. It's a shared library for
external plugin loading but not a static plugin. This means it's built but
not linked into the engine adapter, creating ambiguity about its role.

**Implementation:**

Decide and document the plugin architecture:

**Option A: Make it a dual-crate (staticlib + cdylib)**
- Static version links into engine adapter like other plugins
- Dynamic version supports runtime plugin loading for future extensibility
- Most flexible but most complex

**Option B: Keep cdylib-only, remove from workspace registration path**
- Clarifies that it's a future-use dynamic loader
- Document that it's scaffolding for plugin hot-loading capability
- Simplest

**Recommendation: Option B** unless dynamic plugin loading is an active feature.

Update:
- `Cargo.toml` workspace — clarify strata-plugin-index status with comment
- `CLAUDE.md` — document the plugin architecture (static vs dynamic)
- Add a `PLUGIN_ARCHITECTURE.md` in `/docs/` explaining:
  - How plugins are registered (compile-time via engine adapter)
  - What strata-plugin-index is for (future dynamic loading)
  - How to add a new plugin (step-by-step for future contributors)

Zero code changes required except doc updates.

---

## SPRINT FIX-6 — Plugin Registration Interactive Verification

**Problem identified in field test:**
Five plugins (Apex, Carbon, Pulse, Vault, ARBOR) were built but not registered
in the engine adapter. Without a verification step, this failure mode will
happen again.

**Implementation:**

Create `scripts/verify_plugins.rs` (or a standalone binary in crates/):

```rust
fn main() {
    // 1. Read Cargo.toml workspace members
    // 2. Find all entries matching plugins/strata-plugin-*
    // 3. Read strata-engine-adapter/src/lib.rs (or build.rs)
    // 4. Parse the build_plugins() or register_plugins() function
    // 5. For each workspace plugin, verify it's registered
    // 6. Exit 1 with clear error if any plugin is missing
    // 7. Print table: plugin name | workspace | registered | status
}
```

Wire into CI:
- Add a "Plugin Registration Check" step in `quality-gates.yml`
- Runs before test suite
- Fails fast if any plugin is unregistered
- Prevents future shipping-blocker bugs

Also wire into pre-commit via a git hook or Cargo check:
```toml
# In top-level Cargo.toml or workspace config
[workspace.metadata.verify]
plugin-registration = true
```

**Tests required:**
- Full registration (all plugins present) → exit 0
- Missing plugin → exit 1 with specific plugin name in error
- Extra plugin (registered but not in workspace) → warning but not failure

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 2 — FIELD VALIDATION CYCLE
# ═══════════════════════════════════════════════════════

## SPRINT VALIDATE-1 — Full Test Image Matrix Ingestion

**Objective:**
Run Strata against every test image in `~/Wolfmark/Test Material/` to
surface real-world integration issues. This is the true benchmark.

**Test images to process:**

Korbyn is populating `~/Wolfmark/Test Material/` with:
- iOS public image (already have — Android_14_public_image.tar.gz)
- iOS Full File System extraction
- Android public image
- macOS public image
- Windows public image
- Linux public image (multiple distros if available)
- Memory dump (.raw/.mem/.dmp)
- Google Takeout archive
- Wiped disk image (post-factory-reset)
- Cellebrite UFED export
- Cellebrite UFDR report

**Execution:**

For EACH image in the Test Material folder:

1. **Identify format** — detect container type, document it
2. **Ingest** — run Strata CLI against the image
   ```bash
   strata ingest --source "~/Wolfmark/Test Material/[image]" \
                 --case-dir ./test-cases/[image-name] \
                 --case-name "Test: [image-name]" \
                 --examiner "Opus Field Test"
   ```
3. **Capture terminal output** — save full log to `test-cases/[image-name]/ingest.log`
4. **Record metrics:**
   - Total time
   - Files indexed
   - Files/second
   - Plugins that ran successfully
   - Plugins that errored (with error messages)
   - Plugins that produced zero artifacts
   - Total artifacts emitted
   - Cross-plugin correlations found
   - Top 20 highest-ranked artifacts

5. **Error triage** — for every plugin error:
   - Document the error message
   - Identify root cause (missing dependency, malformed data, parser bug)
   - Tag severity: Blocker / Major / Minor

**Do NOT try to fix errors during VALIDATE-1.** Just document them.
Fixes come in VALIDATE-2 and VALIDATE-3.

**Output:**
- `~/Wolfmark/strata/FIELD_VALIDATION_REPORT.md` — summary table
- `~/Wolfmark/strata/test-cases/[image-name]/` — per-image detailed results

---

## SPRINT VALIDATE-2 — Fix All Blocker-Level Errors

**Objective:**
Triage the error report from VALIDATE-1. Fix every Blocker-severity issue.

**Definition of Blocker:**
- Plugin panics or crashes on valid input
- Plugin loses data silently
- Ingestion fails to complete
- Report generation fails
- Chain of custody audit log corruption
- Any `.unwrap()` that got introduced and fired
- Any data integrity issue

**Process:**

For each blocker:
1. Reproduce the error on the failing image
2. Write a failing test that captures the bug
3. Fix the code
4. Verify the test now passes
5. Re-run the failing image to confirm real-world fix
6. Commit: `fix: [plugin] [brief description]`

**Hard rules:**
- Every fix must add at least one regression test
- Every fix must keep all 3,337+ tests passing
- No shortcuts — if a plugin is fundamentally broken on a data type, fix it properly

**Output:**
- Updated FIELD_VALIDATION_REPORT.md with blocker status
- All blockers marked FIXED
- New test count (should be 3,337 + number of regression tests added)

---

## SPRINT VALIDATE-3 — Fix All Major-Level Errors

**Objective:**
Fix all Major-severity issues from VALIDATE-1.

**Definition of Major:**
- Plugin produces incomplete data (missing fields)
- Plugin produces inaccurate timestamps
- Plugin misses known artifact types for a data format
- Cross-plugin correlation fails to fire when it should
- Artifact ranking produces obviously wrong ordering
- Performance issue (ingestion takes > 10x expected time)

**Process:**
Same as VALIDATE-2 but for Major-severity issues.

**Minor issues** — document in report but do not fix in this sprint.
Queue them for SPRINTS_v6.md.

---

## SPRINT VALIDATE-4 — Re-run Full Image Matrix

**Objective:**
After all blocker and major fixes, re-run the entire test image matrix
to confirm fixes worked and no regressions appeared.

**Execution:**
Same as VALIDATE-1.

**Success criteria:**
- Zero Blocker errors across all test images
- Zero Major errors across all test images
- All 26 plugins produce at least some artifacts on at least one image
- Cross-plugin correlation fires on every multi-plugin scenario
- File index performance meets or exceeds 5,000 files/sec release mode on Apple Silicon
- All 3,337+ tests still pass
- Clippy clean

**Output:**
- Updated FIELD_VALIDATION_REPORT.md showing clean run
- Summary table: plugin coverage per image type
- Ready-to-ship v1.5.0 confirmation

---

## SPRINT VALIDATE-5 — Performance Baseline Documentation

**Objective:**
Document Strata's actual performance characteristics for each image type.
This becomes the baseline for future regression detection and marketing claims.

**Benchmarks to capture:**

For each image size tier:
- Small (< 10 GB): mobile phone extractions
- Medium (10-100 GB): laptop images, memory dumps
- Large (100 GB - 1 TB): workstation images
- Very Large (> 1 TB): server images (if any available)

**Metrics per tier:**
- File index time (seconds)
- File index throughput (files/sec, MB/sec)
- Per-plugin execution time
- Total ingestion time
- Peak memory usage
- Output artifact count
- Correlation finding count

**Hardware baseline:**
- Apple Silicon M1 Max (Korbyn's machine)
- Document for reference on commercial documentation

**Output:**
- `~/Wolfmark/strata/docs/PERFORMANCE_BENCHMARKS.md`
- Include in Strata commercial documentation
- Add to README as a "Performance" section

---

# ═══════════════════════════════════════════════════════
# COMPLETION CRITERIA
# ═══════════════════════════════════════════════════════

SPRINTS_v5.md is complete when:
- All FIX-1 through FIX-6 sprints shipped
- All VALIDATE-1 through VALIDATE-5 sprints shipped
- FIELD_VALIDATION_REPORT.md shows zero Blocker + zero Major issues
- All test images ingest cleanly end-to-end
- Test count is 3,337+ with all passing
- Clippy clean workspace-wide
- CLI and GUI both functional
- Ready-to-ship v1.5.0 declared

---

*STRATA AUTONOMOUS BUILD QUEUE v5*
*Wolfmark Systems — 2026-04-17*
*Part 1: Architectural fixes surfaced by field test*
*Part 2: Full image matrix validation cycle*
*Mission: Close the gap between "compiles clean" and "ships clean"*
*Execute all incomplete sprints in order. Ship everything.*
