# Sprint 10 — Plugin Sandboxing + Tauri Cleanup + ShimCache + Tree Fix

_Date: 2026-04-25_
_Model: claude-opus-4-7_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Context

Sprint 9 unlocked folder and archive ingestion. Live testing on the
MacBookPro CTF image revealed that Phantom plugin panics when fed
non-Windows hive files via the nt-hive crate. The panic takes down
the entire plugin run — all plugins after Phantom stop executing.

This is the highest priority fix in Sprint 10. An examiner loading
a macOS or iOS image should get results from all 23 plugins, not a
partial run that silently stops when one parser chokes.

---

## Hard rules (always)

- Zero NEW `.unwrap()` in production code paths
- Zero NEW `unsafe{}` without explicit justification
- Zero NEW `println!` in production — use `log::` macros
- All errors handled explicitly — no silent failures
- All 9 load-bearing tests must pass after every change
- `cargo test --workspace` must pass
- `cargo clippy --workspace -- -D warnings` must be clean
- No new TODO/FIXME in committed code

---

## PRIORITY 1 — Plugin Panic Sandboxing

### The problem

`run_all_on_evidence` in `crates/strata-engine-adapter/src/plugins.rs`
calls `plugin.execute(context)` directly. If a plugin panics — as
Phantom does when the `nt-hive` crate receives a non-NT-hive file —
the panic unwinds through the calling thread and stops all subsequent
plugins.

On a macOS image: Phantom tries to parse macOS files as Windows
registry hives, nt-hive panics, the entire plugin run stops.
Plugins after Phantom in the execution order never run.

### Fix

Wrap every `plugin.execute()` call in `std::panic::catch_unwind`.

**Step 1 — Locate the plugin execution loop**

In `crates/strata-engine-adapter/src/plugins.rs`, find the loop
inside `run_all_on_evidence` that calls `plugin.execute(context)`.

**Step 2 — Wrap with catch_unwind**

```rust
use std::panic;

// Replace:
let result = plugin.execute(context.clone());

// With:
let plugin_name = plugin.name().to_string();
let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
    plugin.execute(context.clone())
}));

let result = match result {
    Ok(plugin_result) => plugin_result,
    Err(panic_payload) => {
        let msg = panic_payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic_payload.downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("unknown panic");
        log::error!(
            "Plugin '{}' panicked: {} — continuing with remaining plugins",
            plugin_name,
            msg
        );
        // Return an empty result so the run continues
        Ok(vec![])
    }
};
```

**Step 3 — Emit a visible artifact for the panic**

Rather than silently swallowing the panic, emit a special
"plugin_error" artifact so the examiner can see which plugin
failed and why:

```rust
Err(panic_payload) => {
    let msg = /* extract as above */;
    log::error!("Plugin '{}' panicked: {}", plugin_name, msg);

    // Surface the failure as a visible artifact
    let error_artifact = StrataArtifact {
        artifact_type: "plugin_error".to_string(),
        source_plugin: plugin_name.clone(),
        confidence: Confidence::Low,
        is_advisory: true,
        advisory_notice: Some(format!(
            "Plugin '{}' encountered an error and was skipped: {}. \
             Results from this plugin are unavailable for this evidence.",
            plugin_name, msg
        )),
        ..Default::default()
    };
    Ok(vec![error_artifact])
}
```

**Step 4 — Add the same protection to run_plugin (single plugin)**

The single-plugin path used when an examiner clicks "RE-RUN" on
an individual plugin also needs catch_unwind. Find and wrap it
identically.

**Step 5 — Tests**

```rust
#[test]
fn panicking_plugin_does_not_stop_subsequent_plugins() {
    // Create a mock plugin that panics
    // Run it alongside a mock plugin that returns artifacts
    // Verify: the run completes, the second plugin's artifacts
    // are present in the result, a plugin_error artifact is
    // present for the panicking plugin
}

#[test]
fn panic_message_is_captured_in_error_artifact() {
    // Verify the advisory_notice contains the panic message
}

#[test]
fn single_plugin_rerun_survives_panic() {
    // Same test for the single-plugin execution path
}
```

**Step 6 — Verify with MacBookPro**

After fixing, load the MacBookPro CTF folder in Strata.
All 23 plugins should complete. Phantom will produce a
plugin_error artifact (expected — it's a macOS image with
no NT hives) but the run continues to completion.

Expected: artifact count significantly higher than 8,100
because all plugins after Phantom now run.

### Acceptance criteria — P1

- [ ] `catch_unwind` wraps both `run_all_on_evidence` loop
  and single `run_plugin` path
- [ ] Panicking plugin produces a visible `plugin_error` artifact
- [ ] All other plugins continue running after a panic
- [ ] MacBookPro loads — all 23 plugins complete
- [ ] 3 new tests pass
- [ ] All 9 load-bearing tests still green
- [ ] No new `.unwrap()`, clippy clean

---

## PRIORITY 2 — Tauri Configuration Cleanup

**Carried from Sprint 8. Only proceed after P1 passes.**

### The problem

`apps/shield/desktop/tauri.conf.json` uses Tauri v1 format
(`devPath`, `distDir`, `package`, `tauri` keys). This caused the
Sprint 7.5 P1 confusion where `cargo tauri build` from the workspace
root picked up the wrong config.

`apps/strata-desktop/src-tauri/tauri.conf.json` still shows version
`1.5.0` after P4 unified Cargo.tomls at `0.16.0`.

### Fix

**Step 1 — Audit all tauri.conf.json files**

```bash
find . -name "tauri.conf.json" | grep -v target
```

List every config. For each: Tauri v1 or v2? Active app or legacy?

**Step 2 — Resolve the shield app**

Determine: is `apps/shield/` still in active development?

- If legacy: add `LEGACY.md` to `apps/shield/` explaining it should
  not be built, and add `apps/shield/` to `.cargo/config.toml`
  exclude list so it never gets picked up by workspace builds
- If active: convert `tauri.conf.json` to Tauri v2 format

Document the decision in the commit message.

**Step 3 — Fix version string**

Update `apps/strata-desktop/src-tauri/tauri.conf.json` version
from `1.5.0` to `0.16.0`.

**Step 4 — Verify**

```bash
cd apps/strata-desktop
cargo tauri build 2>&1 | grep -E "error|warning|Finished|Bundling"
```

Must build without config validation warnings.

### Acceptance criteria — P2

- [ ] Shield app config resolved (legacy marked or converted)
- [ ] tauri.conf.json version matches workspace (0.16.0)
- [ ] `cargo tauri build` from apps/strata-desktop is clean
- [ ] No remaining "wrong config" risk

---

## PRIORITY 3 — ShimCache / AppCompatCache Parser

**Only proceed after P1 and P2 pass.**

### What it is

ShimCache (AppCompatCache) is a Windows registry artifact that records
program execution history. It is one of the highest-value artifacts
for establishing what ran on a system and when.

Registry location:
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
Value: `AppCompatCache` (binary)

Windows 10/11 format: variable-length entries containing file path,
last modified timestamp, and execution flag.

MITRE ATT&CK: T1059 (Command and Scripting Interpreter),
T1204 (User Execution) depending on path context.

### Implementation

**Step 1 — Find registry parsing infrastructure**

Before writing anything, check what registry parsing already exists
in the codebase. The Phantom plugin uses `nt-hive` for registry
access. Understand the existing pattern before duplicating it.

```bash
grep -rn "AppCompatCache\|ShimCache\|shimcache" \
    --include="*.rs" . | grep -v target
grep -rn "nt.hive\|ntregistry\|registry" \
    --include="*.rs" . | grep -v target | head -20
```

**Step 2 — Parse the AppCompatCache binary value**

Windows 10/11 AppCompatCache format:
- Header: 128 bytes (magic + entry count)
- Entries: variable length, each contains:
  - Path length: 2 bytes (LE u16)
  - Path: UTF-16LE string (path_length bytes)
  - Last modified time: 8 bytes (FILETIME — 100ns intervals since 1601-01-01)
  - Data size: 4 bytes
  - Data: variable

FILETIME to Unix timestamp:
```rust
fn filetime_to_unix(filetime: u64) -> i64 {
    // FILETIME epoch: Jan 1 1601
    // Unix epoch: Jan 1 1970
    // Difference: 11644473600 seconds
    // FILETIME is in 100-nanosecond intervals
    (filetime / 10_000_000) as i64 - 11_644_473_600
}
```

**Step 3 — Where to add the parser**

Two options:
- Add to `strata-plugin-phantom` (already does registry work)
- Create `strata-plugin-shimcache` as a focused new plugin

Check Phantom's current structure. If it already parses
AppCompatCache, document what it produces. If not, adding a
focused parser to Phantom is cleaner than a new plugin for
one artifact type.

**Step 4 — Output format**

Each ShimCache entry becomes a Strata artifact:
```rust
StrataArtifact {
    artifact_type: "shimcache_entry",
    value: file_path,          // the executable path
    timestamp: unix_timestamp, // last modified time
    mitre_technique: "T1059",  // or T1204 depending on path
    confidence: Confidence::High, // deterministic parse
    is_advisory: false,        // not ML-generated
    source_plugin: "Phantom",  // or "ShimCache"
    ..
}
```

**Step 5 — Tests**

```rust
#[test]
fn shimcache_parses_known_good_entry() {
    // Use hardcoded bytes from a known Windows 10 AppCompatCache entry
    // Verify: path, timestamp, no panic
}

#[test]
fn shimcache_handles_empty_hive_gracefully() {
    // Assert Ok(vec![]), not panic
}

#[test]
fn shimcache_filetime_conversion_is_correct() {
    // Known FILETIME value → expected Unix timestamp
    // Use a documented reference value
}

#[test]
fn shimcache_produces_mitre_mapping() {
    // Verify T1059 appears on a path containing known executable patterns
}
```

**Step 6 — Verify on Charlie**

Charlie is a Windows XP image. ShimCache format differs slightly
between XP and Win10. Handle gracefully — if the header magic
doesn't match Win10/11 format, log a warning and return empty
rather than producing garbage.

Expected on Charlie: some entries (XP has AppCompatCache too,
different format). Document what you find.

### Acceptance criteria — P3

- [ ] ShimCache entries parsed from Windows test images
- [ ] At least 1 ShimCache artifact on a Windows image
  (Charlie may produce 0 due to XP format difference — acceptable
  if Win10/11 format parses correctly on synthetic test data)
- [ ] FILETIME conversion correct (unit tested)
- [ ] MITRE T1059 mapping present
- [ ] is_advisory = false (deterministic parse)
- [ ] 4 new tests pass
- [ ] `cargo test --workspace` passes, count increases by 4+
- [ ] All 9 load-bearing tests still green
- [ ] Clippy clean

---

## PRIORITY 4 — Evidence Tree Recursion Fix

**Only proceed if P1-P3 complete. This is cosmetic — do not
sacrifice P3 for P4.**

### The problem

Evidence tree shows "Volume 0 (10223990784 bytes)" nesting 20+
levels deep. The lazy-load walker is following a circular reference
or returning the same node as its own child.

### Diagnose first

```bash
grep -n "get_tree_children\|tree_children\|children_loaded" \
    apps/strata-desktop/src-tauri/src/lib.rs | head -20
```

Find where `get_tree_children` builds its response. Check:
- What node ID does it receive for Volume 0?
- What children does it return for that node?
- Are any returned children identical to the parent?
- Is there a cycle detection guard?

Fix only after diagnosis. Add a depth limit (max 50 levels) as
a safety guard regardless of the root cause fix.

### Acceptance criteria — P4

- [ ] Evidence tree for Charlie shows correct hierarchy
- [ ] MacBookPro folder shows correct tree without recursion
- [ ] Depth limit guard in place as safety net
- [ ] All 9 load-bearing tests still green

---

## What this sprint does NOT touch

- VERIFY (separate repo — Sprint 2 is next for VERIFY)
- `.rar` archives (RAR5 pure-Rust support incomplete)
- `.mem`/`.dmp` memory dumps (dedicated sprint)
- `.dmg` decompression (dedicated sprint)
- exFAT walker (dedicated sprint)
- NSRL hash set integration (blocked on dataset licensing)

---

## Session log format

```
## Sprint 10 — [date]

P1 Plugin sandboxing: PASSED / FAILED
  - MacBookPro all 23 plugins complete: yes/no
  - Artifact count after fix: [number vs 8,100 before]
  - plugin_error artifacts visible for Phantom: yes/no

P2 Tauri cleanup: PASSED / FAILED
  - Shield app: legacy marked / converted / active
  - Version string fixed: yes/no

P3 ShimCache: PASSED / FAILED / SKIPPED
  - Existing registry infrastructure: found / not found
  - Artifacts on Charlie: [count]
  - FILETIME conversion tested: yes/no

P4 Tree recursion: PASSED / SKIPPED

Final test count: [number]
Load-bearing tests: ALL GREEN
Clippy: CLEAN
```

---

## Commit format

```
fix: sprint-10-P1 plugin panic sandboxing — catch_unwind, 
     plugin_error artifact, all 23 plugins complete on macOS image
fix: sprint-10-P2 Tauri config cleanup — shield legacy marked,
     version unified at 0.16.0
feat: sprint-10-P3 ShimCache parser — AppCompatCache entries,
     FILETIME conversion, MITRE T1059, 4 tests
fix: sprint-10-P4 evidence tree recursion — depth guard,
     Volume 0 nesting resolved
```

---

_Sprint 10 authored by: Claude (architect) + KR (approved)_
_Execute with: claude-opus-4-7 in ~/Wolfmark/strata/_
_P1 is the most critical fix — a panicking plugin should never_
_stop the rest of the run. Fix this first._
