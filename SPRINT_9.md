# Sprint 9 — Format Support: Unlock What the Backend Already Does

_Date: 2026-04-25_
_Model: claude-opus-4-7_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Context

Live testing with the 2026 Hexordia CTF images revealed that Strata's
file picker blocks examiners from opening evidence the backend already
supports. Folders, AFF, ISO, QCOW2, UFDR, Cellebrite exports, and
more are all wired in the engine but invisible in the GUI.

Opus diagnosis (2026-04-25) confirmed the exact locations and scope.
This sprint unlocks what already works and adds the two medium-cost
formats (zip/tar) that cover the most real casework.

---

## Hard rules (always)

- Zero NEW `.unwrap()` in production code paths
- Zero NEW `unsafe{}` without explicit justification
- Zero NEW `println!` in production — use `log::` macros
- All errors handled explicitly
- All 9 load-bearing tests must pass after every change
- `cargo test --workspace` must pass
- `cargo clippy --workspace -- -D warnings` must be clean
- No new TODO/FIXME in committed code

---

## PRIORITY 1 — Folder Ingestion (highest leverage, zero backend work)

### The problem

`open_evidence_dialog` calls `pick_file` which cannot select folders
by design. The `ContainerType::Directory` → `FsVfs` path is fully
wired in the engine. Examiners cannot use it because the GUI never
lets them select a folder.

This blocks ALL logical image extractions:
- iOS full filesystem dumps (iPhone14Plus, etc.)
- Android logical extractions
- macOS logical extractions (MacBookPro CTF image)
- Cellebrite UFED folder exports
- GrayKey exports
- Any folder-based evidence

### Fix

**Step 1 — Add `open_folder_dialog` Tauri command**

In `apps/strata-desktop/src-tauri/src/lib.rs`, add alongside
`open_evidence_dialog`:

```rust
#[tauri::command]
async fn open_folder_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog()
        .file()
        .set_title("Open Evidence Folder")
        .pick_folder(move |path| {
            tx.send(path).unwrap();
        });
    match rx.recv() {
        Ok(Some(path)) => Ok(Some(path.to_string_lossy().into_owned())),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("Dialog error: {e}")),
    }
}
```

Register it in the `invoke_handler`.

**Step 2 — Add "Open Folder" button to the frontend**

In `apps/strata-ui/src/components/TopBar.tsx` (or wherever
`+ Open Evidence` lives), add a second button:

```
[+ Open Evidence]  [+ Open Folder]
```

Or combine into a dropdown:
```
[+ Open Evidence ▾]
  → Open Image File...
  → Open Folder...
```

The dropdown approach is cleaner UX — one entry point, two modes.
Your call on which to implement, but document the decision.

**Step 3 — Wire the folder path through `load_evidence`**

`load_evidence` already handles directory paths via
`ContainerType::Directory` → `FsVfs`. No backend changes needed.
The folder path from `open_folder_dialog` passes directly to
`load_evidence` identically to a file path.

**Step 4 — Test**

Load the MacBookPro CTF extracted folder through the GUI.
Confirm FILES and ARTIFACTS populate correctly.

### Acceptance criteria — P1

- [ ] `open_folder_dialog` Tauri command implemented and registered
- [ ] Frontend has folder selection entry point (button or dropdown)
- [ ] MacBookPro CTF folder loads and shows artifact count in GUI
- [ ] iPhone14Plus folder loads and shows artifact count in GUI
- [ ] No new `.unwrap()`, clippy clean
- [ ] All 9 load-bearing tests still green

---

## PRIORITY 2 — Fix the Picker Filter (picker-only, zero backend work)

### The problem

The current picker filter shows only 8 extensions. The backend
supports 20+. Examiners think Strata can't open formats it actually
handles fine.

Current whitelist: `E01, e01, dd, img, raw, vmdk, vhd, vhdx`

Missing from picker (backend already works):
- `aff`, `aff4` — AFF/AFF4 forensic images
- `s01`, `lx01`, `lx02` — EnCase logical formats
- `iso` — ISO disc images
- `qcow2` — QEMU disk images
- `ufdr`, `ufd`, `ufdx` — Cellebrite UFED exports
- `001`, `r01`, `aa` through `az` — split raw sequences
- `EX01`, `DD`, `IMG`, `RAW` — uppercase variants (macOS case-sensitive)

### Fix

In `apps/strata-desktop/src-tauri/src/lib.rs:954`, replace the
filter array with the complete list:

```rust
.add_filter(
    "Evidence Images",
    &[
        // E01 / EnCase
        "E01", "e01", "EX01", "ex01",
        // EnCase logical
        "L01", "l01", "Lx01", "lx01", "Lx02", "lx02",
        // AFF / AFF4
        "aff", "AFF", "aff4", "AFF4",
        // Raw disk images
        "dd", "DD", "img", "IMG", "raw", "RAW",
        // Split raw sequences
        "001", "r01", "R01", "aa",
        // VM disk formats
        "vmdk", "VMDK", "vhd", "VHD", "vhdx", "VHDX",
        // ISO
        "iso", "ISO",
        // QEMU
        "qcow2",
        // Cellebrite UFED
        "ufdr", "ufd", "ufdx",
        // S01 (EnCase split)
        "s01", "S01",
    ],
)
```

Also fix the `println!` at `crates/strata-fs/src/container/mod.rs:154`:
```rust
// Change:
println!("DEBUG: EvidenceSource open: …")
// To:
log::debug!("EvidenceSource open: …")
```

This is a one-line fix that closes a standing CLAUDE.md ratchet
violation. Commit it with P2.

### Acceptance criteria — P2

- [ ] All backend-supported formats visible in the picker
- [ ] Uppercase variants included (macOS case sensitivity)
- [ ] `.dd`/`.img`/`.raw` tested to confirm they were already
  working or identify a remaining blocker
- [ ] `println!` in container/mod.rs replaced with `log::debug!`
- [ ] Clippy clean
- [ ] All 9 load-bearing tests still green

---

## PRIORITY 3 — ZIP/TAR Archive Ingestion (medium backend work)

### The problem

`.zip` and `.tar` archives are not routed in `IngestRegistry::detect`.
The 2026 CTF MacBookPro image is packaged as a zip. Without this,
examiners must manually extract archives before Strata can process
them — which is exactly what other forensic tools handle automatically.

### Approach

Reuse the `materialize_targets` pattern from Sprint 8 P1.

**For both ZIP and TAR:**
1. Detect the archive format by extension
2. Extract to a deterministic scratch path:
   `<system temp>/strata-ui/<evidence_id>/extracted/`
3. Open the extracted directory via `ContainerType::Directory` → `FsVfs`
4. The rest of the pipeline is identical to folder ingestion

**Step 1 — Add archive detection to IngestRegistry**

In `crates/strata-fs/src/container/ingest_registry.rs`:

```rust
// Add to ContainerType enum
ArchiveZip,
ArchiveTar,

// Add to detect() routing
"zip" | "ZIP" => ContainerType::ArchiveZip,
"tar" | "TAR" | "tgz" | "tar.gz" => ContainerType::ArchiveTar,
"gz" | "GZ" => ContainerType::ArchiveTar, // assume tar.gz
```

**Step 2 — Implement archive extraction**

Add `crates/strata-fs/src/container/archive.rs`:

```rust
use std::path::{Path, PathBuf};

/// Extract a ZIP archive to a scratch directory.
/// Returns the path to the extracted root directory.
pub fn extract_zip(
    archive_path: &Path,
    scratch_root: &Path,
) -> Result<PathBuf, VerifyError> {
    // Use zip crate (pure Rust, add to Cargo.toml)
    // Extract to scratch_root/extracted/
    // Return scratch_root/extracted/
}

/// Extract a TAR or TAR.GZ archive to a scratch directory.
pub fn extract_tar(
    archive_path: &Path,
    scratch_root: &Path,
) -> Result<PathBuf, VerifyError> {
    // Use tar crate (pure Rust, add to Cargo.toml)
    // Handle both .tar and .tar.gz (detect by reading first bytes)
    // Return scratch_root/extracted/
}
```

Dependencies to add to `crates/strata-fs/Cargo.toml`:
```toml
zip = "2"      # pure Rust, no system deps
tar = "0.4"    # pure Rust
flate2 = "1"   # for .tar.gz decompression (pure Rust)
```

**Step 3 — Wire into EvidenceSource::open**

When `ContainerType::ArchiveZip` or `ArchiveTar` is detected:
1. Compute scratch path from archive path hash
2. If not already extracted, call `extract_zip` / `extract_tar`
3. Open the extracted directory as `ContainerType::Directory`

**Step 4 — Add to picker filter**

Add `zip`, `ZIP`, `tar`, `TAR`, `tgz`, `gz` to the picker filter
from P2.

**Step 5 — Tests**

Minimum 3 tests:
- `zip_extraction_produces_walkable_directory`
- `tar_extraction_produces_walkable_directory`
- `encrypted_zip_returns_clear_error` (not silent failure)

### Acceptance criteria — P3

- [ ] `.zip` archives open and produce artifacts in GUI
- [ ] `.tar` and `.tar.gz` archives open and produce artifacts
- [ ] MacBookPro.zip from Hexordia CTF loads in Strata GUI
- [ ] Encrypted ZIP returns clear error, not panic or silent failure
- [ ] All 3 new tests pass
- [ ] `cargo test --workspace` passes, count increases by 3+
- [ ] All 9 load-bearing tests still green
- [ ] Clippy clean

---

## PRIORITY 4 — Evidence Tree Infinite Recursion Fix

**Only proceed if P1-P3 are complete.**

### The problem

Sprint 8 identified: evidence tree shows "Volume 0 (10223990784 bytes)"
nesting 20+ levels deep. This is a rendering bug — the lazy-load
tree walker is following a circular reference or re-requesting the
same node.

### Diagnose first

Before writing any fix:
1. Find `get_tree_children` in `lib.rs`
2. Identify what node ID it receives for the Volume 0 node
3. Determine if the same node ID is being re-requested in a loop
4. Check if the child nodes returned by the first call are identical
   to the parent node

Fix only after diagnosis. The tree recursion is cosmetic — it does
not affect artifact counts — but it's confusing for examiners and
needs to be closed.

### Acceptance criteria — P4

- [ ] Evidence tree for Charlie shows correct hierarchy without recursion
- [ ] MacBookPro folder shows correct tree structure
- [ ] No load-bearing tests broken
- [ ] Clippy clean

---

## What this sprint does NOT touch

- `.rar` archives (RAR5 support incomplete in pure-Rust crates)
- `.mem`/`.dmp` memory dumps (separate sprint — memory analysis)
- `.dmg` decompression (partial scaffold, needs dedicated sprint)
- ShimCache/AppCompatCache parser (deferred to Sprint 10)
- Tauri v1 config cleanup (deferred)
- VERIFY work (separate repo, separate sprint)

---

## Session log format

```
## Sprint 9 — [date]

P1 Folder ingestion: PASSED / FAILED
  - MacBookPro CTF folder loaded: yes/no
  - iPhone14Plus folder loaded: yes/no
  - Artifact count: [number]

P2 Picker filter: PASSED / FAILED
  - Extensions added: [count]
  - println! fixed: yes/no

P3 ZIP/TAR: PASSED / FAILED / SKIPPED
  - MacBookPro.zip loads: yes/no
  - Artifact count: [number]
  - Tests added: [count]

P4 Tree recursion: PASSED / SKIPPED

Final test count: [number]
Load-bearing tests: ALL GREEN
Clippy: CLEAN
```

---

## Commit format

```
feat: sprint-9-P1 folder ingestion — open_folder_dialog + frontend CTA
fix: sprint-9-P2 picker filter — all backend formats visible, println cleanup
feat: sprint-9-P3 zip/tar archive ingestion — extract-to-scratch pipeline
fix: sprint-9-P4 evidence tree recursion — Volume 0 infinite nesting resolved
```

---

_Sprint 9 authored by: Claude (architect) + KR (approved)_
_Execute with: claude-opus-4-7 in ~/Wolfmark/strata/_
_P1 is the most valuable fix in this sprint._
_A working folder picker unlocks all mobile/macOS/cloud casework._
