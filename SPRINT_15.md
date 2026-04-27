# Sprint 15 — Evidence Integrity + Hash Set Import + Artifact Notes
# FOR CODEX — Read AGENTS.md before starting

_Date: 2026-04-26_
_Agent: Codex (OpenAI)_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Before you start

1. Read AGENTS.md completely
2. Run `git pull`
3. Run `cargo test -p strata-shield-engine --test quality_gate` — confirm passing
4. Run `cargo test --workspace 2>&1 | tail -5` — confirm passing
5. Do not start until both pass

Current baseline: 3,965 tests passing, quality gate clean.

---

## Hard rules

- Zero new `.unwrap()` in production code
- Zero new `unsafe{}` without justification
- Zero new `println!` in library code
- Quality gate must pass after every priority
- All 9 load-bearing tests must always pass
- `cargo clippy --workspace -- -D warnings` clean
- `npm run build --prefix apps/strata-ui` clean

---

## PRIORITY 1 — Evidence Integrity Verification

### Context

When an examiner opens evidence, Strata should verify that the
evidence file hasn't changed since it was acquired. This is
fundamental chain of custody — the hash at acquisition must match
the hash at analysis time.

### Implementation

**Step 1 — Hash the evidence on load**

In `crates/strata-engine-adapter/src/evidence.rs`, when
`load_evidence` is called:

1. Compute SHA-256 of the evidence file (or folder manifest hash
   for directory ingestion)
2. Store the hash in the evidence store alongside the evidence
3. Record in the custody log: `evidence_hash_verified` with the
   hash value

```rust
pub struct EvidenceIntegrity {
    pub sha256: String,
    pub computed_at: i64,       // Unix timestamp
    pub file_size_bytes: u64,
    pub verified: bool,
}
```

**Step 2 — Display in the UI**

In the evidence detail panel (when evidence root is selected in
the tree), show:

```
EVIDENCE INTEGRITY
SHA-256: a3f4b2c1...d8e9f0a1  ✓ Verified at load time
Size:    9.5 GB
Computed: 2026-04-26 08:15:32 UTC
```

**Step 3 — Re-verify command**

Add a "Re-verify Integrity" button in the evidence detail panel.
On click, recomputes the hash and compares to the stored value.
If mismatch → show a prominent warning: "⚠ EVIDENCE INTEGRITY
FAILURE — Hash mismatch. Evidence may have been modified."

**Step 4 — IPC command**

```rust
#[tauri::command]
async fn get_evidence_integrity(
    evidence_id: String,
) -> Result<EvidenceIntegrity, String>

#[tauri::command]
async fn verify_evidence_integrity(
    evidence_id: String,
) -> Result<EvidenceIntegrity, String>
```

**Step 5 — Include in report**

When a report is generated, include the evidence hash and
verification status in the report header.

### Tests

```rust
#[test]
fn integrity_sha256_computed_on_load() {
    // Load synthetic evidence, verify hash is non-empty
}

#[test]
fn integrity_mismatch_detected() {
    // Compute hash, modify the stored value, re-verify
    // Verify mismatch is detected and reported
}

#[test]
fn integrity_included_in_custody_log() {
    // Load evidence, check custody log contains hash entry
}
```

### Acceptance criteria — P1

- [ ] SHA-256 computed on evidence load
- [ ] Hash stored in evidence store
- [ ] Custody log includes hash verification entry
- [ ] UI shows hash in evidence detail panel
- [ ] Re-verify button detects tampering
- [ ] Hash included in generated reports
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 2 — NSRL Hash Set Import

### Context

The National Software Reference Library (NSRL) maintains a database
of known software hashes. Forensic examiners import NSRL hash sets
to quickly identify and de-prioritize known-good files, focusing
attention on unknown and potentially malicious files.

This is a standard feature in AXIOM, FTK, and Autopsy.

### Implementation

**Step 2 — Hash set data structure**

```rust
pub struct HashSet {
    pub name: String,           // "NSRL", "Custom", etc
    pub description: String,
    pub hash_count: usize,
    pub imported_at: i64,
    pub hashes: std::collections::HashSet<String>, // SHA-256 hashes
}
```

Store in `HASH_SET_STORE: Lazy<Mutex<Vec<HashSet>>>`.

**Step 2 — Import command**

```rust
#[tauri::command]
async fn import_hash_set(
    name: String,
    file_path: String,          // path to NSRL .txt or .csv file
) -> Result<usize, String>      // returns count of hashes imported
```

NSRL format (NSRLFile.txt):
```
"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
"0000...","abc...","12345678","notepad.exe","12345","1","WIN","N"
```

Also accept a simple format: one hash per line (SHA-256).

**Step 3 — Apply to evidence**

After hash sets are imported, when `hash_all` runs on evidence:
1. Compare each file's SHA-256 against the NSRL hash set
2. If match found: mark file as `known_good: true`
3. Surface in the file explorer as a muted/grayed entry
4. The FILES counter shows: "10,183 files (8,421 known-good, 1,762 unknown)"

**Step 4 — Frontend**

Add "Hash Sets" section to Settings or a dedicated tab in the
evidence panel. Show imported hash sets, their sizes, and a
button to import new ones.

Add a filter toggle in the file explorer: "Show known-good files" /
"Hide known-good files" — default: show all.

**Step 5 — IPC commands**

```rust
#[tauri::command]
async fn import_hash_set(name: String, file_path: String) 
    -> Result<usize, String>

#[tauri::command]
async fn list_hash_sets() -> Result<Vec<HashSetInfo>, String>

#[tauri::command]
async fn delete_hash_set(name: String) -> Result<(), String>

#[tauri::command]
async fn get_hash_set_stats(evidence_id: String) 
    -> Result<HashSetStats, String>
```

### Tests

```rust
#[test]
fn hash_set_import_single_line_format() {
    // Import 3 SHA-256 hashes, one per line
    // Verify count == 3
}

#[test]
fn hash_set_lookup_finds_known_good() {
    // Import hash set containing a known hash
    // Create artifact with that hash
    // Verify artifact marked known_good
}

#[test]
fn hash_set_stats_accurate_after_hash_all() {
    // Import hash set, run hash_all on synthetic evidence
    // Verify known_good count matches expected
}
```

### Acceptance criteria — P2

- [ ] Hash set import from one-hash-per-line format works
- [ ] NSRL NSRLFile.txt format parsed (SHA-1 and MD5 columns)
- [ ] Files matched against hash sets during Hash All
- [ ] Known-good files visually distinguished in file explorer
- [ ] FILES counter shows known-good breakdown
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 3 — Artifact Notes

### Context

Examiners need to annotate artifacts with their own observations
during analysis. "This file was accessed 10 minutes before the
incident." "This LNK target matches the suspect's known malware."

Notes are examiner-specific observations attached to artifacts,
persisted across sessions, and included in reports.

### Implementation

**Step 1 — Note data structure**

```rust
pub struct ArtifactNote {
    pub artifact_id: String,    // unique identifier for the artifact
    pub evidence_id: String,
    pub note: String,
    pub created_at: i64,
    pub examiner: String,       // from ExaminerProfile
    pub flagged: bool,          // examiner flagged this artifact
}
```

Persist to `<app_data_dir>/artifact_notes.json`. Load on startup.

**Step 2 — IPC commands**

```rust
#[tauri::command]
async fn save_artifact_note(
    app: tauri::AppHandle,
    artifact_id: String,
    evidence_id: String,
    note: String,
    flagged: bool,
) -> Result<(), String>

#[tauri::command]
async fn get_artifact_note(
    app: tauri::AppHandle,
    artifact_id: String,
) -> Result<Option<ArtifactNote>, String>

#[tauri::command]
async fn get_flagged_artifacts(
    app: tauri::AppHandle,
    evidence_id: String,
) -> Result<Vec<ArtifactNote>, String>
```

**Step 3 — Frontend**

In the artifact detail panel (right side), below the artifact
metadata, add:

```
─── EXAMINER NOTES ─────────────────────────
[ Flag this artifact ]
                                              
_____________________________________________
|                                           |
|  Type your observations here...           |
|___________________________________________|
                              [ Save Note ]
```

Add a "Flagged" filter in the artifact list — when active, shows
only flagged artifacts across all categories.

**Step 4 — Include in report**

When generating a report, include a "Flagged Artifacts" section
listing all flagged artifacts with their notes.

**Step 5 — Artifact ID**

Generate a deterministic artifact ID from
`sha256(source_path + artifact_type + value)` so the same artifact
always gets the same ID across sessions.

### Tests

```rust
#[test]
fn artifact_note_persists_across_sessions() {
    // Save note, reload from disk, verify content matches
}

#[test]
fn flagged_artifacts_queryable_by_evidence() {
    // Flag 3 artifacts across 2 evidence IDs
    // Query by evidence ID, verify correct count
}

#[test]
fn artifact_id_is_deterministic() {
    // Same inputs → same ID every time
}
```

### Acceptance criteria — P3

- [ ] Notes persist across app restarts
- [ ] Flag/unflag toggle works
- [ ] Flagged filter in artifact list works
- [ ] Notes appear in generated reports
- [ ] Deterministic artifact IDs
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## After all priorities complete

```bash
cargo test --workspace 2>&1 | grep "test result" | head -5
cargo test -p strata-shield-engine --test quality_gate 2>&1 | tail -3
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | head -5
npm run build --prefix apps/strata-ui 2>&1 | tail -3
```

Commit only Sprint 15 files:

```bash
git add <only the files you modified for this sprint>
git commit -m "feat: sprint-15 evidence integrity + NSRL hash sets + artifact notes"
```

Do NOT use `git add -A` — stage only the files you touched.

Report:
- Which priorities passed
- Test count before (3,965) and after
- Any deviations from spec

---

_Sprint 15 for Codex — read AGENTS.md first_
_KR approval: granted_
