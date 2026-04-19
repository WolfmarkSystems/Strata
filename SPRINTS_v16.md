# SPRINTS_v16.md — STRATA FILESYSTEM WALKER COMPLETION PHASE 2
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md, FIELD_VALIDATION_v15_REPORT.md,
#         SESSION_STATE_v15_SESSION_E_COMPLETE.md,
#         docs/RESEARCH_v15_EXT4_VIEW.md,
#         docs/RESEARCH_v15_HFSPLUS_SHAPE.md,
#         docs/RESEARCH_v15_HFSPLUS_BTREE_SHAPE.md,
#         docs/RESEARCH_v15_FAT_SHAPE.md,
#         and SPRINTS_v16.md.
#         Execute the next session's sprints in order, then stop."
# Last updated: 2026-04-19
# Prerequisite: SPRINTS_v1.md through SPRINTS_v15.md complete
# Status: v0.15.0 tagged and pushed. Five v16 sessions queued.
#
# ═══════════════════════════════════════════════════════════════════════
# WHERE STRATA IS AT THE START OF v16
# ═══════════════════════════════════════════════════════════════════════
#
# v0.15.0 shipped (April 2026) — tagged and pushed. Four filesystems
# route live through the unified dispatcher: NTFS (v11), ext4
# (Session B), HFS+ (Session D), FAT12/16/32 (Session E). Two explicit
# deferrals from v15 queued for v16: exFAT follow-up walker and HFS+
# read_file extents reading.
#
# Final v15 state:
#   Tests: 3,684 → 3,771 (+87 across five sessions)
#   AST quality gate: baseline preserved (470 unwrap / 5 unsafe /
#     5 println — zero new violations across all five sessions)
#   Charlie/Jo regression guards: unchanged
#   All 9 load-bearing tests preserved
#   Four real parser bugs caught by real-tool-generated fixtures
#     (two HFS+, two FAT) that synth-only testing would have shipped
#     into production
#
# v16 closes the architectural filesystem build-out by shipping
# APFS single-volume and APFS multi-volume walkers, pays down two
# v15 deferrals (exFAT + HFS+ read_file extents), and wires the
# advisory analytics modules into the primary case ingestion pipeline
# (closing audit debt from the website/README rewrite cycle).
#
# ═══════════════════════════════════════════════════════════════════════
# THE v15 METHODOLOGY LESSONS — CARRY FORWARD EXPLICITLY
# ═══════════════════════════════════════════════════════════════════════
#
# Five sessions of v15 produced three durable methodology lessons
# that apply verbatim to v16:
#
# LESSON 1 — Compiler probes verify contracts, not implementations.
#   Session C taught this: read_catalog's signature said
#   Vec<HfsPlusCatalogEntry> but the body returned a placeholder.
#   Compiler probes (assert_send, assert_sync) verify types and
#   traits. They cannot verify that functions do what their names
#   say. Research docs that document existing iteration primitives
#   must inspect function bodies, not just signatures.
#
# LESSON 2 — Round-trip synth tests prove internal consistency, not
# spec conformance.
#   Sessions D and E both demonstrated this. Four parser bugs
#   caught across the two sessions (catalog fork offset, B-tree
#   header field offsets, BPB variant-overlap, NT case-preservation
#   flag byte). Every one survived synth-only tests because the
#   synth builder and parser were written against the same (buggy)
#   spec interpretation. The only way to catch spec-misreads is to
#   parse bytes produced by an independent, spec-conforming tool —
#   system mkfs, newfs_hfs, newfs_msdos, hdiutil, or committed
#   reference images.
#
# LESSON 3 — Research artifacts scale effort down, not up.
#   Every v15 research doc made the subsequent implementation
#   session smaller. Session 1's ext4 research collapsed speculative
#   wrapper code from 500 LOC to 10 LOC. Session C Phase 0 ruled out
#   the reopen-per-call architecture and confirmed the held-handle
#   approach. Session D's B-tree shape audit surfaced the stub
#   before Phase B could wrap it. Session E's FAT shape audit led
#   directly to the fixture that caught the BPB variant-overlap bug.
#
# APPLICATION TO v16:
#   APFS is structurally more complex than any v15 filesystem
#   (object-based not block-based, snapshots, multi-volume
#   containers, encryption). The research session is more important
#   here than in v15. The real-fixture discipline is more important
#   here than in v15. The risk of synth-test-lockstep bugs surviving
#   into production is higher here than in v15 because APFS has
#   more places for byte-offset errors to hide (object descriptors,
#   B-tree node layouts, fsroot records, extent records, snapshot
#   mappings). Commit hdiutil-generated fixtures and treat any
#   disagreement between synth tests and fixture tests as the synth
#   tests being wrong.
#
# ═══════════════════════════════════════════════════════════════════════
# v0.16 SCOPE — FIVE SESSIONS
# ═══════════════════════════════════════════════════════════════════════
#
# SESSION 1 — APFS research doc (no production code)
#   Mirrors v15 Session 1 pattern. Audit existing APFS code in tree.
#   Send/Sync probes on any existing APFS types. Document object-map
#   traversal architecture, snapshot strategy (current state first,
#   snapshot enumeration deferred beyond v16), encryption marking
#   behavior, fusion-drive out-of-scope explicit. Output:
#   docs/RESEARCH_v16_APFS_SHAPE.md. No dispatcher changes, no new
#   walkers, no new tests beyond probes.
#
# SESSION 2 — ML wiring standalone (no filesystem work)
#   Wire AnomalyEngine, ObstructionScorer, SummaryGenerator into
#   strata ingest run and apps/strata-desktop/. Restore Sigma Rules
#   30/31/32 to firing state. Update website "Advisory Analytics"
#   section (removed per Opus audit finding prior to v0.14.0
#   milestone). Update README similarly. Tripwire tests pin old
#   behavior. Entirely orthogonal to APFS work.
#
# SESSION 3 — Object map + container superblock parser + HFS+ read_file
#   The lowest APFS layer. Without working object-map resolution,
#   nothing above parses. ~400-600 LOC of new parser code extending
#   any existing APFS parser stubs. Mirrors Session D's HFS+ B-tree
#   iteration in shape. Folds in HFS+ read_file extents reading
#   (v15 Session D deferral) — ~80-120 LOC, architecturally aligned
#   with APFS extent record reading. Closes the read_file
#   Unsupported tripwire test.
#
# SESSION 4 — APFS-single walker + fixture + dispatcher arm + exFAT
#   On top of the working object map, B-tree iteration of the
#   volume's root filesystem tree. Native macOS fixture via
#   hdiutil create -fs APFS. APFS-single dispatcher arm flip.
#   Folds in exFAT walker (v15 Session E deferral) — ~200-300 LOC
#   extension to the Session E FAT12/16/32 parser, native macOS
#   fixture via newfs_exfat. Two dispatcher arm flips in one session.
#
# SESSION 5 — APFS-multi (CompositeVfs) + final dispatcher + v0.16 tag
#   Multi-volume container wrapping. CompositeVfs iterates each
#   volume in the container, exposing them through a unified VFS
#   interface with volume-scoped paths. APFS-multi dispatcher arm
#   flip. Fusion drives remain explicitly Unsupported. CLAUDE.md
#   update, FIELD_VALIDATION_v16_REPORT.md publication, v0.16
#   annotated tag push.
#
# ═══════════════════════════════════════════════════════════════════════
# TAG POLICY
# ═══════════════════════════════════════════════════════════════════════
#
# v0.16.0 ships ONLY at end of Session 5, and ONLY if ALL of the
# following shipped real (not deferred shallow):
#
#   - APFS-single walker live through dispatcher (Session 4)
#   - APFS-multi walker live through dispatcher (Session 5)
#   - Advisory analytics wired into strata ingest run (Session 2)
#   - HFS+ read_file extents reading shipped (Session 3)
#
# If any of the above failed to ship real, defer the tag to a
# successor session with explicit pickup signals in
# SESSION_STATE_v16_BLOCKER.md. The v15 pattern of holding the tag
# when deliverables aren't complete preserves the meaning of the
# tag for downstream consumers (examiners, defense attorneys,
# CI systems, release pipelines).
#
# exFAT can defer without blocking the tag. It's a v15 follow-up
# that's being folded in opportunistically, not a v16 commitment.
# Document the deferral in SESSION_STATE_v16_BLOCKER.md with a
# pickup signal and continue.
#
# ═══════════════════════════════════════════════════════════════════════
# DISCIPLINE — CARRIED FORWARD FROM v9 THROUGH v15
# ═══════════════════════════════════════════════════════════════════════
#
# "Do not silently compromise the spec." Five sessions of v15 and
# four prior v-cycles have proved this clause works.
#
# Ground truth validation is mandatory. Every walker ships with
# integration tests against either a real image or a committed test
# fixture before it can be declared shipped. "Tests pass" is not
# acceptance — acceptance is "walker enumerates expected files from
# a real or fixture image with verifiable counts matching the
# expected manifest."
#
# Quality gates (every session): all tests pass from session-start
# count, clippy clean, AST quality gate stays at v14 baseline (470
# unwrap, 5 unsafe, 5 println — zero new), all 9 load-bearing tests
# preserved, Charlie/Jo regression guards pass, all previously-
# shipped dispatcher arms (NTFS v11, ext4 Session B, HFS+ Session D,
# FAT Session E) continue routing live.
#
# The tripwire test convention. When shipping something that
# exposes a stub or known limitation, write a _still_X or _pending_Y
# test that pins the current behavior. Session E's HFS+ read_file
# tripwire gets intentionally tripped in Session 3 of v16.
#
# ---
#
# ## HOW TO EXECUTE — SESSION 1
#
# Read CLAUDE.md, FIELD_VALIDATION_v15_REPORT.md,
# SESSION_STATE_v15_SESSION_E_COMPLETE.md, the v15 research docs in
# docs/, and SPRINTS_v16.md in that order. Then execute the SESSION 1
# sprint below. Stop at end of SESSION 1.
#
# Session 1 is research-only. No production code. No dispatcher
# changes. No new walkers. Output is one research document plus any
# needed compiler probes (committed as test code under #[cfg(test)]).
#
# For the sprint:
# 1. Implement exactly as specified
# 2. Run cargo test --workspace — all tests must pass
# 3. Run cargo clippy --workspace -- -D warnings — must be clean
# 4. Run the AST quality gate — must stay at v14 baseline
# 5. Verify all four v15 dispatcher arms still route live (regression)
# 6. Verify Charlie/Jo regression guards still pass
# 7. Commit with message: "docs: [sprint-id] [description]"
# 8. Write SESSION_STATE_v16_SESSION_1_COMPLETE.md
# 9. Push to origin/main. Stop. SESSION 2 is a separate run.
#
# ---

# ═══════════════════════════════════════════════════════════════════════
# █████████████████████████████  SESSION 1  █████████████████████████████
# ═══════════════════════════════════════════════════════════════════════
# █  APFS research. No production code. Research doc + probes only.    █
# █  Stop at end of SESSION 1. Do not proceed into SESSION 2.          █
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# SESSION 1 — SPRINT 1 — FS-APFS-RESEARCH
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-APFS-RESEARCH
**Why first:** APFS is structurally the most complex filesystem v16
will handle. Lesson 3 from v15 applies with extra weight — a thorough
research doc will make the subsequent implementation sessions smaller.
The cost of skipping this session is discovering architectural
surprises mid-implementation in Session 3 or 4.

## Phase A — Audit existing APFS code in tree

Grep for existing APFS-related code:

```bash
grep -rn "apfs\|APFS\|ObjectMap\|ApfsContainer\|ApfsVolume" crates/strata-fs/src/
```

Expected findings based on project history: some partial parser code
likely exists (potentially in a file like `apfs.rs`), possibly
stubbed or boot-sector-only. Document every existing type, function,
and constant. Note which are stubs (empty bodies, placeholder returns,
`_data` unused params) versus working implementations. This is the
v15 Sprint 1 pattern applied to APFS — per Lesson 1, inspect function
bodies, not just signatures.

Specifically look for:

- Container superblock (NXSuperblock) parser
- Object map (OMap) B-tree
- Volume superblock (APSB) parser
- Filesystem tree (fs_tree) B-tree walker
- Extent record parsing
- Checkpoint/snapshot infrastructure
- Any encryption awareness

## Phase B — Send/Sync probes on existing APFS types

For every public struct found in Phase A, run the compiler probe
pattern from Session C:

```rust
#[cfg(test)]
mod _apfs_send_sync_probe {
    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn apfs_container_is_send() { assert_send::<ApfsContainer>(); }
    #[test]
    fn apfs_container_is_sync() { assert_sync::<ApfsContainer>(); }
    // ... for every APFS type
}
```

If any type is !Send or !Sync, document the offending field and
decide the architectural path (Path A held-handle or Path B reopen-
per-call) for Session 4's walker. The decision must be documented
in the research doc, not deferred to Session 4.

## Phase C — Document APFS architecture decisions

The research doc at docs/RESEARCH_v16_APFS_SHAPE.md must cover:

### 1. Existing parser surface (per Phase A)
Full inventory of every APFS-related public function, struct, and
constant. Mark each as stub / partial / working. Identify gaps that
Session 3 must fill.

### 2. Threading contract (per Phase B)
Send + Sync status of every existing APFS type. Walker architecture
decision (Path A vs Path B) with justification.

### 3. Object map traversal
APFS is object-based. Every object has an object ID (OID) and a
transaction ID (XID). The object map (OMap) resolves (OID, XID)
pairs to file offsets. Document the planned resolution API:

```rust
// Planned primitive for Session 3
fn resolve_object(&self, oid: ObjectId, xid: TransactionId)
    -> Result<FileOffset, ApfsError>;
```

Note the forensic implication: OID resolution at different XIDs
walks different historical filesystem states. Snapshots are literally
"here's the XID at which this snapshot was taken." This has real
evidentiary value — deleted files often survive in older XIDs.

### 4. Snapshot strategy for v16
v16 walker iterates the CURRENT state only (latest XID per volume).
Snapshot enumeration is deferred beyond v16. Document the tripwire
test that will pin this behavior in Session 4:

```rust
#[test]
fn apfs_walker_walks_current_state_only_pending_snapshot_enumeration() {
    // Confirms walk() returns entries from the latest XID.
    // When snapshot enumeration ships, this test must be
    // intentionally changed or deleted.
}
```

### 5. Multi-volume container strategy
A single APFS container holds one or more volumes. A Mac boot drive
typically has four: Macintosh HD (read-only system), Macintosh HD -
Data (user data), Preboot, Recovery. v16 ships:

- APFS-single walker: takes a volume index (0 or by name), walks
  that one volume. This is the v16 Session 4 deliverable.
- APFS-multi walker (CompositeVfs): iterates all volumes in the
  container, exposing them through a unified VFS interface with
  volume-scoped paths like /vol0:Macintosh HD/etc/passwd. This is
  the v16 Session 5 deliverable.

Document the CompositeVfs design: how paths are scoped, how read()
resolves volume index from path, how walk() interleaves entries
from multiple volumes.

### 6. Encryption awareness
APFS supports FileVault per-volume encryption with multiple key
classes. Walker must:

- Identify encrypted volumes via the volume superblock flags
- Expose encryption status via VfsEntry metadata (is_encrypted)
- NOT attempt decryption — that's a separate examination step with
  the key bundle
- NOT silently skip encrypted content — mark it clearly so
  examiners know to pursue offline key recovery

### 7. Fusion drives — OUT OF SCOPE
APFS on a fusion drive spans two physical devices with a logical
volume manager. Document as explicitly deferred beyond v16. Pickup
signal for a future sprint. Walker should return
VfsError::Unsupported("APFS fusion drives not yet supported") when
a fusion container is detected — not panic, not silently read only
the SSD portion.

### 8. Encryption keys, space manager, checkpoints — OUT OF SCOPE
Forensically interesting for deeper analysis but not required for
walk/read. Document as deferred. Walker should not pretend these
structures don't exist (e.g., don't skip past checkpoint descriptors
silently); it should simply not parse them.

### 9. Estimated LOC breakdown for v16 Sessions 3-5
Based on the Phase A audit and the architectural decisions above:

- Session 3 object map + superblock parser: ~X LOC new
- Session 3 HFS+ read_file extents reading: ~Y LOC new
- Session 4 APFS-single walker: ~Z LOC
- Session 4 exFAT walker: ~W LOC (extending Session E FAT parser)
- Session 5 APFS-multi CompositeVfs: ~V LOC

Rough estimates based on v15 similar work. The numbers inform
whether session boundaries are reasonable. If any estimate comes in
meaningfully higher than v15 equivalents, flag it in the research
doc and propose a revised session split.

## Acceptance criteria

- [ ] docs/RESEARCH_v16_APFS_SHAPE.md committed with all 9 sections
- [ ] Send/Sync probes committed as #[cfg(test)] under appropriate
      module, all passing (or failing with documented rationale)
- [ ] Every existing APFS type inventoried with stub/partial/working
      status
- [ ] Walker architecture decision (Path A or Path B) made and
      justified
- [ ] Snapshot strategy decided (current-state only for v16) with
      tripwire test design sketched
- [ ] Fusion-drive deferral documented
- [ ] LOC estimates for Sessions 3-5 provided
- [ ] Test count unchanged except for probe tests (if any)
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] All four v15 dispatcher arms still route live
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths. No new
production code — this is research only.

---

# ═══════════════════════════════════════════════════════════════════════
# END OF SESSION 1
# ═══════════════════════════════════════════════════════════════════════
#
# Write SESSION_STATE_v16_SESSION_1_COMPLETE.md documenting the
# research artifact, the probe results, and pickup signals for
# Session 2. Push to origin/main. Stop.
#
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# █████████████████████████████  SESSION 2  █████████████████████████████
# ═══════════════════════════════════════════════════════════════════════
# █  ML wiring standalone. No filesystem work. Closes audit debt       █
# █  from pre-v0.14 website/README rewrite cycle.                       █
# █  Stop at end of SESSION 2. Do not proceed into SESSION 3.          █
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# SESSION 2 — SPRINT 1 — ML-WIRE-1 — WIRE ADVISORY ANALYTICS
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** ML-WIRE-1
**Why standalone:** Opus's pre-v0.14 audit found that strata-ml-anomaly,
strata-ml-obstruction, and strata-ml-summary are real Rust crates with
real tests, but are called only by the legacy apps/tree/ viewer. They
are never invoked by strata ingest run or apps/strata-desktop/. This
means Sigma Rules 30/31/32 (which reference subcategory == "ML Anomaly"
records) never fire on real cases. The website "Advisory Analytics"
section was removed rather than shipped under a false claim.

This sprint wires the modules into the primary case ingestion pipeline.
Orthogonal to APFS. One session, one focused deliverable.

## Phase A — Audit the existing ML modules

Confirm the crates exist and their public APIs:

```bash
find crates/ -type d -name "strata-ml-*"
# Expected: strata-ml-anomaly, strata-ml-obstruction, strata-ml-summary
# Possibly: strata-ml-charges

for crate in crates/strata-ml-*; do
    echo "=== $crate ==="
    grep -n "pub fn\|pub struct" "$crate/src/lib.rs" 2>/dev/null
done
```

For each module, identify:
- The public entry function (typically analyze() or run() taking a
  case state)
- The input type (CaseState, ArtifactSet, or similar)
- The output type (list of advisory findings with severity scores)
- Whether the output goes to the Sigma correlation layer or directly
  to the report

## Phase B — Identify the pipeline insertion point

Find where strata ingest run orchestrates plugins:

```bash
grep -rn "run_all_plugins\|orchestrate\|pipeline" crates/strata-cli/
grep -rn "plugin_manager\|PluginManager" crates/strata-core/
```

The advisory analytics modules should run AFTER all plugins have
produced artifacts but BEFORE the Sigma correlation engine runs.
This ordering lets:
1. Plugins produce the raw artifacts
2. Analytics modules produce advisory scores and summaries
3. Sigma correlates both plugin artifacts and advisory findings
4. Reports include both in the final output

## Phase C — Wire the modules

Add a new pipeline stage (advisory_analysis or similar) to the
primary ingestion flow. The stage:

1. Receives the complete artifact set from the plugin stage
2. Invokes each ML module's public entry function
3. Collects the findings
4. Passes them along with the plugin artifacts to the Sigma stage
5. Logs advisory counts via log::info!

Same pattern for apps/strata-desktop/ — the desktop UI's case view
should display advisory findings in a dedicated panel alongside
plugin artifacts.

## Phase D — Restore Sigma Rules 30/31/32

These rules reference subcategory == "ML Anomaly" records. Once
the ML modules are wired, the records exist. Confirm the rules fire
on cases that should trigger them:

```bash
grep -n "ML Anomaly" crates/strata-sigma/rules/
# Confirm rules 30, 31, 32 still exist
```

Add a fixture-based integration test:

```rust
#[test]
fn sigma_rule_30_fires_when_ml_anomaly_detected() {
    // Construct a case state that produces an ML anomaly finding
    // Confirm Sigma rule 30 fires
}
```

## Phase E — Update website and README

Restore the "Advisory Analytics" section on the website index.html
and in the README under Features. Frame accurately — per the Opus
audit guidance, language like "deterministic statistics and templates
wired into the primary pipeline" rather than "AI-powered scoring"
which was the original overclaim.

Example README section:

```markdown
### Advisory Analytics
Strata includes deterministic advisory analytics modules that run
after plugin extraction and before Sigma correlation:

- Anomaly scoring across system event timelines
- Obstruction detection (anti-forensic tool usage, log tampering)
- Case summary generation for expert witness reports

Output is statistical and template-driven. No ML models, no LLM
calls, no external API dependencies. Findings feed into Sigma
rules 30/31/32 for cross-artifact correlation.
```

Website index.html gets equivalent copy in the features section.

## Phase F — Tripwire test for the old dead-rule behavior

Per v15 tripwire convention, pin the NEW behavior:

```rust
#[test]
fn advisory_analytics_invoked_by_ingest_run() {
    // Run the full ingest pipeline on a synthetic case state.
    // Confirm all three (or four) ML modules were invoked.
    // Confirm advisory records are present in the case output.
    // Confirm Sigma rules 30/31/32 had the opportunity to evaluate
    // against those records.
}
```

Document in the commit message that this test replaces the pre-v16
implicit behavior (ML modules called only from legacy apps/tree/
viewer).

## Acceptance criteria

- [ ] Advisory analytics modules invoked by strata ingest run
- [ ] Advisory analytics modules invoked by apps/strata-desktop/
- [ ] Sigma rules 30/31/32 fire on cases producing advisory findings
- [ ] Integration test confirms end-to-end pipeline flow
- [ ] Website index.html "Advisory Analytics" section restored
- [ ] README "Advisory Analytics" section restored
- [ ] Framing is accurate (deterministic statistics / templates,
      not "AI-powered")
- [ ] Test count grows by at least 3 (pipeline wiring + per-module
      invocation + Sigma rule firing)
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] All four v15 dispatcher arms still route live
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# END OF SESSION 2
# ═══════════════════════════════════════════════════════════════════════
#
# Write SESSION_STATE_v16_SESSION_2_COMPLETE.md documenting the
# ML wiring, test additions, and website/README updates. Push to
# origin/main. Stop. Session 3 is a separate run.
#
# Audit debt closed. Website and README now accurately reflect
# advisory analytics as wired into production. Advisory findings
# appear in case reports. Sigma rules 30/31/32 are live.
#
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# █████████████████████████████  SESSION 3  █████████████████████████████
# ═══════════════════════════════════════════════════════════════════════
# █  APFS object map + container superblock parser.                    █
# █  HFS+ read_file extents reading (folds in v15 Session D deferral). █
# █  Stop at end of SESSION 3. Do not proceed into SESSION 4.          █
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# SESSION 3 — SPRINT 1 — FS-APFS-OBJMAP — OBJECT MAP + SUPERBLOCK
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-APFS-OBJMAP
**Prerequisite:** Session 1 research doc docs/RESEARCH_v16_APFS_SHAPE.md
**Why first in Session 3:** Every APFS structure above the container
superblock is reached through the object map. Without working OID
resolution, volume superblocks can't be parsed, filesystem trees
can't be walked, nothing above this layer works.

## Phase A — Container superblock parser

APFS container superblock (NXSuperblock) is at a known offset
(typically byte 0 of the container). Parse:

- Magic (should be 'NXSB')
- Block size
- Block count
- Feature flags (especially encryption, fusion drive — fusion
  detected here triggers the Unsupported return per research doc)
- Checkpoint descriptor area location
- Next transaction ID (next_xid)
- Current object map OID

Endianness is little-endian on disk (unlike HFS+ which is big-endian).
Every multi-byte read must respect that.

## Phase B — Checkpoint descriptor

The checkpoint descriptor area is a ring buffer of checkpoint
metadata. Each checkpoint descriptor points to:
- A checkpoint mapping (object ID → file offset for that checkpoint)
- A filesystem superblock for each volume at that checkpoint

For v16 Session 3 scope, find the LATEST checkpoint descriptor
(highest XID) and use it. Historical checkpoint walking is deferred
beyond v16. Document the tripwire:

```rust
#[test]
fn apfs_uses_latest_checkpoint_only_pending_historical_walk() {
    // Confirms the parser uses the latest checkpoint.
    // When historical checkpoint walking ships, this test must be
    // intentionally changed or deleted.
}
```

## Phase C — Object map B-tree walker

Object map (OMap) is a B-tree. Each leaf record is
(OID, XID) → (physical_block_number, flags). The walker needs:

1. Node descriptor parsing (similar to HFS+ B-tree nodes — type,
   level, record count, record offsets)
2. Record offset table walking (variable-length records)
3. Key comparison for (OID, XID) lookup
4. Physical block resolution → file offset conversion

Critical correctness considerations from v15 Lessons 1 and 2:

- Node type discrimination: OMap nodes are B-tree nodes. Walker
  iterates keys and resolves values. Internal nodes forward to
  children.
- Variable-length records with key + value split: APFS records
  have a key size and value size in the record metadata. Parser
  must respect the split.
- Little-endian byte order on every multi-byte read (unlike HFS+
  big-endian — the contrast is easy to mix up, test against real
  fixtures to catch this).
- Transaction ID semantics: lookups at XID N return the record
  with the highest XID ≤ N. v16 uses the container's next_xid - 1.

## Phase D — Object resolution primitive

The public entry for Session 4's walker:

```rust
pub fn resolve_object(
    &self,
    oid: ObjectId,
    xid: TransactionId,
) -> Result<FileOffset, ApfsError> {
    // Walks the object map, finds the record for (oid, xid) or
    // the latest XID ≤ xid, returns the resolved file offset.
}
```

This is the lowest-level primitive. Walker uses it to resolve
volume superblock OIDs, filesystem tree root OIDs, extent record
OIDs, and so on.

## Acceptance criteria

- [ ] NXSuperblock parser reads container superblock correctly
- [ ] Fusion drive detection returns Unsupported per research doc
- [ ] Checkpoint descriptor area parsed, latest checkpoint selected
- [ ] Object map B-tree walker resolves (OID, XID) → file offset
- [ ] Little-endian byte order respected on all multi-byte reads
- [ ] Tripwire test apfs_uses_latest_checkpoint_only_pending_
      historical_walk committed
- [ ] Test count grows by at least 5 (superblock + checkpoint +
      object map resolution + tripwire + edge case)
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] All four v15 dispatcher arms still route live
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# SESSION 3 — SPRINT 2 — FS-HFSPLUS-READFILE — PAY DOWN v15 DEFERRAL
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-HFSPLUS-READFILE
**Pickup signal from v15 Session D:** "read_file pinned as Unsupported
tripwire for future Phase B Part 3." That future is now.

**Why in Session 3:** HFS+ data fork extent reading is architecturally
the same pattern as APFS extent record reading. Both walk extent
records to assemble file content. Doing them in the same session
keeps the methodology focused on extent-reading primitives.

## Phase A — Audit existing HfsPlusWalker::read_file

From Session D, HfsPlusWalker::read_file returns VfsError::Unsupported
with a tripwire test pinning that behavior. Audit:

- The existing HfsPlusCatalogEntry: does it surface the file's extent
  records (data fork start blocks + block counts)?
- The existing HfsPlusExtentDescriptor: is it complete, or was it
  stubbed like read_catalog was?

If HfsPlusExtentDescriptor parsing is incomplete, extend it as part
of this sprint (similar to Session D extending read_catalog itself).

## Phase B — Implement data fork extent reading

HFS+ data fork extents are a list of (start_block, block_count) pairs.
The first 8 extent descriptors are inline in the catalog record
(HfsPlusCatalogFile). If the file is larger, the extents overflow
file (a separate B-tree) contains the rest.

Implementation:

1. Read the inline extent descriptors from the catalog record
2. If the file size exceeds what inline extents cover, walk the
   extents overflow file for additional descriptors
3. For each extent descriptor, compute (block_offset * block_size)
   as the file offset and (block_count * block_size) as the length
4. Read each extent's content via self.inner.read_block chained into
   a Vec<u8> of the requested slice

Handle edge cases:
- Sparse files (holes): extent with block_count > 0 but pointing to
  block 0 or similar sentinel — fill with zeros
- File smaller than inline extent coverage: respect file_size, don't
  read past it
- Resource forks: same structure, different catalog record field

## Phase C — Update the tripwire test

The Session D tripwire test `hfsplus_read_file_still_unsupported`
(or similarly named) pinned the Unsupported behavior. Sprint 2
intentionally trips it. Either:

- Delete it with commit message noting "limitation removed in
  [commit hash]"
- Replace with positive test
  `hfsplus_read_file_returns_fork_content_for_minimal_file`

Both approaches acceptable. Make the change intentional.

## Phase D — Integration test against Session D fixture

The Session D hfsplus_small.img fixture has a file large enough to
exercise B-tree extent overflow. Add:

```rust
#[test]
fn hfsplus_walker_reads_big_file_from_fixture() {
    let fixture = "crates/strata-fs/tests/fixtures/hfsplus_small.img";
    if !Path::new(fixture).exists() { return; }

    let walker = HfsPlusWalker::open_on_partition(...)?;
    let content = walker.read_file("/big_file.bin")?;
    assert_eq!(content.len(), 8192);
    // If Session D fixture writes a specific byte pattern, verify it
}
```

## Acceptance criteria

- [ ] HfsPlusWalker::read_file returns real file content via extent
      walking
- [ ] Inline extent descriptors (first 8) handled correctly
- [ ] Extents overflow file walked when file exceeds inline coverage
- [ ] Sparse files handled (zeros for holes)
- [ ] Resource fork reading implemented
- [ ] Session D tripwire test intentionally tripped (deleted or
      replaced positive)
- [ ] hfsplus_walker_reads_big_file_from_fixture passes
- [ ] Test count grows by at least 4
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] HFS+ dispatcher arm still routes live
- [ ] All other v15 dispatcher arms still route live
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# END OF SESSION 3
# ═══════════════════════════════════════════════════════════════════════
#
# Write SESSION_STATE_v16_SESSION_3_COMPLETE.md documenting the
# object map parser, HFS+ read_file implementation, and pickup
# signals for Session 4 (APFS-single walker now unblocked, exFAT
# is Session 4 walker-theme work). Push to origin/main. Stop.
#
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# █████████████████████████████  SESSION 4  █████████████████████████████
# ═══════════════════════════════════════════════════════════════════════
# █  APFS-single walker + fixture + dispatcher arm.                    █
# █  exFAT walker (folds in v15 Session E deferral) + dispatcher arm.  █
# █  Stop at end of SESSION 4. Do not proceed into SESSION 5.          █
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# SESSION 4 — SPRINT 1 — FS-APFS-SINGLE-WALKER
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-APFS-SINGLE-WALKER
**Prerequisite:** Session 3 object map parser shipped
**Why first in Session 4:** Walker wrap depends on the object map
resolution primitive. exFAT (Sprint 3) is architecturally
independent and can ship later in the session.

## Phase A — Implement ApfsSingleWalker

Use the architectural path decided in Session 1 research doc (Path A
held-handle if APFS types are Send + Sync; Path B reopen-per-call if
not). Session 4 follows Session D's HfsPlusWalker pattern if Path A,
Session B's Ext4Walker pattern if Path B.

```rust
pub struct ApfsSingleWalker {
    // Fields determined by research doc architectural decision
    container: Arc<ApfsContainer>,
    volume_index: usize,
    // ...
}

impl ApfsSingleWalker {
    pub fn open<R: Read + Seek + Send + 'static>(
        reader: R,
        volume_index: usize,
    ) -> Result<Self, VfsError> {
        // Parse container superblock (Session 3 primitive)
        // Resolve volume N superblock OID
        // Parse volume superblock
        // Resolve fs_tree root OID
        // Store handles for walk/read
    }
}

impl Vfs for ApfsSingleWalker {
    fn walk(&mut self) -> Box<dyn Iterator<Item = VfsEntry> + Send + '_> {
        // Walk the fs_tree B-tree, yielding VfsEntry per inode record
    }

    fn read(&mut self, path: &Path) -> Result<Vec<u8>, VfsError> {
        // Resolve path → inode via fs_tree walk
        // Read extent records for that inode
        // Assemble content via resolved file offsets
    }
}
```

## Phase B — fs_tree B-tree walker

Each volume has a filesystem tree (fs_tree) B-tree. Leaf records
include inode records, directory records, extent records, xattr
records. Walker iterates inode records for enumeration. Directory
records resolve path components. Extent records assemble file content.

Critical correctness considerations (v15 Lesson 2 applies with force):

- Inode record structure: mode, UID, GID, timestamps, parent ID,
  name. Named records connect back through parent ID chain to
  root (which has a well-known object ID).
- Directory record packing: name → inode ID in directory records.
- Extent record structure: (inode_id, logical_offset) → (physical
  offset, length, flags). Encryption flag surfaces here.
- Little-endian on every multi-byte read.
- Encryption marking: if an extent record's flags indicate
  encryption, the VfsEntry exposes is_encrypted = true. Walker
  does not attempt decryption.

## Phase C — Encryption handling

Per research doc section 6:
- Walker identifies encrypted volumes via volume superblock flags
- Walker exposes VfsEntry metadata (is_encrypted) accurately
- Walker does NOT attempt decryption
- Walker does NOT silently skip encrypted content — examiners must
  see that encryption is present so they can pursue offline key
  recovery

## Phase D — Snapshot tripwire

Per research doc section 4 and Session 1 tripwire sketch:

```rust
#[test]
fn apfs_walker_walks_current_state_only_pending_snapshot_enumeration() {
    // Confirms walk() returns entries from the latest XID only.
    // If snapshot enumeration ships, intentionally change this test.
}
```

## Acceptance criteria

- [ ] ApfsSingleWalker::open succeeds on a single-volume container
- [ ] walk() yields VfsEntry items per fs_tree inode records
- [ ] read() returns file content via extent record resolution
- [ ] Encryption correctly marked on is_encrypted VfsEntry metadata
- [ ] Snapshot tripwire test committed
- [ ] Fusion drive Unsupported return fires on fusion containers
- [ ] Test count grows by at least 6
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] All four v15 dispatcher arms still route live
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# SESSION 4 — SPRINT 2 — FS-APFS-SINGLE-FIXTURE
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-APFS-SINGLE-FIXTURE

## Phase A — Generate APFS fixture on macOS

```bash
# crates/strata-fs/tests/fixtures/mkapfs.sh

#!/bin/bash
set -euo pipefail

OUT="apfs_single.img"
MNT="/tmp/apfs_mount_$$"

hdiutil create -size 10m -fs APFS -volname "STRATA-APFS" -type SPARSE "$OUT.tmp"
hdiutil attach "$OUT.tmp.sparseimage" -mountpoint "$MNT"

# Populate with reproducible content
echo "readme content" > "$MNT/readme.txt"
mkdir -p "$MNT/dir1/dir2/dir3"
echo "deep file" > "$MNT/dir1/dir2/dir3/deep.txt"
# File large enough to exercise multiple extents
dd if=/dev/zero of="$MNT/multi_extent.bin" bs=4096 count=256 2>/dev/null
# File with xattrs (APFS xattrs have their own record type)
touch "$MNT/with_xattrs"
xattr -w com.strata.test "test value" "$MNT/with_xattrs"

hdiutil detach "$MNT"
hdiutil convert "$OUT.tmp.sparseimage" -format UDRO -o "$OUT.tmp2"
mv "$OUT.tmp2.dmg" "$OUT"
rm -rf "$OUT.tmp.sparseimage"
```

APFS sparseimage vs flat image distinction matters — some APFS
parsers expect flat DMG. The conversion step handles that.

If hdiutil unavailable in build environment, commit pre-built
fixture with deterministic generation steps in README (Session B/D/E
fallback pattern).

## Phase B — Expected manifest

```json
// crates/strata-fs/tests/fixtures/apfs_single.expected.json
{
  "volume_label": "STRATA-APFS",
  "fs_type": "apfs",
  "volume_count": 1,
  "expected_entries": [
    {"path": "/readme.txt", "size": 15},
    {"path": "/dir1/dir2/dir3/deep.txt", "size": 10},
    {"path": "/multi_extent.bin", "size": 1048576},
    {"path": "/with_xattrs", "xattrs": ["com.strata.test"]}
  ]
}
```

## Acceptance criteria

- [ ] mkapfs.sh produces deterministic fixture when re-run
- [ ] ApfsSingleWalker::open on fixture succeeds
- [ ] Walker enumeration matches apfs_single.expected.json exactly
- [ ] Multi-extent file reads correctly
- [ ] xattrs exposed on VfsEntry metadata
- [ ] Test count grows by at least 4
- [ ] Walker against real hdiutil-generated fixture catches any
      synth-test-lockstep bugs (Lesson 2 discipline)
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# SESSION 4 — SPRINT 3 — FS-EXFAT-1 — EXFAT WALKER (v15 DEFERRAL)
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-EXFAT-1
**Pickup signal from v15 Session E:** exFAT deferred with pickup signal
"exFAT walker deferred — see roadmap."

**Why in Session 4:** exFAT is a walker-layer extension to the Session E
FAT12/16/32 parser. Architecturally independent of APFS. Session 4 is
the walker-theme session, so it fits.

**Scope guard:** If session time balloons, defer exFAT to v17 cleanly.
Does NOT block the v0.16 tag per the tag policy in this file's
introduction.

## Phase A — Audit existing FAT parser for exFAT shape

The Session E FAT parser is FAT12/16/32. exFAT has a different
on-disk layout — it's FAT-lineage but uses different directory entry
types (file directory entries, stream extension entries, filename
extension entries) and a different FAT format (no 12-bit packed
entries, no LFN chain the same way).

Audit what Session E already knows about exFAT. If the Session E
parser's FatBootSector detection already discriminates exFAT, that's
a partial start. Otherwise, exFAT is essentially a separate parser
wearing FAT's costume.

## Phase B — Implement exFAT parser layer

Likely new parser code alongside FAT12/16/32, not on top of it:

- exFAT boot sector identification (different from FAT32 BPB)
- Allocation bitmap (replaces FAT cluster chain for most cases)
- Up-case table (for case-insensitive name comparison)
- Directory entry parsing (file entry + stream extension + filename
  extension packed records)
- Filename extension: 15-character UTF-16 chunks, checksum validates
  against the file entry
- Cluster fragment runs via the allocation bitmap

## Phase C — ExfatWalker

Walker wraps the new exFAT parser following the FatWalker pattern
from Session E:

```rust
pub struct ExfatWalker {
    inner: ExfatFilesystem,
}

// Vfs trait impl analogous to FatWalker
```

## Phase D — Fixture

Native macOS generation via newfs_exfat (diskutil wrapper) or mount
existing exFAT image and generate with known content:

```bash
# crates/strata-fs/tests/fixtures/mkexfat.sh
# Generate a 10 MB exFAT image with reproducible content
```

If newfs_exfat unavailable in build environment, commit pre-built
fixture.

## Phase E — Dispatcher arm flip

```rust
FsType::Exfat => Ok(Box::new(ExfatWalker::open(reader)?)),
```

Convert the Session E deferral negative test to positive routing test.

## Acceptance criteria (scope-guarded)

- [ ] exFAT parser handles boot sector, allocation bitmap, directory
      entries
- [ ] ExfatWalker::open on fixture succeeds
- [ ] Walker enumeration matches expected manifest
- [ ] Long filenames via filename extension records decoded correctly
- [ ] Dispatcher exFAT arm routes to live ExfatWalker
- [ ] Session E deferral test converted to positive
- [ ] Test count grows by at least 5
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide

If session time balloons on APFS-single work, defer exFAT to v17
with concrete pickup signal in SESSION_STATE_v16_BLOCKER.md. The
v0.16 tag does NOT require exFAT to ship. Document the deferral
and continue.

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# SESSION 4 — SPRINT 4 — FS-DISPATCH-APFS-SINGLE
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-DISPATCH-APFS-SINGLE

## Phase A — Flip the APFS-single dispatcher arm

```rust
FsType::ApfsSingle => Ok(Box::new(ApfsSingleWalker::open(reader, 0)?)),
// APFS-multi still returns Unsupported until Session 5
FsType::ApfsMulti => Err(VfsError::Unsupported(
    "APFS multi-volume walker ships in v0.16 Session 5".into()
)),
```

## Phase B — Convert the Session B/D/E negative test

The existing dispatch_apfs_still_returns_v16 test (or similar)
becomes dispatch_apfs_single_arm_routes_to_live_walker. The
dispatch_apfs_multi_still_returns_v16_session_5 test remains.

## Phase C — CLI verification

strata ingest run --source apfs_single.img --case-dir ./case --auto
must succeed end-to-end on APFS single-volume sources.

## Acceptance criteria

- [ ] APFS-single dispatcher arm routes to live walker
- [ ] APFS-multi dispatcher arm still returns Unsupported with
      "Session 5" message
- [ ] All other v15 dispatcher arms still route live
- [ ] CLI ingest succeeds on APFS single-volume fixture
- [ ] Test count grows by at least 3
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# END OF SESSION 4
# ═══════════════════════════════════════════════════════════════════════
#
# Do NOT tag v0.16.0 — that ships at end of Session 5 only.
# Write SESSION_STATE_v16_SESSION_4_COMPLETE.md. Push to origin/main.
# Stop. Session 5 is a separate run.
#
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# █████████████████████████████  SESSION 5  █████████████████████████████
# ═══════════════════════════════════════════════════════════════════════
# █  APFS-multi (CompositeVfs) + final dispatcher + v0.16 milestone.   █
# █  This is the v0.16 tag session.                                     █
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# SESSION 5 — SPRINT 1 — FS-APFS-MULTI-COMPOSITE — CompositeVfs
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-APFS-MULTI-COMPOSITE

## Phase A — Implement CompositeVfs

Multi-volume APFS container wrapping. CompositeVfs iterates each
volume in the container, exposing them through a unified VFS interface
with volume-scoped paths.

```rust
pub struct ApfsMultiWalker {
    container: Arc<ApfsContainer>,
    volume_walkers: Vec<ApfsSingleWalker>,
}

impl ApfsMultiWalker {
    pub fn open<R: Read + Seek + Send + 'static>(reader: R)
        -> Result<Self, VfsError>
    {
        let container = Arc::new(ApfsContainer::parse(reader)?);
        let volume_walkers = (0..container.volume_count())
            .map(|idx| ApfsSingleWalker::open_on_container(
                container.clone(), idx))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { container, volume_walkers })
    }
}
```

## Phase B — Volume-scoped path semantics

Path format: `/vol{index}:{volume_internal_path}` — e.g.,
`/vol0:/etc/passwd` for the first volume's /etc/passwd,
`/vol1:Users/admin/Library/...` for the second volume's content.

Alternative path format: by volume name — `/@Macintosh HD/etc/passwd`
— with fallback to index if names collide. Pick one convention and
document it.

```rust
impl Vfs for ApfsMultiWalker {
    fn walk(&mut self) -> Box<dyn Iterator<Item = VfsEntry> + Send + '_> {
        // Interleave volume walkers' entries, prefixing each path
        // with the volume scope.
    }

    fn read(&mut self, path: &Path) -> Result<Vec<u8>, VfsError> {
        // Parse volume scope from path, route to appropriate
        // ApfsSingleWalker.
    }
}
```

## Phase C — Fixture

Generate a two-volume APFS container:

```bash
# crates/strata-fs/tests/fixtures/mkapfs_multi.sh
hdiutil create -size 20m -fs APFS -volname "STRATA-APFS-MAIN" -type SPARSE "$OUT.tmp"
# Attach, add second volume to container via diskutil apfs addVolume
# Populate both with reproducible content
# Detach, convert to flat
```

## Acceptance criteria

- [ ] ApfsMultiWalker::open on multi-volume fixture succeeds
- [ ] walk() yields entries from all volumes with correct scoping
- [ ] read() resolves volume-scoped paths to correct volume content
- [ ] Test count grows by at least 5
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# SESSION 5 — SPRINT 2 — FS-DISPATCH-APFS-MULTI — FINAL DISPATCHER
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** FS-DISPATCH-APFS-MULTI

## Phase A — Flip APFS-multi dispatcher arm

```rust
FsType::ApfsMulti => Ok(Box::new(ApfsMultiWalker::open(reader)?)),
```

Convert the Session 4 `dispatch_apfs_multi_still_returns_v16_session_5`
test to positive `dispatch_apfs_multi_arm_routes_to_live_walker`.

## Phase B — Detection

Dispatcher should auto-detect APFS-single vs APFS-multi from
container volume count. Single-volume containers route to
ApfsSingleWalker; multi-volume containers route to ApfsMultiWalker.

## Phase C — CLI verification

strata ingest run --source apfs_multi.img --case-dir ./case --auto
must succeed end-to-end on APFS multi-volume sources.

## Acceptance criteria

- [ ] APFS-multi dispatcher arm routes to live walker
- [ ] Dispatcher auto-detection picks single vs multi correctly
- [ ] All other dispatcher arms still route live (NTFS, ext4, HFS+,
      FAT, exFAT if shipped, APFS-single)
- [ ] CLI ingest succeeds on APFS multi-volume fixture
- [ ] Test count grows by at least 3
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# SESSION 5 — SPRINT 3 — v0.16 MILESTONE
# ═══════════════════════════════════════════════════════════════════════

**Sprint ID:** V16-MILESTONE

## Phase A — Update CLAUDE.md key numbers

Reflect final v16 state:
- Test count
- Walker availability: NTFS, ext4, HFS+, FAT, APFS-single, APFS-multi
  all live (plus exFAT if Sprint 3 of Session 4 shipped). APFS
  snapshots still deferred. Fusion drives still Unsupported.
- Dispatcher activation status

## Phase B — Publish FIELD_VALIDATION_v16_REPORT.md

Cover:
- Per-walker test counts and fixture validation results
- Dispatcher activation status for every filesystem type
- Charlie/Jo regression guard status (must show pass)
- AST quality gate output vs v14 baseline (zero new expected across
  all five v16 sessions, per v15 precedent)
- Any deferred items with concrete pickup signals for v17 (APFS
  snapshots, historical checkpoints, fusion drives, possibly exFAT
  if deferred from Session 4)
- ML wiring status (Session 2 accomplishments)
- HFS+ read_file status (Session 3 accomplishment)
- Comparison against v15 scorecard
- Methodology discipline notes — any new lessons discovered across
  the five sessions worth adding to docs/DISCIPLINE_NOTES.md

## Phase C — Tag v0.16.0

```bash
git tag -a v0.16.0 -m "v0.16.0 — APFS + filesystem completion

APFS single-volume and multi-volume walkers ship live through
the unified dispatcher pipeline. Combined with v11-v15 walkers,
the dispatcher now routes every major filesystem forensic
examiners encounter: NTFS, ext4, HFS+, FAT12/16/32, exFAT*,
APFS-single, APFS-multi.

Also shipped:
  - HFS+ read_file extents reading (v15 Session D deferral closed)
  - Advisory analytics wired into primary ingest pipeline
    (pre-v14 audit debt closed)
  - Sigma rules 30/31/32 restored to live firing state

Still deferred:
  - APFS snapshot enumeration (v17 candidate)
  - APFS historical checkpoint walking (v17 candidate)
  - APFS fusion drives (beyond v17)

Quality gates: AST baseline preserved, Charlie/Jo guards passing,
zero new unwrap/unsafe/println in production code across all
five v16 sessions.

* exFAT status: [ship if Sprint 3 Session 4 shipped; otherwise 'deferred']"

git push origin v0.16.0
```

## Acceptance criteria

- [ ] CLAUDE.md key numbers updated
- [ ] FIELD_VALIDATION_v16_REPORT.md committed
- [ ] v0.16.0 annotated tag created with full five-session summary
- [ ] v0.16.0 tag pushed to origin
- [ ] All eight dispatcher arms route live (NTFS, ext4, HFS+, FAT,
      exFAT if shipped, APFS-single, APFS-multi — plus a few FS
      family subtypes the Session E/4 FAT work enabled)
- [ ] No public API regressions across v16
- [ ] AST quality gate stays at v14 baseline
- [ ] Clippy clean workspace-wide
- [ ] Charlie/Jo regression guards pass

Zero unwrap, zero unsafe, no println in production paths.

---

# ═══════════════════════════════════════════════════════════════════════
# COMPLETION CRITERIA — ENTIRE v16
# ═══════════════════════════════════════════════════════════════════════

SPRINTS_v16.md is complete (across all five sessions) when:

**Required for v0.16.0 tag:**
- docs/RESEARCH_v16_APFS_SHAPE.md committed (Session 1)
- Advisory analytics wired into strata ingest run (Session 2)
- Advisory analytics wired into apps/strata-desktop/ (Session 2)
- Sigma rules 30/31/32 firing (Session 2)
- Website + README restored with Advisory Analytics section (Session 2)
- APFS object map + container superblock parser (Session 3)
- HFS+ read_file extents reading (Session 3, v15 deferral paid)
- APFS-single walker + fixture + dispatcher arm (Session 4)
- APFS-multi walker + fixture + dispatcher arm (Session 5)
- CLAUDE.md updated, FIELD_VALIDATION_v16_REPORT.md published (Session 5)
- v0.16.0 tag pushed (Session 5)

**Ships opportunistically (does NOT block tag):**
- exFAT walker + dispatcher arm (Session 4 Sprint 3)

**Quality gates (non-negotiable, every session):**
- All tests passing
- Clippy clean workspace-wide
- AST quality gate stays at v14 baseline (zero new
  unwrap/unsafe/println)
- All 9 load-bearing tests preserved
- Charlie/Jo regression guards pass — NTFS extraction unchanged
- All previously-shipped dispatcher arms continue routing live
- No public API regressions

**The moment v16 ends (post-Session 5):**

Strata dispatches every major filesystem forensic examiners
encounter: NTFS, ext4, HFS+, FAT12/16/32, (optionally exFAT), APFS
single-volume, APFS multi-volume. The dispatcher CLI flow works
end-to-end on Windows, Linux, legacy macOS, modern macOS, and
removable media evidence. Advisory analytics run in production.
Sigma correlation covers plugin artifacts and advisory findings.

After v16, Strata's architectural filesystem build-out is complete.
Future work is depth (snapshots, historical checkpoints, decryption
with supplied keys), not breadth. The roadmap transitions from
"shipping new filesystem support" to "deepening forensic coverage
within the shipping support."

---

*STRATA AUTONOMOUS BUILD QUEUE v16*
*Wolfmark Systems — 2026-04-19*
*Session 1: FS-APFS-RESEARCH — architectural research, no production code*
*Session 2: ML-WIRE-1 — advisory analytics wired standalone, audit debt closed*
*Session 3: FS-APFS-OBJMAP + FS-HFSPLUS-READFILE — parser foundations + v15 deferral*
*Session 4: FS-APFS-SINGLE-WALKER + FS-EXFAT-1 (opportunistic) + dispatcher arms*
*Session 5: FS-APFS-MULTI-COMPOSITE + final dispatcher + v0.16.0 tag*
*Mission: Ship APFS walkers, close v15 deferrals, close audit debt, tag v0.16.0.*
*Discipline: Do not silently compromise the spec. Real fixtures over synth.*
*Research before code. Tripwire tests for every deferral.*
