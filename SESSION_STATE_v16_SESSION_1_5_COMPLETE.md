# SPRINTS_v16 Session 1.5 — complete

v16 Session 1.5 (ecosystem probe) shipped the research artifact
the queue required. Three Rust APFS crates evaluated. One
adopted. Two rejected. Scope for Sessions 3/4 materially revised
downward.

**`v0.16.0` NOT tagged.** That's Session 5.

## Sprint scorecard

| # | Sprint | Status | Commit |
|---|---|---|---|
| 1 | FS-APFS-ECOSYSTEM-PROBE | **shipped** | `d304f84` |

## Probe results per candidate

### exhume_apfs v0.1.3 — **NO-GO**

- **License: `GPL-2.0-or-later`** — categorical disqualification
  at license-check step per Strata's "NEVER GPL" immutable
  constraint.
- No further probing performed. No time wasted on API
  enumeration, fixture round-trip, or Send/Sync probes. License
  gate terminates.
- For the record: ~4,701 LOC across 11 src modules, active
  forensic-oriented maintainer (k1nd0ne / forensicxlab.com),
  clean public API. None of it matters under GPL.

### apfs v0.2.4 — **GO (multi-layer adoption)**

- **License: MIT** ✓ — Apache/MIT-compatible with Strata.
- Repository: `github.com/Dil4rd/dpp` (sibling crate of `dpp`).
- 2,624 LOC across 9 src modules.
- I/O abstraction: `R: Read + Seek` generic. Matches
  NtfsWalker / HfsPlusWalker / FatWalker pattern via Strata's
  `PartitionReader` adapter (no new adapter needed).
- **Function-body inspection per v15 Lesson 1:**
  - 0 `panic!` / `todo!` / `unimplemented!` across all files.
  - 0 `Ok(vec![])` / `Ok(Vec::new())` silent-empty returns.
  - 0 occurrences of "heuristic" in source — no silent
    fallback from structural parsing to byte-pattern matching.
  - 52 `.unwrap()` calls on pre-validated slices (acceptable
    for a workspace dependency; wrapped not re-audited).
  - `open()` body documents a spec-conformant 9-step parse
    (NXSB magic + Fletcher-64 → checkpoint descriptor → container
    OMAP → volume OID → volume superblock → volume OMAP →
    catalog root).
- **Real-fixture round-trip per v15 Lesson 2:** generated a 10
  MB APFS container via `hdiutil create -fs APFS -volname
  STRATA-PROBE -type SPARSE` + populate + detach + re-attach
  raw + `dd` to flat. First 48 bytes confirm `NXSB` magic at
  byte 32 (raw container, not DMG-wrapped). Probe at
  `/tmp/apfs_ecosystem_probe/` consumed the fixture via
  `File::open` → `ApfsVolume::open` → exercised every walker
  method against the known populated content.
  - **7 of 7 core parser checks PASSED:** root enumeration,
    3-level nested walk, small-file read, multi-extent read
    (12000 'Z' bytes across 3×4K extents), deep-nested read,
    `walk()` enumerating all 9 expected paths, `stat()`
    returning mode/uid/gid/nlink.
  - 2 of 9 probe checks are documented-gap INFO items: no
    multi-volume public API (Strata-owned from NxSuperblock's
    `fs_oids` + `omap::omap_lookup`); no xattr exposure on
    high-level surface (Strata-owned from `catalog::J_TYPE_XATTR`
    low-level record decode).
- **Verdict:** GO. Forensic-correctness-validated external
  dependency materially exceeds in-tree `apfs_walker.rs`
  (which has heuristic_scan fallback liability + stubbed
  `read_file` + never real-fixture validated).

### dpp v0.4.2 — **NO-GO**

- License: MIT (acceptable) but **wrong scope** — the crate is
  a streaming DMG → HFS+/APFS → PKG → PBZX installer-payload
  extraction pipeline. Its APFS parser is the `apfs` crate
  (same repository). Evaluating dpp separately would re-probe
  the same parser with an additional orchestration layer
  Strata doesn't need.
- Strata wants a parser, not an installer pipeline.
- **Verdict:** NO-GO. Stop at the `apfs` crate.

## Architectural decision — multi-layer adoption

Strata adopts `apfs` v0.2.x as the parser layer. Strata-owned
code wraps it for forensic-specific surface:

| Layer | Owner |
|---|---|
| NXSB parse / OMAP walk / volume SB parse / catalog B-tree walk / extent record reading | **`apfs` crate** |
| VFS trait impl (list_dir/read_file/metadata/exists) | Strata (thin delegation to `ApfsVolume`) |
| Multi-volume iteration (`/vol{N}:/path`) | Strata (uses pub submodule helpers: `read_nxsb` + `omap_lookup` + `ApfsSuperblock::parse`) |
| Fusion-drive detection (Unsupported at superblock) | Strata (reads `NxSuperblock.incompatible_features & 0x100`) |
| xattr exposure on `VfsEntry` | Strata (decodes `catalog::J_TYPE_XATTR = 4` records) |
| Encryption marking | Strata (reads `ApfsSuperblock` flags) |
| Snapshot iteration (deferred beyond v16) | deferred |

This is the exact multi-layer pattern v15 Session 1's
`ext4-view` research enabled: external crate for spec-heavy
bit-level work, in-tree code for forensic-specific surface.

## Revised Session 3/4/5 LOC estimates

| Session | Session 1 baseline | Session 1.5 revised | Delta |
|---|---|---|---|
| Session 3 APFS parser | ~420 LOC | **~120 LOC** | **-300** |
| Session 3 HFS+ read_file | ~260 LOC | ~260 LOC | unchanged |
| **Session 3 total** | ~680 LOC | **~380 LOC** | **-300** |
| Session 4 APFS-single walker | ~720 LOC | **~500 LOC** | **-220** |
| Session 4 exFAT (opportunistic) | ~760 LOC | ~760 LOC | unchanged |
| **Session 4 total (APFS only)** | ~720 LOC | **~500 LOC** | **-220** |
| Session 5 APFS-multi CompositeVfs | ~750 LOC | ~700 LOC | ~same |

Net savings ~520 LOC for Sessions 3 + 4 combined. Session
boundaries hold comfortably. Session 4's dual-sprint risk
(flagged in Session 1 research doc §9) is materially lower
post-adoption — APFS-single shipping well under 600 LOC means
exFAT opportunity fits the session without balloon.

## Retirement plan for in-tree APFS code (Session 3 cleanup commit)

Session 3 deletes:

- `crates/strata-fs/src/apfs.rs` (601 LOC) — heuristic scanners
  + stub `resolve_oid` + stub `read_file` + hardcoded-placeholder
  "Preboot / Recovery / VM" entries. v14-audit failure-mode
  shape; should not ship in forensic code.
- `crates/strata-fs/src/apfs_walker.rs` (1,283 LOC) — working
  OMAP + fs-tree walking but:
  - Never real-fixture validated
  - Has `heuristic_scan` fallback that silently substitutes
    byte-pattern matching when structural parsing fails
  - `read_file` not implemented (JFEF extent record decode
    missing per Session 1 audit)
  The crate now ships this surface end-to-end, validated.
- `crates/strata-fs/src/apfs_advanced.rs` (70 LOC) — entirely
  stubs (all method bodies `Ok(vec![])` /
  `Ok(SpaceMetrics::default())`).
- Session 1's 13 Send/Sync probes targeting the types above
  (they move to probes targeting `apfs::ApfsVolume<File>` + the
  Strata-owned wrapper types).

Net deletion: ~1,954 LOC in-tree retired, replaced by ~750 LOC
of wrapper + multi-volume glue + xattr/encryption code
(Sessions 3+4+5 combined).

## SPRINTS_v16.md Session 3 preamble updated

Commit `d304f84` amends the Session 3 Sprint 1 preamble
(FS-APFS-OBJMAP) to:

- Add `docs/RESEARCH_v16_APFS_RUST_ECOSYSTEM.md` as a
  prerequisite alongside the Session 1 research doc.
- Document the scope revision (420 LOC → 120 LOC wrapper).
- Sketch the `crates/strata-fs/src/apfs_walker/` module layout.
- Flag the dedicated cleanup commit for in-tree deletion.

## Quality gates at end-of-session

- **Test count:** **3,795** (unchanged from Session 2 end —
  this session added no production code and no tests to the
  Strata tree).
- `cargo clippy --workspace -- -D warnings`: **clean**.
- AST quality gate: **PASS** at v14 baseline (470 library
  `.unwrap()` / 5 `unsafe{}` / 5 `println!` — zero new).
- All 9 load-bearing tests preserved.
- **All four v15 dispatcher arms still route live**
  (verified via `cargo test -p strata-fs --lib fs_dispatch`:
  17 passed — NTFS, ext4, HFS+, FAT).
- **APFS dispatcher arm still returns literal `"v0.16"`
  message** (`dispatch_apfs_returns_explicit_v016_message`
  test passes).
- exFAT arm still returns deferral message.
- Charlie/Jo regression guards: unchanged.
- **All four Session 2 advisory plugin tripwire tests pass**
  (verified via `cargo test -p strata-engine-adapter --test
  advisory_wiring`: 4 passed —
  `advisory_plugin_registered_before_sigma_in_static_build`,
  `advisory_analytics_invoked_by_ingest_run_pipeline`,
  `advisory_plugin_emits_records_with_sigma_matchable_subcategories`,
  `sigma_rule_30_path_reachable_via_advisory_detail_format`).
- No public API regressions. No files touched in Strata tree
  beyond `docs/RESEARCH_v16_APFS_RUST_ECOSYSTEM.md` (new) and
  `SPRINTS_v16.md` (Session 3 preamble amendment).

## Concrete pickup signals for Session 3

1. **Add `apfs = "0.2"`** to `crates/strata-fs/Cargo.toml`.
2. **Create `crates/strata-fs/src/apfs_walker/mod.rs`** as the
   Strata-owned wrapper. First sprint ships:
   - Fusion-detect helper reading
     `NxSuperblock.incompatible_features & 0x100`.
   - Multi-volume OID enumeration from `fs_oids` (filter
     non-zero).
   - Send/Sync probes under `#[cfg(test)]` on
     `apfs::ApfsVolume<std::fs::File>`,
     `apfs::superblock::NxSuperblock`,
     `apfs::superblock::ApfsSuperblock`.
3. **Dedicated cleanup commit** deleting `apfs.rs` +
   `apfs_walker.rs` + `apfs_advanced.rs` + Session 1's 13
   Send/Sync probes in a single deletion commit. Keeps
   `git blame` clean.
4. **HFS+ read_file extent reading** (Session 3 Sprint 2) —
   unchanged by this doc. ~260 LOC Strata-owned. Architecturally
   analogous to APFS extent reading (handled by the `apfs`
   crate).
5. **Fixture prep:** `/tmp/apfs_probe_fixture.img` from this
   session is available for Session 4 reuse. Move to
   `crates/strata-fs/tests/fixtures/apfs_small.img` as the
   committed snapshot + commit a `mkapfs.sh` regeneration
   script based on Appendix B of this session's research doc.
6. **Tripwire tests carry the dropped-stub invariants:**
   - `apfs_walker_rejects_fusion_container_with_pickup_signal`
     (fusion detect).
   - `apfs_walker_walks_current_state_only_pending_snapshot_enumeration`
     (Session 1's deferral pin).
   - `apfs_walker_marks_encrypted_volumes_does_not_decrypt`
     (Session 1's encryption contract).
7. **Session 2 tripwires stay untouched.** No modifications to
   the advisory plugin wiring; Session 3 is purely filesystem-
   layer work.

## The bottom line

v16 Session 1.5 delivered what ecosystem probes are supposed to
deliver: confidence in Session 3's scope + material LOC savings
via a forensic-correctness-validated external dependency.

Key discoveries:

- `exhume_apfs`, the a-priori priority candidate, was
  GPL-disqualified at license check. Terminal finding. No time
  wasted on deeper probing.
- `apfs` v0.2.4 (MIT, from a sibling repo) passed 7/7 real-
  fixture round-trip checks against an hdiutil-generated APFS
  container. Zero silent-empty fallbacks in source. Zero
  heuristic-scan liability. Materially exceeds the in-tree
  walker which has both.
- The crate's single-volume `ApfsVolume::open()` API is a gap
  for Session 5 — but the submodule helpers (`read_nxsb`,
  `omap_lookup`, `ApfsSuperblock::parse`) are public, so Strata
  assembles multi-volume iteration in-tree without forking or
  upstream coordination.
- In-tree `apfs.rs` + `apfs_walker.rs` + `apfs_advanced.rs`
  retire in Session 3's cleanup commit. Net deletion ~1,954
  LOC of v14-audit-shape code.

Session 3 can pick up with certainty about its scope — ~380 LOC
across two sprints (APFS wrapper + HFS+ read_file extents)
rather than Session 1's ~680 LOC estimate. The queue's
session-boundary risk for Session 4 is reduced correspondingly.

Strata is a forensic tool.
