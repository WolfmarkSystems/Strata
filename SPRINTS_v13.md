# SPRINTS_v13.md — STRATA UNLOCK ALL IMAGE TYPES + PROTECT WHAT'S BUILT
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md, SESSION_STATE_v12_BLOCKER.md, FIELD_VALIDATION_v12_REPORT.md,
#         and SPRINTS_v13.md. Execute all incomplete sprints in order."
# Last updated: 2026-04-18
# Prerequisite: SPRINTS_v1.md through SPRINTS_v12.md complete (3,661 tests passing)
#
# ═══════════════════════════════════════════════════════════════════════
# WHERE STRATA IS AT THE START OF v13
# ═══════════════════════════════════════════════════════════════════════
#
# v12 shipped the `vfs_materialize` universal bridge: walk any VFS, copy
# forensic-target files to a scratch directory, run plugins against the
# scratch directory using their existing std::fs code paths. One commit
# (10ffdd2) took Charlie's E01 from 4 → 3,400 artifacts and Jo's from
# 0 → 3,537.
#
# Diagnostic (`/tmp/strata_v12_state_report.md`) revealed three truths:
#
# 1. FILESYSTEM WALKERS ARE MOSTLY UNBUILT.
#    Only NtfsWalker implements VirtualFilesystem. Ext4Walker doesn't
#    exist. ApfsWalker exists as files but has no VFS impl. HFS+ and
#    FAT are parsers only, no walkers.
#
# 2. PLUGIN MIGRATION IS STILL 21 PLUGINS DEEP.
#    Only Phantom was migrated in v11. v12's vfs_materialize bridge
#    unblocked the other plugins without requiring migration. The
#    bridge has real performance ceilings (512 MiB/file, 16 GiB total,
#    500k files) — it's a correctness-first stopgap, not a long-term
#    scaling solution.
#
# 3. NO REGRESSION GUARD EXISTS.
#    Charlie 3,400 and Jo 3,537 are documented in prose only. A future
#    commit could silently break them. This is the single biggest risk
#    to everything shipped through v12.
#
# Plus several housekeeping findings:
#   - Plugin count is 24, not 26 (CLAUDE.md is stale)
#   - RESEARCH_v10_CRATES.md is referenced but not on disk
#   - Terry/Jean 4-artifact results are acquisition-trim (MFT outside
#     EWF range), not plugin bugs — needs structured warning
#   - Raw grep quality gates overstate violations (include test code)
#
# ═══════════════════════════════════════════════════════════════════════
# THE MISSION
# ═══════════════════════════════════════════════════════════════════════
#
# v13 protects what v12 shipped, unlocks every non-Windows image type
# in Test Material, and migrates the three highest-volume plugins to
# streaming VFS reads (removing the bridge bottleneck for the plugins
# that produce the most artifacts).
#
# When v13 completes:
#
#   - Regression guard: Charlie, Jo, and every future image-artifact
#     count is protected by a cargo-test-runnable integration test.
#     A commit that breaks ingestion fails CI.
#   - Filesystem walkers: ext4, APFS, HFS+, FAT all ship. Every
#     filesystem type in Test Material mounts cleanly.
#   - Dispatcher: routes to live walkers, no Unsupported arms.
#   - Three highest-volume plugins (Vector, Chronicle, Trace) migrated
#     to VFS-native reads — bridge bypassed for the plugins that matter
#     most per-run.
#   - Acquisition-trim diagnostics: Terry/Jean cases report
#     "image truncated" structurally, not as silent 4-artifact results.
#   - Housekeeping: CLAUDE.md plugin count reconciled, research doc
#     committed, AST-aware quality checks replace grep.
#   - Full matrix: every image in Test Material produces expected
#     artifact counts, documented in FIELD_VALIDATION_v13_REPORT.md.
#
# The remaining 18 plugin migrations (Remnant, Sentinel, Guardian,
# Cipher, Nimbus, Conduit, Wraith, Recon, NetFlow, MacTrace, Apex,
# Carbon, Pulse, Specter, Vault, Arbor, CSAM, Sigma) are DEFERRED to
# v14. They work today via vfs_materialize. Migration is mechanical
# perf optimization, not blocking architecture.
#
# ═══════════════════════════════════════════════════════════════════════
# SCOPE
# ═══════════════════════════════════════════════════════════════════════
#
# 9 sprints across 7 parts:
#
# Part 1 — Regression guard (protect what v12 shipped) ............. 1 sprint
# Part 2 — Filesystem walkers (ext4, APFS, HFS+, FAT) .............. 4 sprints
# Part 3 — Dispatcher activation ................................... 1 sprint
# Part 4 — High-leverage plugin migrations (Vector, Chronicle, Trace)  1 sprint
# Part 5 — Acquisition-trim diagnostics ............................. 1 sprint
# Part 6 — Housekeeping (CLAUDE.md, research doc, quality gates) .... (folded)
# Part 7 — Full matrix validation ................................... 1 sprint
#
# Part 6 work folds into the final matrix sprint since it's small.
#
# ═══════════════════════════════════════════════════════════════════════
# DISCIPLINE — CARRIED FORWARD
# ═══════════════════════════════════════════════════════════════════════
#
# "Do not silently compromise the spec." If any sprint reveals a real
# blocker, stop, document in `SESSION_STATE_v13_BLOCKER.md`, continue
# with subsequent unblocked sprints.
#
# Ground truth validation is mandatory. Every filesystem walker ships
# with integration tests against a real image or committed test fixture.
#
# Quality gates: all tests pass from 3,661 start, clippy clean, zero
# new unwrap/unsafe/println in production code (library + parser
# crates), all 9 load-bearing tests preserved, no public API
# regressions.
#
# Sprint 1 is non-negotiable gate. Everything v12 shipped must be
# protected before any new feature work lands.

---

## HOW TO EXECUTE

Read CLAUDE.md, SESSION_STATE_v12_BLOCKER.md, FIELD_VALIDATION_v12_REPORT.md,
`/tmp/strata_v12_state_report.md`, and SPRINTS_v13.md in that order.
Then execute each sprint below in order.

For each sprint:
1. Implement exactly as specified
2. Run `cargo test --workspace` — all tests must pass (starting from 3,661)
3. Run `cargo clippy --workspace -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!` added to
   library/parser crates (CLI binaries may use println! for human
   output — see GATES-1 for AST-aware enforcement)
5. Commit with message: "feat: [sprint-id] [description]" or "fix: [sprint-id] [description]"
6. Move to next sprint immediately

---

## COMPLETED SPRINTS (skip these)

None yet — this is v13.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 1 — REGRESSION GUARD (PROTECT WHAT v12 SHIPPED)
# ═══════════════════════════════════════════════════════════════════════

## SPRINT REGRESS-GUARD-1 — Permanent Regression Test Harness

Create `crates/strata-shield-engine/tests/matrix_regression.rs` as a
cargo-test-runnable integration test that encodes the v12 scorecard
as permanent regression guards.

**Problem statement:**

v12 shipped Charlie's 3,400 artifacts and Jo's 3,537 artifacts. These
numbers live in `FIELD_VALIDATION_v12_REPORT.md` prose. A future
commit that breaks the EWF reader, the NTFS walker, the dispatcher,
the VFS bridge, or Phantom would silently regress these counts and
the failure would only surface during the next manual field
validation — potentially many commits later.

This is the single biggest risk to everything shipped through v12.

**Implementation:**

```rust
//! tests/matrix_regression.rs — permanent regression guard for the
//! v12 universal VFS bridge scorecard. Skip-guarded on Test Material
//! presence; will run in any developer environment that has the
//! standard Wolfmark Test Material directory mounted.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const TEST_MATERIAL: &str = "/Users/randolph/Wolfmark/Test Material";

fn test_material_root() -> Option<&'static Path> {
    static ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();
    ROOT.get_or_init(|| {
        let p = PathBuf::from(TEST_MATERIAL);
        if p.exists() { Some(p) } else { None }
    }).as_deref()
}

struct RegressionCase {
    name: &'static str,
    image_subpath: &'static str,
    min_total_artifacts: u64,
    min_per_plugin: &'static [(&'static str, u64)],
    reason_if_low: &'static str,
}

// Minimums encoded from actual v12 observed counts minus ~5% margin.
// These are regression guards, not aspirational targets.
const V12_BASELINE_CASES: &[RegressionCase] = &[
    RegressionCase {
        name: "charlie-2009-11-12",
        image_subpath: "charlie-2009-11-12.E01",
        min_total_artifacts: 3_200,   // v12 observed 3,400
        min_per_plugin: &[
            ("Strata Phantom", 500),
            ("Strata Vector", 2_300),  // v12 observed 2,465
            ("Strata Chronicle", 100),
            ("Strata Trace", 50),
        ],
        reason_if_low: "EWF reader, NTFS walker, vfs_materialize bridge, or plugin regression",
    },
    RegressionCase {
        name: "jo-2009-11-16",
        image_subpath: "jo-2009-11-16.E01",
        min_total_artifacts: 3_300,   // v12 observed 3,537
        min_per_plugin: &[
            ("Strata Phantom", 500),
            ("Strata Vector", 2_300),
        ],
        reason_if_low: "same as charlie — shared codepath",
    },
    // Acquisition-trim cases (expected low count — not a regression
    // as long as they produce > 0 artifacts):
    RegressionCase {
        name: "terry-2009-12-03",
        image_subpath: "terry-2009-12-03.E01",
        min_total_artifacts: 1,
        min_per_plugin: &[],
        reason_if_low: "image is acquisition-trimmed before MFT; 4 artifacts is baseline",
    },
    RegressionCase {
        name: "nps-2008-jean",
        image_subpath: "nps-2008-jean.E01",
        min_total_artifacts: 1,
        min_per_plugin: &[],
        reason_if_low: "image is acquisition-trimmed before MFT; 4 artifacts is baseline",
    },
    // Host directory (non-E01) baseline:
    RegressionCase {
        name: "takeout",
        image_subpath: "Takeout",
        min_total_artifacts: 2,
        min_per_plugin: &[],
        reason_if_low: "HostVfs or Carbon plugin regression",
    },
];

fn run_case(root: &Path, case: &RegressionCase) -> Result<CaseResult, String> {
    let source = root.join(case.image_subpath);
    if !source.exists() {
        return Ok(CaseResult::Skipped);
    }
    
    let case_dir = tempfile::tempdir().map_err(|e| format!("{e}"))?;
    let args = make_ingest_args(
        source.to_string_lossy().to_string(),
        case_dir.path().to_path_buf(),
        case.name.to_string(),
    );
    
    let result = strata_shield_engine::ingest::run_ingest(args)
        .map_err(|e| format!("ingest failed: {e}"))?;
    
    let db = strata_shield_engine::artifacts::ArtifactDatabase::open(
        case_dir.path(),
        case.name,
    ).map_err(|e| format!("open db: {e}"))?;
    
    let total = db.count().map_err(|e| format!("count: {e}"))?;
    let per_plugin = db.count_by_plugin().map_err(|e| format!("count_by_plugin: {e}"))?;
    
    Ok(CaseResult::Ran { total, per_plugin })
}

#[test]
fn v12_regression_guard() {
    let Some(root) = test_material_root() else {
        eprintln!("SKIP: Test Material not present at {}", TEST_MATERIAL);
        return;
    };
    
    let mut failures: Vec<String> = Vec::new();
    let mut skipped = 0;
    let mut passed = 0;
    
    for case in V12_BASELINE_CASES {
        let result = run_case(root, case);
        match result {
            Ok(CaseResult::Skipped) => {
                eprintln!("SKIP: {} (image not present)", case.name);
                skipped += 1;
            }
            Ok(CaseResult::Ran { total, per_plugin }) => {
                let mut case_failed = false;
                
                if total < case.min_total_artifacts {
                    failures.push(format!(
                        "{}: total artifacts {} < minimum {} (reason: {})",
                        case.name, total, case.min_total_artifacts, case.reason_if_low
                    ));
                    case_failed = true;
                }
                
                for (plugin, min) in case.min_per_plugin {
                    let actual = per_plugin.get(*plugin).copied().unwrap_or(0);
                    if actual < *min {
                        failures.push(format!(
                            "{}: plugin {} artifacts {} < minimum {}",
                            case.name, plugin, actual, min
                        ));
                        case_failed = true;
                    }
                }
                
                if !case_failed {
                    eprintln!("PASS: {} — {} artifacts", case.name, total);
                    passed += 1;
                }
            }
            Err(e) => {
                failures.push(format!("{}: error — {}", case.name, e));
            }
        }
    }
    
    eprintln!();
    eprintln!("Regression guard summary: {} passed, {} skipped, {} failed",
              passed, skipped, failures.len());
    
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {}", f);
        }
        panic!("v12 regression guard: {} case(s) regressed", failures.len());
    }
}

enum CaseResult {
    Skipped,
    Ran { total: u64, per_plugin: std::collections::HashMap<String, u64> },
}
```

**Key design decisions:**

1. **Skip-guarded on Test Material presence.** CI environments without
   the Wolfmark Test Material directory skip cleanly. Developer
   environments with the directory run the guards automatically.

2. **Minimums encoded at ~5% below observed counts.** Artifacts may
   fluctuate slightly across runs due to plugin ordering and
   correlation. A 5% margin absorbs legitimate variance without
   hiding real regressions.

3. **Per-plugin minimums for highest-volume plugins only.** Vector
   and Phantom are most likely to regress (most code, highest
   artifact yield). Low-volume plugins (Cipher, Nimbus) may produce
   0 on specific images legitimately — don't enforce minimums where
   it would cause false positives.

4. **Acquisition-trim cases get a floor of 1 artifact, not 0.**
   Terry/Jean producing 4 artifacts today is not a bug (MFT outside
   EWF range). But if a regression caused them to produce 0, that
   would indicate something worse broke. Floor of 1 catches total
   breakage while allowing the documented 4-artifact trim behavior.

5. **Separate `reason_if_low` field** tells the examiner what to
   investigate first if the test fails. Critical for debugging at
   3am when the CI turns red.

**Tests required:**

- The regression guard itself (1 test, parametrized across cases)
- Unit test for `make_ingest_args` helper
- Unit test for `CaseResult` variant handling

**Acceptance criteria:**

- [ ] `cargo test --release --test matrix_regression` passes on current main
- [ ] Charlie ≥3,200 artifacts, Jo ≥3,300, per-plugin minimums hold
- [ ] Test skips cleanly when Test Material not present
- [ ] Clippy clean, no new unwrap/unsafe/println in production code
- [ ] Documented in CLAUDE.md as a mandatory pre-commit check

Zero unwrap, zero unsafe, Clippy clean, 3 new tests minimum.

**Why this sprint ships first:**

Everything after this point adds new code paths. New code paths create
new ways to regress existing functionality. Before expanding scope,
lock down what's already working. If any subsequent v13 sprint
accidentally breaks Charlie or Jo, this test fails loudly at commit
time instead of silently at next field validation.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 2 — FILESYSTEM WALKERS
# ═══════════════════════════════════════════════════════════════════════

## THE NTFS WALKER PATTERN (REFERENCE FOR ALL FILESYSTEM SPRINTS)

NtfsWalker in `crates/strata-fs/src/ntfs_walker/mod.rs` established the
pattern. All subsequent walkers follow it exactly:

```rust
pub struct XxxWalker {
    fs: Mutex<Inner>,                    // Underlying parser state
    partition_offset: u64,
    partition_size: u64,
}

impl XxxWalker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> XxxResult<Self> {
        let reader = PartitionReader::new(
            Arc::clone(&image),
            partition_offset,
            partition_size,
        );
        let fs = InnerFs::load(reader)?;
        Ok(Self {
            fs: Mutex::new(fs),
            partition_offset,
            partition_size,
        })
    }
}

impl VirtualFilesystem for XxxWalker {
    fn fs_type(&self) -> &'static str { "xxx" }
    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> { ... }
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> { ... }
    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> { ... }
    fn exists(&self, path: &str) -> bool { ... }
    fn alternate_streams(&self, path: &str) -> VfsResult<Vec<String>> { ... }
    fn read_alternate_stream(&self, path: &str, stream: &str) -> VfsResult<Vec<u8>> { ... }
    fn walk(...) -> VfsResult<()> { ... }
    fn list_deleted(&self) -> VfsResult<Vec<VfsDeletedEntry>> { ... }
    fn read_deleted(&self, entry: &VfsDeletedEntry) -> VfsResult<Vec<u8>> { ... }
}
```

The `PartitionReader` adapter is already implemented. Each walker
crate/module adds its own adapter layer between `PartitionReader`
(which provides `Read + Seek`) and whatever the underlying parser
needs.

---

## SPRINT FS-EXT4-1 — ext4 Walker Wrapping ext4-view Crate

Create `crates/strata-fs/src/ext4_walker/mod.rs`.

**Problem statement:**
Linux servers, Chromebook Crostini, Android userdata, and many
forensic Linux images use ext4. Research doc recommends `ext4-view`
v0.9 (NOT the stale FauxFaux `ext4` crate).

**Implementation:**

Add to `crates/strata-fs/Cargo.toml`:
```toml
[dependencies]
ext4-view = "0.9"
```

Follow the NtfsWalker pattern exactly:

```rust
use ext4_view::{Ext4, Ext4Read};
use std::sync::{Arc, Mutex};

pub struct Ext4Walker {
    fs: Mutex<Ext4>,
    partition_offset: u64,
    partition_size: u64,
}

struct Ext4ReadAdapter {
    reader: PartitionReader,  // From v10, already exists
}

impl Ext4Read for Ext4ReadAdapter {
    fn read(
        &mut self,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.reader.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        self.reader.read_exact(buf)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        Ok(())
    }
}

impl Ext4Walker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> Ext4Result<Self> {
        let reader = PartitionReader::new(
            Arc::clone(&image),
            partition_offset,
            partition_size,
        );
        let adapter = Ext4ReadAdapter { reader };
        let fs = Ext4::load(Box::new(adapter))
            .map_err(Ext4Error::from)?;
        Ok(Self {
            fs: Mutex::new(fs),
            partition_offset,
            partition_size,
        })
    }
}

impl VirtualFilesystem for Ext4Walker {
    fn fs_type(&self) -> &'static str { "ext4" }
    
    fn list_dir(&self, path: &str) -> VfsResult<Vec<VfsEntry>> {
        let fs = self.fs.lock().map_err(|_| VfsError::LockPoisoned)?;
        let mut entries = Vec::new();
        for entry_result in fs.read_dir(path).map_err(VfsError::from)? {
            let entry = entry_result.map_err(VfsError::from)?;
            entries.push(ext4_entry_to_vfs(&entry, &fs)?);
        }
        Ok(entries)
    }
    
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let fs = self.fs.lock().map_err(|_| VfsError::LockPoisoned)?;
        fs.read(path).map_err(VfsError::from)
    }
    
    // ... remaining trait methods
}

fn ext4_entry_to_vfs(
    entry: &ext4_view::DirEntry,
    fs: &Ext4,
) -> VfsResult<VfsEntry> {
    let path = entry.path().to_string_lossy().into_owned();
    let metadata = fs.metadata(&path).map_err(VfsError::from)?;
    
    Ok(VfsEntry {
        path: path.clone(),
        name: entry.file_name().to_string_lossy().into_owned(),
        is_directory: metadata.is_dir(),
        size: metadata.len(),
        created: None,          // ext4 crtime if available
        modified: Some(metadata.modified()?.into()),
        accessed: Some(metadata.accessed()?.into()),
        metadata_changed: Some(metadata.created()?.into()),  // ctime
        attributes: VfsAttributes {
            readonly: (metadata.mode() & 0o200) == 0,
            hidden: entry.file_name().to_string_lossy().starts_with('.'),
            system: false,
            archive: false,
            compressed: false,
            encrypted: false,
            sparse: false,
            unix_mode: Some(metadata.mode()),
            unix_uid: Some(metadata.uid()),
            unix_gid: Some(metadata.gid()),
        },
        inode_number: Some(metadata.ino()),
        has_alternate_streams: !metadata.xattrs().is_empty(),
        fs_specific: VfsSpecific::Ext4 {
            inode: metadata.ino(),
            extents_based: metadata.flags() & 0x80000 != 0,  // EXT4_EXTENTS_FL
        },
    })
}
```

**Extended attributes as alternate streams:**
ext4 xattrs (security.selinux, user.*, trusted.*) are the Unix analog
of NTFS ADS. Expose via `alternate_streams(path)` returning xattr
names. `read_alternate_stream(path, xattr)` returns xattr value.

**Ground truth tests:**

Check Test Material for Linux images:
- `2022 CTF - Linux.7z` — unpack, find ext4 partition
- `digitalcorpora/linux-dc3dd/` — check if this is an ext4 image

Tests (all skip-guarded on image presence):

```rust
#[test]
fn ext4_walker_opens_linux_ctf() {
    let Some(linux_image) = find_first_linux_image() else {
        eprintln!("SKIP: no Linux image in Test Material");
        return;
    };
    
    let image = open_evidence(&linux_image).expect("open");
    let partitions = read_partitions(image.as_ref()).expect("partitions");
    
    let ext4_part = partitions.iter()
        .find(|p| matches!(
            p.fs_hint(),
            Some(FsType::Ext4) | Some(FsType::Ext3) | Some(FsType::Ext2)
        ))
        .expect("find ext4 partition");
    
    let walker = Ext4Walker::open(
        Arc::clone(&image),
        ext4_part.offset_bytes(),
        ext4_part.size_bytes(),
    ).expect("open ext4");
    
    let root = walker.list_dir("/").expect("list root");
    let names: HashSet<String> = root.iter().map(|e| e.name.clone()).collect();
    
    assert!(names.contains("etc"), "Linux root must contain /etc");
    assert!(names.contains("var"), "Linux root must contain /var");
    assert!(names.contains("home") || names.contains("root"), "must have /home or /root");
    
    let passwd = walker.read_file("/etc/passwd").expect("read passwd");
    assert!(!passwd.is_empty());
    assert!(passwd.windows(5).any(|w| w == b"root:"), "passwd must contain root entry");
}
```

**Tests required:**
- Open ext4 partition via EvidenceImage
- List root directory (/etc, /var, /home or /root present)
- Read /etc/passwd (non-empty, contains root)
- Walk full filesystem, count > 1000 entries
- Read extended attribute on a file
- Find deleted inode via list_deleted
- Handle symlinks correctly
- ext2/ext3 also work (ext4-view supports all three)
- VirtualFilesystem trait compliance

Zero unwrap, zero unsafe, Clippy clean, 8+ tests minimum.

---

## SPRINT FS-APFS-1 — APFS Walker Wrapping Existing In-Tree Module

Create `crates/strata-fs/src/apfs_walker/mod.rs` (or complete the
existing `apfs_walker.rs` if it's already a file stub).

**Problem statement:**
Strata has in-tree APFS parsers at `crates/strata-fs/src/apfs.rs`,
`apfs_advanced.rs`, and stub `apfs_walker.rs`. No mature pure-Rust
APFS crate exists in the ecosystem. Wrap the in-tree work in an
`ApfsWalker` that implements `VirtualFilesystem`.

**Implementation steps:**

1. **Evaluate existing in-tree work:**

```bash
find crates/strata-fs/src -name "apfs*" -exec wc -l {} \;
cargo test -p strata-fs apfs
```

Verify coverage:
- NXSB (Container Super Block) parsing
- APSB (Volume Super Block) parsing
- OMAP (Object Map) resolution for object ID lookups
- B-tree walking (root tree, extent tree, snapshot tree)
- File/directory inode parsing
- Extended attributes (xattrs)
- Snapshots

2. **Wrap in ApfsWalker following NtfsWalker pattern:**

```rust
pub struct ApfsWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    container: Mutex<ApfsContainer>,    // Existing in-tree type
    volumes: Vec<ApfsVolumeMetadata>,
    active_volume: Mutex<usize>,
}

pub struct ApfsVolumeMetadata {
    pub name: String,
    pub role: ApfsVolumeRole,
    pub uuid: Uuid,
    pub case_sensitive: bool,
    pub encrypted: bool,
    pub snapshot_count: u32,
    pub sealed: bool,
}

impl ApfsWalker {
    pub fn open(
        image: Arc<dyn EvidenceImage>,
        partition_offset: u64,
        partition_size: u64,
    ) -> ApfsResult<Self>;
    
    pub fn volumes(&self) -> &[ApfsVolumeMetadata];
    pub fn set_active_volume(&self, name: &str) -> ApfsResult<()>;
    pub fn with_active_volume(&self, name: &str) -> ApfsResult<Box<dyn VirtualFilesystem>>;
    pub fn list_snapshots(&self, volume: &str) -> ApfsResult<Vec<ApfsSnapshot>>;
}

impl VirtualFilesystem for ApfsWalker {
    fn fs_type(&self) -> &'static str { "apfs" }
    // ... trait methods operate on active_volume
}
```

3. **Multi-volume design (decision required):**

APFS containers typically hold multiple volumes. Standard macOS layout:
- Macintosh HD (System, read-only sealed in Sonoma+)
- Macintosh HD - Data (user data)
- Preboot
- Recovery
- VM (swap)
- Update

On macOS Big Sur+, System and Data are *firmlinked* — they present as
a single logical root to the user. iOS has a similar layout.

**Two valid designs:**

**Design A — One VFS per volume, composed via CompositeVfs:**
Each volume becomes an independent walker. CompositeVfs exposes them
as named roots like `/[Macintosh HD]/` and `/[Macintosh HD - Data]/`.
Plugins walk the composite or filter by volume name.

**Design B — Fused root with firmlink resolution:**
One walker presents a unified view that resolves firmlinks on the fly.
Matches user mental model on Big Sur+ but adds complexity.

**Decision for v13: Design A (CompositeVfs).** Reasons:
- Simpler implementation (matches NtfsWalker pattern exactly)
- Forensically transparent (examiner sees which volume each artifact
  came from)
- Can add Design B on top later without breaking changes
- iOS images don't use firmlinks — Design A is strictly correct there

The dispatcher (FS-DISPATCH-FINAL) will handle multi-volume logic by
returning CompositeVfs when ApfsWalker reports >1 volume.

4. **Sealed system volume handling:**

macOS Sonoma+ seals the System volume with a signed merkle tree.
Walker must:
- Detect sealed state from volume flags
- Walk read-only (always true for forensic use, but explicit)
- Never attempt to unseal or modify
- Report sealed status in `ApfsVolumeMetadata.sealed`

5. **Snapshot handling:**

APFS snapshots preserve point-in-time filesystem state — critical
forensic evidence. Expose:
- `list_snapshots(volume)` returning snapshot metadata
- `with_snapshot(volume, snapshot_id)` returning a walker that reads
  through the snapshot's B-tree

**Ground truth tests:**

Test against Apple images in Test Material:
- `2020 CTF - iOS` — iOS uses APFS internally
- `Jess_CTF_iPhone8` — iOS device
- macOS APFS image if available

```rust
#[test]
fn apfs_walker_opens_ios_ctf() {
    let ios_dir = Path::new("/Users/randolph/Wolfmark/Test Material/2020 CTF - iOS");
    if !ios_dir.exists() {
        return;
    }
    
    let image_path = find_apfs_image_in_dir(ios_dir);
    let Some(image_path) = image_path else { return };
    
    let image = open_evidence(&image_path).expect("open");
    let partitions = read_partitions(image.as_ref()).expect("partitions");
    
    let apfs_part = partitions.iter()
        .find(|p| matches!(p.fs_hint(), Some(FsType::Apfs)))
        .expect("find APFS partition");
    
    let walker = ApfsWalker::open(
        Arc::clone(&image),
        apfs_part.offset_bytes(),
        apfs_part.size_bytes(),
    ).expect("open APFS");
    
    assert!(!walker.volumes().is_empty(), "APFS container must have volumes");
    
    let has_data = walker.volumes().iter().any(|v| {
        matches!(v.role, ApfsVolumeRole::Data) || v.name.contains("Data")
    });
    assert!(has_data, "iOS must have a Data volume");
}
```

**Tests required:**
- Open APFS container via EvidenceImage
- Enumerate volumes with correct roles
- Set active volume, list its root
- Read a file from Data volume
- List snapshots on a volume
- Walk a snapshot
- Handle sealed system volume gracefully
- Extended attributes as alternate streams
- VirtualFilesystem trait compliance

Zero unwrap, zero unsafe, Clippy clean, 8+ tests minimum.

---

## SPRINT FS-HFSPLUS-1 — HFS+ Walker Wrapping Existing Parser

Create `crates/strata-fs/src/hfsplus_walker/mod.rs` promoting the
existing parser-only module at `crates/strata-fs/src/hfsplus.rs` to a
full walker.

**Problem statement:**
Pre-2017 Macs use HFS+. Still relevant for Time Machine backups
(which use HFS+ even on modern Macs) and older Mac casework. Strata
has an in-tree parser; v13 wraps it as a VFS walker.

**Implementation:**

Follow the NtfsWalker pattern.

```rust
pub struct HfsPlusWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    volume_header: Mutex<HfsPlusVolumeHeader>,
    catalog: Mutex<CatalogBtree>,
    extents: Mutex<ExtentsBtree>,
    attributes: Mutex<AttributesBtree>,
    case_sensitive: bool,  // HFSX if true
}
```

**Complete any missing parser features:**

Check existing `hfsplus.rs` for:
- Catalog B-tree walking (required for list_dir)
- Extents Overflow B-tree (required for fragmented files)
- Attributes B-tree (for xattrs)
- Data fork reading
- Resource fork reading
- Hard link resolution via indirect nodes
- Unicode filename handling (HFS+ uses NFC on disk, normalize to NFD
  for lookup — or vice versa depending on input)

Journal reading is optional for v13 (expose stub, implement later).

**Resource fork as alternate stream:**

HFS+ files have two forks:
- Data fork: the file content
- Resource fork: Mac-specific metadata, icons, etc.

Expose resource fork via the `alternate_streams` trait method with
name `"rsrc"`:

```rust
impl VirtualFilesystem for HfsPlusWalker {
    fn alternate_streams(&self, path: &str) -> VfsResult<Vec<String>> {
        let mut streams = self.list_xattrs(path)?;
        if self.has_resource_fork(path)? {
            streams.push("rsrc".to_string());
        }
        Ok(streams)
    }
    
    fn read_alternate_stream(&self, path: &str, stream: &str) -> VfsResult<Vec<u8>> {
        if stream == "rsrc" {
            self.read_resource_fork(path)
        } else {
            self.read_xattr(path, stream)
        }
    }
}
```

**Ground truth tests:**

If a Time Machine backup or older Mac image is available in Test
Material, use it. Otherwise synthesize a minimal HFS+ test fixture:

```rust
#[test]
fn hfsplus_walker_opens_test_fixture() {
    let fixture = Path::new("crates/strata-fs/tests/fixtures/hfsplus_small.img");
    if !fixture.exists() {
        return;
    }
    
    let image = open_evidence(fixture).expect("open");
    let walker = HfsPlusWalker::open(Arc::clone(&image), 0, image.size())
        .expect("open HFS+");
    
    let root = walker.list_dir("/").expect("list root");
    assert!(!root.is_empty(), "HFS+ root must have entries");
}
```

**Tests required:**
- Open HFS+ partition
- List root directory
- Read data fork
- Read resource fork where present
- Walk full filesystem
- Case-sensitive vs case-insensitive (HFSX detection)
- Hard link resolution
- VirtualFilesystem trait compliance

Zero unwrap, zero unsafe, Clippy clean, 6+ tests minimum.

---

## SPRINT FS-FAT-1 — FAT12/16/32/exFAT Walker (Native Read-Only)

Create `crates/strata-fs/src/fat_walker/mod.rs` wrapping the existing
parser-only modules at `crates/strata-fs/src/fat.rs` and `exfat.rs`.

**Problem statement:**
v9 discovered `fatfs` crate requires `ReadWriteSeek` which doesn't
fit read-only forensic use. Native implementation recommended.
v12 diagnostic shows parser-only modules exist — v13 promotes them
to a full walker.

**Implementation scope:**

```rust
pub enum FatVariant {
    Fat12,
    Fat16,
    Fat32,
    ExFat,
}

pub struct FatWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    variant: FatVariant,
    inner: Mutex<FatInner>,  // Wraps existing fat.rs / exfat.rs parsers
}
```

**Follow NtfsWalker pattern** — PartitionReader adapter, Mutex-wrapped
inner state, standard VirtualFilesystem trait impl.

**Verify existing parser coverage:**

Check `fat.rs` and `exfat.rs` for:
- Boot sector parsing + variant detection
- FAT table reading (12/16/32-bit cluster chains)
- Directory entry parsing (8.3 + LFN)
- exFAT entry groups (File/StreamExt/FileName)
- Cluster chain walking
- Deleted entry detection (first byte 0xE5)
- exFAT allocation bitmap

Add any missing pieces to bring parsers up to walker-ready state.

**Deleted file recovery:**

FAT is particularly forensics-friendly because deleted file directory
entries remain intact (just marked with 0xE5). Cluster chains may be
intact too if not overwritten. Implement:

```rust
fn list_deleted(&self) -> VfsResult<Vec<VfsDeletedEntry>> {
    // Scan all directory entries, find 0xE5-marked entries,
    // return with recoverable_content: bool based on whether FAT
    // entries for the first cluster still point to valid data.
}
```

**Test fixture:**

Commit a small FAT32 test fixture at
`crates/strata-fs/tests/fixtures/fat32_small.img`:

- 1 MB FAT32 image
- Known contents:
  - `/README.TXT` containing "test"
  - `/dir1/file1.dat` (multi-cluster file)
  - `/deleted.txt` (marked 0xE5, content in clusters)
  - LFN entry with filename `/longfilename_testcase.txt`

Generate via `mkfs.fat` in a build script or commit the binary fixture
directly. Fixture file is small enough to commit (~1 MB).

**Tests required:**
- Detect FAT12, FAT16, FAT32, exFAT correctly
- Read root directory on each variant
- Walk LFN entries
- Walk multi-cluster file (verify content)
- Recover deleted file from 0xE5 entry
- exFAT filename up to 255 UTF-16 characters
- Reject corrupted boot sector gracefully
- VirtualFilesystem trait compliance

Zero unwrap, zero unsafe, Clippy clean, 8+ tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 3 — DISPATCHER ACTIVATION
# ═══════════════════════════════════════════════════════════════════════

## SPRINT FS-DISPATCH-FINAL — Activate Live Walkers

Update `crates/strata-fs/src/fs_dispatch.rs` to dispatch to live
walkers instead of returning `Unsupported`.

**Problem statement:**
v11's FS-DISPATCH-1 shipped `detect_filesystem` with 12 passing unit
tests covering all 11 filesystem types. `open_filesystem()` currently
dispatches NTFS to live walker but returns `Err(VfsError::Unsupported)`
for ext4, APFS, HFS+, and FAT. Flip those arms now that walkers exist.

**Implementation:**

Update `fs_dispatch.rs:130–154`:

```rust
pub fn open_filesystem(
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
) -> VfsResult<Box<dyn VirtualFilesystem>> {
    let fs_type = detect_filesystem(image.as_ref(), partition_offset)?;
    open_filesystem_by_type(image, partition_offset, partition_size, fs_type)
}

pub fn open_filesystem_by_type(
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    fs_type: FsType,
) -> VfsResult<Box<dyn VirtualFilesystem>> {
    match fs_type {
        FsType::Ntfs => {
            let walker = NtfsWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Ext2 | FsType::Ext3 | FsType::Ext4 => {
            let walker = Ext4Walker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Apfs => {
            let walker = ApfsWalker::open(Arc::clone(&image), partition_offset, partition_size)?;
            // Multi-volume → CompositeVfs
            if walker.volumes().len() > 1 {
                let mut composite = CompositeVfs::new();
                for volume_meta in walker.volumes() {
                    let volume_walker = walker.with_active_volume(&volume_meta.name)?;
                    composite.add(&volume_meta.name, volume_walker);
                }
                Ok(Box::new(composite))
            } else {
                Ok(Box::new(walker))
            }
        }
        FsType::HfsPlus => {
            let walker = HfsPlusWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Fat12 | FsType::Fat16 | FsType::Fat32 | FsType::ExFat => {
            let walker = FatWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Unknown => Err(VfsError::Other(format!(
            "unknown filesystem at partition offset {}",
            partition_offset
        ))),
    }
}
```

**Integration tests (ties detection → open → trait methods):**

```rust
#[test]
fn dispatch_opens_ntfs_on_e01() {
    let image_path = Path::new("/Users/randolph/Wolfmark/Test Material/charlie-2009-11-12.E01");
    if !image_path.exists() { return; }
    
    let image = open_evidence(image_path).expect("open");
    let partitions = read_partitions(image.as_ref()).expect("partitions");
    
    let mut opened = false;
    for partition in partitions {
        if let Ok(fs) = open_filesystem(
            Arc::clone(&image),
            partition.offset_bytes(),
            partition.size_bytes(),
        ) {
            assert_eq!(fs.fs_type(), "ntfs");
            let root = fs.list_dir("/").expect("list root");
            assert!(!root.is_empty());
            opened = true;
            break;
        }
    }
    assert!(opened, "no NTFS partition opened on Charlie");
}

#[test]
fn dispatch_opens_apfs_multi_volume_as_composite() {
    // Similar, but verify CompositeVfs is returned when APFS has >1 volume
}

#[test]
fn dispatch_opens_ext4_on_linux_image() { ... }

#[test]
fn dispatch_opens_fat32_on_fixture() { ... }

#[test]
fn dispatch_returns_unknown_for_zero_bytes() { ... }
```

**Tests required:**
- NTFS dispatch (Charlie E01)
- ext4 dispatch (Linux image if available)
- APFS dispatch (iOS CTF, multi-volume → CompositeVfs)
- HFS+ dispatch (test fixture)
- FAT32 dispatch (test fixture)
- Unknown filesystem returns Err cleanly
- open_filesystem_by_type explicit FsType bypass works

Zero unwrap, zero unsafe, Clippy clean, 7+ tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 4 — HIGH-LEVERAGE PLUGIN MIGRATIONS
# ═══════════════════════════════════════════════════════════════════════

## SPRINT VFS-NATIVE-TOP3 — Migrate Vector, Chronicle, Trace

Migrate the three highest-artifact-yield plugins from vfs_materialize
scratch-copy to VFS-native streaming reads.

**Problem statement:**
v12's vfs_materialize bridge copies forensic-target files from the VFS
to a scratch directory before plugins run. This works but:
- Disk I/O cost: every large file is copied to scratch
- Memory cost: scratch directory can grow to 16 GiB per the limits
- Scaling ceiling: the 500k-file cap hits on enterprise disk images

Vector (2,465 artifacts on Charlie), Chronicle, and Trace are the
three highest-yield plugins per run. Migrating them to VFS-native
reads delivers the largest per-run performance improvement for the
smallest migration effort.

**The Phantom pattern (reference from v11):**

Before (host-fs):
```rust
fn run(&self, ctx: PluginContext) -> PluginResult {
    let root = Path::new(&ctx.root_path);
    let mut results = Vec::new();
    let files = match walk_dir(root) {
        Ok(f) => f,
        Err(_) => return Ok(results),
    };
    for path in files {
        // ... filename matching + parser calls
    }
    Ok(results)
}
```

After (VFS-native):
```rust
fn run(&self, ctx: PluginContext) -> PluginResult {
    let mut results = Vec::new();
    
    // Use ctx helpers — transparent VFS-vs-host-fs dispatch
    for target_path in ctx.find_by_name("target-filename") {
        if let Ok(data) = ctx.read_file(&target_path) {
            if data.len() <= size_gate_bytes {
                results.extend(parsers::xxx::parse(Path::new(&target_path), &data));
            }
        }
    }
    
    Ok(results)
}
```

**Mechanical rules (unchanged from v12 Phantom pattern):**

1. `std::fs::read_dir(&ctx.root_path)` → `ctx.list_dir(path)`
2. `std::fs::read(path)` → `ctx.read_file(path_str)`
3. `Path::new(&ctx.root_path).join(...).exists()` → `ctx.file_exists(path_str)`
4. `walk_dir(root)` + filename-match → `ctx.find_by_name("filename")`
5. Glob searches → `ctx.find_files("**/*.pattern")`
6. Size gates and other logic stay exactly as they were
7. Parser calls stay exactly as they were
8. Keep the host-fs fallback branch for backward compatibility

**Vector migration specifics:**

Vector at `plugins/strata-plugin-vector/src/lib.rs:230` calls
`std::fs::read_to_string(path)`. The plugin scans for PE headers,
macro indicators, IOCs, and known-tool fingerprints. Large file
iteration pattern — perfect candidate for streaming via `ctx.walk`.

**Chronicle migration specifics:**

Chronicle at `plugins/strata-plugin-chronicle/src/lib.rs:726` calls
`walk_dir(root)`. Reads Windows user activity artifacts: UserAssist
from NTUSER.DAT (already decoded via hive parser), RecentDocs, Jump
Lists (CFB files), TypedPaths, WordWheelQuery. Several targeted
filename patterns — uses `ctx.find_by_name` heavily.

**Trace migration specifics:**

Trace at `plugins/strata-plugin-trace/src/lib.rs:519` calls
`walk_dir(root)`. Reads execution artifacts: Prefetch files, BAM/DAM
registry entries (delegated to Phantom's hive output via
`prior_results`), scheduled task XML, BITS job data. Uses
`ctx.find_files("**/*.pf")` for Prefetch glob.

**Per-plugin acceptance:**

- All pre-migration tests pass unchanged
- New VFS-aware smoke test added (minimum 1 per plugin)
- Plugin still works when `ctx.vfs` is None (host-fs fallback)
- Plugin works when `ctx.vfs` is Some (VFS-backed)
- Charlie E01 re-run shows ≥2,300 Vector, ≥100 Chronicle, ≥50 Trace
  (matches or beats v12 scratch-copy counts)
- Clippy clean, no new unwrap/unsafe/println

**After this sprint:**

4 of 24 plugins are VFS-native (Phantom + Vector + Chronicle + Trace).
The remaining 20 continue working via vfs_materialize. The highest-
volume plugins now stream directly from the VFS, reducing scratch-copy
I/O by the majority of the per-run data volume.

The remaining 20 plugin migrations defer to v14 (mechanical work,
non-blocking).

Zero unwrap, zero unsafe, Clippy clean, 3 new smoke tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 5 — ACQUISITION-TRIM DIAGNOSTICS
# ═══════════════════════════════════════════════════════════════════════

## SPRINT EWF-TRIM-WARN-1 — Structured Acquisition-Trim Warnings

Update `crates/strata-evidence/src/e01.rs` to emit structured warnings
when the acquired EWF range doesn't cover a requested filesystem
structure.

**Problem statement:**

Terry's E01 and NPS Jean's E01 produce 4 artifacts each in the v12
field validation. Diagnostic investigation revealed the cause: both
images are acquisition-trimmed before the MFT offset. The NTFS walker
correctly opens the filesystem, reports the MFT location from the
boot sector, but `read_at` for the MFT offset returns zeros because
the acquisition didn't capture that range.

Today this surfaces as a silent 4-artifact result that looks
indistinguishable from a plugin bug. Examiners reviewing field
validation reports can't tell "image truncated" from "plugin broken."

**Implementation:**

Add structured warning to the E01 reader:

```rust
#[derive(Debug, Clone, Serialize)]
pub enum EwfWarning {
    OffsetBeyondAcquired {
        requested_offset: u64,
        acquired_ceiling: u64,
        segment_count: u32,
    },
    ChunkOffsetInvalid {
        chunk_number: u64,
        stored_offset: u64,
    },
    HashMismatch {
        expected: String,
        observed: String,
        algorithm: &'static str,
    },
}

impl E01Image {
    pub fn warnings(&self) -> &[EwfWarning] { &self.warnings }
    
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        // ... existing chunk lookup ...
        
        if chunk_not_found {
            // Instead of returning zeros silently, record a warning
            self.warnings.lock().push(EwfWarning::OffsetBeyondAcquired {
                requested_offset: offset,
                acquired_ceiling: self.highest_chunk_offset,
                segment_count: self.segments.len() as u32,
            });
            // Still return zeros (backward-compatible behavior), but
            // caller can now query warnings() to detect the condition.
            Ok(buf.len())
        } else {
            // ... normal chunk read
        }
    }
}
```

**CLI surface:**

Update `strata ingest run` to report warnings after completion:

```
=== Strata Ingest Run ===
Case: terry-case
...
Artifacts: 4 (persisted to ...)
Warnings: 1
  - E01 reader: 1 read(s) requested past acquired range (MFT at
    offset 0x3A000000 beyond segment ceiling 0x1C000000) — image
    may be acquisition-trimmed
```

**Audit log integration:**

Warnings also flow to `audit_log.jsonl` as first-class events:

```json
{"ts": "...", "kind": "ewf_offset_beyond_acquired", "requested": "0x3A000000", "ceiling": "0x1C000000"}
```

**Tests required:**

- Warning emitted when read_at offset beyond acquired range
- Warning NOT emitted for normal reads within range
- Multiple warnings accumulate, don't overwrite
- `warnings()` returns empty for normal images (Charlie, Jo)
- `warnings()` returns at least one for Terry / NPS Jean
- CLI surface prints warnings section when warnings present
- Audit log includes warning events

**After this sprint:**

Terry's 4-artifact result is now visibly labeled as "image
acquisition-trimmed before MFT, not a plugin failure." Field
validation reports clearly distinguish acquisition issues from tool
bugs. Examiners have actionable signal instead of silent surprise.

Zero unwrap, zero unsafe, Clippy clean, 6+ tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 7 — FULL MATRIX + HOUSEKEEPING
# ═══════════════════════════════════════════════════════════════════════

## SPRINT REGRESS-FULL-V13 — Matrix + Housekeeping + Report

Run the full Test Material matrix with all v13 capabilities enabled,
fold in the housekeeping items surfaced by the v12 diagnostic, and
produce the definitive v13 field validation report.

**Problem statement:**

v13 unlocked ext4, APFS, HFS+, and FAT. Every image type in Test
Material now has a working pipeline. Measure what actually comes out,
encode observed minimums as the v13 regression baseline, close the
housekeeping items, and publish the report.

**Matrix execution:**

Extend `matrix_regression.rs` (created in REGRESS-GUARD-1) with new
cases covering every image type:

```rust
// In matrix_regression.rs, add to V12_BASELINE_CASES or create a
// V13_EXPANDED_CASES list:

const V13_EXPANDED_CASES: &[RegressionCase] = &[
    // Windows (inherits from V12)
    // ... v12 cases ...
    
    // Linux
    RegressionCase {
        name: "ctf-linux-2022",
        image_subpath: "2022 CTF - Linux.7z",
        min_total_artifacts: 50,
        min_per_plugin: &[("Strata Arbor", 10)],
        reason_if_low: "ext4 walker or Arbor plugin regression",
    },
    
    // Chromebook
    RegressionCase {
        name: "ctf-chromebook-2021",
        image_subpath: "2021 CTF - Chromebook.tar",
        min_total_artifacts: 30,
        min_per_plugin: &[],
        reason_if_low: "ChromeOS detection or Carbon plugin regression",
    },
    
    // iOS
    RegressionCase {
        name: "ios-ctf-2020",
        image_subpath: "2020 CTF - iOS",
        min_total_artifacts: 100,
        min_per_plugin: &[("Strata Pulse", 20)],
        reason_if_low: "APFS walker or Pulse plugin regression",
    },
    RegressionCase {
        name: "ios-ctf-2021",
        image_subpath: "2021 CTF - iOS.zip",
        min_total_artifacts: 100,
        min_per_plugin: &[("Strata Pulse", 20)],
        reason_if_low: "APFS walker or Pulse plugin regression",
    },
    RegressionCase {
        name: "jess-iphone8",
        image_subpath: "Jess_CTF_iPhone8",
        min_total_artifacts: 100,
        min_per_plugin: &[("Strata Pulse", 30)],
        reason_if_low: "APFS walker or mobile plugin regression",
    },
    
    // Android
    RegressionCase {
        name: "android-14",
        image_subpath: "Android_14_Public_Image.tar",
        min_total_artifacts: 500,
        min_per_plugin: &[("Strata Carbon", 100)],
        reason_if_low: "Carbon plugin regression",
    },
    RegressionCase {
        name: "android-ctf-2019",
        image_subpath: "2019 CTF - Android",
        min_total_artifacts: 200,
        min_per_plugin: &[("Strata Carbon", 50)],
        reason_if_low: "Carbon plugin regression",
    },
    RegressionCase {
        name: "android-ctf-2022",
        image_subpath: "2022 CTF - Android-001.tar",
        min_total_artifacts: 300,
        min_per_plugin: &[("Strata Carbon", 75)],
        reason_if_low: "Carbon plugin regression",
    },
    
    // Windows CTF (large modern image)
    RegressionCase {
        name: "windows-ctf-2019",
        image_subpath: "2019 CTF - Windows-Desktop/2019 CTF - Windows-Desktop-001.E01",
        min_total_artifacts: 1000,
        min_per_plugin: &[
            ("Strata Phantom", 100),
            ("Strata Chronicle", 50),
        ],
        reason_if_low: "Windows 10 NTFS walker or modern Windows plugin regression",
    },
    
    // Other sources
    RegressionCase {
        name: "cellebrite-ufed",
        image_subpath: "Cellebrite.tar",
        min_total_artifacts: 100,
        min_per_plugin: &[],
        reason_if_low: "UFED unpack + mobile plugin regression",
    },
    RegressionCase {
        name: "memory-dump",
        image_subpath: "memdump-001.mem",
        min_total_artifacts: 5,
        min_per_plugin: &[("Strata Wraith", 3)],
        reason_if_low: "Wraith memory analysis regression",
    },
];
```

**Gap closure during this sprint:**

Run the matrix. For any case producing fewer artifacts than expected:

1. Open artifacts.sqlite for that case
2. Identify which plugin underperformed
3. Debug with known-good reference tool (Registry Explorer, ALEAPP, etc.)
4. Fix the plugin
5. Re-run the case
6. Document fix in commit message
7. Update minimum to observed count minus 5% margin

This sprint runs until the full matrix passes end-to-end.

**Housekeeping items (fold into this sprint):**

**H1. Reconcile plugin count in CLAUDE.md.**
CLAUDE.md references 20 or 26 plugins in various places. Actual count
is 24 (apex, arbor, carbon, chronicle, cipher, conduit, csam,
guardian, index, mactrace, netflow, nimbus, phantom, pulse, recon,
remnant, sentinel, sigma, specter, trace, tree-example, vault,
vector, wraith). Update all references to 24 (or 22 forensic plugins,
excluding index + tree-example).

**H2. Commit RESEARCH_v10_CRATES.md to the repo.**
The doc is referenced in SPRINTS_v10.md, SPRINTS_v11.md, and
SPRINTS_v12.md but doesn't exist on disk. Recreate it (from the
session state or Claude-draft version), commit to `docs/` directory.

**H3. Replace raw-grep quality gates with AST-aware checks.**
Current grep-based checks count 5,338 `.unwrap()` instances which
overstate production-code violations by including `#[cfg(test)]`
blocks. Add a new binary at `tools/strata-verify-quality/` that:
- Walks the AST via `syn` crate
- Counts `.unwrap()` / `unsafe{}` / `println!` in production code only
- Excludes test modules, CLI command handlers, and examples
- Outputs separate counts for "production", "test", "CLI"
- Runs as part of `cargo test --workspace`

This makes future quality gate enforcement meaningful instead of
theater.

**H4. Normalize the `walk_dir(root).unwrap_or_default()` anti-pattern.**
Pulse at `plugins/strata-plugin-pulse/src/lib.rs:123` uses this
pattern. Normalize to the `match walk_dir(root) { ... }` pattern
used elsewhere. Small but accumulated consistency win.

**Report:**

Publish `FIELD_VALIDATION_v13_REPORT.md` with:
- Per-image per-plugin artifact counts
- Acquisition-trim warnings (from EWF-TRIM-WARN-1)
- Performance numbers (total runtime per image)
- Plugin migration status (4/24 VFS-native, 20/24 via vfs_materialize)
- Housekeeping items closed
- Open items for v14

**Acceptance criteria:**

- [ ] Every image in Test Material produces ≥expected minimum artifacts
- [ ] FIELD_VALIDATION_v13_REPORT.md documents real numbers
- [ ] matrix_regression.rs encodes all cases as permanent guards
- [ ] CLAUDE.md plugin count accurate (24)
- [ ] RESEARCH_v10_CRATES.md committed to docs/
- [ ] tools/strata-verify-quality binary works and runs in CI
- [ ] Pulse normalized to match-pattern
- [ ] Test count: 3,661 + substantial growth (likely 3,900+)
- [ ] Clippy clean, no new unwrap/unsafe/println in production code
- [ ] All 9 load-bearing tests preserved
- [ ] No public API regressions

Zero unwrap, zero unsafe, Clippy clean, matrix passes end-to-end.

---

# ═══════════════════════════════════════════════════════════════════════
# COMPLETION CRITERIA
# ═══════════════════════════════════════════════════════════════════════

SPRINTS_v13.md is complete when:

**Regression guard (Part 1):**
- matrix_regression.rs exists and passes on current main
- Charlie, Jo, and acquisition-trim cases encoded as permanent guards
- CI fails if any v12 baseline regresses

**Filesystem walkers (Part 2):**
- Ext4Walker ships wrapping ext4-view crate
- ApfsWalker ships wrapping existing in-tree module (multi-volume via
  CompositeVfs)
- HfsPlusWalker ships promoting existing parser
- FatWalker ships wrapping existing fat.rs + exfat.rs
- Each ships with integration tests

**Dispatcher activation (Part 3):**
- open_filesystem routes to live walkers for all 10 filesystem types
- APFS multi-volume returns CompositeVfs
- No Unsupported arms remain

**High-leverage migrations (Part 4):**
- Vector, Chronicle, Trace are VFS-native
- Charlie artifact counts match or exceed v12 baseline
- Bridge-copy load reduced for the 3 highest-volume plugins

**Acquisition diagnostics (Part 5):**
- EWF reader emits OffsetBeyondAcquired warnings
- CLI surface reports warnings
- Audit log captures warnings
- Terry / NPS Jean results clearly labeled as image-truncated

**Full matrix + housekeeping (Part 7):**
- Every image in Test Material produces expected artifacts
- FIELD_VALIDATION_v13_REPORT.md published
- CLAUDE.md plugin count reconciled (24)
- RESEARCH_v10_CRATES.md committed
- AST-aware quality check binary ships
- Pulse anti-pattern normalized

**Quality gates (non-negotiable):**
- Test count: 3,661 + substantial growth
- All tests passing
- Clippy clean workspace-wide
- Zero new `.unwrap()`, zero `unsafe{}`, zero `println!` in production
  code (enforced by new AST-aware binary)
- All 9 load-bearing tests preserved
- No public API regressions

**The moment v13 ends:**

Every image type in Test Material produces real forensic artifacts
through the unified pipeline. The v12 baseline is protected by a
cargo-test-runnable regression guard. Acquisition-trim issues are
clearly diagnosed. Three of the highest-volume plugins stream from
the VFS natively, reducing bridge I/O pressure. CLAUDE.md is
reconciled, research doc committed, quality gates are meaningful.

The remaining 20 plugin migrations (low-volume / specialty plugins)
defer to v14 where they can be migrated as mechanical work without
architectural risk.

Strata covers the full forensic casework landscape the platform was
designed for. v14 is refinement, not foundation.

---

*STRATA AUTONOMOUS BUILD QUEUE v13*
*Wolfmark Systems — 2026-04-18*
*Part 1: Regression guard — protect what v12 shipped*
*Part 2: Filesystem walkers — ext4, APFS, HFS+, FAT*
*Part 3: Dispatcher activation*
*Part 4: High-leverage plugin migrations (Vector, Chronicle, Trace)*
*Part 5: Acquisition-trim diagnostics*
*Part 7: Full matrix + housekeeping*
*Mission: Unlock all image types and protect what's already built.*
*Execute all incomplete sprints in order. Ship everything.*
