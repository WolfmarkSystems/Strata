# SPRINTS_v12.md — STRATA COMPLETE THE FORENSIC PLATFORM
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md, SESSION_STATE_v11_BLOCKER.md, and SPRINTS_v12.md.
#         Execute all incomplete sprints in order."
# Last updated: 2026-04-18
# Prerequisite: SPRINTS_v1.md through SPRINTS_v11.md complete (3,656 tests passing)
#
# ═══════════════════════════════════════════════════════════════════════
# WHERE STRATA IS AT THE START OF v12
# ═══════════════════════════════════════════════════════════════════════
#
# v11 crossed the finish line. The command:
#
#   strata ingest run --source charlie-2009-11-12.E01 --case-dir ./charlie --auto
#
# now produces a case directory with artifacts.sqlite containing 539 real
# Windows forensic artifacts extracted by Phantom (the pilot plugin
# migrated in VFS-PLUGIN-1) walking a real NTFS filesystem mounted from
# real E01 bytes — no libewf, no libtsk, no FUSE, no kernel extensions.
#
# What shipped through v11:
#   - Evidence image readers (Raw/DD, E01/EWF pure-Rust, VMDK, VHD, VHDX)
#   - Partition walkers (MBR with extended chains, GPT with GUID decoding)
#   - NTFS walker (wrapping ntfs crate, full VirtualFilesystem trait)
#   - Filesystem auto-dispatch (10 filesystem types detected)
#   - Artifact persistence (per-case SQLite with 8 indexes)
#   - PluginContext.vfs field + Phantom as pilot plugin
#   - End-to-end CLI: ingest run → open image → partitions → FS dispatch
#     → CompositeVfs → plugins → artifacts.sqlite
#   - 3,656 workspace tests, zero unwrap/unsafe/println, clippy clean
#
# v12 completes the platform. No architectural surprises remain. Every
# sprint in this queue follows a pattern already established in v10/v11.
#
# ═══════════════════════════════════════════════════════════════════════
# THE MISSION
# ═══════════════════════════════════════════════════════════════════════
#
# v12 turns Strata from "a forensic tool that works on Windows E01s"
# into "a forensic tool that works on every image type in Test Material."
#
# When v12 completes:
#
#   - Every plugin queries ctx.vfs transparently (25 migrations)
#   - Every filesystem walker ships (ext4, APFS, HFS+, FAT)
#   - The dispatcher routes to live walkers (no Unsupported arms)
#   - Every image in Test Material produces expected artifact counts
#   - FIELD_VALIDATION_v12_REPORT.md documents the first all-pass matrix
#
# This is the queue where Strata becomes demonstrably complete for the
# forensic casework categories it was designed to handle.
#
# ═══════════════════════════════════════════════════════════════════════
# SCOPE
# ═══════════════════════════════════════════════════════════════════════
#
# 10 sprints across 4 parts:
#
# Part 1 — Plugin migration completion (25 plugins) ................ 5 sprints
# Part 2 — Remaining filesystem walkers ............................ 4 sprints
# Part 3 — Dispatcher activation ................................... 1 sprint
# Part 4 — Full matrix validation + final gap closure ............... 1 sprint
#
# ═══════════════════════════════════════════════════════════════════════
# DISCIPLINE — CARRIED FORWARD
# ═══════════════════════════════════════════════════════════════════════
#
# "Do not silently compromise the spec." If any sprint reveals a real
# blocker, stop, document in `SESSION_STATE_v12_BLOCKER.md`, continue
# with subsequent unblocked sprints.
#
# Ground truth validation is mandatory. Every filesystem walker ships
# with integration tests against a real image. Every plugin migration
# preserves pre-migration artifact counts on existing test fixtures.
#
# Quality gates: all tests pass from 3,656 start, clippy clean, zero
# new unwrap/unsafe/println, all 9 load-bearing tests preserved, no
# public API regressions.
#
# Plugin migrations use the Phantom pattern exactly. No creative
# interpretation. No "improvements while I'm here." Mechanical work.

---

## HOW TO EXECUTE

Read CLAUDE.md, SESSION_STATE_v11_BLOCKER.md, FIELD_VALIDATION_v11_REPORT.md,
RESEARCH_v10_CRATES.md, and SPRINTS_v12.md in that order. Then execute
each sprint below in order.

For each sprint:
1. Implement exactly as specified
2. Run `cargo test --workspace` — all tests must pass (starting from 3,656)
3. Run `cargo clippy --workspace -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!` introduced
5. Commit with message: "feat: [sprint-id] [description]" or "fix: [sprint-id] [description]"
6. Move to next sprint immediately

---

## COMPLETED SPRINTS (skip these)

None yet — this is v12.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 1 — PLUGIN MIGRATION COMPLETION (THE PHANTOM PATTERN)
# ═══════════════════════════════════════════════════════════════════════

## THE PHANTOM PATTERN (REFERENCE FOR ALL MIGRATION SPRINTS)

Phantom was migrated in v11 as the pilot. All other plugins follow the
identical pattern. Do not deviate from it.

**Before migration (direct std::fs):**
```rust
fn run(&self, ctx: PluginContext) -> PluginResult {
    let root = Path::new(&ctx.root_path);
    let mut results = Vec::new();
    let files = match walk_dir(root) {
        Ok(f) => f,
        Err(_) => return Ok(results),
    };
    for path in files {
        let name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if name == "system" {
            if let Some(data) = read_hive_gated(&path) {
                results.extend(parsers::system::parse(&path, &data));
            }
        }
    }
    Ok(results)
}
```

**After migration (VFS-aware via ctx helpers):**
```rust
fn run(&self, ctx: PluginContext) -> PluginResult {
    let mut results = Vec::new();
    
    for system_path in ctx.find_by_name("SYSTEM") {
        if let Ok(data) = ctx.read_file(&system_path) {
            if data.len() <= 512 * 1024 * 1024 {
                results.extend(parsers::system::parse(
                    Path::new(&system_path),
                    &data,
                ));
            }
        }
    }
    
    Ok(results)
}
```

**Mechanical rules:**

1. Replace `std::fs::read_dir(&ctx.root_path)` → `ctx.list_dir(path)`
2. Replace `std::fs::read(path)` → `ctx.read_file(path_str)`
3. Replace `Path::new(&ctx.root_path).join(...).exists()` → `ctx.file_exists(path_str)`
4. Replace `walk_dir(root)` + filename-match loops → `ctx.find_by_name("filename")`
5. Replace glob searches → `ctx.find_files("**/*.pattern")`
6. Size gates and other logic stay exactly as they were
7. Parser calls stay exactly as they were

**What NOT to do:**

- Do NOT refactor parsers during migration
- Do NOT change artifact schemas
- Do NOT "simplify" logic that survived v6/v7/v8 validation
- Do NOT remove tests, even if they seem redundant after migration
- Do NOT change plugin public APIs

**Acceptance per plugin:**

- All pre-migration tests pass unchanged
- New VFS-aware smoke test added (minimum 1)
- Plugin still works when `ctx.vfs` is None (host-fs fallback)
- Plugin works when `ctx.vfs` is Some (VFS-backed)
- Clippy clean, no new unwrap/unsafe/println

---

## SPRINT VFS-PLUGIN-WIN-1 — Migrate Core Windows Plugins

Migrate plugins whose primary target is Windows filesystems:

1. **Chronicle** — User activity (UserAssist, RecentDocs, Jump Lists, TypedPaths)
2. **Trace** — Execution (BAM/DAM, scheduled tasks, BITS, timestomp)
3. **Remnant** — Deleted evidence (Recycle Bin, USN journal, anti-forensic)
4. **Sentinel** — Windows event logs (EVTX structured parsing)
5. **Guardian** — Windows AV + system health (Defender, Avast, MalwareBytes, WER)

**Per plugin:**

1. Identify all std::fs calls
2. Apply the Phantom pattern
3. Run plugin's unit tests — must all pass
4. Run workspace tests — must all pass (3,656+)
5. Add one VFS-aware smoke test per plugin
6. Commit: `feat: VFS-PLUGIN-WIN-1-{chronicle,trace,remnant,sentinel,guardian} migrate to VFS helpers`

**Expected smoke test results (when a Windows image is mounted via VFS):**

- Chronicle: finds UserAssist entries, RecentDocs, TypedPaths — ≥5 artifacts minimum
- Trace: finds prefetch, BAM entries, scheduled tasks — ≥5 artifacts
- Remnant: finds Recycle Bin $I entries, USN journal activity — ≥3 artifacts
- Sentinel: finds Security/System/Application EVTX entries — ≥10 artifacts
- Guardian: finds Defender configuration, WER reports — ≥2 artifacts

If any of these produce 0 artifacts on a known-populated Windows image,
the migration has a bug. Debug before committing.

Zero unwrap, zero unsafe, Clippy clean, 5+ new smoke tests.

---

## SPRINT VFS-PLUGIN-WIN-2 — Migrate Remaining Windows Plugins

Migrate the remaining Windows-focused plugins:

6. **Cipher** — Windows credentials (WiFi, TeamViewer, AnyDesk, FileZilla)
7. **Nimbus** — Cloud apps (OneDrive, Dropbox, Teams, Slack, Zoom)
8. **Conduit** — Network history (WiFi profiles, RDP, VPN, hosts file, shares)
9. **Vector** — Static malware analysis (PE headers, macros, IOCs, known tools)
10. **Wraith** — Memory artifacts (hiberfil.sys, crash dumps, pagefile strings)

**Per plugin:** Apply the Phantom pattern. Same acceptance criteria as VFS-PLUGIN-WIN-1.

**Expected smoke test results:**

- Cipher: finds any stored creds on a typical image — ≥1 artifact (may be 0 on clean images)
- Nimbus: finds OneDrive/Dropbox SQLite databases — ≥1 artifact (if user has cloud apps)
- Conduit: finds WiFi profiles, hosts file entries — ≥2 artifacts
- Vector: finds at least the Windows system DLLs for PE metadata — ≥5 artifacts
- Wraith: finds pagefile.sys or hiberfil.sys — ≥1 artifact (if present)

Zero-artifact outputs are acceptable for plugins like Cipher where the
specific credential stores may not exist on every test image. Document
which images exercise which plugins in the smoke test comments.

Zero unwrap, zero unsafe, Clippy clean, 5+ new smoke tests.

---

## SPRINT VFS-PLUGIN-MAC-1 — Migrate macOS and Apple Plugins

Migrate plugins whose primary target is macOS/Apple artifacts:

11. **MacTrace** — macOS + iOS artifacts (LaunchAgents, KnowledgeC, PowerLog, SMS, WhatsApp)
12. **Apex** — Apple built-in apps (Messages, FaceTime, Notes, Photos, Safari, Maps, Wallet)
13. **Recon** — Identity extraction (usernames, emails, IPs, API keys — cross-platform but often used on macOS)

**Per plugin:** Apply the Phantom pattern.

**Expected smoke test results (on an iOS/macOS image):**

- MacTrace: finds KnowledgeC.db entries, LaunchAgent plists — ≥5 artifacts
- Apex: finds Messages sms.db, FaceTime callhistory, Notes database — ≥3 artifacts
- Recon: extracts email addresses from common files — ≥2 artifacts

Zero unwrap, zero unsafe, Clippy clean, 3+ new smoke tests.

---

## SPRINT VFS-PLUGIN-MOBILE-1 — Migrate Mobile + Cross-Platform Plugins

Migrate plugins for Android, iOS, and Google ecosystem:

14. **Carbon** — Google-built apps (Takeout, Chrome, Gmail, Drive, Photos, Maps, Play)
15. **Pulse** — Third-party mobile apps (Signal, Telegram, Discord, WhatsApp, TikTok)
16. **Specter** — Mobile + gaming (iOS KnowledgeC, PlayStation, Xbox, Nintendo Switch)

**Per plugin:** Apply the Phantom pattern.

**Expected smoke test results:**

- Carbon: on Takeout folder, finds Calendar, Chrome, Drive data — ≥2 artifacts
- Pulse: on iOS CTF, finds Signal/WhatsApp databases — ≥2 artifacts
- Specter: on iOS CTF, finds KnowledgeC entries — ≥5 artifacts

Zero unwrap, zero unsafe, Clippy clean, 3+ new smoke tests.

---

## SPRINT VFS-PLUGIN-FINAL — Migrate Specialty Plugins + Sigma

Migrate the final plugins:

17. **NetFlow** — Network forensics (PCAP, IIS/Apache logs, WLAN, exfil tools)
18. **ARBOR** — Linux artifacts (auth.log, bash history, systemd, cron, package managers)
19. **Vault** — Steganography + antiforensic (hidden partitions, secure deletion evidence)
20. **Sigma** — Correlation engine (MITRE ATT&CK mapping, kill chain, scoring)
21. **CSAM Scanner** — Known-bad hash detection (NSRL + law enforcement hash sets)

**Special notes:**

**Sigma** is different from the others. It primarily reads from
`prior_results` (other plugins' output), not from the filesystem
directly. Its VFS migration is minimal — mostly just standardizing
that any file reads it does use `ctx.read_file` for consistency.

**CSAM Scanner** requires hash set files (NSRL, LE hash sets). Its
file access pattern is different from artifact-extracting plugins —
it walks the VFS, hashes every file, compares against known-bad sets.
Migration still follows the Phantom pattern but `ctx.vfs.walk(|e|
...)` is the primary access pattern, not `ctx.find_by_name`.

**Plugin migration completion:** After this sprint, all 26 plugins
work transparently with both VFS-backed and host-fs-backed evidence.

**Acceptance criteria (queue-level, checked at end of this sprint):**

- [ ] All 26 plugins migrated (including Phantom pilot from v11)
- [ ] All pre-v12 tests still pass
- [ ] Every plugin has at least one VFS-aware smoke test
- [ ] Full `cargo test --workspace` passes
- [ ] Clippy clean workspace-wide
- [ ] No public API regressions

Zero unwrap, zero unsafe, Clippy clean, 5+ new smoke tests.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 2 — REMAINING FILESYSTEM WALKERS
# ═══════════════════════════════════════════════════════════════════════

## SPRINT FS-EXT4-1 — ext4 Walker Wrapping ext4-view Crate

Create `crates/strata-fs/src/ext4/mod.rs`.

**Problem statement:**
Linux servers, Chromebook Crostini, Android userdata partitions use
ext4. RESEARCH_v10_CRATES.md established `ext4-view = "0.9"` as the
correct crate (NOT the stale `ext4` crate by FauxFaux).

**Implementation:**

Add to `crates/strata-fs/Cargo.toml`:
```toml
ext4-view = "0.9"
```

Follow the NtfsWalker pattern from v10:

```rust
use ext4_view::{Ext4, Ext4Read};

pub struct Ext4Walker {
    fs: Mutex<Ext4>,
    partition_offset: u64,
    partition_size: u64,
}

pub struct Ext4ReadAdapter {
    reader: PartitionReader,  // Established in v10 for NTFS
}

impl Ext4Read for Ext4ReadAdapter {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.reader.seek(SeekFrom::Start(offset))?;
        self.reader.read_exact(buf)?;
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
        let fs = Ext4::load(Box::new(adapter))?;
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
        let fs = self.fs.lock().expect("ext4 lock poisoned");
        let mut entries = Vec::new();
        for entry in fs.read_dir(path)? {
            let entry = entry?;
            entries.push(ext4_entry_to_vfs(&entry, &fs)?);
        }
        Ok(entries)
    }
    
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let fs = self.fs.lock().expect("ext4 lock poisoned");
        fs.read(path).map_err(|e| VfsError::from(e))
    }
    
    // ... other trait methods
}
```

**ext4-specific features to expose:**

- Extended attributes via `alternate_streams` (xattrs like `security.selinux`, `user.*`, `trusted.*`)
- Deleted inode detection via `list_deleted()` (dtime != 0)
- Birth time in VfsMetadata (ext4 crtime, Unix epoch)
- Extents-based vs block-mapping distinction in `VfsSpecific::Ext4`

**Ground truth tests:**

Check Test Material for Linux images:
- `2022 CTF - Linux.7z` — unpack and test
- `digitalcorpora/linux-dc3dd/` — check if extracts to ext4
- Any other Linux image available

```rust
#[test]
fn ext4_walker_opens_linux_ctf() {
    let linux_image = find_first_linux_image_in_test_material();
    if linux_image.is_none() {
        eprintln!("SKIP: no Linux image in Test Material");
        return;
    }
    
    let image = open_evidence(&linux_image.unwrap()).expect("open");
    let partitions = read_partitions(image.as_ref()).expect("partitions");
    
    let ext4_part = partitions.iter()
        .find(|p| p.fs_hint() == Some(FsType::Ext4) 
                  || p.fs_hint() == Some(FsType::Ext3)
                  || p.fs_hint() == Some(FsType::Ext2))
        .expect("find ext4 partition");
    
    let walker = Ext4Walker::open(
        Arc::clone(&image),
        ext4_part.offset_bytes(),
        ext4_part.size_bytes(),
    ).expect("open ext4");
    
    // Standard Linux filesystem layout
    let root = walker.list_dir("/").expect("list root");
    let root_names: HashSet<String> = root.iter().map(|e| e.name.clone()).collect();
    
    assert!(root_names.contains("etc"), "Linux root must contain /etc");
    assert!(root_names.contains("home") || root_names.contains("root"), 
            "Linux root must contain /home or /root");
    assert!(root_names.contains("var"), "Linux root must contain /var");
    
    // Standard system files
    let passwd = walker.read_file("/etc/passwd").expect("read passwd");
    assert!(!passwd.is_empty(), "/etc/passwd must not be empty");
    assert!(passwd.starts_with(b"root:") || passwd.windows(5).any(|w| w == b"root:"),
            "/etc/passwd must contain root entry");
}
```

**Tests required:**
- Open ext4 partition via EvidenceImage
- List root directory (/etc, /home, /var, /usr present)
- Read /etc/passwd (non-empty, contains root)
- Walk full filesystem, count > 1000 entries
- Read extended attribute on a file
- Find deleted inode via list_deleted
- Handle symlinks correctly
- ext2 fallback works (ext4-view supports both)

Zero unwrap, zero unsafe, Clippy clean, eight tests minimum.

---

## SPRINT FS-APFS-1 — APFS Walker Wrapping Existing In-Tree Module

Wire existing `crates/strata-fs/src/apfs/` to VirtualFilesystem trait.

**Problem statement:**
Strata has an in-tree APFS walker (~850 lines, 6 tests passing per v8
session state). No mature pure-Rust APFS crate exists in the ecosystem.
Wrap the existing walker in ApfsWalker with VirtualFilesystem trait.

**Implementation:**

1. **Evaluate existing in-tree module:**
```bash
find crates/strata-fs/src/apfs -name "*.rs" -exec wc -l {} \;
cargo test -p strata-fs apfs
```

Verify what the existing module does:
- NXSB Container Super Block parsing
- APSB Volume Super Block parsing
- B-tree walking (root, extent, snapshot trees)
- OMAP (Object Map) resolution
- File/directory inode parsing
- Extended attributes (xattrs)
- Snapshots

2. **Add PartitionReader adapter (same as NTFS):**
The existing APFS module likely reads from raw bytes already. Wire it
to receive a `PartitionReader` that reads from the evidence image at
the partition offset.

3. **Wrap in ApfsWalker:**

```rust
pub struct ApfsWalker {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    container: Mutex<ApfsContainer>,
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
    pub fn list_snapshots(&self, volume: &str) -> ApfsResult<Vec<ApfsSnapshot>>;
}
```

4. **CompositeVfs integration:**

When an APFS container has multiple volumes (standard macOS layout has
System + Data + Preboot + Recovery + VM), the dispatcher should return
a CompositeVfs with each volume as a named root. Implementation detail
for FS-DISPATCH-FINAL.

5. **Sealed system volume handling:**
macOS Sonoma+ has sealed system volumes. The walker must accept sealed
state as valid (don't try to unseal) and walk the data read-only anyway.
Forensic examination is always read-only.

6. **Snapshot handling:**
APFS snapshots are critical forensic evidence. Expose via
`list_snapshots(volume)` and `walk_snapshot(volume, snapshot_id)`.
Plugins can walk snapshots independently of the current volume state.

**VirtualFilesystem trait implementation:**

Same pattern as NtfsWalker and Ext4Walker. Trait methods acquire the
container mutex briefly, operate on the active volume.

**Ground truth tests:**

Test against Apple images in Test Material:
- `2020 CTF - iOS` (iOS uses APFS internally)
- `Jess_CTF_iPhone8` (iOS device)
- Any macOS APFS image available

```rust
#[test]
fn apfs_walker_opens_ios_ctf() {
    let ios_dir = "/Users/randolph/Wolfmark/Test Material/2020 CTF - iOS";
    if !Path::new(ios_dir).exists() {
        return;
    }
    
    // Locate APFS image file in the directory
    let image_path = find_apfs_image_in_dir(ios_dir);
    if image_path.is_none() {
        return;
    }
    
    let image = open_evidence(&image_path.unwrap()).expect("open");
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
    eprintln!("✓ iOS APFS: {} volumes found", walker.volumes().len());
    
    // iOS-specific layout
    let has_data_volume = walker.volumes().iter().any(|v| {
        matches!(v.role, ApfsVolumeRole::Data) || v.name.contains("Data")
    });
    assert!(has_data_volume, "iOS must have a Data volume");
}
```

**Tests required:**
- Open APFS container
- Enumerate volumes
- Read file from Data volume
- List snapshots
- Walk a snapshot
- Handle sealed system volume gracefully
- Extended attributes as alternate streams
- VirtualFilesystem trait compliance

Zero unwrap, zero unsafe, Clippy clean, eight tests minimum.

---

## SPRINT FS-HFSPLUS-1 — HFS+ Walker Wrapping Existing In-Tree Module

Wire existing `crates/strata-fs/src/hfsplus/` to VirtualFilesystem trait.

**Problem statement:**
Pre-2017 Macs use HFS+. Still relevant for Time Machine backups and
older Mac casework. No mature Rust crate exists. Strata has in-tree
HFS+ module per v8 session state.

**Implementation:**

1. **Evaluate existing in-tree module completeness:**
```bash
find crates/strata-fs/src/hfsplus -name "*.rs" -exec wc -l {} \;
cargo test -p strata-fs hfsplus
```

2. **Complete any missing features:**
- Catalog B-tree walking (required)
- Extents Overflow B-tree (required for fragmented files)
- Attributes B-tree (for xattrs)
- Data fork + resource fork reading (required)
- Journal reading (optional for v12)
- Hard link resolution via indirect nodes

3. **Wrap in HfsPlusWalker:**

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

4. **Resource fork as alternate stream:**

HFS+ files can have two forks: data fork (the file content) and
resource fork (Mac-specific metadata/resources). Expose resource
fork via alternate stream pattern:

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

If Time Machine backup or older Mac image available in Test Material,
test against it. Otherwise synthesize a minimal HFS+ test fixture.

```rust
#[test]
fn hfsplus_walker_opens_test_image() {
    let fixture = "crates/strata-fs/tests/fixtures/hfsplus_minimal.img";
    if !Path::new(fixture).exists() {
        return;
    }
    
    // Raw image test (no partition table — direct HFS+)
    let image = open_evidence(Path::new(fixture)).expect("open");
    let walker = HfsPlusWalker::open(Arc::clone(&image), 0, image.size())
        .expect("open HFS+");
    
    let root = walker.list_dir("/").expect("list root");
    assert!(!root.is_empty(), "HFS+ root must have entries");
}
```

**Tests required:**
- Open HFS+ partition
- List root directory
- Read data fork of regular file
- Read resource fork where present
- Walk full filesystem
- Case-sensitive vs case-insensitive detection
- Hard link resolution

Zero unwrap, zero unsafe, Clippy clean, six tests minimum.

---

## SPRINT FS-FAT-1 — FAT12/16/32/exFAT Walker (Native Implementation)

Create `crates/strata-fs/src/fat/mod.rs` — native read-only parser.

**Problem statement:**
v9 discovered the `fatfs` crate requires `ReadWriteSeek` which doesn't
fit read-only forensic use. RESEARCH_v10_CRATES.md recommends native
implementation (~500 LOC).

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
    boot: FatBootSector,
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    fat_offset: u64,
    data_offset: u64,
    root_dir_offset: u64,        // FAT12/16 fixed root dir
    root_cluster: u32,            // FAT32/exFAT root cluster
    total_clusters: u32,
}
```

**Parsing responsibilities:**

1. **Boot sector (offset 0 of partition):**
   - Parse BPB (BIOS Parameter Block)
   - Detect variant by file system type string:
     - FAT12/FAT16: offset 54 of boot sector
     - FAT32: offset 82
     - exFAT: offset 3 ("EXFAT   ")

2. **FAT table:**
   - FAT12: 12-bit packed entries (3 bytes = 2 entries)
   - FAT16: 16-bit entries
   - FAT32: 32-bit entries (upper 4 bits reserved)
   - exFAT: 32-bit entries, but cluster allocation is via bitmap, not FAT

3. **Directory entries:**
   - Standard 8.3 entry (32 bytes)
   - VFAT Long File Name entries (32 bytes each, preceding the 8.3)
   - exFAT: File (0x85) + Stream Extension (0xC0) + File Name (0xC1) groups

4. **Cluster chain walking:**
   - Follow FAT entries until end-of-chain marker
   - FAT12: 0xFF8–0xFFF
   - FAT16: 0xFFF8–0xFFFF
   - FAT32: 0x0FFFFFF8–0x0FFFFFFF

5. **Deleted file recovery:**
   - 8.3 entries starting with 0xE5 are deleted but potentially recoverable
   - Expose via `list_deleted()` and `read_deleted()`

**Test fixture:**

Create a small FAT32 image for testing:

```rust
// In build.rs or test setup:
// Generate a 1 MB FAT32 image with known contents:
//   - /README.TXT containing "test"
//   - /dir1/file1.dat (multi-cluster)
//   - /deleted.txt (marked deleted, content still in clusters)
```

Alternatively, use a fixture committed to the repo at
`crates/strata-fs/tests/fixtures/fat32_small.img`.

**Tests required:**
- Detect FAT12, FAT16, FAT32, exFAT correctly
- Read root directory on each variant
- Walk LFN (Long File Name) entries
- Walk multi-cluster file
- Recover deleted file from 0xE5 entry
- Handle exFAT filename up to 255 characters
- Reject corrupted boot sector gracefully
- VirtualFilesystem trait compliance

Zero unwrap, zero unsafe, Clippy clean, eight tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 3 — DISPATCHER ACTIVATION
# ═══════════════════════════════════════════════════════════════════════

## SPRINT FS-DISPATCH-FINAL — Activate Live Walkers in Dispatcher

Update `crates/strata-fs/src/dispatch.rs`.

**Problem statement:**
v11's FS-DISPATCH-1 shipped filesystem auto-detection with "Unsupported"
arms for ext4, APFS, HFS+, and FAT. Now that all walkers exist, flip
those arms to dispatch to live walkers.

**Implementation:**

```rust
pub fn open_filesystem(
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
) -> FsResult<Box<dyn VirtualFilesystem>> {
    let fs_type = detect_filesystem(image.as_ref(), partition_offset)?;
    open_filesystem_by_type(image, partition_offset, partition_size, fs_type)
}

pub fn open_filesystem_by_type(
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
    fs_type: FsType,
) -> FsResult<Box<dyn VirtualFilesystem>> {
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
            let walker = ApfsWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::HfsPlus => {
            let walker = HfsPlusWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Fat12 | FsType::Fat16 | FsType::Fat32 | FsType::ExFat => {
            let walker = FatWalker::open(image, partition_offset, partition_size)?;
            Ok(Box::new(walker))
        }
        FsType::Unknown => Err(FsError::UnknownFilesystem),
    }
}
```

**APFS multi-volume handling:**

APFS containers have multiple volumes. The dispatcher should return a
CompositeVfs that exposes each volume as a named root:

```rust
// Inside the APFS arm:
FsType::Apfs => {
    let walker = ApfsWalker::open(Arc::clone(&image), partition_offset, partition_size)?;
    
    if walker.volumes().len() > 1 {
        // Multi-volume APFS — build CompositeVfs
        let mut composite = CompositeVfs::new();
        for volume_meta in walker.volumes() {
            let name = volume_meta.name.clone();
            // Wrap walker with active_volume set to this volume
            // Requires ApfsWalker to support cloning with different active_volume
            composite.add(&name, Box::new(walker.with_active_volume(&name)?));
        }
        Ok(Box::new(composite))
    } else {
        // Single-volume APFS — return walker directly
        Ok(Box::new(walker))
    }
}
```

**Integration tests:**

```rust
#[test]
fn dispatch_opens_ntfs_on_e01() {
    let image = open_evidence(Path::new("nps-2008-jean.E01")).expect("open");
    let partitions = read_partitions(image.as_ref()).expect("partitions");
    
    for partition in partitions {
        if let Ok(fs) = open_filesystem(
            Arc::clone(&image),
            partition.offset_bytes(),
            partition.size_bytes(),
        ) {
            assert_eq!(fs.fs_type(), "ntfs");
            let root = fs.list_dir("/").expect("list root");
            assert!(!root.is_empty());
            return;
        }
    }
    panic!("no filesystem opened on NPS Jean");
}

#[test]
fn dispatch_opens_apfs_on_ios_image() { /* ... */ }

#[test]
fn dispatch_opens_ext4_on_linux_image() { /* ... */ }
```

**Tests required:**
- NTFS dispatch (against Jean E01)
- ext4 dispatch (against Linux image if available)
- APFS dispatch (against iOS CTF)
- HFS+ dispatch (against test fixture)
- FAT32 dispatch (against test fixture)
- Multi-volume APFS returns CompositeVfs
- Unknown filesystem returns Err cleanly

Zero unwrap, zero unsafe, Clippy clean, seven tests minimum.

---

# ═══════════════════════════════════════════════════════════════════════
# PART 4 — FULL MATRIX VALIDATION + FINAL GAP CLOSURE
# ═══════════════════════════════════════════════════════════════════════

## SPRINT REGRESS-FULL — Full Test Material Matrix + Final Report

Run the full Test Material matrix and produce the definitive field
validation report.

**Problem statement:**
This is the capstone of v6 through v12. Every image type now has a
working pipeline: evidence reader → partition walker → filesystem
walker → file index → plugin migration → artifact persistence.
Measure what actually comes out.

**Implementation:**

Extend `tests/regression/matrix_v12.rs` based on v11's matrix:

```rust
#[test]
#[ignore] // Run manually: cargo test --release --ignored matrix_v12
fn v12_full_matrix_final_validation() {
    let test_material = "/Users/randolph/Wolfmark/Test Material";
    let results_root = PathBuf::from("/tmp/strata-v12-regression");
    let _ = fs::remove_dir_all(&results_root);
    fs::create_dir_all(&results_root).unwrap();
    
    let cases: Vec<Case> = vec![
        // Windows XP family
        Case {
            name: "nps-jean",
            path: format!("{}/nps-2008-jean.E01", test_material),
            min_artifacts_total: 200,
            min_per_plugin: &[
                ("Strata Phantom", 30),
                ("Strata Chronicle", 15),
                ("Strata Trace", 10),
                ("Strata Remnant", 5),
                ("Strata Sentinel", 5),
            ],
            expected_classification: "WindowsXp",
        },
        Case {
            name: "charlie",
            path: format!("{}/charlie-2009-11-12.E01", test_material),
            min_artifacts_total: 500,  // v11 showed 539
            min_per_plugin: &[
                ("Strata Phantom", 400),  // v11 showed 535
                ("Strata Chronicle", 10),
                ("Strata Trace", 5),
            ],
            expected_classification: "WindowsXp",
        },
        Case {
            name: "terry",
            path: format!("{}/terry-2009-12-03.E01", test_material),
            min_artifacts_total: 200,
            min_per_plugin: &[("Strata Phantom", 30)],
            expected_classification: "WindowsXp",
        },
        
        // Modern Windows
        Case {
            name: "windows-ftk",
            path: format!("{}/windows-ftkimager-first.E01", test_material),
            min_artifacts_total: 300,
            min_per_plugin: &[
                ("Strata Phantom", 50),
                ("Strata Chronicle", 30),
                ("Strata Trace", 20),
                ("Strata Sentinel", 10),
            ],
            expected_classification: "Windows7Plus",
        },
        Case {
            name: "ctf-windows-2019",
            path: format!("{}/2019 CTF - Windows-Desktop/2019 CTF - Windows-Desktop-001.E01", test_material),
            min_artifacts_total: 1000,
            min_per_plugin: &[
                ("Strata Phantom", 100),
                ("Strata Chronicle", 80),
                ("Strata Trace", 50),
                ("Strata Sentinel", 30),
                ("Strata Guardian", 5),
            ],
            expected_classification: "Windows10Plus",
        },
        
        // Mobile
        Case {
            name: "jess-iphone8",
            path: format!("{}/Jess_CTF_iPhone8", test_material),
            min_artifacts_total: 100,
            min_per_plugin: &[
                ("Strata Pulse", 30),
                ("Strata Apex", 20),
                ("Strata Specter", 20),
            ],
            expected_classification: "IosCtf",
        },
        Case {
            name: "2020-ios",
            path: format!("{}/2020 CTF - iOS", test_material),
            min_artifacts_total: 100,
            min_per_plugin: &[("Strata Pulse", 20)],
            expected_classification: "IosCtf",
        },
        Case {
            name: "2021-ios",
            path: format!("{}/2021 CTF - iOS.zip", test_material),
            min_artifacts_total: 100,
            min_per_plugin: &[],
            expected_classification: "IosCtf",
        },
        
        // Android
        Case {
            name: "android14",
            path: format!("{}/Android_14_Public_Image.tar", test_material),
            min_artifacts_total: 500,
            min_per_plugin: &[
                ("Strata Carbon", 100),
                ("Strata Pulse", 50),
            ],
            expected_classification: "Android",
        },
        Case {
            name: "2019-android",
            path: format!("{}/2019 CTF - Android", test_material),
            min_artifacts_total: 200,
            min_per_plugin: &[("Strata Carbon", 50)],
            expected_classification: "Android",
        },
        Case {
            name: "2022-android",
            path: format!("{}/2022 CTF - Android-001.tar", test_material),
            min_artifacts_total: 300,
            min_per_plugin: &[("Strata Carbon", 75)],
            expected_classification: "Android",
        },
        
        // Linux
        Case {
            name: "2022-linux",
            path: format!("{}/2022 CTF - Linux.7z", test_material),
            min_artifacts_total: 100,
            min_per_plugin: &[("Strata ARBOR", 20)],
            expected_classification: "Linux",
        },
        
        // Chromebook
        Case {
            name: "2021-chromebook",
            path: format!("{}/2021 CTF - Chromebook.tar", test_material),
            min_artifacts_total: 50,
            min_per_plugin: &[],
            expected_classification: "ChromeOs",
        },
        
        // Other sources
        Case {
            name: "takeout",
            path: format!("{}/Takeout", test_material),
            min_artifacts_total: 10,  // Up from v11's 4
            min_per_plugin: &[("Strata Carbon", 5)],
            expected_classification: "GoogleTakeout",
        },
        Case {
            name: "cellebrite",
            path: format!("{}/Cellebrite.tar", test_material),
            min_artifacts_total: 100,
            min_per_plugin: &[],
            expected_classification: "UfedTar",
        },
        Case {
            name: "memory-dump",
            path: format!("{}/memdump-001.mem", test_material),
            min_artifacts_total: 5,
            min_per_plugin: &[("Strata Wraith", 3)],
            expected_classification: "MemoryDump",
        },
    ];
    
    // ... (use same execution loop as v11's matrix, writing to
    // FIELD_VALIDATION_v12_REPORT.md)
    
    // Additional reporting beyond v11:
    // - Plugin-by-plugin performance across the matrix
    // - Artifact density (artifacts per GB) per image
    // - Total runtime per image
    // - Sigma correlation count per case
    
    // Final acceptance:
    assert_eq!(failed, 0, "v12 full matrix: {} failures", failed);
}
```

**Gap closure during this sprint:**

If any case produces fewer artifacts than expected:

1. Open the artifacts.sqlite for that case
2. Identify which plugin underperformed
3. Debug with known-good tool (Registry Explorer, ALEAPP, etc.)
4. Fix the underperforming plugin
5. Re-run the case
6. Document fix in commit message
7. Update matrix_v12.rs with actual observed count as new minimum

This sprint runs until FIELD_VALIDATION_v12_REPORT.md reports all-pass
across the full Test Material matrix.

**Deliverables:**

1. `FIELD_VALIDATION_v12_REPORT.md` — definitive field validation with
   real per-plugin per-image artifact counts
2. `matrix_v12.rs` test harness with encoded minimums (becomes regression
   guard for all future development)
3. Any plugin fixes committed individually with test coverage

**Acceptance criteria:**

- [ ] Every image in Test Material produces ≥expected minimum artifacts
- [ ] FIELD_VALIDATION_v12_REPORT.md shows all-pass
- [ ] matrix_v12.rs encodes observed minimums for future regression detection
- [ ] Test count has grown substantially from v11's 3,656
- [ ] Clippy clean, no new unwrap/unsafe/println
- [ ] All 9 load-bearing tests preserved

Zero unwrap, zero unsafe, Clippy clean, final matrix passes end-to-end.

---

# ═══════════════════════════════════════════════════════════════════════
# COMPLETION CRITERIA
# ═══════════════════════════════════════════════════════════════════════

SPRINTS_v12.md is complete when:

**Plugin migration (Part 1):**
- All 26 plugins use ctx helpers instead of direct std::fs
- Phantom pattern applied uniformly
- Every plugin has a VFS-aware smoke test
- All pre-v12 tests still pass

**Filesystem walkers (Part 2):**
- Ext4Walker ships wrapping ext4-view
- ApfsWalker ships wrapping existing in-tree module
- HfsPlusWalker ships wrapping existing in-tree module
- FatWalker ships as native read-only implementation
- Each has integration tests against real images where available

**Dispatcher activation (Part 3):**
- open_filesystem dispatches to live walkers for all 10 filesystem types
- APFS multi-volume returns CompositeVfs
- Integration tests verify dispatch correctness

**Full matrix validation (Part 4):**
- Every Test Material image produces ≥expected minimum artifacts
- FIELD_VALIDATION_v12_REPORT.md documents the all-pass matrix
- matrix_v12.rs becomes permanent regression guard

**Quality gates (non-negotiable):**
- Test count: 3,656 + substantial growth (likely 4,000+)
- All tests passing
- Clippy clean workspace-wide
- Zero new `.unwrap()`, zero `unsafe{}`, zero `println!`
- All 9 load-bearing tests preserved
- No public API regressions

**The moment v12 ends:**

Strata is a complete forensic platform. Every image type in Test Material
— Windows E01s, macOS/iOS images, Android images, Linux images,
Chromebook images, Google Takeout, Cellebrite UFED, memory dumps — 
produces real forensic artifacts through a unified pipeline with full
audit logging, artifact persistence, and forensic chain of custody.

The architectural work that began in v9 is complete. Every piece of
Strata serves its intended purpose. Future work moves to UI integration,
plugin enhancement, new evidence sources, and commercial polish — not
foundational architecture.

Strata is done being built. Strata moves to being used.

---

*STRATA AUTONOMOUS BUILD QUEUE v12*
*Wolfmark Systems — 2026-04-18*
*Part 1: Plugin migration completion (25 remaining)*
*Part 2: Filesystem walkers (ext4, APFS, HFS+, FAT)*
*Part 3: Dispatcher activation*
*Part 4: Full matrix validation + final gap closure*
*Mission: Complete the forensic platform.*
*Execute all incomplete sprints in order. Ship everything.*
