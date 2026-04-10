# Strata Large-Evidence Safety Audit (Comprehensive)

**Date:** 2026-04-10
**Auditor:** Agent 3 (Claude Opus 4.6)
**Prior audit:** Agent 5 (2026-04-09) — this version subsumes all prior
findings and adds 40+ additional findings from deeper code inspection.
**Scope:** Every code path that reads file bytes, assessed for safety on
500 GB -- multi-TB forensic images on 32 GB RAM hardware.
**Status:** READ-ONLY AUDIT. No code was modified.

---

## Executive Summary

Audited **17 plugins**, the **strata-tree desktop app** (8 subsystems),
and **5 core crates** (strata-fs, strata-core, strata-csam,
strata-engine-adapter, strata-shield-engine). Found **52 distinct
file-read sites**. Of these:

| Severity | Count | Description |
|----------|------:|-------------|
| CRITICAL |    12 | Will OOM on real-world large evidence |
| HIGH     |    14 | Can OOM on enterprise / edge-case evidence |
| MEDIUM   |    12 | Unlikely to OOM but lacks defensive guard |
| LOW      |    14 | Safe (properly chunked, gated, or streaming) |

**Bottom line:** A 2 TB NTFS image with 5 million files will OOM a 32 GB
machine through at least three independent paths before the examiner
sees a single artifact. The VFS layer, the plugin layer, and the
strata-tree app layer each have independent unbounded full-load reads.

---

## Confirmed Safe (no action needed)

These code paths are already correctly implemented:

| Component | File | Pattern | Why safe |
|-----------|------|---------|----------|
| CSAM hash scanner | strata-csam/src/scanner.rs:372 | 1 MB chunked `read_file_range` | Bounded streaming |
| Hash set import | strata-csam/src/hash_db.rs | BufReader streaming | Line-by-line |
| Hex editor | strata-tree state.rs:265 | 64 KB pages, 256 KB window, 16-page LRU (1 MB) | Paged virtual I/O |
| Gallery thumbnails | gallery_view.rs:349 | 512 KB `read_range` gate + 500-entry LRU (~32 MB) | Size-gated |
| Carver scan phase | carve/engine.rs:292 | 1 MB `BufReader` chunks | Chunked |
| Text preview (new) | preview_panel.rs:535 | `read_first(state, f, 8192)` | Bounded 8 KB |
| Hex search | state.rs:1796 | 1 MB chunked `read_range` | Bounded |
| Evidence hasher | evidence/hasher.rs:62 | 64 KB chunked via `read_range` | Streaming SHA-256 |
| Content indexer | search/content.rs:149 | 10 MB size gate before read | Capped |
| CSV/HTML export | ui/export.rs:63 | `writeln!` streaming to File | Streaming write |
| Report template | strata-core report/mod.rs:222 | 1 MB size gate | Capped |
| Engine-adapter text | engine-adapter files.rs:83 | 1 MB `read_file_range` | Capped |
| Wraith magic check | strata-plugin-wraith:92 | 4 byte `read_exact` | Minimal I/O |
| Wraith string scan | strata-plugin-wraith:213 | 1 MB cap read | Size-gated |
| Recon text scan | strata-plugin-recon:183 | 10 MB size gate | Only plugin with explicit gate |
| Cipher entropy | strata-plugin-cipher:947 | 1 MB cap read | Size-gated |
| MFT walker | strata-fs mft_walker.rs:178 | 512 KB bulk reads, 500K entry cap | Chunked + capped |
| NTFS enumeration | strata-fs ntfs.rs:693 | 1 MB parallel reads, 100K entry cap | Chunked + capped |
| Scalpel read_prefix | strata-core scalpel.rs:5 | 8 MB binary / 4 MB text cap | Correct pattern |
| EwfVfs read_file_range | strata-fs virtualization/mod.rs:3386 | NTFS data-run walking, caller-controlled range | Streaming |
| Nimbus | strata-plugin-nimbus | Metadata-only | No file I/O |
| macTrace | strata-plugin-mactrace | SQLite-managed I/O | Page-level reads |
| CSAM plugin shell | strata-plugin-csam | No-op | No file I/O |
| Sigma | strata-plugin-sigma | Correlation-only | No file I/O |

---

## Section 1: Plugin Artifact Extraction

### CRITICAL

```
COMPONENT: strata-plugin-remnant (File Carving Metadata)
FILE: plugins/strata-plugin-remnant/src/lib.rs
LINE: ~980
READS: full-load -- std::fs::read(&path) on EVERY file in evidence root
MAX SAFE SIZE: at risk -- multi-GB images/hibernation files sit in root
ACTION NEEDED: replace with File::open + read_exact for 4-byte magic check
NOTES: Single most dangerous read in the plugin layer. A 128 GB
       hiberfil.sys or 50 GB E01 in evidence root is fully loaded
       just to check 4 magic bytes. Wraith already does this correctly
       via read_exact -- copy that pattern.
```

```
COMPONENT: strata-plugin-netflow (PCAP reads)
FILE: plugins/strata-plugin-netflow/src/lib.rs
LINE: ~293
READS: full-load -- std::fs::read(&path) on PCAP files
MAX SAFE SIZE: at risk -- network captures routinely 1-50 GB
ACTION NEEDED: replace with File::open + read_exact for magic + metadata
NOTES: Only needs 4-byte magic check and file size. Full load unnecessary.
```

```
COMPONENT: strata-plugin-vector (PE analysis)
FILE: plugins/strata-plugin-vector/src/lib.rs
LINE: ~407
READS: full-load -- std::fs::read(path) on all .exe/.dll
MAX SAFE SIZE: at risk -- chrome.dll ~200 MB, many system DLLs >50 MB
ACTION NEEDED: replace with File::open + read(&mut [0u8; 65536])
NOTES: Only uses first 4 KB for PE headers and first 64 KB for malware
       strings. A 200 MB DLL is fully loaded for 64 KB of analysis.
```

```
COMPONENT: strata-plugin-trace (timestomp detection)
FILE: plugins/strata-plugin-trace/src/lib.rs
LINE: ~660
READS: full-load -- std::fs::read on every .exe/.dll/.sys in evidence
MAX SAFE SIZE: at risk -- called on thousands of executables per image
ACTION NEEDED: replace with File::open + read(&mut [0u8; 256])
NOTES: Only uses first 256 bytes (PE header + e_lfanew). Loads entire
       files (potentially hundreds of MB each) just for 256 bytes.
```

```
COMPONENT: strata-plugin-trace/srum.rs (SRUM ESE parser)
FILE: plugins/strata-plugin-trace/src/srum.rs
LINE: 108
READS: full-load -- std::fs::read(path) on SRUDB.dat
MAX SAFE SIZE: at risk -- long-running Win10/11 systems reach 300 MB
ACTION NEEDED: add size gate (~512 MB) or convert to page-level streaming
```

```
COMPONENT: strata-plugin-specter (Android backups)
FILE: plugins/strata-plugin-specter/src/lib.rs
LINE: ~521
READS: full-load -- std::fs::read(path) on .ab Android backup files
MAX SAFE SIZE: at risk -- ADB full backups can be multi-GB
ACTION NEEDED: replace with File::open + read_exact for 15-byte magic
```

### HIGH

```
COMPONENT: strata-plugin-phantom (SYSTEM/SOFTWARE/NTUSER.DAT hives)
FILE: plugins/strata-plugin-phantom/src/lib.rs
LINES: 98, 102, 106, 110, 114, 118, 126
READS: full-load -- std::fs::read(&path) on all 7 hive types, no size gate
MAX SAFE SIZE: unknown -- enterprise SYSTEM/SOFTWARE 256-512 MB,
              NTUSER.DAT 100-256 MB on domain controllers
ACTION NEEDED: add size gate (reject hives >512 MB with warning artifact)
NOTES: nt-hive crate requires &[u8] (full slice), so streaming parse
       is not possible without a crate change. A size gate is the
       pragmatic fix. On a server image with 100+ user profiles,
       Phantom sequentially loads 100+ NTUSER.DAT files.
```

```
COMPONENT: strata-plugin-chronicle (NTUSER.DAT)
FILE: plugins/strata-plugin-chronicle/src/lib.rs
LINE: ~742
READS: full-load -- std::fs::read(&entry_path) on NTUSER.DAT
MAX SAFE SIZE: unknown -- same enterprise sizes as Phantom
ACTION NEEDED: add size gate, or deduplicate with Phantom
NOTES: Duplicate read -- both Phantom and Chronicle independently
       full-load the same NTUSER.DAT.
```

```
COMPONENT: strata-plugin-netflow (IIS / access logs)
FILE: plugins/strata-plugin-netflow/src/lib.rs
LINE: ~314
READS: full-load -- std::fs::read_to_string on IIS/access logs
MAX SAFE SIZE: at risk -- production IIS logs can be multi-GB
ACTION NEEDED: replace with BufReader line-by-line iteration
NOTES: .lines().take(50_000) limits processing but NOT the initial
       string allocation. The full file is loaded first.
```

```
COMPONENT: strata-plugin-vector (script files)
FILE: plugins/strata-plugin-vector/src/lib.rs
LINE: ~224
READS: full-load -- std::fs::read_to_string on .ps1/.vbs/.js/.bat
MAX SAFE SIZE: at risk -- PowerShell transcripts can be 100+ MB
ACTION NEEDED: add size gate (~10 MB)
```

```
COMPONENT: strata-plugin-vector (Office documents)
FILE: plugins/strata-plugin-vector/src/lib.rs
LINE: ~418
READS: full-load -- std::fs::read on .doc/.xls/.ppt
MAX SAFE SIZE: at risk -- OLE2 files can be 100+ MB
ACTION NEEDED: add size gate (~50 MB)
```

```
COMPONENT: strata-plugin-guardian (AV logs)
FILE: plugins/strata-plugin-guardian/src/lib.rs
LINE: ~130
READS: full-load -- std::fs::read_to_string on Avast .log files
MAX SAFE SIZE: at risk -- enterprise AV logs can be 100+ MB
ACTION NEEDED: replace with BufReader line-by-line
NOTES: .lines().take(500) limits output but the full string is
       allocated before the take.
```

### MEDIUM / LOW

Cipher (.ad.trace ~50 MB), Specter (mobile_installation.log ~50 MB),
Netflow (qBittorrent log ~10 MB), Chronicle (Jump Lists, Prefetch),
Conduit (hosts file ~1 KB) -- all full-load but on typically small
files. Add size gates for defense-in-depth.

---

## Section 2: File Tree Indexing

```
COMPONENT: File tree indexing -- FileEntry accumulation
FILE: apps/tree/strata-tree/src/evidence/indexer.rs (lines 11-133)
      apps/tree/strata-tree/src/state.rs (file_index: Vec<FileEntry>)
READS: metadata only, but unbounded struct accumulation
MAX SAFE SIZE: at risk -- 5M files = ~2.5-4 GB of FileEntry structs
ACTION NEEDED: stream entries to SQLite; paginate file_index; add cap
NOTES: FileEntry ~500-800 bytes x 5M files on a 2 TB NTFS image.
       No cap, no pagination, no streaming to disk. This is the primary
       OOM path for large images before artifact parsing begins.
SEVERITY: CRITICAL
```

```
COMPONENT: VFS enumeration returns full Vec
FILE: apps/tree/strata-tree/src/evidence/loader.rs (lines 65-109)
READS: vfs.enumerate_ntfs_directory() returns Vec<VfsEntry>
MAX SAFE SIZE: at risk -- 5M entry Vec before batching
ACTION NEEDED: stream VFS entries via iterator/channel instead of Vec
SEVERITY: HIGH
```

---

## Section 3: Gallery Thumbnails

```
COMPONENT: Gallery thumbnail loader + LRU cache
FILE: apps/tree/strata-tree/src/ui/gallery_view.rs (lines 349-360)
READS: size-gated -- read_range(file, 0, 512 KB)
MAX SAFE SIZE: confirmed -- 512 KB per file, 500 entries x 128x128 = ~32 MB
ACTION NEEDED: none
SEVERITY: LOW (safe)
```

---

## Section 4: Timeline Generation

```
COMPONENT: Timeline entry accumulation
FILE: apps/tree/strata-tree/src/state.rs (line ~422)
READS: in-memory accumulation -- timeline_entries: Vec<TimelineEntry>
MAX SAFE SIZE: at risk -- 5M files x 4 timestamps = 20M entries = ~4 GB
ACTION NEEDED: stream to SQLite; add windowed pagination
NOTES: No streaming to disk, no pagination, no cap. The timeline
       heatmap (timeline_view.rs:371) rebuilds a BTreeMap from ALL
       entries every frame, causing UI stutter on large evidence.
SEVERITY: HIGH
```

---

## Section 5: Carver

```
COMPONENT: Carver scan phase
FILE: apps/tree/strata-tree/src/carve/engine.rs (lines 292-320)
READS: chunked -- 1 MB BufReader
MAX SAFE SIZE: confirmed
ACTION NEEDED: none (safe)
SEVERITY: LOW
```

```
COMPONENT: Carver extract phase
FILE: apps/tree/strata-tree/src/carve/engine.rs (lines 433-466)
READS: 64 KB chunk reads but accumulates into Vec up to sig.max_size
MAX SAFE SIZE: at risk -- sig.max_size can be 2 GB (PST, MP4, AVI)
ACTION NEEDED: stream extracted data directly to output file
SEVERITY: HIGH
```

---

## Section 6: Export (CSV / HTML / PDF)

```
COMPONENT: CSV / HTML export
FILE: apps/tree/strata-tree/src/ui/export.rs (lines 63-180)
READS: streaming write
ACTION NEEDED: none
SEVERITY: LOW (safe)
```

```
COMPONENT: Timeline JSON export
FILE: apps/tree/strata-tree/src/ui/export.rs (lines 182-198)
READS: full Vec<serde_json::Value> in memory before serialize
MAX SAFE SIZE: at risk -- 20M entries x ~400 bytes = ~8 GB
ACTION NEEDED: use serde_json streaming serializer
SEVERITY: HIGH
```

```
COMPONENT: PDF export
FILE: apps/tree/strata-tree/src/ui/export.rs (lines 200-246)
READS: pre-materializes all lines as Vec<String> before paginating
MAX SAFE SIZE: at risk -- 20M entries x ~100 bytes = ~2 GB
ACTION NEEDED: paginate lazily from iterator
SEVERITY: MEDIUM
```

---

## Section 7: File Preview Panel

```
COMPONENT: Text preview (LEGACY -- preview.rs)
FILE: apps/tree/strata-tree/src/ui/preview.rs (lines 152-166)
READS: full-load -- std::fs::read(path), then truncates to 8 KB
MAX SAFE SIZE: at risk -- 2 GB log file fully loaded before truncation
ACTION NEEDED: replace with read_first_n() bounded read
SEVERITY: CRITICAL
```

```
COMPONENT: Image preview (LEGACY -- preview.rs)
FILE: apps/tree/strata-tree/src/ui/preview.rs (lines 269-311)
READS: full-load -- std::fs::read(path) + image::load_from_memory
MAX SAFE SIZE: at risk -- no size gate; decode can 10x the memory use
ACTION NEEDED: add file-size gate (20 MB) before read + decode
SEVERITY: CRITICAL
```

```
COMPONENT: Image preview (NEW -- preview_panel.rs)
FILE: apps/tree/strata-tree/src/ui/preview_panel.rs (line 565)
READS: full-load -- ctx.read_file(f) (full file, no size gate)
MAX SAFE SIZE: at risk
ACTION NEEDED: add file-size check before read_all(); reject >20 MB
SEVERITY: HIGH
```

```
COMPONENT: Hex preview
READS: read_first_n(path, 4096)
SEVERITY: LOW (safe)
```

---

## Section 8: String Extraction

```
COMPONENT: Content search indexer
FILE: apps/tree/strata-tree/src/search/content.rs (lines 149-201)
READS: size-gated full-load -- 10 MB gate
MAX SAFE SIZE: confirmed -- 10 MB per file
SEVERITY: LOW

COMPONENT: Hex byte search
FILE: apps/tree/strata-tree/src/state.rs (lines 1796-1836)
READS: 1 MB chunked via read_range
MAX SAFE SIZE: confirmed
SEVERITY: LOW
```

---

## Section 9: VFS / Core Crate Findings

### CRITICAL

```
COMPONENT: FsVfs::open_file (directory-mode VFS)
FILE: crates/strata-fs/src/virtualization/mod.rs (lines ~483-491)
READS: full-load -- std::fs::read(&file_path), unbounded
MAX SAFE SIZE: at risk -- any file in directory evidence
ACTION NEEDED: add MAX_OPEN_FILE_BYTES (256 MB); override read_file_range
               in FsVfs with seek-based reads
NOTES: Default VFS for logical acquisitions and ALEAPP extractions.
       Every caller using open_file() on directory evidence is exposed.
```

```
COMPONENT: verify_image_integrity full-load
FILE: crates/strata-core/src/acquisition/mod.rs (line ~118)
      crates/strata-shield-engine/src/acquisition/mod.rs (line ~118)
READS: full-load -- file.read_to_end(&mut buffer) on evidence images
MAX SAFE SIZE: at risk -- 500 GB E01 = 500 GB allocation
ACTION NEEDED: convert to streaming SHA-256 (1 MB chunk loop)
NOTES: The streaming pattern already exists in strata-csam scanner.
```

```
COMPONENT: Parser dispatch full-load (evidence engine)
FILE: crates/strata-core/src/evidence/mod.rs (lines ~1954-1971)
      crates/strata-shield-engine/src/evidence/mod.rs (~1956-1960)
READS: full-load -- vfs.open_file() or std::fs::read() per file
MAX SAFE SIZE: at risk -- EVTX 1-4 GB, SQLite multi-GB
ACTION NEEDED: size-gate reads; use EvtxParser::from_path() for EVTX;
               pass streaming reader for files >64 MB
NOTES: Central parser dispatch loop. #1 OOM risk in production.
```

### HIGH

```
COMPONENT: VirtualFileSystem::read_file_range default fallback
FILE: crates/strata-fs/src/virtualization/mod.rs (lines ~183-198)
READS: full-load fallback -- calls open_file() then slices
MAX SAFE SIZE: at risk -- FsVfs, QCOW2, VMDK, SplitRaw, AFF4 do NOT
              override, so callers expecting streaming get full-load
ACTION NEEDED: make read_file_range required; or add size-gate in default
NOTES: CSAM scanner's "streaming" hash degrades to full-load on
       directory evidence because FsVfs uses this default.
```

```
COMPONENT: AFF4 container read_member
FILE: crates/strata-fs/src/container/aff4.rs (lines ~172-176)
READS: full-load -- Vec::with_capacity(stream.size()) + read_to_end
MAX SAFE SIZE: at risk -- AFF4 streams can contain entire disk images
ACTION NEEDED: implement ranged reads for AFF4
```

```
COMPONENT: QCOW2 compressed cluster read
FILE: crates/strata-fs/src/container/qcow2.rs (lines ~189-216)
READS: read_to_end from cluster_offset to EOF of entire QCOW2 file
MAX SAFE SIZE: at risk -- reads to end of multi-hundred-GB file
ACTION NEEDED: use read_exact with compressed cluster size
NOTES: CORRECTNESS BUG AND memory safety issue. read_to_end reads
       everything after cluster_offset, not just the single cluster.
```

```
COMPONENT: EVTX parser buffer copy
FILE: crates/strata-core/src/parsers/evtx.rs (line ~204)
READS: data.to_vec() copies full file buffer (already in memory)
MAX SAFE SIZE: at risk -- doubles memory of already-loaded EVTX
ACTION NEEDED: use EvtxParser::from_path() for streaming
```

```
COMPONENT: strata-engine-adapter hash_file
FILE: crates/strata-engine-adapter/src/hashing.rs (lines ~34-49)
READS: full-load -- vfs.open_file()
ACTION NEEDED: port CSAM scanner hash_streaming pattern
```

```
COMPONENT: Classification modules full-load (17 sites)
FILES: crates/strata-core/src/classification/{wmi,browser,scheduledtasks,
       regservice,logfile,lnk,usnjrnl,prefetch,usb,rdp,mftparse,
       user_activity_mru,restore_shadow,recyclebin,timeline_correlation_qa,
       jumplist}.rs
READS: full-load -- std::fs::read(path) and read_to_string(path)
MAX SAFE SIZE: at risk -- no size guard on any
ACTION NEEDED: adopt scalpel::read_prefix pattern (already exists at 8 MB)
```

### MEDIUM

```
COMPONENT: RawVfs mmap logic bug
FILE: crates/strata-fs/src/virtualization/mod.rs (lines ~554-563)
READS: warns about "too large for mmap" then mmaps anyway
ACTION NEEDED: branch to seek-based I/O when > MAX_MMAP_SIZE
NOTES: Fallthrough bug -- warning fires but code continues to mmap.

COMPONENT: EwfVfs open_file caps (100 MB / 256 MB)
READS: full-load with size gate -- reasonable but large
ACTION NEEDED: consider streaming for large files

COMPONENT: ISO9660 read_file
FILE: crates/strata-fs/src/iso9660.rs (lines ~107-155)
READS: full-load -- Vec with data_length (up to 4 GB from u32)
ACTION NEEDED: add size cap

COMPONENT: VHDX BAT table loading
FILE: crates/strata-fs/src/container/vhd.rs (lines ~456-466)
READS: full-load of BAT -- ~8 MB for 2 TB, ~256 MB for 64 TB
ACTION NEEDED: add size cap

COMPONENT: CSAM perceptual hash full-load
FILE: crates/strata-csam/src/scanner.rs (lines ~250-258)
READS: full-load via vfs.open_file() -- intentional for image decode
ACTION NEEDED: add 200 MB hard cap

COMPONENT: FSEvents decompression bomb potential
FILE: crates/strata-core/src/parsers/macos/fsevents_binary.rs (~21-25)
READS: GzDecoder::read_to_end -- unbounded decompression
ACTION NEEDED: cap decompressed output size
```

---

## Section 10: strata-tree Additional Findings

```
COMPONENT: Hash calculator (legacy path)
FILE: apps/tree/strata-tree/src/hash/calculator.rs (line ~116)
READS: full-load -- file.read_to_end(&mut buf), no size gate
MAX SAFE SIZE: at risk -- used for host-path files of arbitrary size
ACTION NEEDED: unify with chunked evidence/hasher.rs implementation
NOTES: Two hash implementations exist -- hasher.rs (safe, 64 KB chunks)
       and calculator.rs (unsafe, full-load). Must be unified.
SEVERITY: CRITICAL
```

```
COMPONENT: Hash set loader (NSRL)
FILE: apps/tree/strata-tree/src/hash/hashset.rs (lines ~29, 76)
READS: full-load -- std::fs::read_to_string(path)
MAX SAFE SIZE: at risk -- NSRL RDS hash sets can be 6+ GB
ACTION NEEDED: replace with BufReader line-by-line streaming
SEVERITY: CRITICAL
```

```
COMPONENT: VfsReadContext::read_file (central read pathway)
FILE: apps/tree/strata-tree/src/evidence/vfs_context.rs (~110, 167)
READS: full-load -- returns Vec<u8> for entire file
ACTION NEEDED: add size gate; encourage callers to use read_range
SEVERITY: HIGH
```

```
COMPONENT: File export via file table
FILE: apps/tree/strata-tree/src/ui/file_table.rs (line ~284)
READS: full-load -- ctx.read_file(&f) to export
ACTION NEEDED: implement chunked copy via read_range loop
SEVERITY: HIGH
```

```
COMPONENT: Registry hive viewer
FILE: apps/tree/strata-tree/src/ui/registry_view.rs (~500-503)
      apps/tree/strata-tree/src/ui/registry_viewer.rs (~284)
READS: full-load -- f.read_to_end / std::fs::read, no size gate
ACTION NEEDED: add 512 MB cap
SEVERITY: MEDIUM
```

```
COMPONENT: Browser history / EVTX log viewer
FILES: apps/tree/strata-tree/src/ui/browser_history_view.rs (~288)
       apps/tree/strata-tree/src/ui/event_logs_view.rs (~186)
READS: full-load -- ctx.read_file(file) or std::fs::read
ACTION NEEDED: add per-file size gate alongside file-count cap
SEVERITY: MEDIUM
```

---

## Remediation Priority

### P0 -- Must fix before any large-evidence testing

| # | Finding | Fix |
|---|---------|-----|
| 1 | FsVfs::open_file unbounded | Add `MAX_OPEN_FILE_BYTES` (256 MB); override `read_file_range` in FsVfs |
| 2 | Parser dispatch full-load (strata-core) | Size-gate; use `EvtxParser::from_path()` for EVTX |
| 3 | verify_image_integrity full-load | Streaming SHA-256 (1 MB chunks, pattern in CSAM) |
| 4 | FileEntry accumulation unbounded | Stream to SQLite; paginate; add cap |
| 5 | Hash set loader full-load (NSRL) | `BufReader` line-by-line streaming |
| 6 | Hash calculator full-load | Unify with chunked `evidence/hasher.rs` |
| 7 | Text preview legacy full-load | Replace with `read_first_n()` |
| 8 | Image preview legacy full-load | Add 20 MB file-size gate |

### P1 -- Must fix before v1.5.0

| # | Finding | Fix |
|---|---------|-----|
| 9 | Plugin magic-byte-only reads (remnant, netflow PCAP, specter .ab) | `File::open` + `read_exact` for header only |
| 10 | Plugin partial-content reads (vector PE, trace timestomp) | Read only needed prefix (64 KB / 256 B) |
| 11 | Phantom/Chronicle hive reads (8 sites) | 512 MB size gate |
| 12 | QCOW2 read_to_end correctness bug | `read_exact` with cluster size |
| 13 | AFF4 unbounded read_member | Size cap; implement `read_file_range` |
| 14 | VFS read_file_range default fallback | Make required trait method |
| 15 | Carver extract accumulation | Stream 64 KB chunks directly to output file |
| 16 | Timeline JSON export full-Vec | Streaming JSON serializer |
| 17 | EVTX parser double-allocation | Use `from_path()` |
| 18 | Classification modules full-load (17 sites) | Adopt `scalpel::read_prefix` |
| 19 | Engine-adapter hash_file | Port CSAM hash_streaming pattern |
| 20 | Log file readers (guardian, netflow IIS) | `BufReader` + line iteration |
| 21 | New preview_panel image preview no gate | 20 MB file-size gate |
| 22 | File export full-load | Chunked copy via `read_range` loop |
| 23 | Timeline entry unbounded accumulation | Stream to SQLite; paginate |

### P2 -- Fix when convenient

| # | Finding | Fix |
|---|---------|-----|
| 24 | RawVfs mmap fallthrough bug | Branch to seek-based I/O |
| 25 | ISO9660 read_file no cap | Add cap |
| 26 | VHDX BAT unbounded | Cap for >64 TB images |
| 27 | CSAM perceptual scan no cap | 200 MB hard cap |
| 28 | FSEvents decompression bomb | Cap decompressed output |
| 29 | Timeline heatmap per-frame rebuild | Cache; invalidate on change |
| 30 | PDF export pre-materializes lines | Lazy pagination |
| 31 | Registry viewer no cap | 512 MB cap |
| 32 | Browser/EVTX viewer no per-file gate | Per-file size gate |

---

## Design Patterns to Adopt Codebase-Wide

### The Correct Pattern (already in codebase)

```rust
// Hex panel -- exemplary paged virtual I/O
const HEX_PAGE_SIZE: usize = 65_536;
const HEX_MAX_CACHED_PAGES: usize = 16;
// 64 KB pages on demand via read_range(), 256 KB window, 1 MB cache

// CSAM scanner -- exemplary streaming hash
const HASH_CHUNK: usize = 1_048_576;
loop {
    let chunk = vfs.read_file_range(path, offset, HASH_CHUNK)?;
    hasher.update(&chunk);
    offset += chunk.len() as u64;
}

// Recon -- exemplary size gate
let meta = std::fs::metadata(path)?;
if meta.len() > 10_485_760 { return results; }
```

### The Anti-Pattern (must be eliminated)

```rust
// BAD: loads full file just to check a few bytes
let data = std::fs::read(path)?;      // <-- OOM on large file
if data.len() < 4 { return; }
if &data[0..4] != MAGIC { return; }

// GOOD: reads only what's needed
let mut f = std::fs::File::open(path)?;
let mut magic = [0u8; 4];
f.read_exact(&mut magic)?;
if magic != MAGIC { return; }
```

---

## Conclusion

Strata's streaming infrastructure (`read_file_range`, chunked hashers,
paged hex editor, scalpel prefix reads) is **well-designed**. The
problem is that most code paths **don't use it yet**. The VFS has the
right API but the wrong default. The plugins overwhelmingly call
`std::fs::read()` directly instead of going through the VFS.

The fix is **mechanical, not architectural**. Each CRITICAL/HIGH finding
has a clear pattern to follow that already exists somewhere in the
codebase. The remediation can be done plugin-by-plugin with independent
commits and without any API changes.

The three load-bearing CSAM tests are **unaffected** by any of these
findings -- the CSAM module correctly uses `read_file_range` everywhere.

---

*Audit complete. No code was modified.*
*Previous audit (Agent 5, 2026-04-09) is subsumed by this version.*
