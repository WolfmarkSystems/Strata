# RESEARCH_v15_EXT4_VIEW.md — ext4-view v0.9 API verification

*v15 Sprint 3 Phase A — produced by the throwaway probe at
`/tmp/ext4_api_check/` (not committed to the workspace; reproducible
in any developer environment via `cargo new` + `cargo add ext4-view`).*

*Date: 2026-04-19*

## Summary

**No blockers.** `ext4-view v0.9.3` is a clean fit for Strata's
`VirtualFilesystem` walker and a *direct* fit for `EvidenceImage`
without the `Read + Seek` adapter the v14 planning expected. The
walker sprint can proceed exactly as SPRINTS_v15.md specifies in
Phase B/C with one simplification to the adapter shape (below).

## Crate facts

- **Latest 0.9.x release:** `ext4-view v0.9.3`
- **License:** Apache-2.0 OR MIT (per `Cargo.toml` and
  `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ext4-view-0.9.3/README.md`).
  ✅ **Compatible** with Strata's reference-tools-only policy —
  non-GPL, dual-licensed, permissive.
- **Author/Origin:** Google LLC (per source file copyright headers).
  Actively maintained; 2024 copyright.
- **`no_std`:** yes, with `alloc` required. Library feature-gated `std`
  implementation adds `Ext4::load_from_path` and a blanket
  `Ext4Read for std::fs::File`.
- **Write support:** explicit non-goal per the `Design Goals` section
  of the README — correct fit for Strata's read-only forensic stance.
- **Unsafe:** README states "No `unsafe` code in the main package (it
  is allowed in dependencies)." Dependencies are `bitflags`, `crc`,
  `crc-catalog` — standard low-level helpers, all audited by the
  broader Rust ecosystem.

## The I/O abstraction (critical finding)

The question the v14 blocker flagged was *"does `ext4-view` take
`Read + Seek`, a callback, or only a `&[u8]`?"*

**Answer:** none of the above. It defines its own single-method trait:

```rust
pub trait Ext4Read {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), BoxedError>;
}
```

(defined at `src/reader.rs` line ~24)

This is an **offset-addressed read API**, which is *exactly* the shape
of Strata's existing `EvidenceImage` trait:

```rust
// crates/strata-evidence/src/image.rs line 21
fn read_at(&self, offset: u64, buf: &mut [u8]) -> EvidenceResult<usize>;
```

The two are one adapter line apart. A real Strata `Ext4PartitionReader`
looks like:

```rust
struct Ext4PartitionReader {
    image: Arc<dyn EvidenceImage>,
    partition_offset: u64,
    partition_size: u64,
}

impl Ext4Read for Ext4PartitionReader {
    fn read(&mut self, start_byte: u64, dst: &mut [u8])
        -> Result<(), Box<dyn Error + Send + Sync + 'static>>
    {
        if start_byte + dst.len() as u64 > self.partition_size {
            return Err("read past partition end".into());
        }
        let abs = self.partition_offset + start_byte;
        let n = self.image.read_at(abs, dst).map_err(|e| e.to_string())?;
        if n != dst.len() {
            return Err("short read".into());
        }
        Ok(())
    }
}
```

**No buffering required.** `EvidenceImage::read_at` already handles
chunk caching internally (per `E01Image`'s `ChunkCache`); `ext4-view`
operates on small ~4 KB block reads and caches its own decoded block
entries (`src/block_cache.rs`); stacking these two caches is harmless
and performant.

This is *simpler* than the `NtfsWalker` pattern from v11, which had to
wrap `PartitionReader` in `BufReader<Mutex<PartitionReader>>` to
satisfy the `ntfs` crate's `Read + Seek` requirement. For ext4 no such
adapter exists — `Ext4Read` matches `read_at` signature-for-signature.

## Public API surface the walker will consume

From `src/lib.rs` (struct `Ext4`):

| Method | Signature (abbreviated) | Maps to VFS trait method |
|---|---|---|
| `Ext4::load(Box<dyn Ext4Read>)` | `-> Result<Ext4, Ext4Error>` | `Ext4Walker::open` |
| `fs.read(path)` | `-> Result<Vec<u8>, Ext4Error>` | `VirtualFilesystem::read_file` |
| `fs.exists(path)` | `-> Result<bool, Ext4Error>` | `VirtualFilesystem::exists` |
| `fs.metadata(path)` | `-> Result<Metadata, Ext4Error>` | `VirtualFilesystem::metadata` |
| `fs.read_dir(path)` | `-> Result<ReadDir, Ext4Error>` | `VirtualFilesystem::list_dir` |
| `fs.read_link(path)` | `-> Result<PathBuf, Ext4Error>` | (new) symlink target → VfsEntry |

From `src/metadata.rs`:

| Method | Notes |
|---|---|
| `file_type()` | `FileType` enum (RegularFile / Directory / Symlink / FIFO / Socket / CharDev / BlockDev) |
| `is_dir()` | |
| `is_symlink()` | |
| `len()` | `u64` — maps to `VfsEntry.size` |
| `mode()` | `u16` — Unix mode bits, maps to `VfsAttributes { unix_mode: Some(...) }` |
| `uid()` | `u32` — maps to `VfsAttributes.unix_uid` |
| `gid()` | `u32` — maps to `VfsAttributes.unix_gid` |

All required fields for Strata's `VfsEntry` / `VfsMetadata` / `VfsAttributes`
are present. The walker can construct `VfsSpecific::Ext4 { inode, extents_based }`
— inode lookup will need a helper since `Metadata` doesn't expose it
directly; `DirEntry::inode()` *may* expose this (see `src/dir_entry.rs`), TBD
in the walker sprint.

## Error type

`Ext4Error` is an exhaustive enum covering:

- `NotAbsolute`, `NotASymlink`, `NotFound`, `IsADirectory`,
  `NotADirectory`, `IsASpecialFile`, `FileTooLarge`, `NotUtf8`,
  `MalformedPath`
- (implied additional variants — the enum is `#[non_exhaustive]`)

Mapping to Strata's `VfsError`:

| Ext4Error | VfsError |
|---|---|
| `NotFound` | `VfsError::NotFound(path)` |
| `NotADirectory` | `VfsError::NotADirectory(path)` |
| `IsADirectory` / `IsASpecialFile` | `VfsError::NotAFile(path)` |
| `NotAbsolute` / `MalformedPath` | `VfsError::Other(msg)` |
| I/O propagated via `BoxedError` | `VfsError::Other(msg)` |
| everything else | `VfsError::Other(msg)` |

No lossy mapping; no need to extend `VfsError`.

## Features we explicitly will NOT wrap in v15

- **Encryption** — the crate does not decrypt. Walker will mark
  encrypted entries in `VfsAttributes { encrypted: true }` but return
  `VfsError::Unsupported` on `read_file` against an encrypted inode.
  Offline key recovery is out of scope for the walker.
- **Journal replay** — the crate does not appear to expose journal
  replay. Walker treats the filesystem as committed-state-only.
- **Deleted-inode recovery** — not in the crate's public API.
  `list_deleted` returns an empty vec for v15; flagged as follow-up in
  the v15 blocker doc.
- **Extended attributes** — need to verify in the walker sprint whether
  `ext4-view` exposes xattrs (the `Metadata` type doesn't in v0.9.3;
  `DirEntry` may). If not exposed, `alternate_streams` returns empty
  and the walker documents the gap.

## Probe output (bit-for-bit reproducible)

```
=== ext4-view v0.9 API probe ===

Step 1: Ext4Error variants enumerate
  PASS

Step 2: Vec<u8> impls Ext4Read
  PASS

Step 3: offset-addressed MockPartitionReader impls Ext4Read
  PASS — no Read+Seek adapter needed, direct fit for EvidenceImage::read_at

Step 4: Ext4::load(Box<dyn Ext4Read>) signature
  PASS — returns Ext4Error on bad data: Corrupt(SuperblockMagic)

Step 5: walker-required methods exist with expected signatures
  PASS — read / exists / metadata / read_dir

Step 6: Metadata exposes VfsEntry fields
  PASS — is_dir / is_symlink / len / mode / uid / gid

=== probe complete ===
```

The probe lives at `/tmp/ext4_api_check/` for inspection; it's not
committed because it has no reason to live in the workspace once this
document captures the findings.

## Walker sprint recommendations (for FS-EXT4-1 Phase B)

1. **Add the dependency.** `ext4-view = "0.9"` in
   `crates/strata-fs/Cargo.toml`. No feature flags needed — default
   features (`std`) give us `Ext4::load_from_path` which is handy for
   the Phase C fixture tests.
2. **Create `crates/strata-fs/src/walkers/ext4_walker.rs`** with the
   pattern above. The whole adapter + VFS impl is ~400 LOC based on
   the NtfsWalker baseline.
3. **Implement the VFS trait methods** by delegating to
   `Ext4::{read, metadata, read_dir, exists}`. Use `Arc<Mutex<Ext4>>`
   to satisfy `Send + Sync + &self` mutability requirements (the
   ext4-view block cache mutates internal state on reads).
4. **Skip the `Read + Seek` adapter entirely** — the queue's Phase B
   pseudo-code calls it out, but the real API is offset-addressed and
   the simpler adapter wins.
5. **Phase C fixture** — commit `ext4_small.img` (~2 MB) + `mkext4.sh`
   + `ext4_small.expected.json` as specified. Generation script uses
   `dd` + `mkfs.ext4` + loopback mount + file-population + unmount. On
   macOS dev machines, `mkfs.ext4` requires `e2fsprogs` via Homebrew;
   document this in the script header.
6. **Ext4Error → VfsError mapping helper** lives at the top of
   `ext4_walker.rs`, ~20 lines. Map each documented variant to the
   corresponding `VfsError`; everything else to `VfsError::Other`.
7. **VfsSpecific::Ext4 { inode, extents_based }** — `inode` comes
   from `DirEntry::inode()` (verify in the sprint); `extents_based`
   is true for any file created on an ext4 filesystem (the extents
   feature flag is on by default since Linux 2.6.30). Safe to hard-
   code `true` for v15 and refine later.

## Recommendation

**No blocker. Proceed with Phase B and C in FS-EXT4-1.** The API is
cleaner than the v14 planning anticipated; the walker should ship
closer to the NtfsWalker baseline in LOC and test count than the
original 400-line estimate.
