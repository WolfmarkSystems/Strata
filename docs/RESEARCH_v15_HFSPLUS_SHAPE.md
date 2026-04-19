# RESEARCH_v15_HFSPLUS_SHAPE.md

**Purpose:** Verify the threading contract, public API surface, and refactor scope of the existing `crates/strata-fs/src/hfsplus.rs` before SPRINTS_v15.md Session C Sprint 1 (FS-HFSPLUS-1) commits to an architectural path.

**Status:** Phase 0 research complete. Sprint 1 unblocked. Path A (held handle) confirmed viable.

**Date:** 2026-04-19

**Author:** Wolfmark Systems — research session preceding Session C

---

## TL;DR

`HfsPlusFilesystem` is `Send + Sync`. The existing public surface already includes `read_catalog(&mut self) -> Vec<HfsPlusCatalogEntry>`, which is the iteration shape — just not packaged as an iterator. Sprint 1's `HfsPlusWalker::walk()` wraps it as `Vec::into_iter`, which is `Send` for free. The Phase A Read+Seek refactor is mechanical, not architectural — estimated 120–180 LOC delta, well below the original 350 LOC ceiling.

Path A from SPRINTS_v15.md (held handle, not Session B's reopen-per-call pattern) is the right architecture. Phase B walker code is ~80 LOC.

---

## 1. Threading Contract

### Probe

```rust
// Dropped into crates/strata-fs/src/hfsplus.rs under #[cfg(test)]
#[cfg(test)]
mod _send_sync_probe {
    use super::HfsPlusFilesystem;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn hfsplus_filesystem_is_send() {
        assert_send::<HfsPlusFilesystem>();
    }

    #[test]
    fn hfsplus_filesystem_is_sync() {
        assert_sync::<HfsPlusFilesystem>();
    }
}
```

### Result

```
running 2 tests
test hfsplus::_send_sync_probe::hfsplus_filesystem_is_sync ... ok
test hfsplus::_send_sync_probe::hfsplus_filesystem_is_send ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 97 filtered out
```

### Interpretation

`HfsPlusFilesystem` is both `Send` and `Sync`. No `Rc`, `RefCell`, `Cell`, or raw pointer fields are present in the struct. This contrasts with `ext4-view`'s `Ext4` type, which is `Rc<Ext4Inner>` internally and forced Session B's "reopen per trait method" workaround.

**Implication:** Path A from SPRINTS_v15.md (walker holds the parsed `HfsPlusFilesystem`) is on the table. The Session B reopen-per-call pattern is unnecessary for HFS+.

---

## 2. Existing Public API Surface

### Probe

```bash
grep -nE "^\s*pub fn" crates/strata-fs/src/hfsplus.rs
```

### Result

```
9:  pub fn hfsplus_fast_scan(data: &[u8]) -> Result<HfsPlusFastScanResult, ForensicError>
46: pub fn open_hfsplus(path: &Path) -> Result<HfsPlusFilesystem, ForensicError>
59: pub fn open(path: &Path) -> Result<Self, ForensicError>
63: pub fn open_at_offset(path: &Path, offset: u64) -> Result<Self, ForensicError>
147:pub fn read_block(&mut self, block: u64) -> Result<Vec<u8>, ForensicError>
155:pub fn read_catalog(&mut self) -> Result<Vec<HfsPlusCatalogEntry>, ForensicError>
233:pub fn parse_hfsplus_btree(_data: &[u8]) -> Result<HfsPlusBtree, ForensicError>
244:pub fn extract_hfsplus_timeline(...)
```

### Interpretation

Four public functions matter for the walker:

| Function | Purpose | Walker Impact |
|---|---|---|
| `open_hfsplus(path)` | Free function constructor — takes file path | Phase A: add `Read + Seek` variant alongside |
| `HfsPlusFilesystem::open(path)` | Method constructor — takes file path | Phase A: add `Read + Seek` variant alongside |
| `HfsPlusFilesystem::open_at_offset(path, offset)` | Method constructor — partition-aware variant | Phase A: add `Read + Seek` variant alongside |
| `read_block(&mut self, block)` | Low-level block read by block number | Phase A: internal swap from `File` to `R: Read + Seek` handle |
| `read_catalog(&mut self)` | Returns `Vec<HfsPlusCatalogEntry>` — every catalog entry | **Phase B foundation** — wrap as iterator |

Two public functions are not relevant to the walker:

| Function | Why Not Relevant |
|---|---|
| `hfsplus_fast_scan(&[u8])` | In-memory scan on a byte slice. No I/O. Unaffected by Phase A. |
| `parse_hfsplus_btree(_data: &[u8])` | Stub — `_data` prefix means the parameter is unused. Leave alone. |
| `extract_hfsplus_timeline(...)` | Forensic timeline extraction, not general filesystem enumeration. Out of walker scope. |

### Architectural signal

Both `read_block` and `read_catalog` take `&mut self`. This means `HfsPlusFilesystem` holds mutable internal state during reads — almost certainly an open `File` handle plus a seek position. The struct stashes the file handle inside on construction. Path A's refactor swaps that internal handle from `File` to a `Read + Seek` consumer; the public method signatures (`&mut self`) stay the same.

---

## 3. Iteration Shape

### Finding

`read_catalog(&mut self) -> Result<Vec<HfsPlusCatalogEntry>, ForensicError>` is the existing iteration primitive. It eagerly materializes every catalog entry into a `Vec` and returns it. From a walker perspective, this is everything `walk()` needs — just not packaged as an `Iterator`.

### Walker `walk()` sketch

```rust
fn walk(&mut self) -> impl Iterator<Item = VfsEntry> + Send + '_ {
    self.read_catalog()
        .into_iter()                                  // Result -> iter (0 or 1 Vec)
        .flat_map(|entries| entries.into_iter())      // Vec -> iter of entries
        .map(|entry| convert_to_vfs_entry(entry))     // domain conversion
}
```

### Send analysis

`std::vec::IntoIter<T>` is `Send` whenever `T: Send`. The chain reduces to:

- `HfsPlusCatalogEntry` must be `Send` — verify with a one-line probe (see §6)
- `VfsEntry` must be `Send` — already used by `NtfsWalker` and `Ext4Walker`, so almost certainly `Send`; verify with a one-line probe (see §6)

If both are `Send`, the entire iterator chain is `Send` automatically. No `RefCell`-borrowing internal state, no surprise `!Send` types in the iterator.

### Implication

The Path B "iterator might borrow internal state" wrinkle that I flagged for HFS+ before this research **does not apply**. `read_catalog` returns owned data; the iterator owns the `Vec` and yields owned entries. The walker doesn't have to worry about lifetimes leaking from the parsed B-tree node cache.

---

## 4. Refactor Scope — Phase A (Read+Seek)

### Estimated delta

**120–180 LOC of changes**, not the 350 LOC ceiling estimated in the original SPRINTS_v15.md sprint sketch.

Breakdown:

| Component | Estimated LOC | Notes |
|---|---|---|
| Three new constructor variants taking `R: Read + Seek` | ~30 | Add alongside path-based; existing path constructors become thin wrappers delegating to new variants |
| Internal handle storage swap (`File` → `R: Read + Seek`) | 10–40 | Generic parameter or `Box<dyn Read + Seek + Send>` trait object — pick one based on monomorphization vs binary size tradeoff |
| `read_block` impl change | ~10 | Swap underlying `seek + read` calls to use new handle type |
| `read_catalog` impl change | ~10 | Same as above |
| Existing test updates | ~30 | Existing tests use path-based API; some tests added for Read+Seek variants |
| Doc comment updates | ~10 | Reflect new constructor surface |

### What does NOT change

- `hfsplus_fast_scan(&[u8])` — no I/O, untouched
- `parse_hfsplus_btree` — stub, untouched
- `extract_hfsplus_timeline` — forensic-specific, untouched
- `HfsPlusFilesystem`'s public `&mut self` method signatures — only the internal handle type changes
- Volume header, B-tree, catalog parsing logic — pure data transformation, no I/O coupling

### Constructor compatibility strategy

Preserve the existing path-based API as thin wrappers:

```rust
impl HfsPlusFilesystem {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let file = File::open(path)?;
        Self::open_reader(file)
    }

    pub fn open_at_offset(path: &Path, offset: u64) -> Result<Self, ForensicError> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        Self::open_reader(file)  // or open_reader_at_offset if needed
    }

    pub fn open_reader<R: Read + Seek + Send>(reader: R) -> Result<Self, ForensicError> {
        // new primary constructor
    }
}
```

Existing callers and tests of `open(path)` keep working. Walker calls `open_reader(partition_slice)`.

---

## 5. Walker Scope — Phase B

### Estimated delta

**~80 LOC** including `Vfs` trait impl, error mapping, and construction sugar.

### Sketch

```rust
// crates/strata-fs/src/walkers/hfsplus_walker.rs

pub struct HfsPlusWalker {
    inner: HfsPlusFilesystem,
}

impl HfsPlusWalker {
    pub fn open<R: Read + Seek + Send>(reader: R) -> Result<Self, VfsError> {
        let inner = HfsPlusFilesystem::open_reader(reader)
            .map_err(|e| VfsError::Open(e.to_string()))?;
        Ok(Self { inner })
    }
}

impl Vfs for HfsPlusWalker {
    fn walk(&mut self) -> Box<dyn Iterator<Item = VfsEntry> + Send + '_> {
        Box::new(
            self.inner
                .read_catalog()
                .into_iter()
                .flat_map(|entries| entries.into_iter())
                .map(convert_catalog_entry_to_vfs_entry)
        )
    }

    fn read(&mut self, path: &Path) -> Result<Vec<u8>, VfsError> {
        // Look up path in catalog, follow extent records, assemble file
        // contents through self.inner.read_block(...)
    }
}

fn convert_catalog_entry_to_vfs_entry(entry: HfsPlusCatalogEntry) -> VfsEntry {
    // Map HFS+ domain types to VFS-layer types
    // Handle data fork / resource fork distinction here
    // Resource forks become separate VfsEntry items with .rsrc suffix
}
```

### Special HFS+ considerations (carried forward from SPRINTS_v15.md)

- **Data fork vs resource fork** — both exposed as separate VfsEntry items, `.rsrc` suffix on the fork stream. Implementation in `convert_catalog_entry_to_vfs_entry`.
- **Case sensitivity** — respect the volume's `case_sensitive` flag (HFS+ vs HFSX).
- **Special files** — skip `\x00\x00\x00\x00HFS+ Private Data\x0D` directory by default; expose via `--include-private` flag.
- **Unicode normalization** — HFS+ stores filenames in NFC. Return as-is; do not re-normalize. Examiners need original bytes.

---

## 6. Outstanding Probes (Recommended for Sprint 1 Phase 0)

Before writing Phase A or Phase B production code, run two final one-line probes to lock the iterator contract:

```rust
#[cfg(test)]
mod _walker_send_probes {
    use super::*;

    fn assert_send<T: Send>() {}

    #[test]
    fn hfsplus_catalog_entry_is_send() {
        assert_send::<HfsPlusCatalogEntry>();
    }

    #[test]
    fn vfs_entry_is_send() {
        assert_send::<VfsEntry>();
    }
}
```

If both pass — and they almost certainly will, given both are plain data structs — the iterator chain in §3 is `Send` automatically and the walker's `Vfs::walk()` can return `Box<dyn Iterator<Item = VfsEntry> + Send + '_>` without issue.

If either fails, the error message identifies the offending field and the fix is local to that struct (almost always replacing an `Rc` with `Arc` or unwrapping a `RefCell`).

---

## 7. Recommendation

**Proceed with Path A as documented in SPRINTS_v15.md Session C Sprint 1.** Phase A is meaningfully smaller than originally estimated (120–180 LOC vs 350). Phase B is a thin wrapper around `read_catalog`. Run the two outstanding `Send` probes in §6 as Sprint 1 Phase 0 before writing any production code. The threading contract is friendly, the iteration primitive already exists, and no architectural surprises remain to be discovered.

The Session B "reopen per trait method" pattern is not needed for HFS+ — that pattern was forced by `ext4-view`'s internal `Rc<Ext4Inner>`. HFS+ has no such constraint.

---

## 8. Comparison to ext4 Research Outcome

| Dimension | ext4-view (Session 1 research) | HFS+ (this research) |
|---|---|---|
| Threading contract | `!Send + !Sync` (internal `Rc`) | `Send + Sync` |
| Reopen-per-call pattern | Required | Not needed |
| API addressing model | Offset-addressed (`Ext4Read::read(start, dst)`) | Path-based today; refactor adds Read+Seek |
| Existing iteration primitive | None — walker uses `Ext4::load + walk` | `read_catalog` returns `Vec<HfsPlusCatalogEntry>` |
| Walker scope | ~10 LOC adapter + walker | ~80 LOC walker (simpler — no adapter needed) |
| Phase A scope | Research only (no refactor) | ~120–180 LOC refactor |
| Phase B scope | ~10 LOC adapter + Vfs trait impl | ~80 LOC including iterator wrapper |

The two filesystems land at meaningfully different architectures despite both being walker sprints. ext4 had small Phase B because the external crate constrained the design. HFS+ has small Phase B because `read_catalog` already does the heavy lifting and no external crate constraints apply.

---

*Wolfmark Systems — Strata v15 Session C Phase 0*
*Probes verified against current `crates/strata-fs/src/hfsplus.rs` on 2026-04-19*
*Author of probe execution: Korbyn Randolph (MacBook Pro M1 Max, macOS)*
