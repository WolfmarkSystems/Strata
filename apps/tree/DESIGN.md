# Strata Tree - Design Guide

This document contains the data points and architecture decisions that define the unique, legal-safe implementation strategy for Strata Tree, a Rust-based digital forensic suite. It is informed by general digital forensics best practices and high-level behaviors of X-Ways, but explicitly avoids license-protected design and code reuse.

## 1. Project Identity and Constraints

- Name: Strata Tree
- Language: Rust
- License: MIT or Apache 2.0
- Goal: filesystem & disk-image forensic suite with strong performance, accuracy, security, and extensibility.
- Non-goal: clone X-Ways internals, UI, proprietary formats; no dependency on closed source.

## 2. Core use cases

1. Mount and analyze disk images (E01, DD, AFF, VHD, VMDK, raw) + physical disk access.
2. Extract filesystem metadata (NTFS, FAT, exFAT, ext2/3/4, XFS, ReiserFS, HFS+, APFS, ReFS).
3. Volume snapshot and persistence for case reuse.
4. Fast text searches (indexed + recursive) including embedded archives.
5. Carving file fragments and recovered deleted objects.
6. Hashing and hit list classification (MD5/SHA1/SHA256, fuzzy hashing).
7. Audit trail and integrity. Chain-of-custody logs.

## 3. Unique technical data points and design decisions

### 3.1 engine modules

- vt-core
  - `ImageReader` trait + concrete readers per container type.
  - `FsParser` trait + concrete parser per filesystem.
  - `Object` model: `FileObject`, `DirectoryObject`, `Unallocated`, `Slack`, `ArchiveMember`.
  - `AllocationMap` + `ActiveMap` to support non-redundant scan.

- vt-snapshot
  - Persisted database (RocksDB/LMDB/SQLite) with strong alignment to `case_id`, `snapshot_id`.
  - Includes dataset version + parser version for invalidation.
  - Stores paths, metadata, file object hashes, text extraction state.

- vt-index
  - `Tokenizer`: text, HTML, XML, binary, machine
  - Inverted index (block-based) with optional BTree for phrase matching.
  - Config: `meta-only`, `text-only`, `full-content`.

- vt-carve
  - signature-driven header/footer search (PE, JPEG, PNG, PDF, DOCX, ZIP, RAR, MP4, etc.) with optional size heuristics.
  - fragmentation-aware by reading allocation map.

### 3.2 concurrency + I/O

- pipeline stages on worker threads with `crossbeam` or `tokio` channels
- read pool uses `mmap` for file-backed images, with adaptive chunk size (4MB-64MB)
- primary index and snapshot writes in background: uses `async` commit with fsync throttling.

### 3.3 robustness and safety

- all parsing uses `nom`/`binread` with explicit bounds checks
- every filesystem parser returns `ParseResult` with recoverable errors and statistics
- isolates heavy file-type extraction in subprocess (`vt-worker`) with timeouts
- optional `sandbox` for untrusted archives (using containerized plugin)

### 3.4 non-canonical but X-Ways-inspired features

- `snapshot incremental update`:
  - maintain `volume fingerprint` (hash of partition table + key sectors)
  - cache per-file hash; on re-scan, skip file with unchanged reference + hash
- `external text extraction cache`.
  - store extracted text in snapshot blob, keyed by hash + mime.
- `gallery thumbnail engine` with optional external processor.
- `virtual free space` object model and indexing ability.

### 3.5 no-copy policies

- avoid exact names/flags used in X-Ways (e.g., do not use `VS`, use `VT-Snapshot`)
- UI workflows same general goals but different terms (e.g., "Evidence View" vs "Snapshot Browser")
- no reference to internal X-Ways dialog paths or binary structures; use public NTFS, FAT specs.

## 4. Scalable feature roadmap

1. `phase-0`: basic image read + filesystem traversal + table metadata export.
2. `phase-1`: snapshot store + file list, Newton/CS algorithm for allocation map.
3. `phase-2`: metadata search + hash set pipeline + user-defined tags.
4. `phase-3`: indexing + text search + archive expansion.
5. `phase-4`: plugin API + external script support + GUI.

## 5. Minimal v0 demo interface

`vt show <image>`: print filesystem tree.
`vt hash <image> --type sha256`: compute hashes for all resident files.
`vt index <image> --target case.db`: build text index.
`vt search <case.db> --q "password"`: fast result set by index.

## 6. Key deliverables to start building

- `Cargo.toml` workspace for `vt-core`, `vt-cli`, `vt-index`.
- `vt-core/src/lib.rs`: core traits, structs, base error.
- `vt-cli/src/main.rs`: command parser, task dispatch.
- test assets: small sample disk image, sample NTFS and FAT partitions.
- `docs/API.md` and `docs/feature_matrix.md`.

## 7. Data required from you before development

- target OSes (Windows + Linux + macOS /only)?
- prioritized file systems (NTFS-only first is fine; others as stretch goals).
- whether to support enterprise encryption formats (BitLocker, APFS FileVault).
- intended score/verification criteria (speed, memory, coverage).

## 8. Security and ethical governance

- add `SECURITY.md` and `ETHICS.md` before public release.
- include built-in decontamination step for evidence (hash list offload, readonly mode).
- add legal disclaimers: meant for lawful forensic use only.
