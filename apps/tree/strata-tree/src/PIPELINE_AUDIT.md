# Strata Tree Indexing Pipeline Audit
**Date:** 2026-03-27
**Auditor:** Claude

## Pipeline Flow

```
Open Evidence Dialog (ui/dialogs/open_evidence.rs)
  |
  v
evidence::loader::start_indexing(path, evidence_id)
  |
  v  (spawns std::thread)
  |
  +-- Directory? --> evidence::indexer::index_directory() --> std::fs recursive walk
  |
  +-- Container? --> strata_fs::container::EvidenceSource::open(path)
        |
        +-- vfs.get_volumes() --> detect partitions (MBR/GPT)
        |
        +-- For each volume: enumerate_{ntfs,fat32,ext4,...}_directory(vol)
        |
        +-- If no volumes: vfs.read_dir("/") fallback
        |
        +-- If nothing works: register_container_entry (single entry)
        |
        v
  evidence::indexer::send_vfs_entries_count() --> IndexBatch::Files(Vec<FileEntry>)
  |
  v
  IndexBatch::Done { total, elapsed_ms }
  |
  v  (mpsc channel)
  |
  app.rs::poll_indexer() -- drains channel each frame
  |
  +-- IndexBatch::Files --> state.file_index.extend(entries)
  +-- IndexBatch::Done  --> state.indexing_state = Complete
  +-- IndexBatch::Error --> state.error = Some(e)
  |
  v
  ui::render() --> titlebar shows stats, file_table shows visible_files()
```

## Where the Pipeline Breaks for E01 Images

### Root Cause Analysis

1. **strata_fs::container::EvidenceSource::open(path)** succeeds for E01 files
   (the `ewf` crate parses the E01 header correctly).

2. **vfs.get_volumes()** on EwfVfs calls partition detection which reads the
   first 1MB of the E01 image and detects MBR/GPT partitions. For NTFS
   Windows images this typically finds 1-3 partitions.

3. **enumerate_ntfs_directory(vol)** is where it breaks. The EwfVfs
   implementation at line 2318 calls `self.enumerate_ntfs_directory(vol_info)`
   which calls the EwfVfs inherent method (line 1523+). This method:
   - Creates an EwfContainerRef adapter
   - Calls `crate::ntfs::enumerate_directory()` with the container
   - Returns whatever entries NTFS parsing finds

4. The NTFS parsing in `crate::ntfs::enumerate_directory()` does real MFT
   parsing via the `ntfs` crate. If it succeeds, it returns VfsEntry records.
   If any step fails (bad offset, read error, parse error), it returns Ok(vec![]).

5. **The result: VFS returns entries but they may be empty or partial.**
   The loader then calls `send_vfs_entries_count()` which converts VfsEntry to
   FileEntry and sends them via the channel.

6. **send_vfs_entries_count()** correctly sends batches of 500 and returns count.

7. **poll_indexer()** correctly extends file_index and updates status.

### Why "0 files" Happens

The most likely causes for E01 images showing 0 files:

A. **EvidenceSource::open() fails** -- e01 parsing fails, falls to error path
   which sends Error + registers 1 container entry + Done{total:1}. The Error
   message is consumed but doesn't stop processing. The 1 container entry
   appears, but the user sees "1 file" not "0 files".

B. **get_volumes() returns empty** -- partition detection fails (e.g. corrupt
   MBR, GPT not recognized). Then read_dir("/") fallback also fails for
   E01 (it's not a directory). So register_container_entry fires.

C. **enumerate_ntfs_directory returns Ok(vec![])** -- NTFS parsing runs but
   finds no entries. The check `if !vfs_entries.is_empty()` skips it, found_files
   stays false, falls through to read_dir which also fails for E01.

D. **Channel dropped too early** -- Not the case here; the thread owns tx
   and sends Done at the end.

### Key Data Structures

- `FileEntry` (state.rs): id, evidence_id, path, name, extension, size,
  is_dir, is_deleted, is_carved, timestamps, mft_record, hashes, category,
  hash_flag. All fields are String/Option<String>. id is UUID.

- `EvidenceSource` (state.rs): id, path, format, sha256, hash_verified,
  loaded_utc, size_bytes.

- `IndexBatch` (state.rs): Files(Vec<FileEntry>), Done{total,elapsed_ms},
  Error(String).

- Communication: mpsc::channel<IndexBatch>. Sender in background thread,
  Receiver stored as state.indexing_rx: Option<Receiver>.

### What strata-fs VFS Already Provides

The strata-fs crate has substantial existing support:
- E01 opening via `ewf` crate (EwfVfs)
- Partition detection (MBR/GPT)
- NTFS enumeration via `ntfs` crate
- FAT32 fast scan
- APFS detection
- XFS, Ext4 enumeration stubs
- VfsEntry { name, path, is_dir, size, modified }

The EwfVfs.get_volumes() does real partition detection including:
- MBR signature check (0xAA55)
- GPT scanning
- APFS container superblock detection
- Filesystem type detection from boot sector bytes

### Recommendations

1. **Add tracing** to the loader to surface exactly which path is taken
   and what strata-fs returns at each step.

2. **The NTFS parser in strata-fs works** -- but it needs correct volume
   offset calculation. The `vol_info.offset` must be the byte offset of
   the NTFS partition within the E01 image.

3. **FileEntry needs parent_path** for directory-based browsing. Currently
   paths are flat strings; the tree panel uses `collect_dirs()` which
   extracts parent paths. This works but is fragile.

4. **Hex editor** cannot read files inside E01 containers because
   HexState::load_file() uses std::fs::read() which only works for
   host filesystem paths. For VFS files, it needs to use the strata-fs
   read API.
