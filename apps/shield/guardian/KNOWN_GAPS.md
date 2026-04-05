# ForensicSuite Known Gaps

**Document Type:** Honest Capability Inventory  
**Effective Date:** 2026-03-23  
**Maintained By:** Strata - Suite Guardian

---

## Preamble

This document is an honest accounting of what the ForensicSuite can and cannot do as of the documented date. It exists so that examiners and integrations know exactly where trust boundaries are.

A gap documented here is not a failure. A gap that is undocumented is a hazard.

---

## Section A: Container Format Support

### A.1: Fully Implemented Containers

| Format | Status | Notes |
|--------|--------|-------|
| RAW/DD | ✅ COMPLETE | Full VFS, memory-mapped reads, NTFS/FAT32/ext4 enumeration |
| E01 (EnCase) | ✅ COMPLETE | Via `ewf` crate, full VFS support |
| Directory | ✅ COMPLETE | Native filesystem passthrough VFS |

### A.2: Partial or Stubbed Containers

| Format | Status | Gap Detail |
|--------|--------|------------|
| VHD | ⚠️ PARTIAL | VFS header visible; enumeration may return partial or empty results |
| VMDK | ⚠️ PARTIAL | Silent failure possible; may return empty tree without error |
| VHDX | 🔲 STUB | Explicit error message expected; not functional |
| AFF4 | 🔲 STUB | Module commented out in `container/mod.rs` |
| VHD (split RAW) | 🔲 STUB | Module commented out |
| LUKS | 🔲 STUB | Returns zeros; encryption status unconfirmed |
| QCOW2 | 🔲 STUB | Returns zeros |
| VDI | 🔲 STUB | Returns zeros |
| LVM | 🔲 STUB | Returns zeros |
| L01 (FTK) | 🔲 STUB | Returns zeros |
| FileVault | 🔲 STUB | Returns zeros; encryption unhandled |
| Storage Spaces | 🔲 STUB | Returns zeros |

**Strata guidance:** Do not present VHD/VMDK results as complete analysis. Verify that enumeration returned actual file entries, not just a container header.

---

## Section B: Filesystem Support

### B.1: Verified Filesystem Parsing

| Filesystem | Status | Validation |
|------------|--------|------------|
| NTFS | ✅ COMPLETE | Full MFT parsing, USN journal, USN journal, attribute extraction |
| FAT32/exFAT | ✅ COMPLETE | Directory enumeration, file records |
| ext4 | ✅ COMPLETE | Directory enumeration, inodes |
| BitLocker | ⚠️ PARTIAL | Detection works; decryption not implemented |

### B.2: Filesystems with Known Limitations

| Filesystem | Status | Gap Detail |
|------------|--------|------------|
| APFS | ⚠️ PARTIAL | Snapshot diff parsing exists; full enumeration not fully validated |
| XFS | ⚠️ PARTIAL | Basic parsing exists; real-enumeration validation incomplete |
| Btrfs | 🔲 STUB | Module exists; not fully implemented |
| ReFS | 🔲 STUB | Not implemented |
| HFS+ | 🔲 STUB | Basic structures defined; not functional |

**Strata guidance:** For APFS and XFS, verify that the file enumeration count matches expected scale before trusting results. Report as "partial enumeration" if count is suspiciously low.

---

## Section C: Parser Coverage

### C.1: Stubbed Classification Modules

The following modules contain only struct definitions and/or `Default::default()` returns. Each has a `// STUB:` annotation:

| Module | Planned Feature |
|--------|-----------------|
| `wdigest.rs` | WDigest credential caching configuration |
| `lmcompat.rs` | LM Compatibility Level detection |
| `sccmcfg.rs` | SCCM/MECM client configuration |
| `cluster.rs` | Windows Failover Cluster topology |
| `computerinfo.rs` | Basic computer identification |
| `failover.rs` | Failover Clustering configuration |
| `spoolerinfo.rs` | Print Spooler status (PrintNightmare relevance) |
| `winlogon.rs` | Winlogon session and logon timestamps |
| `userrights.rs` | Local security policy user rights |
| `win32serv.rs` | Windows services enumeration |
| `wintasks.rs` | Scheduled tasks summary |
| `userassist.rs` | UserAssist ROT13-encoded execution data |
| `layout.rs` | Disk partition layout enum |
| `windowsdefender.rs` | Windows Defender status and exclusions |

**Impact:** These modules will return empty results or stub artifacts until implemented.

### C.2: Partial Parser Coverage

| Parser | Status | Gap Detail |
|--------|--------|------------|
| macOS APFS snapshots | ⚠️ PARTIAL | `ApfsSnapshotDiffParser` exists; full APFS enumeration limited |
| Cloud acquisition | ⚠️ PARTIAL | Dropbox, Google Drive, OneDrive parsers exist; cloud API integration not implemented |
| iOS extraction | ⚠️ PARTIAL | GrayKey, Cellebrite, Axiom parsers exist; live device acquisition not implemented |

---

## Section D: Hash and Hashset Workflows

### D.1: Implemented Features

| Feature | Status | Validation |
|---------|--------|------------|
| MD5/SHA1/SHA256 | ✅ COMPLETE | `hash_bytes()`, `hash_container()` functional |
| NSRL integration | ✅ COMPLETE | `load_nsrl_sqlite()` implemented |
| Custom hashsets | ✅ COMPLETE | `SqliteHashSetManager` functional |
| Hash categories | ✅ COMPLETE | KnownGood, KnownBad, KnownUnknown, Changed, NewFile |

### D.2: Hash Workflow Limitations

| Limitation | Status | Impact |
|------------|--------|--------|
| Hashset editing | 🔲 STUB | Current hashset workflow is read-only |
| Hashset import formats | ⚠️ PARTIAL | SQLite direct; text/hash-only import may need conversion |
| Hash match metadata | ⚠️ PARTIAL | Match results indicate category; detailed NSRL metadata access limited |

**Strata guidance:** Hashset operations are for triage and categorization. For detailed NSRL lookups, use the CLI's `hashset stats` and `hashset list` commands and verify field availability.

---

## Section E: GUI and Frontend Integration

### E.1: Tauri Command Coverage

The GUI uses these commands from `gui-tauri/src-tauri/src/lib.rs`:

| Command | Status | Notes |
|---------|--------|-------|
| `load_evidence_and_build_tree` | ✅ FUNCTIONAL | Calls `open_evidence_container`, `SqliteHashSetManager`, `build_filtered_tree`, `EvidenceAnalyzer` |
| `get_initial_timeline` | ✅ FUNCTIONAL | Calls `TimelineManager` |
| `acquire_live_memory` | ✅ FUNCTIONAL | Calls `MemoryAcquirer` |
| `generate_report` | ✅ FUNCTIONAL | Calls `ReportGenerator` |
| `export_jsonl_timeline` | ✅ FUNCTIONAL | Direct SQLite export |
| `list_plugins` | ✅ FUNCTIONAL | Calls `PluginManager` |
| `load_plugin` | ✅ FUNCTIONAL | Dynamic .dll/.so loading |

### E.2: Known GUI Limitations

| Issue | Status | Notes |
|-------|--------|-------|
| Frontend build | ⚠️ PARTIAL | esbuild platform mismatch in current environment |
| React integration | ⚠️ PARTIAL | Tauri backend complete; React components may need full integration |
| File browser pagination | ⚠️ PARTIAL | Large evidence trees may load incrementally |
| Timeline pagination | ⚠️ PARTIAL | Cursor-based pagination exists; UI may need completion |

**Strata guidance:** Before trusting GUI displays, verify that the underlying CLI command produces the expected envelope structure. Use `doctor` and `smoke-test` commands to validate the environment.

---

## Section F: Memory Analysis

### F.1: Implemented Features

| Feature | Status | Validation |
|---------|--------|------------|
| Memory acquisition | ✅ COMPLETE | `MemoryAcquirer` functional |
| Process listing | ✅ COMPLETE | Basic process enumeration |
| Memory parser | ⚠️ PARTIAL | Basic parsing; not full Volatility integration |

### F.2: Memory Analysis Gaps

| Gap | Status | Impact |
|-----|--------|--------|
| Volatility integration | 🔲 NOT IMPLEMENTED | Memory analysis is basic; complex memory forensics requires external tools |
| Kernel object parsing | 🔲 NOT IMPLEMENTED | Limited kernel-level artifact extraction |
| Malfind/driver detection | 🔲 NOT IMPLEMENTED | No malicious memory region detection |

**Strata guidance:** Memory acquisition is useful for live response triage. For deep memory forensics, the suite should be used for acquisition only, with analysis in Volatility or similar tools.

---

## Section G: Test Coverage

### G.1: Current Test Status

| Check | Status | Notes |
|-------|--------|-------|
| Debug build | ✅ COMPILES CLEAN | No errors, 24 warnings (documented) |
| Unit tests | ✅ PASSING | 519 tests passed, 1 ignored |
| Clippy strict | ❌ FAILING | 24+ unused import warnings — tracked, non-blocking |
| Test coverage | ⚠️ LIMITED | No fixture library yet; ingest pipeline not validated against real evidence |
### G.2: Test Impact on Guardian Validation

The failing test and clippy checks do not prevent runtime operation but indicate:
1. Test infrastructure needs `HashResults` struct update
2. Some structs need `Default` implementations added
3. Code cleanup needed before release

**Strata guidance:** The failing tests do not affect forensic correctness but should be resolved before production deployment.

---

## Section H: Strata-Specific Gaps

### H.1: Guardian Knowledge Base Maintenance

| Gap | Status | Notes |
|-----|--------|-------|
| Automated gap tracking | 🔲 NOT IMPLEMENTED | This document maintained manually |
| Parser behavior tests | 🔲 NOT IMPLEMENTED | No automated parser quality validation |
| Envelope validation tests | 🔲 NOT IMPLEMENTED | No automated CliResultEnvelope schema validation |
| Fallback mode detection | ⚠️ PARTIAL | KB bridge exposes `embedding_backend`; other fallbacks not instrumented |

### H.2: Bridge Monitoring

| Component | Status | Gap Detail |
|-----------|--------|------------|
| KB bridge (Strata) | ✅ RUNNING | `dfir_kb_bridge.py` operational on port 8090 |
| Llama server | ✅ RUNNING | llama-server.exe operational on port 8080 |
| Envelope shape validation | 🔲 NOT IMPLEMENTED | No automated validation that GUI claims match envelope fields |
| Stale data detection | 🔲 NOT IMPLEMENTED | No timestamp tracking on cached responses |

---

### H.3: Build and Validation Follow-Ups

| Gap | Status | Notes |
|-----|--------|-------|
| KB bridge /summarize endpoint | 🔲 NOT IMPLEMENTED | `kb_assist.rs` has graceful fallback; activates when the Python bridge exposes the endpoint |
| Evidence fixture library | 🔲 NOT IMPLEMENTED | No synthetic test evidence for parser regression testing |
| Frontend TypeScript clean | ✅ COMPLETE | `npx tsc --noEmit` passes after Task 1.1 cleanup |
## Section I: Resolution Tracking

| Gap | Discovered | Status | Resolution Target |
|-----|-----------|--------|------------------|
| Test compilation error | 2026-03-22 | OPEN | Before release |
| Clippy errors | 2026-03-22 | OPEN | Before release |
| VMDK silent failure | 2026-03-22 | OPEN | Documented; no fix scheduled |
| VHDX stub | 2026-03-22 | OPEN | No implementation planned |
| Hashset editing | 2026-03-22 | OPEN | Not yet planned |
| Frontend build | 2026-03-22 | OPEN | Requires platform-specific build fix |

---

## Document Maintenance

This document must be updated when:
- New stubs are discovered
- Existing stubs are implemented
- Container support changes
- Parser coverage expands or contracts
- GUI integration gaps are found

Location: `D:\forensic-suite\guardian\KNOWN_GAPS.md`

