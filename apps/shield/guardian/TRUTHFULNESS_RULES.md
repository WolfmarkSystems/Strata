# ForensicSuite Truthfulness Rules

**Document Type:** Non-Negotiable Forensic Truth Contract  
**Effective Date:** 2026-03-23  
**Enforced By:** Strata - Suite Guardian

---

## Preamble

Every result that leaves this suite—displayed in the GUI, exported in reports, or passed to external tools—must be grounded in actual evidence. This document defines the explicit rules that make that guarantee possible.

These rules are not style guidelines. Violating them produces false forensic conclusions.

---

## Rule 1: Container Opened ≠ Filesystem Parsed

**Statement:** Opening an evidence container (RAW, E01, Directory) does not mean the contained filesystem was successfully parsed.

**Why it matters:** A RAW image may contain unallocated space, an unsupported partition layout, or a damaged filesystem that prevents enumeration. The container is open; the filesystem may not be accessible.

**Correct behavior:**
```
Container: OPEN (evidence loaded)
Filesystem: ENUMERATED (filesystem structure readable) ← Must be verified
Enumeration: SUCCEEDED (files listed) ← Must be verified
```

**Strata checks:**
- Does the tree node for the filesystem show files, or is it empty?
- Does the filetable command return actual entries?
- Are the enumeration results consistent with the container size?

---

## Rule 2: Filesystem Detected ≠ Enumeration Succeeded

**Statement:** Detecting a filesystem signature (NTFS, ext4, APFS) does not mean enumeration of its contents succeeded.

**Why it matters:** A filesystem may be detected but locked, encrypted (BitLocker), corrupted, or of a version the engine does not fully support. Detection is a necessary but not sufficient condition for enumeration.

**Correct behavior:**
```
Detection: NTFS signature found at offset 0x100000
Encryption: BitLocker detected ← Encryption status matters
Enumeration: 12,847 files enumerated ← Real count required
```

**Strata checks:**
- Is the enumeration count greater than zero?
- Does the count match expected scale for the evidence size?
- Are there empty volumes where files should exist?

---

## Rule 3: Enumeration Succeeded ≠ Indexing Completed

**Statement:** Listing files in a filesystem does not mean all those files were parsed by their respective artifact parsers.

**Why it matters:** Parsing is selective. The engine matches files against parser patterns (e.g., `*.evtx`, `*.reg`). Not every file matches a parser. Files that don't match are not failures—they are simply not artifact targets.

**Correct behavior:**
```
Files enumerated: 12,847
Files matched by parsers: 847
Parser results: 12,431 artifacts extracted
```

**Strata checks:**
- Does the artifact count reflect actual parser output, not enumeration count?
- Are parsers reporting actual artifact counts from `parse_file()`?
- Does the timeline show real `ParsedArtifact` entries, not synthesized ones?

---

## Rule 4: Zero Rows ≠ Success (Unless Explicitly Empty by Design)

**Statement:** A command, parser, or indexing operation that returns zero rows must not be presented as successful indexing.

**Why it matters:** Zero rows can mean:
- The source file was empty
- The source file was corrupted
- The parser failed silently
- The file format was not recognized
- The data was encrypted or inaccessible

None of these are "successful indexing." They are empty results.

**Correct behavior:**
```
Parser run: YES
Source file: /Evidence/user.dat (0 bytes)
Result: 0 artifacts
Status: EMPTY_SOURCE (not "SUCCESS")
```

**Strata checks:**
- Is zero-row output explicitly labeled (in envelope, UI, or report)?
- Did the parser actually run, or was it skipped?
- Is there a warning or error in the envelope that explains the zero rows?

---

## Rule 5: Synthetic/Debug Placeholders ≠ Real Evidence

**Statement:** Output that contains debug text, TODO comments, STUB markers, or `Default::default()` values must never be counted as real evidence or presented as discovered artifacts.

**Examples of prohibited content:**
```rust
// STUB: implement full parser
description: "TBD: add real implementation"
artifact_type: Default::default()
artifacts: vec![]  // returned on error path, not empty-by-design
```

**Why it matters:** Placeholders indicate unimplemented or failed code paths. Presenting them as evidence produces false forensic conclusions.

**Correct behavior:**
```
Parser: ShimcacheParser
Result: 0 artifacts
Envelope status: "warn"
Envelope warning: "No valid entries found in Shimcache format"
```

**Strata checks:**
- Does parser output contain any `STUB`, `TODO`, `TBD`, or `Default::default()` artifacts?
- Are artifact descriptions human-readable or clearly synthetic?
- Does the `source_path` field on every artifact point to a real file?

---

## Rule 6: Unsupported Formats ≠ Supported Formats

**Statement:** A format that is declared in `ContainerType` but not fully implemented must not be presented as a fully supported evidence format.

**Current stubs (as of March 2026):**
| Format | Status | Presentation Rule |
|--------|--------|-----------------|
| VHD | PARTIAL | May show VFS header only; no enumeration guarantee |
| VHDX | STUB | Error message expected; no results |
| VMDK | PARTIAL | Silent failure possible; verify tree before trusting |
| AFF4 | STUB | Returns zeros or empty; must not be called "analyzed" |
| LUKS | STUB | Returns zeros or empty; encryption status unconfirmed |

**Strata checks:**
- Is the container format listed in `KNOWN_GAPS.md`?
- Does the GUI show a warning for partial/stubbed formats?
- Are VMDK and VHD results checked for actual data vs. empty returns?

---

## Rule 7: Fallback Modes Must Be Visibly Labeled

**Statement:** When the suite falls back to an alternative behavior (e.g., regex-token embedding instead of sentence-transformers, SQLiteHashSetManager for unknown hashsets), the fallback must be indicated in the UI and reports.

**Why it matters:** Fallbacks indicate reduced capability. An examiner must know when they are working with full fidelity vs. degraded mode.

**Correct behavior:**
```
Embedding backend: sentence-transformers:all-MiniLM-L6-v2
Embedding backend: regex-token (fallback: sentence-transformers unavailable)
```

**Strata checks:**
- Does the KB bridge health endpoint expose `embedding_backend`?
- Is the fallback label visible in the UI when active?
- Are fallback modes logged and traceable?

---

## Rule 8: GUI Claims ≤ CLI Reality

**Statement:** Any capability, feature, or result displayed in the GUI must be directly supported by what the CLI actually returns.

**Why it matters:** The GUI is a view on CLI output. If the GUI claims a timeline exists but the `timeline` command returns zero entries, the GUI is lying.

**Correct behavior:**
```
CLI: forensic_cli timeline --case mycase
Envelope status: "ok"
Envelope data: { "entries": 0, "timeline": [] }
GUI display: "Timeline: 0 entries" ← Matches CLI reality
```

**Strata checks:**
- Does the GUI claim match the envelope `data` field structure?
- Are envelope warnings/errors surfaced in the GUI, not dropped?
- Does the GUI handle missing fields gracefully (not crash or show NaN)?

---

## Rule 9: Partial Results Must Be Surfaced Clearly

**Statement:** When a command produces partial results (some parsers succeeded, others failed), the partial nature must be explicit, not buried.

**Why it matters:** A timeline with 80% of expected artifacts is still a partial timeline. Presenting it as complete misleads examiners.

**Correct behavior:**
```
Parser run: 45/50 parsers succeeded
Failed parsers: ["RegistryHive::custom_format", "CloudSync::dropbox_cache"]
Timeline: 12,847 entries (partial)
Warning: "2 parsers failed; results may be incomplete"
```

**Strata checks:**
- Does the envelope contain a `warning` field when parsers fail?
- Is the failed parser count visible in the UI?
- Does the timeline page show a partial result indicator?

---

## Rule 10: Missing Data Must Not Be Fabricated

**Statement:** Hash values, match results, timeline entries, or artifact data that do not exist in the evidence source must not be invented to fill UI slots or complete partial reports.

**Explicit prohibitions:**
- Never create `sha256: "0000..."` as a placeholder hash
- Never create a timeline entry with `timestamp: 0` as a filler
- Never report `match: unknown` as equivalent to `match: none`
- Never synthesize file paths that don't exist in the evidence

**Correct behavior:**
```
Hash computation: FAILED (file not accessible)
Hash field: null ← Not "0000..."
Timeline entry: NOT CREATED ← Not fake entry with timestamp 0
```

**Strata checks:**
- Are all hash fields traceable to actual `hash_bytes()` output?
- Are timeline entries created only from `ParsedArtifact` results?
- Does the hashset match command return `null` for unmatched vs. `unknown`?

---

## Rule 11: Sidecar Health ≠ Bridge Health

**Statement:** A running CLI sidecar process does not mean the forensic engine is functioning correctly.

**Why it matters:** The sidecar can spawn, accept connections, and even return exit code 0 while producing empty or error-laden output.

**Correct behavior:**
```
Process: RUNNING (llama-server.exe alive)
Model: LOADED (Llama 3.1 8B)
API: RESPONDING (HTTP 200)
Output shape: VALID (matches expected schema) ← This is the real health check
```

**Strata checks:**
- Does the health endpoint confirm output shape validity, not just process existence?
- Are empty HTTP 200 responses distinguished from valid JSON responses?
- Is the CLI sidecar's stderr monitored, not just its exit code?

---

## Enforcement

These rules are enforced by:
1. **Strata validation** - Automated checks on envelope fields and output shapes
2. **Guardian knowledge base** - This document and associated validation rules
3. **Human review** - Escalation pathway for uncertain cases
4. **Known gaps tracking** - `KNOWN_GAPS.md` documents current limitations honestly

When a rule is violated, Strata flags it and prevents the claim from propagating. The violation is logged, the examiner is notified, and the issue is escalated for resolution.

---

## Document Maintenance

This document must be updated when:
- New container formats are added or stubbed
- Parser behavior changes are introduced
- GUI/CLI contract mappings are updated
- New fallback modes are added

Location: `D:\forensic-suite\guardian\TRUTHFULNESS_RULES.md`
