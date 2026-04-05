# ForensicSuite Runtime Failure Patterns

**Document Type:** Dangerous Pattern Catalog  
**Effective Date:** 2026-03-23  
**Purpose:** Teach Strata to recognize and respond to dangerous runtime patterns

---

## Preamble

Forensic tools fail in subtle ways. Unlike application crashes, forensic failures often return success codes (exit 0) while producing empty, corrupted, or misleading output. This catalog documents the dangerous patterns Strata must recognize and the appropriate response for each.

---

## Pattern 1: Instant Indexing with No Data

### Description
A command completes in milliseconds and returns zero rows. The tool claims to have processed the evidence but found nothing.

### Example
```
Command: forensic_cli timeline --case evidence123
Elapsed: 47ms
Envelope status: "ok"
Envelope exit_code: 0
Timeline entries: 0
```

### Why It's Dangerous
A timeline with zero entries in 47ms is not a valid result. Either:
- The evidence was not actually parsed
- The parsers silently failed
- The evidence format was not recognized but no error was raised
- The container was opened but the filesystem was not enumerated

Presenting this as "analyzed with 0 findings" implies the evidence contains nothing, which is rarely true.

### What Strata Checks Next

1. **Envelope warning field:** Did the command return a warning about parsing failures?
2. **Parser log output:** Are there stderr messages indicating which parsers ran?
3. **Evidence structure:** Is the container type supported (see `KNOWN_GAPS.md`)?
4. **Filesystem enumeration:** Does `filetable` return actual file entries?
5. **Time scale:** Is 47ms realistic for the evidence size?

### Strata Response
If the result is implausibly fast for the evidence size, Strata flags the result as **UNVERIFIED** and recommends manual CLI verification.

---

## Pattern 2: Success Envelope with Zero Real Rows

### Description
The `CliResultEnvelope` has `status: "ok"` and `exit_code: 0`, but the data payload contains zero real rows or empty collections.

### Example
```json
{
  "status": "ok",
  "exit_code": 0,
  "warning": null,
  "error": null,
  "data": {
    "artifacts": [],
    "count": 0
  }
}
```

### Why It's Dangerous
The envelope signals success, but the payload is empty. This pattern is designed to look legitimate. The GUI may display "Analysis Complete" with no indication that no data was found.

### What Strata Checks Next

1. **Empty by design?** Is this expected for the input type? (e.g., empty recycle bin)
2. **Parser warnings:** Did individual parsers report failures?
3. **Envelope warning field:** Is there a warning that explains the empty result?
4. **Source file status:** Is the source file empty, corrupted, or unsupported?

### Strata Response
Strata distinguishes between:
- **INTENTIONALLY_EMPTY:** `warning` field explains why, source file verified empty or unsupported
- **UNEXPLAINED_EMPTY:** `warning` is null, source file exists and has content → flagged as **POTENTIAL_SILENT_FAILURE**

---

## Pattern 3: Filesystem Detected but Tree/Filetable Empty

### Description
The evidence container is opened, a filesystem signature is detected, but the directory tree contains no entries.

### Example
```
Evidence container: OPEN
Container type: RAW
Filesystem detected: NTFS at offset 0x100000
Directory tree: EMPTY (0 nodes)
Filetable entries: 0
```

### Why It's Dangerous
NTFS containers with zero entries are physically implausible. This indicates either:
- The NTFS parser failed silently
- The volume is encrypted (BitLocker) and inaccessible
- The MFT is damaged
- The filesystem version is unsupported

### What Strata Checks Next

1. **BitLocker status:** Is the volume BitLocker-encrypted?
2. **Encryption field:** Does the envelope indicate encryption was detected?
3. **MFT integrity:** Does `examine` or `doctor` report MFT parsing status?
4. **Container type:** Is this a supported container (see `KNOWN_GAPS.md`)?

### Strata Response
If filesystem is detected but tree is empty and no encryption flag is set, Strata flags as **FILESYSTEM_PARSE_FAILURE** with recommendation to verify via CLI `filetable` command.

---

## Pattern 4: Command Succeeds but Page Remains Fallback-Only

### Description
A CLI command returns successfully, but the GUI page still shows fallback or placeholder content.

### Example
```
CLI command: forensic_cli hashset list
Envelope status: "ok"
Envelope exit_code: 0
Expected: Hash list displayed
Actual: GUI shows "No hashsets loaded" or spinner continues
```

### Why It's Dangerous
The CLI worked, but the GUI did not update. This could indicate:
- GUI parsing error for the response format
- Field name mismatch between CLI output and GUI expectations
- Race condition in async update
- Cached response displayed instead of fresh data

### What Strata Checks Next

1. **GUI console errors:** Are there JavaScript errors in the browser console?
2. **Envelope field names:** Do the CLI field names match what the GUI expects?
3. **JSON structure:** Is the envelope `data` field structured as expected?
4. **Freshness:** Is the GUI displaying cached data from a previous session?

### Strata Response
Strata documents the GUI/CLI field mapping discrepancy in `COMMAND_CONTRACTS.md` if found, and recommends CLI verification as ground truth.

---

## Pattern 5: Sidecar Missing / Wrong Model / Wrong Path

### Description
The sidecar process cannot be found, or it is found but running the wrong binary or model version.

### Example
```
Error: Failed to run CLI at 'D:\forensic-suite\target\forensic_cli.exe': 
       The system cannot find the file specified.

Error: Llama model not found: 
       Expected: Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf
       Found: Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf
```

### Why It's Dangerous
Wrong sidecar or model means:
- Commands run against the wrong tool version
- Output format may not match expectations
- Results may be from an outdated or modified binary

### What Strata Checks Next

1. **Sidecar hash:** Does the running binary match the expected version?
2. **Model file:** Does the model path match the configured path in `start_llama_server.bat`?
3. **Version field:** Does `capabilities` command return the expected tool version?

### Strata Response
If sidecar or model mismatch is detected, Strata prevents the operation and returns **SIDEcar_MISMATCH** with the expected vs. actual paths.

---

## Pattern 6: Bridge Healthy but Response Shape Mismatched

### Description
The KB bridge health endpoint returns 200 OK, but the chat/response payload has unexpected structure.

### Example
```
Bridge health: {"status":"ok", ...}
Chat response: {"error": "llama_forward_failed", "detail": "..."}
Response shape: {"choices": [...]}  // Expected format
Actual format: {"error": {...}}    // Error envelope
```

### Why It's Dangerous
A healthy bridge that returns error-shaped responses can cause:
- GUI parsing crashes if it expects success shape
- Silent error propagation if errors are not surfaced
- Incorrect assumption that inference succeeded

### What Strata Checks Next

1. **Response top-level key:** Is it `choices` (success) or `error` (failure)?
2. **Envelope status:** Does the response contain `status` field and what is its value?
3. **Error detail:** Is there a human-readable error message?
4. **Partial success:** Did some completions succeed while others failed?

### Strata Response
Strata validates response shape against the expected `/v1/chat/completions` schema before forwarding. If shape is mismatched, Strata returns the raw error with appropriate status code.

---

## Pattern 7: GUI Showing Stale or Synthetic Data as Real

### Description
The GUI displays data that was cached from a previous session or synthesized by the application, presenting it as current evidence-derived data.

### Example
```
GUI display: "Timeline: 12,847 entries"
Actual state: Data loaded from cache file created 3 days ago
Current evidence: New case, empty timeline
```

### Why It's Dangerous
Stale data presented as fresh can lead to:
- Incorrect forensic conclusions
- Mixing evidence from different cases
- Reporting on data that no longer exists

### What Strata Checks Next

1. **Cache headers:** Does the data have timestamp metadata?
2. **Evidence metadata:** Does the displayed case ID match the loaded evidence?
3. **Freshness indicator:** Is there a last-updated timestamp visible?
4. **Reload behavior:** Does refresh update the display or keep cached data?

### Strata Response
Strata validates that displayed data includes case ID and timestamp metadata. If stale data is detected, Strata surfaces a warning and recommends data refresh.

---

## Pattern 8: Parser Returns Partial Results Without Warning

### Description
A parser processes some records successfully and fails on others, returning partial artifacts without indicating that failures occurred.

### Example
```
Records in file: 1,247
Records parsed successfully: 847
Records failed: 400 (file corrupted at offset 0x4A000)
Artifacts returned: 847
Warning in envelope: null  // No indication of failures
```

### Why It's Dangerous
The examiner sees 847 artifacts and assumes this represents all parseable records. The 400 failed records may contain critical evidence that was silently dropped.

### What Strata Checks Next

1. **Envelope warning field:** Is there a warning about parse failures?
2. **Parser stderr:** Are there error messages in the logs?
3. **File integrity:** Does the `doctor` command report file integrity issues?
4. **Expected vs. actual:** Is the artifact count consistent with file size?

### Strata Response
If a parser returns partial results without warning, Strata flags the result as **PARTIAL_PARSE_UNREPORTED** and surfaces the warning if one exists, or recommends CLI `doctor` verification.

---

## Pattern 9: Evidence Integrity Chain Broken

### Description
The case database's `activity_log` table has a broken hash chain, indicating data tampering or incomplete operation.

### Example
```
Command: forensic_cli verify --case evidence123
Envelope status: "warn"
Envelope warning: "Hash chain violation at record 847"
Integrity violations: 3
```

### Why It's Dangerous
A broken hash chain means:
- Evidence records may have been modified without audit
- The case database is no longer tamper-evident
- Findings derived from this case may be unreliable

### What Strata Checks Next

1. **Violation details:** Which tables and operations had violations?
2. **Chain position:** Is the violation in recent or historical records?
3. **Remediation:** Can the case be replayed to restore integrity?

### Strata Response
Strata immediately flags integrity violations as **CRITICAL** and prevents further analysis of the affected case until resolved via `replay-verify` command.

---

## Pattern 10: Container Opens but Returns Zeros for All Reads

### Description
An evidence container is successfully opened, but all read operations return zeros or empty buffers.

### Example
```
Container: OPENED (E01)
Container size: 40 GB
Read test: 8192 bytes at offset 0x1000
Result: 8192 bytes of 0x00
```

### Why It's Dangerous
Zeros on read indicate:
- The container is a zero-filled sparse file
- The evidence is encrypted and decryption failed
- The read path is broken
- The file is a decoy or test artifact

### What Strata Checks Next

1. **Container type:** Is this a stubbed format (AFF4, LUKS, etc.)?
2. **Encryption status:** Is the container encrypted?
3. **Sparse file:** Is the file sparse or truly zero-filled?
4. **Hash verification:** Does the container hash match expected values?

### Strata Response
If all reads return zeros on a non-sparse container, Strata flags as **CONTAINER_READ_FAILURE** and recommends verifying the evidence source.

---

## Response Protocol Summary

| Pattern | Severity | Strata Action |
|---------|----------|---------------|
| Instant indexing, no data | HIGH | Flag UNVERIFIED, recommend CLI check |
| Success envelope, zero rows | MEDIUM | Distinguish intentional vs. unexplained |
| Filesystem detected, tree empty | HIGH | Flag FILESYSTEM_PARSE_FAILURE |
| Command succeeds, GUI fallback | MEDIUM | Document field mapping issue |
| Sidecar/model mismatch | CRITICAL | Block operation |
| Bridge healthy, shape mismatch | MEDIUM | Validate schema, return error |
| Stale/synthetic data displayed | HIGH | Surface warning, recommend refresh |
| Partial results without warning | HIGH | Flag PARTIAL_PARSE_UNREPORTED |
| Integrity chain broken | CRITICAL | Block case, recommend replay |
| Container opens, reads zeros | CRITICAL | Flag CONTAINER_READ_FAILURE |

---

## Document Maintenance

This document must be updated when:
- New failure patterns are discovered
- Existing patterns are resolved
- Response protocols change
- New envelope fields are added

Location: `D:\forensic-suite\guardian\RUNTIME_FAILURE_PATTERNS.md`
