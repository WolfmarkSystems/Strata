# ForensicSuite Command Contracts

**Document Type:** CLI-to-GUI Contract Reference  
**Effective Date:** 2026-03-23  
**Purpose:** Document how commands are used, what they return, and how the GUI must handle their output

---

## Preamble

The ForensicSuite uses a **contract-first** approach to CLI-GUI integration. Every command that the GUI calls has a defined output shape (the `CliResultEnvelope`) and expected data fields. The GUI must not assume fields exist that the CLI did not return.

This document establishes the command contracts, explains the envelope system, and defines the rules for safe integration.

---

## Section A: The CliResultEnvelope Contract

### Structure

Every CLI command returns a `CliResultEnvelope`:

```rust
pub struct CliResultEnvelope {
    pub tool_version: String,           // "0.1.0"
    pub timestamp_utc: String,          // ISO 8601 timestamp
    pub platform: String,               // "windows" | "linux" | "macos"
    pub command: String,                // Command name invoked
    pub args: Vec<String>,             // Arguments passed
    pub status: String,                 // "ok" | "error" | "warn"
    pub exit_code: i32,                 // Process exit code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,          // Error message if status == "error"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,        // Warning message (may coexist with "ok")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,     // Categorized error type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,          // Suggested remediation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<HashMap<String, Option<String>>>,  // Named output files
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sizes: Option<HashMap<String, u64>>,               // File sizes in bytes
    pub elapsed_ms: u64,                // Execution time in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>, // Command-specific payload
}
```

### Envelope Status Values

| Status | Meaning | GUI Behavior |
|--------|---------|--------------|
| `"ok"` | Command succeeded, data is valid | Display data |
| `"warn"` | Command succeeded but with warnings | Display data + surface warning |
| `"error"` | Command failed | Display error, do not display stale data |

### Critical Rules

1. **Always check `status` first.** Do not assume `exit_code == 0` means success. A command may exit 0 with `status: "warn"`.

2. **Surface warnings.** The `warning` field exists precisely for cases where the command succeeded but something noteworthy happened. Do not drop warnings.

3. **Handle missing `data` gracefully.** If `data` is `None`, display "No data returned" or equivalent, not an empty table with headers.

4. **Use `elapsed_ms` for performance display.** Do not compute your own timing.

---

## Section B: Output Mode Types

The CLI supports three output modes:

### B.1: Envelope-Backed (JSON File)

The primary mode. CLI writes the full envelope to a JSON file specified by `--json-result`:

```bash
forensic_cli timeline --case mycase --json-result C:\temp\result.json
```

**Usage:** All GUI commands should use this mode.

**Advantage:** Full envelope with status, warnings, timing, and structured data.

### B.2: stdout_json

Raw JSON to stdout (no envelope wrapper):

```bash
forensic_cli capabilities --stdout-json
```

**Usage:** Commands that return machine-readable data directly.

**Caveat:** No envelope metadata. GUI must handle errors differently (check exit code and parse stdout as JSON).

### B.3: stdout_text

Human-readable text to stdout:

```bash
forensic_cli doctor --stdout-text
```

**Usage:** Debugging and human review.

**Caveat:** Not suitable for programmatic parsing. Use only for display.

---

## Section C: Command Inventory

### C.1: `capabilities`

**Purpose:** Show capability registry  
**Output mode:** envelope-backed or stdout_json  
**Data shape:**
```json
{
  "capabilities": [
    {
      "name": "container.raw",
      "status": "implemented",
      "category": "container"
    },
    ...
  ]
}
```

**GUI usage:** Populate capability display, feature gates  
**Contract rule:** Check `capabilities[].status` before enabling features

---

### C.2: `doctor`

**Purpose:** System diagnostics and health check  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "checks": [
    { "name": "cli_version", "status": "pass", "detail": "0.1.0" },
    { "name": "engine_modules", "status": "pass", "detail": "28 modules loaded" },
    { "name": "case_database", "status": "pass", "detail": "43 tables accessible" },
    ...
  ]
}
```

**GUI usage:** Health dashboard, pre-flight checks  
**Contract rule:** Check all `checks[].status` values, not just overall pass/fail

---

### C.3: `smoke-test`

**Purpose:** Quick validation of core functionality  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "tests": [
    { "name": "container_open", "passed": true },
    { "name": "parser_registry", "passed": true },
    { "name": "hash_computation", "passed": true },
    ...
  ],
  "overall": "pass"
}
```

**GUI usage:** Initial setup validation  
**Contract rule:** Always check `tests` array, not just `overall`

---

### C.4: `verify`

**Purpose:** Case verification with hash chain validation  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "case_id": "evidence123",
  "verification_status": "verified",
  "hash_chain_valid": true,
  "violations": [],
  "verified_at": "2026-03-23T10:30:00Z"
}
```

**GUI usage:** Case integrity display  
**Contract rule:** `violations` must be empty array, not null

---

### C.5: `triage-session`

**Purpose:** Full evidence triage with bundle generation  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "case_id": "evidence123",
  "files_categorized": 12847,
  "hashes_computed": 12847,
  "artifacts_extracted": 4321,
  "bundle_path": "C:\\cases\\evidence123\\bundle.zip"
}
```

**GUI usage:** Triage progress and results  
**Contract rule:** Verify `bundle_path` exists before reporting completion

---

### C.6: `examine`

**Purpose:** Run examination with specified preset  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "preset": "full",
  "stages_completed": ["container_open", "filesystem_enum", "artifact_parse"],
  "stages_failed": [],
  "artifacts_found": 12431
}
```

**GUI usage:** Examination progress display  
**Contract rule:** Check `stages_failed` even when overall status is "ok"

---

### C.7: `watchpoints`

**Purpose:** List integrity watchpoints  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "watchpoints": [
    { "id": 1, "table": "evidence_timeline", "operation": "INSERT", "active": true },
    ...
  ]
}
```

**GUI usage:** Integrity monitoring display  
**Contract rule:** Handle empty `watchpoints` array gracefully

---

### C.8: `violations`

**Purpose:** List integrity violations  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "violations": [
    {
      "id": 1,
      "table_name": "evidence_timeline",
      "operation": "UPDATE",
      "violated_at": "2026-03-23T09:15:00Z",
      "severity": "high"
    },
    ...
  ]
}
```

**GUI usage:** Alert display for integrity issues  
**Contract rule:** Non-empty `violations` array is a critical signal

---

### C.9: `timeline`

**Purpose:** Merged case timeline generation  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "entries": [
    {
      "id": 1,
      "timestamp": 1774320416000,
      "artifact_type": "prefetch",
      "description": "Application prefetch: chrome.exe",
      "source_path": "C:\\Users\\...\\Prefetch\\chrome.exe..."
    },
    ...
  ],
  "total_count": 12431,
  "pagination": { "cursor": "abc123", "has_more": true }
}
```

**GUI usage:** Timeline visualization  
**Contract rule:** Use `total_count` for pagination, not `entries.len()`

---

### C.10: `hashset list`

**Purpose:** List available hashsets  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "hashsets": [
    { "name": "NSRL", "type": "known_good", "entries": 100000 },
    { "name": "Custom-Bad", "type": "known_bad", "entries": 5000 },
    ...
  ]
}
```

**GUI usage:** Hashset selector  
**Contract rule:** Verify `entries` count is non-zero before counting as loaded

---

### C.11: `hashset stats`

**Purpose:** Hashset statistics  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "hashset_name": "NSRL",
  "total_hashes": 100000,
  "categories": {
    "known_good": 95000,
    "known_bad": 3000,
    "known_unknown": 2000
  }
}
```

**GUI usage:** Hashset detail view  
**Contract rule:** Sum of categories may not equal total (hashes can be in multiple categories)

---

### C.12: `open-evidence`

**Purpose:** Open and analyze evidence container  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "container_type": "raw",
  "container_size": 42949672960,
  "filesystems": [
    { "type": "ntfs", "offset": 1048576, "filesEnumerated": 12847 }
  ],
  "hash": { "md5": "...", "sha1": "...", "sha256": "..." }
}
```

**GUI usage:** Evidence loading and tree building  
**Contract rule:** `filesystems[].filesEnumerated` must be non-zero; empty count indicates parse failure

---

### C.13: `filetable`

**Purpose:** List files in evidence  
**Output mode:** envelope-backed  
**Data shape:**
```json
{
  "entries": [
    {
      "path": "C:\\Windows\\System32\\config\\SYSTEM",
      "size": 50331648,
      "isDirectory": false,
      "mft_record": 12345
    },
    ...
  ],
  "total_count": 12847,
  "cursor": "next_page_token"
}
```

**GUI usage:** File browser  
**Contract rule:** Use cursor-based pagination; do not load all entries at once

---

## Section D: Safe Command Integration Rules

### Rule 1: Don't Assume Output Shape

```rust
// WRONG: Assumes data.timeline_entries exists
let entries = response["data"]["timeline_entries"].as_array().unwrap();

// CORRECT: Check for existence first
let entries = response["data"]["entries"].as_array()
    .or_else(|| response["data"]["timeline_entries"].as_array())
    .unwrap_or(&empty_array);
```

### Rule 2: Don't Claim More Than Returned Fields Support

```rust
// WRONG: Claims SHA256 support when only MD5 was returned
display_hash(response, "SHA256: " + md5_value);  // Misleading

// CORRECT: Only display fields that were actually returned
if let Some(sha256) = response["hash"]["sha256"].as_str() {
    display_hash(response, "SHA256: " + sha256);
}
```

### Rule 3: Preserve Warnings and Errors

```rust
// WRONG: Drops warning, shows only data
display_data(response["data"]);
status_text = "Success";

// CORRECT: Surface warning
display_data(response["data"]);
if let Some(warning) = response["warning"].as_str() {
    status_text = format!("Success (warning: {})", warning);
    show_warning_banner(warning);
}
```

### Rule 4: Support Fallback Honestly

```rust
// WRONG: Pretends full capability when using fallback
display_capability("Embedding: sentence-transformers (full fidelity)");

// CORRECT: Label fallback mode explicitly
let backend = response["embedding_backend"].as_str().unwrap_or("unknown");
if backend.contains("fallback") {
    display_capability(format!("Embedding: {} (degraded mode)", backend));
} else {
    display_capability(format!("Embedding: {}", backend));
}
```

### Rule 5: Verify Envelope Completeness

```rust
// Before trusting a command result, validate:
fn validate_envelope(envelope: &CliResultEnvelope) -> ValidationResult {
    // 1. Status must be present
    if envelope.status.is_empty() {
        return ValidationResult::Invalid("Missing status field");
    }
    
    // 2. Exit code consistency
    if envelope.exit_code != 0 && envelope.status == "ok" {
        return ValidationResult::Suspicious("exit_code != 0 but status is ok");
    }
    
    // 3. Error consistency
    if envelope.status == "error" && envelope.error.is_none() {
        return ValidationResult::Suspicious("status is error but no error message");
    }
    
    // 4. Warning appropriateness
    if envelope.status == "ok" && envelope.warning.is_some() {
        // OK - warnings can coexist with ok status
    }
    
    ValidationResult::Valid
}
```

---

## Section E: Tauri Command Mapping

The GUI Tauri backend maps CLI commands via `gui-tauri/src-tauri/src/lib.rs`:

| Tauri Command | CLI Command | Expected Data Fields |
|---------------|-------------|---------------------|
| `load_evidence_and_build_tree` | Internal engine call | `filesystems`, `tree` |
| `get_initial_timeline` | `timeline` | `entries`, `total_count` |
| `list_plugins` | `capabilities` (filtered) | `capabilities[].category=plugin` |
| `acquire_live_memory` | Internal engine call | `acquisition_status` |

**Contract rule:** The Tauri backend returns `CliRunResult` which wraps the envelope:

```rust
pub struct CliRunResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub envelope_json: Option<CliResultEnvelope>,
    pub json_path: Option<String>,
}
```

Always prefer `envelope_json` over parsing `stdout`. The envelope is structured; stdout may be text or empty.

---

## Section F: Error Handling Contract

### CLI Errors → GUI Display

| CLI Output | GUI Display |
|------------|-------------|
| `status: "error"`, `error: "File not found"` | Error modal with message |
| `status: "warn"`, `warning: "2 parsers failed"` | Warning banner + data |
| `status: "ok"`, `exit_code: 0` | Normal display |
| `status: "ok"`, `exit_code: 1` | Suspicious - log and warn |
| Timeout / No response | "Command timed out" message |

### Unknown Field Handling

```rust
// WRONG: Crash on missing field
let value = obj["required_field"].as_str().unwrap();

// CORRECT: Graceful degradation
let value = obj["required_field"].as_str()
    .ok_or_else(|| Warning::new("Missing required_field"));
```

---

## Document Maintenance

This document must be updated when:
- New commands are added to the CLI
- Existing command output shapes change
- New envelope fields are added
- Tauri command mappings change

Location: `D:\forensic-suite\guardian\COMMAND_CONTRACTS.md`
