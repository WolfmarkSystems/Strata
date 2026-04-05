# Strata Parser Review Checklist

**Document Type:** Parser Quality Review Checklist  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Purpose:** Repeatable review process for new or modified parser modules

---

## Purpose

This checklist defines the review process for any new or modified `ArtifactParser` implementation before it is approved for integration into the ForensicSuite. Every item must pass before the parser is merged.

Strata uses this checklist when:
- Reviewing new parser submissions
- Auditing existing parsers for quality issues
- Validating parser changes before release

---

## Pre-Review Setup

Before beginning the review:

1. **Identify the parser module** under review
2. **Obtain the full implementation** (not just diff)
3. **Locate the registration** in `parser.rs`
4. **Identify target patterns** the parser is meant to match
5. **Determine the artifact type** this parser produces

---

## Section 1: Parser Identity and Naming

### 1.1: Parser Name Review
**Why it matters:** Parser name is used for logging, debugging, and error reporting. Inconsistent naming makes triage difficult.

**What to check:**
- `fn name(&self) -> &str` returns a descriptive, consistent name
- Name matches the file/module name convention
- No generic names like "Parser", "MyParser", or "TestParser"

**Signs of failure:**
- Name is "Parser" or similar generic
- Name doesn't match file/module name
- Name contains special characters or spaces

**Required evidence for approval:**
```rust
// Correct:
fn name(&self) -> &str { "ShimcacheParser" }
fn name(&self) -> &str { "EvtxSecurityParser" }

// Incorrect:
fn name(&self) -> &str { "Parser" }
fn name(&self) -> &str { "my parser" }
```

**When to escalate:** If name is generic or doesn't match established conventions

---

### 1.2: Artifact Type Consistency
**Why it matters:** `artifact_type()` determines how artifacts are categorized, filtered, and displayed. Inconsistent naming breaks timeline filtering and artifact browsing.

**What to check:**
- `fn artifact_type(&self) -> &str` follows the naming convention
- Type is lowercase with underscores for multi-word names
- Type is consistent with related parsers (e.g., `registry_shimcache` not `shimcache` in registry category)

**Signs of failure:**
- Mixed case: `registryShimcache` instead of `registry_shimcache`
- Generic type: `artifact` or `event`
- Inconsistent prefix: `browser_chrome` but `firefox_browser`

**Required evidence for approval:**
```rust
// Correct:
fn artifact_type(&self) -> &str { "registry_shimcache" }
fn artifact_type(&self) -> &str { "browser_chrome" }
fn artifact_type(&self) -> &str { "evtx_security" }

// Incorrect:
fn artifact_type(&self) -> &str { "RegistryShimcache" }
fn artifact_type(&self) -> &str { "chrome" }
```

**When to escalate:** If type naming is inconsistent with related parsers

---

### 1.3: Target Patterns Validation
**Why it matters:** `target_patterns()` determines which files the parser runs against. Empty patterns mean the parser never runs.

**What to check:**
- `fn target_patterns(&self) -> Vec<&str>` returns non-empty vector
- Patterns are valid glob patterns for the target file type
- Patterns are specific enough to avoid false positives

**Signs of failure:**
- Empty vec: `vec![]`
- Overly broad pattern: `*` matching all files
- Incorrect extension: `*.evt` for EVTX files (EVTX not EVT)

**Required evidence for approval:**
```rust
// Correct:
fn target_patterns(&self) -> Vec<&str> {
    vec!["*.evtx", "*\\Microsoft\\Windows\\*\\Operational.evtx"]
}

// Incorrect:
fn target_patterns(&self) -> Vec<&str> { vec![] }
fn target_patterns(&self) -> Vec<&str> { vec!["*"] }
```

**When to escalate:** If patterns are empty or match unintended files

---

## Section 2: ArtifactParser Contract Review

### 2.1: Function Signature Compliance
**Why it matters:** The `ArtifactParser` trait has a specific signature. Deviations cause compilation or trait implementation errors.

**What to check:**
- `parse_file` has signature: `fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError>`
- Return type is exactly `Result<Vec<ParsedArtifact>, ParserError>`
- No additional parameters or changed types

**Signs of failure:**
- Returns `Option<Vec<...>>` instead of `Result<Vec<...>, ParserError>`
- `ParserError` replaced with generic `Box<dyn Error>`
- Extra parameters in function signature

**Required evidence for approval:** Code compiles against `parser.rs` trait definition

**When to escalate:** Any signature deviation

---

### 2.2: Error Type Usage
**Why it matters:** `ParserError` variants provide context for debugging. Using wrong variants or missing context makes triage difficult.

**What to check:**
- Uses appropriate `ParserError` variants: `Io`, `Parse`, `Database`, `Vfs`
- Error messages include relevant context (file path, offset, expected format)
- No bare `unwrap()` or `expect()` that would panic

**Signs of failure:**
```rust
// BAD: Panics on malformed input
let header = parse_header(data).unwrap();

// BAD: Generic error without context
return Err(ParserError::Parse("error".to_string()));

// BAD: Using wrong error variant
return Err(ParserError::Io(std::io::Error::new(...)::Parse("...")));
```

**Required evidence for approval:**
```rust
// Correct: Specific error with context
fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
    let header = parse_header(data).map_err(|e|
        ParserError::Parse(format!("Failed to parse {}: {}", path.display(), e))
    )?;
    // ...
}

// Correct: Appropriate variant
return Err(ParserError::Io(std::io::Error::new(
    std::io::ErrorKind::InvalidData,
    format!("Invalid magic {:x} at {}", magic, path.display())
)));
```

**When to escalate:** Any panic-inducing code or missing error context

---

## Section 3: Evidence-Derived Output Validation

### 3.1: No Invented Artifacts
**Why it matters:** Artifacts must represent real evidence. Invented artifacts create false forensic conclusions.

**What to check:**
- No hardcoded artifact generation
- No returning artifacts when parse fails
- No creating artifacts from non-evidence sources

**Signs of failure:**
```rust
// BAD: Inventing artifact on empty result
if records.is_empty() {
    return Ok(vec![ParsedArtifact {
        artifact_type: self.artifact_type(),
        description: "No records found".to_string(),
        // This is a fake artifact!
        timestamp: None,
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::json!({}),
    }]);
}

// BAD: Creating placeholder artifacts
if data.len() < MIN_SIZE {
    return Ok(vec![ParsedArtifact {
        artifact_type: self.artifact_type(),
        description: "File too small - placeholder".to_string(),
        // ...
    }]);
}
```

**Required evidence for approval:**
```rust
// Correct: Return empty explicitly
if records.is_empty() {
    return Ok(vec![]);  // Empty result, not fake artifact
}
```

**When to escalate:** Any invented artifacts—immediate escalation

---

### 3.2: No Default::default() Artifacts
**Why it matters:** `Default::default()` produces artifacts with empty/zero fields that look real but contain no forensic data.

**What to check:**
- No `ParsedArtifact::default()` returns in the code
- All `ParsedArtifact` constructions have explicit field values
- No empty strings for required fields

**Signs of failure:**
```rust
// BAD: Returning default artifact on error path
Err(_)?; // Fall through
return Ok(vec![ParsedArtifact::default()]);
```

**Required evidence for approval:** Code has zero `ParsedArtifact::default()` calls

**When to escalate:** Any `Default::default()` usage

---

### 3.3: Field Completeness
**Why it matters:** Incomplete fields break provenance tracking and timeline accuracy.

**What to check:**
- Every `ParsedArtifact` has non-empty `source_path`
- Every artifact has `artifact_type` matching parser's return
- `timestamp` is `Option<i64>`, not `0` as placeholder
- `json_data` contains actual parsed fields, not `Value::Null`

**Required evidence for approval:**
```rust
// Correct: Complete artifact
ParsedArtifact {
    timestamp: Some(parse_timestamp(record)?),
    artifact_type: self.artifact_type().to_string(),
    description: format!("Event ID {}: {}", record.id, record.name),
    source_path: path.to_string_lossy().to_string(),
    json_data: serde_json::json!({
        "event_id": record.id,
        "name": record.name,
        "keywords": record.keywords,
    }),
}
```

**When to escalate:** Any field left empty or zero as placeholder

---

## Section 4: Error and Fallback Handling

### 4.1: Explicit Empty Results
**Why it matters:** Empty results must be intentional, not a fallback from error.

**What to check:**
- Empty `vec![]` is returned only when source is genuinely empty
- No silent conversion of errors to empty results

**Signs of failure:**
```rust
// BAD: Silent failure to empty
fn parse_file(...) -> Result<Vec<ParsedArtifact>, ParserError> {
    match parse_impl(data) {
        Ok(artifacts) => Ok(artifacts),
        Err(_) => Ok(vec![]),  // Silent failure!
    }
}
```

**Required evidence for approval:**
```rust
// Correct: Propagate errors
fn parse_file(...) -> Result<Vec<ParsedArtifact>, ParserError> {
    let records = parse_impl(data)
        .map_err(|e| ParserError::Parse(format!("Parse error: {}", e)))?;
    Ok(records.into_iter().map(|r| self.to_artifact(r)).collect())
}
```

**When to escalate:** Any silent error-to-empty conversion

---

### 4.2: Graceful Format Rejection
**Why it matters:** Parsers must reject wrong formats, not crash or produce garbage.

**What to check:**
- Magic bytes/file header validation
- Clear error message for wrong format
- No panic on invalid input

**Signs of failure:**
```rust
// BAD: Assumes valid input without checking
let header = Header::unpack(data)?;  // Panics if data too short
let magic = data[0..4].try_into()?;  // Panics if data too short
```

**Required evidence for approval:**
```rust
// Correct: Validate before parsing
fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
    if data.len() < HEADER_SIZE {
        return Err(ParserError::Parse(format!(
            "File too short for {}: {} bytes (minimum {})",
            self.name(),
            data.len(),
            HEADER_SIZE
        )));
    }
    // ... continue with validated data
}
```

**When to escalate:** Any input that could cause panic

---

## Section 5: Provenance and Source-Path Review

### 5.1: Evidence Path Tracing
**Why it matters:** Every artifact must trace back to its source file in the evidence. Without source_path, there's no provenance.

**What to check:**
- `source_path` field is set to the actual evidence file path
- Path is not empty, not working directory, not relative

**Signs of failure:**
```rust
// BAD: Empty source path
ParsedArtifact {
    source_path: String::new(),  // No provenance!
    // ...
}

// BAD: Working directory path
source_path: "./data/System"  // Not an evidence path
```

**Required evidence for approval:**
```rust
// Correct: Evidence-relative path
ParsedArtifact {
    source_path: path.to_string_lossy().to_string(),
    // ...
}
```

**When to escalate:** Any empty or working-directory source path

---

### 5.2: Path Preservation in Batch Operations
**Why it matters:** When parsing multiple records from one file, source_path must be preserved accurately.

**What to check:**
- Loop-based parsing preserves path for each artifact
- No path variable being overwritten

**Signs of failure:**
```rust
// BAD: Path lost in iteration
for record in records {
    let path = get_next_path();  // Overwrites original path
    artifacts.push(ParsedArtifact {
        source_path: path,  // Not original evidence path
        // ...
    });
}
```

**Required evidence for approval:** `source_path` consistently set to original `path` parameter

**When to escalate:** If path could be confused across records

---

## Section 6: Timestamp Handling

### 6.1: Option<i64> Correctness
**Why it matters:** `timestamp` must be `Option<i64>` representing Unix epoch milliseconds. Zero is a valid timestamp (1970-01-01), not a placeholder.

**What to check:**
- `timestamp` field is `Option<i64>`, not `i64` or `u64`
- `None` used when timestamp is genuinely unknown
- No `0` used as a placeholder for unknown

**Signs of failure:**
```rust
// BAD: Using 0 as unknown placeholder
timestamp: 0  // This is Jan 1, 1970, not "unknown"

// BAD: Wrong type
timestamp: Some(SystemTime::now())  // Wrong type
```

**Required evidence for approval:**
```rust
// Correct: Option with valid epoch
timestamp: Some(parse_windows_timestamp(record.timestamp)?)

// Correct: None when unknown
timestamp: None  // Timestamp not present in record
```

**When to escalate:** Any use of 0 or wrong type as placeholder

---

### 6.2: Timestamp Parsing Accuracy
**Why it matters:** Wrong timestamp parsing produces incorrect forensic timelines.

**What to check:**
- Correct use of Windows FILETIME (100-nanosecond intervals since 1601-01-01)
- Correct use of Unix epoch (seconds/milliseconds since 1970-01-01)
- Proper handling of FILETIME zero (1601-01-01, not valid forensic data)

**Required evidence for approval:** Timestamp conversion function tested against known values

**When to escalate:** If timestamp format is not documented or verified

---

## Section 7: Timeline-Entry Suitability

### 7.1: Artifact Completeness for Timeline
**Why it matters:** Timeline entries must be suitable for investigator review. Incomplete entries waste time.

**What to check:**
- `description` is human-readable and meaningful
- `json_data` contains all relevant fields for deeper investigation
- Category and type are accurate

**Signs of failure:**
```rust
// BAD: Meaningless description
description: "Record".to_string()

// BAD: Empty json_data
json_data: serde_json::json!({})
```

**Required evidence for approval:**
```rust
// Correct: Meaningful description
description: format!(
    "Application executed: {} (Hash: {}, Size: {})",
    record.path, record.sha256, record.size
)
```

**When to escalate:** If description is generic or json_data is empty

---

## Section 8: Placeholder and Fake-Artifact Review

### 8.1: No Placeholder Strings
**Why it matters:** Placeholder strings indicate incomplete implementation.

**What to check:**
- No `TODO`, `TBD`, `FIXME`, `STUB` in artifact descriptions
- No hardcoded strings like "implement me", "not yet supported"

**Signs of failure:**
```rust
// BAD: Placeholder in description
description: "TBD: implement full parsing".to_string()

// BAD: Stub artifact
description: "Not implemented yet - this is a placeholder".to_string()
```

**Required evidence for approval:** Zero placeholder strings in code

**When to escalate:** Any placeholder strings—immediate escalation

---

### 8.2: No Synthetic Test Data
**Why it matters:** Synthetic data in production parsers corrupts forensic results.

**What to check:**
- No hardcoded test hashes (e.g., `deadbeef...`)
- No invented timestamps (e.g., `2025-01-01`)
- No generated paths that don't exist in evidence

**Required evidence for approval:** Parser only uses data from input `data: &[u8]` parameter

**When to escalate:** Any synthetic data—immediate escalation

---

## Section 9: Test Fixture Expectations

### 9.1: Test Coverage
**Why it matters:** Parser must have tests that verify correct behavior.

**What to check:**
- Unit tests exist for the parser
- Tests use real or representative fixture data
- Tests verify error handling paths

**Required evidence for approval:**
- At least one passing test for valid input
- At least one test for empty/invalid input

**When to escalate:** If no tests exist

---

### 9.2: Fixture Data Integrity
**Why it matters:** Test fixtures must be real forensic samples or accurately simulated.

**What to check:**
- Fixtures are documented as real or synthetic
- Synthetic fixtures are clearly marked
- No hardcoded "correct answers" that don't match fixture data

**Required evidence for approval:** Fixture sources documented

**When to escalate:** If fixture sources are unknown

---

## Section 10: Performance and Safety Review

### 10.1: No Unbounded Memory Allocation
**Why it matters:** Malformed evidence can cause parsers to allocate unbounded memory.

**What to check:**
- No `vec![0; user_controlled_size]`
- No `String::from_utf8` without length checks
- Streaming parsing for large files

**Signs of failure:**
```rust
// BAD: Unbounded allocation
let size = read_u32_from_file(data)? as usize;
let buffer = vec![0u8; size];  // Could be huge
```

**Required evidence for approval:** Size limits validated before allocation

**When to escalate:** Any potentially unbounded allocation

---

### 10.2: Streaming for Large Files
**Why it matters:** Large evidence files (GB-scale) must not be loaded entirely into memory.

**What to check:**
- Parser uses streaming/chunked reading for large files
- No `data.to_vec()` for entire file
- Uses VFS read methods for partial access

**Required evidence for approval:** Large file test case exists or documented limitation

**When to escalate:** If parser loads entire file into memory

---

## Review Completion Summary

| Section | Items | Passed | Failed | Escalated |
|---------|-------|--------|--------|-----------|
| 1. Identity/Naming | 3 | | | |
| 2. Contract Review | 2 | | | |
| 3. Evidence Output | 3 | | | |
| 4. Error Handling | 2 | | | |
| 5. Provenance | 2 | | | |
| 6. Timestamp | 2 | | | |
| 7. Timeline Suitability | 1 | | | |
| 8. Placeholder Review | 2 | | | |
| 9. Test Fixtures | 2 | | | |
| 10. Performance/Safety | 2 | | | |
| **Total** | **21** | | | |

### Review Status
- [ ] **APPROVED** — All items passed, parser ready for integration
- [ ] **APPROVED WITH CONDITIONS** — Minor issues, documented and acceptable
- [ ] **REQUIRES REVISION** — Significant issues, must fix before re-review
- [ ] **REJECTED** — Critical issues (fabrication, panics), must redesign

### Sign-Off
Reviewer: Strata  
Date: _________________  
Parser: _________________  
Status: _________________

---

## Document Maintenance

Update this checklist when:
- New ParserError variants are added
- Convention changes are established
- New anti-patterns are discovered

Location: `D:\forensic-suite\guardian\STRATA_PARSER_REVIEW_CHECKLIST.md`
