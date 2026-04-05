# ForensicSuite Parser Conventions

**Document Type:** Parser Quality Guidelines  
**Effective Date:** 2026-03-23  
**Governs:** All `ArtifactParser` implementations in `forensic_engine`

---

## Purpose

Parsers are the primary mechanism by which the forensic engine extracts structured artifacts from raw evidence files. A parser that violates these conventions can produce false forensic conclusions, silently drop evidence, or mask critical errors.

This document defines what a correct parser looks like, what behaviors are prohibited, and what Strata checks when reviewing a parser module.

---

## Parser Architecture Overview

### Core Types

```rust
// The primary parser interface
pub trait ArtifactParser: Send + Sync {
    fn name(&self) -> &str;           // Human-readable parser name
    fn artifact_type(&self) -> &str;  // Category label (e.g., "registry", "prefetch")
    fn target_patterns(&self) -> Vec<&str>;  // File patterns to match (e.g., "*.evtx")

    fn parse_file(&self, path: &Path, data: &[u8]) 
        -> Result<Vec<ParsedArtifact>, ParserError>;
}

// The output structure
pub struct ParsedArtifact {
    pub timestamp: Option<i64>,      // Unix epoch ms; None if unknown
    pub artifact_type: String,       // Must match parser's artifact_type()
    pub description: String,         // Human-readable artifact summary
    pub source_path: String,         // Absolute path in evidence, not working dir
    pub json_data: serde_json::Value // Structured artifact fields
}
```

### ParserRegistry

```rust
pub struct ParserRegistry {
    parsers: Vec<Box<dyn ArtifactParser>>,
}

impl ParserRegistry {
    pub fn register(&mut self, parser: Box<dyn ArtifactParser>);
    pub fn register_default_parsers(&mut self);
    pub fn find_matching_parsers(&self, path: &Path) -> Vec<&dyn ArtifactParser>;
}
```

### Data Flow

```
Evidence File (e.g., Security.evtx)
       │
       ▼
EvidenceAnalyzer::analyze()
       │
       ▼
ParserRegistry::find_matching_parsers()  ← Matched by target_patterns()
       │
       ▼
Parser::parse_file(path, data)  → Result<Vec<ParsedArtifact>, ParserError>
       │
       ▼
ParsedArtifact vec
       │
       ▼
TimelineManager::insert_entry()  → Stored in SQLite
```

---

## Required Parser Behavior

### 1. Deterministic Output

Given the same file and same parser version, `parse_file()` must always return the same artifacts in the same order.

**Prohibited:** Randomization, non-deterministic iteration order, time-based variation.

**Required:** Sort artifacts by timestamp before returning, or document non-deterministic behavior.

### 2. Evidence-Derived Content

Every field in `ParsedArtifact` must come from the source file, not from code defaults, hardcoded strings (except as fallbacks with explicit labeling), or runtime environment.

**Correct:**
```rust
// Values extracted from actual file data
ParsedArtifact {
    timestamp: Some(parse_windows_timestamp(&record.time_created)?),
    artifact_type: "evtx_security".to_string(),
    description: format!("Event ID {}: {}", event_id, event_name),
    source_path: source_path.to_string_lossy().to_string(),
    json_data: serde_json::json!({ ... parsed fields ... }),
}
```

### 3. No Invented Artifacts

A parser must not return artifacts that do not correspond to actual records in the source file.

**Prohibited patterns:**
```rust
// WRONG: Inventing a "dummy" artifact when file is empty
if records.is_empty() {
    return Ok(vec![ParsedArtifact {
        artifact_type: "dummy".to_string(),
        description: "No records found".to_string(),
        // ...
    }]);
}

// WRONG: Returning Default::default() on error
fn parse_file(...) -> Result<Vec<ParsedArtifact>, ParserError> {
    Err(e)?;  // or Ok(vec![ParsedArtifact::default()])
}
```

**Correct patterns:**
```rust
// Correct: Empty result with explicit return
if records.is_empty() {
    return Ok(vec![]);  // Empty vec, not fake artifact
}

// Correct: Error propagation
fn parse_file(...) -> Result<Vec<ParsedArtifact>, ParserError> {
    let records = parse_records(data).map_err(|e| ParserError::Parse(e.to_string()))?;
    // ...
}
```

### 4. Explicit Error and Fallback Handling

When a parser cannot complete a parse, it must:
1. Return a meaningful `ParserError` (not panic or unwrap)
2. Log the failure reason if logging is available
3. Not return partial or guessed artifacts

**Correct:**
```rust
fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
    let header = parse_header(data).map_err(|e| 
        ParserError::Parse(format!("Invalid header at {}: {}", path.display(), e))
    )?;
    
    if header.magic != EXPECTED_MAGIC {
        return Err(ParserError::Parse(format!(
            "Not a valid {} file: magic {:x} != {:x}",
            self.name(), header.magic, EXPECTED_MAGIC
        )));
    }
    
    // Parse records or return empty if none found
    let records = parse_records(header, data)?;
    Ok(records.into_iter().map(|r| self.record_to_artifact(r, path)).collect())
}
```

### 5. Consistent Category and Type Naming

Parser `artifact_type()` values must be consistent across the codebase:

| Parser | artifact_type | Convention |
|--------|---------------|------------|
| EvtxParser | `evtx_security`, `evtx_sysmon` | `evtx_` prefix + source |
| PrefetchParser | `prefetch` | Lowercase single word |
| RegistryParser | `registry_persistence`, `registry_shimcache` | `registry_` prefix + subtype |
| BrowserParser | `browser_chrome`, `browser_firefox` | `browser_` prefix + browser |
| AmcacheParser | `amcache` | Lowercase single word |

**Rules:**
- Use lowercase with underscores for multi-word types
- Prefix related parsers with a shared category (e.g., `browser_`, `registry_`)
- Avoid generic names like `artifact` or `event`
- Document new type names in the artifact registry

---

## Signs of a Bad Parser

### 1. Fake Defaults

```rust
// BAD: Returns Default::default() or invented values on error
impl Default for ParsedArtifact {
    fn default() -> Self {
        ParsedArtifact {
            timestamp: None,
            artifact_type: String::new(),
            description: "TBD".to_string(),
            source_path: String::new(),
            json_data: serde_json::Value::Null,
        }
    }
}
```

**Why dangerous:** `Default::default()` produces artifacts that look real but contain no actual forensic data. They can be mistaken for empty-but-valid results.

### 2. Swallowed Errors

```rust
// BAD: catch-all unwrap() that panics on unexpected input
let timestamp = parse_timestamp(data).unwrap();  // Panics on malformed data

// BAD: ignoring parse failures silently
for record in records {
    let artifact = parse_record(record)?;  // ? returns, but not for individual records
    artifacts.push(artifact);
}
return Ok(artifacts);  // Some records may have been silently dropped
```

**Why dangerous:** Panics crash the engine. Silent drops lose evidence without notification.

### 3. Missing Provenance

```rust
// BAD: Artifact without source_path
ParsedArtifact {
    timestamp: Some(ts),
    artifact_type: "prefetch".to_string(),
    description: "App execution".to_string(),
    source_path: String::new(),  // Empty - no traceability
    json_data: json,
}

// BAD: Artifact with working-dir path, not evidence path
source_path: "C:\\Users\\examiner\\evidence\\case1/System"


```

**Why dangerous:** Without source_path, there is no way to trace an artifact back to its origin in the evidence. Working-dir paths are meaningless outside the current session.

### 4. Placeholder Artifacts Counted as Real

```rust
// BAD: Returning synthetic placeholder
if data.is_empty() {
    return Ok(vec![ParsedArtifact {
        artifact_type: self.artifact_type(),
        description: "Placeholder - implement full parsing".to_string(),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::json!({}),
    }]);
}
```

**Why dangerous:** Placeholder artifacts look like real results. They will be counted in artifact totals and may appear in reports as evidence.

### 5. Silent Empty Returns on Error Paths

```rust
// BAD: Returns empty vec on error instead of propagating error
fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
    match parse_impl(data) {
        Ok(artifacts) => Ok(artifacts),
        Err(_) => Ok(vec![]),  // Silent failure - caller thinks parsing succeeded
    }
}
```

**Why dangerous:** The caller sees `Ok(vec![])` and does not know that parsing actually failed. The empty result looks intentional.

---

## What Strata Reviews in a New Parser Module

When Strata reviews a new or modified parser, Strata checks:

### File: `engine/src/parsers/{module}.rs`

| Check | Expected | Prohibited |
|-------|----------|------------|
| `parse_file` signature | `Result<Vec<ParsedArtifact>, ParserError>` | Panics, `unwrap()`, `expect()` |
| `artifact_type()` return | Consistent naming, lowercase with `_` | Generic names, camelCase |
| `target_patterns()` | Non-empty vec of glob patterns | Empty vec (no files matched) |
| Error handling | `ParserError::Parse/String/Io` with context | Silent `Ok(vec![])` on failure |
| `source_path` field | Evidence-relative path string | Empty string, working-dir path |
| `timestamp` field | `Option<i64>`, `None` if unknown | `0` as placeholder |
| `json_data` field | Actual parsed fields | `Value::Null` or `json!({})` as fallback |

### File: `engine/src/parser.rs` (registry integration)

| Check | Expected | Prohibited |
|-------|----------|------------|
| Registration call | `ParserRegistry::register(Box::new(...))` in `register_default_parsers()` | Parser defined but not registered |
| Parser construction | Real initialization, not `new()` returning empty | `new()` returning stub |

### File: `engine/src/classification/{module}.rs`

| Check | Expected | Prohibited |
|-------|----------|------------|
| Artifact classification | Real `ParsedArtifact` construction | `Default::default()` artifacts |
| Error propagation | `Err()` with context | Silent drop of failed records |
| Category consistency | Consistent with `artifact_type()` naming | Inconsistent prefix/suffix |

---

## Stubbed Parsers

The suite contains stubbed parsers that are registered but return empty results:

```rust
// STUB file example
pub struct StubParser { }

impl ArtifactParser for StubParser {
    fn name(&self) -> &str { "StubParser" }
    fn artifact_type(&self) -> &str { "stub" }
    fn target_patterns(&self) -> Vec<&str> { vec![] }
    
    fn parse_file(&self, _path: &Path, _data: &[u8]) 
        -> Result<Vec<ParsedArtifact>, ParserError> {
        Ok(vec![])  // Explicitly empty, not hidden failure
    }
}
```

**Requirements for stubs:**
1. File must contain `// STUB:` comment explaining planned functionality
2. `parse_file()` must return `Ok(vec![])` explicitly (not silently)
3. `target_patterns()` should return empty vec or patterns that won't match
4. Stub status must be documented in `KNOWN_GAPS.md`

---

## Parser Error Types

```rust
pub enum ParserError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("VFS error: {0}")]
    Vfs(String),
}
```

**Correct usage:**
```rust
// Map specific errors with context
let header = parse_header(data).map_err(|e| 
    ParserError::Parse(format!("Failed to parse header at {}: {}", path.display(), e))
)?;
```

---

## Document Maintenance

This document must be updated when:
- New parser conventions are established
- New `ParserError` variants are added
- Category naming conventions change
- Stubbed parsers are implemented

Location: `D:\forensic-suite\guardian\PARSER_CONVENTIONS.md`
