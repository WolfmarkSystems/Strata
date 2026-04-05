# Strata Parser Review — Operating Runbook

**Document Type:** Operational SOP  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Authority:** Strata — Suite Guardian  
**Governs:** All `ArtifactParser` implementations in `forensic_engine`

---

## Purpose

### What Parser Review Is For

Parser review is the process by which Strata validates that a new or modified `ArtifactParser` implementation in `forensic_engine` meets the truthfulness and quality standards required before the parser is trusted with real evidence. A parser that passes review produces artifacts that are evidence-derived, correctly typed, provenance-traced, and error-handled. A parser that fails review may produce false forensic conclusions.

This runbook is not a style guide. It is a gate. Strata either approves a parser for integration or rejects it. This decision must be traceable to specific code and evidence.

### When to Run Parser Review

| Trigger | Context |
|---------|---------|
| New parser submitted for integration | Pre-merge review |
| Existing parser modified | Post-change review |
| Parser behavior reported as suspicious | Incident review |
| Pre-release validation | Full parser regression review |
| Capability claim audit | Periodic coverage audit |

Parser review is required before any new parser is merged. Modified parsers should be reviewed before the change is accepted.

### What Approval and Rejection Mean

| Status | Meaning | Consequence |
|--------|---------|-------------|
| **APPROVED** | Parser meets all standards. Ready for integration. | Parser may be registered and used. |
| **APPROVED WITH WARNINGS** | Parser is acceptable but has non-blocking issues. | Parser may be registered with documented caveats. |
| **PARTIAL / NEEDS MORE VALIDATION** | Parser cannot be fully assessed. Additional runtime testing or fixtures required. | Parser is blocked until validation complete. |
| **REJECTED** | Parser violates truthfulness rules or contains dangerous patterns. | Parser must not be merged. |

---

## Preconditions

Before beginning parser review, Strata must verify:

### Repository Access
- [ ] Read access to `D:\forensic-suite\engine\src\parsers\`
- [ ] Read access to `D:\forensic-suite\engine\src\parser.rs` (trait definition)
- [ ] Read access to `D:\forensic-suite\engine\src\classification\` (if classification module exists)

### Parser Identification
- [ ] Parser file path known: `engine/src/parsers/{module}.rs`
- [ ] Parser name identified (from `name()` method)
- [ ] Artifact type identified (from `artifact_type()` method)
- [ ] Target patterns identified (from `target_patterns()` method)

### Reference Documents Available
- [ ] `PARSER_CONVENTIONS.md` — Quality standards and anti-patterns
- [ ] `TRUTHFULNESS_RULES.md` — Non-negotiable evidence contracts
- [ ] `STRATA_PARSER_REVIEW_CHECKLIST.md` — Itemized checklist (21 items)
- [ ] `KNOWN_GAPS.md` — Current stubbed/partial features

### Branch and Diff Available
- [ ] Branch name: `[branch name]`
- [ ] Diff reviewed: `[git diff or PR link]`
- [ ] Commit hash: `[hash]`

### Fixtures and Tests (if available)
- [ ] Unit tests: `engine/src/tests/` or inline tests
- [ ] Test fixtures: `fixtures/parsers/` or embedded test data
- [ ] Sample evidence files: `[paths if available]`
- [ ] Expected output samples: `[paths if available]`

---

## Inputs to Review

Strata must gather the following before beginning the review:

### Core Parser Source
- `engine/src/parsers/{module}.rs` — Primary parser implementation
- [ ] Full file content (not just diff)
- [ ] All `parse_file` implementations
- [ ] All helper functions called by `parse_file`

### Trait and Registry Integration
- `engine/src/parser.rs` — `ArtifactParser` trait definition
- `engine/src/parser_registry.rs` or registration code — Where and how parser is registered
- [ ] Verify `register()` or `register_default_parsers()` includes this parser

### Related Classification Modules (if applicable)
- `engine/src/classification/{module}.rs` — Any related classification logic
- [ ] Artifact classification that depends on this parser

### Target Pattern Evidence
- [ ] What file patterns does `target_patterns()` return?
- [ ] Are the patterns specific enough to avoid false positives?
- [ ] Are the patterns correct for the artifact type?

### Test and Fixture Files
- `engine/src/tests/` — Unit tests
- `fixtures/parsers/` — Test data files
- [ ] What cases do tests cover?
- [ ] Are test cases representative of real evidence?
- [ ] Are failure cases tested?

### Sample Outputs
- [ ] Actual `parse_file` output on test fixtures
- [ ] Envelope status when parser runs (does it surface warnings?)
- [ ] Artifact shape in timeline (does it fit the expected schema?)

### GUI/CLI Surfaces That Depend on This Parser
- [ ] Which CLI commands invoke this parser? (`examine`, `triage-session`)
- [ ] Which GUI pages display results from this parser?
- [ ] Which timeline categories or artifact filters depend on this artifact type?

---

## Review Sequence

Strata follows this sequence for every parser review. Do not skip phases. Do not reach verdict until all phases are complete.

---

### Phase 1 — Identity and Scope

**Objective:** Confirm what the parser is, what it targets, and what it is supposed to produce.

#### 1.1 Parser Name
- [ ] `fn name(&self) -> &str` exists
- [ ] Name is descriptive: `"EvtxSecurityParser"`, not `"Parser"`, not `"MyParser"`
- [ ] Name matches the file/module name
- [ ] Name does not contain special characters or spaces

**Red flag:** Generic names like "Parser", "Handler", "Module". Name does not match file.

#### 1.2 Artifact Type
- [ ] `fn artifact_type(&self) -> &str` exists
- [ ] Type follows naming convention: lowercase with underscores
- [ ] Type is consistent with related parsers (e.g., `registry_shimcache`, not `Shimcache`)
- [ ] Type is specific enough to be useful for filtering

**Reference:** `PARSER_CONVENTIONS.md` Section on naming conventions.

**Red flag:** Mixed case, generic types like "artifact" or "event", inconsistent prefix/suffix with related parsers.

#### 1.3 Target Patterns
- [ ] `fn target_patterns(&self) -> Vec<&str>` exists
- [ ] Vector is non-empty
- [ ] Patterns are correct file extensions/paths for the artifact type
- [ ] Patterns are specific enough to avoid false positives

**Examples of correct patterns:**
- `vec!["*.evtx"]` for EVTX files
- `vec!["*.reg"]` for Windows registry hives
- `vec!["*\\Microsoft\\Windows\\*\\Prefetch\\*.pf"]` for prefetch files

**Examples of incorrect patterns:**
- `vec![]` — Empty patterns mean parser never runs
- `vec!["*"]` — Overly broad, matches everything
- `vec!["*.evt"]` — Wrong extension for EVTX (EVTX, not EVT)

**Red flag:** Empty target patterns. Overly broad patterns that match unintended files. Wrong file extensions.

#### 1.4 Intended Evidence Source
- [ ] What file type is this parser meant to process?
- [ ] Is the file format documented (public specification or reverse-engineered)?
- [ ] Is there any ambiguity about what the parser should accept?

**Document:** The evidence source this parser targets.

---

### Phase 2 — Contract Review

**Objective:** Verify the parser complies with the `ArtifactParser` trait contract.

#### 2.1 Function Signature
- [ ] `parse_file` has exactly the correct signature:
  ```rust
  fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError>
  ```
- [ ] Return type is `Result<Vec<ParsedArtifact>, ParserError>`, not `Option<Vec<...>>`
- [ ] No extra parameters added to signature
- [ ] Parser implements `ArtifactParser` trait correctly

**Red flag:** Changed signature. Using wrong error type. Generic `Box<dyn Error>` instead of `ParserError`.

#### 2.2 Error Type Usage
- [ ] Uses appropriate `ParserError` variants: `Io`, `Parse`, `Database`, `Vfs`
- [ ] Error messages include relevant context: file path, offset, expected format
- [ ] No bare `unwrap()` or `expect()` in the parsing path
- [ ] No `unwrap()` on user-controlled or evidence-derived data

**Correct error handling:**
```rust
let header = parse_header(data).map_err(|e|
    ParserError::Parse(format!("Failed to parse {}: {}", path.display(), e))
)?;
```

**Incorrect error handling:**
```rust
// Panics on malformed input
let header = parse_header(data).unwrap();

// Generic error without context
return Err(ParserError::Parse("error".to_string()));
```

**Red flag:** `unwrap()` or `expect()` calls that can panic. Generic errors without context. Wrong error variant.

#### 2.3 No Invented Data in parse_file
- [ ] Function body does not contain hardcoded artifacts
- [ ] Function does not generate artifacts from non-evidence sources
- [ ] Function does not return artifacts as a fallback when parsing fails

**Red flag:** Function creates artifacts with hardcoded descriptions, timestamps, or values that are not extracted from input data.

---

### Phase 3 — Output Truthfulness Review

**Objective:** Verify every artifact the parser returns is evidence-derived and traceable.

#### 3.1 Every Artifact Is Evidence-Derived
- [ ] Each `ParsedArtifact` is constructed from actual data in the `data: &[u8]` parameter
- [ ] No hardcoded artifact generation
- [ ] No returning artifacts when parse fails
- [ ] No creating artifacts from non-evidence sources

**Correct pattern:**
```rust
let records = parse_records(data)?;  // From evidence data
for record in records {
    artifacts.push(ParsedArtifact {
        timestamp: Some(record.timestamp),
        description: format!("Event {}: {}", record.id, record.name),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::json!({ ... from record ... }),
        // ...
    });
}
Ok(artifacts)
```

**Prohibited patterns:**
```rust
// Invented artifact on empty result
if records.is_empty() {
    return Ok(vec![ParsedArtifact {
        description: "No records found".to_string(),
        // This is fake!
        // ...
    }]);
}

// Placeholder on error path
Err(_)?; // Fall through
return Ok(vec![ParsedArtifact::default()]);
```

**Red flag:** Invented artifacts. `Default::default()` returns. Placeholder descriptions like "TBD", "Placeholder", "implement me".

#### 3.2 Source Path Provenance
- [ ] Every `ParsedArtifact` has a non-empty `source_path`
- [ ] `source_path` is the `path` parameter or derived from it
- [ ] `source_path` is not an empty string, working directory, or hardcoded path

**Correct:**
```rust
source_path: path.to_string_lossy().to_string(),
```

**Incorrect:**
```rust
source_path: String::new(),  // No provenance!
source_path: "./data/System"  // Working directory path, not evidence
```

**Red flag:** Empty source path. Working directory paths. Hardcoded paths that don't match the evidence file.

#### 3.3 Timestamp Honesty
- [ ] `timestamp` field is `Option<i64>` (Unix epoch milliseconds)
- [ ] `None` is used when timestamp is genuinely unknown or not present
- [ ] `0` is NOT used as a placeholder for unknown (0 is January 1, 1970, a valid timestamp)
- [ ] Timestamp parsing uses correct epoch (Windows FILETIME vs. Unix epoch)

**Correct:**
```rust
timestamp: Some(parse_windows_timestamp(record.time_created)?)
// or
timestamp: None  // Timestamp not present in record
```

**Incorrect:**
```rust
timestamp: 0  // This is Jan 1, 1970, not "unknown"
timestamp: Some(SystemTime::now())  // Wrong type
```

**Red flag:** Using `0` as unknown placeholder. Wrong timestamp type. Missing timestamp validation.

#### 3.4 Nullable/Missing Fields Not Fabricated
- [ ] `json_data` is populated with actual parsed fields
- [ ] `json_data` is not `Value::Null` or `json!({})` as a fallback
- [ ] Fields are present when they exist in the source data
- [ ] Fields are omitted (or `None`) when they don't exist

**Red flag:** Empty `json_data`. Placeholder field values. Fabricated data in JSON fields.

#### 3.5 Synthetic Artifacts Not Counted as Real
- [ ] No artifacts with placeholder text in `description`
- [ ] No artifacts with `Default::default()` values
- [ ] Parser does not create "informational" artifacts that didn't come from evidence
- [ ] Empty result is `Ok(vec![])`, not a synthetic artifact

**Red flag:** Parser returns fake artifacts to indicate "no data found" or "parse failed." Empty result must be empty.

---

### Phase 4 — Quality Review

**Objective:** Verify the parser produces high-quality, consistent, and usable output.

#### 4.1 Naming Consistency
- [ ] Parser name is consistent with established conventions
- [ ] Parser module name matches its function
- [ ] No typos in names or strings

#### 4.2 Artifact Typing Consistency
- [ ] `artifact_type()` is consistent across the parser
- [ ] Type matches category conventions (prefixes like `browser_`, `registry_`, `evtx_`)
- [ ] Type is documented in the artifact registry if new

**Reference:** `PARSER_CONVENTIONS.md` Section 5 for naming conventions.

#### 4.3 Category Suitability
- [ ] The artifact type is appropriate for the evidence source
- [ ] The parser is not producing artifacts from the wrong category
- [ ] If producing multiple artifact types, each is appropriately typed

#### 4.4 JSON Shape Sanity
- [ ] `json_data` structure is consistent and predictable
- [ ] Field names are clear and follow conventions
- [ ] JSON is valid and parseable
- [ ] Nested structures are not unnecessarily deep

#### 4.5 Timeline-Entry Suitability
- [ ] `description` is human-readable and meaningful
- [ ] `description` contains actionable information, not generic strings
- [ ] Timestamps in `description` match the `timestamp` field
- [ ] `json_data` contains all relevant fields for deeper investigation

**Good description:**
```rust
description: format!(
    "Application executed: {} (Hash: {}, Size: {})",
    record.path, record.sha256, record.size
)
```

**Bad description:**
```rust
description: "Record".to_string()  // Not helpful
description: "TBD".to_string()     // Placeholder
```

**Red flag:** Generic or placeholder descriptions. Descriptions that don't add investigative value.

---

### Phase 5 — Failure Mode Review

**Objective:** Verify the parser handles errors, malformed input, and edge cases correctly.

#### 5.1 Malformed Input Handling
- [ ] Parser validates input before processing (magic bytes, header size)
- [ ] Parser returns meaningful error for invalid format
- [ ] Parser does not panic on malformed input
- [ ] Buffer bounds are checked before access

**Correct:**
```rust
if data.len() < HEADER_SIZE {
    return Err(ParserError::Parse(format!(
        "File too short for {}: {} bytes (minimum {})",
        self.name(),
        data.len(),
        HEADER_SIZE
    )));
}
```

**Incorrect:**
```rust
// Panics if data too short
let header = Header::unpack(data).unwrap();
let magic = data[0..4].try_into().unwrap();
```

**Red flag:** Input validation missing. Potential panics on malformed evidence. No bounds checking.

#### 5.2 Empty Input Handling
- [ ] Parser handles empty input gracefully
- [ ] Empty input returns `Ok(vec![])`, not a synthetic artifact
- [ ] No panic or error on empty input (unless format is genuinely invalid)

**Correct:**
```rust
if data.is_empty() {
    return Ok(vec![]);
}
```

**Incorrect:**
```rust
if data.is_empty() {
    return Ok(vec![ParsedArtifact {
        description: "Empty file".to_string(),
        // This is fabricated!
        // ...
    }]);
}
```

#### 5.3 Partial Parse Behavior
- [ ] If some records parse and others fail, parser handles partial success
- [ ] Parser does not abort entire parse on one bad record
- [ ] If partial parsing occurs, parser surface warning in result (if envelope available)

**Note:** If the parser cannot surface warnings directly (no access to envelope), document the limitation.

#### 5.4 Warning/Escalation Expectations
- [ ] Parser propagates errors, does not suppress them
- [ ] Error messages are actionable and include context
- [ ] Parser does not silently swallow errors

**Incorrect:**
```rust
fn parse_file(...) -> Result<Vec<ParsedArtifact>, ParserError> {
    match parse_impl(data) {
        Ok(artifacts) => Ok(artifacts),
        Err(_) => Ok(vec![]),  // Silent failure!
    }
}
```

**Correct:**
```rust
fn parse_file(...) -> Result<Vec<ParsedArtifact>, ParserError> {
    let records = parse_impl(data)
        .map_err(|e| ParserError::Parse(format!("Parse error: {}", e)))?;
    Ok(records.into_iter().map(|r| self.to_artifact(r)).collect())
}
```

**Red flag:** Silent error-to-empty conversion. Catch-all error handlers that hide failures.

---

### Phase 6 — Test / Fixture Review

**Objective:** Verify the parser has adequate test coverage and that test fixtures are representative.

#### 6.1 Test Coverage
- [ ] Unit tests exist for the parser
- [ ] At least one test for valid input
- [ ] At least one test for empty/invalid input
- [ ] Tests verify error handling paths

**Minimum required tests:**
- [ ] Parser runs on valid fixture without panic
- [ ] Parser returns expected artifact count on valid fixture
- [ ] Parser handles empty input without panic
- [ ] Parser handles malformed input without panic

#### 6.2 Fixture Representativeness
- [ ] Test fixtures are documented as real or synthetic
- [ ] Synthetic fixtures are clearly marked and justified
- [ ] Fixtures cover the common cases the parser is designed for
- [ ] Fixtures are not "perfect" synthetic data that masks real-world complexity

**Red flag:** All test fixtures are synthetic with no real-world variation. Test fixtures don't match the file format actually used in evidence.

#### 6.3 Untested Cases
- [ ] Known edge cases are documented
- [ ] Cases that are difficult to test are noted
- [ ] Gaps in test coverage are documented for future improvement

**Document:** Cases that are currently untested and why.

#### 6.4 Runtime Validation Still Needed
- [ ] If fixtures are limited, runtime validation on real evidence is recommended
- [ ] If test coverage is weak, note this as a condition for approval
- [ ] If no tests exist, parser cannot be approved without runtime proof

**Rule:** If tests don't exist, the parser requires runtime validation on real evidence before approval.

---

### Phase 7 — Verdict

**Objective:** Render a final decision based on all preceding phases.

Strata classifies the parser into one of four statuses:

#### APPROVED

**Conditions for APPROVED:**
- [ ] All Phase 1–5 checks pass
- [ ] All Phase 6 tests pass or runtime validation is planned
- [ ] No red flags identified in any phase
- [ ] Parser is ready for registration and integration

#### APPROVED WITH WARNINGS

**Conditions for APPROVED WITH WARNINGS:**
- [ ] No critical truthfulness violations
- [ ] Minor quality issues present (naming, JSON shape, etc.)
- [ ] Test coverage is limited but runtime validation is feasible
- [ ] Non-blocking issues documented as conditions
- [ ] Parser may be registered with caveats

#### PARTIAL / NEEDS MORE VALIDATION

**Conditions for PARTIAL:**
- [ ] Parser cannot be fully assessed due to missing fixtures
- [ ] Runtime validation required before final verdict
- [ ] Ambiguous evidence of truthfulness violations
- [ ] Parser is blocked until validation complete

#### REJECTED

**Conditions for REJECTED:**
- [ ] Any truthfulness violation (invented artifacts, fabricated data)
- [ ] Any use of `Default::default()` on error paths
- [ ] Any panic-inducing code (`unwrap()` on evidence data)
- [ ] Missing provenance on artifacts
- [ ] Silent error suppression
- [ ] Parser output conflicts with GUI/CLI contracts

**Critical rejection triggers:**
- Parser creates fake artifacts
- Parser uses placeholder data as evidence
- Parser has no provenance on output
- Parser panics on malformed input

---

## Red Flags

The following are explicit red flags. Any single red flag is grounds for REJECTION or PARTIAL status.

| Red Flag | Severity | Trigger |
|----------|----------|---------|
| Fake defaults | CRITICAL | `Default::default()` used for artifacts |
| Placeholder artifacts | CRITICAL | Artifacts with "TBD", "TODO", "Placeholder", "STUB" |
| Missing provenance | CRITICAL | `source_path` is empty or working-directory path |
| Success on empty without explanation | HIGH | Returns `status: ok` with 0 rows and no warning |
| Invented timestamps | HIGH | `0` used as unknown timestamp, or timestamps not from evidence |
| Swallowed errors | HIGH | Silent `Err(_) => Ok(vec![])` conversion |
| Panic on malformed input | HIGH | `unwrap()` or `expect()` on evidence-derived data |
| Overclaimed output | HIGH | Parser claims richer data than source supports |
| Empty target patterns | MEDIUM | `target_patterns()` returns empty vec |
| Generic descriptions | MEDIUM | `description` is "Record" or similar non-informative text |
| No tests and no fixtures | HIGH | Cannot verify behavior without runtime testing |
| Weak fixture coverage | MEDIUM | Fixtures don't represent real evidence |
| Wrong error type | MEDIUM | Using `Box<dyn Error>` instead of `ParserError` |
| Timestamp type wrong | HIGH | Using `SystemTime` instead of `Option<i64>` |

---

## Required Evidence for Approval

Before issuing APPROVED or APPROVED WITH WARNINGS, Strata must confirm:

### Code Inspection
- [ ] Full parser source reviewed
- [ ] All `parse_file` paths examined
- [ ] Error handling paths reviewed
- [ ] No prohibited patterns found

### Evidence-Derived Output Confirmed
- [ ] All artifacts trace to `data: &[u8]` input
- [ ] No hardcoded artifact generation
- [ ] `source_path` set from `path` parameter on every artifact
- [ ] Timestamps extracted from evidence data or `None`

### Test/Fixture Output Reviewed
- [ ] At least one passing test verified
- [ ] Parser output shape matches expected schema
- [ ] Error handling paths produce errors, not silent empty returns

### Failure Paths Reviewed
- [ ] Empty input produces empty result
- [ ] Malformed input produces error or empty result
- [ ] No panic-inducing code paths

### Timeline/Category Implications Reviewed
- [ ] `artifact_type` is consistent and appropriate
- [ ] `description` is human-readable
- [ ] Output fits expected timeline schema

### Open Questions Documented
- [ ] Any gaps in test coverage documented
- [ ] Runtime validation recommendations noted
- [ ] Any ambiguities resolved or escalated

---

## Escalation Rules

Strata must escalate instead of approving when:

### Uncertain Provenance
- Cannot confirm that `source_path` on artifacts traces to evidence
- Evidence paths look fabricated or non-existent
- Parser output includes data not present in input

**Response:** Issue PARTIAL. Request clarification from author. Cannot approve until provenance is confirmed.

### Ambiguous Timestamps
- Parser uses timestamp format that cannot be verified
- `0` used as unknown placeholder without documentation
- Timestamp epoch (Windows vs. Unix) cannot be confirmed

**Response:** Issue PARTIAL. Request timestamp validation evidence. Cannot approve until timestamps are verified.

### Parser Infers Unsupported Conclusions
- Parser adds data not present in source
- Parser synthesizes fields from inference rather than extraction
- Parser claims more detail than evidence supports

**Response:** Issue REJECTED. Invention of evidence is a critical violation.

### Fixture Coverage Too Weak
- No tests exist
- Fixtures are synthetic and don't represent real evidence
- Edge cases are not covered and cannot be inferred

**Response:** Issue PARTIAL. Require runtime validation on real evidence before approval.

### Output Shape Conflicts with GUI/CLI Contracts
- Parser output field names don't match what GUI expects
- Parser artifact types don't match capability registry
- Parser output cannot be displayed by existing pages

**Response:** Issue PARTIAL. Coordinate with GUI team. Parser must match contracts.

### Parser Overclaims Beyond Evidence
- Parser claims support for format features that aren't implemented
- Parser output implies complete analysis when it's partial
- Parser doesn't surface warnings when results are partial

**Response:** Issue REJECTED if fabricated claims. Issue APPROVED WITH WARNINGS if partial behavior is honestly labeled.

---

## Parser Review Report Template

Use this template to document the outcome of each parser review.

---

### Parser Review Report

**Review ID:** `[REVIEW-YYYYMMDD-NNN]`  
**Date:** `[YYYY-MM-DD]`  
**Parser Name:** `[name()]`  
**Parser File:** `engine/src/parsers/{module}.rs`  
**Artifact Type:** `[artifact_type()]`  
**Target Patterns:** `[target_patterns()]`  
**Auditor:** Strata  
**Review Type:** `[New | Modified | Incident | Pre-release]`

---

### Files Reviewed

| File | Purpose | Status |
|------|---------|--------|
| `engine/src/parsers/{module}.rs` | Parser implementation | Reviewed |
| `engine/src/parser.rs` | Trait definition | Reviewed |
| `engine/src/parser_registry.rs` | Registration | Reviewed |
| `engine/src/tests/` | Unit tests | Reviewed / Not found |
| `fixtures/parsers/` | Test fixtures | Reviewed / Not found |

---

### Target Evidence Source

`[What file type this parser processes. Format specification if known.]`

---

### Verdict

```
┌──────────────────────────────────────────────────┐
│ VERDICT: [APPROVED | APPROVED WITH WARNINGS |    │
│          PARTIAL / NEEDS MORE VALIDATION |       │
│          REJECTED]                               │
└──────────────────────────────────────────────────┘
```

---

### Strengths

`[What this parser does well. Specific positive observations.]`

---

### Issues Found

#### Critical Issues (none / list)

| # | Issue | Location | Required Fix |
|---|-------|----------|-------------|
| C1 | | | |

#### High Issues

| # | Issue | Location | Required Fix |
|---|-------|----------|-------------|
| H1 | | | |

#### Medium Issues

| # | Issue | Location | Recommended Fix |
|---|-------|----------|----------------|
| M1 | | | |

#### Low Issues

| # | Issue | Notes |
|---|-------|-------|
| L1 | | |

---

### Red Flags Encountered

| Red Flag | Severity | Encountered? |
|----------|----------|-------------|
| Fake defaults | CRITICAL | [YES/NO] |
| Placeholder artifacts | CRITICAL | [YES/NO] |
| Missing provenance | CRITICAL | [YES/NO] |
| Success on empty without warning | HIGH | [YES/NO] |
| Invented timestamps | HIGH | [YES/NO] |
| Swallowed errors | HIGH | [YES/NO] |
| Panic on malformed input | HIGH | [YES/NO] |
| No tests | HIGH | [YES/NO] |

---

### Evidence of Correct Behavior

`[Specific evidence that the parser produces correct output. Quote code, cite test results, reference fixture outputs.]`

---

### Open Questions

| # | Question | Status | Resolution |
|---|----------|--------|------------|
| Q1 | | Unresolved / Resolved | |

---

### Next Actions

| Priority | Action | Owner | Due Date |
|----------|--------|-------|----------|
| P1 | | | |
| P2 | | | |

---

### Registration Recommendation

- [ ] APPROVED for registration — Ready for integration
- [ ] APPROVED WITH WARNINGS — Ready with documented caveats
- [ ] PARTIAL — Blocked pending runtime validation
- [ ] REJECTED — Must not be merged

**Caveats (if any):**  
`[List conditions for APPROVED WITH WARNINGS]`

**Runtime validation required (if any):**  
`[List what must be verified on real evidence before final approval]`

---

**Reviewer:** Strata  
**Date:** `[YYYY-MM-DD]`  
**Status:** `[FINAL / DRAFT]`

---

## Operating Philosophy

Strata closes every parser review with a reminder of why this discipline matters.

### Parsers Must Extract, Not Imagine

A parser's purpose is to read evidence and produce structured artifacts from what is actually there. A parser that invents, infers, or fabricates data is not a parser—it is a false witness. Every artifact must trace to the input data. If the data is not there, the artifact does not exist.

### Provenance Outranks Convenience

A complete artifact without a source path is worse than an empty result. Empty results are honest. Artifacts without provenance are dangerous—they appear legitimate but cannot be verified or traced. Strata values source path completeness over artifact count. A single provenance-traced artifact is worth more than a thousand fabricated ones.

### Uncertainty Must Be Surfaced, Not Hidden

When a parser encounters ambiguous data, truncated records, or unknown fields, it must say so. Returning `Ok(vec![])` with no warning when the file may contain data is a form of hiding. Returning an error with context is honest. Strata prefers honest errors over confident lies. Operators can work with honest uncertainty. They cannot work with confident lies.

### Approval Requires Evidence, Not Confidence Alone

A parser cannot be approved because its author believes it is correct. It must be shown to be correct through code inspection, test results, fixture validation, and runtime proof. Belief without evidence is not approval. Strata requires concrete evidence for every approval. Where evidence is absent, Strata escalates.

---

## Document Maintenance

**Last Updated:** 2026-03-23  
**Next Review:** 2026-06-23 (quarterly)  
**Update Triggers:**
- New `ParserError` variants added
- New anti-patterns discovered
- Convention changes established
- New artifact categories added

**Related Documents:**
- `PARSER_CONVENTIONS.md` — Quality standards and anti-patterns
- `STRATA_PARSER_REVIEW_CHECKLIST.md` — Itemized 21-item checklist
- `TRUTHFULNESS_RULES.md` — Non-negotiable evidence contracts
- `RUN_STRATA_SUITE_AUDIT.md` — How parser review fits into full audit
- `STRATA_AUDIT_REPORT_TEMPLATE.md` — How parser review is reported

**Location:** `D:\forensic-suite\guardian\RUN_STRATA_PARSER_REVIEW.md`
