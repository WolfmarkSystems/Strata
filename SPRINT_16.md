# Sprint 16 — Report System + Artifact Confidence + macOS Keychain Depth
# FOR CODEX — Read AGENTS.md before starting

_Date: 2026-04-26_
_Agent: Codex (OpenAI)_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Before you start

1. Read AGENTS.md completely
2. Run `git pull`
3. Run `cargo test -p strata-shield-engine --test quality_gate`
4. Run `cargo test --workspace 2>&1 | tail -5`
5. Both must pass. Baseline: 3,977 tests.

---

## Hard rules

- Zero new `.unwrap()` in production code
- Zero new `unsafe{}` without justification
- Zero new `println!` in library code
- Quality gate must pass after every priority
- All 9 load-bearing tests must always pass
- `cargo clippy --workspace -- -D warnings` clean
- `npm run build --prefix apps/strata-ui` clean
- Do NOT use `git add -A` — stage only files you modified

---

## PRIORITY 1 — Court-Ready Report System

### Context

Strata has a report button but it generates a basic HTML output.
For court admission, a forensic report needs a structured format
with case information, examiner credentials, methodology, findings,
and chain of custody. This is what separates a forensic tool from
a toy.

### Implementation

**Step 1 — Report structure**

The report must contain these sections in order:

```
1. Cover Page
   - Case number, examiner name/badge/agency
   - Evidence description (file name, size, SHA-256 hash)
   - Date/time of analysis (from custody log)
   - Strata version

2. Methodology
   - What plugins were run
   - What hash sets were applied (if any)
   - Analysis timestamps (start/end from custody log)

3. Evidence Integrity
   - SHA-256 at acquisition
   - SHA-256 at analysis time
   - Match confirmation or MISMATCH WARNING

4. Executive Summary
   - Total artifacts found
   - Categories with counts
   - Flagged artifacts count
   - Suspicious files count

5. Flagged Artifacts (if any)
   - Each flagged artifact with examiner notes
   - Source file path
   - MITRE technique if mapped

6. Findings by Category
   - User Activity
   - Communications (with thread summaries)
   - Execution History
   - Network Artifacts
   - Web Activity
   - [other categories with content]

7. Chain of Custody Log
   - All custody entries from custody.rs
   - Timestamped, examiner-attributed

8. Examiner Certification
   - "I certify that this report accurately reflects..."
   - Examiner name, badge, agency, date
```

**Step 2 — HTML report generation**

Replace the existing report generation in `lib.rs` with a proper
structured report. Use `html_escape()` on all user-controlled strings
(already implemented in Sprint 12).

The HTML report must be:
- Self-contained (no external CSS/JS dependencies)
- Printable (print-friendly CSS)
- Professional appearance (not a debug dump)

**Step 3 — PDF export option**

Add `--format pdf` option that calls the system's print-to-PDF.
On macOS, use `wkhtmltopdf` if available, otherwise document
the "Print → Save as PDF" path.

**Step 4 — IPC command update**

```rust
#[tauri::command]
async fn generate_report(
    app: tauri::AppHandle,
    evidence_id: String,
    output_path: String,
    format: String,  // "html" or "pdf"
) -> Result<String, String>  // returns path to generated report
```

**Step 5 — Frontend**

The REPORT button opens a dialog:
- Output path picker
- Format selector (HTML / PDF)
- Preview of what will be included
- Generate button

### Tests

```rust
#[test]
fn report_includes_evidence_hash() {
    // Generate report, verify SHA-256 present in output
}

#[test]
fn report_html_escapes_case_name() {
    // Case name with <script> tag
    // Verify not present unescaped in report
}

#[test]
fn report_includes_custody_log() {
    // Load evidence, run plugins, generate report
    // Verify custody entries present
}
```

### Acceptance criteria — P1

- [ ] Report has all 8 required sections
- [ ] Evidence integrity hash in report
- [ ] Flagged artifacts with notes in report
- [ ] Chain of custody log in report
- [ ] HTML self-contained, printable
- [ ] All user strings HTML-escaped
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 2 — Artifact Confidence Scoring

### Context

Right now artifacts show as HIGH/MEDIUM/LOW forensic value
but don't have a numeric confidence score. For ML-generated
artifacts especially, examiners need to know how confident
the system is. This also enables filtering by confidence threshold.

### Implementation

**Step 1 — Confidence score field**

Add to `ArtifactRecord` in `crates/strata-engine-adapter/src/types.rs`:

```rust
pub struct ArtifactRecord {
    // existing fields...
    pub confidence_score: f32,    // 0.0 - 1.0
    pub confidence_basis: String, // "deterministic_parse", "ml_model", "heuristic"
}
```

Default: `confidence_score: 1.0`, `confidence_basis: "deterministic_parse"`
for all existing artifacts. ML-generated artifacts get lower scores.

**Step 2 — Score assignment rules**

```
deterministic_parse (registry, SQLite, plist): 1.0
file_signature_match: 0.95
pattern_match: 0.85
heuristic: 0.70
ml_model: 0.60-0.85 depending on model confidence
advisory: 0.50
```

**Step 3 — Frontend filter**

Add a confidence threshold slider to the artifact list:
"Minimum confidence: [====|----] 0.70"

Artifacts below the threshold are dimmed or hidden depending
on a "hide low confidence" toggle.

**Step 4 — Display in artifact detail**

In the artifact detail panel, show:
```
CONFIDENCE: 0.95 (file_signature_match)
```

**Step 5 — Sort by confidence**

Add confidence as a sort option in the artifact list header.

### Tests

```rust
#[test]
fn deterministic_parse_artifacts_score_1_0() {
    // Registry artifact → confidence_score == 1.0
}

#[test]
fn advisory_artifacts_score_below_0_7() {
    // is_advisory == true → confidence_score <= 0.65
}

#[test]
fn confidence_basis_is_never_empty() {
    // Every artifact has non-empty confidence_basis
}
```

### Acceptance criteria — P2

- [ ] `confidence_score` and `confidence_basis` on all artifacts
- [ ] Score assigned correctly per artifact type
- [ ] Frontend confidence filter slider working
- [ ] Confidence shown in artifact detail panel
- [ ] Sort by confidence works
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 3 — macOS Keychain Depth

### Context

Sprint 13 added basic keychain metadata detection. It surfaces
keychain entry labels but not the full forensic picture. This
sprint adds depth — account names, service names, creation dates,
and the security framework attributes that matter for investigations.

### Investigation first

```bash
grep -rn "keychain\|Keychain" \
    plugins/strata-plugin-mactrace/src/ \
    --include="*.rs" | grep -v target | head -20
```

Find the Sprint 13 keychain parser. Understand what it currently
extracts. Then extend it.

### What to add

The macOS keychain SQLite schema (login.keychain-db) has these
tables with forensically relevant data:

**genp (generic passwords):**
- `svce` — service name (app that stored the credential)
- `acct` — account name (username)
- `cdat` — creation date (when credential was stored)
- `mdat` — modification date (last changed)
- `labl` — human-readable label
- `agrp` — access group (which apps can read this)
- `sync` — iCloud sync status (0=local, 1=synced to iCloud)

**inet (internet passwords):**
- `srvr` — server/hostname
- `ptcl` — protocol (htps, ftp, etc.)
- `atyp` — authentication type
- `port` — port number
- `path` — URL path
- `acct` — account name
- `cdat`, `mdat`, `labl` — same as genp

**cert (certificates):**
- `subj` — subject name
- `issr` — issuer
- `slnr` — serial number
- `cdat`, `mdat`

**Forensic value:**
- `sync = 1` entries indicate iCloud Keychain sync — evidence of
  cloud credential exposure
- `agrp` values reveal which apps had credential access
- Creation/modification dates establish timeline of credential storage
- Internet passwords reveal what services the user authenticated to

### Implementation

Extend the existing keychain parser in MacTrace to extract
all fields above. Each keychain entry becomes a richer artifact:

```
Keychain Entry: Safari (iCloud Sync)
  Service: com.apple.safari.savedpasswords
  Account: user@example.com
  Server: example.com (https, port 443)
  Created: 2025-08-15 09:23:11 UTC
  Modified: 2025-11-01 14:55:03 UTC
  iCloud Sync: YES ← forensically significant
  Access Group: com.apple.safari.savedpasswords
  MITRE: T1555.001 (Keychain)
  Forensic Value: HIGH
```

### Tests

```rust
#[test]
fn keychain_icloud_sync_detected() {
    // Entry with sync=1 → icloud_synced: true in artifact
}

#[test]
fn keychain_internet_password_includes_server() {
    // inet entry → server field populated
}

#[test]
fn keychain_creation_date_parsed_correctly() {
    // cdat CoreData timestamp → correct UTC string
}
```

### Acceptance criteria — P3

- [ ] genp, inet, cert tables all parsed
- [ ] iCloud sync status detected and flagged
- [ ] Server/protocol/port for internet passwords
- [ ] Creation and modification dates in UTC
- [ ] MITRE T1555.001 mapping
- [ ] Identity & Accounts category > 0 on MacBookPro
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## After all priorities complete

```bash
cargo test --workspace 2>&1 | grep "test result" | grep "passed" | \
    awk -F' ' '{sum += $4} END {print sum " total passing"}'
cargo test -p strata-shield-engine --test quality_gate 2>&1 | tail -3
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | head -5
npm run build --prefix apps/strata-ui 2>&1 | tail -3
```

Stage only Sprint 16 files and commit:
```bash
git add <only files you modified>
git commit -m "feat: sprint-16 court-ready reports + confidence scoring + keychain depth"
```

Report:
- Which priorities passed
- Test count before (3,977) and after
- Deviations from spec

---

_Sprint 16 for Codex — read AGENTS.md first_
_KR approval: granted_
