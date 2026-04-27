# Sprint 19 — AUGUR Plugin Wiring + MRU Depth + Zone.Identifier + Report Polish
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
5. Both must pass. Baseline: 3,988 tests.

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

## PRIORITY 1 — Wire AUGUR as Strata Plugin #24

### Context

AUGUR (formerly VERIFY) implemented the StrataPlugin trait in
Sprint 8. The vendored SDK lives in `~/Wolfmark/augur/vendor/`.
This sprint wires AUGUR into Strata as a first-class plugin so
foreign language artifacts surface directly in the Strata UI.

### Investigation first

```bash
# Check current plugin count
grep -rn "PLUGIN_NAMES\|plugin_names\|\"VERIFY\"\|\"AUGUR\"" \
    apps/strata-desktop/src-tauri/src/lib.rs \
    apps/strata-ui/src/ \
    --include="*.rs" --include="*.ts" --include="*.tsx" | head -20

# Check how existing plugins are registered
grep -n "run_plugin\|match.*plugin" \
    apps/strata-desktop/src-tauri/src/lib.rs | head -20

# Check PLUGIN_DATA in frontend
grep -n "PLUGIN_DATA\|pluginData\|PluginData" \
    apps/strata-ui/src/ -r --include="*.ts" --include="*.tsx" | head -10
```

### Implementation

**Step 1 — Add AUGUR to Cargo.toml**

In `apps/strata-desktop/Cargo.toml`, add a path dependency
to the AUGUR plugin SDK:

```toml
[dependencies]
# existing...
augur-plugin-sdk = { path = "../../../../augur/crates/augur-plugin-sdk",
                     features = ["strata"],
                     optional = true }

[features]
augur = ["augur-plugin-sdk"]
```

If the path dependency causes issues (workspace conflicts),
copy just the plugin SDK crate into Strata's vendor/ directory:

```bash
mkdir -p vendor/augur-plugin-sdk
cp -r ~/Wolfmark/augur/crates/augur-plugin-sdk/src vendor/augur-plugin-sdk/
cp ~/Wolfmark/augur/crates/augur-plugin-sdk/Cargo.toml vendor/augur-plugin-sdk/
```

Then reference as:
```toml
augur-plugin-sdk = { path = "../../vendor/augur-plugin-sdk",
                     features = ["strata"] }
```

**Step 2 — Add to PLUGIN_NAMES**

Find where PLUGIN_NAMES or equivalent is defined and add AUGUR:

```rust
// In lib.rs or wherever plugins are enumerated
pub const PLUGIN_NAMES: &[&str] = &[
    // existing 23 plugins...
    "AUGUR",  // Plugin #24 — Foreign language detection and translation
];
```

**Step 3 — Wire in run_plugin**

Find the `match plugin_name` block and add:

```rust
"AUGUR" => {
    #[cfg(feature = "augur")]
    {
        use augur_plugin_sdk::AugurStrataPlugin;
        let plugin = AugurStrataPlugin::new("en");
        plugin.execute(ctx)
            .map_err(|e| format!("AUGUR error: {}", e))
    }
    #[cfg(not(feature = "augur"))]
    {
        Ok(vec![]) // AUGUR not compiled in
    }
}
```

**Step 4 — Add to frontend PLUGIN_DATA**

Find the TypeScript plugin data structure and add:

```typescript
{
  name: "AUGUR",
  version: "1.0.0",
  category: "Analyzer",
  color: "#1D9E75",  // teal — matches AUGUR brand
  description: "Foreign language detection and translation. " +
    "Identifies non-English content and produces machine translations. " +
    "All translations require human verification.",
  artifactTypes: ["augur_translation"],
  platforms: ["windows", "macos", "linux", "ios", "android"],
  mitreTechniques: [],
  advisoryNote: "All translations are machine-generated. " +
    "Verify with a certified human translator before legal use.",
}
```

**Step 5 — AUGUR artifact display in UI**

AUGUR artifacts have `is_advisory: true`. In the artifact detail
panel, advisory artifacts should show a distinct visual treatment:

- Amber border-left accent instead of default
- "⚠ Machine Translation" badge in the artifact header
- The `advisory_notice` field displayed prominently below the value
- A "Requires human verification" note in muted text

Find `ArtifactDetail.tsx` and add advisory artifact handling:

```typescript
{artifact.isAdvisory && (
  <div style={{
    borderLeft: '3px solid var(--color-warning)',
    paddingLeft: '12px',
    marginTop: '8px'
  }}>
    <span className="badge-warning">⚠ Machine Translation</span>
    <p className="advisory-text">{artifact.advisoryNotice}</p>
    <p className="muted">Verify with a certified human translator</p>
  </div>
)}
```

**Step 6 — Test**

```rust
#[test]
#[cfg(feature = "augur")]
fn augur_plugin_registered_in_plugin_names() {
    assert!(PLUGIN_NAMES.contains(&"AUGUR"));
}

#[test]
fn augur_plugin_data_has_advisory_note() {
    // Frontend plugin data includes advisoryNote for AUGUR
    // This is a documentation test — verify the constant exists
    let data = PLUGIN_DATA.iter().find(|p| p.name == "AUGUR");
    assert!(data.is_some());
}
```

### Acceptance criteria — P1

- [ ] AUGUR dependency added to Strata's Cargo.toml
- [ ] AUGUR in PLUGIN_NAMES (plugin #24)
- [ ] `run_plugin` routes "AUGUR" to AugurStrataPlugin
- [ ] Frontend PLUGIN_DATA includes AUGUR with advisory note
- [ ] Advisory artifacts display with amber accent and warning badge
- [ ] `cargo build` succeeds with augur feature
- [ ] 2 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 2 — MRU Registry Key Depth

### Context

Sprint 18 added basic MRU parsing. This sprint adds depth —
the remaining MRU key types that Sprint 18 may have missed,
and improves PIDL resolution for OpenSavePidlMRU entries
which are the most forensically valuable.

### Investigation first

```bash
# Check what MRU parsing currently exists
grep -rn "MRU\|mru\|OpenSave\|LastVisited\|RunMRU\|TypedPaths\|RecentDocs" \
    plugins/strata-plugin-phantom/src/ \
    --include="*.rs" | grep -v target | head -20

cat plugins/strata-plugin-phantom/src/mru.rs 2>/dev/null | head -50
```

### What to add or improve

**1. LastVisitedPidlMRU depth:**
This key maps applications to the directories they last opened.
Each entry is: `<executable_name>\0<PIDL_bytes>`.
Parse the executable name from the null-terminated prefix:

```rust
pub fn parse_last_visited_entry(data: &[u8]) -> Option<LastVisitedEntry> {
    // Find null terminator or UNICODE null (0x00 0x00)
    // Everything before: executable name
    // Everything after: PIDL bytes for the directory
    let null_pos = find_unicode_null(data)?;
    let exe_name = decode_utf16_lossy(&data[..null_pos]);
    let pidl_bytes = &data[null_pos + 2..];
    let directory = extract_display_name_from_pidl(pidl_bytes)
        .unwrap_or_else(|| hex::encode(&pidl_bytes[..pidl_bytes.len().min(16)]));
    Some(LastVisitedEntry { exe_name, directory })
}
```

**2. WordWheelQuery — Explorer search terms:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery\
```
Contains what the user typed in Explorer's search box.
Plain string values ordered by `MRUListEx`. Highly valuable —
proves what the user was looking for.

**3. TypedURLs (Internet Explorer / Edge legacy):**
```
HKCU\Software\Microsoft\Internet Explorer\TypedURLs\
```
URLs typed in IE/Edge address bar. `url1`, `url2`... format.
Separate from TypedPaths. IE/Edge artifacts still appear on
enterprise Windows machines.

**4. MS Office Recent Files:**
```
HKCU\Software\Microsoft\Office\16.0\Word\File MRU\
HKCU\Software\Microsoft\Office\16.0\Excel\File MRU\
HKCU\Software\Microsoft\Office\16.0\PowerPoint\File MRU\
```
Each contains `Item 1`, `Item 2`... with format:
`[F00000000][T<FILETIME_HEX>][O00000000]*<file_path>`
Parse the FILETIME and file path from each item.

**5. Jump Lists (Recent + Frequent):**
```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\
```
Jump List files are OLE compound documents. Each file is named
by AppID (e.g., `1b4dd67f29cb1962.automaticDestinations-ms`).
Parse the LNK entries embedded in each Jump List file.
These contain recently accessed files per application — taskbar
right-click history.

### Tests

```rust
#[test]
fn word_wheel_query_parsed_as_plain_strings() {
    // REG_SZ values → search terms in MRU order
}

#[test]
fn office_mru_filetime_extracted() {
    // "Item 1" = "[F00000000][T01D9A3B2C4E5F678][O00000000]*C:\doc.docx"
    // → path = "C:\doc.docx", timestamp parsed from T field
}

#[test]
fn last_visited_exe_name_extracted() {
    // Data with "notepad.exe\0\0" prefix + PIDL bytes
    // → exe_name = "notepad.exe"
}
```

### Acceptance criteria — P2

- [ ] WordWheelQuery parsed (Explorer search terms)
- [ ] TypedURLs parsed (IE/Edge legacy)
- [ ] Office MRU parsed for Word, Excel, PowerPoint
- [ ] LastVisitedPidlMRU executable name extracted
- [ ] Office MRU FILETIME → UTC timestamp
- [ ] All entries tagged with MITRE T1005
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 3 — Zone.Identifier + macOS Quarantine Depth

### Context

Sprint 18 added Zone.Identifier parsing. This sprint adds
the macOS equivalent (quarantine xattr) and deepens the
Windows ADS parser with additional context.

### Investigation first

```bash
grep -rn "zone\|Zone\|quarantine\|xattr\|ADS\|alternate" \
    plugins/ --include="*.rs" | grep -v target | head -20
```

### What to add

**1. macOS Quarantine xattr:**

Location: `com.apple.quarantine` extended attribute on any
file downloaded from the internet on macOS.

Format: `0083;5f8a3c2d;Safari;`
Fields (semicolon-separated):
- Flags (hex): `0083` = downloaded from internet
- Timestamp (hex Unix seconds): `5f8a3c2d`
- Application that downloaded: `Safari`
- Optional UUID

```rust
pub struct MacOsQuarantine {
    pub file_path: String,
    pub flags: u32,
    pub downloaded_at: Option<i64>,   // Unix timestamp from hex
    pub downloaded_by: Option<String>, // "Safari", "Chrome", etc
    pub uuid: Option<String>,
    pub is_internet_origin: bool,      // flags & 0x0001 != 0
}

pub fn parse_quarantine_xattr(value: &str) -> Option<MacOsQuarantine>
```

Where to wire: MacTrace plugin, which already handles macOS
system artifacts. Look for existing xattr handling.

```bash
grep -rn "xattr\|quarantine\|com\.apple" \
    plugins/strata-plugin-mactrace/src/ \
    --include="*.rs" | head -10
```

**2. Zone.Identifier HostUrl enrichment:**

When `HostUrl` contains a URL, extract:
- Domain (hostname only)
- Is it a known malware hosting domain? (check against a small
  hardcoded list of commonly-seen malware CDNs)
- Is it a legitimate CDN? (github.com, githubusercontent.com,
  download.microsoft.com etc → mark as likely legitimate)

```rust
pub fn classify_host_url(url: &str) -> HostUrlClassification {
    let domain = extract_domain(url)?;
    
    // Known legitimate download sources
    const LEGITIMATE_DOMAINS: &[&str] = &[
        "github.com", "githubusercontent.com",
        "download.microsoft.com", "dl.google.com",
        "releases.mozilla.org", "update.microsoft.com",
    ];
    
    // Commonly seen in malware delivery (not exhaustive)
    const SUSPICIOUS_TLDS: &[&str] = &[
        ".tk", ".ml", ".ga", ".cf", ".gq",  // free TLDs abused by malware
    ];
    
    HostUrlClassification {
        domain: domain.to_string(),
        is_likely_legitimate: LEGITIMATE_DOMAINS.iter()
            .any(|d| domain.ends_with(d)),
        is_suspicious_tld: SUSPICIOUS_TLDS.iter()
            .any(|tld| domain.ends_with(tld)),
        classification_note: String::new(),
    }
}
```

**3. Cross-reference Zone.Identifier with execution artifacts:**

When a Zone.Identifier artifact is found for a file, and that
same file path appears in ShimCache, AmCache, or Prefetch as
an executed binary:

Emit an additional artifact:
```
⚠ EXECUTION OF INTERNET-DOWNLOADED FILE
  File: payload.exe
  Internet origin confirmed: Zone.Identifier present (ZoneId=3)
  Source: https://evil.com/payload.exe
  Executed: confirmed via AmCache (SHA-1: abc123...)
  MITRE: T1105 (Ingress Tool Transfer) + T1059 (Execution)
  Forensic Value: CRITICAL
```

This cross-reference is one of the most powerful forensic
findings — proves a file was downloaded from the internet
AND executed.

### Tests

```rust
#[test]
fn quarantine_xattr_timestamp_from_hex() {
    let xattr = "0083;5f8a3c2d;Safari;";
    let q = parse_quarantine_xattr(xattr).unwrap();
    assert_eq!(q.downloaded_by.unwrap(), "Safari");
    assert!(q.is_internet_origin);
}

#[test]
fn quarantine_xattr_flags_detect_internet_origin() {
    // flags 0x0083 → is_internet_origin = true
    // flags 0x0000 → is_internet_origin = false
}

#[test]
fn zone_identifier_legitimate_domain_classified() {
    let result = classify_host_url("https://github.com/user/repo/release.zip");
    assert!(result.is_likely_legitimate);
    assert!(!result.is_suspicious_tld);
}

#[test]
fn zone_identifier_suspicious_tld_flagged() {
    let result = classify_host_url("https://malware.tk/payload.exe");
    assert!(result.is_suspicious_tld);
}
```

### Acceptance criteria — P3

- [ ] macOS quarantine xattr parsed (flags, timestamp, application)
- [ ] Internet-origin detection from quarantine flags
- [ ] Zone.Identifier HostUrl domain classification
- [ ] Suspicious TLD flagging
- [ ] Legitimate CDN recognition
- [ ] Cross-reference: internet download + execution = Critical artifact
- [ ] 4 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 4 — Report System Polish

### Context

Sprint 16 shipped the court-ready report system. This sprint
polishes it based on what a real forensic report needs —
specifically the examiner certification block, proper section
numbering, and a table of contents.

### What to add

**1. Table of contents:**

At the top of the report, after the cover page, add:

```html
<h2>Table of Contents</h2>
<ol>
  <li><a href="#evidence-integrity">Evidence Integrity</a></li>
  <li><a href="#methodology">Methodology</a></li>
  <li><a href="#executive-summary">Executive Summary</a></li>
  <li><a href="#flagged-artifacts">Flagged Artifacts</a> (N items)</li>
  <li><a href="#findings">Findings by Category</a></li>
  <li><a href="#custody-log">Chain of Custody</a></li>
  <li><a href="#certification">Examiner Certification</a></li>
</ol>
```

Each section heading gets an `id` attribute matching the TOC links.

**2. Examiner certification block:**

At the end of the report, a formal certification:

```html
<section id="certification">
  <h2>Examiner Certification</h2>
  <p>I, <strong>[Examiner Name]</strong>, certify that:</p>
  <ol>
    <li>The information in this report is accurate to the best
        of my knowledge and belief.</li>
    <li>This report was generated by Strata v[VERSION] on
        [DATE] and has not been altered since generation.</li>
    <li>The evidence described herein was handled in accordance
        with applicable forensic standards.</li>
    <li>The SHA-256 hash of the evidence at time of analysis
        is recorded in Section 1 of this report.</li>
  </ol>
  
  <div class="signature-block">
    <p>Examiner: ___________________________</p>
    <p>Badge/ID: ___________________________</p>
    <p>Agency:   ___________________________</p>
    <p>Date:     ___________________________</p>
    <p>Signature: __________________________</p>
  </div>
</section>
```

**3. Section numbering:**

Every section heading gets a number:
```
1. Evidence Integrity
2. Methodology
3. Executive Summary
4. Flagged Artifacts
5. Findings by Category
   5.1 User Activity (N artifacts)
   5.2 Communications (N artifacts)
   5.3 Execution History (N artifacts)
   ...
6. Chain of Custody
7. Examiner Certification
```

**4. Print CSS:**

Add `@media print` CSS to make the report print-ready:

```css
@media print {
  .no-print { display: none; }
  section { page-break-inside: avoid; }
  h2 { page-break-after: avoid; }
  .signature-block { page-break-inside: avoid; }
  a { text-decoration: none; color: inherit; }
  .page-break { page-break-before: always; }
}
```

**5. Report filename convention:**

When saving a report, auto-generate a filename:
```
Strata_Report_[CaseNumber]_[YYYYMMDD]_[HHMMSS].html
```

If no case number, use evidence filename.

**6. AUGUR translation artifacts in report:**

When AUGUR artifacts are present, add a dedicated section:

```html
<section id="foreign-language">
  <h2>5.X Foreign Language Evidence (AUGUR)</h2>
  <div class="advisory-block">
    ⚠ All translations in this section are machine-generated.
    Verify with a certified human translator before legal use.
  </div>
  [artifact table]
</section>
```

### Tests

```rust
#[test]
fn report_contains_table_of_contents() {
    // Generated report HTML contains TOC with expected links
}

#[test]
fn report_certification_block_includes_examiner_name() {
    // ExaminerProfile with name → name appears in certification
}

#[test]
fn report_filename_includes_case_number() {
    // Case number "2026-001" → filename contains "2026-001"
}

#[test]
fn report_augur_section_present_when_advisory_artifacts_exist() {
    // At least one is_advisory artifact → AUGUR section in report
}
```

### Acceptance criteria — P4

- [ ] Table of contents with working anchor links
- [ ] Section numbering throughout
- [ ] Examiner certification block with signature lines
- [ ] Print CSS added
- [ ] Auto-generated filename with case number
- [ ] AUGUR/advisory artifact section in report
- [ ] 4 new tests pass
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

Stage only Sprint 19 files:
```bash
git add <only files you modified>
git commit -m "feat: sprint-19 AUGUR plugin wiring + MRU depth + quarantine xattr + report polish"
```

Report:
- Which priorities passed
- Test count before (3,988) and after
- Whether `cargo build --features augur` succeeds
- Any deviations from spec

---

_Sprint 19 for Codex — read AGENTS.md first_
_KR approval: granted_
_P1 closes the AUGUR/Strata integration loop._
_P4 makes Strata reports court-submission ready._
