# Sprint 12 — Security Hardening + Examiner Profile + Report Integrity
# FOR CODEX — Read AGENTS.md before starting

_Date: 2026-04-25_
_Agent: Codex (OpenAI)_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Before you start

1. Read AGENTS.md completely
2. Run `git pull` to get latest commits
3. Run `cargo test --workspace 2>&1 | tail -5` — confirm passing
4. Run `cargo test -p strata-shield-engine --test quality_gate` — confirm passing
5. Do not start until both pass

---

## Context

GPT-5.5 external review identified four issues that must be fixed
before any agency evaluation of Strata:

1. Tauri security is wide open (CSP disabled, asset scope "**")
2. Examiner profile is demo-only (save_examiner_profile just prints)
3. Tags are pre-seeded with fake data and hardcoded timestamps
4. Report HTML has string interpolation without escaping

These are not cosmetic. A forensic tool with injection vulnerabilities
or fake pre-seeded data cannot be used in a professional context.

---

## Hard rules — read AGENTS.md for full list

- Zero new `.unwrap()` in production code
- Zero new `unsafe{}` without justification comment
- Zero new `println!` in library code
- Quality gate must pass after every change:
  `cargo test -p strata-shield-engine --test quality_gate`
- All 9 load-bearing tests must still pass
- `cargo clippy --workspace -- -D warnings` must be clean

---

## PRIORITY 1 — Tauri Security Hardening

### Location

`apps/strata-desktop/src-tauri/tauri.conf.json`

### Current state (insecure)

```json
{
  "security": {
    "csp": null,
    "freezePrototype": false,
    "assetProtocol": {
      "scope": ["**"]
    }
  }
}
```

### Required state

```json
{
  "security": {
    "csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: asset:; connect-src ipc: http://ipc.localhost",
    "freezePrototype": true,
    "assetProtocol": {
      "scope": [
        "$APPDATA/strata/**",
        "$APPDATA/wolfmark/**",
        "$TEMP/strata-ui/**"
      ],
      "enable": true
    }
  }
}
```

### Why each setting matters

**CSP** — prevents XSS attacks if any evidence content is rendered
as HTML. A forensic tool rendering untrusted content without CSP
is a security liability.

**freezePrototype** — prevents prototype pollution attacks via
JavaScript. Should always be true in production.

**assetProtocol scope** — `["**"]` allows the Tauri webview to
read ANY file on the filesystem. An attacker who can inject
JavaScript into the webview can read `/etc/passwd`, SSH keys,
anything. Scope must be locked to only paths Strata actually needs.

### After changing tauri.conf.json

Test that the app still builds and launches:
```bash
cd apps/strata-desktop
cargo tauri build 2>&1 | tail -5
open src-tauri/target/release/bundle/macos/Strata.app
```

Confirm Strata loads evidence correctly with the new CSP.
If any IPC calls break due to CSP, adjust the policy — do not
revert to `null`.

### Acceptance criteria — P1

- [ ] CSP set to a restrictive policy (not null)
- [ ] freezePrototype set to true
- [ ] assetProtocol scope limited to Strata-specific paths
- [ ] App still builds and launches
- [ ] Evidence loading still works after CSP change

---

## PRIORITY 2 — Real Examiner Profile Persistence

### Location

`apps/strata-desktop/src-tauri/src/lib.rs`

Find `get_examiner_profile` and `save_examiner_profile`.

### Current state (demo)

```rust
// save_examiner_profile just prints:
println!("save_examiner_profile: {:?}", profile);

// get_examiner_profile always returns blank:
Ok(ExaminerProfile {
    name: String::new(),
    badge: String::new(),
    agency: String::new(),
    ..Default::default()
})
```

### Required state

Persist the examiner profile to disk using Tauri's app data directory:

```rust
use tauri::Manager;

#[tauri::command]
async fn save_examiner_profile(
    app: tauri::AppHandle,
    profile: ExaminerProfile,
) -> Result<(), String> {
    let path = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("examiner_profile.json");

    let json = serde_json::to_string_pretty(&profile)
        .map_err(|e| e.to_string())?;

    std::fs::write(&path, json)
        .map_err(|e| format!("Failed to save profile: {e}"))?;

    log::debug!("Examiner profile saved to {}", path.display());
    Ok(())
}

#[tauri::command]
async fn get_examiner_profile(
    app: tauri::AppHandle,
) -> Result<ExaminerProfile, String> {
    let path = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("examiner_profile.json");

    if !path.exists() {
        return Ok(ExaminerProfile::default());
    }

    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read profile: {e}"))?;

    serde_json::from_str(&json)
        .map_err(|e| format!("Failed to parse profile: {e}"))
}
```

### Acceptance criteria — P2

- [ ] `save_examiner_profile` writes to disk (not println)
- [ ] `get_examiner_profile` reads from disk
- [ ] Returns empty profile if no file exists (not error)
- [ ] No `.unwrap()` in the implementation
- [ ] Profile persists across app restarts

---

## PRIORITY 3 — Remove Pre-seeded Fake Tags

### Location

`apps/strata-desktop/src-tauri/src/lib.rs`

Find where tags are initialized. GPT-5.5 noted:
- Tags pre-seeded with fake mimikatz/security.evtx entries
- New tags get hardcoded `2009-11-16 09:00` timestamp
- Tags live only in memory (lost on restart)

### Fix

1. **Remove fake pre-seeded tags** — start with empty tag list
2. **Fix timestamp** — use current system time, not hardcoded date:
   ```rust
   use std::time::{SystemTime, UNIX_EPOCH};
   let timestamp = SystemTime::now()
       .duration_since(UNIX_EPOCH)
       .unwrap_or_default()
       .as_secs();
   ```
   Note: `.unwrap_or_default()` is acceptable here — SystemTime
   before UNIX_EPOCH is impossible on any real system, and the
   fallback to 0 is safe.

3. **Persist tags to disk** — same pattern as examiner profile:
   `app_data_dir()/tags.json`
   Load on startup, save on every add/remove/modify.

### Acceptance criteria — P3

- [ ] No pre-seeded fake tags on fresh install
- [ ] Tag timestamps use system time not hardcoded date
- [ ] Tags persist across app restarts
- [ ] No `.unwrap()` in tag persistence code

---

## PRIORITY 4 — Report HTML Escaping

### Location

`apps/strata-desktop/src-tauri/src/lib.rs` around line 831 and 933.

### Current state (dangerous)

Report generation interpolates user-controlled strings directly
into HTML:

```rust
// Dangerous — case name and examiner name go directly into HTML
format!("<h1>{}</h1>", case_name)
format!("<p>Examiner: {}</p>", examiner_name)
```

If `case_name` contains `<script>alert(1)</script>`, that script
executes when the report is opened in a browser.

For a forensic tool, this is a credibility and security problem —
a report that can be tampered with via crafted evidence metadata
is not defensible in court.

### Fix

Add an HTML escaping function:

```rust
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#x27;")
}
```

Apply it to every user-controlled string interpolated into HTML:
- case_name
- examiner_name
- examiner_badge
- examiner_agency
- any artifact values rendered in the report
- any file paths rendered in the report

### Test

```rust
#[test]
fn html_escape_prevents_script_injection() {
    let malicious = "<script>alert('xss')</script>";
    let escaped = html_escape(malicious);
    assert!(!escaped.contains('<'));
    assert!(!escaped.contains('>'));
    assert!(escaped.contains("&lt;script&gt;"));
}

#[test]
fn html_escape_handles_all_special_chars() {
    assert_eq!(html_escape("a&b"), "a&amp;b");
    assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
}
```

### Acceptance criteria — P4

- [ ] `html_escape` function implemented
- [ ] Applied to all user-controlled strings in report generation
- [ ] 2 tests pass
- [ ] `<script>` in case name does not appear unescaped in report
- [ ] No `.unwrap()` added

---

## After all priorities complete

Run the full quality check:

```bash
cargo test --workspace 2>&1 | grep "test result"
cargo test -p strata-shield-engine --test quality_gate 2>&1 | tail -3
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | head -5
npm run build --prefix apps/strata-ui 2>&1 | tail -5
```

All must pass. Then commit:

```bash
git add -A
git commit -m "fix: sprint-12 security hardening — CSP, examiner profile, tags, HTML escaping"
```

Report back with:
- Which priorities passed
- Test count before and after
- Quality gate status
- Any deviations from spec

---

## What this sprint does NOT touch

- Plugin logic
- Evidence parsing
- The 9 load-bearing tests (do not modify)
- CLAUDE.md (do not modify without KR approval)
- waivers.toml baseline numbers (do not raise them)
- Any VERIFY code (separate repo)

---

_Sprint 12 for Codex — read AGENTS.md first_
_KR approval: granted_
