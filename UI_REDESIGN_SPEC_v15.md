# UI Redesign Spec — Strata v1.5.0

**Author:** Agent 5 (Infrastructure)
**Date:** 2026-04-09
**Status:** SPEC ONLY — no code changes
**Scope:** CLAUDE.md v1.5.0 target #8: "UI redesign to Wolfmark dark aesthetic"

---

## 1. Design principles

Strata is used in federal forensic labs, ICAC task forces, and
air-gapped SCIFs. The UI must communicate *authority* and
*trustworthiness* — not flashiness. Every design decision follows
from three rules:

1. **Density wins.** Examiners spend 8–12 hour shifts staring at
   artifact tables. Wasted whitespace forces scrolling; scrolling
   hides evidence. Maximize information density without sacrificing
   readability.
2. **Dark by default, light by option.** Most forensic workstations
   run in dim labs. Dark themes reduce eye strain on long shifts.
   The single light theme (Ash) exists for depositions and courtroom
   projection.
3. **Zero chrome.** No gradients, no shadows, no rounded-corner
   excesses. Flat, matte surfaces with 1px borders. Let the data
   dominate the screen.

---

## 2. Current UI architecture (as-built v1.4.0)

### File structure

```
apps/tree/strata-tree/src/
├── main.rs                        # eframe bootstrap, 1400x900 default
├── app.rs                         # StrataTreeApp — egui::App impl
├── state.rs                       # AppState, FileEntry, 14 ViewModes
├── theme/mod.rs                   # StrataTheme struct, 7 themes
└── ui/
    ├── mod.rs                     # render() entry point, keyboard nav
    ├── layout.rs                  # 4-column explorer + tab-content dispatch
    ├── toolbar.rs                 # 2-row top bar (logo, nav, search)
    ├── tabbar.rs                  # 48px left icon sidebar (Phosphor icons)
    ├── tree_panel.rs              # Evidence tree (left, 220px)
    ├── file_table.rs              # Sortable file listing (center)
    ├── preview_panel.rs           # META/HEX/TEXT/IMAGE tabs (right, 280px)
    ├── splash.rs                  # License activation screen
    ├── status_bar.rs              # Bottom bar (currently unused)
    ├── titlebar.rs                # Custom titlebar
    ├── hex_panel.rs               # Hex editor (64KB paged)
    ├── gallery.rs / gallery_view.rs
    ├── artifacts_view.rs          # Plugin artifact results
    ├── bookmarks_view.rs          # Tagged evidence
    ├── timeline_view.rs           # Unified timeline
    ├── registry_view.rs           # Registry hive browser
    ├── event_logs_view.rs         # EVTX logs
    ├── browser_history_view.rs    # Web history
    ├── search_view.rs / search_panel.rs
    ├── compare_view.rs            # Evidence diff
    ├── hash_sets_view.rs          # Hash set management
    ├── audit_view.rs / audit_log.rs
    ├── plugins_view.rs            # Plugin output
    ├── settings_view.rs
    └── dialogs/                   # Modal dialogs (open evidence, new case, etc.)
```

### Current layout (FileExplorer mode)

```
┌──────────────────────────────────────────────────────────────────┐
│  TOOLBAR ROW 1: [Wolf] S T R A T A  [+Open Evidence] [New] [Open]│
│  TOOLBAR ROW 2: [Search bar]                    [Hash] [Export]  │
├────┬──────────┬───────────────────────────┬─────────────────────┤
│    │ Evidence │      FILE LISTING         │   PREVIEW PANEL     │
│ 48 │  Tree    │  NAME  SIZE  MOD  SHA-256 │  [META][HEX][TEXT]  │
│ px │  220px   │    (sortable columns)     │  [IMAGE]            │
│    │          │                           │                     │
│ I  │ > Vol 0  │  svchost.exe   72KB  ...  │  Path: /Windows/... │
│ C  │   > Win  │  ntdll.dll    1.9MB  ...  │  Size: 1,900,000    │
│ O  │   > Sys  │  kernel32.dll  750K  ...  │  Modified: ...      │
│ N  │   > Usr  │  explorer.exe 4.5MB  ...  │  MFT: 45021         │
│    │          │                           │  SHA-256: abcdef... │
│ S  │          │                           │                     │
│ I  │          │                           │  [Hex view]         │
│ D  │          │                           │                     │
│ E  │          │                           │                     │
│ B  │          │                           │                     │
│ A  │          │                           │                     │
│ R  │          │                           │                     │
└────┴──────────┴───────────────────────────┴─────────────────────┘
```

### Current theme system

`StrataTheme` struct has 13 color slots:
- Layout surfaces: `bg`, `panel`, `card`, `elevated`, `border`
- Accent: `active`
- Text: `text`, `secondary`, `muted`
- Status: `suspicious` (amber), `flagged` (red), `clean` (green)

7 themes: Iron Wolf (default), Midnight, Void, Tactical, Ash (light),
Graphite, High Contrast.

Radius constants: `RADIUS_LG = 10.0`, `RADIUS_MD = 6.0`,
`RADIUS_PILL = 20.0`.

### Current ViewModes (14)

FileExplorer, Artifacts, Bookmarks, Gallery, Compare, Timeline,
Registry, EventLogs, BrowserHistory, Search, HashSets, AuditLog,
Plugins, Settings.

Keyboard: Ctrl+1..0 for first 10, Ctrl+F1/F2 for AuditLog/Plugins.
Ctrl+Tab cycles. F6 cycles forward.

---

## 3. Redesign goals

| Goal | Rationale |
|---|---|
| Wolfmark brand identity | Dark steel/silver palette, wolf iconography, "Forensic Intelligence Platform" positioning |
| Higher information density | Reduce margins, tighten row heights, show more files per screen |
| Faster workflow | Reduce clicks to common actions; make keyboard-first navigation feel native |
| Better CSAM workflow | Dedicated CSAM review mode that keeps the examiner in control without accidental exposure |
| Mobile/tablet artifact views | Pulse (Android/iOS) parsers need artifact-specific views, not just generic tables |
| Court-mode | One-click switch to a presentation-safe mode for courtroom projection |
| Accessibility | WCAG 2.1 AA contrast ratios on all text; keyboard-only operability |

---

## 4. Layout redesign

### 4.1 New default layout: 3-panel with collapsible sidebar

Replace the current 4-column layout with a cleaner 3-panel design:

```
┌──────────────────────────────────────────────────────────────────────┐
│  COMMAND BAR: [Wolf] STRATA  /path/to/evidence.E01   [Search...]    │
│              [Case: Operation Foxhunt]  [Examiner: K. Smith]   [?]  │
├────┬─────────────────────────────────────────────────────────────────┤
│    │  ┌─ NAVIGATION ──────────────────────────────────────────────┐  │
│ 40 │  │  [Evidence] [Artifacts] [Timeline] [Tagged] [Plugins]    │  │
│ px │  └──────────────────────────────────────────────────────────┘  │
│    ├────────────────────┬────────────────────────────────────────────┤
│ N  │   NAVIGATOR        │  WORKSPACE                                │
│ A  │   (collapsible)    │  (content depends on active nav tab)      │
│ V  │                    │                                           │
│    │   > Evidence Tree  │  ┌── File Table ──────────────────────┐   │
│ R  │   OR               │  │  (sortable, filterable, virtualized│   │
│ A  │   > Plugin List    │  │   — shows 10,000+ rows smoothly)  │   │
│ I  │   OR               │  └───────────────────────────────────┘   │
│ L  │   > Timeline Nav   │  ┌── Inspector ──────────────────────┐   │
│    │   OR               │  │  META | HEX | TEXT | IMAGE | SIGMA│   │
│    │   > Tag Categories │  │  (horizontal split, draggable)    │   │
│    │                    │  └───────────────────────────────────┘   │
│    │   200px default    │                                           │
│    │   Ctrl+B toggle    │                                           │
└────┴────────────────────┴───────────────────────────────────────────┘
```

Key changes:
- **Icon sidebar narrows to 40px.** Icons only, no text. Tooltip on hover.
- **Navigation rail replaces the sidebar's role.** The 4 "core" icons
  in the current sidebar become a horizontal tab strip at the top of
  the workspace area. The icon sidebar becomes a pure ViewMode
  selector.
- **Navigator panel is collapsible.** Ctrl+B toggles it. When
  collapsed, the workspace gets the full width. In presentations
  (court-mode) the navigator auto-collapses.
- **Inspector panel is a horizontal split** at the bottom of the
  workspace, not a right-side panel. This is the dominant pattern in
  forensic tools (FTK, X-Ways, Autopsy) and gives the file table
  the full width of the screen. The split is draggable.
- **Command bar replaces the 2-row toolbar.** Single row: wolf mark,
  "STRATA" wordmark, breadcrumb path, global search field, case name,
  examiner name. Compact and always visible.

### 4.2 Icon sidebar — refined

Keep the existing Phosphor icon set but reorganize into logical groups
with separator lines:

```
┌────┐
│ FE │  File Explorer
│ AR │  Artifacts
│ TG │  Tagged Evidence
│ PL │  Plugins
├────┤
│ TL │  Timeline
│ GL │  Gallery
│ RG │  Registry
│ EV │  Event Logs
│ BH │  Browser History
│ SR │  Search
├────┤
│ HS │  Hash Sets
│ CM │  Compare
│ CS │  CSAM Review  ← NEW (see Section 7)
│ AL │  Audit Log
├────┤
│ ⚙  │  Settings (pinned bottom)
└────┘
```

Active icon: filled background in theme `active` color, 2px left
accent border (keep current pattern). Inactive: 40% opacity.

### 4.3 Navigator panel content per ViewMode

| ViewMode | Navigator shows |
|---|---|
| FileExplorer | Evidence tree (current `tree_panel.rs`) |
| Artifacts | Plugin list with artifact counts per plugin |
| Timeline | Date range selector + event type filter checkboxes |
| Tagged | Tag categories (Notable / Relevant / Suspicious / ...) with counts |
| Plugins | Plugin list with run status (passed / errored / not run) |
| Gallery | Folder tree filtered to image-containing directories |
| Registry | Hive selector (SYSTEM / SOFTWARE / SAM / NTUSER / ...) |
| EventLogs | Log source selector (Security / System / Application / Sysmon / ...) |
| BrowserHistory | Browser selector (Chrome / Firefox / Safari / Edge) |
| Search | Saved searches + search history |
| HashSets | Hash set list (imported sets with match counts) |
| Compare | Evidence A / Evidence B selector dropdowns |
| CSAM Review | CSAM scan status + hash set info (see Section 7) |
| AuditLog | Date range filter |

### 4.4 Inspector panel (replaces right-side preview)

The inspector is a horizontal split below the main content area.
Default height: 35% of workspace. Draggable divider. Ctrl+I toggles
collapse.

Tabs: **META** | **HEX** | **TEXT** | **IMAGE** | **SIGMA** | **DETAILS**

New tabs:
- **SIGMA** — shows which Sigma rules fired on the selected artifact,
  with MITRE technique links and narrative.
- **DETAILS** — knowledge bank entry for the selected file type.
  Replaces the current conditional "DETAILS" tab.

The META tab should be redesigned as a **property grid** (key-value
pairs in a 2-column layout) rather than the current free-form labels:

```
┌─────────────────────────────────────────────────┐
│  META                                           │
│  ───────────────────────────────────────────────│
│  Path          /Windows/System32/cmd.exe        │
│  Size          302,592 bytes (295.5 KB)         │
│  Created       2024-12-14 08:15:32 UTC          │
│  Modified      2024-12-14 08:15:32 UTC          │
│  Accessed      2026-01-08 14:22:01 UTC          │
│  MFT Record    29441                            │
│  SHA-256       a1b2c3d4...                      │
│  Signature     PE Executable (MZ)               │
│  Category      Executable                       │
│  Hash Flag     ── (no match)                    │
│  Bookmark      [+ Tag]                          │
│  ───────────────────────────────────────────────│
│  [Copy All] [Export JSON]                       │
└─────────────────────────────────────────────────┘
```

---

## 5. Theme refinements

### 5.1 Keep all 7 themes

The existing theme system is well-designed. Keep all 7 themes and the
`StrataTheme` struct. Refinements only:

### 5.2 Add 4 new color slots to `StrataTheme`

```rust
pub struct StrataTheme {
    // ... existing 13 fields ...
    // NEW:
    pub csam_alert: Color32,     // CSAM-specific alert (distinct from flagged)
    pub surface_hover: Color32,  // Row hover highlight
    pub divider: Color32,        // Thinner than border, for intra-panel separators
    pub selection: Color32,      // Selected row background
}
```

### 5.3 Tighten Iron Wolf palette

The default Iron Wolf theme is excellent but the `bg` → `panel` →
`card` progression is too subtle on some monitors. Increase contrast
between depth levels:

```
Current:    bg 070809 → panel 0d0e12 → card 0f1014
Proposed:   bg 050607 → panel 0c0e14 → card 12151c
```

This gives a visible "lift" between the base layer and cards without
breaking the dark aesthetic.

### 5.4 Reduce border radius

```
Current:   RADIUS_LG = 10.0, RADIUS_MD = 6.0, RADIUS_PILL = 20.0
Proposed:  RADIUS_LG = 6.0,  RADIUS_MD = 4.0, RADIUS_PILL = 14.0
```

Forensic tools look sharper with tighter radii. 10px felt modern-app;
6px feels professional-tool.

### 5.5 Typography

Currently all text uses egui's default proportional font with ad-hoc
sizes (8.5, 9, 10, 11, 13, 14, 18, 52 across the codebase). Define a
type scale:

| Token | Size | Weight | Usage |
|---|---|---|---|
| `DISPLAY` | 32px | Bold | Splash wordmark only |
| `H1` | 18px | Bold | Panel titles |
| `H2` | 14px | Semibold | Section headers |
| `BODY` | 12px | Regular | File table rows, metadata values |
| `CAPTION` | 10px | Regular | Column headers, status text, breadcrumbs |
| `MONO` | 12px | Regular (monospace) | Hex, hashes, paths, timestamps |
| `MONO_SM` | 10px | Regular (monospace) | Hash preview in table cells |

All text that represents forensic data (paths, hashes, timestamps,
registry keys) should use monospace. This is a forensic tool, not a
consumer app — monospace communicates precision.

---

## 6. File table redesign

The file table is the most-used component. Current issues:
- Column widths are fixed on init; no auto-sizing.
- No column reordering or show/hide.
- Row height is generous; could fit 30–40% more rows.
- No row striping (alternating bg makes dense tables scannable).

### 6.1 Proposed changes

| Change | Detail |
|---|---|
| Row height | Reduce from ~24px to 20px. Monospace 12px text fits in 20px with 4px vertical padding. |
| Row striping | Alternate rows between `card` and `card + 2% lighter`. Subtle but scannable. |
| Column auto-size | On evidence load, measure the widest value in each column (sample first 200 rows) and set column width to `max(header_width, value_width) + 16px padding`. |
| Column show/hide | Right-click column header → checkbox list of all columns. Default visible: NAME, SIZE, MODIFIED, SHA-256, CATEGORY. Hidden by default: CREATED, ACCESSED, MFT RECORD, MD5, SIGNATURE, HASH FLAG. |
| Column reorder | Drag column headers to reorder. Persist order in case settings. |
| Inline hash flag | If a file matches a hash set, show a colored dot (red = KnownBad, green = KnownGood, amber = Notable) in the NAME column, not a separate column. |
| Selection | Multi-select with Shift+Click (range) and Ctrl+Click (toggle). Selected rows get `selection` background color. |
| Context menu | Right-click row → Copy SHA-256 / Copy Path / Tag as... / Export / Open in Hex / Jump to Timeline |
| Virtualized rendering | Only render visible rows + `BUFFER_ROWS` (currently 50 — keep). This already exists in `file_table.rs` but should be formalized as the only rendering path. |
| Filter bar | Below column headers: a text input per column for live filtering. Type "exe" in the NAME filter → instant filter. |

### 6.2 File table columns (full set)

| Column | Default visible | Alignment | Font |
|---|---|---|---|
| NAME | yes | left | proportional + icon |
| SIZE | yes | right | mono |
| MODIFIED | yes | left | mono |
| CREATED | no | left | mono |
| ACCESSED | no | left | mono |
| SHA-256 | yes | left | mono_sm (truncated, full on hover) |
| MD5 | no | left | mono_sm |
| CATEGORY | yes | left | proportional |
| SIGNATURE | no | left | proportional |
| MFT RECORD | no | right | mono |
| HASH FLAG | no | center | dot indicator |
| ENTROPY | no | right | mono |
| BOOKMARK | no | center | tag icon |

---

## 7. CSAM review mode

CSAM workflow is safety-critical. The current implementation routes
everything through `publish_csam_plugin_output()` in `state_csam.rs`
and never auto-displays images. The redesign must preserve these
guarantees while giving the examiner a purpose-built workflow.

### 7.1 CSAM Review as a dedicated ViewMode

Add `ViewMode::CsamReview` to the enum. Accessible only when a CSAM
scan has been run (grayed out otherwise). The icon sidebar entry
appears between HashSets and AuditLog.

### 7.2 CSAM Review layout

```
┌─────────────────────────────────────────────────────────────────┐
│  CSAM REVIEW — Operation Foxhunt — 2026-04-09                  │
│  ──────────────────────────────────────────────────────────────│
│  ┌─ Status ─────────────────────────────────────────────────┐  │
│  │  Scan: Complete (14,322 files scanned in 3m 42s)         │  │
│  │  Hash DB: NCMEC 2026-Q1 (1,247,891 hashes loaded)       │  │
│  │  Hits: 7 confirmed  ·  3 pending review  ·  2 dismissed  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─ Hit Table ──────────────────────────────────────────────┐  │
│  │  STATUS    PATH                SHA-256     MATCH TYPE    │  │
│  │  ● Conf.   /Users/.../img1     a1b2c3...   MD5 exact    │  │
│  │  ● Conf.   /Users/.../img2     d4e5f6...   SHA-1 exact  │  │
│  │  ○ Pend.   /Users/.../img3     g7h8i9...   pHash (92%)  │  │
│  │  ○ Pend.   /Users/.../img4     j0k1l2...   pHash (87%)  │  │
│  │  ○ Pend.   /Users/.../img5     m3n4o5...   dHash (91%)  │  │
│  │  ✕ Dism.   /Users/.../img6     p6q7r8...   pHash (72%)  │  │
│  │  ✕ Dism.   /Users/.../img7     s9t0u1...   dHash (68%)  │  │
│  │  ● Conf.   /tmp/.../img8       v2w3x4...   MD5 exact    │  │
│  │  ...                                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─ Selected Hit Detail ────────────────────────────────────┐  │
│  │  Path: /Users/suspect/Downloads/image003.jpg             │  │
│  │  SHA-256: a1b2c3d4e5f6...                                │  │
│  │  Match: MD5 exact against NCMEC 2026-Q1                  │  │
│  │  Confidence: Confirmed                                    │  │
│  │  Category: (from hash DB if available)                    │  │
│  │                                                           │  │
│  │  ⚠ IMAGE NOT DISPLAYED — explicit examiner action        │  │
│  │    required. [Review Image] button below.                 │  │
│  │                                                           │  │
│  │  [Confirm] [Dismiss] [Review Image] [Add Note]           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─ Mandatory Reporting Notice ─────────────────────────────┐  │
│  │  18 U.S.C. § 2258A: Electronic service providers and     │  │
│  │  certain persons are required to report apparent CSAM     │  │
│  │  to NCMEC. [Generate Report]                              │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 7.3 CSAM safety guarantees (unchanged)

- **No auto-display.** The hit table shows metadata only (path, hash,
  match type, confidence). The "Review Image" button is the ONLY way
  to display image content, and it requires an explicit click.
- **Every action routes through `publish_csam_plugin_output()`.** No
  new code path may bypass it.
- **Detail format is load-bearing.** The bracket-delimited format
  `[match_type=X] [confidence=Y] [source=Z] [sha256=...]` must not
  change without updating Sigma rules 28+29 in lockstep.
- **Every report includes the 18 U.S.C. § 2258A notice.**
- **The three load-bearing tests must pass after any CSAM UI work.**

---

## 8. Court-mode

One-click toggle (Ctrl+Shift+C or toolbar button) that switches the
UI to a presentation-safe configuration:

| Setting | Court-mode value |
|---|---|
| Theme | Ash (light, high contrast on projectors) |
| Navigator | Auto-collapsed (maximizes workspace) |
| Font size | +2px across all tokens (readability at distance) |
| CSAM Review | Hidden entirely (no accidental exposure during testimony) |
| Examiner name | Visible in command bar (attribution for the record) |
| Case name | Visible in command bar |
| Status bar | Re-enabled with case metadata |

Court-mode is a presentation layer — it does not change any analysis
state. Toggling it off restores the examiner's prior theme and layout
settings.

---

## 9. Keyboard-first navigation

The current keyboard system is solid (Ctrl+1..0, Ctrl+Tab, arrows,
PgUp/PgDn, Home/End). Additions for v1.5.0:

| Shortcut | Action |
|---|---|
| Ctrl+B | Toggle navigator panel |
| Ctrl+I | Toggle inspector panel |
| Ctrl+Shift+C | Toggle court-mode |
| Ctrl+G | Go to MFT record / file ID (dialog) |
| Ctrl+E | Quick export selected file(s) |
| Ctrl+D | Tag selected file as "Relevant" (quick-tag) |
| Ctrl+Shift+D | Tag selected file as "Suspicious" (quick-tag) |
| Space | Toggle file selection (multi-select) |
| Enter | Open selected file in inspector |
| / | Focus search bar (vim-style) |

---

## 10. Mobile artifact views (Pulse integration)

When Pulse parsers produce artifact records, the Artifacts view should
group them by **parser category** rather than showing a flat table:

```
┌─ Artifacts View ────────────────────────────────────────────┐
│  Navigator: Plugin list       Workspace: Category cards     │
│                                                              │
│  > Pulse (Android)            ┌─ Communications ──────────┐ │
│    > Communications (142)     │  SMS: 89 records           │ │
│    > Web Activity (67)        │  Call Logs: 34 records     │ │
│    > User Activity (23)       │  Contacts: 19 records      │ │
│    > System (8)               │  Gmail: (expand →)         │ │
│    > Network (4)              └────────────────────────────┘ │
│  > Pulse (iOS)                ┌─ Web Activity ────────────┐ │
│    > Communications (210)     │  Browser History: 45       │ │
│    > ...                      │  Chrome Downloads: 12      │ │
│  > Phantom (Registry)         │  Chrome Cookies: 10        │ │
│  > Trace (Execution)          └────────────────────────────┘ │
│  > Guardian (AV/EDR)                                         │
│  > Sigma (29 rules)                                          │
└──────────────────────────────────────────────────────────────┘
```

Clicking a category card drills into a **record-level table** with
parser-specific columns (e.g., SMS shows: Date, Sender, Recipient,
Body preview, Suspicious flag).

---

## 11. Status bar resurrection

The current status bar (`status_bar.rs`) is unused — stats were moved
to toolbar Row 2. Resurrect it as a slim (24px) bottom bar:

```
┌─────────────────────────────────────────────────────────────────┐
│ FILES: 14,322  │  SUSPICIOUS: 47  │  TAGGED: 12  │  CSAM: 7   │
│                │                  │              │  HASH: 100% │
└─────────────────────────────────────────────────────────────────┘
```

Each stat is a clickable pill that jumps to the relevant view. The
CSAM count only appears when a CSAM scan has been run.

---

## 12. Splash screen refinements

The current splash is well-designed. Minor refinements:

- Replace the procedural chevron stack with the actual Wolfmark SVG
  logo (`~/Wolfmark/Wolfmark.svg`) loaded via `include_bytes!`.
- Add version string below subtitle: `v1.5.0 — Build 2026-04-10`.
- Add `.gov / .mil` badge: "Free for government and military use"
  in muted text below the activation form.
- On successful activation, animate a 400ms fade-to-workspace
  transition instead of the current instant swap.

---

## 13. Implementation plan

### Phase 1 — Theme tightening (no layout changes)

1. Add 4 new color slots to `StrataTheme`.
2. Tighten Iron Wolf palette contrast.
3. Reduce border radii.
4. Define type scale constants and apply across all `RichText` calls.
5. Add row striping to file table.
6. Reduce file table row height to 20px.

**Estimated scope:** ~400 lines changed across `theme/mod.rs`,
`file_table.rs`, and scattered `RichText::new()` calls.

### Phase 2 — Layout restructure

1. Convert right-side preview panel to bottom inspector (horizontal
   split).
2. Make navigator panel collapsible (Ctrl+B).
3. Replace 2-row toolbar with single-row command bar.
4. Add Ctrl+I inspector toggle.

**Estimated scope:** ~600 lines. `layout.rs` rewrite + `toolbar.rs`
simplification + new `inspector.rs`.

### Phase 3 — New views

1. Add `ViewMode::CsamReview`.
2. Build CSAM review layout in `csam_review_view.rs`.
3. Build court-mode toggle.
4. Build Pulse category-card artifact view.
5. Resurrect status bar.

**Estimated scope:** ~800 lines across 3 new files + status_bar
revamp.

### Phase 4 — Polish

1. File table column show/hide, reorder, auto-size.
2. Context menu on right-click.
3. Multi-select (Shift+Click, Ctrl+Click).
4. Per-column filter bar.
5. Splash screen SVG logo + fade transition.
6. Remaining keyboard shortcuts.

**Estimated scope:** ~500 lines.

---

## 14. Files that will be modified

| File | Phase | Change |
|---|---|---|
| `theme/mod.rs` | 1 | Add color slots, tighten palette, reduce radii, type scale |
| `file_table.rs` | 1, 4 | Row height, striping, column mgmt, context menu, filter |
| `layout.rs` | 2 | Horizontal inspector split, collapsible navigator |
| `toolbar.rs` | 2 | Simplify to single-row command bar |
| `preview_panel.rs` | 2 | Move to inspector position, add SIGMA tab |
| `tabbar.rs` | 2 | Reorganize icon groups, add CSAM Review entry |
| `status_bar.rs` | 3 | Resurrect with clickable stat pills |
| `state.rs` | 3 | Add `ViewMode::CsamReview`, court-mode flag |
| `mod.rs` | 3 | Wire CsamReview + court-mode rendering |
| `splash.rs` | 4 | SVG logo, version string, fade transition |

New files:
- `csam_review_view.rs` — CSAM review layout (Phase 3)
- `inspector.rs` — inspector panel controller (Phase 2, optional split from preview_panel)
- `court_mode.rs` — court-mode toggle logic (Phase 3)

---

## 15. What this spec does NOT cover

- **Color token names / CSS variables.** egui doesn't have a CSS
  layer. Colors are accessed via `state.theme().<field>`. No change.
- **Font file bundling.** The current `include_bytes!` approach for
  Phosphor icons is fine. If a custom Wolfmark font is designed later,
  it drops into the same slot.
- **Responsive / mobile layout.** Strata is a desktop forensic tool.
  Minimum window: 800x600 (already enforced in `main.rs`).
- **Animations beyond splash fade.** egui's immediate mode makes
  complex animations expensive. The splash fade is a simple alpha
  interpolation on the central panel; everything else stays instant.

---

## 16. Acceptance criteria

- [ ] `cargo clippy --workspace --all-targets` → 0 warnings after
  each phase.
- [ ] All existing tests pass after each phase.
- [ ] Three load-bearing CSAM tests pass after Phase 3.
- [ ] CSAM review mode never auto-displays image content (verified by
  manual test + code review of the render path).
- [ ] Court-mode hides CSAM Review entirely.
- [ ] Iron Wolf theme passes WCAG 2.1 AA contrast ratio (4.5:1) for
  all body text and 3:1 for all large text.
- [ ] File table renders 50,000 rows at 60fps on M1 MacBook Pro.

---

*Spec written by Agent 5 — ready for Korbyn's review before
implementation begins.*
