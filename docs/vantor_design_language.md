# STRATA DESIGN LANGUAGE — LOCKED
### Version 1.0 | 2026-03-29
### Apply to ALL Strata tools: Tree, Forge, Shield, Wraith, Pulse, Insight, Chronicle, Trace, Cipher, Remnant

---

## PHILOSOPHY

Strata tools are used by forensic examiners during 
8-12 hour examination sessions in lab environments.
The UI must:

- Not cause eye strain over long sessions
- Make critical information immediately visible
- Never feel like a generic enterprise SaaS product
- Feel like a tool built by someone who uses it
- Work at any screen size from laptop to 4K monitor

We do NOT do:
- White or light grey backgrounds (bland, causes glare)
- Flat design with no depth (hard to parse)
- Cramped layouts with no breathing room
- Rainbow color schemes (distracting)
- Generic sans-serif everything (boring)
- Top tab bars with 10+ tabs (cognitive overload)

We DO:
- Dark navy backgrounds (easy on eyes, professional)
- Floating cards with subtle elevation (clear hierarchy)
- Single accent color per tool (focused, distinctive)
- Rounded corners everywhere (modern, approachable)
- Left icon sidebar (more space, cleaner navigation)
- Breathing room between every element

---

## COLOR PALETTE — EXACT VALUES

### Base Colors (same across ALL tools)
```
App background:    #0f1117  — near-black navy, not pure black
Panel background:  #161b27  — slightly lighter, panels sit above bg
Card surface:      #1e2535  — cards float above panels
Elevated/selected: #252d3d  — active/hover states
Subtle border:     #2a3347  — all card and panel borders
Active border:     tool accent color (see per-tool below)
```

### Text Colors (same across ALL tools)
```
Primary text:      #e2e8f0  — near-white, main content
Secondary text:    #8899aa  — labels, metadata, secondary info
Muted text:        #4a5568  — timestamps, tertiary info
Section labels:    #8899aa  — 10-11px uppercase letter-spaced
```

### Status Colors (same across ALL tools — these NEVER change)
```
Suspicious:        #f59e0b  — amber, warning level
Flagged:           #ef4444  — red, critical/dangerous
Clean/Verified:    #22c55e  — green, confirmed safe
Carved:            #a855f7  — purple, recovered/carved
Deleted:           #4a5568  — muted, deleted files
Bookmarked:        tool accent color
```

### Per-Tool Accent Colors
```
Tree:       #7dd3fc  — cyan         (forensic workbench)
Forge:      #f97316  — orange       (AI knowledge engine)
Shield:     #60a5fa  — blue         (guardian/access control)
Wraith:     #94a3b8  — slate        (zero-trace imaging)
Pulse:      #e2e8f0  — white        (triage engine)
Insight:    #a855f7  — purple       (analysis layer)
Chronicle:  #fbbf24  — amber        (timeline)
Trace:      #4ade80  — green        (execution tracking)
Cipher:     #f43f5e  — rose         (encryption analysis)
Remnant:    #818cf8  — indigo       (data carving)
```

---

## BORDER RADIUS — EXACT VALUES

```
Large panels:      border-radius: 10px
Buttons:           border-radius: 6px
Input fields:      border-radius: 6px
Status badges:     border-radius: 4px
Pill elements:     border-radius: 20px
  (status bar, active tabs, pill buttons)
```

---

## TYPOGRAPHY

### Hierarchy
```
Section labels:
  font-size: 10-11px
  font-weight: 600
  letter-spacing: 0.8px
  text-transform: uppercase
  color: #8899aa

File/item names:
  font-size: 13-14px
  font-weight: 400
  color: #e2e8f0

Metadata values:
  font-size: 12-13px
  color: #e2e8f0

Secondary info (sizes, dates):
  font-size: 11-12px
  color: #8899aa

Status badges:
  font-size: 9-10px
  font-weight: 700
  letter-spacing: 0.5px
  text-transform: uppercase

Hex editor:
  font-family: 'Courier New', monospace
  font-size: 10-11px
  color: tool accent color (offsets in #4a5568)
```

### Minimum sizes
```
Nothing below 10px ever
Body text minimum: 12px
Labels minimum: 10px
```

---

## LAYOUT STRUCTURE

### Standard 4-column layout
```
┌──────┬──────────┬────────────────────┬──────────┐
│      │          │                    │          │
│ ICON │ EVIDENCE │   MAIN CONTENT     │  DETAIL  │
│ NAV  │  TREE    │   (file table,     │  PANEL   │
│ 48px │  220px   │   hex, timeline,   │  260px   │
│      │          │   etc)             │          │
└──────┴──────────┴────────────────────┴──────────┘
```

### Left Icon Sidebar (48px)
```
- Icons only, no text labels
- Tooltip on hover showing name
- Active icon: accent color + 2px left border indicator
- Active background: card surface (#1e2535)
- Hover: subtle card surface highlight
- Settings icon pinned to bottom
- No scrollbar — all icons visible
```

### Toolbar (top, 48px height)
```
Left:    Logo + primary actions
         [+ Open Evidence] in accent color (primary)
         [New Case] [Open Case] [Profile] in secondary style
Center:  Case metadata (Case | Examiner | Evidence)
Right:   Tool actions [Hash All] [Carve] [Index] 
         [Report] [Export]
Style:   Slim, no wasted space
         Buttons: pill/rounded, no square corners
         Primary button: accent bg, dark text
         Secondary: transparent + border
```

### Cards
```
Every panel is a card:
  background: #1e2535
  border: 1px solid #2a3347
  border-radius: 10px
  
Card header:
  padding: 10px 12px
  border-bottom: 1px solid #2a3347
  title: 10px uppercase #8899aa
  count/info: 10px #4a5568 (right aligned)

Card body:
  padding: 12-16px
  overflow: auto with thin scrollbar
```

### Status Bar (floating pill, bottom center)
```
Position: fixed, bottom: 12px, centered
background: #1e2535
border: 1px solid #2a3347
border-radius: 20px
padding: 5px 16px
font-size: 10px uppercase
Stats separated by 1px dividers
Suspicious count > 0: #f59e0b
Flagged count > 0: #ef4444
Shadow: 0 4px 20px rgba(0,0,0,0.4)
```

---

## INTERACTIVE STATES

### File/Item Rows
```
Default:   transparent background
Hover:     #252d3d background (subtle transition 0.15s)
Selected:  #252d3d background + 2px left border accent color
Suspicious: left border #f59e0b (regardless of selection)
Flagged:   left border #ef4444 (regardless of selection)
```

### Buttons
```
Primary (accent):
  background: accent color
  color: #0f1117 (dark text on bright bg)
  border: none
  hover: slight brightness increase

Secondary:
  background: transparent
  border: 1px solid #2a3347
  color: #8899aa
  hover: border becomes #4a5568, color becomes #e2e8f0

Destructive:
  background: transparent
  border: 1px solid #ef4444
  color: #ef4444
  hover: background #ef4444, color #fff
```

### Input Fields
```
background: #161b27
border: 1px solid #2a3347
border-radius: 6px
color: #e2e8f0
font-size: 12px
padding: 5px 10px
placeholder: #4a5568
focus: border-color becomes accent color
```

### Tab Navigation (detail panel)
```
Style: pill tabs (border-radius: 20px)
Default: transparent, color #4a5568
Hover: color #8899aa
Active: accent color background, #0f1117 text
```

---

## SPACING RULES

```
Minimum padding inside any card:     12px
Minimum gap between cards:           8px
Minimum gap between toolbar buttons: 6px
Row height in any list/table:        28px minimum
Between metadata fields:             10px
Between section groups:              16px
Status bar bottom margin:            12px

ZERO TOLERANCE: No two elements may touch at 0px margin
                Everything breathes
```

---

## SCROLLBARS

```
Width: 4px
Track: transparent
Thumb: #2a3347
Thumb hover: #4a5568
Border-radius: 2px
Never use system default scrollbars
```

---

## STATUS BADGES

```
Shape:      pill (border-radius: 4px)
Padding:    2px 5px
Font:       9-10px, bold, uppercase, letter-spacing 0.5px
Colors:
  SUSPICIOUS: bg #f59e0b, text #0f1117
  FLAGGED:    bg #ef4444, text #ffffff
  CARVED:     bg #a855f7, text #ffffff
  DELETED:    bg #4a5568, text #e2e8f0
  CLEAN:      bg #22c55e, text #0f1117
  ENCRYPTED:  bg #f43f5e, text #ffffff
  KNOWN BAD:  bg #ef4444, text #ffffff
  KNOWN GOOD: bg #22c55e, text #0f1117
```

---

## WHAT THIS LOOKS LIKE IN PRACTICE

Reference: strata_tree_ui_mockup.html
This file is the visual reference for all future tools.
Every new tool starts from this base and applies 
its own accent color.

```
Tree UI = this mockup with #7dd3fc accent
Forge UI = same structure with #f97316 accent
Shield UI = same structure with #60a5fa accent
etc.
```

The structure never changes.
The accent color is the only major variable.
This creates instant visual coherence across 
the entire Strata ecosystem.

---

## WHAT WE ARE NOT

```
Not Windows Explorer (flat, boring)
Not EnCase (dated, grey everything)
Not Axiom (dark but cluttered)
Not FTK (outdated paradigm)

We are: dark, modern, professional, breathable
        distinctive without being distracting
        forensic-grade without feeling clinical
        built by an examiner for examiners
```

---

## IMPLEMENTATION NOTES FOR OPUS/CODEX

When implementing this design language:

1. Apply the color palette via constants/theme struct
   Never hardcode hex values inline — use named constants
   
2. Border radius applied via theme constants
   --radius-lg: 10px
   --radius-md: 6px  
   --radius-sm: 4px
   --radius-pill: 20px

3. Status bar always floats at bottom center
   Never attached to window edge
   Always shows all 6 stats

4. Left sidebar always 48px
   Never expands
   Tooltips handle label visibility

5. Detail panel always on the right
   Always shows METADATA | HEX | TEXT | IMAGE tabs
   Pill tab style always

6. Run cargo check after every visual change
   Run cargo test — all tests must still pass
   Visual changes must NEVER break functionality

---

*D:\Wolfmark\docs\strata-design-language.md*
*This document is the visual law for the Strata ecosystem*
*Do not deviate without approval from Wolfmark Systems*

---

## THEMES — LOCKED (5 themes, all tools)

### Theme 1 — Strata Dark (DEFAULT)
```
Name:      "Strata Dark"
Subtitle:  "DEFAULT"
bg:        #0f1117
panel:     #161b27
card:      #1e2535
elevated:  #252d3d
border:    #2a3347
active:    #7dd3fc  (cyan)
text:      #e2e8f0
secondary: #8899aa
muted:     #4a5568
```

### Theme 2 — Strata Crimson (THREAT HUNT)
```
Name:      "Strata Crimson"
Subtitle:  "THREAT HUNT"
bg:        #120a0a
panel:     #1a0e0e
card:      #221414
elevated:  #2c1a1a
border:    #3a2020
active:    #f87171  (soft red)
text:      #ffe8e8
secondary: #aa7070
muted:     #5a3030
```

### Theme 3 — Strata Midnight (PURPLE VOID)
```
Name:      "Strata Midnight"
Subtitle:  "PURPLE VOID"
bg:        #0a0a0f
panel:     #101018
card:      #18181f
elevated:  #22222c
border:    #2a2a38
active:    #a78bfa  (purple)
text:      #ede9fe
secondary: #7c6faa
muted:     #3f3a58
```

### Theme 4 — Strata Slate (TACTICAL GREEN)
```
Name:      "Strata Slate"
Subtitle:  "TACTICAL GREEN"
bg:        #0f1214
panel:     #161c20
card:      #1e252a
elevated:  #252e34
border:    #2a3840
active:    #4ade80  (green)
text:      #e2ede8
secondary: #6a8878
muted:     #3a4e44
```

### Theme 5 — Strata Light (COURT READY)
```
Name:      "Strata Light"
Subtitle:  "COURT READY"
bg:        #f0f4f8
panel:     #ffffff
card:      #ffffff
elevated:  #e8f0f8
border:    #d0dce8
active:    #0369a1  (navy blue)
text:      #0f1827
secondary: #4a6480
muted:     #8aa0b8
pill-text: #ffffff
```

### Status colors (SAME across ALL themes — never change)
```
suspicious: #f59e0b  amber
flagged:    #ef4444  red
clean:      #22c55e  green
carved:     #a855f7  purple
deleted:    #4a5568  muted
```

### Theme implementation (Rust/egui)
```rust
pub struct StrataTheme {
    pub name: &'static str,
    pub bg:        Color32,
    pub panel:     Color32,
    pub card:      Color32,
    pub elevated:  Color32,
    pub border:    Color32,
    pub active:    Color32,
    pub text:      Color32,
    pub secondary: Color32,
    pub muted:     Color32,
    // Status colors never change:
    pub suspicious: Color32,  // always #f59e0b
    pub flagged:    Color32,  // always #ef4444
    pub clean:      Color32,  // always #22c55e
    pub carved:     Color32,  // always #a855f7
}

pub const THEMES: &[StrataTheme] = &[
    THEME_DARK,
    THEME_CRIMSON,
    THEME_MIDNIGHT,
    THEME_SLATE,
    THEME_LIGHT,
];
```

### Settings persistence
```
Save selected theme index to:
  %APPDATA%\Strata\settings.json
  { "theme": 0 }  // 0 = Dark (default)
Apply on startup before first frame renders
No restart required — hot-swap on selection
```

### Reference files
```
strata_tree_ui_mockup.html    — full UI reference (Dark theme)
strata_theme_selector.html    — all 5 themes interactive
strata_design_language.md     — this document (the law)
```
