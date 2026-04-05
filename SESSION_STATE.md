# STRATA — SESSION STATE
### Last Updated: 2026-03-28
### Read this file at the start of EVERY session before touching any code.

---

## ACTIVE SESSIONS

| Agent | Tool | Prompt File | Status |
|-------|------|-------------|--------|
| Codex | Tree v0.3.0 | `D:\Strata\apps\tree\strata-tree\codex_tree_v03_prompt.md` | IN PROGRESS |
| Opus  | Forge v0.1.0 | `D:\Strata\apps\forge\opus_forge_prompt.md` | QUEUED |

---

## OWNERSHIP MAP — DO NOT CROSS THESE LINES

```
Codex owns:
  D:\Strata\apps\tree\strata-tree\     ← ALL .rs files, Cargo.toml
  D:\Strata\crates\strata-fs\          ← filesystem/container parsing
  D:\Strata\crates\strata-core\        ← core types
  D:\Strata\plugins\                   ← all plugin crates

Opus owns:
  D:\Strata\apps\forge\                ← ALL forge files

Neither agent touches:
  D:\Strata\apps\shield\               ← NOT STARTED (built last)
  D:\Strata\apps\pulse\                ← NOT STARTED
  D:\Strata\apps\wraith\               ← NOT STARTED
  D:\Strata\apps\insight\              ← NOT STARTED
  D:\Strata\docs\                      ← Opus writes here only
```

If your task requires changes to a file you don't own:
  1. Document the required interface change
  2. Write it in your prompt's notes section
  3. Do NOT implement it — flag it for coordination

---

## TOOL STATUS

### Tree (Codex)
**Current version:** v0.2.0  
**Target version:** v0.3.0  
**Binary:** `D:\Strata\target\release\strata-tree.exe`  
**Last known binary size:** 16,462,848 bytes (~15.7 MB)  
**Last build time:** 6.46s  

**COMPLETED (do not re-implement):**
- ✅ E01 opening via strata-fs VFS
- ✅ NTFS indexing with real file counts
- ✅ FAT32 detection (partial — enumeration stub)
- ✅ SQLite-backed .vtp case files (5 tables, 6 indexes)
- ✅ 9 UI tabs — all render real content
- ✅ Registry viewer (nt-hive, full tree, 16 forensic keys, search, bookmarking)
- ✅ Timeline view (file timestamps, suspicious detection, filters, color coding)
- ✅ Gallery view (thumbnails, background worker, LRU-500 cache, EXIF)
- ✅ Evidence comparison (full diff, timestomping detection, CSV+PDF export)
- ✅ File bookmarks (6 tags, examiner notes, VTP persistence)
- ✅ Registry bookmarks (key + value targeting, double-click navigation)
- ✅ Export (CSV files/bookmarks/timeline, HTML bookmarks, PDF report)
- ✅ Audit log (13 action types, in-memory + VTP, no chain integrity yet)
- ✅ Hash worker (SHA-256 + MD5, HASH ALL button, background thread)
- ✅ Plugin loader (loads DLLs, extracts metadata — not yet executed)
- ✅ Compare view (EvidenceDiff, timestomping detection, CSV+PDF)
- ✅ Bookmarks view (unified file + registry, double-click navigation)
- ✅ Status bar (build timestamp + git hash)
- ✅ unwrap() audit complete — 0 in production paths

**IN PROGRESS (current Codex session — v0.3.0):**
- 🔄 Task 1: VFS Read Context — CRITICAL, wire hex/gallery/preview/hasher to VFS
- 🔄 Task 2: Carve engine UI — button + dialog + background worker + $CARVED node
- 🔄 Task 3: Hash set manager UI — tab + import + matching + indicators
- 🔄 Task 4: Virtual scrolling file table — 1M+ file performance
- 🔄 Task 5: Hex editor virtual rendering + demand paging + search
- 🔄 Task 6: Prefetch parser (versions 17/23/26/30 + MAM decompress)
- 🔄 Task 7: LNK file parser (MS-SHLLINK spec)
- 🔄 Task 8: Browser history parser (Chrome/Firefox/Edge)
- 🔄 Task 9: Audit chain integrity (SHA-256 hash chain)
- 🔄 Task 10: .VTP completion (timeline persist, auto-save, integrity hash, .bak)
- 🔄 Task 11: Examiner profile persistence (%APPDATA%\Strata\examiner.json)
- 🔄 Task 12: Court-ready PDF report (wired to REPORT button)
- 🔄 Task 13: Shellbag parser (BagMRU walk, timeline integration)
- 🔄 Task 14: EVTX parser (evtx crate, high-value event IDs)
- 🔄 Task 15: Content search UI (wire tantivy ContentIndexer)
- 🔄 Task 16: 22-step smoke test + v0.3.0 release build

**NOT STARTED (future Codex sessions):**
- ⬜ VFS byte-range access for hex editor paging (large files)
- ⬜ Plugin execution (C-ABI, run on evidence files, timeout + sandbox)
- ⬜ USN Journal parser ($UsnJrnl)
- ⬜ AmCache.hve parser
- ⬜ AppCompatCache (ShimCache) parser
- ⬜ UserAssist parser
- ⬜ SRUM database parser
- ⬜ Recover deleted files from $MFT
- ⬜ Multi-page hex demand paging at 1GB+ scale
- ⬜ Forge integration — "Open in Forge" button (after Forge is built)
- ⬜ Full installer (NSIS or WiX)
- ⬜ Code signing

**PRIMARY GAP (must be fixed in v0.3.0 Task 1):**
```
HexState::load_file() uses std::fs::read() — cannot read
files inside E01/VHD containers. strata-fs VFS has
open_file() and read_volume_at() but NOT wired to:
  - Hex editor
  - Gallery thumbnails
  - Preview panel
  - Hasher
  - Carver
Fix this first. Everything else depends on it.
```

---

### Forge (Opus)
**Current version:** v0.0.0 (not started)  
**Target version:** v0.1.0  
**Stack:** Tauri v2, Rust backend, TypeScript/React frontend  
**Location:** `D:\Strata\apps\forge\`  

**What Forge is:**
AI-powered forensic knowledge engine. Examiners ask it what
artifacts mean. It answers using local LLM (ollama) + embedded
DFIR knowledge base. Runs 100% offline — no evidence leaves
the machine. Not a generic chatbot — domain-specialized on
MITRE ATT&CK, malware families, Windows artifacts, threat actors.

**Tasks queued for Opus (v0.1.0):**
- ⬜ Task 1: Audit existing codebase (read-only first)
- ⬜ Task 2: Local LLM integration (ollama HTTP, streaming, ForgeContext)
- ⬜ Task 3: Main UI (chat interface, Quick Tools, context panel)
- ⬜ Task 4: IOC enrichment engine (local classifier)
- ⬜ Task 5: DFIR knowledge base (50 tools, 100 ATT&CK techniques)
- ⬜ Task 6: Tree integration protocol (HTTP server on port 7842)
- ⬜ Task 7: Settings + first-run wizard
- ⬜ Task 8: Conversation history persistence
- ⬜ Task 9: Report draft export (PDF + copy)
- ⬜ Task 10: Final build + UI polish

---

### Shield (NOT STARTED — Built Last)
**Reason:** Shield is the host for all plugins. Building it
after the plugins exist means its interfaces are designed
around observed reality, not guesswork.

**Build order:**
```
1. Tree complete      ← Codex, in progress
2. Forge complete     ← Opus, queued
3. Plugins complete   ← Remnant, Chronicle, Cipher, Trace
4. Wraith             ← imaging engine (builds on strata-fs)
5. Pulse              ← triage engine (calls Wraith)
6. Shield             ← last, wraps everything
7. Insight            ← AI analysis, consumes Shield's surfaces
```

---

### Plugins (NOT STARTED)
All four core plugins are queued after Tree v0.3.0 is solid.

| Plugin | Purpose | Status |
|--------|---------|--------|
| strata-plugin-remnant | Deep file carving | Not started |
| strata-plugin-chronicle | Timeline enrichment | Not started |
| strata-plugin-cipher | Encryption analysis | Not started |
| strata-plugin-trace | Execution tracking (Shimcache, Amcache) | Not started |

Plugin SDK interface must be frozen before plugins are built.
Opus documents this in Task 6 of the Forge prompt.

---

## DESIGN — LOCKED STANDARDS

### Logo Standards (all tool logos)
```
viewBox:        0 0 400 400
Outer hex:      stroke=accent, sw=1.8, opacity=0.7
Inner hex:      stroke=accent, sw=1.4, opacity=0.9
Hex ticks:      outer vertex → inner vertex EXACTLY
Primary elem:   sw=2.2, opacity=0.9
Secondary:      sw=1.4, opacity=0.7
No filters/glow on any element
No STRATA text — tool name only

Wordmark:       font-size=32, letter-spacing=6, x=203, y=340
Accent line:    x=88, width=224, y=348
Tagline:        font-size=14, letter-spacing=4, x=202, y=381
(x offsets corrected for SVG letter-spacing trailing drift)
```

### Tool Colors
| Tool | Color | Hex |
|------|-------|-----|
| Wraith | Slate | #94a3b8 |
| Pulse | White | #e2e8f0 |
| Shield | Blue | #60a5fa |
| Tree | Cyan | #7dd3fc |
| Forge | Orange | #f97316 |
| Insight | Purple | #a855f7 |
| Chronicle | Amber | #fbbf24 |
| Trace | Green | #4ade80 |
| Cipher | Rose | #f43f5e |
| Remnant | Indigo | #818cf8 |

### Logo Status
| Logo | Design | File | Status |
|------|--------|------|--------|
| Strata (company) | Vanta mark — V polygon, diamond frame, ticks | strata-logo.svg | ✅ LOCKED |
| Wraith | Zero Trace eye + USB trident + orbit rings | strata-wraith.svg | ✅ LOCKED |
| Pulse | ECG spike + radar + USB trident | strata-pulse.svg | ✅ LOCKED |
| Shield | Warden — chain links on perimeter + crosshair eye | strata-shield-v2.svg | ✅ LOCKED (temp — redesign when tool is built) |
| Tree | Twin prow longship + rune compass | strata-tree-v2.svg | ✅ LOCKED |
| Forge | Anvil + lightning bolt + impact sparks | strata-forge.svg | ✅ LOCKED |
| Insight | Constellation kill chain — scatter nodes + bright path | strata-insight.svg | ✅ LOCKED |
| Chronicle | Convergence — 8 streams to center target | strata-chronicle.svg | ✅ LOCKED |
| Trace | Process tree + dashed suspicious child | strata-trace.svg | ✅ LOCKED |
| Cipher | Padlock + double shackle + binary matrix | strata-cipher.svg | ✅ LOCKED |
| Remnant | Sector scan spike + disk platter + emerging file | strata-remnant.svg | ✅ LOCKED |

### Wallpaper
```
File:     strata_wallpaper_v4.svg (3840x2160)
Preview:  strata_wallpaper_preview.svg (960x540)
Layout:   10 tools at 384px spacing (x=192,576,960...3648)
V Logo:   scale=2.4, center=(1920,780)
Wordmark: font-size=56, x=1940, y=1159
Accent:   x=1704 to x=2136 (432px = V outer width at scale 2.4)
```

### Strata V Logo Geometry (exact)
```
V polygon points (design space, center 0,0):
  -90,-110  -11,110  11,110  90,-110  68,-110  0,79.4  -68,-110

Top bar:  x=-90 to x=90, y=-110 (180px)
Apex node: center (0,110), outer r=9, inner r=4
Top corner nodes: (-90,-110) and (90,-110), r=4
Authority ticks: ±148 spine, 5 ticks at y=-100,-67.5,-35,-2.5,30
Corner marks: ±210, leg=32px
Diamond frame: points at (0,±195) and (±195,0)

Wordmark (600x600 SVG, center at 300,300):
  font-size=24, letter-spacing=16
  x=308 (300 + 16/2 — SVG trailing drift fix)
  y=458 (apex_bottom 419 + gap 22 + cap_height 17)
  Visual width ≈ 180px = top bar width ✓

Accent line: x=210 to x=390 (180px, matches top bar exactly)
Tagline: x=308, y=484
```

---

## CODING STANDARDS (BOTH AGENTS)

```
- No unwrap() in production code — always ? or explicit match
- No panic!() in production — return Err instead
- No todo!() or unimplemented!() — stub returns meaningful error
- All timestamps UTC, displayed as UTC explicitly
- Evidence paths NEVER written to — read only
- All file reads logged to audit trail
- cargo check after every single change
- PowerShell 5.1 — no && operators, no ternary, no null coalescing
- Forward slashes for internal file paths
- All new pub structs derive Debug, Clone where appropriate
```

---

## INTEGRATION POINTS (Cross-Tool Interfaces)

These are the places where tools need to talk to each other.
Neither agent implements the other's side — document only.

### Tree → Forge ("Open in Forge")
- Forge runs HTTP server on port 7842 (default, configurable)
- Tree POSTs ForgeContext JSON to http://localhost:7842/api/context
- Tree checks Forge health at http://localhost:7842/health
- If Forge not running, Tree launches it then POSTs
- Opus documents the full API in D:\Strata\docs\forge-tree-integration.md
- Codex implements Tree's "Open in Forge" button AFTER Opus publishes the doc

### Plugin SDK Interface
- Defined in D:\Strata\crates\strata-tree-sdk\
- Frozen before any plugin is built
- C-ABI: strata_plugin_meta(), strata_plugin_init(),
         strata_plugin_run(), strata_plugin_free_result(),
         strata_plugin_shutdown()
- Opus documents the full protocol in Task 6 of Forge prompt

### Shield ← Everything (Future)
- Shield wraps all plugins — designed after plugins exist
- Every plugin's actual interface informs Shield's design
- No Shield work until Remnant, Chronicle, Cipher, Trace are done

---

## BINARY VERSIONS (Update after each release build)

| Tool | Version | Binary Size | Build Time | Date |
|------|---------|-------------|------------|------|
| Tree | v0.2.0 | 16,462,848 bytes | 6.46s | 2026-03-28 |
| Forge | — | — | — | — |
| Shield | — | — | — | — |
| Wraith | — | — | — | — |
| Pulse | — | — | — | — |
| Insight | — | — | — | — |

---

## HOW TO USE THIS FILE

**At the start of every Codex session:**
1. Read this file
2. Check COMPLETED list — do not re-implement anything on it
3. Check ACTIVE SESSIONS — confirm you own the files you're touching
4. Run `cargo build -p strata-tree 2>&1 | Select-String "^error"` first
5. Fix all errors before starting new work

**At the start of every Opus session:**
1. Read this file
2. Check OWNERSHIP MAP — confirm you're in D:\Strata\apps\forge\
3. Check Forge status — don't redo Task 1 if it's already done
4. Read the integration points section for context on interfaces

**After each session completes:**
1. Update the relevant tool's status section
2. Move completed tasks from IN PROGRESS to COMPLETED
3. Update binary version table with new size and build time
4. Note any new integration points discovered
5. Save and commit this file

---

*D:\Strata\SESSION_STATE.md*
*Keep this file accurate — it's the single source of truth for the entire project.*

---

## COMPANY — LOCKED

```
Company Name: Wolfmark Systems LLC
Founder:      Korbyn Randolph
Etymology:    Randolph (Anglo-Saxon) — Rand (shield) + olf (wolf)
              Shield-Wolf. 7th generation Texas. Built by the lineage.
Entity:       LLC — file in Texas when back in May (no state income tax)
              sos.state.texas.gov — $300 filing fee
EIN:          Apply at irs.gov after LLC is filed — free, 10 min

Flagship Product: Strata Forensic Intelligence Ecosystem
Mission:      Sovereign, court-ready forensic intelligence tools
              for law enforcement, military, and national security.

Founder Background:
  - Active duty US Army Counterintelligence Special Agent
  - CDTI (Counterintelligence Digital Threat Investigator)
  - Digital Forensic Examiner
  - Champlain College — Computer Forensics & Digital Investigations
  - 7th generation Texan, Randolph family (England/Scotland)
  - Currently: Georgia → Texas (May 2026) → Korea (TBD end of year)
```

## DOMAINS TO CLAIM (check tonight at namecheap.com)
  wolfmarksystems.com   ← primary target
  wolfmark.systems      ← modern alternative
  wolfmark.io           ← tech credibility
  wolfmarksystems.io    ← backup

## SOCIAL HANDLES TO LOCK TONIGHT (free)
  Twitter/X:  @WolfmarkSystems
  LinkedIn:   Wolfmark Systems (company page)
  GitHub:     github.com/wolfmark-systems
  YouTube:    @WolfmarkSystems

## BRAND VOICE — LOCKED
  Wolfmark/Strata is:
    Technical without arrogance
    Direct — no marketing language ever
    Honest about limitations
    Evidence-focused — everything connects to the examiner's job
    Sovereign — your data, your machine, your case

  Never says: industry-leading, seamless, empower, leverage,
              AI-powered (without specifics), cutting-edge
  Always says: specific numbers, honest trade-offs,
               technical specifics, plain language

  Strata tagline: FORENSIC INTELLIGENCE

## HARDWARE
  MacBook Pro 14" M1 Max — arriving in days
    10-core CPU, 24-core GPU, 64GB RAM, 1TB storage
    Primary dev machine — coding only
    Samsung T7 1TB SSD — Strata lives here, mounts to Mac

## AGENTIC TEAM PLAN (Mac setup day)
  Dev Team:       Phi-4 14B + Phi-4 Mini via OpenClaw
  Social Agent:   Phi-4 Mini — Wolfmark/Strata brand voice
  Legal Agent:    Phi-4 14B — CJIS, contracts, EULA, ToS
  Business Ops:   Phi-4 Mini — invoicing, proposals, grants
  Models:         Microsoft Phi-4 family (no Chinese LLMs)
  Orchestration:  OpenClaw
  Local inference: ollama on M1 Max GPU

## REVENUE PLAN
  Immediate:   Freelance DFIR tool development ($75-150/hr)
  Month 3-6:   GitHub Sponsors ($200-500/mo)
  Month 4-6:   Strata Tree Professional ($299/yr/seat)
               Strata Forge standalone ($199/yr/seat)
  Month 6-12:  Enterprise site licenses ($5,000-15,000)
  Long term:   SBIR grant application (DOJ/DHS/DoD)
               Training/certification program
               Full Strata ecosystem government sales

## PRODUCT PRICING (planned)
  Strata Tree Free:         Open source / community
  Strata Tree Professional: $299/year per seat
  Strata Tree Enterprise:   $999/year per seat (site license available)
  Strata Forge:             $199/year per seat
  Training (future):        $500/seat per course

## LEGAL / PRIVACY STRUCTURE

### LLC Filing — ON HOLD pending JAG consultation
  Status:     Do NOT file until cleared by organization and JAG
  When:       Back in Texas, May 2026 — consult first, then file
  JAG topics to cover:
    - Outside business ownership while active duty (AR 27-10)
    - Income disclosure requirements at clearance level
    - CI-adjacent technology company — any conflict of interest
    - Use of personal (not government) resources only — confirm OK
  Expected outcome: Cleared to proceed (standard for soldier-owned LLCs)

### Privacy Structure (implement when filing)
  Registered Agent service — $49-99/year
    Recommended: Northwest Registered Agent
    Effect: Your name/address replaced by agent on all public filings
  WHOIS Privacy — free via Namecheap
    Effect: Domain registration shows proxy, not your name
  Professional email — contact@wolfmarksystems.com
    Effect: No personal email ever public-facing
  Payment processing — Stripe (KYC required but stays private)
    Effect: Your identity verified by Stripe only, never public

  Public record shows:     Wolfmark Systems LLC + agent address
  Private (you only):      Korbyn Randolph, member/owner
                           Stored with: Texas SOS, IRS, Stripe, agent

### Interim (before LLC is filed)
  Claim social handles and domain now — no legal entity required
  Begin development — no legal entity required
  Do NOT take payment or sign contracts until LLC is filed and JAG cleared

## FINANCIAL PRIORITIES

### Immediate Debt
  MacBook Pro 14" M1 Max — purchased via Affirm
  Amount: $1,800
  Priority: Pay off EARLY — Affirm charges deferred interest
            if not paid in full before promo period ends
  Strategy: First freelance income goes directly to this
            Goal: paid off within 90 days of first client

### Revenue Waterfall (priority order)
  1. Pay off MacBook ($1,800) — first 90 days
  2. Cover Claude + Codex monthly cost (~$50-200/mo)
  3. Cover registered agent fee ($49-99/yr) when LLC filed
  4. Cover domain renewal ($12/yr)
  5. Everything above = business sustainable
  6. Surplus → reinvest into marketing and next product

### Fastest Path to $1,800
  Freelance DFIR development:
    Rate: $75-150/hour
    Hours to pay off Mac at $100/hr: 18 hours of work
    Realistic timeline: 2-4 weeks once first client lands
    Where to find clients:
      LinkedIn — post about Strata, examiners reach out
      DFIR.training community forums
      Reddit r/computerforensics
      Direct outreach to private forensic firms
      Digital forensics Facebook groups
      Former colleagues / military network

  One solid freelance client = MacBook paid off.
  That's the immediate mission.

### Affirm Tip
  Check your Affirm app for the promo end date.
  Pay the full $1,800 before that date to avoid
  deferred interest hitting all at once.
  Even $200-300/month aggressively chips it down.

## LICENSING SYSTEM — PLANNED

### Architecture
  Model: Offline cryptographic license files (.vlic)
  Crypto: Ed25519 signatures (public key in binary, private key on Mac)
  Machine binding: Hardware fingerprint (CPU + motherboard + OS GUID + volume serial)
  No internet required to validate — critical for air-gapped law enforcement

### Tiers
  Free (permanent):
    - Basic evidence browsing
    - Hex editor (read only)
    - CSV export
    - Max 10GB evidence
    - Gallery (thumbnails only)
    - No registry, timeline, parsers, PDF export

  Trial (30 days, full features):
    - Everything in Professional
    - Time-bombed via first-launch registry key
    - Shows "TRIAL (X days remaining)" in titlebar

  Professional ($299/year):
    - Registry viewer
    - Timeline analysis
    - Gallery + EXIF
    - All artifact parsers (Prefetch, LNK, Browser, Shellbag, EVTX)
    - PDF court-ready reports
    - Hash sets + NSRL
    - Compare view
    - Email support

  Enterprise ($999/year per seat or site license):
    - Everything in Professional
    - Plugin system (Remnant, Chronicle, Cipher, Trace)
    - Forge AI integration
    - Priority support + SLA
    - Compliance documentation (CJIS)
    - Volume discounts

### Components to Build (after Tree v0.3.0)
  strata-license crate:   D:\Strata\crates\strata-license\
    machine_id.rs         hardware fingerprinting
    license.rs            License struct, parse, validate
    crypto.rs             Ed25519 signature verification
    features.rs           FeatureSet, tier gating
    trial.rs              trial timer, first-launch tracking

  wolfmark-license-gen:   D:\Strata\tools\license-gen\
    Internal tool only — NEVER released
    egui UI for generating signed .vlic files
    Private key stays on MacBook, encrypted, never in repo

  Tree integration:
    Startup license check → apply FeatureSet
    Locked features show lock icon + tier badge
    [Start Free Trial] button in titlebar
    [Purchase] button → wolfmarksystems.com/purchase

### Trial Flow
  Download → Free tier → [Start Free Trial] →
  Enter email → receive .vlic → drop in folder →
  Full features 30 days → drops to Free →
  [Purchase] → Stripe $299 → Professional .vlic emailed →
  Drop in folder → permanent Professional

### Trial License Delivery (Phase 1 — manual)
  Customer emails machine ID
  You generate .vlic in license-gen tool
  Email back within 24 hours
  Scales to ~50 requests/month easily

### Trial License Delivery (Phase 2 — automated)
  Cloudflare Worker (free tier)
  Receives email + machine_id via API
  Signs trial license using private key env var
  Sends .vlic via SendGrid free tier
  Cost: $0

### Private Key Security
  Generated on MacBook, day of first license issuance
  Stored: encrypted on MacBook + physical USB backup in safe
  NEVER committed to git
  NEVER uploaded to cloud
  Loss = cannot generate new licenses (keep that backup safe)

### .vlic File Format
  JSON with Ed25519 signature
  Filename: strata-[tier]-[machine-id-prefix].vlic
  Location: same folder as strata-tree.exe
  Detection: automatic on next app launch

## TRIAL STRATEGY — AXIOM MODEL (refined)

### How Axiom Does It
  - Form fill on website (name, org, email, role)
  - Sales team reviews and issues time-limited license file
  - Manual at the sales layer — trial is a sales tool not self-serve
  - This is correct for the law enforcement / government buyer

### Strata Trial Model — Phase 1 (first 50 users, manual)
  - Person contacts contact@wolfmarksystems.com
  - OR direct warm intro (like SOCOM contact)
  - Provides: Name, Org, Role, Use Case, Machine ID
  - You review (2 minutes), generate .vlic, email back <24hr
  - Every trial = a direct sales relationship
  - No anonymous tire-kickers

### First Target — SOCOM Contact (former west coast sales, Detego)
  - Warm intro, knows Korbyn personally
  - Issue: 60-day extended VIP trial (vs standard 30)
  - Full Professional tier, no restrictions
  - Framing: "built this for people exactly like us"
  - He evaluates → procurement conversation → site license

### VIP Trial Protocol (high-value targets)
  - 60 days instead of 30
  - Direct personal outreach, not a form
  - Follow-up at day 30 for feedback
  - Follow-up at day 55 for purchase conversation
  - These relationships = word of mouth in tight military/LE community

### Phase 2 (after 50 users — automate)
  - Cloudflare Worker handles trial license generation
  - SendGrid delivers .vlic via email
  - Self-serve form on wolfmarksystems.com
  - Still review manually for enterprise prospects
  - Cost: $0 (both free tier)

### Implementation (simpler than originally planned)
  LicenseState enum:
    Licensed(LicenseInfo)   — valid .vlic found and verified
    Trial(days_remaining)   — active trial
    TrialExpired            — had trial, now expired
    Free                    — no trial ever started

  No online activation required
  No Cloudflare worker needed until Phase 2
  Just: check .vlic → validate Ed25519 sig → determine tier
  license-gen tool: internal egui app on Mac, you run it manually

## WOLFMARK SYSTEMS — BRAND ASSETS LOCKED

### Logo Files (save to D:\Wolfmark\brand\)
  wolfmark-systems-logo-white-bg.png  — full lockup, light backgrounds
  wolfmark-systems-logo-black-bg.png  — full lockup, dark backgrounds
  wolfmark-systems-icon.png           — wolf head only, avatars/favicons

### Logo Description
  Style:      Minimalist flat design, black and white only
  Mark:       Snarling wolf head, front-facing, white silhouette
              Angular ears, piercing eyes, fangs visible
              Aggressive but controlled — predator not rage
  Typography: WOLFMARK bold sans-serif, SYSTEMS spaced below
  Colors:     Pure black + pure white only (no gradients)
  Created:    ChatGPT DALL-E, 2026-03-28

### Usage
  Dark backgrounds:   white wolf (wolfmark-systems-logo-black-bg.png)
  Light backgrounds:  black wolf (wolfmark-systems-logo-white-bg.png)
  Avatar/icon:        wolfmark-systems-icon.png
  GitHub:             wolfmark-systems-icon.png ← upload now
  LinkedIn:           wolfmark-systems-icon.png ← upload now
  Favicon:            wolfmark-systems-icon.png (convert to .ico)
  PDF reports:        wolfmark-systems-logo-white-bg.png (light docs)
                      wolfmark-systems-logo-black-bg.png (dark docs)

## FINANCIAL REALITY — CURRENT STATE (2026-03-28)

### Available Cash
  Remaining Pell Grant funds: $537.00

### Already Paid This Period
  MacBook Pro (Affirm payment):  $208.00
  Claude Pro subscription:       $106.00
  ChatGPT Plus:                  $20.00
  Codex API key:                 $100.00
  wolfmarksystems.com domain:    $6.79
  ─────────────────────────────────────
  Total spent:                   $440.79
  Remaining:                     $537.00 (approximate — track carefully)

### Affirm MacBook Payment Schedule
  Total balance:    $1,800.00
  Paid to date:     $208.00
  Remaining:        $1,592.00
  Next payment:     $145.00 due April 28, 2026
  Following:        $145.00 due May 28, 2026
  Goal:             Pay off early to avoid deferred interest
                    Check promo end date in Affirm app

### Monthly Burn Rate
  Claude Pro:       $106.00/mo
  ChatGPT Plus:     $20.00/mo
  Codex API:        $100.00/mo (see note below)
  Affirm payment:   $145.00/mo
  ─────────────────────────────────────
  Total monthly:    ~$371.00/mo

### CODEX API NOTE — COST REDUCTION PLAN
  Once MacBook arrives and Phi-4 fleet is operational:
  - Phi-4 14B + Phi-4 Mini handle mechanical coding tasks
  - Codex API becomes redundant for most work
  - Plan: cancel Codex API key after Mac agent team is verified
  - Savings: $100/mo redirected to MacBook payoff
  - Claude + Opus remain for architecture and decisions
  - ChatGPT Plus: reassess after Mac setup — may keep for image gen

### Reduced Monthly Burn (after Mac setup)
  Claude Pro:       $106.00/mo
  ChatGPT Plus:     $20.00/mo  (reassess)
  Affirm payment:   $145.00/mo
  ─────────────────────────────────────
  Target monthly:   ~$271.00/mo (saving $100 vs current)

### Break-Even Math
  Need to cover $271/mo minimum
  At $100/hr freelance: 3 hours of work = monthly costs covered
  At $100/hr freelance: 18 hours = MacBook paid off entirely
  First freelance client = changes everything

### Priority Order for Any Income
  1. MacBook Affirm payments (avoid deferred interest)
  2. Claude Pro (core tool — keep)
  3. ChatGPT Plus (image gen — reassess)
  4. Savings buffer
  5. Everything else

### Affirm Clarification
  Payment plan:     18 months (plenty of runway)
  Promo end:        ~October 2027
  Strategy:         Pay minimums ($145/mo) until revenue comes in
                    Then accelerate payoff with freelance income
                    No rush — 18 months is safe territory
  Next Pell Grant:  Coming after current 2 classes complete
                    Use portion for MacBook acceleration
  Interest note:    Paying interest is acceptable vs cash flow stress
                    Priority is keeping monthly burn manageable
                    until first freelance client lands

## FORGE v0.1.0 — SHIPPED (2026-03-28)

### Binary
  Size:      13.4 MB release binary
  Errors:    0
  Warnings:  0
  Location:  D:\Strata\apps\forge\target\release\

### Modules Delivered
  error.rs              71 lines  — ForgeError typed variants
  llm.rs               279 lines  — ollama HTTP client, streaming SSE
  context.rs            96 lines  — ForgeContext + prompt block renderer
  prompt.rs            136 lines  — DFIR system prompt + 5 Quick Tool prompts
  forge_state.rs        44 lines  — Shared app state (Mutex-wrapped)
  commands.rs          401 lines  — 28 Tauri commands
  ioc.rs               222 lines  — 12-type classifier + KB enrichment
  knowledge/          ~1640 lines  — 52 tools, 100+ techniques, 20 artifacts,
                                    40 paths, 20 actors
  context_server.rs    283 lines  — HTTP server port 7842 (Tree→Forge IPC)
  settings.rs           89 lines  — Persistent settings (APPDATA)
  history.rs           295 lines  — Conversation persistence + MITRE extraction
  export.rs            181 lines  — Text/Markdown/HTML export
  src/index.html       582 lines  — Full forensic chat UI
  docs/forge-tree-integration.md  — 179 lines — Codex integration guide

### Knowledge Base
  MITRE ATT&CK:  102 techniques confirmed
  Tools:         52 known attacker tools
  Artifacts:     20 Windows forensic artifact types
  Paths:         40 suspicious path patterns
  Actors:        20 threat actor profiles

### Integration
  Context server: HTTP on port 7842 — ready for Tree connection
  Integration doc: D:\Strata\docs\forge-tree-integration.md
  Codex can now implement "Open in Forge" button in Tree

### Next Opus Session — QUEUED
  Options:
  A) Plugin SDK specification (strata-plugin-sdk crate)
  B) Forge v0.2.0 — expand knowledge base, add more parsers
  C) Documentation — full API docs, user guide
  Recommendation: Plugin SDK spec — needed before any plugin work begins

## TREE v0.3.0 — SHIPPED (2026-03-28)

### Verification Results
  cargo check:    PASS — 0 errors, 0 warnings
  cargo test:     PASS — 32/32 tests passing
  unwrap() audit: PASS — 0 in production code
  Release binary: 24,240,032 bytes (23.1 MB)
  Version:        0.3.0 in Cargo.toml
  Total tasks:    55 completed (39 roadmap + 16 v0.3.0)

### All 16 v0.3.0 Tasks Delivered
  Task 1:  VFS Read Context — wired to hex, gallery, preview,
           hasher, content indexer, carver
  Task 2:  Carve engine — 26 signatures, dialog, background
           worker, $CARVED tree node
  Task 3:  Hash sets — NSRL import, KnownBad/Good/Notable
           matching wired to file table
  Task 4:  Virtual scrolling — index-based, 50-row buffer,
           rayon parallel sort
  Task 5:  Hex editor — 256KB window paging, search, go-to offset
  Task 6:  Prefetch — versions 17/23/26/30 + MAM decompression
  Task 7:  LNK — MS-SHLLINK spec, drive type, machine ID
  Task 8:  Browser history — Chrome/Edge/Firefox + downloads
           + suspicious URL detection
  Task 9:  Audit chain — SHA-256 hash chain
  Task 10: VTP — timeline_entries table, auto-save 5min, schema v3
  Task 11: Examiner — %APPDATA%\Strata\examiner.json persistence
  Task 12: Report — 8-section court-ready HTML + CSV export
  Task 13: Shellbags — nt_hive BagMRU walk, path reconstruction
  Task 14: EVTX — evtx crate, high-value event IDs
  Task 15: Content search — tantivy full-text, INDEX button wired
  Task 16: Release — 32 tests, 0 unwrap(), 23.1MB binary

### Status
  Tree v0.3.0: COMPLETE — demo ready, trial ready, public ready
  Next session: Plugin SDK specification OR licensing system

## ECOSYSTEM STATUS SUMMARY (2026-03-28)
  Tree  v0.3.0  SHIPPED ✅  23.1MB  55 tasks  32 tests
  Forge v0.1.0  SHIPPED ✅  13.4MB  10 tasks   0 errors
  Shield        NOT STARTED (built last)
  Wraith        NOT STARTED
  Pulse         NOT STARTED
  Insight       NOT STARTED
  Plugins       NOT STARTED (need Plugin SDK spec first)

## FINANCIAL UPDATE (2026-03-29)

### Corrected Cash Position
  Available capital:  $633.00 (corrected — +$96 from previous)

### April Plan (updated)
  Claude Pro:         $20.00  (downgrading from $106 — dropping Opus)
  ChatGPT Plus:       $20.00
  Codex API:          $100.00 (final month — cancelling after Mac arrives)
  Affirm MacBook:     $145.00 (due April 28)
  ─────────────────────────────
  April total:        $285.00
  After April:        $348.00

### May Plan (steady state)
  Claude Pro:         $20.00
  ChatGPT Plus:       $20.00
  Affirm MacBook:     $145.00
  ─────────────────────────────
  May total:          $185.00
  After May:          $163.00 buffer

### Agent Architecture (finalized)
  Claude Pro $20:     Overlord — weekly task lists, architecture,
                      design reviews, judgment calls
  Phi-4 14B:          Heavy implementation — Rust, features, bugs
  Phi-4 Mini:         Fast tasks — tests, docs, social, business ops
  Opus:               On-demand only via Claude.ai when needed
  Codex:              CANCELLED after Mac arrives

## LICENSING SYSTEM — COMPLETE (2026-03-29)

### strata-license crate
  Status:   SHIPPED ✅
  Tests:    8/8 passing
  Features: Ed25519 validation, machine fingerprint,
            trial management, feature gating,
            free/trial/pro/enterprise tier sets

### wolfmark-license-gen tool
  Status:   SHIPPED ✅
  Binary:   1.03 MB
  Commands: generate-keypair, issue, issue-trial,
            verify, list-features

### License integration in Tree
  Status:   COMPLETE ✅
  Features gated:
    registry_viewer, content_search, file_carving,
    report_export (HTML), hash_sets, plugins
  UI elements:
    License status dot in toolbar (green/yellow/red)
    Machine ID display + copy in Settings
    .vlic file loader with live refresh

### Test keypair (COMPROMISED — DO NOT USE IN PRODUCTION)
  Private: 7UrIZFjXRZqXPj8wM3DZMNFTjD7J5kdqsoJPFMEs6cc=
  Public:  +WTWXfbkl/xoK8Uv3dtzpG85d4SFitBB1JMxp7IxQ+E=
  STATUS:  TEST ONLY — visible in chat/Codex session
           Generate NEW keypair on Mac setup day
           Store private key: ~/Wolfmark/keys/ + USB only
           Embed new public key in strata-license crate
           Rebuild for production

### First trial license
  File:       tools/wolfmark-license-gen/test/wolfmark_internal_test.vlic
  Licensee:   Korbyn Randolph / Wolfmark Systems
  Tier:       Trial (60 days)
  Machine ID: placeholder (test only)
  Status:     VALID

### Binary sizes
  strata-tree.exe:          23.28 MB (24,403,456 bytes)
  wolfmark-license-gen.exe:  1.03 MB ( 1,082,880 bytes)
  
### Test suite
  strata-tree:    33/33 ✅
  strata-license:  8/8 ✅
  Total:          41/41 ✅
  Build time:     40.46 seconds

### Production key generation (Mac setup day):
  1. wolfmark-license-gen generate-keypair
  2. Save private key to ~/Wolfmark/keys/wolfmark-private.key
  3. Copy to USB drive (physical backup)
  4. Embed public key in crates/strata-license/src/validator.rs
  5. cargo build --release (production build)
  6. This becomes the real Wolfmark Systems signing key
  7. NEVER commit, email, or cloud-store private key

## TREE v0.3.0 ADDITIONS (2026-03-29)

### GitHub README
  File:     D:\Strata\apps\tree\README.md
  Lines:    68
  Status:   Public-ready
  Content:  What it does, platform support, download,
            quick start, free vs pro, built with,
            background, contributing, license

### CLI Mode — strata-tree.exe
  Implementation: main.rs + cli.rs + preview_panel.rs
  Commands:
    --help           PASS — exit 0
    fingerprint      PASS — prints machine ID (free tier)
    info <file>      PASS — files, deleted, size, volumes
    hash <file>      PASS — hashes all, writes CSV
    carve <file>     PASS — license gated (Pro required)
    report <file>    PASS — license gated (Pro required)
    search <file>    PASS — license gated (Pro required)
  License gates: enforced — exit 1 on free tier for
                 carve, report, search
  Exit codes: 0 success, 1 error/unlicensed

### Code Quality
  Before: 31 clippy errors in strata-tree
  After:  0 warnings in strata-tree
  Files cleaned: 21 source files
  Full workspace clippy (excluding forge/shield): PASS
  Forge clippy: not touched (Opus owns)

### Binary Sizes
  strata-tree.exe:          23.78 MB (24,937,472 bytes)
  wolfmark-license-gen.exe:  1.03 MB ( 1,082,880 bytes)

### Test Suite
  strata-tree:    33/33 ✅
  strata-license:  8/8  ✅
  Total:          41/41 ✅

### Desktop Agent Integration
  CLI enables Desktop Evidence Processor agent:
  strata-tree info <file>   → quick stats
  strata-tree hash <file>   → overnight batch hashing
  strata-tree carve <file>  → automated carving (Pro)
  strata-tree report <file> → automated reports (Pro)
  All scriptable via cron or agent orchestration

## OPENCLAW + NEMOCLAW — LOCKED (2026-03-29)

### OpenClaw
  What:     Open-source agent orchestration gateway
  Install:  ollama launch openclaw
  Features: Slack/Discord integration native
            Multi-agent orchestration
            Routes between Claude + Phi-4 fleet
            localhost:18789 dashboard
            Node.js 22.16+ required

### NemoClaw
  What:     NVIDIA enterprise security add-on
            Released: March 16 2026
            Mandatory for Wolfmark Systems
  Why:      OpenShell sandboxing
            Agents run in isolated containers
            Cannot access evidence data or keys
            CJIS-adjacent security posture
  Install:  openclaw install nemoclaw

### Agent Routing
  Claude Pro:    Overlord — orchestration + judgment
  Phi-4 14B:     Lead Dev + Security Researcher
  Phi-4 Mini:    Social + Business Ops + Legal
  OpenClaw:      Gateway + routing + lifecycle
  NemoClaw:      Security sandbox (always active)
  Slack:         #agent-escalations + notifications

### Setup Order on Mac Day
  1. Node.js 22.16+
  2. ollama (already planned)
  3. OpenClaw via ollama launch openclaw
  4. NemoClaw via openclaw install nemoclaw
  5. Configure ~/Wolfmark/openclaw-config.yaml
  6. Connect Slack workspace
  7. Load agent soul documents
  8. Test with simple task
  9. Fleet operational
