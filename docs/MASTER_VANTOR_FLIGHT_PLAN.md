# 🚀 STRATA FORENSIC ECOSYSTEM: THE 4-MONTH FLIGHT PLAN

This document outlines the strategic implementation of the **Strata Forensic Suite**. The vision is to transform a monolithic forensic tool into a high-performance, modular, plugin-first ecosystem.

---

## 🏆 CURRENT GLOBAL STATUS: [PHASE 1 - CORE MODULARIZATION]

- [x] Initial Workspace Structuring (`apps/`, `crates/`, `plugins/`)
- [x] Root Workspace Dependency Resolution (`rusqlite`, `blake3`, `tokio` alignment)
- [x] Shared Crate Implementation (`strata-core`, `strata-fs`, `strata-plugin-sdk`)
- [x] Production-Grade Hot-Reload Plugin Manager Implementation (Shield Engine)
- [ ] First Functional Plugin Integration (Index/Prefetch)

---

## 📅 MONTH 1: THE ARCHITECTURAL REBIRTH
**Goal:** Stabilize the core engine, finalize the SDK, and migrate 50% of legacy parsers.

### Phase 1.1: Shared Crate Stability
- [ ] Refactor all `apps/shield` engine modules to use `strata-core` for hashing/errors.
- [ ] Fully implement `strata-fs` by merging APFS/NTFS logic from `shield`.
- [ ] Add unit tests for `strata-plugin-sdk` contract validation.
- [ ] Implement `strata-artifacts` canonical schemas for all 10 base artifact types.

### Phase 1.2: The Hot-Reload Loop
- [ ] Finalize `PluginManager` in `strata-shield-engine`.
- [ ] Successfully load and reload the `strata-plugin-index` at runtime without locks.
- [ ] Implement UI indicators in Shield for "Plugin Reload Status".
- [ ] Create automated "Watch & Build" helper script for plugin development.

### Phase 1.3: Migration (The "Index" Plugin)
- [ ] Move `amcache` parser into `strata-plugin-index`.
- [ ] Move `prefetch` + `shimcache` parsers into `strata-plugin-index`.
- [ ] Move `registry` (persistence nodes) into `strata-plugin-index`.
- [ ] Move `browser` (Chrome/Firefox/Edge) into `strata-plugin-index`.

---

## 📅 MONTH 2: FEATURE EXPANSION & DOMAIN COVERAGE
**Goal:** Achieve full parity with industry-standard forensic tools across multiple OS domains.

### Phase 2.1: Domain Plugins
- [ ] **Cipher Plugin:** Implement Credential/Token extraction for Windows DPAPI and Apple Keychain.
- [ ] **Chronicle Plugin:** Implement unified timeline reconstruction logic.
- [ ] **Trace Plugin:** Implement deep-pattern searching (Regex/YARA) across disk images.
- [ ] **Remnant Plugin:** Implement high-speed file carving and recovery (Header/Footer logic).

### Phase 2.2: Mobile Forensics
- [ ] Port `ios` and `android` parsers from legacy Shield into `strata-plugin-index`.
- [ ] Implement support for `graykey` and `cellebrite` ingestion.
- [ ] Implement `whatsapp` and `discord` chat database decoders.

### Phase 2.3: Cross-Platform Support
- [ ] Finalize Linux `journald` and `bash_history` modules.
- [ ] Finalize macOS `unified_logs` and `spotlight` modules.
- [ ] Ensure `strata-fs` handles image formats like Raw, E01, and VHDX seamlessly.

---

## 📅 MONTH 3: UI/UX & ECOSYSTEM TOOLS
**Goal:** Launch the graphical companion tools and polish the user experience.

### Phase 3.1: Strata Tree (Visual Explorer)
- [ ] Integrate `strata-fs` into Tree for real-time file system browsing.
- [ ] Implement "Hex View" and "Property Inspector" for files.
- [ ] Sync Tree search with the `strata-plugin-trace` search engine.

### Phase 3.2: Strata Wraith (Live Imaging Engine)
- [ ] Implement Wraith as a standalone live forensic imaging engine (databases, memory dumps).
- [ ] Support SQL execution and visualization on internal evidence DBs.

### Phase 3.3: Aesthetics & Experience
- [ ] Full Strata Branding: Glassmorphism UI, Dark Mode, High-Density Layouts.
- [ ] Implement 3rd-pane detail views for artifacts (JSON views + Pretty-printing).
- [ ] Optimize rendering for 1M+ artifacts in the Shield UI.

---

## 📅 MONTH 4: AI FORGE & FINAL STABILITY
**Goal:** Empower Forge for autonomous plugin generation and final production hardening.

### Phase 4.1: Strata Forge Integration
- [ ] Connect `forge-memory` SQLite vault to Shield to store "Learned Artifact Patterns".
- [ ] Implement Forge CLI: `strata forge generate-plugin <pattern_spec>`.
- [ ] Allow Forge to auto-validate generated plugin code via internal test suites.

### Phase 4.2: Reporting & Case Management
- [ ] Move Case/Catalog logic into a standalone library.
- [ ] Implement exporting to PDF, HTML, and CSV.
- [ ] Implement "Evidence Integrity Reports" (Automatic MD5/SHA256 logging).

### Phase 4.3: Final Hardening
- [ ] Perform a full memory safety audit across all `unsafe` code in and plugins.
- [ ] Optimize multi-threaded parsing for 10x performance gains.
- [ ] Global release candidate: Strata 1.0 (The Shield of Justice).

---

## 🚦 MILESTONES & STATUS
- [ ] **M1: Modular Beta** (End of Month 1) -> Shield runs purely on plugins.
- [ ] **M2: Data Mastery** (End of Month 2) -> All major OS artifacts supported.
- [ ] **M3: Visual Suite** (End of Month 3) -> Shield/Tree/Wraith fully integrated.
- [ ] **M4: Production Ready** (End of Month 4) -> AI-powered plugin system live.

---

**Doctrine Note:** *Forensic integrity is non-negotiable. Every line of code must adhere to the "No-Touch" policy. Strata is not just a tool; it is a fortress.*
