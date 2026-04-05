# 🛠️ FORGE ECOSYSTEM: MASTER MISSION CONTROL

This document outlines the strategic roadmap for **Strata Forge** to begin autonomous construction, validation, and expansion of the Strata Forensic Ecosystem. Each task must be followed by an **External Audit & Validation** step before being marked as complete.

---

## 🏗️ PHASE 1: CORE INFRASTRUCTURE STABILIZATION (CURRENT)
*Primary Goal: Achieve 100% stable compilation and unified workspace parity.*

- [ ] **[TASK-1.1] Finalize `strata-fs` Base Layer**
    - [ ] Move any remaining low-level trait definitions from `strata-core` to `strata-fs`.
    - [ ] Verify `strata-fs` compiles independently without any workspace dependencies.
    - [ ] **EXTERNAL AUDIT**: Review dependency graph for circular references.
    
- [ ] **[TASK-1.2] Unified Error & Result Propogation**
    - [ ] Audit all modules to ensure they use the standardized `ForensicError` from `strata-fs`.
    - [ ] Implement `From<anyhow::Error>` for `ForensicError` where needed for CLI compatibility.
    - [ ] **EXTERNAL AUDIT**: Manually verify error mapping in `virtualization/mod.rs`.

- [ ] **[TASK-1.3] Strata Forge Desktop Launch**
    - [ ] Successfully execute `npm run tauri dev` without backend panics.
    - [ ] Verify KB Bridge and Ollama connectivity status indicators in UI.
    - [ ] **EXTERNAL AUDIT**: UI/UX smoke test on Windows 11.

---

## 🔌 PHASE 2: PLUGIN ARCHITECTURE & SDK (THE "PLUG-IN" HARMONY)
*Primary Goal: Enable Forge to build hot-reloadable modules.*

- [ ] **[TASK-2.1] Scaffolding `strata-plugin-sdk`**
    - [ ] Implement the `ForensicPlugin` trait with support for `init`, `metadata`, and `execute`.
    - [ ] Add `abi_stable` or similar version-checking mechanism to prevent crash-on-load.
    - [ ] **EXTERNAL AUDIT**: Review Plugin ABI for memory safety across boundaries.

- [ ] **[TASK-2.2] The "Trace" Reference Plugin**
    - [ ] Scaffold `plugins/strata-plugin-trace` using the SDK.
    - [ ] Port USN Journal parsing logic from `strata-core` into the Trace plugin.
    - [ ] **EXTERNAL AUDIT**: Verify USN record parsing parity vs. internal engine.

- [ ] **[TASK-2.3] Dynamic Plugin Loader System**
    - [ ] Implement a hot-reloading directory watcher for the `plugins/` folder in `strata-core`.
    - [ ] Build a Plugin Registry capable of exposing plugin-provided tools to the AI.
    - [ ] **EXTERNAL AUDIT**: Load/Unload stability test (Stress test 100 cycles).

---

## 🔍 PHASE 3: ARTIFACT & EVIDENCE MODELING
*Primary Goal: Standardize how Strata "sees" digital evidence.*

- [ ] **[TASK-3.1] Unified Artifact Schema (UAS)**
    - [ ] Define the `Artifact` struct with fields for `source_path`, `category`, `timestamp_map`, and `raw_payload`.
    - [ ] Implement JSON-LD export support for external laboratory tools (Cellebrite/Magnet parity).
    - [ ] **EXTERNAL AUDIT**: Schema compatibility check with CASE/UCO standards.

- [ ] **[TASK-3.2] The Knowledge Bridge (KB) Enhancement**
    - [ ] Create a local vector store for artifact "fingerprinting" (using the KB Bridge).
    - [ ] Implement "Contextual Threading" where the AI can relate different artifacts (e.g., LNK file to a ZIP).
    - [ ] **EXTERNAL AUDIT**: Review vector search accuracy for cross-file correlation.

---

## 🤖 PHASE 4: AGENTIC CAPABILITIES (THE "INNER MONOLOGUE")
*Primary Goal: Let Forge think aloud and solve complex forensic puzzles.*

- [ ] **[TASK-4.1] Tool-Call Logging Protocol**
    - [ ] Integrate real-time backend logging that feeds the UI's "Agent Monologue" drawer.
    - [ ] Implement "Step-Back Planning" where Forge pauses to verify findings before proceeding.
    - [ ] **EXTERNAL AUDIT**: Verify log privacy (No Sensitive Data Leakage).

- [ ] **[TASK-4.2] Forensic "Playbooks"**
    - [ ] Create a library of reusable forensic scripts (YAML/JSON) that Forge can execute for specific cases (e.g., "Malware Persistence Check").
    - [ ] Enable "Multi-Agent Hand-off" between the UI and the Shield CLI.
    - [ ] **EXTERNAL AUDIT**: Execute "Trial by Fire" - Run persistence check on a test VM.

---

## 🧪 PHASE 5: ECOSYSTEM EXPANSION (BEYOND WINDOWS)
*Primary Goal: Cross-platform dominance.*

- [ ] **[TASK-5.1] Linux/XFS Advanced Parsing**
    - [ ] Complete the `xfs_advanced` module to support XFS reflink and deduplication.
    - [ ] Add support for LVM/LUKS layer extraction in plugins.
    - [ ] **EXTERNAL AUDIT**: Verify decryption of a LUKS test volume.

- [ ] **[TASK-5.2] Android/iOS Artifact Plugins**
    - [ ] Implement the `strata-plugin-chronicle` for SQLite-based mobile databases.
    - [ ] Port Samsung Health/Rubidium parsers into modular plugins.
    - [ ] **EXTERNAL AUDIT**: Parse a real (anonymized) Android image snapshot.

---

> [!IMPORTANT]
> **MANDATORY**: No task is "DONE" until an **External Audit** has been performed and documented in the `Audits/` directory. Forge is authorized to suggest fixes for audit findings but cannot override them without USER approval.
