# 🏛️ STRATA FORENSIC ECOSYSTEM: MASTER VISION

## 🌟 THE VISION
**Strata** is designed to be the definitive, high-performance digital forensics ecosystem for the modern era. Moving away from monolithic "Swiss Army Knife" tools, Strata embraces a **modular, plugin-first architecture** built on Rust. 

The goal is simple: **Speed, Security, and Scalability.** 
Strata is engineered to handle massive datasets, support real-time hot-reloading of forensic logic, and integrate deeply with AI (Forge) for automated artifact discovery.

---

## 🛠️ THE STANDALONE CORE APPS
The ecosystem consists of several specialized tools that operate independently but share the Strata core DNA.

### 🛡️ 1. Strata Shield (The Orchestrator)
*   **Role:** Central command-and-control for forensic investigations.
*   **Mission:** Acts as a pure orchestration layer. It handles dynamic plugin loading, case management, and GUI/CLI dispatch. Shield itself does **not** contain parsing logic—it delegates all specialized analysis to the plugin layer.
*   **Key Feature:** Hot-reloadable engine. Add new parsers at runtime without restarting active analysis.

### 🌲 2. Strata Tree (The Visual Explorer)
*   **Role:** Real-time, ultra-fast file system and disk explorer.
*   **Mission:** Provides a "Google Maps" style experience for forensic images. It uses `strata-fs` to browse NTFS, APFS, and Linux filesystems instantly, with a focus on visual density and metadata inspection.

### 🔨 3. Strata Forge (The AI Developer)
*   **Role:** AI-driven development and knowledge hub.
*   **Mission:** An AI system that "learns" the Strata architecture to generate, test, and deploy new forensic plugins autonomously.
*   **AI Integration:** Uses local LLMs (Llama-3/Qwen) to draft Rust code for proprietary artifact parsers based on hex-dumps.

### 👻 4. Strata Wraith (Live Imaging Engine)
*   **Role:** Silent cross-platform live forensic imaging engine.
*   **Mission:** Focuses on sub-domain deep dives where Shield provides the overview. Wraith handles complex database analysis (e.g., massive SQLite parsing), log correlation, and internal data visualization.

### 💓 5. Strata Pulse (Real-Time Monitor)
*   **Role:** Live evidence and system monitor.
*   **Mission:** Focused on "Live Response" and monitoring of active system changes during incident response.

---

## 🧩 THE GLOBAL SHARED ENGINE (Strata Crates)
These are the foundational libraries that power every tool in the ecosystem.

*   📦 **strata-core:** Unified error handling, high-speed hashing (Blake3), and basic data types (Regions, ByteRanges).
*   📦 **strata-fs:** The world-class filesystem engine. Handles image detection, NTFS MFT walking, APFS container parsing, and disk layout mapping.
*   📦 **strata-artifacts:** The "Common Data Model." Ensures that every plugin, regardless of its author, produces artifacts that Shield can understand and render.
*   📦 **strata-acquire:** High-integrity disk and memory imaging library (E01, RAW, VHDX, etc.).
*   📦 **strata-insight:** Analysis and search engine. Powers complex regex searches across terabytes of data.
*   📦 **strata-plugin-sdk:** The "Contract." Defines the `StrataPlugin` trait that all dynamic libraries must implement to talk to Shield.

---

## 🔌 THE DYNAMIC PLUGIN LAYER
Shield gains its "superpowers" through these hot-swappable plugins.

### 📅 1. strata-plugin-index (Artifact Engine)
*   **Domain:** Core artifact extraction.
*   **Coverage:** Prefetch, Amcache, Registry, Browser History, Mobile (iOS/Android) Core artifacts.
*   **Migration Goal:** Extracts legacy parsing bloat into a clean, testable dylib.

### ⏳ 2. strata-plugin-chronicle (Timeline)
*   **Domain:** Temporal reconstruction.
*   **Coverage:** Building a 4D view of every event on a system.
*   **Innovation:** Uses `strata-artifacts` to merge disparate data into a single, high-fidelity timeline.

### 🔐 3. strata-plugin-cipher (Security & Auth)
*   **Domain:** Credentials and encryption.
*   **Coverage:** DPAPI, Keychain, stored browser passwords, cloud tokens, and authentication linkage.

### 🕵️ 4. strata-plugin-trace (Deep Search)
*   **Domain:** Discovery.
*   **Coverage:** Uses YARA-style patterns and advanced regex to find needles in the haystack of unallocated space.

### ♻️ 5. strata-plugin-remnant (Recovery)
*   **Domain:** Data Carving.
*   **Coverage:** Recovering deleted files from artifacts or raw disk slack using signature-based reconstruction.

---

## 🧬 SYSTEM MIGRATION & COHESION
Strata achieves its effectiveness through **Strict Decoupling** and **Standardized I/O**.

1.  **Ingestion:** `strata-acquire` grabs the image.
2.  **Structure:** `strata-fs` identifies the volumes and allows browsing in Strata Tree.
3.  **Extraction:** Shield detects the plugins folder, loads `strata-plugin-index`, and begins parsing artifacts into the `strata-artifacts` model.
4.  **Correlation:** `strata-plugin-chronicle` takes those artifacts and builds a master case map.
5.  **Intelligence:** Strata Forge suggests new plugins if an unknown data structure is encountered.

---
**Doctrine of Excellence:** *Strata is built to outpace the adversary. Every module is a brick in the wall of digital justice.*
