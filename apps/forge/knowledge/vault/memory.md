# STRATA CHAT: THE MEMORY (CORE FIXES & LESSONS)

This document contains the collective memory of the Strata Suite's evolution, logging critical errors encountered and the confirmed solutions to prevent recurrence.

---

## 🛡️ CRITICAL SYSTEM FIXES

### 1. **CORS Connection Failure ("Failed to fetch")**
-   **Error**: Desktop frontend could not connect to KB Bridge or Llama server due to browser security (CORS preflight).
-   **Memory**: Standard HTTP servers need a `do_OPTIONS` handler.
-   **Solution**: Implemented full CORS support in `dfir_kb_bridge.py` with `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Headers: *`, and a `200 OK` response for OPTIONS requests. 

### 2. **Llama Startup Crash (Illegal Flags)**
-   **Error**: `llama-server.exe` failed to start with "invalid argument: --allow-origins".
-   **Memory**: The specific version of `llama.bin` (v4676) does not support the `--allow-origins` flag.
-   **Solution**: Removed the flag from `start_dfir_coding_ai.bat`. Connectivity is now handled entirely through the KB Bridge's CORS logic.

### 3. **GPU Binary Incompatibility (Missing DLLs)**
-   **Error**: Python scripts failed to launch Llama server because of missing CUDA runtime libraries on the host machine.
-   **Memory**: GPU-only binaries are not portable if NVIDIA drivers/tools are missing.
-   **Solution**: Swapped GPU binaries for **Portable CPU (AVX2)** binaries. This ensures the suite runs on any machine instantly.

---

## 🎨 VISUAL IDENTITY & BRANDING
-   **Branding**: Renamed suite to **Strata Chat**. Updated `tauri.conf.json`, `index.html`, and `heart.md`.
-   **Splash Screen**: Implemented a **full-screen splash screen overlay** in CSS/JS.
    -   *Logic*: Logo is `object-fit: cover` with an off-white background (`#fdfdfd`) to match the JPG profile.
-   **Rebuild Requirement**: Remember that source changes to `index.html` or `tauri.conf.json` require an `npm run tauri build` to update the production executable.

---

## 🛠️ SUITE ARCHITECTURE
-   **Root Detection**: The suite uses the **`DFIR_ROOT`** environment variable or dynamically detects its location for 100% portability.
-   **Watchdog**: A background Rust monitor ensures services are restarted automatically upon crash.

**THIS MEMORY IS STRATA'S SHIELD. LEARN FROM THE PAST TO PROTECT THE FUTURE.**
