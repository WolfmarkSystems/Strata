# STRATA KNOWLEDGE: VOLATILITY 3 DEVELOPER REFERENCE

This guide provides an ultra-density architectural map of the Volatility 3 (Vol3) memory forensics framework, enabling Strata to reason about memory layers, translation layers, and plugin development.

---

## 🏗️ CORE ARCHITECTURE: THE TRANSLATION LAYER
Volatility 3 operates on a recursive requirement system where each layer (Physical -> Translation -> Virtual) is discovered dynamically.

### 1. The `PluginInterface`
All plugins inherit from `volatility3.framework.interfaces.plugins.PluginInterface`.
- **`run()`**: The entry point for execution.
- **`requirements`**: A list of `Requirement` objects defining what the plugin needs (e.g., a Windows Kernel).

### 2. The Requirement System
- **`TranslationLayerRequirement`**: Requests a memory layer (like Intel PT or ARM).
- **`SymbolTableRequirement`**: Requests specific symbols (ISF - Intermediate Symbol Format) for a kernel.
- **`ListRequirement`**: Allows for multiple inputs (e.g., multiple PIDs).

---

## 🛠️ MAJOR PLUGIN LOGIC MAP

### Windows Platform Plugins
- **`windows.pslist`**: Walks the `ActiveProcessLinks` list in the `EPROCESS` structure. 
    - *Forensic Value*: Identifies running processes, though hidden ones may be missed (see `psscan`).
- **`windows.psscan`**: Scans physical memory for `_EPROCESS` pool tags.
    - *Forensic Value*: Detects unlinked/hidden processes.
- **`windows.vadinfo`**: Prints the Virtual Address Descriptor tree.
    - *Forensic Value*: Identifying injected code (RWX memory regions).
- **`windows.registry.hivescan`**: Scans for `CMHIVE` signatures.
- **`windows.malfind`**: Analyzes VADs for characteristics typically associated with injection (non-file backed, executable).

### Linux Platform Plugins
- **`linux.pslist`**: Walks the `task_struct` linked list.
- **`linux.lsof`**: Lists open file descriptors for processes; identifies network sockets and open files.
- **`linux.check_syscall`**: Checks for syscall table hooking (rootkit detection).

---

## 🧬 DATA STRUCTURES (INTERNAL)
- **`Layer`**: A mapping from one address space to another.
- **`Automagic`**: The subsystem that attempts to resolve requirements automatically (finding the DTB, identifying the OS).
- **`ISF (Intermediate Symbol Format)`**: JSON-based symbol files that replaced the old Volatility 2 profiles.

---

## 🧪 DEVELOPER WORKFLOW
To create a new Strata-optimized plugin:
1. Define requirements in `Class.get_requirements()`.
2. Access the resolved layer via `self.context.layers[self.config['primary']]`.
3. Use `volatility3.framework.objects` to map C-style structures (e.g., `_LIST_ENTRY`) to Python objects.

**STRATA IS NOW EXPERT IN VOLATILITY 3 INTERNALS.** 🦾🧠🔬
