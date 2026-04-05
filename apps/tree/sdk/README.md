# Strata Tree Plugin SDK

Plugins extend Strata Tree with custom analysis capabilities without requiring
access to the core codebase. A plugin is a native shared library
(`.dll` on Windows, `.so` on Linux, `.dylib` on macOS) that exports a single
C-ABI entry point.

---

## 1. The Plugin Trait

Every plugin must implement the `TreePlugin` trait from the `strata-tree-sdk`
crate. The host loads the library and calls the entry function to obtain a
plugin instance.

```rust
// From crates/strata-tree-sdk/src/lib.rs

/// Metadata describing this plugin.
pub struct PluginMeta {
    pub name:        &'static str,
    pub description: &'static str,
    pub version:     &'static str,
    pub author:      &'static str,
    pub category:    &'static str,
}

/// Context passed to every plugin invocation.
pub struct PluginContext<'a> {
    /// Read-only access to the evidence source path.
    pub evidence_path: &'a std::path::Path,
    /// All files currently in the case index.
    pub file_index: &'a [FileEntry],
    /// Output directory where the plugin can write artifacts.
    pub output_dir: &'a std::path::Path,
    /// Case name for labelling outputs.
    pub case_name: &'a str,
    /// Examiner name for audit attribution.
    pub examiner: &'a str,
}

/// Every plugin implements this trait.
pub trait TreePlugin: Send + Sync {
    fn describe(&self) -> PluginMeta;
    fn run(&self, ctx: &PluginContext<'_>) -> PluginResult;
}

/// Result returned by plugin.run().
pub struct PluginResult {
    pub success: bool,
    pub message: String,
    /// Optional path to an output file the host should display.
    pub output_path: Option<std::path::PathBuf>,
    /// Artifact entries to add to the case file index.
    pub artifacts: Vec<ArtifactEntry>,
}
```

The host calls one C-ABI function:

```rust
/// Mandatory C-ABI entry point — the ONLY symbol the host looks for.
#[no_mangle]
pub extern "C" fn strata_tree_plugin_entry() -> *mut dyn TreePlugin {
    Box::into_raw(Box::new(MyPlugin))
}
```

---

## 2. Manifest Format

Alongside the plugin binary, ship a `<plugin_name>.manifest.json`:

```json
{
  "name":        "my-plugin",
  "version":     "1.0.0",
  "description": "Brief one-line description shown in the plugin panel",
  "author":      "Your Name <email@example.com>",
  "category":    "Utility",
  "min_host":    "0.1.0",
  "sdk_version": "0.1.0"
}
```

The host reads this file to populate the plugin panel before loading the library.

---

## 3. Building a Plugin

### Step 1 — Create a new crate

```bash
cargo new --lib my-strata-plugin
cd my-strata-plugin
```

### Step 2 — Configure Cargo.toml

```toml
[package]
name    = "my-strata-plugin"
version = "1.0.0"
edition = "2021"

[lib]
# Required: produce a C-ABI shared library.
crate-type = ["cdylib"]

[dependencies]
strata-tree-sdk = { path = "path/to/crates/strata-tree-sdk" }
```

### Step 3 — Implement the plugin

See the full example in Section 5.

### Step 4 — Build

```bash
# Debug build
cargo build

# Release build (smaller, faster — use for distribution)
cargo build --release

# Output:
#   Windows: target/release/my_strata_plugin.dll
#   Linux:   target/release/libmy_strata_plugin.so
#   macOS:   target/release/libmy_strata_plugin.dylib
```

### Step 5 — Load in Strata Tree

1. Open Strata Tree.
2. Switch to the **Plugins** tab.
3. Click **Load Plugin…** and select your `.dll` / `.so` / `.dylib`.
4. The plugin appears in the plugin list with status **Ready**.
5. Click **Invoke** to run it against the loaded evidence.

---

## 4. Example Plugin — List All Executables

The following complete plugin lists every `.exe` file in the evidence index
and writes a summary CSV to the output directory.

```rust
// src/lib.rs

use strata_tree_sdk::{
    ArtifactEntry, FileEntry, PluginContext, PluginMeta, PluginResult, TreePlugin,
};

pub struct ExeListPlugin;

impl TreePlugin for ExeListPlugin {
    fn describe(&self) -> PluginMeta {
        PluginMeta {
            name:        "exe-lister",
            description: "Lists all .exe files in the evidence index",
            version:     "1.0.0",
            author:      "Example Author",
            category:    "Enumeration",
        }
    }

    fn run(&self, ctx: &PluginContext<'_>) -> PluginResult {
        // Find all .exe files — read-only, never write to evidence.
        let exes: Vec<&FileEntry> = ctx
            .file_index
            .iter()
            .filter(|f| {
                f.extension
                    .as_deref()
                    .map(|e| e.eq_ignore_ascii_case("exe"))
                    .unwrap_or(false)
            })
            .collect();

        // Build a CSV report.
        let mut csv = String::from("path,size,sha256\n");
        for f in &exes {
            csv.push_str(&format!(
                "{},{},{}\n",
                f.path,
                f.size.unwrap_or(0),
                f.sha256.as_deref().unwrap_or(""),
            ));
        }

        // Write output — only to the designated output_dir, never to evidence.
        let out_path = ctx.output_dir.join("executables.csv");
        if std::fs::write(&out_path, &csv).is_err() {
            return PluginResult {
                success: false,
                message: "Failed to write output CSV".to_string(),
                output_path: None,
                artifacts: Vec::new(),
            };
        }

        PluginResult {
            success: true,
            message: format!("Found {} executables. Report: {}", exes.len(), out_path.display()),
            output_path: Some(out_path),
            artifacts: Vec::new(),
        }
    }
}

/// C-ABI entry point — mandatory, exact name.
#[no_mangle]
pub extern "C" fn strata_tree_plugin_entry() -> *mut dyn TreePlugin {
    Box::into_raw(Box::new(ExeListPlugin))
}
```

---

## 5. Plugin Safety Rules

Plugins are sandboxed by convention. The following rules are enforced:

| Rule | Rationale |
|------|-----------|
| **Plugins are read-only** | Plugins receive file paths and byte slices. They must not write to evidence containers or modify the case SQLite database. |
| **Never `unwrap()` or `panic!()`** | A panicking plugin crashes the host process. Use `Result` and return `PluginResult { success: false, … }` on error. |
| **Complete within 300 seconds** | The host sets a 300-second timer. Plugins exceeding this are terminated. Long operations must report incremental progress. |
| **All invocations are audited** | Every call to `plugin.run()` is recorded in the case activity log with the plugin name, evidence path, and result. Plugins cannot suppress this. |
| **No network access** | Plugins must not open outbound network connections. Forensic evidence must not leave the examination system. |
| **No spawning processes** | Plugins must not call `std::process::Command` or similar. All processing must happen within the plugin's own code. |

---

## 6. Distributing Plugins

To share a plugin between examiners:

1. Build with `cargo build --release`.
2. Copy the shared library + `.manifest.json` to a shared directory.
3. Examiners click **Load Plugin…** and select the `.dll`/`.so`/`.dylib`.

For official agency plugins, sign the binary with your code-signing certificate
before distribution. Strata Tree does not enforce signature verification by
default, but the audit trail records the plugin path and a SHA-256 of the
library at load time.

> **Chain of custody note:** Every plugin invocation is written to the case
> activity log (`activity_log` table in the `.vtp` file) and appears in the
> HTML court report under the Appendix section. Examiners must be prepared to
> explain any plugin used during an examination.
