// plugin/loader.rs — Dynamic plugin loader for Strata.
// Phase 3, Task 3.3.
//
// Loads shared libraries (.dll / .so / .dylib) that implement the TreePlugin
// trait from the strata-tree-sdk crate.  Each plugin exports exactly one
// C-ABI function: `strata_tree_plugin_entry`.
//
// Safety: libloading manages the library lifetime.  The Library must outlive
// the loaded plugin pointer — `LoadedPlugin` keeps both together.

use anyhow::{Context, Result};
use libloading::{Library, Symbol};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

// ─── Types mirrored from strata-tree-sdk (avoid SDK dependency in the host) ─

/// Plugin info returned by the SDK's `describe()` method.
/// We keep a copy as plain Rust strings.
#[derive(Debug, Clone)]
pub struct PluginMeta {
    pub name: String,
    pub description: String,
    pub version: String,
    pub author: String,
    pub category: String,
    pub path: PathBuf,
}

/// Result of a plugin `run()` call.
#[derive(Debug)]
pub struct PluginRunResult {
    pub success: bool,
    pub message: String,
    pub output_path: Option<String>,
}

/// A loaded plugin — keeps the Library alive alongside its raw plugin pointer.
pub struct LoadedPlugin {
    pub meta: PluginMeta,
    #[allow(dead_code)]
    lib: Library,
    // Raw function pointer to `run` is stored per-call rather than cached,
    // because the plugin object is opaque from the host side.
    // We call through the FFI each time.
    entry_fn: unsafe extern "C" fn() -> *mut std::ffi::c_void,
}

// SAFETY: LoadedPlugin is only used on the main thread.
unsafe impl Send for LoadedPlugin {}

impl LoadedPlugin {
    /// Invoke the plugin entrypoint in a guarded thread.
    ///
    /// This validates that:
    /// 1) the plugin call does not panic
    /// 2) the plugin returns a non-null pointer
    /// 3) the call returns before `timeout`
    pub fn invoke_with_timeout(&self, timeout: Duration) -> PluginRunResult {
        let (tx, rx) = mpsc::channel::<PluginRunResult>();
        let entry_fn = self.entry_fn;
        let plugin_name = self.meta.name.clone();

        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(move || {
                // SAFETY: symbol was resolved from loaded plugin at load time.
                let raw = unsafe { entry_fn() };
                if raw.is_null() {
                    PluginRunResult {
                        success: false,
                        message: format!("Plugin '{}' returned null pointer", plugin_name),
                        output_path: None,
                    }
                } else {
                    PluginRunResult {
                        success: true,
                        message: format!(
                            "Plugin '{}' invoked safely (entrypoint reachable)",
                            plugin_name
                        ),
                        output_path: None,
                    }
                }
            });

            let payload = match result {
                Ok(v) => v,
                Err(_) => PluginRunResult {
                    success: false,
                    message: format!("Plugin '{}' panicked during invocation", plugin_name),
                    output_path: None,
                },
            };
            let _ = tx.send(payload);
        });

        match rx.recv_timeout(timeout) {
            Ok(res) => res,
            Err(_) => PluginRunResult {
                success: false,
                message: format!(
                    "Plugin '{}' invocation exceeded {:?}",
                    self.meta.name, timeout
                ),
                output_path: None,
            },
        }
    }
}

/// Manager that owns all loaded plugins.
#[derive(Default)]
pub struct PluginManager {
    pub plugins: Vec<LoadedPlugin>,
    pub search_paths: Vec<PathBuf>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a directory to scan for plugins.
    pub fn add_search_path(&mut self, path: impl AsRef<Path>) {
        self.search_paths.push(path.as_ref().to_path_buf());
    }

    /// Scan all registered search paths and load plugins found there.
    /// Returns the number of newly loaded plugins.
    pub fn scan_and_load(&mut self) -> usize {
        let paths: Vec<_> = self.search_paths.clone();
        let mut loaded = 0;
        for dir in paths {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if is_plugin_file(&path) {
                        match self.load_plugin(&path) {
                            Ok(_) => loaded += 1,
                            Err(e) => {
                                tracing::warn!("Failed to load plugin {:?}: {}", path, e);
                            }
                        }
                    }
                }
            }
        }
        loaded
    }

    /// Load a single plugin from a .dll/.so/.dylib path.
    pub fn load_plugin(&mut self, path: &Path) -> Result<()> {
        // Safety: we use libloading with explicit lifetime management.
        let lib = unsafe {
            Library::new(path)
                .with_context(|| format!("Cannot open library: {}", path.display()))?
        };

        // Locate the entry symbol.
        let entry_fn: Symbol<unsafe extern "C" fn() -> *mut std::ffi::c_void> = unsafe {
            lib.get(b"strata_tree_plugin_entry\0")
                .context("Symbol 'strata_tree_plugin_entry' not found — not a Strata plugin")?
        };

        // Call entry to obtain a raw plugin pointer, then call describe().
        // We treat the pointer as opaque here — the SDK handles the vtable.
        let entry_fn_copy = *entry_fn;
        let raw = unsafe { entry_fn_copy() };
        if raw.is_null() {
            anyhow::bail!("Plugin entry returned null pointer");
        }

        // Build minimal meta without calling describe() directly
        // (avoids needing to link against strata-tree-sdk in the host).
        // Production plugins should expose describe_json() for richer metadata.
        let meta = PluginMeta {
            name: path.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            description: "(loaded via C ABI)".to_string(),
            version: "?".to_string(),
            author: "?".to_string(),
            category: "Utility".to_string(),
            path: path.to_path_buf(),
        };

        self.plugins.push(LoadedPlugin {
            meta,
            lib,
            entry_fn: entry_fn_copy,
        });

        tracing::info!("Loaded plugin: {}", path.display());
        Ok(())
    }

    /// Unload all plugins (drop libraries).
    pub fn unload_all(&mut self) {
        self.plugins.clear();
    }
}

fn is_plugin_file(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    matches!(ext.as_str(), "dll" | "so" | "dylib")
}
