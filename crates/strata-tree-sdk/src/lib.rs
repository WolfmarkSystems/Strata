// strata-tree-sdk/src/lib.rs
//
// Strata Tree Plugin SDK — Stable C-ABI interface.
//
// STABILITY GUARANTEE
// ───────────────────
// All types and exported symbols in this file are SEMVER-stable.
// The ABI is C-compatible so plugins compiled against any minor version of the
// SDK can be loaded at runtime without recompilation.
//
// PLUGIN CONTRACT
// ───────────────
// A plugin is a shared library (.dll / .so / .dylib) that exports exactly one
// symbol:
//
//     #[no_mangle]
//     pub extern "C" fn strata_tree_plugin_entry() -> *mut StrataTreePlugin
//
// The returned pointer must remain valid for the lifetime of the plugin.
// Strata Tree calls `plugin.describe()` once, then calls `plugin.run()` each
// time the user activates the plugin from the Plugins menu.
//
// MEMORY SAFETY
// ─────────────
// All strings crossing the ABI boundary use null-terminated C strings.
// The SDK provides `PluginStr` — a thin wrapper with a safe `as_str()`.
// Plugins MUST NOT free memory allocated by the host, and vice-versa.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// ─── String helper ───────────────────────────────────────────────────────────

/// A null-terminated C string owned by the plugin.
/// Valid for as long as the plugin is loaded.
#[repr(C)]
pub struct PluginStr {
    ptr: *const c_char,
}

impl PluginStr {
    /// Create a `PluginStr` from a Rust string literal.
    /// The returned value leaks the allocation intentionally (plugin lifetime).
    pub fn from_static(s: &'static str) -> Self {
        let c = CString::new(s).unwrap_or_else(|_| CString::new("invalid").unwrap());
        Self {
            ptr: CString::into_raw(c),
        }
    }

    /// Borrow the string as a Rust `&str`.
    pub fn as_str(&self) -> &str {
        if self.ptr.is_null() {
            return "";
        }
        unsafe { CStr::from_ptr(self.ptr) }.to_str().unwrap_or("")
    }
}

// ─── Plugin metadata ─────────────────────────────────────────────────────────

/// Metadata describing a plugin.  Returned by `TreePlugin::describe()`.
#[repr(C)]
pub struct PluginInfo {
    /// Short display name shown in the Plugins menu.
    pub name: PluginStr,
    /// One-line description shown in the Plugins panel.
    pub description: PluginStr,
    /// Semantic version string, e.g. "1.0.0".
    pub version: PluginStr,
    /// Plugin author or organisation.
    pub author: PluginStr,
    /// Plugin category — used to group in the menu.
    /// Values: "Analysis" | "Export" | "Import" | "Utility"
    pub category: PluginStr,
}

// ─── Context passed to plugin.run() ─────────────────────────────────────────

/// A file entry passed to the plugin.  All strings are UTF-8, null-terminated.
#[repr(C)]
pub struct PluginFileEntry {
    pub id: *const c_char,
    pub path: *const c_char,
    pub name: *const c_char,
    pub extension: *const c_char,
    pub size_bytes: i64,
    pub is_deleted: u8,
    pub md5: *const c_char,
    pub sha256: *const c_char,
    pub modified_utc: *const c_char,
    pub category: *const c_char,
}

/// Context object passed to `TreePlugin::run()`.
/// The host retains ownership of all pointed-to memory.
#[repr(C)]
pub struct PluginContext {
    /// Case name (UTF-8, null-terminated, host-owned).
    pub case_name: *const c_char,
    /// Examiner name.
    pub examiner: *const c_char,
    /// Currently selected files (may be NULL if count == 0).
    pub selected_files: *const PluginFileEntry,
    pub selected_count: usize,
    /// All indexed files (may be NULL if count == 0).
    pub all_files: *const PluginFileEntry,
    pub all_count: usize,
    /// Scratch directory plugins may use for temporary output.
    pub scratch_dir: *const c_char,
    /// Callback: log a message to the examiner audit log.
    /// `level`: 0=info, 1=warn, 2=error
    pub log_fn: Option<unsafe extern "C" fn(level: u8, msg: *const c_char)>,
    /// Callback: write a result file to the case output directory.
    /// Returns 0 on success.
    pub write_result_fn:
        Option<unsafe extern "C" fn(filename: *const c_char, data: *const u8, len: usize) -> i32>,
}

// ─── Plugin result ────────────────────────────────────────────────────────────

/// Result returned by `TreePlugin::run()`.
#[repr(C)]
pub struct PluginResult {
    /// 0 = success, non-zero = error.
    pub status: i32,
    /// Human-readable summary (null-terminated, plugin-owned).
    pub message: *const c_char,
    /// Optional path to a generated output file (null = no output file).
    pub output_path: *const c_char,
}

impl PluginResult {
    pub fn ok(message: &'static str) -> Self {
        Self {
            status: 0,
            message: CString::new(message)
                .map(|s| s.into_raw() as *const c_char)
                .unwrap_or(std::ptr::null()),
            output_path: std::ptr::null(),
        }
    }

    pub fn err(message: &'static str) -> Self {
        Self {
            status: -1,
            message: CString::new(message)
                .map(|s| s.into_raw() as *const c_char)
                .unwrap_or(std::ptr::null()),
            output_path: std::ptr::null(),
        }
    }
}

// ─── Plugin trait (Rust-side) ─────────────────────────────────────────────────

/// Implement this trait and export `strata_tree_plugin_entry()` to create a plugin.
///
/// ```rust
/// use strata_tree_sdk::*;
///
/// struct MyPlugin;
///
/// impl TreePlugin for MyPlugin {
///     fn describe(&self) -> PluginInfo {
///         PluginInfo {
///             name:        PluginStr::from_static("My Plugin"),
///             description: PluginStr::from_static("Does something useful"),
///             version:     PluginStr::from_static("1.0.0"),
///             author:      PluginStr::from_static("ACME Corp"),
///             category:    PluginStr::from_static("Analysis"),
///         }
///     }
///
///     fn run(&mut self, ctx: &PluginContext) -> PluginResult {
///         PluginResult::ok("Completed successfully")
///     }
/// }
///
/// #[no_mangle]
/// pub extern "C" fn strata_tree_plugin_entry() -> *mut dyn TreePlugin {
///     Box::into_raw(Box::new(MyPlugin))
/// }
/// ```
pub trait TreePlugin: Send {
    fn describe(&self) -> PluginInfo;
    fn run(&mut self, ctx: &PluginContext) -> PluginResult;
}

// ─── Host-side loader (used inside strata-tree, not exported to plugins) ─────

/// Symbol name exported by every Strata Tree plugin.
pub const PLUGIN_ENTRY_SYMBOL: &[u8] = b"strata_tree_plugin_entry\0";

/// Type of the plugin entry function.
#[allow(improper_ctypes_definitions)]
pub type PluginEntryFn = unsafe extern "C" fn() -> *mut dyn TreePlugin;
