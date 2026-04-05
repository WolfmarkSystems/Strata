// platform.rs — Platform-specific helpers.
// Abstracts OS differences for physical disk access, paths, etc.

/// Returns a human-readable platform identifier.
pub fn platform_name() -> &'static str {
    #[cfg(target_os = "windows")]
    return "Windows";
    #[cfg(target_os = "macos")]
    return "macOS";
    #[cfg(target_os = "linux")]
    return "Linux";
    #[allow(unreachable_code)]
    "Unknown"
}

/// Returns the default directory for case files on this platform.
pub fn default_case_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::path::PathBuf::from(r"C:\StrataCases")
    }
    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        std::path::PathBuf::from(home).join("StrataCases")
    }
}
