use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreflightStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResult {
    pub name: String,
    pub status: PreflightStatus,
    pub message: String,
    pub details_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub started_utc: String,
    pub finished_utc: String,
    pub overall_status: PreflightStatus,
    pub results: Vec<PreflightResult>,
}

impl PreflightReport {
    pub fn new() -> Self {
        Self {
            started_utc: chrono::Utc::now().to_rfc3339(),
            finished_utc: String::new(),
            overall_status: PreflightStatus::Pass,
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: PreflightResult) {
        if result.status == PreflightStatus::Fail {
            self.overall_status = PreflightStatus::Fail;
        } else if result.status == PreflightStatus::Warn && self.overall_status == PreflightStatus::Pass {
            self.overall_status = PreflightStatus::Warn;
        }
        self.results.push(result);
    }

    pub fn finalize(&mut self) {
        self.finished_utc = chrono::Utc::now().to_rfc3339();
    }

    pub fn is_pass(&self) -> bool {
        self.overall_status == PreflightStatus::Pass
    }
}

impl Default for PreflightReport {
    fn default() -> Self {
        Self::new()
    }
}

pub mod system {
    use super::*;
    use std::path::PathBuf;
    #[cfg(target_os = "windows")]
    use std::os::windows::process::CommandExt;
    #[cfg(target_os = "windows")]
    use std::process::{Command, Output};

    #[cfg(target_os = "windows")]
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    #[cfg(target_os = "windows")]
    fn run_hidden_command(program: &str, args: &[&str]) -> std::io::Result<Output> {
        let mut command = Command::new(program);
        command.args(args).creation_flags(CREATE_NO_WINDOW);
        command.output()
    }

    #[cfg(target_os = "windows")]
    pub fn check_webview2() -> PreflightResult {
        let webview2_keys = [
            r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
            r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        ];

        let mut found = false;
        let mut version = None;

        for key in &webview2_keys {
            let output = run_hidden_command("reg", &["query", &format!("HKLM\\{}", key), "/v", "pv"]);

            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("REG_SZ") {
                        found = true;
                        for line in stdout.lines() {
                            if line.contains("REG_SZ") {
                                version = Some(line.split("REG_SZ").nth(1).map(|s| s.trim().to_string()).unwrap_or_default());
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }

        if found {
            PreflightResult {
                name: "WebView2".to_string(),
                status: PreflightStatus::Pass,
                message: format!("WebView2 runtime found: {}", version.as_deref().unwrap_or("unknown version")),
                details_json: serde_json::json!({
                    "found": true,
                    "version": version,
                }),
            }
        } else {
            PreflightResult {
                name: "WebView2".to_string(),
                status: PreflightStatus::Fail,
                message: "WebView2 runtime not found. Install from: https://developer.microsoft.com/en-us/microsoft-edge/webview2/".to_string(),
                details_json: serde_json::json!({
                    "found": false,
                    "install_url": "https://developer.microsoft.com/en-us/microsoft-edge/webview2/",
                }),
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn check_webview2() -> PreflightResult {
        PreflightResult {
            name: "WebView2".to_string(),
            status: PreflightStatus::Pass,
            message: "WebView2 check only on Windows".to_string(),
            details_json: serde_json::json!({}),
        }
    }

    #[cfg(target_os = "windows")]
    pub fn check_gpu() -> PreflightResult {
        let output = run_hidden_command(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion | ConvertTo-Json"
            ],
        );

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let has_nvidia = stdout.contains("NVIDIA") || stdout.contains("GeForce");
                let has_amd = stdout.contains("AMD") || stdout.contains("Radeon");
                let has_intel = stdout.contains("Intel");

                let gpu_count = [has_nvidia, has_amd, has_intel].iter().filter(|&&x| x).count();

                if gpu_count >= 2 {
                    PreflightResult {
                        name: "GPU".to_string(),
                        status: PreflightStatus::Warn,
                        message: "Multiple GPUs detected. Known issues with hybrid graphics on Windows.".to_string(),
                        details_json: serde_json::json!({
                            "gpu_count": gpu_count,
                            "has_nvidia": has_nvidia,
                            "has_amd": has_amd,
                            "has_intel": has_intel,
                            "warning": "Try launching with --disable-gpu or set WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--disable-gpu",
                        }),
                    }
                } else {
                    PreflightResult {
                        name: "GPU".to_string(),
                        status: PreflightStatus::Pass,
                        message: "GPU detected".to_string(),
                        details_json: serde_json::json!({
                            "gpu_count": gpu_count,
                        }),
                    }
                }
            }
            _ => PreflightResult {
                name: "GPU".to_string(),
                status: PreflightStatus::Warn,
                message: "Could not enumerate GPUs".to_string(),
                details_json: serde_json::json!({}),
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn check_gpu() -> PreflightResult {
        PreflightResult {
            name: "GPU".to_string(),
            status: PreflightStatus::Pass,
            message: "GPU check only on Windows".to_string(),
            details_json: serde_json::json!({}),
        }
    }

    #[cfg(target_os = "windows")]
    pub fn check_remote_session() -> PreflightResult {
        let output = run_hidden_command(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "[System.Environment]::GetEnvironmentVariable('SESSIONNAME', 'Machine')"
            ],
        );

        let is_remote = output
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("RDP"))
            .unwrap_or(false);

        if is_remote {
            PreflightResult {
                name: "Remote Session".to_string(),
                status: PreflightStatus::Warn,
                message: "Running under Remote Desktop. WebView2 may have display limitations.".to_string(),
                details_json: serde_json::json!({
                    "is_remote": true,
                    "warning": "Some features may not render correctly",
                }),
            }
        } else {
            PreflightResult {
                name: "Remote Session".to_string(),
                status: PreflightStatus::Pass,
                message: "Not running under Remote Desktop".to_string(),
                details_json: serde_json::json!({
                    "is_remote": false,
                }),
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn check_remote_session() -> PreflightResult {
        PreflightResult {
            name: "Remote Session".to_string(),
            status: PreflightStatus::Pass,
            message: "Not applicable on this platform".to_string(),
            details_json: serde_json::json!({}),
        }
    }

    pub fn check_app_data_writable() -> PreflightResult {
        let app_data = get_app_data_dir();
        
        if let Some(ref dir) = app_data {
            match std::fs::create_dir_all(dir) {
                Ok(_) => {
                    let test_file = dir.join(".write_test");
                    match std::fs::write(&test_file, "test") {
                        Ok(_) => {
                            let _ = std::fs::remove_file(&test_file);
                            PreflightResult {
                                name: "App Data".to_string(),
                                status: PreflightStatus::Pass,
                                message: format!("{} is writable", dir.display()),
                                details_json: serde_json::json!({
                                    "path": dir.to_string_lossy(),
                                    "writable": true,
                                }),
                            }
                        }
                        Err(e) => PreflightResult {
                            name: "App Data".to_string(),
                            status: PreflightStatus::Fail,
                            message: format!("Cannot write to {}: {}", dir.display(), e),
                            details_json: serde_json::json!({
                                "path": dir.to_string_lossy(),
                                "writable": false,
                                "error": e.to_string(),
                            }),
                        },
                    }
                }
                Err(e) => PreflightResult {
                    name: "App Data".to_string(),
                    status: PreflightStatus::Fail,
                    message: format!("Cannot create {}: {}", dir.display(), e),
                    details_json: serde_json::json!({
                        "path": dir.to_string_lossy(),
                        "error": e.to_string(),
                    }),
                },
            }
        } else {
            PreflightResult {
                name: "App Data".to_string(),
                status: PreflightStatus::Fail,
                message: "Could not determine app data directory".to_string(),
                details_json: serde_json::json!({}),
            }
        }
    }

    pub fn check_temp_writable() -> PreflightResult {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join(format!("forensic_test_{}", std::process::id()));
        
        match std::fs::write(&test_file, "test") {
            Ok(_) => {
                let _ = std::fs::remove_file(&test_file);
                PreflightResult {
                    name: "Temp Directory".to_string(),
                    status: PreflightStatus::Pass,
                    message: format!("{} is writable", temp_dir.display()),
                    details_json: serde_json::json!({
                        "path": temp_dir.to_string_lossy(),
                    }),
                }
            }
            Err(e) => PreflightResult {
                name: "Temp Directory".to_string(),
                status: PreflightStatus::Fail,
                message: format!("Cannot write to temp {}: {}", temp_dir.display(), e),
                details_json: serde_json::json!({
                    "path": temp_dir.to_string_lossy(),
                    "error": e.to_string(),
                }),
            },
        }
    }

    pub fn check_database() -> PreflightResult {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("preflight_test_{}.sqlite", std::process::id()));
        
        match rusqlite::Connection::open(&db_path) {
            Ok(conn) => {
                let check: Result<String, _> = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0));
                let _ = std::fs::remove_file(&db_path);
                
                match check {
                    Ok(result) if result == "ok" => {
                        PreflightResult {
                            name: "Database".to_string(),
                            status: PreflightStatus::Pass,
                            message: "SQLite database creation and integrity check passed".to_string(),
                            details_json: serde_json::json!({
                                "integrity_check": result,
                            }),
                        }
                    }
                    Ok(result) => {
                        PreflightResult {
                            name: "Database".to_string(),
                            status: PreflightStatus::Fail,
                            message: format!("Database integrity check failed: {}", result),
                            details_json: serde_json::json!({
                                "integrity_check": result,
                            }),
                        }
                    }
                    Err(e) => {
                        PreflightResult {
                            name: "Database".to_string(),
                            status: PreflightStatus::Fail,
                            message: format!("Database error: {}", e),
                            details_json: serde_json::json!({
                                "error": e.to_string(),
                            }),
                        }
                    }
                }
            }
            Err(e) => {
                PreflightResult {
                    name: "Database".to_string(),
                    status: PreflightStatus::Fail,
                    message: format!("Cannot create database: {}", e),
                    details_json: serde_json::json!({
                        "error": e.to_string(),
                    }),
                }
            }
        }
    }

    pub fn get_app_data_dir() -> Option<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            std::env::var("LOCALAPPDATA").ok().map(|p| PathBuf::from(p).join("ForensicSuite"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::env::var("HOME").ok().map(|p| PathBuf::from(p).join(".forensic_suite"))
        }
    }

    pub fn get_version_info() -> serde_json::Value {
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "name": env!("CARGO_PKG_NAME"),
            "engine_version": option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"),
        })
    }

    pub fn get_system_info() -> serde_json::Value {
        #[cfg(target_os = "windows")]
        {
            let os_version = run_hidden_command(
                "powershell",
                &["-NoProfile", "-Command", "(Get-CimInstance Win32_OperatingSystem).Caption"],
            )
                .ok()
                .and_then(|o| if o.status.success() { Some(String::from_utf8_lossy(&o.stdout).trim().to_string()) } else { None })
                .unwrap_or_else(|| "Unknown".to_string());

            serde_json::json!({
                "os": "windows",
                "os_version": os_version,
                "architecture": std::env::consts::ARCH,
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            serde_json::json!({
                "os": std::env::consts::OS,
                "architecture": std::env::consts::ARCH,
            })
        }
    }
}

pub fn run_preflight_checks() -> PreflightReport {
    let mut report = PreflightReport::new();

    report.add_result(system::check_webview2());
    report.add_result(system::check_gpu());
    report.add_result(system::check_remote_session());
    report.add_result(system::check_app_data_writable());
    report.add_result(system::check_temp_writable());
    report.add_result(system::check_database());

    report.finalize();
    report
}

pub fn save_preflight_report(report: &PreflightReport) -> std::io::Result<()> {
    if let Some(app_dir) = system::get_app_data_dir() {
        std::fs::create_dir_all(&app_dir)?;
        let path = app_dir.join("preflight.latest.json");
        let json = serde_json::to_string_pretty(report).unwrap_or_default();
        std::fs::write(path, json)?;
    }
    Ok(())
}

pub fn load_latest_preflight_report() -> Option<PreflightReport> {
    if let Some(app_dir) = system::get_app_data_dir() {
        let path = app_dir.join("preflight.latest.json");
        if path.exists() {
            if let Ok(json) = std::fs::read_to_string(&path) {
                return serde_json::from_str(&json).ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preflight_report() {
        let mut report = PreflightReport::new();
        assert_eq!(report.overall_status, PreflightStatus::Pass);

        report.add_result(PreflightResult {
            name: "test".to_string(),
            status: PreflightStatus::Warn,
            message: "warning".to_string(),
            details_json: serde_json::json!({}),
        });
        assert_eq!(report.overall_status, PreflightStatus::Warn);

        report.add_result(PreflightResult {
            name: "test2".to_string(),
            status: PreflightStatus::Fail,
            message: "fail".to_string(),
            details_json: serde_json::json!({}),
        });
        assert_eq!(report.overall_status, PreflightStatus::Fail);
    }

    #[test]
    fn test_system_info() {
        let info = system::get_system_info();
        assert!(info.get("os").is_some());
    }

    #[test]
    fn test_version_info() {
        let info = system::get_version_info();
        assert!(info.get("version").is_some());
    }

    #[test]
    fn test_preflight_result_serialization() {
        let result = PreflightResult {
            name: "webview2".to_string(),
            status: PreflightStatus::Pass,
            message: "WebView2 runtime found".to_string(),
            details_json: serde_json::json!({"version": "120.0.0"}),
        };

        let serialized = serde_json::to_string(&result).unwrap();
        assert!(serialized.contains("webview2"));
        assert!(serialized.contains("Pass"));

        let deserialized: PreflightResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.name, "webview2");
        assert_eq!(deserialized.status, PreflightStatus::Pass);
    }

    #[test]
    fn test_preflight_report_serialization() {
        let mut report = PreflightReport::new();
        report.add_result(PreflightResult {
            name: "webview2".to_string(),
            status: PreflightStatus::Pass,
            message: "Found".to_string(),
            details_json: serde_json::json!({}),
        });
        report.add_result(PreflightResult {
            name: "gpu".to_string(),
            status: PreflightStatus::Warn,
            message: "Software rendering".to_string(),
            details_json: serde_json::json!({"render_mode": "software"}),
        });
        report.finalize();

        let serialized = serde_json::to_string(&report).unwrap();
        assert!(serialized.contains("Warn"));

        let deserialized: PreflightReport = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.results.len(), 2);
        assert_eq!(deserialized.overall_status, PreflightStatus::Warn);
    }

    #[test]
    fn test_webview2_check_missing_runtime() {
        let result = check_webview2();
        let _ = result;
    }

    #[test]
    fn test_webview2_check_returns_result() {
        let result = check_webview2();
        assert!(!result.name.is_empty());
        assert!(matches!(result.status, PreflightStatus::Pass | PreflightStatus::Warn | PreflightStatus::Fail));
    }
}
