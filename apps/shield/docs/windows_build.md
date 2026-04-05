# Windows Build Guide

## Prerequisites

### Required Tools
- Rust 1.70+ with `cargo`
- Visual Studio Build Tools 2022+
- Node.js 18+ (for Tauri)
- WebView2 Runtime

### System Requirements
- Windows 10/11 64-bit
- 8GB RAM minimum
- 50GB disk space

## Build Steps

### 1. Install Rust
```powershell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update
```

### 2. Install Visual Studio Build Tools
Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
Select:
- "Desktop development with C++"
- Windows 10/11 SDK

### 3. Install Node.js
Download from: https://nodejs.org/

### 4. Build CLI
```powershell
cd forensic-suite
cargo build --release --package forensic-cli
```

### 5. Build Desktop
```powershell
cd desktop
npm install
npm run tauri build
```

## WebView2 Requirements

### Detection
The desktop application checks for WebView2 at startup:
```rust
// In desktop/src/preflight.rs
pub fn check_webview2() -> PreflightResult
```

### Installation Options
1. **Evergreen (Recommended)**: Auto-updating via Microsoft Update
2. **Fixed**: Version-specific installer

### Detection Registry Keys
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`
- `HKLM\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`

## Safe Mode

If WebView2 is missing or preflight checks fail:
```powershell
forensic_desktop.exe --safe-mode
```

Safe mode provides:
- Read-only case access
- Export functionality only
- No evidence acquisition

### Black Window Mitigation

If black window appears on launch:
1. Check WebView2 installation
2. Run with `--safe-mode`
3. Check graphics drivers
4. Try software rendering:
```powershell
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--disable-gpu"
```

## Bundling CLI with Desktop

The desktop build automatically bundles the CLI as a sidecar:
- CLI location: `resources/forensic-cli.exe`
- Accessible from desktop via IPC

## Troubleshooting

### Build Errors
- Ensure VS Build Tools installed with C++ workload
- Run `cargo clean` if caching issues

### Runtime Errors
- Check Windows Event Viewer
- Run with RUST_BACKTRACE=1
- Verify WebView2 installed

### Performance
- Use release builds for production
- Enable hardware acceleration
- Allocate sufficient RAM
