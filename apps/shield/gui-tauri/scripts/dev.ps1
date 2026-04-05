$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = "$ScriptDir\.."

Push-Location $ProjectRoot

try {
    # 1) Ensure Node deps
    if (-not (Test-Path "node_modules")) {
        Write-Host "Installing Node dependencies..."
        npm install
    }

    # 2) Ensure sidecar binary is always synced for deterministic dev runs
    & "$ScriptDir\sync-sidecar.ps1"

    # 3) Run dev
    Write-Host "Starting Tauri dev..."
    npm run tauri dev
}
finally {
    Pop-Location
}
