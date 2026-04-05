Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-PathSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path)
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$guiRoot = Resolve-PathSafe (Join-Path $scriptRoot "..")
$repoRoot = Resolve-PathSafe (Join-Path $guiRoot "..")

Write-Host "[portable] GUI root: $guiRoot"
Write-Host "[portable] Repo root: $repoRoot"

Push-Location $guiRoot
try {
    Write-Host "[portable] Building frontend..."
    npm run build

    Write-Host "[portable] Building release binary..."
    cargo build --manifest-path "$guiRoot/src-tauri/Cargo.toml" --release
}
finally {
    Pop-Location
}

$candidateExePaths = @(
    (Join-Path $repoRoot "target/release/forensic-suite-gui.exe"),
    (Join-Path $guiRoot "src-tauri/target/release/forensic-suite-gui.exe")
)

$exePath = $null
foreach ($candidate in $candidateExePaths) {
    if (Test-Path $candidate) {
        $exePath = $candidate
        break
    }
}

if (-not $exePath) {
    throw "Portable build failed: forensic-suite-gui.exe was not found in expected release locations."
}

$portableRoot = Join-Path $guiRoot "dist-portable"
$portableDir = Join-Path $portableRoot "ForensicSuite-Portable"
$launcherPath = Join-Path $portableDir "Start-ForensicSuitePortable.cmd"
$readmePath = Join-Path $portableDir "README.txt"
$zipPath = Join-Path $portableRoot "ForensicSuite-Portable.zip"

if (Test-Path $portableDir) {
    Remove-Item -Recurse -Force $portableDir
}
New-Item -ItemType Directory -Path $portableDir -Force | Out-Null

$portableExePath = Join-Path $portableDir "forensic-suite-gui.exe"
Copy-Item -Path $exePath -Destination $portableExePath -Force

@"
@echo off
setlocal
cd /d "%~dp0"
start "" "forensic-suite-gui.exe"
"@ | Set-Content -Path $launcherPath -Encoding ascii

@"
ForensicSuite Portable Build
============================

How to run:
1) Double-click Start-ForensicSuitePortable.cmd
   or run forensic-suite-gui.exe directly.

Notes:
- This is a non-installer portable package.
- Microsoft Edge WebView2 runtime is required on the host machine.
- Logs are written next to the executable as forensic_suite.log.
"@ | Set-Content -Path $readmePath -Encoding utf8

if (Test-Path $zipPath) {
    Remove-Item -Force $zipPath
}
Compress-Archive -Path (Join-Path $portableDir "*") -DestinationPath $zipPath -CompressionLevel Optimal

Write-Host ""
Write-Host "[portable] Complete."
Write-Host "[portable] EXE: $portableExePath"
Write-Host "[portable] ZIP: $zipPath"
