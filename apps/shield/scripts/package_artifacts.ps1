# Package Artifacts
# Run from repository root

param(
    [string]$Version = "1.0.0",
    [string]$OutputDir = "./dist"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Packaging Forensic Suite ===" -ForegroundColor Cyan

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Package CLI
Write-Host "Packaging CLI..." -ForegroundColor Yellow
$cliExe = "./target/release/forensic-cli.exe"
if (Test-Path $cliExe) {
    Copy-Item $cliExe "$OutputDir/forensic-cli-$Version.exe"
    Write-Host "CLI packaged: forensic-cli-$Version.exe"
} else {
    Write-Warning "CLI executable not found at $cliExe"
}

# Package Desktop
$msiPath = "./target/release/bundle/msi/Forensic_Suite_$Version.msi"
if (Test-Path $msiPath) {
    Copy-Item $msiPath "$OutputDir/"
    Write-Host "MSI packaged: Forensic_Suite_$Version.msi"
} else {
    Write-Warning "MSI not found at $msiPath"
}

# Create manifest
$manifest = @{
    version = $Version
    timestamp = (Get-Date -Format "o")
    artifacts = @()
} | ConvertTo-Json

# Add CLI artifact
if (Test-Path "$OutputDir/forensic-cli-$Version.exe") {
    $manifestObject = Get-Content "$OutputDir/forensic-cli-$Version.exe" -Raw -ErrorAction SilentlyContinue
    $cliHash = (Get-FileHash "$OutputDir/forensic-cli-$Version.exe" -Algorithm SHA256).Hash
    $manifest.artifacts += @{
        name = "forensic-cli-$Version.exe"
        sha256 = $cliHash
        type = "cli"
    }
}

$manifest | Out-File "$OutputDir/manifest.json" -Encoding UTF8

Write-Host "=== Packaging Complete ===" -ForegroundColor Green
Write-Host "Output directory: $OutputDir"
Get-ChildItem $OutputDir | ForEach-Object { Write-Host "  $($_.Name)" }
