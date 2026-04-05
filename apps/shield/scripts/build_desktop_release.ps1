# Build Desktop Release
# Run from repository root

param(
    [string]$Config = "release"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Building Forensic Suite Desktop ===" -ForegroundColor Cyan

# Check prerequisites
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "Rust/Cargo not found. Install from https://rustup.rs/"
    exit 1
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js not found. Install from https://nodejs.org/"
    exit 1
}

# Set environment
$env:RUST_BACKTRACE = "1"

# Build CLI first
Write-Host "Building CLI..." -ForegroundColor Yellow
Push-Location .. 
cargo build --package forensic-cli --$Config
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Write-Error "CLI build failed"
    exit 1
}
Pop-Location

# Build Desktop
Write-Host "Building Desktop..." -ForegroundColor Yellow
Push-Location ../desktop
npm install
npm run tauri build -- --$Config
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Write-Error "Desktop build failed"
    exit 1
}
Pop-Location

# Verify output
$outputDir = "../target/$Config/bundle/msi"
if (Test-Path $outputDir) {
    Write-Host "=== Build Complete ===" -ForegroundColor Green
    Get-ChildItem $outputDir -Filter "*.msi" | ForEach-Object {
        Write-Host "Output: $($_.FullName)"
    }
} else {
    Write-Warning "MSI not found, check bundle output"
}

Write-Host "Done!" -ForegroundColor Green
