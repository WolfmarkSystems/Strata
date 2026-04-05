Param(
    [string]$RepoRoot = "D:\Vantor"
)

$ErrorActionPreference = "Stop"
$projectRoot = Join-Path $RepoRoot "apps\tree\vantor-tree"
$nsiScript = Join-Path $projectRoot "installer\vantor-tree.nsi"
$releaseExe = Join-Path $RepoRoot "target\release\vantor-tree.exe"

Write-Host "Building Vantor Tree release binary..."
Push-Location $RepoRoot
cargo build -p vantor-tree --release
Pop-Location

if (!(Test-Path -LiteralPath $releaseExe)) {
    throw "Release binary missing at $releaseExe"
}
if (!(Test-Path -LiteralPath $nsiScript)) {
    throw "NSIS script missing at $nsiScript"
}

$makensis = Get-Command "makensis.exe" -ErrorAction SilentlyContinue
if ($null -eq $makensis) {
    throw "makensis.exe not found in PATH. Install NSIS and retry."
}

Write-Host "Building NSIS installer..."
Push-Location (Join-Path $projectRoot "installer")
& $makensis.Source $nsiScript
Pop-Location

Write-Host "Installer build complete."
