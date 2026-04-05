param(
    [switch]$ForceRebuild,
    [switch]$SkipVerify
)

$ErrorActionPreference = "Stop"

$GuiRoot = Split-Path -Parent $PSScriptRoot
$RepoRoot = Split-Path -Parent $GuiRoot
$SourceExe = Join-Path $RepoRoot "target\release\forensic_cli.exe"
$DestDir = Join-Path $GuiRoot "src-tauri\bin"
$DestExe = Join-Path $DestDir "forensic_cli-x86_64-pc-windows-msvc.exe"

function Build-Sidecar {
    Write-Host "Building forensic_cli (release) from $RepoRoot ..."
    Push-Location $RepoRoot
    try {
        cargo build -p forensic_cli --release
    }
    finally {
        Pop-Location
    }
}

if ($ForceRebuild -or -not (Test-Path $SourceExe)) {
    Build-Sidecar
}

if (-not (Test-Path $SourceExe)) {
    throw "Sidecar build output not found: $SourceExe"
}

if (-not (Test-Path $DestDir)) {
    New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
}

$copyNeeded = $true
if (Test-Path $DestExe) {
    $src = Get-Item $SourceExe
    $dst = Get-Item $DestExe
    if ($src.Length -eq $dst.Length -and $src.LastWriteTimeUtc -le $dst.LastWriteTimeUtc) {
        $copyNeeded = $false
    }
}

if ($copyNeeded) {
    Copy-Item $SourceExe $DestExe -Force
    Write-Host "Copied sidecar to $DestExe"
} else {
    Write-Host "Sidecar already up to date at $DestExe"
}

$srcHash = (Get-FileHash -Path $SourceExe -Algorithm SHA256).Hash
$dstHash = (Get-FileHash -Path $DestExe -Algorithm SHA256).Hash
Write-Host "Source SHA256: $srcHash"
Write-Host "Dest   SHA256: $dstHash"

if ($srcHash -ne $dstHash) {
    throw "SHA256 mismatch after sidecar sync."
}

if (-not $SkipVerify) {
    try {
        & $DestExe --help *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Sidecar --help exited with code $LASTEXITCODE"
        }
        Write-Host "Sidecar runtime probe passed (--help)."
    } catch {
        throw "Sidecar runtime probe failed: $($_.Exception.Message)"
    }
}

Write-Host "Sidecar sync complete."
