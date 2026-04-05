# test_surface.ps1
# End-to-end surface test against an E01 and write outputs to .\exports\surface_test
# PowerShell 5+ / Windows

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$msg) { throw $msg }

# Always run from repo root
$repoRoot = "D:\forensic-suite"
Set-Location -LiteralPath $repoRoot

# --- Paths ---
$exe = Join-Path $repoRoot "target\release\forensic_cli.exe"
$evidenceDir = Join-Path $repoRoot "evidence"
$outDir = Join-Path $repoRoot "exports\surface_test"

# --- Locate image ---
$defaultImage = Join-Path $evidenceDir "Stack001_Surface_HDD.E01"
if (Test-Path -LiteralPath $defaultImage) {
  $image = $defaultImage
} else {
  $found = Get-ChildItem -LiteralPath $evidenceDir -File -Filter "*.E01" -ErrorAction SilentlyContinue |
           Select-Object -First 1
  if (-not $found) {
    Fail "No .E01 file found in $evidenceDir. Put the E01 there (or update the script with the correct path)."
  }
  $image = $found.FullName
}

# --- Ensure output directory exists ---
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# --- Build release if needed ---
if (-not (Test-Path -LiteralPath $exe)) {
  Write-Host "Release exe not found at $exe. Building release..." -ForegroundColor Yellow
  & cargo build -p forensic_cli --release | Out-Host
  if (-not (Test-Path -LiteralPath $exe)) { Fail "Still can't find $exe after build." }
}

# --- Output files ---
$summary   = Join-Path $outDir "summary.txt"
$timeline  = Join-Path $outDir "timeline.csv"
$auditJson = Join-Path $outDir "audit.json"
$runLog    = Join-Path $outDir ("run_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

# Track start time to validate "fresh" outputs
$startedAt = Get-Date

Write-Host "=== Forensic CLI Surface Test ===" -ForegroundColor Cyan
Write-Host "Repo:  $repoRoot"
Write-Host "Exe:   $exe"
Write-Host "Image: $image"
Write-Host "Out:   $outDir"
Write-Host "Log:   $runLog"
Write-Host ""

# --- Build argument list safely (no manual quoting needed) ---
# NOTE: keep it light first; raise later.
$argList = @(
  $image
  "--summary",  $summary
  "--timeline", $timeline
  "--json",     $auditJson
  "--mft",      "2000"
)

Write-Host ("Running: `"$exe`" " + ($argList | ForEach-Object { "`"$_`"" } ) -join " ") -ForegroundColor Green

# Capture stdout/stderr to a log while still showing it live
$sw = [System.Diagnostics.Stopwatch]::StartNew()
& $exe @argList 2>&1 | Tee-Object -FilePath $runLog
$sw.Stop()

$exit = $LASTEXITCODE

Write-Host ""
Write-Host ("Exit code: {0}" -f $exit) -ForegroundColor Cyan
Write-Host ("Elapsed:   {0:n2}s" -f $sw.Elapsed.TotalSeconds) -ForegroundColor Cyan

# --- Show outputs created ---
Write-Host ""
Write-Host "Outputs:" -ForegroundColor Cyan
Get-ChildItem -LiteralPath $outDir -File |
  Sort-Object LastWriteTime -Descending |
  Select-Object Name, Length, LastWriteTime |
  Format-Table -AutoSize

# --- Validate result ---
if ($exit -ne 0) {
  Write-Host ""
  Write-Host "Last 80 log lines:" -ForegroundColor Yellow
  Get-Content -LiteralPath $runLog -Tail 80 | Out-Host
  Fail "forensic_cli exited with code $exit"
}

# Validate that outputs are non-empty and written during this run
function Assert-NonEmptyFresh([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { Fail "Expected output missing: $path" }
  $fi = Get-Item -LiteralPath $path
  if ($fi.Length -le 0) { Fail "Expected output is empty: $path" }
  if ($fi.LastWriteTime -lt $startedAt.AddSeconds(-2)) { Fail "Expected output not updated this run: $path" }
}

Assert-NonEmptyFresh $summary
# Timeline/JSON might be empty depending on implementation; enforce if you want:
Assert-NonEmptyFresh $timeline
Assert-NonEmptyFresh $auditJson

Write-Host ""
Write-Host "Done." -ForegroundColor Green