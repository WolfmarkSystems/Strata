param(
    [string]$Root = ".",
    [switch]$SkipTests
)

$ErrorActionPreference = "Continue"
$rootPath = (Resolve-Path $Root).Path
$guardianReport = Join-Path $rootPath "guardian\VANTOR_RELEASE_READINESS_REPORT.md"

Write-Host "== Vantor Shield: Automated Release Gate =="
if (Test-Path $guardianReport) { Remove-Item $guardianReport }
$header = "# Vantor Shield - Release Readiness Report`n**Date:** $((Get-Date).ToUniversalTime()) UTC`n`n## 1. Engine Core Audit"
$header | Out-File $guardianReport -Encoding utf8

$allPassed = $true

# [1/5] Tests
if (-not $SkipTests) {
    Write-Host "[1/5] Running Rust Unit Tests..."
    & cargo test -p forensic_engine -p forensic_cli --quiet
    if ($LASTEXITCODE -eq 0) {
        "- [OK] Unit Tests: PASS" | Out-File $guardianReport -Append -Encoding utf8
        Write-Host "  [+] PASS" -ForegroundColor Green
    } else {
        "- [FAIL] Unit Tests: FAIL" | Out-File $guardianReport -Append -Encoding utf8
        Write-Host "  [-] FAIL" -ForegroundColor Red
        $allPassed = $false
    }
}

# [2/5] Stubs
Write-Host "[2/5] Scanning for Stubs..."
& "$rootPath\scripts\scan_stubs.ps1"
if ($LASTEXITCODE -eq 0) {
    "- [OK] Stub Scanner: PASS" | Out-File $guardianReport -Append -Encoding utf8
    Write-Host "  [+] PASS" -ForegroundColor Green
} else {
    "- [FAIL] Stub Scanner: FAIL" | Out-File $guardianReport -Append -Encoding utf8
    Write-Host "  [-] FAIL" -ForegroundColor Red
    $allPassed = $false
}

# [3/5] Envelopes
Write-Host "[3/5] Validating CLI Envelopes..."
& "$rootPath\scripts\validate_envelopes.ps1"
if ($LASTEXITCODE -eq 0) {
    "- [OK] Envelope Validator: PASS" | Out-File $guardianReport -Append -Encoding utf8
    Write-Host "  [+] PASS" -ForegroundColor Green
} else {
    "- [FAIL] Envelope Validator: FAIL" | Out-File $guardianReport -Append -Encoding utf8
    Write-Host "  [-] FAIL" -ForegroundColor Red
    $allPassed = $false
}

# [4/5] Contracts
Write-Host "[4/5] Validating GUI/CLI Contracts..."
& "$rootPath\scripts\validate_contracts.ps1" -Root $rootPath
if ($LASTEXITCODE -eq 0) {
    "- [OK] Contract Validator: PASS" | Out-File $guardianReport -Append -Encoding utf8
    Write-Host "  [+] PASS" -ForegroundColor Green
} else {
    "- [FAIL] Contract Validator: FAIL" | Out-File $guardianReport -Append -Encoding utf8
    Write-Host "  [-] FAIL" -ForegroundColor Red
    $allPassed = $false
}

# [5/5] Parsers
Write-Host "[5/5] Running Parser Quality Tests..."
& "$rootPath\scripts\test_parsers.ps1" -Root $rootPath
if ($LASTEXITCODE -eq 0) {
    "- [OK] Parser Quality: PASS" | Out-File $guardianReport -Append -Encoding utf8
    Write-Host "  [+] PASS" -ForegroundColor Green
} else {
    "- [FAIL] Parser Quality: FAIL" | Out-File $guardianReport -Append -Encoding utf8
    Write-Host "  [-] FAIL" -ForegroundColor Red
    $allPassed = $false
}

Write-Host ""
if ($allPassed) {
    "### RELEASE READY" | Out-File $guardianReport -Append -Encoding utf8
    Write-Host "FINAL VERDICT: RELEASE READY" -ForegroundColor Green
    exit 0
} else {
    "### RELEASE BLOCKED" | Out-File $guardianReport -Append -Encoding utf8
    Write-Host "FINAL VERDICT: RELEASE BLOCKED" -ForegroundColor Red
    exit 1
}
