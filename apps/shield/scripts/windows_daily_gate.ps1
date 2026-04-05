param(
    [string]$OutRoot = "_run/windows_roadmap",
    [string]$BaselineSummaryPath = "",
    [switch]$EnableCorpusHarness,
    [int]$CorpusMaxFiles = 50,
    [int]$CorpusMaxBytes = 2097152
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-LatestBaselineSummary {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath
    )
    if (-not (Test-Path -LiteralPath $RootPath)) {
        return $null
    }
    return Get-ChildItem -LiteralPath $RootPath -Recurse -Filter baseline_summary.json -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$outRootPath = Join-Path $repoRoot $OutRoot

$newSummaryPath = & (Join-Path $PSScriptRoot "windows_baseline_snapshot.ps1") `
    -OutRoot $OutRoot `
    -EnableCorpusHarness:$EnableCorpusHarness `
    -CorpusMaxFiles $CorpusMaxFiles `
    -CorpusMaxBytes $CorpusMaxBytes

$newSummary = Get-Content -LiteralPath $newSummaryPath -Raw | ConvertFrom-Json

$referencePath = $BaselineSummaryPath
if ([string]::IsNullOrWhiteSpace($referencePath)) {
    $latest = Get-LatestBaselineSummary -RootPath $outRootPath
    if ($latest -and ($latest.FullName -ne $newSummaryPath)) {
        $referencePath = $latest.FullName
    }
}

$reference = $null
if (-not [string]::IsNullOrWhiteSpace($referencePath) -and (Test-Path -LiteralPath $referencePath)) {
    $reference = Get-Content -LiteralPath $referencePath -Raw | ConvertFrom-Json
}

$issues = @()
if (-not $newSummary.metrics.build_ok) { $issues += "build failed" }
if (-not $newSummary.metrics.tests_ok) { $issues += "tests failed" }
if (-not $newSummary.metrics.clippy_ok) { $issues += "clippy command failed" }
if (-not $newSummary.metrics.fixture_harness_ok) { $issues += "fixture harness failed" }

if ($reference -ne $null) {
    if ([int]$newSummary.metrics.failed_test_count -gt [int]$reference.metrics.failed_test_count) {
        $issues += "failed test count increased ($($reference.metrics.failed_test_count) -> $($newSummary.metrics.failed_test_count))"
    }
    if ([int]$newSummary.metrics.clippy_warning_count -gt [int]$reference.metrics.clippy_warning_count) {
        $issues += "clippy warning count increased ($($reference.metrics.clippy_warning_count) -> $($newSummary.metrics.clippy_warning_count))"
    }
}

$gatePassed = ($issues.Count -eq 0)
$gate = [pscustomobject]@{
    timestamp_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    passed = $gatePassed
    issues = $issues
    new_summary_path = $newSummaryPath
    reference_summary_path = if ($reference -ne $null) { $referencePath } else { $null }
}

$gateOutPath = Join-Path (Split-Path -Parent $newSummaryPath) "daily_gate_result.json"
$gate | ConvertTo-Json -Depth 6 | Set-Content -Path $gateOutPath -Encoding UTF8

if ($gatePassed) {
    Write-Host "Daily gate PASSED: $gateOutPath" -ForegroundColor Green
} else {
    Write-Host "Daily gate FAILED: $gateOutPath" -ForegroundColor Red
    $issues | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
}

Write-Output $gateOutPath
