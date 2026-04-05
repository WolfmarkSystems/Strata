param(
    [string]$OutRoot = "_run/windows_roadmap",
    [switch]$EnableCorpusHarness,
    [int]$CorpusMaxFiles = 50,
    [int]$CorpusMaxBytes = 2097152
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-CapturedStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$WorkDir,
        [Parameter(Mandatory = $true)][string]$OutDir
    )

    $logPath = Join-Path $OutDir "$Name.log"
    Write-Host "[$Name] $Command" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $fullCmd = "cd /d `"$WorkDir`" && $Command"
    $cmdLine = "$fullCmd > `"$logPath`" 2>&1"
    & cmd.exe /d /c $cmdLine | Out-Null
    $exitCode = $LASTEXITCODE
    if (Test-Path -LiteralPath $logPath) {
        Get-Content -LiteralPath $logPath | Out-Host
    }
    $sw.Stop()
    return [pscustomobject]@{
        name = $Name
        command = $Command
        exit_code = $exitCode
        elapsed_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 3)
        log_path = $logPath
    }
}

function Get-LatestRegexCount {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return 0
    }
    return @(Select-String -Path $Path -Pattern $Pattern).Count
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$timestampUtc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$stamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd_HHmmss")
$outDir = Join-Path $repoRoot $OutRoot
$outDir = Join-Path $outDir $stamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$env:FORENSIC_CORPUS_HARNESS = if ($EnableCorpusHarness) { "1" } else { "0" }
$env:FORENSIC_CORPUS_MAX_FILES = [string]$CorpusMaxFiles
$env:FORENSIC_CORPUS_MAX_BYTES = [string]$CorpusMaxBytes

$steps = @()
$steps += Invoke-CapturedStep -Name "build_workspace" -Command "cargo build --workspace" -WorkDir $repoRoot -OutDir $outDir
$steps += Invoke-CapturedStep -Name "test_workspace" -Command "cargo test --workspace -- --nocapture" -WorkDir $repoRoot -OutDir $outDir
$steps += Invoke-CapturedStep -Name "clippy_workspace" -Command "cargo clippy --workspace --all-targets --all-features" -WorkDir $repoRoot -OutDir $outDir
$steps += Invoke-CapturedStep -Name "fixture_harness" -Command "cargo test -p forensic_engine fixture_harness -- --nocapture" -WorkDir $repoRoot -OutDir $outDir

$buildStep = $steps | Where-Object { $_.name -eq "build_workspace" } | Select-Object -First 1
$testStep = $steps | Where-Object { $_.name -eq "test_workspace" } | Select-Object -First 1
$clippyStep = $steps | Where-Object { $_.name -eq "clippy_workspace" } | Select-Object -First 1
$fixtureStep = $steps | Where-Object { $_.name -eq "fixture_harness" } | Select-Object -First 1

$buildErrorCount = Get-LatestRegexCount -Path $buildStep.log_path -Pattern "^error(\[E[0-9]{4}\])?:"
$clippyWarningCount = Get-LatestRegexCount -Path $clippyStep.log_path -Pattern "^\s*warning:"
$testFailLines = @()
if (Test-Path -LiteralPath $testStep.log_path) {
    $testFailLines = @(Select-String -Path $testStep.log_path -Pattern "^test .+ \.\.\. FAILED$" |
        ForEach-Object { $_.Line.Trim() }
    )
}
$uniqueFailedTests = @($testFailLines | Select-Object -Unique)
$testFailureCount = $uniqueFailedTests.Count

$fixtureMissingCount = 0
if (Test-Path -LiteralPath $fixtureStep.log_path) {
    $fixtureMissingCount = @(Select-String -Path $fixtureStep.log_path -Pattern "\[fixture-harness\] manifest missing fixture files").Count
}

$manifestPath = Join-Path $repoRoot "fixtures/images/manifest.json"
$totalFixtures = 0
$windowsFixtures = 0
$totalParserInputs = 0
$windowsParserInputs = 0
if (Test-Path -LiteralPath $manifestPath) {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $fixtures = @($manifest.fixtures)
    $parserInputs = @($manifest.parser_inputs)
    $totalFixtures = $fixtures.Count
    $windowsFixtures = ($fixtures | Where-Object { $_.platform -eq "windows" }).Count
    $totalParserInputs = $parserInputs.Count
    $windowsParserInputs = ($parserInputs | Where-Object { $_.path -like "windows/*" }).Count
}

$summary = [pscustomobject]@{
    timestamp_utc = $timestampUtc
    repo_root = [string]$repoRoot
    out_dir = $outDir
    corpus = [pscustomobject]@{
        enabled = [bool]$EnableCorpusHarness
        max_files = $CorpusMaxFiles
        max_bytes = $CorpusMaxBytes
    }
    steps = $steps
    metrics = [pscustomobject]@{
        build_ok = ($buildStep.exit_code -eq 0)
        tests_ok = ($testStep.exit_code -eq 0)
        clippy_ok = ($clippyStep.exit_code -eq 0)
        fixture_harness_ok = ($fixtureStep.exit_code -eq 0)
        build_error_count = $buildErrorCount
        clippy_warning_count = $clippyWarningCount
        failed_test_count = $testFailureCount
        failed_tests = $uniqueFailedTests
        fixture_missing_warning_count = $fixtureMissingCount
    }
    fixtures = [pscustomobject]@{
        manifest_path = $manifestPath
        total_fixtures = $totalFixtures
        windows_fixtures = $windowsFixtures
        total_parser_inputs = $totalParserInputs
        windows_parser_inputs = $windowsParserInputs
    }
}

$summaryPath = Join-Path $outDir "baseline_summary.json"
$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryPath -Encoding UTF8

$mdPath = Join-Path $outDir "baseline_summary.md"
$failedTestsForMd = @($summary.metrics.failed_tests)
$failedTestsText = if ($failedTestsForMd.Count -gt 0) {
    ($failedTestsForMd -join "`n")
} else {
    "None"
}
@"
# Baseline Snapshot

- Timestamp (UTC): $($summary.timestamp_utc)
- Build OK: $($summary.metrics.build_ok)
- Tests OK: $($summary.metrics.tests_ok)
- Clippy OK: $($summary.metrics.clippy_ok)
- Fixture Harness OK: $($summary.metrics.fixture_harness_ok)
- Build Error Count: $($summary.metrics.build_error_count)
- Clippy Warning Count: $($summary.metrics.clippy_warning_count)
- Failed Test Count: $($summary.metrics.failed_test_count)
- Fixture Missing Warnings: $($summary.metrics.fixture_missing_warning_count)
- Windows Fixtures in Manifest: $($summary.fixtures.windows_fixtures) / $($summary.fixtures.total_fixtures)
- Windows Parser Inputs in Manifest: $($summary.fixtures.windows_parser_inputs) / $($summary.fixtures.total_parser_inputs)

## Failed Tests
$failedTestsText
"@ | Set-Content -Path $mdPath -Encoding UTF8

Write-Host "Baseline summary written to: $summaryPath" -ForegroundColor Green
Write-Output $summaryPath
