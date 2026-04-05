param(
    [Parameter(Mandatory = $true)][string]$ImagePath,
    [string]$OutRoot = "_run/windows_roadmap/stress",
    [int]$MftCount = 5000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$stamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd_HHmmss")
$outDir = Join-Path $repoRoot $OutRoot
$outDir = Join-Path $outDir $stamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$smokeOutDir = Join-Path $outDir "smoke_out"
New-Item -ItemType Directory -Force -Path $smokeOutDir | Out-Null
$stdoutPath = Join-Path $outDir "stdout.txt"
$stderrPath = Join-Path $outDir "stderr.txt"
$jsonSummaryPath = Join-Path $smokeOutDir "smoke_summary.json"

$args = @(
    "run", "-q", "-p", "forensic_cli", "--",
    "smoke-test",
    "--image", $ImagePath,
    "--out", $smokeOutDir,
    "--mft", "$MftCount",
    "--quiet"
)

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "cargo"
$psi.WorkingDirectory = $repoRoot
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
foreach ($arg in $args) {
    [void]$psi.ArgumentList.Add($arg)
}

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$null = $proc.Start()

$peakWorkingSet = 0L
$peakPrivateBytes = 0L

while (-not $proc.HasExited) {
    $proc.Refresh()
    if ($proc.WorkingSet64 -gt $peakWorkingSet) {
        $peakWorkingSet = $proc.WorkingSet64
    }
    if ($proc.PrivateMemorySize64 -gt $peakPrivateBytes) {
        $peakPrivateBytes = $proc.PrivateMemorySize64
    }
    Start-Sleep -Milliseconds 250
}

$stdout = $proc.StandardOutput.ReadToEnd()
$stderr = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
$sw.Stop()

$stdout | Set-Content -Path $stdoutPath -Encoding UTF8
$stderr | Set-Content -Path $stderrPath -Encoding UTF8

$summaryJson = $null
if (Test-Path -LiteralPath $jsonSummaryPath) {
    try {
        $summaryJson = Get-Content -Raw -Path $jsonSummaryPath | ConvertFrom-Json
    }
    catch {
        $summaryJson = $null
    }
}

$result = [pscustomobject]@{
    timestamp_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    image_path = $ImagePath
    mft_count = $MftCount
    exit_code = $proc.ExitCode
    elapsed_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
    peak_working_set_mb = [math]::Round(($peakWorkingSet / 1MB), 2)
    peak_private_bytes_mb = [math]::Round(($peakPrivateBytes / 1MB), 2)
    stdout_path = $stdoutPath
    stderr_path = $stderrPath
    smoke_summary_path = if (Test-Path -LiteralPath $jsonSummaryPath) { $jsonSummaryPath } else { $null }
    smoke_summary_status = if ($summaryJson -and $summaryJson.status) { $summaryJson.status } else { $null }
}

$resultPath = Join-Path $outDir "stress_gate_summary.json"
$result | ConvertTo-Json -Depth 6 | Set-Content -Path $resultPath -Encoding UTF8

Write-Host "Large-image stress summary written to: $resultPath" -ForegroundColor Green
Write-Output $resultPath
