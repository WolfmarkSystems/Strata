param(
    [Parameter(Mandatory = $true)][string]$TasksRoot,
    [string]$OutRoot = "_run/windows_roadmap/benchmarks"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-ScheduledTasksBench {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$TasksRoot,
        [Parameter(Mandatory = $true)][int]$Limit
    )

    $argList = @(
        "run", "-q", "-p", "forensic_cli", "--",
        "scheduled-tasks-artifacts",
        "--tasks-root", $TasksRoot,
        "--limit", "$Limit",
        "--json",
        "--quiet"
    )

    $stdoutFile = $null
    $stderrFile = $null
    $peakWorkingSetBytes = 0
    Push-Location $RepoRoot
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $stdoutFile = [System.IO.Path]::GetTempFileName()
        $stderrFile = [System.IO.Path]::GetTempFileName()
        $proc = Start-Process -FilePath "cargo" -ArgumentList $argList -PassThru -NoNewWindow -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
        $proc.WaitForExit()
        $exitCode = $proc.ExitCode
        $peakWorkingSetBytes = $proc.PeakWorkingSet64
        $sw.Stop()
    }
    finally {
        if (Test-Path $stdoutFile) { Remove-Item -Force $stdoutFile -ErrorAction SilentlyContinue }
        if (Test-Path $stderrFile) { Remove-Item -Force $stderrFile -ErrorAction SilentlyContinue }
        Pop-Location
    }

    [pscustomobject]@{
        limit = $Limit
        exit_code = $exitCode
        elapsed_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
        peak_working_set_bytes = $peakWorkingSetBytes
    }
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$resolvedInput = Resolve-Path $TasksRoot
$stamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd_HHmmss")
$outDir = Join-Path $repoRoot $OutRoot
$outDir = Join-Path $outDir $stamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$limits = @(200, 1000, 5000)
$runs = @()
foreach ($limit in $limits) {
    $runs += Invoke-ScheduledTasksBench -RepoRoot $repoRoot -TasksRoot $resolvedInput -Limit $limit
}

$summary = [pscustomobject]@{
    timestamp_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    inputs = [ordered]@{
        tasks_root = "$resolvedInput"
    }
    runs = $runs
}

$summaryPath = Join-Path $outDir "scheduled_tasks_benchmark_summary.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding UTF8
Write-Host "Scheduled tasks benchmark summary written to: $summaryPath" -ForegroundColor Green
Write-Output $summaryPath
