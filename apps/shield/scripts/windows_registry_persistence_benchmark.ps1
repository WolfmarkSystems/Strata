param(
    [Parameter(Mandatory = $true)][string]$AutorunRegPath,
    [Parameter(Mandatory = $true)][string]$BamRegPath,
    [Parameter(Mandatory = $true)][string]$AmcacheRegPath,
    [Parameter(Mandatory = $true)][string]$TasksRootPath,
    [string]$OutRoot = "_run/windows_roadmap/benchmarks"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-RegistryPersistenceBench {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$AutorunRegPath,
        [Parameter(Mandatory = $true)][string]$BamRegPath,
        [Parameter(Mandatory = $true)][string]$AmcacheRegPath,
        [Parameter(Mandatory = $true)][string]$TasksRootPath,
        [Parameter(Mandatory = $true)][int]$Limit
    )

    $argList = @(
        "run", "-q", "-p", "forensic_cli", "--",
        "registry-persistence",
        "--autorun-reg", $AutorunRegPath,
        "--bam-reg", $BamRegPath,
        "--amcache-reg", $AmcacheRegPath,
        "--tasks-root", $TasksRootPath,
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
$resolvedAutorun = Resolve-Path $AutorunRegPath
$resolvedBam = Resolve-Path $BamRegPath
$resolvedAmcache = Resolve-Path $AmcacheRegPath
$resolvedTasksRoot = Resolve-Path $TasksRootPath
$stamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd_HHmmss")
$outDir = Join-Path $repoRoot $OutRoot
$outDir = Join-Path $outDir $stamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$limits = @(200, 1000, 5000)
$runs = @()
foreach ($limit in $limits) {
    $runs += Invoke-RegistryPersistenceBench -RepoRoot $repoRoot -AutorunRegPath $resolvedAutorun -BamRegPath $resolvedBam -AmcacheRegPath $resolvedAmcache -TasksRootPath $resolvedTasksRoot -Limit $limit
}

$summary = [pscustomobject]@{
    timestamp_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    inputs = [ordered]@{
        autorun = "$resolvedAutorun"
        bam = "$resolvedBam"
        amcache = "$resolvedAmcache"
        tasks_root = "$resolvedTasksRoot"
    }
    runs = $runs
}

$summaryPath = Join-Path $outDir "registry_persistence_benchmark_summary.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding UTF8
Write-Host "Registry persistence benchmark summary written to: $summaryPath" -ForegroundColor Green
Write-Output $summaryPath
