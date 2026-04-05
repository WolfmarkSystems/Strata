param(
    [Parameter(Mandatory = $true)][string]$Input,
    [string]$OutRoot = "_run/windows_roadmap/benchmarks"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-PrefetchBench {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Input,
        [Parameter(Mandatory = $true)][int]$Limit
    )

    $argList = @(
        "run", "-q", "-p", "forensic_cli", "--",
        "prefetch-fidelity",
        "--input", $Input,
        "--limit", "$Limit",
        "--json",
        "--quiet"
    )

    Push-Location $RepoRoot
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $stdoutFile = [System.IO.Path]::GetTempFileName()
        $stderrFile = [System.IO.Path]::GetTempFileName()
        $proc = Start-Process -FilePath "cargo" -ArgumentList $argList -PassThru -NoNewWindow -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
        $proc.WaitForExit()
        $sw.Stop()

        [pscustomobject]@{
            limit = $Limit
            exit_code = $proc.ExitCode
            elapsed_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            peak_working_set_bytes = $proc.PeakWorkingSet64
        }
    }
    finally {
        if (Test-Path $stdoutFile) { Remove-Item -Force $stdoutFile -ErrorAction SilentlyContinue }
        if (Test-Path $stderrFile) { Remove-Item -Force $stderrFile -ErrorAction SilentlyContinue }
        Pop-Location
    }
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$resolvedInput = Resolve-Path $Input
$stamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd_HHmmss")
$outDir = Join-Path $repoRoot $OutRoot
$outDir = Join-Path $outDir $stamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$limits = @(200, 1000, 5000)
$runs = @()
foreach ($limit in $limits) {
    $runs += Invoke-PrefetchBench -RepoRoot $repoRoot -Input $resolvedInput -Limit $limit
}

$summary = [pscustomobject]@{
    timestamp_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    inputs = [ordered]@{ input = "$resolvedInput" }
    runs = $runs
}

$summaryPath = Join-Path $outDir "prefetch_fidelity_benchmark_summary.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding UTF8
Write-Host "Prefetch fidelity benchmark summary written to: $summaryPath" -ForegroundColor Green
Write-Output $summaryPath
