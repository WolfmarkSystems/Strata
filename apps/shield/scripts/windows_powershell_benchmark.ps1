param(
    [Parameter(Mandatory = $true)][string]$HistoryPath,
    [Parameter(Mandatory = $true)][string]$ScriptLogPath,
    [Parameter(Mandatory = $true)][string]$EventsPath,
    [Parameter(Mandatory = $true)][string]$TranscriptsDir,
    [Parameter(Mandatory = $true)][string]$ModulesPath,
    [string]$OutRoot = "_run/windows_roadmap/benchmarks"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-PowerShellArtifactsBench {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$HistoryPath,
        [Parameter(Mandatory = $true)][string]$ScriptLogPath,
        [Parameter(Mandatory = $true)][string]$EventsPath,
        [Parameter(Mandatory = $true)][string]$TranscriptsDir,
        [Parameter(Mandatory = $true)][string]$ModulesPath,
        [Parameter(Mandatory = $true)][int]$Limit
    )

    $argList = @(
        "run", "-q", "-p", "forensic_cli", "--",
        "powershell-artifacts",
        "--history", $HistoryPath,
        "--script-log", $ScriptLogPath,
        "--events", $EventsPath,
        "--transcripts-dir", $TranscriptsDir,
        "--modules", $ModulesPath,
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
$resolvedHistory = Resolve-Path $HistoryPath
$resolvedScriptLog = Resolve-Path $ScriptLogPath
$resolvedEvents = Resolve-Path $EventsPath
$resolvedTranscripts = Resolve-Path $TranscriptsDir
$resolvedModules = Resolve-Path $ModulesPath
$stamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd_HHmmss")
$outDir = Join-Path $repoRoot $OutRoot
$outDir = Join-Path $outDir $stamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$limits = @(200, 1000, 5000)
$runs = @()
foreach ($limit in $limits) {
    $runs += Invoke-PowerShellArtifactsBench -RepoRoot $repoRoot -HistoryPath $resolvedHistory -ScriptLogPath $resolvedScriptLog -EventsPath $resolvedEvents -TranscriptsDir $resolvedTranscripts -ModulesPath $resolvedModules -Limit $limit
}

$summary = [pscustomobject]@{
    timestamp_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    inputs = [ordered]@{
        history = "$resolvedHistory"
        script_log = "$resolvedScriptLog"
        events = "$resolvedEvents"
        transcripts_dir = "$resolvedTranscripts"
        modules = "$resolvedModules"
    }
    runs = $runs
}

$summaryPath = Join-Path $outDir "powershell_benchmark_summary.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding UTF8
Write-Host "PowerShell artifacts benchmark summary written to: $summaryPath" -ForegroundColor Green
Write-Output $summaryPath
