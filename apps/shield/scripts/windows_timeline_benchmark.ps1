param(
    [Parameter(Mandatory = $true)][string]$CaseId,
    [Parameter(Mandatory = $true)][string]$DbPath,
    [string]$FromUtc = "",
    [string]$ToUtc = "",
    [string]$OutRoot = "_run/windows_roadmap/benchmarks"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-TimelineBench {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$CaseId,
        [Parameter(Mandatory = $true)][string]$DbPath,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][int]$Limit,
        [string]$FromUtc = "",
        [string]$ToUtc = ""
    )

    $argList = @(
        "run", "-q", "-p", "forensic_cli", "--",
        "timeline",
        "--case", $CaseId,
        "--db", $DbPath,
        "--source", $Source,
        "--limit", "$Limit",
        "--json",
        "--quiet"
    )
    if (-not [string]::IsNullOrWhiteSpace($FromUtc)) {
        $argList += @("--from", $FromUtc)
    }
    if (-not [string]::IsNullOrWhiteSpace($ToUtc)) {
        $argList += @("--to", $ToUtc)
    }

    Push-Location $RepoRoot
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & cargo @argList | Out-Null
        $exitCode = $LASTEXITCODE
        $sw.Stop()
    }
    finally {
        Pop-Location
    }

    [pscustomobject]@{
        source = $Source
        limit = $Limit
        exit_code = $exitCode
        elapsed_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
    }
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$stamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd_HHmmss")
$outDir = Join-Path $repoRoot $OutRoot
$outDir = Join-Path $outDir $stamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$matrix = @(
    @{ source = "all"; limit = 200 },
    @{ source = "all"; limit = 1000 },
    @{ source = "activity"; limit = 500 },
    @{ source = "evidence"; limit = 500 },
    @{ source = "violations"; limit = 500 },
    @{ source = "execution"; limit = 500 }
)

$runs = @()
foreach ($row in $matrix) {
    $runs += Invoke-TimelineBench -RepoRoot $repoRoot -CaseId $CaseId -DbPath $DbPath -Source $row.source -Limit $row.limit -FromUtc $FromUtc -ToUtc $ToUtc
}

$summary = [pscustomobject]@{
    timestamp_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    case_id = $CaseId
    db_path = $DbPath
    from_utc = if ([string]::IsNullOrWhiteSpace($FromUtc)) { $null } else { $FromUtc }
    to_utc = if ([string]::IsNullOrWhiteSpace($ToUtc)) { $null } else { $ToUtc }
    runs = $runs
}

$summaryPath = Join-Path $outDir "timeline_benchmark_summary.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding UTF8
Write-Host "Timeline benchmark summary written to: $summaryPath" -ForegroundColor Green
Write-Output $summaryPath
