param(
    [string]$OutRoot = "_run/windows_roadmap/snapshots"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-CliSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$OutDir,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Args
    )

    $outFile = Join-Path $OutDir "$Name.out"
    $cmd = "cd /d `"$RepoRoot`" && cargo run -q -p forensic_cli -- $Args > `"$outFile`" 2>&1"
    & cmd.exe /d /c $cmd | Out-Null
    $exitCode = $LASTEXITCODE

    $hash = $null
    if (Test-Path -LiteralPath $outFile) {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $outFile).Hash
    }

    return [pscustomobject]@{
        name = $Name
        args = $Args
        exit_code = $exitCode
        output_file = $outFile
        sha256 = $hash
    }
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$stamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd_HHmmss")
$outDir = Join-Path $repoRoot $OutRoot
$outDir = Join-Path $outDir $stamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$runs = @()
$runs += Invoke-CliSnapshot -RepoRoot $repoRoot -OutDir $outDir -Name "capabilities_json" -Args "capabilities --json"
$runs += Invoke-CliSnapshot -RepoRoot $repoRoot -OutDir $outDir -Name "doctor_json" -Args "doctor --json"
$runs += Invoke-CliSnapshot -RepoRoot $repoRoot -OutDir $outDir -Name "timeline_help" -Args "timeline --help"
$runs += Invoke-CliSnapshot -RepoRoot $repoRoot -OutDir $outDir -Name "registry_persistence_help" -Args "registry-persistence --help"
$runs += Invoke-CliSnapshot -RepoRoot $repoRoot -OutDir $outDir -Name "execution_correlation_help" -Args "execution-correlation --help"
$runs += Invoke-CliSnapshot -RepoRoot $repoRoot -OutDir $outDir -Name "recent_execution_help" -Args "recent-execution --help"
$runs += Invoke-CliSnapshot -RepoRoot $repoRoot -OutDir $outDir -Name "violations_help" -Args "violations --help"

$summary = [pscustomobject]@{
    timestamp_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    out_dir = $outDir
    runs = $runs
}

$summaryPath = Join-Path $outDir "cli_snapshot_summary.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding UTF8
Write-Host "CLI snapshot summary written to: $summaryPath" -ForegroundColor Green
Write-Output $summaryPath
