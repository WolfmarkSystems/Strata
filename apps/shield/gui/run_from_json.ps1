# run_from_json.ps1
# Reads a request JSON file from gui/fixtures/, translates to CLI, runs forensic_cli.exe
#
# Usage:
#   .\gui\run_from_json.ps1 -RequestPath .\gui\fixtures\capabilities_request.json
#   .\gui\run_from_json.ps1 -RequestPath .\gui\fixtures\smoke_test_request.json
#   .\gui\run_from_json.ps1 -RequestPath .\gui\fixtures\doctor_request.json
#   .\gui\run_from_json.ps1 -RequestPath .\gui\fixtures\verify_request.json
#   .\gui\run_from_json.ps1 -RequestPath .\gui\fixtures\export_request.json
#   .\gui\run_from_json.ps1 -RequestPath .\gui\fixtures\triage_session_request.json

param(
    [Parameter(Mandatory=$true)]
    [string]$RequestPath
)

$ErrorActionPreference = "Stop"

$repoRoot = "D:\forensic-suite"
$configPath = Join-Path $repoRoot "gui\config\gui_runtime.json"

if (-not (Test-Path $configPath)) {
    Write-Error "Config file not found: $configPath"
    exit 1
}

$config = Get-Content $configPath -Raw | ConvertFrom-Json
$cliExe = $config.cli_release_exe
$repoRoot = $config.repo_root

if (-not (Test-Path $cliExe)) {
    Write-Error "CLI executable not found: $cliExe"
    exit 1
}

if (-not (Test-Path $RequestPath)) {
    Write-Error "Request file not found: $RequestPath"
    exit 1
}

$request = Get-Content $RequestPath -Raw | ConvertFrom-Json

$command = $request.command
$argsList = @()

switch ($command) {
    "capabilities" {
        $argsList += "capabilities"
        if ($request.quiet -eq $true) { $argsList += "--quiet" }
    }
    "doctor" {
        $argsList += "doctor"
        if ($request.verbose -eq $true) { $argsList += "--verbose" }
        if ($request.quiet -eq $true) { $argsList += "--quiet" }
    }
    "smoke-test" {
        $argsList += "smoke-test"
        $argsList += "--image"
        $argsList += $request.image_path
        $argsList += "--out"
        $argsList += $request.out_dir
        $argsList += "--mft"
        $argsList += $request.mft_count
        if ($request.timeline_enabled -eq $false) { $argsList += "--no-timeline" }
        if ($request.audit_enabled -eq $false) { $argsList += "--no-audit" }
        if ($request.quiet -eq $true) { $argsList += "--quiet" }
    }
    "verify" {
        $argsList += "verify"
        $argsList += "--case"
        $argsList += $request.case_id
        $argsList += "--db"
        $argsList += $request.db_path
        $argsList += "--sample"
        $argsList += $request.sample
        if ($request.strict_fts -eq $true) { $argsList += "--strict-fts" }
        if ($request.quiet -eq $true) { $argsList += "--quiet" }
    }
    "export" {
        $argsList += "export"
        $argsList += "--case"
        $argsList += $request.case_id
        $argsList += "--db"
        $argsList += $request.db_path
        $argsList += "--output"
        $argsList += $request.output_dir
        if ($request.no_verify -eq $true) { $argsList += "--no-verify" }
        if ($request.strict -eq $true) { $argsList += "--strict" }
        if ($request.max_age_sec) { 
            $argsList += "--max-age"
            $argsList += $request.max_age_sec
        }
        if ($request.quiet -eq $true) { $argsList += "--quiet" }
    }
    "triage-session" {
        $argsList += "triage-session"
        $argsList += "--case"
        $argsList += $request.case_id
        $argsList += "--db"
        $argsList += $request.db_path
        if ($request.name) { 
            $argsList += "--name"
            $argsList += $request.name
        }
        if ($request.flags) {
            if ($request.flags.no_watchpoints -eq $true) { $argsList += "--no-watchpoints" }
            if ($request.flags.no_replay -eq $true) { $argsList += "--no-replay" }
            if ($request.flags.no_verify -eq $true) { $argsList += "--no-verify" }
            if ($request.flags.no_bundle -eq $true) { $argsList += "--no-bundle" }
            if ($request.flags.strict -eq $true) { $argsList += "--strict" }
        }
        if ($request.bundle_dir) { 
            $argsList += "--bundle-dir"
            $argsList += $request.bundle_dir
        }
        if ($request.sample) { 
            $argsList += "--sample"
            $argsList += $request.sample
        }
        if ($request.quiet -eq $true) { $argsList += "--quiet" }
    }
    default {
        Write-Error "Unknown command: $command"
        exit 1
    }
}

if ($request.json_result_path) {
    $argsList += "--json-result"
    $argsList += $request.json_result_path
}

if ($request.out_dir) {
    $outDir = $request.out_dir
    if (-not [System.IO.Path]::IsPathRooted($outDir)) {
        $outDir = Join-Path $repoRoot $outDir
    }
    $outDirParent = Split-Path $outDir -Parent
    if ($outDirParent -and -not (Test-Path $outDirParent)) {
        New-Item -ItemType Directory -Path $outDirParent -Force | Out-Null
    }
}

if ($request.json_result_path) {
    $jsonPath = $request.json_result_path
    if (-not [System.IO.Path]::IsPathRooted($jsonPath)) {
        $jsonPath = Join-Path $repoRoot $jsonPath
    }
    $jsonParent = Split-Path $jsonPath -Parent
    if ($jsonParent -and -not (Test-Path $jsonParent)) {
        New-Item -ItemType Directory -Path $jsonParent -Force | Out-Null
    }
}

if ($request.output_dir) {
    $outDir = $request.output_dir
    if (-not [System.IO.Path]::IsPathRooted($outDir)) {
        $outDir = Join-Path $repoRoot $outDir
    }
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
}

if ($request.db_path) {
    $dbPath = $request.db_path
    if (-not [System.IO.Path]::IsPathRooted($dbPath)) {
        $dbPath = Join-Path $repoRoot $dbPath
    }
    $dbParent = Split-Path $dbPath -Parent
    if ($dbParent -and -not (Test-Path $dbParent)) {
        New-Item -ItemType Directory -Path $dbParent -Force | Out-Null
    }
}

if ($request.bundle_dir) {
    $bundleDir = $request.bundle_dir
    if (-not [System.IO.Path]::IsPathRooted($bundleDir)) {
        $bundleDir = Join-Path $repoRoot $bundleDir
    }
    if (-not (Test-Path $bundleDir)) {
        New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null
    }
}

$fullCommand = "$cliExe $($argsList -join ' ')"
Write-Host "Running: $fullCommand"
Write-Host ""

& $cliExe $argsList
$exitCode = $LASTEXITCODE

Write-Host ""
Write-Host "Exit code: $exitCode"

if ($request.json_result_path) {
    $jsonPath = $request.json_result_path
    if (-not [System.IO.Path]::IsPathRooted($jsonPath)) {
        $jsonPath = Join-Path $repoRoot $jsonPath
    }
    Write-Host "JSON result: $jsonPath"
}

exit $exitCode
