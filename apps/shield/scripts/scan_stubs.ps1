param(
    [switch]$CreateBaseline
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$cratesRoot = Join-Path $repoRoot 'crates'
$guardianDir = Join-Path $repoRoot 'apps\shield\guardian'
$reportPath = Join-Path $guardianDir 'stub_report.json'
$baselinePath = Join-Path $guardianDir 'stub_baseline.json'

if (-not (Test-Path $guardianDir)) {
    New-Item -ItemType Directory -Path $guardianDir -Force | Out-Null
}

function Get-LineNumber {
    param(
        [string]$Text,
        [int]$Index
    )

    return (($Text.Substring(0, $Index) -split "`n").Count)
}

function New-MatchRecord {
    param(
        [string]$FilePath,
        [string]$RepoRoot,
        [string]$Type,
        [string]$Content,
        [int]$Line
    )

    return [PSCustomObject]@{
        file = $FilePath.Replace($RepoRoot + '\', '').Replace('\', '/')
        line = $Line
        type = $Type
        content = (($Content -replace '\s+', ' ').Trim())
    }
}

$dangerous = New-Object System.Collections.Generic.List[object]
$stubMarkers = New-Object System.Collections.Generic.List[object]

$errToEmptyPattern = 'Err\([^)]*\)\s*=>\s*\{[\s\S]{0,400}?Ok\(Vec::new\(\)\)'
$errCatchAllPattern = 'Err\(_\)\s*=>\s*return\s+Ok\('
$stubPattern = 'STUB:'

Get-ChildItem -LiteralPath $cratesRoot -Recurse -Filter '*.rs' -File | ForEach-Object {
    $filePath = $_.FullName
    try {
        $text = Get-Content -LiteralPath $filePath -Raw -Encoding utf8 -ErrorAction Stop
    }
    catch {
        return
    }

    if ($null -eq $text) {
        return
    }

    foreach ($match in [regex]::Matches($text, $errToEmptyPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)) {
        $dangerous.Add((New-MatchRecord -FilePath $filePath -RepoRoot $repoRoot -Type 'err_to_empty_vec' -Content $match.Value -Line (Get-LineNumber -Text $text -Index $match.Index)))
    }

    foreach ($match in [regex]::Matches($text, $errCatchAllPattern)) {
        $dangerous.Add((New-MatchRecord -FilePath $filePath -RepoRoot $repoRoot -Type 'err_catchall_ok_return' -Content $match.Value -Line (Get-LineNumber -Text $text -Index $match.Index)))
    }

    foreach ($match in [regex]::Matches($text, $stubPattern)) {
        $stubMarkers.Add((New-MatchRecord -FilePath $filePath -RepoRoot $repoRoot -Type 'stub_marker' -Content 'STUB:' -Line (Get-LineNumber -Text $text -Index $match.Index)))
    }
}

$dangerousRecords = $dangerous | Sort-Object file, line, type -Unique
$stubRecords = $stubMarkers | Sort-Object file, line, type -Unique

$report = [ordered]@{
    scan_date = (Get-Date).ToString('yyyy-MM-dd')
    dangerous_empty_returns = @($dangerousRecords)
    stub_markers = @($stubRecords)
    total_dangerous = @($dangerousRecords).Count
    total_stubs = @($stubRecords).Count
}

$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding utf8

if ($CreateBaseline) {
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $baselinePath -Encoding utf8
    Write-Host "Baseline created: $baselinePath"
    Write-Host "$($report.total_dangerous) dangerous patterns (baseline: $($report.total_dangerous)). Delta: +0"
    exit 0
}

if (-not (Test-Path $baselinePath)) {
    Write-Host "Baseline missing: $baselinePath"
    Write-Host 'Run scan_stubs.ps1 -CreateBaseline to create the initial baseline.'
    exit 1
}

$baseline = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
$baselineDangerous = [int]$baseline.total_dangerous
$currentDangerous = [int]$report.total_dangerous
$delta = $currentDangerous - $baselineDangerous
$deltaDisplay = if ($delta -ge 0) { "+$delta" } else { "$delta" }

Write-Host "$currentDangerous dangerous patterns (baseline: $baselineDangerous). Delta: $deltaDisplay"
Write-Host "Stub markers: $($report.total_stubs)"
Write-Host "Report written: $reportPath"

if ($currentDangerous -gt $baselineDangerous) {
    exit 1
}

