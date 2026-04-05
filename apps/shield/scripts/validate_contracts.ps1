param(
    [string]$Root = "."
)

$ErrorActionPreference = "Continue"
$rootPath = (Resolve-Path $Root).Path
$backendPath = Join-Path $rootPath "gui\src-tauri\src\lib.rs"
$frontendPath = Join-Path $rootPath "gui\src"

Write-Host "== Vantor Guardian: Contract Validator =="
Write-Host "Scanning backend: $backendPath"
Write-Host "Scanning frontend: $frontendPath"

if (-not (Test-Path $backendPath)) {
    Write-Error "Backend source not found at $backendPath"
    exit 1
}

# 1. Extract Backend Commands
$backendContent = [System.IO.File]::ReadAllText($backendPath)
$backendRegex = "#\[tauri::command\]\r?\n(?:async\s+)?fn\s+([a-z0-9_]+)"
$backendMatches = [regex]::Matches($backendContent, $backendRegex)
$backendCommands = $backendMatches | ForEach-Object { $_.Groups[1].Value } | Sort-Object | Unique

# 2. Extract Frontend Invokes
$frontendFiles = Get-ChildItem -Recurse -Path $frontendPath -File | Where-Object { $_.Extension -in ".tsx", ".ts" }
$frontendCommands = @()
$frontendRegex = "invoke(?:<[^>]*>)?\s*\(\s*['""]([a-zA-Z0-9_\-]+)['""]"

foreach ($file in $frontendFiles) {
    $text = [System.IO.File]::ReadAllText($file.FullName)
    $matches = [regex]::Matches($text, $frontendRegex)
    foreach ($m in $matches) {
        $frontendCommands += [PSCustomObject]@{
            Command = $m.Groups[1].Value
            File = $file.FullName -replace [regex]::Escape($rootPath), ""
        }
    }
}

$uniqueFrontend = $frontendCommands | Select-Object -ExpandProperty Command -Unique | Sort-Object

# 3. Cross-Reference
$missingInBackend = @()
foreach ($cmd in $uniqueFrontend) {
    if ($cmd -notin $backendCommands) {
        $missingInBackend += $cmd
    }
}

$unusedInFrontend = @()
foreach ($cmd in $backendCommands) {
    if ($cmd -notin $uniqueFrontend) {
        $unusedInFrontend += $cmd
    }
}

# 4. Report
Write-Host ""
Write-Host "--- Summary ---"
Write-Host "Total Backend Commands: $($backendCommands.Count)"
Write-Host "Total Frontend Invokes: $($uniqueFrontend.Count)"

Write-Host ""
if ($missingInBackend.Count -gt 0) {
    Write-Host "[!] MISSING IN BACKEND (Frontend calls these, but backend lacks implementation):" -ForegroundColor Red
    $missingInBackend | ForEach-Object { Write-Host "  - $_" }
} else {
    Write-Host "[+] All frontend invokes have backend implementations." -ForegroundColor Green
}

Write-Host ""
if ($unusedInFrontend.Count -gt 0) {
    Write-Host "[i] UNUSED IN FRONTEND (Backend provides these, but frontend doesn't call them):" -ForegroundColor Yellow
    $unusedInFrontend | ForEach-Object { 
        if ($_ -eq "greet") {
            Write-Host "  - $_ (PLACEHOLDER)" -ForegroundColor Gray
        } else {
            Write-Host "  - $_" 
        }
    }
}

# 5. Export JSON Report
$report = [PSCustomObject]@{
    Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    BackendCommands = $backendCommands
    FrontendInvokes = $uniqueFrontend
    MissingInBackend = $missingInBackend
    UnusedInFrontend = $unusedInFrontend
}

$reportDir = Join-Path $rootPath "guardian"
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory $reportDir | Out-Null }
$reportPath = Join-Path $reportDir "contract_validation_report.json"
$report | ConvertTo-Json -Depth 5 | Out-File $reportPath -Encoding utf8

Write-Host ""
Write-Host "Wrote report to $reportPath"

if ($missingInBackend.Count -gt 0) {
    exit 1
}
exit 0
