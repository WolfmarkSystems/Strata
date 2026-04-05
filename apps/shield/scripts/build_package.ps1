param(
    [string]$Version,
    [string]$OutputRoot = "dist"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$distRoot = Join-Path $repoRoot $OutputRoot

function Get-CargoTomlVersion {
    param([string]$CargoTomlPath)

    $match = Select-String -Path $CargoTomlPath -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $match) {
        throw "Unable to determine version from $CargoTomlPath"
    }

    return $match.Matches[0].Groups[1].Value
}

if (-not $Version) {
    $Version = Get-CargoTomlVersion (Join-Path $repoRoot "crates\vantor-shield-cli\Cargo.toml")
}

$packageRoot = Join-Path $distRoot ("vantor_{0}" -f $Version)
$binDir = Join-Path $packageRoot "bin"
$docsDir = Join-Path $packageRoot "docs\guardian"
$scriptsDir = Join-Path $packageRoot "scripts"

$cliSource = Join-Path $repoRoot "target\release\vantor.exe"
$cliDest = Join-Path $binDir "forensic_cli.exe"
$guiCargoManifest = Join-Path $repoRoot "apps\shield\gui\src-tauri\Cargo.toml"
$guiFrontendDir = Join-Path $repoRoot "apps\shield\gui"
$guardianDir = Join-Path $repoRoot "apps\shield\guardian"
$readmeCandidates = @(
    (Join-Path $repoRoot "README.md"),
    (Join-Path $repoRoot "apps\shield\README.md")
)
$readmePath = $readmeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $readmePath) {
    throw "Unable to locate README.md for packaging"
}
$manifestPath = Join-Path $packageRoot "MANIFEST.json"

Write-Host "=== Building Vantor Portable Package ===" -ForegroundColor Cyan
Write-Host "Repo root: $repoRoot"
Write-Host "Version: $Version"

Push-Location $repoRoot
try {
    Write-Host "Building Rust workspace (release)..." -ForegroundColor Yellow
    cargo build --workspace --release
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build --workspace --release failed"
    }

    $guiSourceCandidates = New-Object System.Collections.Generic.List[string]

    if ((Test-Path $guiFrontendDir) -and (Test-Path $guiCargoManifest)) {
        Write-Host "Building GUI frontend assets..." -ForegroundColor Yellow
        Push-Location $guiFrontendDir
        try {
            npm run build
            if ($LASTEXITCODE -ne 0) {
                throw "npm run build failed in $guiFrontendDir"
            }
        }
        finally {
            Pop-Location
        }

        Write-Host "Building GUI release binary..." -ForegroundColor Yellow
        cargo build --manifest-path $guiCargoManifest --release
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "GUI cargo build failed; falling back to existing GUI binaries if available"
        }

        $guiSourceCandidates.Add((Join-Path $repoRoot "apps\shield\gui\src-tauri\target\release\vantorshield.exe"))
        $guiSourceCandidates.Add((Join-Path $repoRoot "apps\shield\gui\src-tauri\target\release\forensic-suite-gui.exe"))
        $guiSourceCandidates.Add((Join-Path $repoRoot "apps\shield\gui\src-tauri\target\release\vantor-shield.exe"))
    }

    $guiSourceCandidates.Add((Join-Path $repoRoot "apps\shield\gui-tauri\src-tauri\target\release\forensic-suite-gui.exe"))
    $guiSourceCandidates.Add((Join-Path $repoRoot "apps\shield\gui-tauri\src-tauri\target\release\vantor-shield.exe"))
    $guiSourceCandidates.Add((Join-Path $repoRoot "apps\shield\final_version\VantorShield.exe"))

    $guiSource = $guiSourceCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $guiSource) {
        throw "Unable to locate a GUI executable after build. Checked: $($guiSourceCandidates -join '; ')"
    }

    $resolvedPackageRoot = [System.IO.Path]::GetFullPath($packageRoot)
    $resolvedDistRoot = [System.IO.Path]::GetFullPath($distRoot)
    if (-not $resolvedPackageRoot.StartsWith($resolvedDistRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove package path outside dist root: $resolvedPackageRoot"
    }

    if (Test-Path $packageRoot) {
        Remove-Item -LiteralPath $packageRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    New-Item -ItemType Directory -Path $docsDir -Force | Out-Null
    New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null

    if (-not (Test-Path $cliSource)) {
        throw "CLI binary not found at $cliSource"
    }

    Copy-Item -LiteralPath $cliSource -Destination $cliDest -Force
    Copy-Item -LiteralPath $guiSource -Destination (Join-Path $packageRoot "vantor-shield.exe") -Force
    Copy-Item -LiteralPath $readmePath -Destination (Join-Path $packageRoot "README.md") -Force

    Get-ChildItem -LiteralPath $guardianDir -Filter *.md -File | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $docsDir $_.Name) -Force
    }

    @"
`$scriptDir = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$root = (Resolve-Path (Join-Path `$scriptDir '..')).Path
`$gui = Join-Path `$root 'vantor-shield.exe'
if (-not (Test-Path `$gui)) {
    throw "GUI executable not found at `$gui"
}
Start-Process -FilePath `$gui | Out-Null
"@ | Set-Content -LiteralPath (Join-Path $scriptsDir "start_vantor.ps1") -Encoding utf8

    @"
param(
    [Parameter(ValueFromRemainingArguments = `$true)]
    [string[]]`$CliArgs
)

`$scriptDir = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$root = (Resolve-Path (Join-Path `$scriptDir '..')).Path
`$binDir = Join-Path `$root 'bin'
`$cli = Join-Path `$binDir 'forensic_cli.exe'
if (-not (Test-Path `$cli)) {
    throw "CLI executable not found at `$cli"
}
`$env:Path = "`$binDir;`$env:Path"
& `$cli @CliArgs
exit `$LASTEXITCODE
"@ | Set-Content -LiteralPath (Join-Path $scriptsDir "run_cli.ps1") -Encoding utf8

    $expectedFiles = @(
        $cliDest,
        (Join-Path $packageRoot "vantor-shield.exe"),
        (Join-Path $packageRoot "README.md"),
        (Join-Path $scriptsDir "start_vantor.ps1"),
        (Join-Path $scriptsDir "run_cli.ps1")
    )

    foreach ($expected in $expectedFiles) {
        if (-not (Test-Path $expected)) {
            throw "Expected package file missing: $expected"
        }
    }

    $packageFiles = Get-ChildItem -LiteralPath $packageRoot -Recurse -File | Where-Object {
        $_.Extension -ne '.gguf' -and $_.FullName -notmatch '\\target\\' -and $_.FullName -notmatch '\\node_modules\\'
    } | Sort-Object FullName

    $fileEntries = foreach ($file in $packageFiles) {
        [pscustomobject]@{
            path = $file.FullName.Substring($packageRoot.Length + 1).Replace('\\', '/')
            size_bytes = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        }
    }

    $cliHash = (Get-FileHash -LiteralPath $cliDest -Algorithm SHA256).Hash

    $manifest = [pscustomobject]@{
        package_name = "vantor"
        version = $Version
        generated_utc = (Get-Date).ToUniversalTime().ToString('o')
        package_root = (Split-Path -Leaf $packageRoot)
        cli_sha256 = $cliHash
        total_files = $fileEntries.Count
        files = $fileEntries
    }

    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8

    Write-Host ("Package built: {0}" -f $packageRoot) -ForegroundColor Green
    Write-Host ("forensic_cli.exe SHA-256: {0}" -f $cliHash) -ForegroundColor Green
    Write-Host ("Total files: {0}" -f $fileEntries.Count) -ForegroundColor Green
}
finally {
    Pop-Location
}



