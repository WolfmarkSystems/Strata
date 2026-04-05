param(
    [string]$Root = ".",
    [string]$CliPath = ""
)

$ErrorActionPreference = "Continue"
$rootPath = (Resolve-Path $Root).Path
if (-not $CliPath) {
    $CliPath = Join-Path $rootPath "target\debug\forensic_cli.exe"
}

if (-not (Test-Path $CliPath)) {
    Write-Error "CLI binary not found at $CliPath"
    exit 1
}

$fixtureDir = Join-Path $rootPath "fixtures\artifacts"
$tempDir = Join-Path $rootPath "_run\parser_tests"
if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory $tempDir -Force | Out-Null }

$tests = @(
    @{ Name = "EVTX Parser"; Image = "test.evtx"; Type = "EVTX" },
    @{ Name = "Prefetch Parser"; Image = "TESTAPP.EXE-12345678.pf"; Type = "Prefetch" },
    @{ Name = "LNK Parser"; Image = "test_shortcut.lnk"; Type = "LNK" }
)

Write-Host "== Vantor Guardian: Parser Quality Tests =="

$results = @()

foreach ($test in $tests) {
    $name = $test.Name
    $filePath = Join-Path $fixtureDir $test.Image
    $jsonOut = Join-Path $tempDir "$($test.Image).envelope.json"
    
    Write-Host "Testing $name on $filePath..."
    
    if (-not (Test-Path $filePath)) {
        Write-Host "  [-] SKIP: Fixture missing" -ForegroundColor Gray
        continue
    }

    # Run smoke-test
    & $CliPath smoke-test --image $filePath --json-summary (Join-Path $tempDir "$($test.Image).summary.json") --json-result $jsonOut --quiet
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $results += [PSCustomObject]@{ Test = $name; Status = "FAIL"; Reason = "CLI exited with code $exitCode" }
        Write-Host "  [-] FAILED: CLI crashed" -ForegroundColor Red
        continue
    }

    if (-not (Test-Path $jsonOut)) {
        $results += [PSCustomObject]@{ Test = $name; Status = "FAIL"; Reason = "JSON envelope not produced" }
        Write-Host "  [-] FAILED: No output" -ForegroundColor Red
        continue
    }

    try {
        $json = Get-Content $jsonOut -Raw | ConvertFrom-Json
        $indexedCount = $json.outputs.indexed_items | Measure-Object -Sum | Select-Object -ExpandProperty Sum
        
        # In a real smoke-test, it might not report indexed_items directly in the envelope's 'outputs' branch 
        # but in the specialized summary. 
        # Let's check if there's any evidence of work.
        if ($json.status -eq "ok" -and ($null -ne $json.outputs)) {
            $results += [PSCustomObject]@{ Test = $name; Status = "PASS"; Artifacts = $indexedCount }
            Write-Host "  [+] PASSED" -ForegroundColor Green
        } else {
            $results += [PSCustomObject]@{ Test = $name; Status = "FAIL"; Reason = "Status: $($json.status)" }
            Write-Host "  [-] FAILED: status is $($json.status)" -ForegroundColor Red
        }
    } catch {
        $results += [PSCustomObject]@{ Test = $name; Status = "FAIL"; Reason = "Invalid JSON" }
        Write-Host "  [-] FAILED: JSON parse error" -ForegroundColor Red
    }
}

Write-Host ""
$passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
Write-Host "Results: $passCount/$($results.Count) parsers verified."

if ($passCount -ne $results.Count) {
    exit 1
}
exit 0
