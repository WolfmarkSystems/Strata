param(
  [string]$WorkspaceRoot = ".",
  [switch]$SkipBenchmarks
)

$ErrorActionPreference = "Stop"

Write-Host "== Vantor Shield Quality Gate =="
Push-Location $WorkspaceRoot
try {
  Write-Host "[1/4] Running engine + cli tests"
  cargo test -p forensic_engine -p forensic_cli

  Write-Host "[2/4] Running parser drift check"
  $fixtureDir = Join-Path $WorkspaceRoot "tests\fixtures"
  if (!(Test-Path $fixtureDir)) {
    throw "Missing tests\fixtures directory"
  }

  Write-Host "[3/4] Checking ingest docs are present"
  $requiredDocs = @(
    "docs\ingestion-compatibility-matrix.md",
    "docs\parser-contract.md",
    "docs\canonical-model.md",
    "docs\validation-policy.md"
  )
  foreach ($doc in $requiredDocs) {
    if (!(Test-Path (Join-Path $WorkspaceRoot $doc))) {
      throw "Required documentation missing: $doc"
    }
  }

  if (-not $SkipBenchmarks) {
    Write-Host "[4/4] Running baseline timeline benchmark"
    & (Join-Path $WorkspaceRoot "scripts\windows_timeline_benchmark.ps1")
  } else {
    Write-Host "[4/4] Benchmarks skipped by flag"
  }

  Write-Host "Quality gate PASSED"
  exit 0
}
catch {
  Write-Error "Quality gate FAILED: $($_.Exception.Message)"
  exit 1
}
finally {
  Pop-Location
}
