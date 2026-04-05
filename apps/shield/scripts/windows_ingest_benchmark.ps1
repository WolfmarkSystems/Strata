param(
  [string]$InputPath = ".\\evidence",
  [int]$Iterations = 5
)

$ErrorActionPreference = "Stop"
Write-Host "== Windows ingest benchmark =="
Write-Host "Input: $InputPath"
Write-Host "Iterations: $Iterations"

for ($i = 1; $i -le $Iterations; $i++) {
  $start = Get-Date
  cargo run -p forensic_cli -- ingest doctor --input $InputPath | Out-Null
  $elapsed = (Get-Date) - $start
  Write-Host ("Run {0}: {1} ms" -f $i, [int]$elapsed.TotalMilliseconds)
}

Write-Host "Benchmark complete."
