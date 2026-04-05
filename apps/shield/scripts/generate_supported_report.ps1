param(
  [string]$OutputPath = ".\\exports\\supported-validated-formats.json"
)

$ErrorActionPreference = "Stop"

Write-Host "Generating supported + validated formats report..."
$matrix = cargo run -p forensic_cli -- ingest matrix --json | Out-String
$payload = @{
  generated_utc = (Get-Date).ToUniversalTime().ToString("o")
  tool = "vantor-shield"
  matrix = ($matrix | ConvertFrom-Json)
}

$dir = Split-Path -Parent $OutputPath
if ($dir -and !(Test-Path $dir)) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

$payload | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Report written to $OutputPath"
