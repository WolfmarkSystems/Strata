$ErrorActionPreference = "Stop"

$uri = "http://127.0.0.1:11434/"

Write-Host "=========================================="
Write-Host "Vantor AI (OLLAMA) - Health Check"
Write-Host "=========================================="
Write-Host ""

try {
    $resp = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 3
    Write-Host "[OK] Ollama server responded"
    Write-Host ("StatusCode: " + $resp.StatusCode)
    Write-Host ("URL:     " + $uri)
    exit 0
}
catch {
    Write-Host "[FAIL] Ollama server did not respond at $uri"
    Write-Host ("Error: " + $_.Exception.Message)
    exit 1
}
