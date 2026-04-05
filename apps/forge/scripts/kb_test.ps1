$ErrorActionPreference = "Stop"

Write-Host "== KB Bridge Health =="
$health = Invoke-RestMethod -Uri "http://127.0.0.1:8090/health" -Method Get -TimeoutSec 5
$health | ConvertTo-Json -Depth 5

Write-Host ""
Write-Host "== KB Bridge Search: NTFS parser =="
$searchBody = @{ query = "NTFS parser"; limit = 5 } | ConvertTo-Json
$search = Invoke-RestMethod -Uri "http://127.0.0.1:8090/search" -Method Post -ContentType "application/json" -Body $searchBody -TimeoutSec 10
$search | ConvertTo-Json -Depth 6

Write-Host ""
Write-Host "== KB Bridge Chat Forward =="
$chatBody = @{
    model = "local"
    messages = @(
        @{
            role = "user"
            content = "Reply with the exact text: Vantor Shield online."
        }
    )
    temperature = 0.1
    max_tokens = 32
} | ConvertTo-Json -Depth 5
$chat = Invoke-RestMethod -Uri "http://127.0.0.1:8090/chat" -Method Post -ContentType "application/json" -Body $chatBody -TimeoutSec 90
$chat.choices[0].message.content
