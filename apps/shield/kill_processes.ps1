# Kill processes holding build files
Get-Process | Where-Object { $_.MainWindowTitle -like '*forensic*' -or $_.Name -like '*vantorshield*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "Done killing processes"
