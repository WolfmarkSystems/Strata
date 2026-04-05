@echo off
setlocal

echo ==========================================
echo Vantor AI - OLLAMA Status
echo ==========================================
echo.

tasklist /FI "IMAGENAME eq ollama.exe" | find /I "ollama.exe" >NUL
if errorlevel 1 (
    echo [STOPPED] ollama.exe is NOT running
    echo.
    endlocal
    exit /b 0
)

echo [OK] ollama.exe is RUNNING
echo.
echo Process details:
tasklist /FI "IMAGENAME eq ollama.exe"
echo.
echo Listening ports (Expected 11434):
netstat -ano | findstr /I "11434"
echo.
echo Endpoint:
echo http://127.0.0.1:11434
echo.

endlocal
