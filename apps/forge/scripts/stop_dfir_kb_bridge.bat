@echo off
setlocal

REM Kill common python process names (only if they are hosting our bridge)
REM Simple version: kill python running the bridge by image name.
REM If you want PID-specific later, we can tighten it.

taskkill /IM python3.13.exe /F >NUL 2>&1
taskkill /IM python.exe /F >NUL 2>&1
taskkill /IM pythonw.exe /F >NUL 2>&1

echo [OK] Stop requested (python processes targeted).
exit /b 0
