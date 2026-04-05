@echo off
setlocal

echo ==========================================
echo DFIR KB Bridge - Restart
echo ==========================================
echo.

call "%~dp0stop_dfir_kb_bridge.bat"
timeout /t 1 >NUL
call "%~dp0start_dfir_kb_bridge.bat"

echo.
echo Done.
exit /b 0
