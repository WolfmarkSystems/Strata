@echo off
echo ==========================================
echo DFIR KB Bridge - Restart
echo ==========================================
echo.

echo Stopping KB Bridge...
call "D:\DFIR Coding AI\scripts\stop_kb_bridge.bat"
timeout /t 1 /nobreak >NUL

echo Starting KB Bridge...
call "D:\DFIR Coding AI\scripts\start_kb_bridge.bat"
timeout /t 1 /nobreak >NUL

echo Done.
echo.
call "D:\DFIR Coding AI\scripts\status_kb_bridge.bat"
