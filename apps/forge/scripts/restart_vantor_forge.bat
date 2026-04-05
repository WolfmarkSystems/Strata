@echo off
set "ROOT=%~dp0.."

echo ==========================================
echo Vantor Forge - Restart (Ollama)
echo ==========================================
echo.

echo Stopping service...
call "%ROOT%\scripts\stop_vantor_forge.bat"
timeout /t 2 /nobreak >NUL

echo Starting service...
call "%ROOT%\scripts\start_vantor_forge.bat"
timeout /t 1 /nobreak >NUL

echo Done.
echo.
call "%ROOT%\scripts\status_vantor_forge.bat"
