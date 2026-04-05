@echo off
setlocal

if "%DFIR_ROOT%"=="" (
    set "ROOT=%~dp0.."
) else (
    set "ROOT=%DFIR_ROOT%"
)

call "%ROOT%\scripts\start_kb_bridge.bat"
exit /b %errorlevel%
