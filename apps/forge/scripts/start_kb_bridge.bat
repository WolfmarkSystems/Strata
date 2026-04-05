@echo off
setlocal

if "%DFIR_ROOT%"=="" (
    set "ROOT=%~dp0.."
) else (
    set "ROOT=%DFIR_ROOT%"
)

:: Ensure VANTOR_SUITE_ROOT points to the current project
if "%VANTOR_SUITE_ROOT%"=="" (
    set "VANTOR_SUITE_ROOT=D:\Vantor"
)

set "LOG=%ROOT%\logs"
set "KB=%ROOT%\bin\kb\dfir_kb_bridge.py"
set "WATCHER=%ROOT%\bin\kb\activity_watcher.py"

if not exist "%KB%" (
    echo [ERROR] KB bridge file missing: "%KB%"
    exit /b 1
)

if not exist "%LOG%" mkdir "%LOG%"

:: 1. Start KB Bridge
netstat -ano | findstr ":8090" >nul
if %errorlevel% equ 0 (
    echo [OK] KB bridge already running on port 8090
) else (
    echo [INFO] Starting KB Bridge...
    start "" /B python -u "%KB%" 1>> "%LOG%\kb_bridge_stdout.log" 2>> "%LOG%\kb_bridge_stderr.log"
)

:: 2. Start Activity Watcher
tasklist /FI "WINDOWTITLE eq VantorForgeWatcher" | find /I "python.exe" >nul
if %errorlevel% neq 0 (
    echo [INFO] Starting Activity Watcher...
    start "VantorForgeWatcher" /B python -u "%WATCHER%" 1>> "%LOG%\activity_watcher.log" 2>> "%LOG%\activity_watcher.err"
)

echo [OK] Vantor Intelligence Services started.
exit /b 0
