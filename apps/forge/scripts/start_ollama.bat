@echo off
setlocal EnableExtensions EnableDelayedExpansion

if "%DFIR_ROOT%"=="" (
    set "ROOT=%~dp0.."
) else (
    set "ROOT=%DFIR_ROOT%"
)

set "LOG=%ROOT%\logs"
set "MODEL=phi4-mini"

if not exist "%LOG%" mkdir "%LOG%"

netstat -ano | findstr ":11434" >nul
if %errorlevel% equ 0 (
    echo [OK] Ollama already running on port 11434
    exit /b 0
)

echo [INFO] Starting Ollama server
echo [INFO] Model: %MODEL%

:: Try to start Ollama tray app or server
start "" "ollama" serve

:: Wait for it to start
timeout /t 5 /nobreak >nul

netstat -ano | findstr ":11434" >nul
if %errorlevel% equ 0 (
    echo [OK] Ollama started successfully
    exit /b 0
) else (
    echo [ERROR] Failed to start Ollama. Please start it manually.
    exit /b 1
)
