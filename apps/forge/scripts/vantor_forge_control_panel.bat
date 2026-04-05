@echo off
setlocal
set "ROOT=%~dp0.."
set "SCRIPTS=%ROOT%\scripts"
set "URL=http://127.0.0.1:11434"
set "CHATPAGE=%ROOT%\ui\dfir_chat.html"

:menu
cls
echo ==========================================
echo Vantor AI - Forge Control Panel (PHI4)
echo ==========================================
echo.
echo 1) Start (Ollama)
echo 2) Stop  (Ollama)
echo 3) Restart (Ollama)
echo 4) Status (Ollama)
echo 5) Health Check (Ollama)
echo 6) Open Ollama API (Browser)
echo 7) Open Vantor Chat Page
echo.
echo 8) Start KB Bridge (Knowledge Base)
echo 9) Stop  KB Bridge
echo 10) Restart KB Bridge
echo 11) Status KB Bridge
echo.
echo 0) Exit
echo.

set /p choice=Select an option: 

if "%choice%"=="1" goto do_start
if "%choice%"=="2" goto do_stop
if "%choice%"=="3" goto do_restart
if "%choice%"=="4" goto do_status
if "%choice%"=="5" goto do_health
if "%choice%"=="6" goto do_open
if "%choice%"=="7" goto do_chat
if "%choice%"=="8" goto do_kb_start
if "%choice%"=="9" goto do_kb_stop
if "%choice%"=="10" goto do_kb_restart
if "%choice%"=="11" goto do_kb_status
if "%choice%"=="0" goto end

echo.
echo Invalid selection. Press any key to try again...
pause >NUL
goto menu

:do_start
call "%SCRIPTS%\start_vantor_forge.bat"
echo.
echo Press any key to return to menu...
pause >NUL
goto menu

:do_stop
call "%SCRIPTS%\stop_vantor_forge.bat"
echo.
echo Press any key to return to menu...
pause >NUL
goto menu

:do_restart
call "%SCRIPTS%\restart_vantor_forge.bat"
echo.
echo Press any key to return to menu...
pause >NUL
goto menu

:do_status
call "%SCRIPTS%\status_vantor_forge.bat"
echo.
echo Press any key to return to menu...
pause >NUL
goto menu

:do_health
call "%SCRIPTS%\health_vantor_forge.bat"
echo.
echo Press any key to return to menu...
pause >NUL
goto menu

:do_open
start "" "%URL%"
echo.
echo Opened: %URL%
echo Press any key to return to menu...
pause >NUL
goto menu

:do_chat
if exist "%CHATPAGE%" (
  start "" "%CHATPAGE%"
  echo.
  echo Opened: %CHATPAGE%
) else (
  echo.
  echo Chat page not found:
  echo %CHATPAGE%
)
echo Press any key to return to menu...
pause >NUL
goto menu

:do_kb_start
call "%SCRIPTS%\start_kb_bridge.bat"
echo.
call "%SCRIPTS%\status_kb_bridge.bat"
echo Press any key to return to menu...
pause >NUL
goto menu

:do_kb_stop
call "%SCRIPTS%\stop_kb_bridge.bat"
echo.
call "%SCRIPTS%\status_kb_bridge.bat"
echo Press any key to return to menu...
pause >NUL
goto menu

:do_kb_restart
call "%SCRIPTS%\restart_kb_bridge.bat"
echo.
echo Press any key to return to menu...
pause >NUL
goto menu

:do_kb_status
call "%SCRIPTS%\status_kb_bridge.bat"
echo.
echo Press any key to return to menu...
pause >NUL
goto menu

:end
endlocal
exit /b 0
