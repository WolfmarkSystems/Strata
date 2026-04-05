@echo off
setlocal EnableExtensions EnableDelayedExpansion
echo ==========================================
echo DFIR KB Bridge - Status
echo ==========================================
echo.

for /f "tokens=5" %%P in ('netstat -ano ^| findstr /R /C:"127\.0\.0\.1:8090 .*LISTENING"') do (
  set "PID=%%P"
)

if not defined PID (
  echo [STOPPED] KB Bridge is NOT listening on 127.0.0.1:8090
  echo.
  endlocal
  exit /b 0
)

echo [OK] KB Bridge is RUNNING
echo.
echo Listening:
netstat -ano | findstr /R /C:"127\.0\.0\.1:8090 .*LISTENING"
echo.
echo Process details (PID=!PID!):
tasklist /FI "PID eq !PID!"
echo.
echo Endpoint:
echo http://127.0.0.1:8090/chat
echo.
endlocal
