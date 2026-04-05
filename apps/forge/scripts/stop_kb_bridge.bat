@echo off
echo Stopping Vantor Intelligence Services...

:: Kill KB Bridge
for /f "tokens=2 delims=," %%P in ('wmic process where "name='python.exe' and CommandLine like '%%dfir_kb_bridge.py%%'" get ProcessId /format:csv ^| findstr /r "[0-9]"') do (
  taskkill /PID %%P /F >NUL 2>&1
)

:: Kill Activity Watcher
for /f "tokens=2 delims=," %%P in ('wmic process where "name='python.exe' and CommandLine like '%%activity_watcher.py%%'" get ProcessId /format:csv ^| findstr /r "[0-9]"') do (
  taskkill /PID %%P /F >NUL 2>&1
)

echo [OK] KB Bridge and Activity Watcher stopped.
