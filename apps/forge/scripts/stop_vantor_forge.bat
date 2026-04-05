@echo off
tasklist /FI "IMAGENAME eq ollama.exe" | find /I "ollama.exe" >NUL
if errorlevel 1 (
  echo Ollama already stopped.
  exit /b 0
)
taskkill /IM ollama.exe /F >NUL
echo Ollama stopped.
