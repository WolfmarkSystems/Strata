@echo off
echo ================================================
echo Llama 3.1 70B Model Downloader
echo ================================================
echo.
echo This will download Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf (~40GB)
echo This is the LARGE model for best quality.
echo.
echo WARNING: Requires significant RAM/VRAM and disk space.
echo.
echo Press any key to start download...
pause >nul

echo.
echo Downloading Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf...
echo This will take 20-60 minutes depending on your internet speed.
echo.

curl -L -o "D:\DFIR Coding AI\models\gguf\Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf" "https://huggingface.co/bartowski/Meta-Llama-3.1-70B-Instruct-GGUF/resolve/main/Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf"

echo.
echo Download complete!
echo.
echo Next steps:
echo 1. Run start_llama_server.bat to start the server with Llama 3.1 70B
echo 2. The 70B model will be used automatically if present
pause
