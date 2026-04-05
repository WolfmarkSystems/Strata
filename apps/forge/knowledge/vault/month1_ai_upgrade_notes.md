# Month 1 AI Upgrade Notes

## Launcher Changes

- Default model path is now `Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf`
- Fallback model path is `Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf`
- Context window increased from `4096` to `8192`
- NVIDIA detection is automatic through `nvidia-smi`
- If an NVIDIA GPU is detected, llama.cpp is started with `-ngl 999`
- If no NVIDIA GPU is detected, the launcher falls back to CPU mode with `-ngl 0`

## Expected Performance Notes

- 32B on CPU will be much slower than 7B but gives better code synthesis and review quality
- 32B with GPU offload should improve response quality without forcing a second launcher path
- 7B remains the safe fallback when the 32B GGUF is missing
- Startup logs now clearly print the selected model and GPU mode

## Test Commands

### Start the server

```powershell
cd "D:\DFIR Coding AI"
.\scripts\start_llama_server.bat
```

### Check health

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8080/" -UseBasicParsing
```

### Basic chat completion test

```powershell
curl.exe -X POST "http://127.0.0.1:8080/v1/chat/completions" ^
  -H "Content-Type: application/json" ^
  -d "{\"model\":\"local\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the words Strata Shield online.\"}],\"temperature\":0.1,\"max_tokens\":32}"
```

### Expected result

The response should contain a completion confirming the server is online. If it does not, inspect:

- `D:\DFIR Coding AI\logs\llama_stdout.log`
- `D:\DFIR Coding AI\logs\llama_stderr.log`

