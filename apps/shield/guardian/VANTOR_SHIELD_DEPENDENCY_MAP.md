# Strata Shield — Dependency Map

**Document Type:** Dependency Reference  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Authority:** Strata — Suite Guardian  
**Purpose:** Document what Strata Shield depends on, what breaks when each dependency fails, and how to recover

---

## Overview

Strata Shield is a layered system where each layer depends on components below it. This document maps every dependency, describes the failure mode when each dependency breaks, and provides a recovery path for restoring the system to operational state.

Dependencies are categorized as:
- **Runtime dependencies** — Services that must be running for the system to function
- **File/path dependencies** — Files, directories, and paths that must exist and be accessible
- **Startup dependencies** — Scripts and services that must run in correct order
- **Model dependencies** — AI model files and configuration
- **Suite repo dependencies** — ForensicSuite source code and build outputs
- **Documentation dependencies** — Guardian knowledge base documents

---

## Runtime Dependencies

### Llama Server

| Property | Value |
|----------|-------|
| **Binary** | `llama-server.exe` |
| **Location** | `D:\DFIR Coding AI\bin\llama\` |
| **Port** | 8080 |
| **Protocol** | HTTP REST (Ollama-compatible) |
| **Started by** | `start_llama_server.bat` |
| **Health check** | `GET http://127.0.0.1:8080/api/tags` |
| **Monitored by** | Watchdog layer |

**What depends on this:**
- KB bridge (forwards inference requests)
- Any external client using chat completions API
- Strata audit processes that validate model quality

**What breaks if this fails:**
- Chat completions return error
- KB bridge health shows degraded
- AI-assisted guardian validation unavailable
- System operates in degraded mode (guardian still validates CLI envelopes without AI)

**Recovery path:**
1. Check `D:\DFIR Coding AI\logs\llama_stderr.log` for error
2. Verify model file exists and path is correct in `start_llama_server.bat`
3. Verify sufficient RAM/VRAM for model size
4. Restart service: `stop_llama_server.bat && start_llama_server.bat`
5. If crash persists, check model file integrity (SHA256)
6. If model file corrupted, restore from backup

---

### KB Bridge

| Property | Value |
|----------|-------|
| **Script** | `dfir_kb_bridge.py` |
| **Location** | `D:\DFIR Coding AI\bin\kb\` |
| **Port** | 8090 |
| **Protocol** | HTTP REST |
| **Started by** | `start_kb_bridge.bat` |
| **Health check** | `GET http://127.0.0.1:8090/health` |
| **Monitored by** | Watchdog layer |

**What depends on this:**
- ForensicSuite GUI (if integrated)
- External KB clients
- Strata audit processes

**What breaks if this fails:**
- KB health endpoint unavailable
- Chat completions fail
- System operates in degraded mode (guardian validates CLI only)

**Recovery path:**
1. Check `D:\DFIR Coding AI\logs\kb_bridge_stderr.log` for error
2. Verify `dfir_kb_bridge.py` exists and is not corrupted
3. Verify port 8090 is not in use by another process
4. Restart: `taskkill /F /IM python.exe && start_kb_bridge.bat`
5. If script error, restore from backup or check Python version

---

### Watchdog

| Property | Value |
|----------|-------|
| **Script** | `watchdog_*.py` or monitoring script |
| **Location** | `D:\DFIR Coding AI\scripts\` |
| **Monitors** | Llama server (8080), KB bridge (8090) |
| **Started by** | `start_watchdog.bat` or system startup |

**What depends on this:**
- Automatic service restart on failure
- Failure storm detection

**What breaks if this fails:**
- Services do not auto-restart on crash
- Failure storms not detected
- Manual restart required

**Recovery path:**
1. Restart watchdog manually
2. If watchdog script corrupted, restore from backup
3. If watchdog is failing repeatedly, investigate underlying service issues

---

## File and Path Dependencies

### Model Files

| File | Location | Required By |
|------|----------|------------|
| `Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf` | `D:\DFIR Coding AI\models\gguf\` | Llama server |
| `Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf` | `D:\DFIR Coding AI\models\gguf\` | Llama server (fallback) |

**What breaks if model file missing:**
- Llama server fails to start
- Chat completions unavailable
- AI-assisted guardian validation unavailable

**Recovery path:**
1. Restore from backup: `models/gguf/backup/`
2. Verify SHA256 of restored file
3. Restart llama server

**What breaks if model file corrupted:**
- Llama server loads but produces garbled output
- Responses may be nonsensical
- Guardian validation may produce incorrect verdicts

**Recovery path:**
1. Verify file with SHA256 against known-good hash
2. Restore from backup or re-download
3. Restart llama server

---

### KB Bridge Configuration

| File | Location | Contents |
|------|----------|---------|
| `dfir_kb_bridge.py` | `D:\DFIR Coding AI\bin\kb\` | Bridge logic |
| `knowledge/vault/` | `D:\DFIR Coding AI\knowledge\vault\` | Document store |
| `ROOT` env var | Runtime | Root path for KB |
| `VAULT` env var | Runtime | Vault path override |

**What breaks if bridge script missing:**
- KB bridge cannot start
- Health endpoint unavailable
- Chat completions unavailable

**Recovery path:**
1. Restore from backup
2. Verify Python syntax
3. Restart bridge

**What breaks if vault directory missing:**
- Bridge starts but health shows empty document counts
- Chat completions may still work (depends on whether vault is required for chat)
- Guardian queries may return no results

**Recovery path:**
1. Verify `ROOT` and `VAULT` environment variables
2. Recreate vault directory if accidentally deleted
3. Rebuild vault from source documents if corrupted

---

### Startup Scripts

| Script | Location | Starts |
|--------|----------|--------|
| `start_llama_server.bat` | `D:\DFIR Coding AI\scripts\` | Llama server |
| `start_kb_bridge.bat` | `D:\DFIR Coding AI\scripts\` | KB bridge |
| `stop_all.bat` | `D:\DFIR Coding AI\scripts\` | Stops all services |
| `health_dfir_coding_ai.bat` | `D:\DFIR Coding AI\scripts\` | Health check |

**What breaks if startup script corrupted:**
- Service may fail to start
- Wrong model may be loaded
- Wrong ports may be used

**Recovery path:**
1. Restore from backup
2. Verify script syntax
3. Test start command manually

---

### Log Directory

| Directory | Location |
|-----------|----------|
| `logs/` | `D:\DFIR Coding AI\logs\` |

**What breaks if logs directory missing:**
- Logs written to current directory instead
- Debugging becomes difficult
- Audit trail may be incomplete

**Recovery path:**
1. Recreate directory
2. Restart services to resume logging

---

## Startup Dependencies

### Service Startup Order

Services must start in this order:

```
1. Verify model files exist
        ↓
2. Start llama-server.exe (wait for port 8080)
        ↓
3. Start dfir_kb_bridge.py (waits for port 8080)
        ↓
4. Start watchdog (monitors 8080 and 8090)
```

**What breaks if order is wrong:**
- KB bridge starts before llama server → health check fails, chat completions fail
- Watchdog starts before bridge → false alarms
- Services restart out of order → cascading failures

**Recovery path:**
- Always use provided startup scripts
- Always stop in reverse order (watchdog → bridge → server)

---

### Port Dependencies

| Port | Service | Dependency |
|------|---------|-----------|
| 8080 | Llama server | None (primary) |
| 8090 | KB bridge | 8080 (forwards to llama) |
| 8091+ | Staging/test | None |

**What breaks if port 8080 occupied:**
- Llama server fails to start
- All downstream services affected

**Recovery path:**
```batch
netstat -ano | findstr :8080
taskkill /F /PID {pid}
```

**What breaks if port 8090 occupied:**
- KB bridge fails to start
- Health endpoint unavailable

**Recovery path:**
```batch
netstat -ano | findstr :8090
taskkill /F /PID {pid}
```

---

## Model Dependencies

### Primary Model

| Property | Value |
|----------|-------|
| File | `Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf` |
| Size | ~40GB |
| Purpose | Full-capability AI inference |
| Loaded by | `llama-server.exe` |
| Path configured in | `start_llama_server.bat` |

### Fallback Model

| Property | Value |
|----------|-------|
| File | `Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf` |
| Size | ~5GB |
| Purpose | Degraded mode when primary unavailable |
| Loaded by | `llama-server.exe` (alternate path) |

### Model Configuration

Model selection is controlled by the `--model` argument in `start_llama_server.bat`:

```batch
llama-server.exe --model D:\DFIR Coding AI\models\gguf\Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf
```

**What breaks if path is wrong:**
- Llama server fails to load model
- Error in stderr: "file not found"

**Recovery path:**
1. Verify file exists at specified path
2. Correct path in startup script
3. Restart service

---

## Suite Repo Dependencies

### ForensicSuite Workspace

| Dependency | Location | Used For |
|-----------|----------|---------|
| Source code | `D:\forensic-suite\` | Build, validation |
| CLI binary | `target/debug/forensic_cli.exe` | Runtime validation |
| Engine library | `target/debug/forensic_engine.dll` | Evidence processing |
| Guardian docs | `D:\forensic-suite\guardian\` | Doctrine, checklists |

**What breaks if forensic-suite unavailable:**
- Cannot build new CLI binaries
- Cannot run full guardian audits
- Cannot validate evidence processing

**Recovery path:**
1. Verify `D:\forensic-suite\` is accessible
2. Rebuild if needed: `cargo build --workspace`
3. Run Quick Health Audit to verify

---

### Tauri GUI

| Dependency | Location | Used For |
|-----------|----------|---------|
| Source | `D:\forensic-suite\gui-tauri\` | GUI build |
| Binary | `target/release/` or `src-tauri/target/` | GUI execution |

**What breaks if Tauri unavailable:**
- GUI cannot be rebuilt
- GUI integration tests skipped

**Recovery path:**
1. Verify `D:\forensic-suite\gui-tauri\` is accessible
2. Rebuild if needed: `cargo tauri build`

---

## Documentation Dependencies

### Guardian Knowledge Base

| Document | Location | Purpose | What Breaks If Missing |
|---------|----------|---------|------------------------|
| `SUITE_GUARDIAN_PROFILE.md` | `guardian/` | Identity and authority | Strata doesn't know its role |
| `TRUTHFULNESS_RULES.md` | `guardian/` | Evidence contracts | Cannot validate truthfulness |
| `PARSER_CONVENTIONS.md` | `guardian/` | Parser standards | Cannot review parsers |
| `KNOWN_GAPS.md` | `guardian/` | Capability inventory | Cannot verify gaps |
| `RUNTIME_FAILURE_PATTERNS.md` | `guardian/` | Failure catalog | Cannot identify failures |
| `COMMAND_CONTRACTS.md` | `guardian/` | CLI-GUI contracts | Cannot validate contracts |
| `RUN_STRATA_SUITE_AUDIT.md` | `guardian/` | Audit procedure | Cannot run audits |
| `RUN_STRATA_PARSER_REVIEW.md` | `guardian/` | Parser review SOP | Cannot review parsers |
| `STRATA_AUDIT_REPORT_TEMPLATE.md` | `guardian/` | Report format | Reports inconsistent |
| `STRATA_*_CHECKLIST.md` | `guardian/` | Validation checklists | Validation incomplete |

### What Breaks If Guardian Docs Missing

| Missing Document | Impact |
|-----------------|--------|
| `SUITE_GUARDIAN_PROFILE.md` | CRITICAL — Strata loses identity and boundaries |
| `TRUTHFULNESS_RULES.md` | CRITICAL — Cannot validate evidence contracts |
| `RUN_STRATA_SUITE_AUDIT.md` | HIGH — Cannot run structured audits |
| `KNOWN_GAPS.md` | HIGH — Cannot verify capability claims |
| `STRATA_*_CHECKLIST.md` | MEDIUM — Validation may be incomplete |

### Recovery Path for Documentation

```batch
# Verify guardian directory exists
dir D:\forensic-suite\guardian\

# Verify all required documents present
# (list from table above)

# If document missing, check git history
git -C D:\forensic-suite\guardian\ log --oneline

# Restore from git
git -C D:\forensic-suite\guardian\ checkout HEAD -- missing_file.md

# If entire directory missing, restore from backup
```

---

## Dependency Failure Summary

### Single-Point Failures (Critical)

| Component | Failure Mode | Impact | Recovery Time |
|-----------|-------------|--------|---------------|
| Llama server | Won't start | AI inference unavailable | <5 min (restart) |
| KB bridge | Won't start | Health unavailable | <5 min (restart) |
| Model file (primary) | Corrupted | AI inference fails | 30-60 min (restore/re-download) |
| `TRUTHFULNESS_RULES.md` | Missing/corrupted | Guardian doctrine lost | <5 min (git restore) |

### Cascading Failures

| Primary Failure | Cascades To |
|----------------|------------|
| Llama server down | KB bridge health fails, chat completions fail |
| KB bridge down | Health endpoint fails, external clients fail |
| Watchdog down | No auto-restart, services stay down |
| Model file corrupted | Garbled output, incorrect verdicts |

### Graceful Degradation

| Failure | Degraded Mode | What's Lost |
|---------|--------------|------------|
| Llama server down | CLI-only validation | AI-assisted guardian |
| KB bridge down | Manual health checks | Automated health monitoring |
| Fallback model only | 8B capability | 70B full capability |
| Guardian docs partially missing | Strata partial | Some validation incomplete |

---

## Recovery Priority Order

When multiple dependencies fail, recover in this order:

1. **Llama server** — Restore primary inference
2. **Model files** — Ensure correct model available
3. **KB bridge** — Restore health endpoint
4. **Startup scripts** — Ensure services can start
5. **Guardian docs** — Restore doctrine
6. **Watchdog** — Restore auto-recovery
7. **ForensicSuite** — Restore CLI/engine

---

## Document Maintenance

**Last Updated:** 2026-03-23  
**Next Review:** 2026-06-23 (quarterly)  
**Update Triggers:**
- New dependencies added
- Component locations change
- New failure modes discovered
- Recovery procedures change

**Location:** `D:\forensic-suite\guardian\STRATA_SHIELD_DEPENDENCY_MAP.md`
