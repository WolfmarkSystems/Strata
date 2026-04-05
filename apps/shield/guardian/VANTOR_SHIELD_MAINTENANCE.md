# Strata Shield — Maintenance Procedures

**Document Type:** Operational Maintenance Guide  
**Version:** 1.0  
**Effective Date:** 2026-03-23  
**Authority:** Strata — Suite Guardian  
**Audience:** Operators, system administrators, Strata (automated)

---

## Overview

Strata Shield requires regular maintenance to remain effective. This document describes the procedures for safely updating each component, validating changes, rolling back if necessary, and monitoring system health after modifications.

All maintenance operations must follow the change control process described in `STRATA_SHIELD_CHANGE_CONTROL.md`. Emergency patches are exceptions but still require post-hoc documentation.

---

## Component Inventory

| Component | File | Location | Type |
|-----------|------|----------|------|
| Llama runtime | `llama-server.exe` | `D:\DFIR Coding AI\bin\llama\` | Binary |
| Model files | `Meta-Llama-3.1-*.gguf` | `D:\DFIR Coding AI\models\gguf\` | Model data |
| KB bridge | `dfir_kb_bridge.py` | `D:\DFIR Coding AI\bin\kb\` | Python script |
| Watchdog | `watchdog*.py` or script | `D:\DFIR Coding AI\scripts\` | Python/script |
| Startup scripts | `start_*.bat` | `D:\DFIR Coding AI\scripts\` | Batch scripts |
| Guardian docs | `*.md` | `D:\forensic-suite\guardian\` | Documentation |
| Logs | `*.log` | `D:\DFIR Coding AI\logs\` | Log files |

---

## Section 1 — Updating the Model Safely

### When to Update

Model updates are major changes. Update when:
- A new Llama model version provides materially better capability
- Security advisory requires updating the model binary
- Current model is causing consistent quality issues in outputs
- Change control approves a model rotation (see `STRATA_SHIELD_CHANGE_CONTROL.md`)

### Pre-Update Checklist

Before updating:

1. **Document current state**
   - Current model file: `[filename]` — SHA256: `[hash]`
   - Current `llama-server.exe` version: `[version]`
   - Expected new model: `[filename]`
   - Expected new model SHA256: `[hash]` (from official source)

2. **Download new model to staging location**
   - Do not overwrite current model until validated
   - Store in `D:\DFIR Coding AI\models\gguf\staging\`
   - Verify SHA256 of downloaded file

3. **Backup current model**
   - Copy current model to `D:\DFIR Coding AI\models\gguf\backup\`
   - Include timestamp: `backup_YYYYMMDD/`

4. **Review model change with Strata**
   - Run parser review on any guardian prompt changes
   - Validate that output quality meets standards
   - Check for regression in response accuracy

### Update Procedure

1. **Stop services**
   ```batch
   cd D:\DFIR Coding AI\scripts
   stop_all.bat
   ```

2. **Install new model file**
   - Copy from staging to primary model directory
   - Verify file integrity

3. **Update startup script if needed**
   - Edit `start_llama_server.bat` to point to new model file
   - Verify model path is correct

4. **Start services**
   ```batch
   cd D:\DFIR Coding AI\scripts
   start_llama_server.bat
   start_kb_bridge.bat
   ```

5. **Validate model loads**
   ```bash
   curl http://127.0.0.1:8080/api/tags
   ```
   Verify model appears in the list.

6. **Run health check**
   ```bash
   curl http://127.0.0.1:8090/health
   ```
   Verify `embedding_backend` and `status: ok`.

7. **Run Quick Health Audit** (see `RUN_STRATA_SUITE_AUDIT.md`)
   - Minimum: verify `forensic_cli doctor` still works
   - Full: run Mode 1 Quick Health Audit

### Post-Update Validation

After any model update, Strata must run a full validation:

| Check | Command | Pass Criteria |
|-------|---------|---------------|
| Model loads | `curl http://127.0.0.1:8080/api/tags` | Model listed |
| Bridge health | `curl http://127.0.0.1:8090/health` | `status: ok` |
| CLI sanity | `forensic_cli doctor` | Envelope status ok |
| Prompt quality | Run test query via bridge | Response is coherent |
| Guard validation | Run guardian doctrine test query | Response follows doctrine |

### Rollback Procedure

If the new model causes issues:

1. **Stop services**
   ```batch
   stop_all.bat
   ```

2. **Restore backup model**
   ```batch
   copy D:\DFIR Coding AI\models\gguf\backup\backup_YYYYMMDD\* D:\DFIR Coding AI\models\gguf\
   ```

3. **Restore startup script**
   - Restore `start_llama_server.bat` to previous version

4. **Restart services**
   ```batch
   start_llama_server.bat
   start_kb_bridge.bat
   ```

5. **Verify rollback**
   ```bash
   curl http://127.0.0.1:8080/api/tags  # Confirm old model listed
   curl http://127.0.0.1:8090/health    # Confirm status ok
   ```

6. **Document rollback**
   - Note in `STRATA_SHIELD_CHANGE_CONTROL.md` incident log
   - Report: What failed, when, what was done

---

## Section 2 — Rotating Between Primary and Fallback Models

### Model Configuration

Strata Shield supports two model tiers:
- **Primary:** `Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf` — Full capability
- **Fallback:** `Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf` — Reduced capability

### When to Use Fallback

Use fallback when:
- Primary model file is unavailable (corrupted, deleted)
- Primary model fails to load (OOM, binary incompatibility)
- Temporary mode during maintenance

### Rotation Procedure

1. **Stop llama-server**
   ```batch
   taskkill /F /IM llama-server.exe
   ```

2. **Edit `start_llama_server.bat`**
   - Change `--model` parameter to fallback model path:
   ```batch
   set MODEL_PATH=D:\DFIR Coding AI\models\gguf\Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf
   ```

3. **Start with fallback**
   ```batch
   start_llama_server.bat
   ```

4. **Verify fallback active**
   ```bash
   curl http://127.0.0.1:8080/api/tags
   # Should show 8B model, not 70B
   ```

5. **Update guardian docs**
   - Note fallback mode activation in maintenance log
   - Document reason for fallback activation

### Returning to Primary

1. **Stop llama-server**

2. **Restore `start_llama_server.bat`**
   - Change `--model` parameter back to primary model path

3. **Start with primary**
   ```batch
   start_llama_server.bat
   ```

4. **Verify primary active**
   ```bash
   curl http://127.0.0.1:8080/api/tags
   ```

---

## Section 3 — Updating Startup Scripts Safely

### What Can Be Updated

Startup scripts may be updated for:
- Correcting model paths
- Adding new CLI arguments
- Fixing port conflicts
- Adding health check retries
- Improving error messages

### What Requires Change Control

The following changes require change control approval (see `STRATA_SHIELD_CHANGE_CONTROL.md`):
- Changing default ports (8080, 8090)
- Adding network dependencies
- Changing log file locations
- Adding environment variable dependencies

### Update Procedure

1. **Backup current script**
   ```batch
   copy start_llama_server.bat start_llama_server.bat.bak
   ```

2. **Edit script in staging**
   - Create `start_llama_server.bat.new`
   - Make intended changes
   - Verify syntax

3. **Test in isolation**
   - Stop current service
   - Run `start_llama_server.bat.new`
   - Verify service starts correctly

4. **Replace if validated**
   ```batch
   move start_llama_server.bat.new start_llama_server.bat
   ```

5. **Document change**
   - Note in `STRATA_SHIELD_CHANGE_CONTROL.md`
   - Include diff summary

### Rollback Procedure

```batch
copy start_llama_server.bat.bak start_llama_server.bat
```

---

## Section 4 — Updating the KB Bridge Safely

### What Can Be Updated

KB bridge updates may include:
- Bug fixes in response handling
- New API endpoints
- Performance improvements
- Logging improvements
- Security hardening

### Pre-Update Checklist

1. **Backup current bridge**
   ```batch
   copy dfir_kb_bridge.py dfir_kb_bridge.py.bak
   ```

2. **Review new bridge code**
   - Strata reviews for safety
   - Check for new network dependencies
   - Verify envelope validation logic unchanged

3. **Test in staging**
   - Run new bridge on non-production port (e.g., 8091)
   - Validate health endpoint responds
   - Validate chat completions work

### Update Procedure

1. **Stop bridge**
   ```batch
   taskkill /F /IM python.exe  # if bridge process
   ```

2. **Replace bridge file**
   ```batch
   copy dfir_kb_bridge.py.new dfir_kb_bridge.py
   ```

3. **Restart bridge**
   ```batch
   start_kb_bridge.bat
   ```

4. **Validate health**
   ```bash
   curl http://127.0.0.1:8090/health
   ```

5. **Run Quick Health Audit**

### Rollback Procedure

```batch
taskkill /F /IM python.exe
copy dfir_kb_bridge.py.bak dfir_kb_bridge.py
start_kb_bridge.bat
```

---

## Section 5 — Updating Guardian Documents

### Document Categories

| Category | Examples | Update Authority |
|----------|----------|-----------------|
| Doctrine | `TRUTHFULNESS_RULES.md`, `SUITE_GUARDIAN_PROFILE.md` | Human reviewer + Strata |
| Runbooks | `RUN_STRATA_SUITE_AUDIT.md`, `RUN_STRATA_PARSER_REVIEW.md` | Strata (automated) |
| Checklists | `STRATA_*_CHECKLIST.md` | Strata (automated) |
| Inventory | `KNOWN_GAPS.md`, `WARNINGS_REPORT.md` | Strata (automated) |
| Architecture | `STRATA_SHIELD_*.md` | Human reviewer + Strata |

### Update Triggers

Guardian documents must be updated when:
- New parsers added or removed
- New CLI commands integrated
- Known gaps resolved or discovered
- Failure patterns documented
- Doctrine principles clarified
- Operating boundaries change

### Update Procedure

1. **Draft changes**
   - Create new version of document
   - Track changes using diff

2. **Strata review**
   - Strata validates changes are consistent with doctrine
   - Strata flags any conflicts with other documents

3. **Human reviewer approval**
   - Doctrine documents require human sign-off
   - Runbooks may be auto-approved by Strata with documented rationale

4. **File update**
   ```batch
   copy NEW_FILE.md D:\forensic-suite\guardian\OLD_FILE.md
   ```

5. **Audit log entry**
   - Note change in `STRATA_SHIELD_CHANGE_CONTROL.md`
   - Include: what changed, why, who approved

### Validation After Update

After any guardian document update:

1. **Verify document is readable**
   - Open and verify no corruption

2. **Verify cross-references**
   - Check that links to other documents are still valid
   - Update any section numbers that changed

3. **Run Quick Health Audit**
   - Ensure Strata can still parse and apply the updated document

---

## Section 6 — Validating After Changes

### Validation Hierarchy

| Change Type | Validation Required |
|-------------|--------------------|
| Model update | Full validation (Section 1) |
| Bridge update | Full validation (Section 4) |
| Script update | Smoke test + health check |
| Guardian doc update | Quick Health Audit |
| Minor config change | Health endpoint check |

### Standard Validation Sequence

After any change to Strata Shield:

1. **Service health check**
   ```bash
   curl http://127.0.0.1:8090/health
   # Expected: {"status": "ok", "embedding_backend": "...", ...}
   ```

2. **CLI sanity check**
   ```bash
   forensic_cli doctor --json-result temp.json
   # Expected: status "ok" in envelope
   ```

3. **Llama server check**
   ```bash
   curl http://127.0.0.1:8080/api/tags
   # Expected: model listed, no errors
   ```

4. **Quick Health Audit** (see `RUN_STRATA_SUITE_AUDIT.md` Mode 1)

5. **Full Guardian Audit** if major change (see `RUN_STRATA_SUITE_AUDIT.md` Mode 6)

---

## Section 7 — Backup and Rollback Process

### What to Back Up

| Component | Backup Location | Frequency |
|-----------|----------------|-----------|
| Model files | `models/gguf/backup/` | Before every model update |
| KB bridge | `bin/kb/backup/` | Before every bridge update |
| Startup scripts | `scripts/backup/` | Before every script change |
| Guardian docs | `guardian/AUDIT_REPORTS/` | Automatic on change |
| Logs | `logs/archive/` | Weekly rotation |

### Backup Naming Convention

```
{component}_{YYYYMMDD}_{HHMMSS}.{ext}
```

Example:
```
llama_model_70B_20260323_143000.gguf.bak
dfir_kb_bridge_20260323_143000.py.bak
start_llama_server_20260323_143000.bat.bak
```

### Rollback Decision Matrix

| Issue | Rollback Required? | Additional Action |
|-------|-------------------|-----------------|
| Model fails to load | Yes | Report incident |
| Bridge health check fails | Yes | Report incident |
| CLI commands fail | No (check CLI first) | Verify CLI separately |
| Guardian doc corrupted | Yes (restore from repo) | Check git history |
| Log says unknown error | Assess | Run diagnostics |

---

## Section 8 — Log and History Review

### Log Locations

| Log | Location | Contents |
|-----|----------|----------|
| KB bridge stdout | `D:\DFIR Coding AI\logs\kb_bridge_stdout.log` | Bridge startup, requests, errors |
| KB bridge stderr | `D:\DFIR Coding AI\logs\kb_bridge_stderr.log` | Errors, warnings |
| Llama server stderr | `D:\DFIR Coding AI\logs\llama_stderr.log` | Model loading, inference |
| Server logs | `D:\DFIR Coding AI\logs\server_stderr.log` | Service-level events |
| Guardian audit logs | `D:\forensic-suite\guardian\AUDIT_REPORTS\` | Audit reports |

### Log Review Schedule

| Review | Frequency | Who |
|--------|-----------|-----|
| Health check | Daily (automated) | Strata |
| KB bridge logs | Weekly | Operator |
| Llama server logs | Weekly | Operator |
| Guardian audit reports | After every audit | Strata + reviewer |
| Maintenance incident log | After every incident | Strata |

### What to Check in Logs

**KB bridge logs:**
- [ ] Startup shows "Strata KB Bridge" (not old name)
- [ ] No Qwen model references
- [ ] Health endpoint responds correctly
- [ ] No HTTP 500 errors
- [ ] Document counts are non-zero

**Llama server logs:**
- [ ] Model loads successfully
- [ ] No CUDA/memory errors
- [ ] No crash reports
- [ ] Correct model file loaded

**Guardian audit logs:**
- [ ] Reports filed in correct location
- [ ] Verdicts are consistent
- [ ] Issues are tracked to resolution

---

## Section 9 — Post-Upgrade Checklist

After any upgrade to Strata Shield, complete this checklist:

### Immediate (0-15 minutes after upgrade)

- [ ] All services started
- [ ] Health endpoint returns 200 OK
- [ ] Llama model listed in tags
- [ ] Bridge shows correct vault path
- [ ] No Qwen references in logs

### Short-term (15-60 minutes after upgrade)

- [ ] Quick Health Audit passes (Mode 1)
- [ ] CLI commands respond correctly
- [ ] Chat completions work via bridge
- [ ] Logs show no new errors

### Long-term (24-72 hours after upgrade)

- [ ] Run Full Guardian Audit (Mode 6)
- [ ] Review any new warnings
- [ ] Update `KNOWN_GAPS.md` if new gaps observed
- [ ] Verify no regression in audit verdicts

### Emergency Rollback Triggers

Roll back immediately if:
- Llama server fails to start
- Bridge health check fails after 3 retries
- CLI commands start failing
- Logs show repeated crashes
- Guardian audit produces unexpected verdicts

---

## Document Maintenance

**Last Updated:** 2026-03-23  
**Next Review:** 2026-06-23 (quarterly)  
**Update Triggers:**
- New maintenance procedures added
- Component locations change
- Backup strategy changes
- New validation requirements

**Location:** `D:\forensic-suite\guardian\STRATA_SHIELD_MAINTENANCE.md`
