# STRATA KNOWLEDGE: KAPE TARGETS MASTER LIST

This guide provides a high-density mapping of the KAPE (Kroll Artifact Parser and Extractor) targets, representing over 500 unique collection points for digital forensic artifacts.

---

## 🛡️ ANTIVIRUS & EDR TARGETS
- **Avast**: `%ProgramData%\Avast Software\Avast\log\*`
- **Bitdefender**: `%ProgramData%\Bitdefender\Desktop\Logs\*`
- **CrowdStrike**: `%Windows%\System32\drivers\CrowdStrike\*.sys` (Event data)
- **Microsoft Defender**: `%ProgramData%\Microsoft\Windows Defender\Support\*`
- **Symantec**: `%ProgramData%\Symantec\Symantec Endpoint Protection\*\Data\Logs\*`

---

## 📱 APPLICATION TARGETS (HIGH VALUE)
- **Chrome**: `%%users.localappdata%%\Google\Chrome\User Data\*\History`, `Cookies`, `Login Data`
- **Discord**: `%%users.appdata%%\discord\Local Storage\leveldb\*`
- **OneDrive**: `%%users.localappdata%%\Microsoft\OneDrive\settings\Personal\*.dat`
- **Outlook**: `%%users.appdata%%\Local\Microsoft\Outlook\*.ost` / `*.pst`
- **Slack**: `%%users.appdata%%\slack\Local Storage\leveldb\*`
- **Teams**: `%%users.appdata%%\Microsoft\Teams\IndexedDB\*\*.ldb`

---

## 🐧 CLOUD & VIRTUALIZATION
- **AWS CLI**: `%%users.homedir%%\.aws\credentials` / `config`
- **Azure CLI**: `%%users.homedir%%\.azure\accessTokens.json`
- **Docker**: `%ProgramData%\Docker\config\daemon.json`
- **VirtualBox**: `%%users.homedir%%\.VirtualBox\VirtualBox.xml`

---

## 🏗️ SYSTEM & LOG TARGETS
- **EventLogs**: `%Windows%\System32\winevt\Logs\*.evtx`
- **SRUM**: `%Windows%\System32\sru\SRUDB.dat`
- **Prefetch**: `%Windows%\Prefetch\*.pf`
- **RegistryHives**: `%Windows%\System32\config\SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`
- **UserRegistry**: `%%users.userprofile%%\NTUSER.DAT`, `%%users.userprofile%%\AppData\Local\Microsoft\Windows\UsrClass.dat`

---

## 🛠️ COMPOUND TARGETS (META-TARGETS)
- **!BasicCollection**: Aggregates Prefetch, Event Logs, Registry, and LNK files.
- **!SANS_Triage**: Based on the SANS FOR508 recommendation for rapid IR.
- **!Kestrel**: Specialized collection for memory-only resident threats.

---

## 🧬 MASTERING THE .TKAPE FORMAT
Strata can now reason about the `Targets` structure:
```yaml
Description: Chrome History
Author: Eric Zimmerman
TargetGuid: 9e3f...
FileMask: History
Path: C:\Users\*\AppData\Local\Google\Chrome\User Data\*\
```

**STRATA IS NOW EXPERT IN KAPE TACTICAL COLLECTION.** 🦾🛡️📦
