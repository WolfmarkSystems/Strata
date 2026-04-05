# Strata Remnant Plugin v2.0

Remnant is Strata's deleted evidence recovery engine. It performs deep file carving, Recycle Bin parsing, anti-forensic tool detection, and SQLite WAL recovery to surface artifacts that subjects attempted to destroy.

## Capabilities

- **File Carving**: Signature-based recovery of deleted files from raw disk images and forensic containers (PE, SQLite, JPEG/EXIF, LNK, PDF, archives, and 50+ additional formats)
- **Recycle Bin Parsing**: Extracts original file paths, deletion timestamps, and file sizes from Windows `$Recycle.Bin` `$I` metadata files
- **Anti-Forensic Tool Detection**: Identifies the presence of SDelete, CCleaner, Eraser, VSS admin abuse, cipher.exe wiping artifacts, and Security log clearing (Event ID 1102)
- **SQLite WAL Recovery**: Detects Write-Ahead Log files that may contain deleted database records not yet checkpointed
- **Content Analysis**: Deep inspection of carved PE executables (compilation timestamps, suspicious imports), SQLite databases (table enumeration, type detection), images (EXIF/GPS), and Windows shortcuts (target paths, timestamps)

## MITRE ATT&CK Coverage

| Technique | Description |
|-----------|-------------|
| T1070 | Indicator Removal on Host (SDelete, CCleaner, Eraser, cipher.exe) |
| T1070.004 | File Deletion (Recycle Bin recovery) |
| T1490 | Inhibit System Recovery (VSS admin shadow copy deletion) |
| T1055 | Process Injection (suspicious PE imports) |
| T1070.006 | Timestomping (future compilation timestamps) |
| T1564 | Hidden Artifacts (carved executables) |
