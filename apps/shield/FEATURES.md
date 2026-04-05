# ForensicSuite — Feature Status

**Last updated:** March 17, 2026

This document provides an honest accounting of implemented vs planned features.

---

## Container Formats

| Format | Status | Notes |
|--------|--------|-------|
| RAW/DD | ✅ Implemented | Full VFS with memory-mapped reads, NTFS/FAT32/ext4 enumeration |
| E01 (EnCase) | ✅ Implemented | Via `ewf` crate, full VFS support |
| Directory | ✅ Implemented | Native filesystem passthrough VFS |
| VHD | 🔲 Stub | Declared in `ContainerType` enum, no parser implemented |
| VHDX | 🔲 Stub | Declared in `ContainerType` enum, no parser implemented |
| VMDK | 🔲 Stub | Declared in `ContainerType` enum, no parser implemented |
| AFF4 | 🔲 Stub | Module commented out in `container/mod.rs` |
| Split RAW | 🔲 Stub | Module commented out in `container/mod.rs` |

---

## Classification Modules (275 total)

### Fully Implemented (260 files, >30 lines of real logic)

Major modules by size:

| Module | Lines | Description |
|--------|-------|-------------|
| `macos_catalog.rs` | 3,975 | macOS artifact classification catalog |
| `eventlog.rs` | 3,451 | EVTX/XML/EVT event log parsing with 200+ event ID mappings |
| `jumplist.rs` | 1,836 | Windows Jump List parsing (automatic + custom destinations) |
| `mftparse.rs` | 1,488 | NTFS MFT record parsing with attribute extraction |
| `registryhive.rs` | 1,061 | Windows registry hive binary parsing |
| `lnk.rs` | 1,024 | Windows shortcut (.lnk) file parsing |
| `usnjrnl.rs` | 915 | NTFS USN Journal change tracking |
| `srum.rs` | 898 | System Resource Usage Monitor parsing |
| `prefetch.rs` | 854 | Windows Prefetch execution trace parsing |
| `browser.rs` | 841 | Multi-browser history/cookie/download parsing |
| `scheduledtasks.rs` | 798 | Windows Task Scheduler XML parsing |

Plus ~249 more implemented modules covering: security logs, USB artifacts, RDP sessions, PowerShell history, macOS artifacts (Safari, iMessage, Keychain, etc.), iOS extraction (WhatsApp, GrayKey, Cellebrite), Linux artifacts (systemd journal, bash history), cloud services, email parsing, and more.

### Annotated Stubs (14 files)

These files contain only struct definitions and/or `Default::default()` returns. Each has been annotated with a `// STUB:` comment describing planned functionality.

| Module | Category | Planned Feature |
|--------|----------|-----------------|
| `wdigest.rs` | Credential Security | WDigest credential caching configuration |
| `lmcompat.rs` | Auth Security | LM Compatibility Level detection |
| `sccmcfg.rs` | Endpoint Mgmt | SCCM/MECM client configuration |
| `cluster.rs` | Infrastructure | Windows Failover Cluster topology |
| `computerinfo.rs` | System Info | Basic computer identification |
| `failover.rs` | Infrastructure | Failover Clustering configuration |
| `spoolerinfo.rs` | Service Security | Print Spooler status (PrintNightmare relevance) |
| `winlogon.rs` | Session Data | Winlogon session and logon timestamps |
| `userrights.rs` | Privilege Analysis | Local security policy user rights |
| `win32serv.rs` | Service Analysis | Windows services enumeration |
| `wintasks.rs` | Persistence | Scheduled tasks summary |
| `userassist.rs` | Execution History | UserAssist ROT13-encoded execution data |
| `layout.rs` | Disk Analysis | Disk partition layout enum (used by detect.rs) |
| `windowsdefender.rs` | AV Analysis | Windows Defender status and exclusions |

---

## Parsers (80+ registered)

All parsers listed in `ParserRegistry::register_default_parsers()` have working `ArtifactParser` trait implementations with `target_patterns()` for file matching and `parse_file()` for extraction. Coverage includes:

- **Windows:** Registry, Prefetch, Shellbags, EVTX, Browser (Chrome/Edge/Firefox/Brave/IE), JumpList, LNK, RecentDocs, SRUM, Amcache, RecycleBin, USN Journal, Outlook (PST/OST), OneDrive, Teams, Skype, Windows Search
- **macOS:** Launchd, Unified Logs, Spotlight, Time Machine, Safari, iMessage, Keychain, Notes, Calendar, Contacts, Reminders, Photos, FSEvents
- **iOS:** Backup, WhatsApp, iMessage, Safari, Photos, Location, Health, GrayKey, Cellebrite, Axiom, ScreenTime, App Usage, Wallet, Reminders, Keychain
- **Linux:** Systemd Journal, Bash History, Zsh History, Cron, APT Logs, Firefox/Chrome, /var/log, Packages
- **Cloud:** Google Drive, Dropbox, iCloud Sync
- **Email:** Generic, Outlook Full/Deep, Gmail, Thunderbird
- **Chat:** Discord, Slack, Telegram
- **Mobile:** Android, Android Full, Signal, WhatsApp Full
- **Network:** Network, Cloud Audit, Malware, AWS Deep, Azure Deep, Google Workspace, PCAP
- **Analysis:** Steganography, Ransomware, Advanced Search, AI Triage

---

## CLI Commands (40+)

All commands produce JSON envelope output via `CliResultEnvelope`. Two commands (`verify`, `capabilities`) have been migrated to `clap` with proper argument parsing. The remaining ~38 commands still use manual argument parsing in `main.rs`.
