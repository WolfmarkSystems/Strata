# Strata

**Professional-grade digital forensics platform — 3,300 tests, 26 plugins, air-gap deployable, court-ready.**

Built by a US Army Counterintelligence Special Agent and Digital Forensic Examiner.  
Free for US military and law enforcement. Commercial licensing available.

---

## What is Strata

Strata is an air-gapped, court-ready forensic analysis platform built in Rust. It runs as a single portable binary on Windows, macOS, and Linux with no installation, no dependencies, and no network connection required. It parses evidence from Windows, macOS, iOS, Android, and Linux systems and produces court-defensible reports with a full chain-of-custody audit trail.

The tools that exist were built for enterprise budgets and conference demos. Strata was built for the examination — because a tool budget should never stand between an examiner and the evidence.

---

## Platform Coverage

| Platform | Status |
|---|---|
| Windows (XP → 11) | ✅ Full coverage |
| macOS (10.x → 15 Sequoia) | ✅ Full coverage |
| iOS (12 → 18) | ✅ Full coverage |
| Android (8 → 15) | ✅ Full coverage |
| Linux (Ubuntu, Debian, RHEL, Arch) | ✅ Full coverage |
| Cloud artifacts (client-side, air-gap) | ✅ AWS / Azure / GCP / OneDrive / Google Drive |

---

## Key Numbers

| Metric | Count |
|---|---|
| Tests passing | **3,300** |
| Forensic plugins | **26** |
| Sigma correlation rules | **34** (expandable to 3,000+ via SigmaHQ import) |
| Mobile artifact parsers | **428** (232 Android + 196 iOS) |
| MITRE ATT&CK techniques mapped | **80+** |
| Binary size (macOS ARM64) | **~35 MB** |
| External dependencies at runtime | **0** |
| Network calls at runtime | **0** |
| `.unwrap()` in production paths | **0** |
| `unsafe {}` blocks | **0** |

---

## Features

- **26 forensic plugins** covering Windows, macOS, iOS, Android, Linux, cloud, network, memory, containers, and malware
- **428 mobile artifact parsers** — 232 Android + 196 iOS, all read-only SQLite
- **Full SIGMA engine** — 34 built-in rules, import SigmaHQ's 3,000+ rule repository as YAML files
- **ATT&CK kill chain reconstruction** — automatically maps detected artifacts to all 14 ATT&CK tactic stages
- **Behavioral detection** — beaconing analysis, credential harvesting patterns, lateral movement chain visualization
- **Memory forensics** — raw memory image carving (.raw/.mem/.vmem/.dmp/.lime), process list heuristics, network connection extraction
- **ML-powered analysis** — anomaly detection, executive case summary, anti-forensic obstruction scoring (0–100)
- **CSAM detection module** — hash-based and perceptual detection, NCMEC/Project VIC compatible, immutable audit trail, free on all tiers
- **Vault detection** — VeraCrypt volumes, photo vault apps, anti-forensic tools, steganography indicators, Tor Browser artifacts
- **Court-ready reporting** — HTML/PDF export, UCMJ court-martial format, agency branding, Ed25519 cryptographic report sealing, FACT attribution framework
- **Chain of custody** — SHA256-chained tamper-evident audit log, evidence integrity verification on open, warrant scope enforcement
- **Examiner workflow** — triage mode (60-second fast scan), artifact notes, IOC search, NSRL hash set, ATT&CK Navigator export
- **Air-gap deployable** — single binary, USB portable, no cloud dependency, no telemetry, no license server
- **Cross-platform** — Windows, macOS, Linux. Parses evidence from all major platforms

---

## Plugins

### Windows Forensics

#### Phantom — Windows System Artifacts
Registry hives, execution evidence, cloud CLI credentials, memory artifacts.

**Registry artifacts:**
- SYSTEM, SOFTWARE, SAM, NTUSER.DAT, USRCLASS.DAT, AmCache.hve
- ShimCache / AppCompatCache (all Windows versions)
- BAM/DAM execution timestamps (Windows 10+)
- USB device history (USBSTOR, MountedDevices, drive serial numbers)
- MRU keys (OpenSavePidlMRU, RunMRU, RecentDocs, TypedPaths, WordWheelQuery)
- WDigest credential caching
- Network profiles, RDP history, timezone, installed software
- Run/RunOnce persistence keys
- Windows Services (full parse + anomaly detection)

**Execution evidence:**
- Prefetch files (full execution timeline, file references, run count)
- Program Compatibility Assistant (PCA) — Windows 11 22H2+
- Windows Recall database (Copilot+ PCs) — OCR text, window captures
- Windows 11 Notepad TabState — unsaved tab content recovery

**Email:**
- Outlook PST/OST — message metadata, attachment names, folder hierarchy

**Memory:**
- Raw memory image string carving (.raw, .mem, .vmem, .dmp, .lime)
- Process list heuristic extraction
- Network connection table extraction
- LiME format support

**Cloud CLI credentials (client-side, no network calls):**
- AWS CLI (~/.aws/credentials, config, STS cache)
- Azure CLI (~/.azure/accessTokens.json, azureProfile.json)
- GCP CLI (~/.config/gcloud/credentials.db, properties)
- Terraform state files (resource inventory)
- kubectl config (cluster endpoints, credentials)

---

#### Chronicle — User Activity
UserAssist, Jump Lists, LNK files, Shellbags, Windows Timeline, Capability Access Manager.

**Artifacts parsed:**
- UserAssist (full ROT13 decode, GUID resolution, run counts, focus time)
- RecentDocs (binary MRU decode, UTF-16LE)
- Jump Lists (CFB parse, DestList stream, 21 AppID mappings)
- TypedPaths, WordWheelQuery
- ActivitiesCache.db (Windows Timeline — app usage, web visits, clipboard)
- Capability Access Manager (microphone, camera, location, screen capture access log)
- CAM SQLite database (Windows 11 23H2+ expanded schema)

---

#### Sentinel — Windows Event Logs
Structured EVTX parsing with lateral movement correlation.

**Event sources:**
- Security.evtx (4624/4625/4648/4672/4688/4698/4720/4728/4732/4756)
- Microsoft-Windows-PowerShell/Operational (4103/4104 script block logging)
- Microsoft-Windows-Sysmon/Operational (1/3/7/8/10/11/12/13/17/18)
- Windows PowerShell.evtx (400/403/800)
- Microsoft-Windows-WinRM/Operational
- Microsoft-Windows-TaskScheduler/Operational
- Microsoft-Windows-TerminalServices-RemoteConnectionManager
- Microsoft-Windows-Bits-Client/Operational

**Lateral movement correlator:**
Correlates 4624/4648/4768/4769/4776/5140/5145/7045 across time windows to build lateral movement chains (RDP/SMB/Kerberos/NTLM/Service).

---

#### Trace — Execution and Persistence
Prefetch, BAM/DAM, Scheduled Tasks, BITS Jobs, timestomp detection, PCA.

**Artifacts parsed:**
- Prefetch (.pf) — execution count, last 8 run timestamps, file references
- BAM/DAM — Windows 10+ background activity monitor
- Scheduled Tasks (XML full parse — triggers, actions, hidden encoded args)
- BITS Jobs (qmgr0.dat/qmgr1.dat/qmgr.db — source URLs, destinations, notify URLs)
- $SI vs $FN timestomp detection (3 independent methods)
- SRUM (System Resource Usage Monitor) binary extraction
- PCA (Program Compatibility Assistant) — Windows 11 execution log

---

#### Remnant — Deleted and Anti-Forensic Evidence
Recycle Bin, USN Journal, ADS, anti-forensic tool detection.

**Artifacts parsed:**
- $I Recycle Bin records (original path, deletion time, file size)
- $UsnJrnl full USN_RECORD_V2 parse (all reason flags)
- Zone.Identifier ADS (download origin, referrer URL)
- Anti-forensic tool detection: sdelete, CCleaner, BleachBit, Eraser, Cipher.exe
- VSS deletion indicators (Event ID 8224)
- SQLite WAL recovery detection

---

#### Guardian — Security Software Logs
Windows Defender, AV/EDR logs, WER crash files, firewall.

---

#### Cipher — Credentials and Exfiltration
WiFi passwords, browser credentials, SSH keys, cloud keys, remote access tools.

**Artifacts parsed:**
- WiFi XML profiles (SSID, authentication type, encryption, PSK presence)
- TeamViewer session logs (tab-delimited)
- AnyDesk connection_trace.txt (pipe-delimited)
- OneDrive/Dropbox/Google Drive sync evidence
- FileZilla XML credentials
- Windows Credential Manager DPAPI blob detection
- SSH private key detection

---

#### Vault — Hidden Storage and Anti-Forensic Detection
VeraCrypt, photo vault apps, steganography, encrypted archives, Tor Browser, secure messaging.

**VeraCrypt / TrueCrypt:**
- Volume detection via entropy analysis (Shannon entropy > 7.9 on sector-aligned files)
- VeraCrypt.xml preferences (last mounted volumes, keyfile paths)
- Registry artifacts (last volume path, mount history)

**Mobile photo vault apps (iOS + Android):**
- Calculator+ (com.mobilityware.calculator)
- Keepsafe (com.keepsafe.keepsafe / com.keepsafe.vault)
- Private Photo Vault (com.destek.recovery)
- Hide It Pro (com.hideitmedia.hideitpro)
- NQ Vault, Secret Folder, Photo Safe, Calculator Vault
- .nomedia file detection (Android gallery hiding)

**Anti-forensic tools:**
- CCleaner (registry + config + last run timestamp)
- BleachBit (config + cleaners enabled)
- Eraser (XML task list + scheduled targets)
- sdelete / Cipher.exe (Prefetch + Event Log)
- Metadata stripping tools (ExifTool, MAT2)

**Hidden storage:**
- Partition table anomalies (MBR + GPT — unaccounted sectors, gap detection)
- HPA / DCO detection indicators
- Steganography statistical indicators (LSB chi-square, file size anomalies)
- Known steganography tool output patterns (OpenStego, SilentEye)

**Encrypted archives:**
- 7-Zip encrypted (AES-256 flag detection)
- ZIP with encryption (general purpose bit flag)
- RAR encrypted (header flag)
- AxCrypt (.axx files, magic bytes)

**Secure messaging (presence detection):**
- Signal Desktop (Windows + macOS)
- Wickr, Session, Briar

**Tor Browser:**
- places.sqlite (.onion URL history)
- torrc (custom bridge configuration)
- Extension inventory
- Circuit log artifacts

---

#### W-10 — PowerShell Execution History
ConsoleHost_history.txt — full command history with suspicious pattern detection.

Flags: base64 encoded commands, download cradles (IEX/DownloadString/WebClient), AMSI bypass patterns, credential harvesting, lateral movement commands, LOLBin abuse.

---

### macOS Forensics

#### MacTrace — macOS System Artifacts
LaunchAgents, FSEvents, Unified Log, Gatekeeper, KnowledgeC, Biome, plist artifacts, Rosetta 2.

**Artifacts parsed:**
- LaunchAgents/LaunchDaemons (persistence)
- FSEvents (.fseventsd — file system activity log)
- Apple Unified Logging (.tracev3) — sudo, sshd, SecurityAgent, screensharingd, MDM
- Gatekeeper quarantine database
- Time Machine metadata
- KnowledgeC.db (macOS 10.x–12.x) — app focus, Safari history, device lock, app sessions
- Apple Biome (macOS 13+ Ventura through Sequoia) — SEGB/protobuf format
  - AppFocusActivity, SafariHistory, NotificationCenter, MediaPlayback
  - NetworkUsage, LocationActivity, DeviceLocked
- plist artifacts: com.apple.recentitems, LoginItems, QuarantineEventsV2, sidebarlists, Dock
- Modern macOS artifacts (13–15): Background Task Management DB, Screen Time DB, InstallHistory.plist, netusage.sqlite
- Rosetta 2 translation cache — proves deleted x86_64 binaries executed on Apple Silicon

---

#### Apex — Image Metadata and Authenticity
Deep EXIF parsing with media authenticity indicators.

**Artifacts parsed:**
- GPS coordinates (decimal degrees, altitude, speed plausibility check)
- Device make/model (camera fingerprinting)
- DateTimeOriginal, DateTimeDigitized, filesystem timestamps
- Software field (Photoshop/GIMP/Stable Diffusion/ComfyUI flagging)
- Thumbnail mismatch detection (cropping/replacement indicator)
- Error Level Analysis (ELA) — JPEG recompression inconsistency detection
- Timestamp consistency cross-check (EXIF vs filesystem)

**Supported formats:** JPEG, PNG, TIFF, HEIC/HEIF

---

### iOS Forensics

#### Pulse (iOS) — 196 iOS Artifact Parsers

**Communications:**
- iMessage / SMS (chat.db) — attributedBody BLOB decode, tapback/reaction tracking, disappearing message indicators, attachment metadata
- WhatsApp — message database, media metadata, ephemeral message indicators
- Signal — presence detection, WAL fragment recovery
- Telegram — presence detection, tdata structure
- Snapchat — arroyo.db (snap metadata, expiry timestamps)
- FaceTime call history

**Browsing:**
- Safari history, bookmarks, downloads, reading list, cached search terms
- Chrome iOS (history, downloads)
- Firefox iOS

**Location and activity:**
- KnowledgeC.db (iOS) — /app/inFocus, /device/isPluggedIn, /device/batteryPercentage, /safariHistory, /location/significant
- iOS Biome — streams/app/inFocus, streams/safariHistory, streams/photos/assetAdded, streams/messaging/sent, streams/location/significant
- Significant Locations (frequented places)
- Maps search history
- Find My location data

**Health and fitness:**
- HealthKit database (steps, heart rate, sleep, workouts)
- Workout routes (GPS tracks)
- Strava, AllTrails activity databases

**Device and system:**
- PowerLog (battery and screen-on events)
- Apple Pay transaction records
- HomeKit device inventory
- CarPlay connection history
- Clipboard history
- Keyboard cache (typed word suggestions)
- Notification history
- Calendar events and reminders
- Contacts database

**Cloud:**
- iCloud Drive sync metadata
- Photos library (asset database, location, creation metadata)

---

#### MOB-1/2/3 — iOS Biome and iMessage Deep Parsers
- iOS Biome SEGB format — location tracking (T1430), messaging, photo capture
- iOS KnowledgeC — battery, media, messages, charging state
- iMessage attributedBody decode — recovers message text from iOS 16+ BLOB format

---

### Android Forensics

#### Carbon — Android System and Browser Artifacts
Chromium-based browser deep parsing, factory reset detection, Samsung-specific artifacts, work profile/MDM, ADB backup.

**Chromium browsers (Chrome, Edge, Brave, Opera, Vivaldi):**
- History (URLs, visit counts, last visit, WebKit epoch conversion)
- Downloads (target path, source URL, referrer, danger type)
- Login Data (origin URL, username, creation/last used — no passwords)
- Autofill (form field values, use counts)
- Favicons (confirms URLs even after history cleared)
- Network Action Predictor (typed URL prefixes)
- Search terms (keyword searches)

**Factory reset detection:**
- /data/misc/bootstat/factory_reset (mtime = wipe timestamp)
- /data/misc/bootstat/persistent_boot_stat (boot reason history)
- Samsung /data/system/resetinfo
- Samsung Knox device_policies.xml wipe records
- Confidence-rated output with examiner caveats

**Samsung-specific artifacts:**
- Samsung Health (step count, heart rate, sleep, exercise sessions)
- Samsung Knox security events (failed unlock attempts, biometric events, MDM commands)
- Samsung Location History (independent of Google location)
- Samsung Messages database
- Samsung Internet browser history

**Work profile / MDM:**
- /data/system/users/ — personal vs work profile separation
- device_policies.xml — device administrator list, password policy, wipe-after-N-failures
- MDM app detection: AirWatch, MobileIron/Ivanti, Intune, Citrix, JAMF, SOTI, BlackBerry
- Remote wipe command detection (highest forensic value)

**ADB backup (.ab format):**
- Magic byte validation (ANDROID BACKUP)
- Header parse (version, compression, encryption detection)
- Included app inventory (proves what was on device)
- Database file inventory
- Encrypted backup detection with examiner note

---

#### Specter — Android System Artifacts
Package inventory, Wi-Fi config, device profile, backup artifacts.

---

#### Pulse (Android) — 232 Android Artifact Parsers

**Communications:**
- SMS/MMS (MMSSMS.db)
- Call logs (contacts2.db)
- WhatsApp (msgstore.db — messages, media, ephemeral indicators, WAL recovery)
- Telegram (/data/data/org.telegram.messenger/ — tdata, message fragments)
- Signal (database presence, WAL fragment carving)
- Snapchat (arroyo.db — snap metadata, viewed timestamps)
- Viber (viber.db — messages, calls)
- WeChat (MSG databases — messages, payment artifacts)
- Line (naver_line.db — messages)
- Facebook Messenger
- Instagram Direct

**Browsing:**
- Chrome history (all tables)
- Firefox for Android
- Samsung Internet

**Location:**
- Google Maps search history and navigation
- Google Location History (JSON export format)
- Network location cache

**Health and fitness:**
- Google Fit databases
- Samsung Health (step count, heart rate, GPS tracks)

**Gaming platforms:**
- Steam (loginusers.vdf, chat logs, playtime)
- Discord (LevelDB message fragments, user IDs)
- Xbox (local app artifacts)
- Roblox (log files, chat fragments, player IDs)

**Device and system:**
- Contacts database
- Calendar events
- Gmail artifacts
- Google Drive sync metadata
- Clipboard history
- Keyboard cache
- Notification database
- Wi-Fi connection history and passwords
- Bluetooth device history
- Installed app inventory with timestamps
- Google account artifacts

**AI apps:**
- ChatGPT local artifacts (conversation metadata)
- Microsoft Copilot artifacts
- AI app installation records

**Ephemeral messaging indicators:**
- WhatsApp disappearing message timer settings
- Telegram TTL detection
- Snapchat expiry metadata
- SQLite WAL fragment recovery across all messaging DBs

---

### Linux Forensics

#### ARBOR — Linux and Unix System Artifacts
Shell history, persistence mechanisms, system logs, SSH artifacts, package history, containers.

**Shell history:**
- bash (~/.bash_history) — with timestamp parsing when HISTTIMEFORMAT set
- zsh (~/.zsh_history) — extended history format (: timestamp:elapsed;command)
- fish (~/.local/share/fish/fish_history) — YAML format
- History tampering detection (zeroed file, timestamp gaps, truncation)
- Shell init persistence (~/.bashrc, ~/.bash_profile, /etc/profile, ~/.zshrc)

**Persistence mechanisms:**
- Systemd unit files (/etc/systemd/system/, /lib/systemd/system/, ~/.config/systemd/user/)
  - ExecStart path analysis, privileged mode, timer intervals
  - Unowned unit files (not installed by any package)
- Cron (/etc/crontab, /etc/cron.d/, /var/spool/cron/crontabs/, at jobs)
- rc.local and SysV init scripts (/etc/init.d/, /etc/init/)
- LD_PRELOAD (/etc/ld.so.preload — rootkit indicator)
- SUID/SGID binary anomalies

**System logs:**
- Systemd journal (.journal binary format — EMERG through ERROR priority)
- auth.log / /var/log/secure — SSH logins, sudo, PAM, failed attempts
- syslog / messages — USB events, kernel errors, process crashes
- Rotated/compressed logs (.gz decompression and parse)
- wtmp/btmp/lastlog (binary utmp format — login history, failed logins)

**SSH artifacts:**
- /etc/ssh/sshd_config (PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords)
- ~/.ssh/authorized_keys (per user — key inventory, anomaly detection)
- ~/.ssh/known_hosts (systems this user connected to, .onion addresses)
- ~/.ssh/config (configured tunnels, ProxyJump chains)

**Package manager history:**
- APT (/var/log/apt/history.log, /var/log/dpkg.log)
- YUM/DNF (/var/log/yum.log, /var/log/dnf.log)
- Pacman (/var/log/pacman.log)
- Suspicious package detection (nmap, netcat, john, hydra, hashcat, metasploit, sqlmap)

**User accounts:**
- /etc/passwd (UID=0 anomalies, suspicious usernames, shell/home mismatches)
- /etc/shadow metadata (recent password changes, non-expiring accounts)
- /etc/sudoers + /etc/sudoers.d/ (unrestricted sudo rules, non-admin grants)

**Docker/Container artifacts:**
- Container config.v2.json (image, name, created, entrypoint, environment, mounts)
- Container logs (stdout/stderr with timestamps)
- Privileged container detection
- Sensitive host path mount detection (/etc, /root, /var mounted into container)
- Docker image history (Dockerfile command history, build timestamp)
- Overlay2 filesystem diff scanning (new executables in /tmp, modified /etc/passwd)
- Suspicious environment variable detection (PASSWORD, SECRET, TOKEN, KEY)

---

### Network Forensics

#### NetFlow — Network Traffic and IDS
PCAP/PCAPNG, DNS logs, IDS/IPS alerts, web server logs.

**Artifacts parsed:**
- PCAP/PCAPNG full packet parse
- BIND named query logs (client IP, query, type, response)
- Windows DNS debug logs
- macOS mDNSResponder (from Unified Logs)
- Snort fast alert format (signature, classification, priority, src/dst)
- Suricata eve.json (all fields including rule ID)
- IIS/Apache/Nginx access and error logs
- Exfiltration tool detection

---

#### Conduit — Network Configuration
WiFi profiles, RDP history, VPN artifacts, DNS cache.

---

### Malware and Threat Analysis

#### Vector — Malware Indicators
PE headers, VBA macros, PowerShell obfuscation, known tool detection.

**Artifacts parsed:**
- PE headers (imports, exports, compile timestamp, sections, entropy)
- VBA macro extraction and analysis
- PowerShell obfuscation patterns
- Mimikatz, Cobalt Strike, Meterpreter indicators
- Office document macro indicators

---

#### Wraith — Memory Artifacts
hiberfil.sys artifacts, LSASS dump detection, crash dump analysis.

---

#### Recon — Entity Extraction
Username/email/IP extraction, AWS key detection, SID history, IOC surface area.

---

### Cloud and Collaboration

#### Nimbus — Cloud Storage and Collaboration
OneDrive (updated SQLite schema + quickXorHash), Google Drive, Microsoft Teams, Slack, M365 UAL, AWS CloudTrail, Azure Activity Logs.

**OneDrive (updated 2025 schema):**
- SyncEngineDatabase.db (SQLite)
- LocalPath, ServerPath, QuickXorHash, SHA1Hash, FileSize, ModifiedTime
- DeletedTime (proves file existed even after deletion)
- Account email association

---

### Intelligence Layer

#### Sigma — Correlation Engine
34 built-in rules + full SigmaHQ import capability.

**Built-in rule categories:**
- Credential access (Mimikatz, LSASS access, SAM dump)
- Lateral movement (PsExec, WMI, scheduled task creation)
- Defense evasion (timestomping, log clearing, AMSI bypass)
- Persistence (registry run keys, scheduled tasks, services)
- Execution (PowerShell encoded, LOLBins, script block logging)
- Exfiltration (cloud upload tools, DNS tunneling)
- Command and control (beaconing patterns, Cobalt Strike indicators)

**SigmaHQ import:**
- Import 3,000+ community rules from YAML files, directories, or ZIP archives
- Full SIGMA detection language support (field modifiers, condition expressions)
- Time-window cross-artifact correlation
- Rule validation on import (invalid rules skipped, not failed)

**Kill chain reconstruction:**
- Automatically maps all detected artifacts to 14 ATT&CK tactic stages
- Attack timeline with start/end timestamps and duration
- Completeness score (stages covered / total stages)
- Missing stage identification

**Behavioral detection:**
- Beaconing: coefficient of variation analysis on connection intervals (CV < 0.3 = regular = suspicious)
- Credential harvesting: LSASS access + account creation + lateral movement correlation
- Lateral movement chains: multi-hop visualization with timestamps
- Hypothesis-driven hunt mode: 8 pre-built hunt packages (InsiderThreat, Ransomware, APT, CredentialTheft, DataStaging, Persistence, AntiForensic)

---

### Forensic Support Modules

#### CSAM Detection (`strata-csam`)
- NCMEC MD5 hash list import, Project VIC VICS JSON, SHA1/SHA256 generic sets
- 64-bit dHash perceptual matching with Hamming distance scoring
- SHA256-chained immutable audit log
- Court-ready PDF/JSON reports — no image content ever embedded
- Mandatory 18 U.S.C. § 2258A reporting notice in every report
- **Free on all license tiers — no gating, ever**

#### ML Analysis (`strata-ml-*`)
All modules are deterministic — no model files, no cloud calls, fully local.

| Module | Purpose |
|---|---|
| strata-ml-anomaly | Statistical outlier detection across file metadata — catches timestomping, data staging, exfil patterns |
| strata-ml-summary | Plain-English case narrative generator — one paragraph for the prosecutor, one for the jury |
| strata-ml-obstruction | 0-100 anti-forensic obstruction score — aggregates all detected anti-forensic behavior |
| strata-ml-charges | Charge indicator mapping to common statutes |

---

## Examiner Experience Features

### Chain of Custody
- **Tamper-evident audit log** — SHA256-chained entries, every examiner action recorded
- **Evidence integrity verification** — hash check on image open, mismatch warning
- **Warrant scope enforcement** — flag out-of-scope artifacts, minimization logging
- **FACT Attribution Framework** — competing hypotheses, confidence levels, AI disclosure

### Reporting
- **Civilian court HTML report** — agency branding, logo, signature block, case number
- **UCMJ court-martial format** — DD Form 2922 fields, UCMJ Article selection, examiner certification block
- **Ed25519 cryptographic report sealing** — mathematically verifiable report integrity
- **Expert witness mode** — plain-language output for judges and juries
- **Media authenticity indicators** — ELA analysis, EXIF consistency, software field flagging

### Workflow
- **Triage mode** — 60-second fast scan, top findings, risk indicator, field-ready
- **Unified timeline** — all artifacts chronological, bodyfile export, activity density visualization
- **Global IOC search** — STIX 2.1, MISP JSON, OpenIOC, plain text feed import
- **NSRL hash set** — known-good file exclusion
- **Artifact filtering** — by plugin, MITRE technique, date range, forensic value, suspicious flag
- **Artifact notes** — examiner annotations with case-critical bookmarking
- **Multi-image correlation** — shared hashes, accounts, IPs, communication records across devices
- **ATT&CK Navigator export** — layer JSON for local Navigator instance
- **CSV/JSON export** — interoperability with Autopsy, Cellebrite, custom databases

### Field Use
- **Low resource mode** — < 8GB RAM optimized, streaming artifact write
- **Partial image scan** — scan first N GB for rapid field triage
- **Selective re-scan** — re-run single plugin without full rescan
- **Offline threat intel** — Emerging Threats, Feodo Tracker, MalwareBazaar, LOKI/THOR feed import

---

## Intelligence Coverage by Agency Mission

| Agency / Mission | Key Strata Capabilities |
|---|---|
| Army CI / Army CID / NCIS / AFOSI / CGIS | CSAM detection, SAPR evidence (Android factory reset, iMessage, Biome location), UCMJ report format, mobile full coverage |
| FBI Cyber / RCFL | Full Windows artifact coverage, lateral movement detection, memory forensics, malware indicators, MITRE kill chain |
| HSI | CSAM, WhatsApp/Telegram/Signal parsing, Tor Browser artifacts, photo vault detection, dark web indicators |
| IRS-CI | Crypto wallet detection (Bitcoin Core, Electrum, MetaMask, exchange CSVs), cloud sync evidence |
| USSS | Crypto artifacts, financial platform indicators, anti-forensic detection |
| DEA | EXIF GPS deep parse, WhatsApp/Telegram, Tor Browser, location timeline |
| ATF | EXIF metadata (weapons photos), 3D printing artifact detection |
| ICAC Task Forces | CSAM (non-negotiable), gaming platform artifacts (Roblox, Discord, Steam), photo vault apps |
| Corporate Insider Threat | USB history, LNK/JumpList/RecentDocs, cloud sync exfil, anti-forensic tools, Teams/Slack chat |
| Private Forensic Firms | Chain of custody, agency branding, expert witness report, Ed25519 signed reports |
| Military SCIF / Air-gapped | Single binary, no network, no telemetry, no license server, USB portable |

---

## Build

```bash
# Prerequisites: Rust stable
git clone https://github.com/WolfmarkSystems/strata.git
cd strata
cargo build --release
```

The release binary is self-contained. Copy it to a USB drive. Run it anywhere.

**CI:** macOS ✅ · Linux ✅ · Windows ✅

---

## Licensing

**Government Use License — Free**  
US military and law enforcement use Strata free of charge. Verified by .mil or .gov email, CAC, or command letter.

Covers: Army CID, NCIS, AFOSI, CGIS, DCIS, FBI RCFL, HSI, IRS-CI, USSS, DEA, ATF, USPIS, ICAC task forces, state police, municipal LE digital forensics units.

**Commercial License — Annual**  
Private forensic firms, corporate security teams, independent examiners, legal firms, insurance investigators, and international law enforcement.

Contact: contact@wolfmarksystems.com

---

## CSAM Policy

The CSAM detection module is free on every license tier. No gating. No upsell. No exceptions.

Every examiner doing this work deserves every tool available to protect children.

---

## Security

To report a vulnerability: [SECURITY.md](SECURITY.md)

---

## Copyright

Copyright © 2026 Wolfmark Systems. All rights reserved.  
US Copyright Registration: Case #1-15137320181

See [LICENSE](LICENSE) for full terms.

---

**wolfmarksystems.com** · [@WolfmarkSystems](https://x.com/WolfmarkSystems) · [contact@wolfmarksystems.com](mailto:contact@wolfmarksystems.com)
