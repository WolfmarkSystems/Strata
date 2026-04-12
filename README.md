# Strata

**Professional digital forensics platform — 17 plugins, 355 mobile parsers, 34 Sigma rules, ML-powered analysis, court-ready reporting.**

Built by a US Army Counterintelligence Special Agent and Digital Forensic Examiner.  
Free for US military and law enforcement. Commercial licensing available.

---

## What is Strata

Strata is an air-gapped, court-ready forensic analysis platform built in Rust. It runs as a single binary on Windows, macOS, and Linux with no installation required. It parses evidence from Windows, macOS, iOS, and Android systems and produces court-defensible reports with a full chain-of-custody audit trail.

The tools that exist were built for enterprise budgets and conference demos. Strata was built for the examination — because a tool budget should never stand between an examiner and the evidence.

---

## Features

- **17 forensic plugins** covering Windows, macOS, iOS, Android, cloud, network, memory, and malware
- **355 mobile artifact parsers** — 157 Android (ALEAPP-equivalent) + 198 iOS (iLEAPP-equivalent), all read-only SQLite
- **34 Sigma correlation rules** with full MITRE ATT&CK kill chain coverage
- **ML-powered analysis** — anomaly detection, executive case summary, anti-forensic obstruction scoring (0-100)
- **CSAM detection module** — hash-based and perceptual detection, NCMEC/Project VIC compatible, immutable audit trail, free on all license tiers
- **Court-ready reporting** — Word and PDF export, chain-of-custody audit log, evidence integrity verification, obstruction score section
- **Air-gap deployable** — single binary (24 MB macOS), USB portable, no cloud dependency, no telemetry
- **Cross-platform** — Windows, macOS, Linux. Parses evidence from iOS and Android devices
- **89% pure Rust** — 2,393 tests, zero unsafe blocks in production paths, zero clippy warnings

---

## Plugins

| Plugin | Coverage |
|---|---|
| Phantom | Registry hives (SYSTEM/SOFTWARE/SAM/NTUSER/AmCache/USRCLASS), USBSTOR, ShimCache, WDigest, 23 persistence/credential/lateral-movement parsers, full AmCache schema |
| Chronicle | UserAssist, Jump Lists, LNK files, Shellbags, Windows Timeline |
| Sentinel | Security.evtx, PowerShell 4103/4104, Sysmon, RDP, Kerberos, lateral movement |
| Trace | Prefetch, BAM/DAM, Scheduled Tasks, BITS jobs, timestomp detection, structural SRUM ESE parser |
| Remnant | Recycle Bin, USN Journal, ADS, anti-forensic tool detection, VSS deletion |
| Guardian | Windows Defender, AV/EDR logs, WER crash files, firewall configuration |
| Cipher | WiFi passwords, browser credentials, SSH keys, AWS/Azure keys |
| MacTrace | LaunchAgents, FSEvents, Unified Log, Gatekeeper, quarantine, Time Machine |
| Nimbus | OneDrive, Google Drive, Teams, Slack, M365 UAL, AWS CloudTrail, Azure |
| Conduit | WiFi profiles, RDP history, VPN artifacts, DNS cache |
| NetFlow | PCAP/PCAPNG, IIS/Apache/Nginx logs, exfil tool detection |
| Vector | PE headers, VBA macros, PowerShell obfuscation, Mimikatz/Cobalt Strike |
| Wraith | hiberfil.sys, LSASS dump detection, crash dump analysis |
| Recon | Username/email/IP extraction, AWS AKIA key detection, SID history |
| Specter | Android backup (`.ab`), package inventory, Wi-Fi config, device profile |
| Pulse | **157 Android parsers** (SMS, calls, contacts, Gmail, Chrome, photos, location, clipboard, keyboard cache, Wi-Fi, Bluetooth, calendar, notifications + more) · **198 iOS parsers** (KnowledgeC, iMessage, Safari, Health, Significant Locations, Notes, WhatsApp, Signal, Telegram, Snapchat, Find My, Biome, PowerLog, HealthKit, Strava, AllTrails, CarPlay, HomeKit, Apple Pay, Workout Routes + more) — all read-only SQLite, UFDR-compatible |
| **Sigma** | **34 correlation rules. Always runs last. Full MITRE ATT&CK kill chain.** |

---

## CSAM Detection Module

The `strata-csam` crate provides hash-based and perceptual CSAM detection for forensic examiners and law enforcement.

- Imports NCMEC MD5 hash lists, Project VIC VICS JSON, and generic SHA1/SHA256 sets
- 64-bit dHash perceptual matching with Hamming distance scoring
- SHA256-chained immutable audit log — every action recorded, nothing auto-displayed
- Court-ready PDF and JSON reports — no image content ever embedded
- Mandatory reporting notice per 18 U.S.C. § 2258A in every report
- **Free on all license tiers — no gating, ever**

Examiners import their own hash sets. Strata never bundles hash data.

---

## ML-Powered Analysis

Strata includes three deterministic ML modules — no model files required, no cloud calls, all run locally.

| Module | What it does |
|---|---|
| **Anomaly Detection** (`strata-ml-anomaly`) | Flags statistical outliers across file metadata (timestamps, sizes, entropy). Catches timestomping, data staging, and exfiltration patterns that manual review misses. |
| **Executive Summary** (`strata-ml-summary`) | Generates a plain-English case summary from artifact data. One paragraph for the prosecutor, one for the jury — no jargon, no acronyms. |
| **Obstruction Scoring** (`strata-ml-obstruction`) | Produces a single 0-100 score summarizing all detected anti-forensic behavior (VSS deletion, log clearing, secure-delete tools, timestamp manipulation). Always advisory. |

All ML modules are available on **every license tier** including free Gov/Mil.

---

## Tools

| Tool | Purpose |
|---|---|
| `wolfmark-deploy` | Internal deployment wizard — builds signed, org-customized Strata USB packages with Ed25519 license signing, bulk license packs, and full audit trail |
| `wolfmark-license-gen` | License keypair generator |

---

## Build

```bash
# Prerequisites: Rust stable, Node.js, pnpm
git clone https://github.com/WolfmarkSystems/Strata.git
cd Strata
cargo build --release -p strata
```

**CI status:** macOS ✅ · Linux ✅ · Windows ✅

---

## Licensing

**Government Use License — Free**  
US military and law enforcement use Strata free. Verified by .mil or .gov email.  
Covers: Army CID, NCIS, AFOSI, CGIS, FBI RCFL, HSI, IRS-CI, USSS, DEA, ATF, ICAC task forces, state and local LE.

**Commercial License — Annual**  
For private forensic firms, corporate security teams, independent examiners, legal firms, and insurance investigators.  
Contact: contact@wolfmarksystems.com

---

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## Copyright

Copyright © 2026 Wolfmark Systems. All rights reserved.  
US Copyright Registration: Case #1-15137320181

See [LICENSE](LICENSE) for full terms.

---

**wolfmarksystems.com** · [@WolfmarkSystems](https://x.com/WolfmarkSystems) · [contact@wolfmarksystems.com](mailto:contact@wolfmarksystems.com)
