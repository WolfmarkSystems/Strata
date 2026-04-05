# MITRE ATT&CK Framework Reference

## Overview

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a knowledge base of adversary tactics and techniques based on real-world observations.

## Enterprise Matrix

### Reconnaissance

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Gather Victim Identity Information | Email addresses, credentials | Monitor threat intel feeds |
| Gather Victim Network Information | IP ranges, DNS, internal networks | Monitor DNS queries |
| Gather Victim Org Information | Relationships, supply chain | Monitor OSINT |
| Search Closed Sources | Paid databases, threat intel | Monitor subscriptions |
| Search Open Sources | Social media, search engines | Monitor search alerts |
| Search Victim-Owned Websites | Company websites | N/A |

### Resource Development

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Acquire Infrastructure | Domains, servers, cloud | Monitor new registrations |
| Compromise Accounts | Social media, email | Monitor account creation |
| Compromise Infrastructure | Malicious servers | Monitor infrastructure |
| Develop Capabilities | Malware, exploits | Threat intel |
| Obtain Capabilities | Malware, tools | Threat intel |

### Initial Access

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Drive-by Compromise | Exploit visiting websites | EDR, browser isolation |
| Exploit Public-Facing Application | Web vulnerabilities | WAF, patching |
| Hardware Additions | USB, network devices | Device control |
| Phishing | Spearphishing, spearphishing link | Email gateway, user training |
| Replication Through Removable Media | USB malware | Device control |
| Supply Chain Compromise | Software, hardware | Supply chain security |
| Trusted Relationship | Partner access | Monitor third-party access |
| Valid Accounts | Stolen credentials | MFA, anomaly detection |

### Execution

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Command and Scripting Interpreter | PowerShell, CMD, Python | Script blocking, AMSI |
| Exploit for Execution | Application exploits | Patch management |
| Inter-Process Communication | COM, LPC | Process monitoring |
| Native API | Windows API | EDR |
| Scheduled Task/Job | Task Scheduler, cron | Task monitoring |
| Software Deployment Tools | SCCM, PDQ | Deploy monitoring |
| System Services | Service execution | Service monitoring |
| User Execution | Malicious link, file | User training |

### Persistence

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Account Manipulation | Modify accounts | Monitor admin actions |
| BITS Jobs | Background Intelligent Transfer | Monitor BITS |
| Boot or Logon Autostart | Registry, Startup folder | Monitor autostart |
| Browser Extensions | Malicious extensions | Extension monitoring |
| Component Firmware | BIOS, UEFI | Firmware integrity |
| Compromise Client Software | Update mechanisms | Code signing |
| Create Account | New accounts | Monitor account creation |
| Create or Modify System Process | Windows services | Service monitoring |
| Event Triggered Execution | Windows Event Log | Log monitoring |
| External Remote Services | VPN, RDP | Monitor remote access |
| File and Directory Permissions Modification | Modify permissions | Audit logs |
| Hijack Execution Flow | DLL search order, DLL hijacking | EDR |
| Implant Client Image | Image planting | Integrity monitoring |
| Modify Authentication Process | MFA, password filter | Monitor auth changes |
| Office Application Startup | Office add-ins | Monitor Office |
| Pre-OS Boot | Bootkit, BIOS | Secure boot |
| Scheduled Task/Job | Scheduled tasks | Task monitoring |
| Server Software Component | Web shells | Monitor web servers |
| Traffic Signaling | ARP, routing | Network monitoring |
| Valid Accounts | Stolen accounts | MFA, anomaly |

### Privilege Escalation

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Abuse Elevation Control Mechanism | UAC bypass | Monitor UAC |
| Boot or Logon Initialization | Login scripts | Monitor scripts |
| Create Process with Token | Token stealing | Process monitoring |
| Exploitation for Privilege Escalation | Kernel exploits | Patch, EDR |
| Fake Microsoft Service | Masquerading | Monitor services |
| File and Directory Permissions Modification | Wrong permissions | Audit logs |
| Hijack Execution Flow | DLL, EXE hijacking | EDR |
| Process Injection | DLL, reflective | EDR |
| Scheduled Task/Job | Root task | Task monitoring |
| Service File Permissions Weakness | Wrong service perms | Service audit |
| Setuid and Setgid | Linux priv escal | Audit logs |
| Sudo and Sudo Caching | Sudo misconfig | Monitor sudoers |

### Defense Evasion

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Abuse Elevation Control Mechanism | UAC bypass | Monitor UAC |
| Access Token Manipulation | Token manipulation | EDR |
| Binary Padding | Add junk to binary | File integrity |
| Bypass Data Loss Prevention | DLP bypass | Monitor data flows |
| Deobfuscate/Decode Files | Unpack, decrypt | Monitor decryption |
| Disk Wipe | Destroy evidence | Monitor disk I/O |
| Domain Policy Modification | GPO manipulation | Monitor GPO |
| Execution Guardrails | Environment keying | Monitor execution |
| File and Directory Permissions Modification | Remove permissions | Audit |
| Hide Artifacts | Hidden files, Alternate Data Streams | File monitoring |
| Hijack Execution Flow | DLL, code injection | EDR |
| Impair Defenses | Disable AV, logging | Monitor security tools |
| Indicator Removal | Clear logs, timestomp | Log monitoring |
| Masquerading | Rename, fake files | File integrity |
| Modify Authentication Process | Change MFA | Monitor auth |
| Modify Registry | Registry artifacts | Registry monitoring |
| Network Traffic Capture | Cleartext, protocols | Network monitoring |
| Obfuscated Files or Information | Encrypted, packed | File analysis |
| Pre-Process Binary | Packing | File analysis |
| Rootkit | Hide processes, files | Memory forensics |
| Subvert Trust Controls | Code signing, certificates | Certificate monitoring |
| Trusted Developer Utilities | MSBuild, wireshark | Monitor usage |

### Credential Access

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Brute Force | Login attempts | Account lockout, MFA |
| Credentials from Password Stores | Browser, password managers | Monitor access |
| Exploit for Credential Access | Memory, DLL | EDR |
| Forced Authentication | SMB, Kerberos | Network monitoring |
| Input Capture | Keylogger, clipboard | EDR |
| Modify System Image | Authentication library | Integrity |
| Network Sniffing | Cleartext creds | Network monitoring |
| OS Credential Dumping | LSASS, SAM | Credential guard |
| Steal Application Access Token | OAuth, API tokens | Monitor tokens |
| Steal Web Session | Session hijacking | Monitor sessions |
| Two-Factor Authentication Interception | MFA bypass | Monitor MFA |

### Discovery

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Account Discovery | User, admin groups | Monitor queries |
| Application Window Discovery | Running apps | Process monitoring |
| Browser Information Discovery | Browser data | Monitor browsers |
| Cloud Infrastructure Discovery | Cloud APIs | Audit logs |
| Code Signing Dependencies Discovery | Signed binaries | Binary analysis |
| Container and Resource Discovery | Docker, Kubernetes | Monitor API |
| Domain Discovery | Trust relationships | Monitor DNS, LDAP |
| File and Directory Discovery | File enumeration | Audit |
| Group and Policy Discovery | AD, group policy | Monitor queries |
| Host System Discovery | System info | Process monitoring |
| Network Service Discovery | Port, service scan | NIDS |
| Network Sniffing | Network traffic | NIDS |
| Password Policy Discovery | Policy settings | Audit |
| Permission Groups Discovery | AD groups | Audit |
| Process Discovery | Running processes | Process monitor |
| Query Registry | Registry queries | Audit |
| Remote System Discovery | Discovery tools | EDR |
| Software Discovery | Installed software | Inventory |
| System Information Discovery | OS, hardware | Process monitor |
| System Network Configuration Discovery | Network config | Audit |
| System Network Connections Discovery | Active connections | Network monitor |
| System Owner/User Discovery | Users | Audit |
| System Service Discovery | Services | Service monitor |

### Lateral Movement

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Application Deployment Software | SCCM, PDQ | Deploy monitoring |
| Exploitation of Remote Services | Service exploits | Patch, EDR |
| Internal Spearphishing | Internal phishing | Email monitoring |
| Logon Scripts | Login scripts | Script monitoring |
| Pass the Hash | NTLM hash reuse | Network monitoring |
| Pass the Ticket | Kerberos ticket | Monitor TGT |
| Remote Services | SSH, RDP, VNC | Monitor remote access |
| Replication Through Removable Media | Spread via USB | Device control |
| Software Deployment Tools | Deploy tools | Deploy monitoring |
| Taint Shared Content | Contaminate shared drives | File integrity |
| Use Alternate Authentication Material | Token, hash reuse | EDR |

### Collection

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Archive Collected Data | Compression, encryption | Monitor archives |
| Audio Capture | Microphone | Device control |
| Automated Collection | Scripts | Process monitoring |
| Browser Session Hijacking | Cookies, sessions | Monitor sessions |
| Clipboard Data | Clipboard | Monitor clipboard |
| Cloud Dashboard | Cloud API | Audit logs |
| Clipboard Monitoring | GPO, keylogger | EDR |
| Data from Common Application | Browser, email | Monitor apps |
| Data from Information Repositories | SharePoint, Confluence | Audit |
| Data from Local System | Local files | File monitoring |
| Data from Network Shared Drive | Network shares | File integrity |
| Data from Removable Media | USB | Device control |
| Email Collection | Email archives | Monitor access |
| Screen Capture | Screenshots | EDR |
| Video Capture | Webcam | Device control |

### Command and Control

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Application Layer Protocol | HTTP, DNS | NIDS |
| Communication Through Removable Media | USB | Device control |
| Data Encoding | Base64, unicode | NIDS |
| Data Obfuscation | Encryption, tunneling | NIDS |
| Dynamic Resolution | DNS, fast-flux | DNS monitoring |
| Encrypted Channel | TLS | NIDS |
| Fallback Channels | Alternate C2 | Network monitoring |
| Ingress Tool Transfer | Download tools | EDR |
| Multi-Stage Channels | Multi-hop | Network monitoring |
| Non-Application Layer Protocol | Raw TCP, UDP | NIDS |
| Non-Standard Port | Unusual ports | Firewall logs |
| Protocol Tunneling | SSH tunneling | NIDS |
| Proxy | HTTP, SOCKS | Network monitoring |
| Remote Access Software | RAT, VNC | EDR |
| Web Service | Cloud APIs | API logs |

### Exfiltration

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Alternate Protocol | FTP, SMTP | Network monitoring |
| Archive Over Network | Compression | Network monitoring |
| Automated Exfiltration | Scheduled | DLP |
| Backdoor Over Web Service | Data via C2 | DLP |
| Cached Domain Credentials | Credential caching | Audit |
| Data Compressed | WinRAR, gzip | Monitor archives |
| Data Encrypted | Encryption | DLP |
| Data Transfer Size Limits | Chunking | DLP |
| Exfiltration Over Alternative Protocol | Non-HTTP | Network |
| Exfiltration Over Web Service | Cloud, webDAV | DLP |
| Scheduled Transfer | Scheduled exfil | Monitor scheduled tasks |

### Impact

| Technique | Description | Detection |
|-----------|-------------|-----------|
| Account Access Removal | Disable accounts | Monitor accounts |
| Data Destruction | Wiper | File integrity |
| Data Encrypted for Impact | Ransomware | EDR |
| Data Manipulation | Defacement, logs | Integrity |
| Denial of Service | DDoS, resource | Network monitoring |
| Disk Wipe | Destroy disk | Monitor disk I/O |
| Endpoint Denial of Service | Blue screen | EDR |
| Exfiltration Over Physical Medium | USB | Device control |
| Firmware Corruption | Brick device | Firmware integrity |
| Inhibit System Recovery | Delete backups | Monitor backups |
| Network Denial of Service | Traffic flood | Network monitoring |
| Resource Hijacking | Cryptomining | Process monitor |
| Service Stop | Stop services | Service monitoring |
| System Shutdown/Reboot | Shutdown | Event logs |

## MITRE ATT&CK Techniques - Quick Reference

### Linux-Specific
| Technique | ID | Description |
|-----------|-----|-------------|
| SSH | T1021.004 | Remote services |
| Web Shell | T1505.003 | Server software |
| Sudo | T1548.003 | Abuse |
| Cron | T1053.003 | Scheduled task |
| LD_PRELOAD | T1574.006 | Hijack |
| Proc Filesystem | T1005 | Collection |

### macOS-Specific
| Technique | ID | Description |
|-----------|-----|-------------|
| AppleScript | T1059.002 | Execution |
| Hidden Files | T1564 | Evasion |
| Dylib Hijacking | T1574.001 | Persistence |

### Cloud-Specific
| Technique | ID | Description |
|-----------|-----|-------------|
| Cloud Service | T1588 | Resource |
| Valid Account | T1078 | Initial access |
| API Service | T1204 | Execution |
| Network Service Discovery | T1590 | Discovery |

## Tools Mapping to ATT&CK

### Reconnaissance
- Nmap
- theHarvester
- Shodan
- Maltego

### Weaponization
- Metasploit
- Cobalt Strike
- Covenant

### Delivery
- Phishing frameworks
- Watering hole tools

### Exploitation
- Metasploit
- Exploit-db
- Cobalt Strike

### Installation
- Empire
- Covenant
- Cobalt Strike

### Actions
- Mimikatz
- Rubeus
- PowerSploit

## Detection Resources

### ATT&CK Navigator
https://mitre-attack.github.io/attack-navigator/

### Atomic Red Team
https://github.com/redcanaryco/atomic-red-team

### Caldera
https://github.com/mitre/caldera

### ATT&CK CoA
https://mitre.github.io/attack-coa/
