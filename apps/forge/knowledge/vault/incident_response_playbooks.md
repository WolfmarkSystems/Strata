# Incident Response Playbooks

## Overview

Incident Response (IR) is the methodology for handling security incidents. The goal is to handle the situation in a way that limits damage and reduces recovery time and costs.

## IR Phases (NIST)

### 1. Preparation
- [ ] Establish IR team
- [ ] Document contact info
- [ ] Define severity levels
- [ ] Create runbooks
- [ ] Deploy monitoring
- [ ] Train staff

### 2. Detection & Analysis
- [ ] Identify the incident
- [ ] Determine scope
- [ ] Assess severity
- [ ] Document findings
- [ ] Notify stakeholders

### 3. Containment
- [ ] Isolate affected systems
- [ ] Block attacker access
- [ ] Preserve evidence
- [ ] Prevent spread
- [ ] Implement temporary fixes

### 4. Eradication
- [ ] Remove malware
- [ ] Close vulnerabilities
- [ ] Patch systems
- [ ] Reset credentials
- [ ] Remove attacker tools

### 5. Recovery
- [ ] Restore from clean backups
- [ ] Rebuild compromised systems
- [ ] Verify functionality
- [ ] Monitor for recurrence
- [ ] Resume operations

### 6. Post-Incident
- [ ] Document lessons learned
- [ ] Update procedures
- [ ] Improve detection
- [ ] Review policy
- [ ] Brief stakeholders

## Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| Critical | Active breach, data exfil | Immediate |
| High | Confirmed compromise | 1 hour |
| Medium | Suspicious activity | 4 hours |
| Low | Policy violation | 24 hours |

## Common Incident Types

### 1. Malware Infection

#### Indicators
- Unusual processes
- High CPU/disk usage
- Unknown files
- Network connections

#### Response Steps
```bash
# 1. Isolate
# Disconnect from network

# 2. Identify
tasklist
netstat -ano
wmic process list

# 3. Capture
# Memory dump
winpmem_mini_x64.exe memory.raw

# 4. Analyze
# Use volatility, YARA

# 5. Eradicate
# Reimage system
```

### 2. Phishing

#### Indicators
- Suspicious emails
- User reports
- Mails server logs

#### Response Steps
```powershell
# 1. Quarantine
Get-Mailbox -Identity user | Search-Mailbox -SearchQuery "subject:phishing" -DeleteContent

# 2. Block sender
Add-IPBlockListEntry -IpAddress 1.2.3.4

# 3. Notify users
# Send security awareness

# 4. Check for compromise
# Check for forwarded emails
Get-Mailbox -Identity user | Get-MailboxForwardingStatistics
```

### 3. Ransomware

#### Indicators
- Encrypted files
- Ransom notes
- Unusual file extensions

#### Response Steps
```powershell
# 1. ISOLATE IMMEDIATELY
# Disconnect network cable
# Disable WiFi

# 2. Identify variant
# Check ransom note
# Check file extension

# 3. Check backups
# Verify backup integrity

# 4. Report
# Contact law enforcement
# No More Ransom project

# 5. Don't pay
# Recovery may be possible
```

### 4. Unauthorized Access

#### Indicators
- Failed login attempts
- Unknown accounts
- Unusual admin activity

#### Response Steps
```bash
# 1. Review logs
/var/log/auth.log
/var/log/secure
Windows Event Viewer

# 2. Identify scope
# Which accounts?
# What access?

# 3. Disable accounts
# Local
net user attacker /active:no
# AD
Disable-ADAccount -Identity attacker

# 4. Reset passwords
# All potentially compromised
```

### 5. Data Breach

#### Indicators
- DLP alerts
- Unusual data access
- Data in unexpected location

#### Response Steps
```bash
# 1. Contain
# Isolate affected systems

# 2. Assess scope
# What data?
# How much?
# Who affected?

# 3. Legal
# Notify legal counsel
# Check regulations (GDPR, HIPAA)

# 4. Notify
# Per legal requirements
# Regulatory agencies
# Affected individuals

# 5. Preserve evidence
```

## Evidence Collection

### Chain of Custody
```markdown
# Document:
- Date/Time
- Evidence description
- Location
- Who collected
- Who handled
- Methods used
- Hash values (MD5, SHA256)
```

### Live Collection
```powershell
# Memory
winpmem_mini_x64.exe memory.raw

# Network
tcpdump -i eth0 -w capture.pcap

# Process list
tasklist > processes.txt
netstat -ano > connections.txt

# Registry
reg export "HKLM\SOFTWARE" registry.hives
```

### Dead Box Collection
```bash
# Create forensic image
dd if=/dev/sda of=image.raw bs=4k

# Verify
md5sum /dev/sda > image.md5
sha256sum /dev/sda > image.sha256
```

## Communication Templates

### Initial Assessment
```
INCIDENT ASSESSMENT - [DATE]

Incident Type: [Malware/Phishing/Breach/etc]
Severity: [Critical/High/Medium/Low]
Status: [In Progress/Contained/Eradicated/Recovering]

Affected Systems:
- [system1]
- [system2]

Initial Findings:
[What we know so far]

Next Steps:
[Immediate actions required]
```

### Stakeholder Notification
```
SECURITY INCIDENT NOTIFICATION

Dear [Stakeholder],

We are investigating a security incident that may affect [systems/data].

What happened:
[Brief description]

What we are doing:
[Steps taken]

What you should do:
[Any required actions]

We will provide updates as the investigation continues.

Contact: [IR team email/phone]
```

### Post-Incident Report
```
POST-INCIDENT REPORT - [DATE]

Executive Summary:
[2-3 sentence overview]

Incident Details:
- Date/Time Discovered:
- Date/Time Contained:
- Date/Time Eradicated:
- Date/Time Recovered:

Timeline:
- [Time] - [Event]
- [Time] - [Event]

Root Cause:
[What allowed this to happen]

Impact:
- Systems affected:
- Data exposed:
- Business impact:

Lessons Learned:
- What went well:
- What needs improvement:
- Action items:
```

## IR Tools

### SIEM
- Microsoft Sentinel
- Splunk
- Elastic
- QRadar

### Forensic
- FTK Imager
- EnCase
- Autopsy
- Volatility
- SANS SIFT

### Endpoint Detection
- CrowdStrike
- Carbon Black
- Microsoft Defender
- SentinelOne

### Network
- Zeek
- Suricata
- Snort
- NetworkMiner

## Regulatory Requirements

| Regulation | Notification Timeframe | Authority |
|------------|----------------------|-----------|
| GDPR | 72 hours | EU DPA |
| HIPAA | 60 days | HHS |
| PCI-DSS | Immediate | Card brands |
| State laws | Varies | State AG |
| SEC | 4 days (public) | SEC |

## Contact List Template

```
INCIDENT RESPONSE CONTACTS

IR Team:
- IR Lead: [Name] - [Phone] - [Email]
- Technical Lead: [Name] - [Phone] - [Email]
- Communications: [Name] - [Phone] - [Email]

Executive:
- CISO: [Name] - [Phone]
- CEO: [Name] - [Phone]
- Legal: [Name] - [Phone]

External:
- Law Enforcement: [Agency] - [Phone]
- Insurance: [Carrier] - [Policy#]
- Forensics Firm: [Company] - [Contact]
- PR Firm: [Company] - [Contact]
```
