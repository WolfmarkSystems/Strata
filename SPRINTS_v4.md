# SPRINTS_v4.md — STRATA AUTONOMOUS BUILD QUEUE
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md and SPRINTS_v4.md. Execute all incomplete sprints in order.
#         For each sprint: implement, test, commit, then move to the next."
# Last updated: 2026-04-16
# Prerequisite: All SPRINTS.md, SPRINTS_v2.md, and SPRINTS_v3.md complete
# Focus: Category 3 — Platform Expansion (Android, Linux, Containers, Cloud)
#         Category 4 — Intelligence Layer (SIGMA, Threat Hunting, Memory Forensics)
#
# AIR-GAP REQUIREMENT: Every sprint in this file must work on a fully
# air-gapped forensic computer with zero network access. All data sources
# are either parsed from forensic images or imported manually by the examiner.
# Cloud CLI artifacts are parsed from files already on disk — no cloud API calls.

# LEGAL NOTICE:
# All implementations are original Wolfmark Systems code.
# Strata is proprietary commercial software.
# No GPL code may be linked, incorporated, or derived from under any circumstances.

---

## HOW TO EXECUTE

Read CLAUDE.md first. Then execute each sprint below in order.
For each sprint:
1. Implement exactly as specified
2. Run `cargo test` — all tests must pass
3. Run `cargo clippy -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!`
5. Commit with message: "feat: [sprint-id] [description]"
6. Move to next sprint immediately

If a sprint is marked COMPLETE — skip it.
If blocked — implement manually, document why in a comment.

---

## RESUME INSTRUCTIONS

If this session was interrupted by a rate limit:
1. Run: git log --oneline -5
2. Find the last completed sprint commit
3. Mark that sprint COMPLETE in this file
4. Continue from the next incomplete sprint
5. Do not re-implement anything already committed

---

## COMPLETED SPRINTS (skip these)

None yet — this is v4.

---

# ═══════════════════════════════════════════════════════
# CATEGORY 3 — PLATFORM EXPANSION
# ═══════════════════════════════════════════════════════

## SPRINT AND-1 — Android Factory Reset Detection

Create `plugins/strata-plugin-carbon/src/factory_reset.rs`.

Detect when an Android device was factory reset. This is among the
most important artifacts in SAPR, CSAM, and trafficking investigations —
suspects frequently wipe their devices before surrendering them.
A reset does not destroy all evidence of the reset itself.

### Key Artifacts

**`/data/misc/bootstat/persistent_boot_stat`**
Binary file. Parse fields:
- `factory_reset_time_utc` (int64 — Unix timestamp of the wipe)
- `boot_reason_history` (array of strings — boot reasons including "factory_reset")
- `last_boot_time_utc` (int64 — most recent boot time)

**`/data/misc/bootstat/` directory**
Enumerate all files. The directory's own mtime reflects last modification.
Each file's mtime is individually forensically significant.

**`factory_reset` empty file**
Path: `/data/misc/bootstat/factory_reset`
This file is EMPTY but its mtime is the timestamp of the factory reset.
This is the primary and most reliable indicator.
Analog to iOS `.obliterated` file.

**`/data/system/resetinfo`** (Samsung devices)
Directory containing reset history. Parse if present.

**`/data/system/device_policies.xml`** (Samsung Knox)
If last_wipe_time field present — extract wipe timestamp.

**`/data/logger/`** or **`/data/log/`** (Samsung-specific)
Scan for files with names containing "factory" or "reset" — extract mtimes.

**`/proc/cmdline`** boot arguments — if image was captured live, may contain
`androidboot.bootreason=factory_reset` or similar.

### Caveats
Document in struct doc comments:
- Artifact availability depends on OEM, Android version, and acquisition method
- Physical/FFS extraction required for most artifacts — logical may miss them
- Samsung and Pixel artifact paths differ from other OEMs
- Some OEMs clear bootstat on reset — absence of factory_reset file is inconclusive

Typed struct `AndroidFactoryReset`:
```rust
pub struct AndroidFactoryReset {
    /// Timestamp of the factory reset (UTC)
    pub reset_time: Option<DateTime<Utc>>,
    /// Source artifact that provided the timestamp
    pub source_artifact: String,
    /// Device manufacturer hint (Pixel/Samsung/Unknown)
    pub device_oem: String,
    /// Confidence in the timestamp
    pub confidence: String,  // High/Medium/Low
    /// All reset-related artifacts found (for completeness)
    pub corroborating_artifacts: Vec<String>,
    /// Caveats the examiner should note in their report
    pub caveats: Vec<String>,
}
```

Emit `Artifact::new("Android Factory Reset", path_str)`.
suspicious=true always — reset before examination is inherently significant.
MITRE: T1485 (data destruction), T1070 (indicator removal).
forensic_value: High.

Wire into Carbon `run()` when path contains `/data/misc/bootstat/` or
filename is `factory_reset` in a bootstat directory.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT AND-2 — Samsung-Specific Artifacts

Create `plugins/strata-plugin-carbon/src/samsung.rs`.

Samsung devices are the most common Android devices in criminal investigations.
Samsung's EMUI/One UI layer adds unique artifact locations not present on
stock Android. These go largely unexamined by tools that only handle AOSP paths.

### Samsung Health
Path: `/data/data/com.sec.android.app.shealth/databases/`
Files: `healthdatashare.db`, `pedometer.db`

`healthdatashare.db` — SQLite
Tables:
- `health_data_all`: data_type (step_count/heart_rate/sleep/exercise),
  start_time (Unix ms), end_time (Unix ms), value (REAL),
  pkg_name (source app), device_uuid
- `step_count`: time_offset (Unix ms), count (INTEGER), distance (REAL),
  calorie (REAL), speed (REAL)

Key forensic value: proves device was physically in use at specific times.
High value in alibi cases, trafficking investigations, and SAPR cases
where device location/activity at a specific time is contested.

MITRE: T1430 (location tracking via activity inference).
forensic_value: High for time-of-activity evidence.

### Samsung Knox Security Events
Path: `/data/system/sec_knox/`
Files: `knox_security_log.db` or `knox_security_log.txt`

Knox logs security events: failed unlock attempts, biometric events,
policy enforcement, MDM commands received.

Parse: event_time (Unix ms), event_type (String), result (success/fail),
       user_id (INTEGER)

forensic_value: High for unlock attempt counts and timing (proves device use).

### Samsung Location History
Path: `/data/data/com.samsung.android.locationsharing/databases/`
File: `LocationHistory.db`
Table: `history`
Fields: latitude (REAL), longitude (REAL), timestamp (Unix ms),
        accuracy (REAL meters), provider (gps/network)

forensic_value: High — location history independent of Google.

### Samsung Messages (distinct from AOSP Messages)
Path: `/data/data/com.samsung.android.messaging/databases/`
File: `message.db`
Tables: `message` (msg_id, address, body, date, type, status),
        `thread` (thread_id, recipient_ids, message_count)

### Samsung Internet Browser
Path: `/data/data/com.sec.android.app.sbrowser/`
Files: `sbrowser.db` — history, bookmarks, downloads

Typed struct `SamsungArtifact`:
```rust
pub struct SamsungArtifact {
    /// Artifact category
    pub category: String,
    /// Source database path
    pub source_path: String,
    /// Timestamp
    pub timestamp: Option<DateTime<Utc>>,
    /// Primary value (location coords, step count, message body, etc.)
    pub value: String,
    /// Secondary value (accuracy, distance, address, etc.)
    pub secondary_value: Option<String>,
    /// Samsung-specific metadata
    pub metadata: Option<String>,
}
```

Emit `Artifact::new("Samsung [Category]", path_str)` per record.
Wire into Carbon `run()` by Samsung-specific package name paths.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT AND-3 — Android Work Profile and MDM Artifacts

Create `plugins/strata-plugin-carbon/src/work_profile.rs`.

Android work profiles (for BYOD and corporate-managed devices) create a
separate app container. MDM enrollment artifacts prove device management
and can contain evidence of corporate data access or remote wipe commands.

### Work Profile Detection
Path: `/data/system/users/`
Subdirectories: `0/` (personal), `10/` (first work profile), `11/` etc.

Work profile indicator: directory `10/` or higher present alongside `0/`.
Parse each user directory:
- `userInfo.xml` — user_id, name, flags (0x30 = managed profile), created_time

### Device Policy (MDM) Artifacts
Path: `/data/system/device_policies.xml`
Parse XML fields:
- `admin-list`: active device administrator package names
- `password-quality`: enforced password policy (proves MDM control)
- `max-failed-passwords`: wipe-after-N-failures setting
- `device-owner`: package name of device owner (MDM app)
- `profile-owner`: package name of work profile owner
- `last-security-patch-time`: Unix timestamp
- Wipe commands: detect `wipeData` entries with timestamps

### MDM App Detection
Known MDM package names to flag:
- `com.airwatch.androidagent` — VMware AirWatch/Workspace ONE
- `com.mobileiron` — MobileIron/Ivanti
- `com.microsoft.intune` — Microsoft Intune
- `com.citrix.mdm` — Citrix Endpoint Management
- `com.jamf.management.jamfnow` — JAMF Now
- `com.soti.mobicontrol` — SOTI MobiControl
- `com.blackberry.dynamics.android` — BlackBerry Dynamics
- Any package ending in `.mdm` or `.mam`

For each detected MDM: record package_name, install_time, last_active.

### Google Play Protect / SafetyNet
Path: `/data/data/com.google.android.gms/databases/phenotype.db`
Table: `Flags` — parse for enrollment status, device attestation results.

### Work Profile App Data
For each user directory (work profile):
- Enumerate installed apps: `/data/system/users/10/package-restrictions.xml`
- Parse enabled/disabled app list — proves what corporate apps were installed

Typed struct `WorkProfileArtifact`:
```rust
pub struct WorkProfileArtifact {
    /// Artifact type (WorkProfile/MDMEnrollment/DevicePolicy/WipeCommand)
    pub artifact_type: String,
    /// User profile ID (0=personal, 10+=work)
    pub profile_id: u32,
    /// MDM package name if applicable
    pub mdm_package: Option<String>,
    /// Policy detail or event description
    pub description: String,
    /// Timestamp
    pub timestamp: Option<DateTime<Utc>>,
    /// Whether a remote wipe was detected
    pub wipe_detected: bool,
}
```

Emit `Artifact::new("Android Work Profile", path_str)` per finding.
Emit `Artifact::new("MDM Enrollment", path_str)` for MDM detections.
Emit `Artifact::new("Remote Wipe Command", path_str)` for wipe events.
suspicious=false for enrollment (expected), suspicious=true for wipe commands.
MITRE: T1485 (data destruction) for remote wipe, T1078 (valid accounts) for MDM.
forensic_value: High for wipe commands, Medium for enrollment records.

Wire into Carbon `run()` by path pattern.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT AND-4 — ADB Backup Artifact Parser

Create `plugins/strata-plugin-carbon/src/adb_backup.rs`.

Parse Android Debug Bridge (ADB) backup files (.ab format).
ADB backups are created when a user or investigator runs `adb backup`.
Finding a .ab file on a computer proves the device was connected and
backed up — the backup content proves what was on the device.

### ADB Backup Format
Magic: `ANDROID BACKUP\n` at offset 0
Header lines (plain text until data stream):
- Line 2: version (1-5)
- Line 3: compression flag (0=none, 1=zlib)
- Line 4: encryption algorithm (none/AES-256)
- If encrypted: salt (hex), IV (hex), PBKDF2 iterations, user password hash

Data stream: zlib-compressed TAR archive starting after header.

### Parsing Strategy
1. Validate magic bytes
2. Parse header (plain text lines)
3. If NOT encrypted AND compressed:
   - Decompress zlib stream
   - Parse TAR entries
   - Extract app package names from paths (`apps/[package]/`)
   - Extract database files (`_db/` entries) and document their presence
   - Do NOT extract file content — record metadata only

4. If encrypted:
   - Emit `Artifact::new("ADB Backup Encrypted", path_str)`
   - Note: encryption requires password — flag for investigator

5. Version-specific handling:
   - v1: basic backup
   - v3+: supports individual app selection

### Key Forensic Value
- Backup timestamp (file mtime + header version date if present)
- List of apps included in backup (proves they existed on device)
- Database files backed up (proves app was used)
- Presence of backup file on examiner's computer proves device was connected

Typed struct `AdbBackup`:
```rust
pub struct AdbBackup {
    /// Path to .ab file
    pub backup_path: String,
    /// Backup format version
    pub version: u8,
    /// Whether backup is encrypted
    pub encrypted: bool,
    /// Whether backup is compressed
    pub compressed: bool,
    /// Encryption algorithm if encrypted
    pub encryption_algo: Option<String>,
    /// List of app packages found in backup
    pub included_apps: Vec<String>,
    /// Number of database files found
    pub database_count: usize,
    /// Total number of files in backup
    pub total_file_count: usize,
    /// Backup file modification time
    pub file_mtime: Option<DateTime<Utc>>,
}
```

Emit `Artifact::new("ADB Backup", path_str)`.
forensic_value: High — proves device connection and app presence.
MITRE: T1005 (data from local system), T1119 (automated collection).

Wire into Carbon `run()` when extension is `.ab`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

# ═══════════════════════════════════════════════════════
# LINUX ARBOR — FULL PLATFORM IMPLEMENTATION
# ═══════════════════════════════════════════════════════

## SPRINT LNX-1 — Linux Shell History and Persistence Artifacts

Create `plugins/strata-plugin-arbor/src/shell_artifacts.rs`.

NOTE: Check if `strata-plugin-arbor` exists. If not — scaffold it first
following the same pattern as other plugins.

Plugin metadata if scaffolding needed:
```rust
pub fn name() -> &'static str { "ARBOR" }
pub fn description() -> &'static str {
    "Linux and Unix system forensic artifacts. \
     Shell history, persistence mechanisms, user activity, \
     and system configuration changes."
}
pub fn color() -> &'static str { "#22d3ee" }  // Cyan
```

### Shell History Files
Parse shell history for all users found in `/etc/passwd` or `/home/*/`:

**Bash**: `~/.bash_history`
Format: one command per line. Optionally timestamped if `HISTTIMEFORMAT` set:
`#[unix_timestamp]\n[command]` — parse timestamps when present.

**Zsh**: `~/.zsh_history`
Format: `: [unix_timestamp]:[elapsed];[command]` (extended history format)
or plain text if not extended.

**Fish**: `~/.local/share/fish/fish_history`
Format: YAML-like:
```
- cmd: [command]
  when: [unix_timestamp]
```

For all shells:
Flag suspicious commands:
- Data exfiltration: `curl`, `wget`, `nc`, `scp`, `rsync` with external IPs
- Privilege escalation: `sudo`, `su`, `chmod 4755`, `setuid`
- Anti-forensic: `shred`, `wipe`, `rm -rf /var/log`, `history -c`, truncation of history
- Reverse shells: `bash -i >& /dev/tcp/`, `python -c 'import socket'`, `nc -e`
- Persistence: `crontab -e`, `systemctl enable`, edits to `.bashrc`
- Credential access: `cat /etc/shadow`, `cat /etc/passwd`, `unshadow`

Flag history tampering:
- File size = 0 (history cleared)
- File mtime significantly earlier than last login (history may have been modified)
- Gap in timestamps > 24 hours suggests deletion of entries

### Shell Initialization Files
Parse for unauthorized persistence:
- `~/.bashrc`, `~/.bash_profile`, `~/.profile`
- `/etc/profile`, `/etc/bash.bashrc`, `/etc/environment`
- `~/.zshrc`, `~/.zprofile`
- `~/.config/fish/config.fish`

Flag: any line containing external URL, base64 decode, curl/wget, or
path to `/tmp/` or world-writable directory.

Typed struct `ShellHistoryEntry`:
```rust
pub struct ShellHistoryEntry {
    /// Shell type (bash/zsh/fish)
    pub shell: String,
    /// Username who owns this history
    pub username: String,
    /// Command executed
    pub command: String,
    /// Timestamp if available
    pub timestamp: Option<DateTime<Utc>>,
    /// Suspicious pattern detected
    pub suspicious_pattern: Option<String>,
    /// Line number in history file
    pub line_number: usize,
}
```

Typed struct `ShellInitPersistence`:
```rust
pub struct ShellInitPersistence {
    /// Path to init file
    pub file_path: String,
    /// Username (or "system" for /etc/ files)
    pub username: String,
    /// Suspicious line content
    pub suspicious_line: String,
    /// Line number
    pub line_number: usize,
    /// Why it was flagged
    pub reason: String,
}
```

Emit `Artifact::new("Shell History", path_str)` per suspicious entry.
Emit one summary artifact per history file with total_commands count.
Emit `Artifact::new("Shell Init Persistence", path_str)` per suspicious init line.
MITRE: T1059.004 (Unix shell), T1546.004 (Unix shell config persistence).
forensic_value: High for suspicious entries and init persistence.

Wire into ARBOR `run()` by path pattern for known shell history locations.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT LNX-2 — Linux Systemd and Cron Persistence

Create `plugins/strata-plugin-arbor/src/persistence.rs`.

Parse Linux persistence mechanisms. Unlike Windows with its central registry,
Linux persistence is scattered across multiple locations — this sprint
consolidates them all.

### Systemd Unit Files
Scan these directories for unit files:
- `/etc/systemd/system/` — custom system units (admin-installed)
- `/lib/systemd/system/` — package-installed units
- `/usr/lib/systemd/system/` — vendor units
- `~/.config/systemd/user/` — per-user units (per user account found)

For each `.service`, `.timer`, `.path`, `.socket` file:
Parse key fields:
- `[Unit]` section: `Description`, `After`, `Requires`
- `[Service]` section: `ExecStart`, `ExecStartPre`, `User`, `WorkingDirectory`,
  `Restart`, `Environment`
- `[Install]` section: `WantedBy`

Flag suspicious unit files:
- `ExecStart` path in `/tmp/`, `/dev/shm/`, `/var/tmp/`, or world-writable dir
- `ExecStart` contains base64 decode or encoded payload
- Unit file not owned by any known package (no symlink in `/lib/systemd/system/`)
- `User=root` with `ExecStart` pointing to user-writable location
- Timer unit with very short interval (< 60 seconds) — beaconing
- Unit file mtime is recent (within 30 days of last known incident)

### Cron Artifacts
Parse all cron locations:
- `/etc/crontab` — system-wide
- `/etc/cron.d/` — drop-in cron files
- `/etc/cron.hourly/`, `cron.daily/`, `cron.weekly/`, `cron.monthly/`
- `/var/spool/cron/crontabs/[username]` — per-user crons

For each entry parse:
schedule (minute hour dom month dow), user (if system cron), command

Flag suspicious cron entries:
- Command in temp or world-writable directory
- Command downloads from internet (curl/wget — even if IP not present)
- Command pipes to bash or sh
- Reverse shell patterns
- Cron file not owned by root in `/etc/cron.d/`
- Unusual schedule (every minute, randomized offset suggesting C2)

### rc.local and SysV Init
`/etc/rc.local` — legacy startup script
`/etc/init.d/` — SysV init scripts
`/etc/init/` — Upstart jobs

Flag any `rc.local` that has been modified recently or contains
unusual commands. Flag init scripts not matching known package names.

### LD_PRELOAD Persistence
`/etc/ld.so.preload` — any entry here loads a library into EVERY process.
This is a rootkit technique. Flag any non-empty `ld.so.preload`.
MITRE: T1574.006 (dynamic linker hijacking).

### SUID/SGID Binary Anomalies
Record all files with SUID bit set (`stat` metadata, `mode & 04000`).
Flag files with SUID that are in unusual locations (not `/bin/`, `/usr/bin/`).

Typed struct `PersistenceArtifact`:
```rust
pub struct PersistenceArtifact {
    /// Mechanism type (SystemdUnit/Cron/RcLocal/InitScript/LdPreload/Suid)
    pub mechanism: String,
    /// Path to the persistence artifact
    pub path: String,
    /// Command that executes on trigger
    pub exec_command: Option<String>,
    /// When this was created or last modified
    pub modified_time: Option<DateTime<Utc>>,
    /// Owner username
    pub owner: Option<String>,
    /// Why this was flagged
    pub suspicious_reason: Option<String>,
    /// Schedule (for cron entries)
    pub schedule: Option<String>,
}
```

Emit `Artifact::new("Linux Persistence", path_str)` per finding.
suspicious=true when suspicious_reason is Some.
MITRE: T1053.003 (cron), T1543.002 (systemd service), T1574.006 (LD_PRELOAD),
T1546.004 (Unix shell init), T1037.004 (rc scripts).
forensic_value: High for suspicious persistence, Medium for known-good.

Wire into ARBOR `run()` by scanning all persistence locations.
Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT LNX-3 — Linux Log Artifacts

Create `plugins/strata-plugin-arbor/src/logs.rs`.

Parse Linux system log files. Unlike Windows Event Log, Linux logs are
plain text or binary (systemd journal) scattered across `/var/log/`.

### Systemd Journal
Path: `/var/log/journal/[machine-id]/` — binary `.journal` files

Use the `systemd-journal` crate if available in Cargo.toml.
If not available — implement a minimal journal reader:

Journal file magic: `d8c5fed1` at offset 0 (little-endian)
Journal entries contain: realtime (microseconds since epoch),
monotonic (boot time), priority, message, unit, pid, uid, comm

Priority levels: 0=EMERG, 1=ALERT, 2=CRIT, 3=ERR, 4=WARNING,
5=NOTICE, 6=INFO, 7=DEBUG

Extract high-forensic-value entries:
- Priority 0-3 (emergency through error)
- `_SYSTEMD_UNIT` = known attack tool names
- `MESSAGE` contains: "authentication failure", "invalid user",
  "accepted password", "accepted publickey", "session opened",
  "sudo:", "su:", "FAILED SU", "segfault"

If full journal parsing unavailable — implement string-carving fallback:
Scan `.journal` binary files for UTF-8 text blocks > 20 chars
containing forensically significant strings.
Document approach used in comments.

### Auth Log
Paths: `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL/CentOS)

Parse plain text lines. Key patterns:
- SSH login: `Accepted password for [user] from [ip] port [port]`
- SSH login: `Accepted publickey for [user] from [ip]`
- Failed SSH: `Failed password for [user] from [ip]`
- Invalid user: `Invalid user [user] from [ip]`
- Sudo: `[user] : TTY=[tty] ; PWD=[path] ; USER=root ; COMMAND=[cmd]`
- Su: `pam_unix(su:session): session opened for user root`
- Session: `pam_unix(sshd:session): session opened for user [user]`

Extract: timestamp, event_type, username, source_ip, command.

### Syslog / Messages
Paths: `/var/log/syslog`, `/var/log/messages`

Parse for:
- USB device connections: `usb [device]: New USB device found`
- Kernel errors: `kernel: [timestamp] [error message]`
- Process crashes: `[process][pid]: segfault at [addr]`
- Out of memory: `Out of memory: Kill process`
- Network: `IN=eth0` firewall log entries

### Rotated Logs
Scan for `.gz` compressed log files:
`auth.log.1`, `auth.log.2.gz`, `syslog.1`, `syslog.2.gz` etc.
Decompress `.gz` files using the `flate2` crate (check Cargo.toml).
Apply same parsing to rotated log content.

### wtmp / btmp / lastlog
`/var/log/wtmp` — successful logins (binary utmp format)
`/var/log/btmp` — failed logins (binary utmp format)
`/var/log/lastlog` — last login per user (binary)

Parse utmp records:
```
struct Utmp {
    ut_type: i16,     // LOGIN_PROCESS=6, USER_PROCESS=7, DEAD_PROCESS=8
    ut_pid: i32,
    ut_line: [u8; 32],  // terminal
    ut_id: [u8; 4],
    ut_user: [u8; 32],
    ut_host: [u8; 256], // source host/IP
    ut_time: i32,       // Unix timestamp
}
```

Typed struct `LinuxLogEntry`:
```rust
pub struct LinuxLogEntry {
    /// Log source (journal/auth_log/syslog/wtmp/btmp)
    pub source: String,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type (SSHLogin/SSHFail/SudoUse/USBConnect/ProcessCrash/etc)
    pub event_type: String,
    /// Username involved
    pub username: Option<String>,
    /// Source IP address
    pub source_ip: Option<String>,
    /// Command executed (for sudo events)
    pub command: Option<String>,
    /// Raw log line
    pub raw_line: String,
}
```

Emit `Artifact::new("Linux Log Event", path_str)` per high-value event.
Do NOT emit every log line — only: auth events, sudo, failed logins,
USB connections, and suspicious process events.
MITRE: T1078 (valid accounts), T1021.004 (SSH), T1548.003 (sudo abuse).
forensic_value: High for auth events and sudo abuse, Medium for others.

Wire into ARBOR `run()` by path pattern for known log locations.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT LNX-4 — Linux SSH, Package Manager, and User Account Artifacts

Create `plugins/strata-plugin-arbor/src/system_artifacts.rs`.

Parse Linux system artifacts for user accounts, SSH configuration,
package history, and filesystem anomalies.

### SSH Artifacts

**`/etc/ssh/sshd_config`**
Parse key security-relevant settings:
- `PermitRootLogin` — if "yes", flag as suspicious
- `PasswordAuthentication` — if "yes" with no restrictions, note
- `AuthorizedKeysFile` — non-default location is suspicious
- `PermitEmptyPasswords` — "yes" is critical flag
- `AllowUsers`, `DenyUsers` — access control lists
- `Port` — non-standard SSH port

**`~/.ssh/authorized_keys`** (per user)
Parse public keys. Extract key type, comment (often contains username/hostname).
Flag: keys with no comment (may be attacker-added), multiple keys for system accounts.

**`~/.ssh/known_hosts`** (per user)
Each line: `[hostname/IP] [key-type] [public-key]`
Parse hostnames/IPs — reveals systems this user connected TO.
Flag: `.onion` addresses, IP addresses in unusual ranges.

**`~/.ssh/config`** (per user)
Parse Host entries: `Host`, `HostName`, `User`, `IdentityFile`, `ProxyJump`
Reveals configured SSH tunnels and jump hosts.

### Package Manager History

**APT (Debian/Ubuntu)**
`/var/log/apt/history.log` — human-readable installation log
`/var/log/dpkg.log` — lower-level package events
Parse: date, action (install/remove/upgrade/purge), package_name, version

**YUM/DNF (RHEL/CentOS/Fedora)**
`/var/log/yum.log` or `/var/log/dnf.log`
Parse: date, action, package_name, version

**Pacman (Arch)**
`/var/log/pacman.log`
Parse: [timestamp] [action] package_name (version)

Flag suspicious package installations:
- Packages installed outside normal hours
- Security/hacking tools: `nmap`, `netcat`, `john`, `hydra`, `aircrack-ng`,
  `metasploit`, `sqlmap`, `nikto`, `gobuster`, `hashcat`
- Packages removed just before incident (anti-forensic)
- Multiple packages installed in rapid succession (scripted installation)

### User Account Artifacts

**`/etc/passwd`** — user accounts
Parse: username, uid, gid, home_dir, shell
Flag: uid=0 non-root accounts (privilege escalation),
      accounts with shell but no home directory,
      suspicious usernames (random strings, common attacker names)

**`/etc/shadow`** metadata only — do NOT parse password hashes
Parse: username, last_password_change (days since 1970),
       password_expiry_days, account_expiry
Flag: accounts with password changed recently, accounts that never expire

**`/etc/sudoers`** and `/etc/sudoers.d/`
Parse sudo rules. Flag:
- `ALL=(ALL) NOPASSWD: ALL` — unrestricted passwordless sudo
- Rules added for non-admin users
- Files in `/etc/sudoers.d/` not following standard naming

Typed struct `LinuxSystemArtifact`:
```rust
pub struct LinuxSystemArtifact {
    /// Artifact category (SSH/Package/UserAccount/Sudoers)
    pub category: String,
    /// Specific artifact type within category
    pub artifact_type: String,
    /// Username associated
    pub username: Option<String>,
    /// Timestamp (install time, password change, etc.)
    pub timestamp: Option<DateTime<Utc>>,
    /// Primary value (package name, IP, rule text, etc.)
    pub value: String,
    /// Why this was flagged
    pub suspicious_reason: Option<String>,
}
```

Emit `Artifact::new("Linux System Artifact", path_str)` per finding.
suspicious=true when suspicious_reason is Some.
MITRE: T1098.004 (SSH authorized keys), T1059.004 (Unix shell),
T1136.001 (local account creation), T1548.003 (sudo abuse).
forensic_value: High for suspicious findings, Low for clean config records.

Wire into ARBOR `run()` by path pattern.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT CONT-1 — Docker and Container Artifact Parser

Create `plugins/strata-plugin-arbor/src/containers.rs`.

Parse Docker and container runtime artifacts from Linux forensic images.
Container artifacts prove what was running, what images were used, and
what data was accessed — even after containers are deleted.

### Docker Artifacts

**Container Metadata**
Path: `/var/lib/docker/containers/[container-id]/`
Files:
- `config.v2.json` — JSON: Image, Name, Created, Entrypoint, Cmd,
  Env (environment variables), Mounts, NetworkSettings, State
- `hostconfig.json` — JSON: Binds (volume mounts), PortBindings,
  RestartPolicy, Privileged (flag if true — container breakout risk)
- `[container-id]-json.log` — container stdout/stderr logs

Parse `config.v2.json`:
- image name and SHA256
- container creation time
- entrypoint and command
- environment variables (flag: PASSWORD, SECRET, KEY, TOKEN in variable names)
- volume mounts (flag: mounts to sensitive host paths like `/etc`, `/root`, `/var`)
- privileged mode flag

**Container Logs**
Parse `[id]-json.log` — newline-delimited JSON:
`{"log":"[line]\n","stream":"stdout","time":"[RFC3339]"}`
Extract log lines with timestamps.
Flag: error messages, crash output, suspicious commands in logs.

**Docker Images**
Path: `/var/lib/docker/image/overlay2/imagedb/content/sha256/`
Files: JSON image manifests
Parse: created timestamp, author, architecture, os,
       history (list of commands used to build image — `Dockerfile` history)
Flag: images built with `curl | bash` pattern in history,
      images created at unusual times, images with no known base.

**Overlay2 Filesystem**
Path: `/var/lib/docker/overlay2/`
Each subdirectory is a container/image layer.
Within each layer: `diff/` contains filesystem changes.
Do NOT enumerate all files — scan `diff/` for:
- New executables in `/tmp/`, `/dev/shm/`
- Modified `/etc/passwd` or `/etc/shadow`
- New cron files or systemd units

**Docker Networks**
Path: `/var/lib/docker/network/files/local-kv.db` (BoltDB — binary KV store)
If parseable: extract network names, subnets, container IP assignments.
If not: scan for IP address patterns in the binary file.

Typed struct `ContainerArtifact`:
```rust
pub struct ContainerArtifact {
    /// Container ID (short form: first 12 chars)
    pub container_id: String,
    /// Container name
    pub name: Option<String>,
    /// Image name and tag
    pub image: Option<String>,
    /// Image SHA256
    pub image_sha256: Option<String>,
    /// Container created timestamp
    pub created: Option<DateTime<Utc>>,
    /// Container entry command
    pub entrypoint: Option<String>,
    /// Whether container ran privileged
    pub privileged: bool,
    /// Volume mounts (host_path:container_path)
    pub mounts: Vec<String>,
    /// Suspicious environment variable names found
    pub suspicious_env_vars: Vec<String>,
    /// Suspicious volume mounts (sensitive host paths)
    pub suspicious_mounts: Vec<String>,
    /// Log lines flagged as suspicious
    pub suspicious_log_lines: Vec<String>,
}
```

Emit `Artifact::new("Docker Container", path_str)` per container.
Emit `Artifact::new("Container Image", path_str)` per image with suspicious history.
suspicious=true when privileged=true OR suspicious_mounts non-empty.
MITRE: T1610 (deploy container), T1611 (escape to host),
T1552.007 (container credentials in environment).
forensic_value: High for privileged containers and sensitive mounts.

Wire into ARBOR `run()` when path contains `/var/lib/docker/containers/`.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT CLOUD-1 — Cloud CLI Credential and Configuration Artifacts

Create `plugins/strata-plugin-phantom/src/cloud_cli.rs`.

Parse cloud provider CLI credential files and configuration artifacts
found on forensic images. These files prove cloud account access, reveal
infrastructure details, and may contain credentials or tokens.

AIR-GAP NOTE: This sprint parses FILES on disk — it makes zero network
calls. All artifacts are parsed from the forensic image locally.

### AWS CLI Artifacts

**`~/.aws/credentials`** — INI format
```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[production]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
```
Parse: profile names, access key IDs (do NOT log secret keys — flag presence only),
       key type (AKIA=long-term, ASIA=temporary STS).

**`~/.aws/config`** — INI format
Parse: profile names, region, output format, role_arn (assume-role config),
       mfa_serial (MFA device — presence proves MFA was configured).

**`~/.aws/cli/cache/`** — JSON files containing temporary credentials
Parse: AccessKeyId, SessionToken presence (proves STS assumption),
       Expiration timestamp, RoleArn (what role was assumed).

### Azure CLI Artifacts

**`~/.azure/accessTokens.json`** — JSON array
Parse: subscriptionName, subscriptionId, tenantId, userId,
       tokenType, expiresOn (timestamp proves last active time).
Do NOT log actual token values.

**`~/.azure/config`** — INI format
Parse: subscription, cloud (AzureCloud/AzureUSGovernment/AzureChinaCloud),
       output, default group.

**`~/.azure/azureProfile.json`**
Parse: subscriptions array — name, id, tenantId, isDefault.

### GCP CLI Artifacts

**`~/.config/gcloud/credentials.db`** — SQLite
Table: credentials
Fields: account_id, value (JSON blob — parse for token_uri, client_id)
Do NOT log token values.

**`~/.config/gcloud/properties`** — INI format
Parse: [core] project, account; [compute] region, zone.

**`~/.config/gcloud/application_default_credentials.json`**
Parse: type (authorized_user/service_account), client_email (for service accounts),
       project_id. Flag: service account keys stored locally.

### Infrastructure-as-Code

**`terraform.tfstate`** (any location — common in project dirs)
Parse JSON: resources array — extract type, name, provider, attributes.
Flag: resource types suggesting cloud infrastructure
(aws_instance, azurerm_virtual_machine, google_compute_instance).
Extract: IP addresses, region, instance IDs, storage bucket names.
Do NOT log secret/sensitive attribute values.

**`~/.kube/config`** — Kubernetes config
Parse YAML: clusters (server URL, CA data), users (token presence),
            contexts (cluster+namespace+user combinations).
Flag: server URLs pointing to cloud Kubernetes services
(eks.amazonaws.com, azmk8s.io, gke.googleusercontent.com).

Typed struct `CloudCliArtifact`:
```rust
pub struct CloudCliArtifact {
    /// Cloud provider (AWS/Azure/GCP/Kubernetes/Terraform)
    pub provider: String,
    /// Artifact type (Credentials/Config/Cache/StateFile)
    pub artifact_type: String,
    /// Profile or account name
    pub profile_name: Option<String>,
    /// Account/subscription/project identifier
    pub account_id: Option<String>,
    /// Tenant/organization identifier
    pub tenant_id: Option<String>,
    /// Region configured
    pub region: Option<String>,
    /// Whether credentials/tokens were present (not the values)
    pub credentials_present: bool,
    /// Key type if AWS (LongTerm/Temporary)
    pub aws_key_type: Option<String>,
    /// Role ARN if role assumption configured
    pub role_arn: Option<String>,
    /// Last active timestamp from token expiry or cache
    pub last_active: Option<DateTime<Utc>>,
    /// Infrastructure resources found (Terraform)
    pub terraform_resources: Vec<String>,
}
```

Emit `Artifact::new("Cloud CLI Config", path_str)` per finding.
suspicious=true when service account keys stored locally or
temporary credentials found (proves active cloud session).
MITRE: T1552.001 (credentials in files), T1078.004 (cloud accounts).
forensic_value: High for credential files, Medium for config-only.

Wire into Phantom `run()` by path pattern for all cloud CLI locations.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

# ═══════════════════════════════════════════════════════
# CATEGORY 4 — INTELLIGENCE LAYER
# ═══════════════════════════════════════════════════════

## SPRINT SIGMA-1 — Full SigmaHQ Rule Import and Expanded Engine

Enhance `crates/strata-core/src/sigma/` with full SigmaHQ rule set import.

Strata currently ships 34 hardcoded SIGMA rules. The SigmaHQ community
repository contains 3,000+ rules. This sprint enables examiners to import
the full rule set and any custom rules as YAML files.

AIR-GAP NOTE: Examiner downloads the SigmaHQ rule repository as a ZIP
file and imports it locally. No network access required during import or use.

### Rule Import
Support importing SIGMA rules from:
- Single `.yml` file
- Directory of `.yml` files (recursive)
- ZIP archive containing `.yml` files

SIGMA rule YAML format fields to parse:
```yaml
title: [string]
id: [UUID]
status: stable|test|experimental|deprecated
description: [string]
references: [list]
author: [string]
date: [YYYY/MM/DD]
modified: [YYYY/MM/DD]
tags:
  - attack.[technique]
  - attack.[tactic]
logsource:
  product: windows|linux|macos
  category: process_creation|network_connection|file_event|registry_event|etc
  service: [optional]
detection:
  [condition_name]:
    [field]: [value or list]
    [field|contains]: [value]
    [field|startswith]: [value]
    [field|endswith]: [value]
    [field|re]: [regex]
  condition: [condition expression]
falsepositives: [list]
level: informational|low|medium|high|critical
```

### Detection Language Support
Parse SIGMA detection logic:

**Field modifiers:**
- `|contains` → substring match
- `|startswith` → prefix match
- `|endswith` → suffix match
- `|re` → regex match
- `|contains|all` → all values must match
- No modifier → exact match

**Condition expressions:**
- `selection` → named detection block
- `1 of selection*` → match any block with prefix
- `all of them` → all blocks must match
- `not selection` → negation
- `selection1 and not filter` → combination

### Rule Storage
Store imported rules in `~/.config/strata/sigma_rules.db` (SQLite):
```sql
CREATE TABLE rules (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT,
    level TEXT,
    product TEXT,
    category TEXT,
    tags TEXT,  -- JSON array
    detection_yaml TEXT,  -- original YAML preserved
    imported_at INTEGER
);
```

### Rule Validation
On import, validate each rule:
- Required fields present (title, detection, condition)
- Detection block references valid in condition
- Regex patterns compile without error
- Log invalid rules to stderr with rule title and error — do NOT fail import

### Rule Statistics
`strata sigma stats` — show: total rules, by level, by product, by status.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.
Tests: valid rule import, invalid rule graceful skip, condition parsing,
field modifier matching, ZIP import.

---

## SPRINT SIGMA-2 — Cross-Artifact SIGMA Correlation Engine

Enhance `crates/strata-core/src/sigma/` with cross-artifact correlation.

SIGMA rules are designed for log streams. Strata artifacts are structured
data. This sprint maps SIGMA rule fields to Strata artifact fields and
enables multi-artifact correlation — rules that fire when multiple
conditions are met across different artifact types within a time window.

### Field Mapping
Create a mapping from SIGMA logsource/field combinations to Strata
artifact fields:

```rust
pub struct SigmaFieldMapping {
    /// SIGMA logsource product
    pub product: String,
    /// SIGMA logsource category
    pub category: String,
    /// SIGMA field name
    pub sigma_field: String,
    /// Strata artifact type to search
    pub artifact_type: String,
    /// Strata artifact field to check
    pub artifact_field: String,
}
```

Key mappings to implement:
- `windows/process_creation/Image` → Prefetch `exe_name` or Trace artifacts
- `windows/process_creation/CommandLine` → PowerShell history, BITS jobs
- `windows/registry_event/TargetObject` → Registry artifacts from Phantom/Chronicle
- `windows/network_connection/DestinationIp` → Network artifacts from Netflow
- `linux/process_creation/exe` → Shell history command
- `linux/syslog/message` → Linux log entries

### Time-Window Correlation
For multi-condition SIGMA rules:
If condition requires `selection1 AND selection2`:
- Find artifacts matching selection1
- Find artifacts matching selection2
- Check if both occurred within configurable time window (default: 300 seconds)
- Emit correlation finding if within window

### SIGMA Match Result
```rust
pub struct SigmaMatch {
    /// Rule that fired
    pub rule_id: String,
    pub rule_title: String,
    pub rule_level: String,
    /// MITRE techniques from rule tags
    pub mitre_techniques: Vec<String>,
    /// Artifacts that matched this rule
    pub matched_artifacts: Vec<String>,
    /// Time of first matching artifact
    pub first_match_time: Option<DateTime<Utc>>,
    /// Time of last matching artifact
    pub last_match_time: Option<DateTime<Utc>>,
    /// Whether this was a time-window correlation
    pub is_correlation: bool,
}
```

Run SIGMA matching after all plugins complete.
Emit `Artifact::new("SIGMA Rule Match", "sigma_engine")` per match.
forensic_value: High for critical/high rules, Medium for medium rules.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT HUNT-1 — ATT&CK Kill Chain Reconstruction

Create `crates/strata-core/src/hunt/kill_chain.rs`.

Automatically map detected artifacts to ATT&CK kill chain stages and
build a kill chain reconstruction showing the examiner what stage of an
attack the evidence suggests.

### ATT&CK Tactic Stages (in kill chain order)
```rust
pub enum AttackTactic {
    Reconnaissance,         // TA0043
    ResourceDevelopment,    // TA0042
    InitialAccess,          // TA0001
    Execution,              // TA0002
    Persistence,            // TA0003
    PrivilegeEscalation,    // TA0004
    DefenseEvasion,         // TA0005
    CredentialAccess,       // TA0006
    Discovery,              // TA0007
    LateralMovement,        // TA0008
    Collection,             // TA0009
    CommandAndControl,      // TA0011
    Exfiltration,           // TA0010
    Impact,                 // TA0040
}
```

### Tactic Detection from Artifacts
Map MITRE technique IDs to tactics:

Build a lookup table from technique ID prefix to tactic:
- T1059, T1204, T1203 → Execution
- T1547, T1543, T1053 → Persistence
- T1548, T1055, T1027 → Defense Evasion + Privilege Escalation
- T1070, T1485 → Defense Evasion + Impact
- T1021, T1550 → Lateral Movement
- T1071, T1090 → Command and Control
- T1041, T1567, T1052 → Exfiltration

For each artifact with a MITRE technique:
- Map to tactic(s)
- Add to kill chain stage

### Kill Chain Report
```rust
pub struct KillChainReconstruction {
    /// Stages with evidence
    pub stages: Vec<KillChainStage>,
    /// Earliest evidence timestamp
    pub attack_start: Option<DateTime<Utc>>,
    /// Latest evidence timestamp
    pub attack_end: Option<DateTime<Utc>>,
    /// Total attack duration
    pub duration_hours: Option<f64>,
    /// Completeness score (stages covered / total stages)
    pub completeness: f64,
    /// Missing stages (no evidence found)
    pub missing_stages: Vec<String>,
}

pub struct KillChainStage {
    pub tactic: String,
    pub tactic_id: String,
    pub artifact_count: usize,
    pub artifacts: Vec<String>,  // artifact IDs
    pub earliest_timestamp: Option<DateTime<Utc>>,
    pub techniques_observed: Vec<String>,
}
```

Output: Kill chain report as HTML section + JSON export.
Include in main Strata report when kill chain evidence found.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT HUNT-2 — Behavioral Detection: Beaconing, Credential Harvesting, Lateral Movement

Create `crates/strata-core/src/hunt/behavioral.rs`.

Detect behavioral patterns that indicate attacker activity by correlating
artifacts across plugins. These detections go beyond individual artifact
flags to identify patterns only visible when artifacts are combined.

### Beaconing Detection
Network artifacts (DNS queries, IDS alerts, proxy logs from Netflow plugin):

Algorithm:
1. Group network connection artifacts by destination IP/domain
2. For each group with >= 5 connections: compute inter-connection intervals
3. Compute coefficient of variation (CV) of intervals: `std_dev / mean`
4. CV < 0.3 → highly regular interval → beaconing indicator
5. Flag beacon candidates with: destination, interval_mean_seconds,
   interval_cv, connection_count, first_seen, last_seen

```rust
pub struct BeaconingIndicator {
    pub destination: String,  // IP or domain
    pub interval_mean_secs: f64,
    pub interval_cv: f64,     // < 0.3 = regular = suspicious
    pub connection_count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source_artifacts: Vec<String>,
}
```

MITRE: T1071 (application layer protocol C2), T1568 (dynamic resolution).

### Credential Harvesting Detection
Correlate these artifact combinations within a 60-minute window:
- LSASS access (Prefetch: `lsass.exe` accessed by non-system process)
  + new local account created (Security event 4720)
  + lateral movement within 2 hours

- Mimikatz indicators: Prefetch entry for `mimikatz.exe`, `sekurlsa.exe`
  or ShimCache entry for known credential tools
  + new account or password change event

- PowerShell with encoded command + credential-related keywords in history
  + subsequent network connections

```rust
pub struct CredentialHarvestingIndicator {
    pub indicator_type: String,
    pub confidence: String,
    pub correlated_artifacts: Vec<String>,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub description: String,
}
```

MITRE: T1003 (credential dumping), T1555 (credentials from stores).

### Lateral Movement Chain
Build a lateral movement chain from Sentinel plugin artifacts:
(Already parsed in R-3 — this sprint adds chain visualization)

1. Collect all lateral movement artifacts from Sentinel
2. Sort by timestamp
3. Build graph: source_ip → target_account → next_hop
4. Identify multi-hop lateral movement (chain length > 2)
5. Emit chain summary: A → B → C with timestamps

```rust
pub struct LateralMovementChain {
    pub hops: Vec<LateralHop>,
    pub total_duration_minutes: f64,
    pub chain_length: usize,
}

pub struct LateralHop {
    pub source_ip: Option<String>,
    pub target_account: String,
    pub movement_type: String,
    pub timestamp: DateTime<Utc>,
    pub artifact_id: String,
}
```

MITRE: T1021 (remote services), T1550 (use alternate authentication).

### Hypothesis-Driven Hunt Mode
Allow examiner to select a hunt hypothesis and surface all related artifacts:

```rust
pub enum HuntHypothesis {
    InsiderThreatExfiltration,
    RansomwarePrecursor,
    APTLateralMovement,
    CredentialTheft,
    DataStagingAndExfil,
    PersistenceMechanism,
    AntiForensicActivity,
}
```

For each hypothesis: define a set of artifact types, MITRE techniques,
and plugin outputs to surface. When hypothesis is selected:
- Filter all artifacts to those relevant to hypothesis
- Sort by forensic_value and timestamp
- Present as "Hunt Package" — all evidence for this hypothesis in one view

Emit `Artifact::new("Behavioral Detection", "hunt_engine")` per finding.
suspicious=true for all behavioral detections.
forensic_value: High.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT MEM-1 — Memory Image String and Pattern Carving

Create `plugins/strata-plugin-phantom/src/memory_carving.rs`.

Parse raw memory image files for forensic artifacts. This is not full
memory forensics (which requires Volatility) — this sprint implements
targeted pattern carving to extract high-value indicators from memory
dumps without requiring complex structure parsing.

AIR-GAP NOTE: All parsing is local. No external tool dependencies.

### Supported Memory Image Formats
- Raw `.raw`, `.mem`, `.bin` files (flat binary dump)
- `.vmem` VMware memory files
- `.dmp` Windows crash dumps (detect by magic `MDMP` or `PAGE`)
- `.lime` LiME (Linux Memory Extractor) format
  Magic: `0xD4C3B2A1` at offset 0, header size 32 bytes

Detect format by magic bytes, fall back to raw if unknown.

### String Carving
Scan memory image in 4MB chunks with overlap buffer:

**Network Indicators**
- IPv4 addresses: `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
- IPv6 addresses: `[0-9a-fA-F:]{7,39}` (rough match, validate separately)
- URLs: `https?://[^\x00-\x1f\x7f-\xff ]{8,200}`
- .onion addresses: `[a-z2-7]{16,56}\.onion`

**Credential Patterns**
- Email addresses in memory
- Strings matching `password`, `passwd`, `secret`, `api_key` followed by `=` or `:`
  within 200 bytes — extract surrounding context (50 bytes each side)
- Base64 strings > 64 chars that decode to printable text

**Process Artifacts**
- Windows process path patterns: `[A-Z]:\\[Windows|Users|Temp][^\x00]{4,260}\.exe`
- Command line patterns with spaces and common parameters
- DLL paths: `[A-Z]:\\.*\.dll`

**Interesting Strings**
- Registry key paths: `HKEY_[A-Z_]+\\`
- File paths containing `\AppData\`, `\Temp\`, `\Downloads\`

### Deduplification
Memory contains many duplicate strings. Deduplicate by value before emitting.
Cap total artifacts at 10,000 per memory image.

Typed struct `MemoryStringArtifact`:
```rust
pub struct MemoryStringArtifact {
    /// Type of pattern matched
    pub pattern_type: String,
    /// The extracted string
    pub value: String,
    /// Byte offset in memory image
    pub offset: u64,
    /// Whether this string appeared multiple times
    pub occurrence_count: usize,
    /// Context around credential patterns (50 bytes before/after)
    pub context: Option<String>,
}
```

Emit `Artifact::new("Memory String", path_str)` per unique finding.
suspicious=true for .onion URLs and credential patterns.
MITRE: T1005 (data from local system), T1552 (unsecured credentials).
forensic_value: High for .onion and credential hits, Medium for network indicators.

Wire into Phantom `run()` when extension is `.raw`, `.mem`, `.vmem`,
`.dmp`, `.lime`, `.bin` and file size > 1MB (avoid false triggers on small binaries).
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT MEM-2 — Memory Image Structure Parsing

Create `plugins/strata-plugin-phantom/src/memory_structures.rs`.

Parse known binary structures from memory images to extract process lists,
network connections, and loaded modules. This provides structured forensic
output from memory without requiring Volatility.

AIR-GAP NOTE: This is entirely self-contained. No Volatility dependency.

### Windows Memory Structures

**EPROCESS Chain (Windows)**
Windows kernel maintains a doubly-linked list of EPROCESS structures.
Each EPROCESS contains: process name (ImageFileName — 16 bytes at offset 0x5a0
on Win10 x64, varies by version), PID, PPID, CreateTime (FILETIME).

Approach: scan for EPROCESS magic patterns.
Signature: look for `_EPROCESS` heuristic —
sequences that match: 4-byte PID followed by 4-byte PPID followed by
16-byte process name (printable ASCII) followed by FILETIME.

This is heuristic — document confidence level in artifact output.

**Process List Output**
```rust
pub struct MemoryProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub create_time: Option<DateTime<Utc>>,
    pub offset: u64,
    pub detection_confidence: String,  // Heuristic/Structural
}
```

Flag: processes with names that are common malware impersonations
(e.g., `svchost.exe` with unusual parent, `csrss.exe` with wrong PID).
Note: without full symbol resolution, false positives are possible.
Always include caveat: "Process list derived from heuristic scan —
verify with full memory forensics tool."

**Network Connection Structures (Windows)**
TCP connection table in memory contains: local_ip, local_port,
remote_ip, remote_port, state, PID, creation_time.

Signature: scan for structures with:
- Two valid IPv4 addresses (non-private ranges flag for attention)
- Two port numbers (1-65535)
- TCP state values (0-12)

```rust
pub struct MemoryNetworkConnection {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub offset: u64,
}
```

Flag: connections to non-RFC1918 IPs on suspicious ports (4444, 1337,
31337, 8080 with non-browser process, etc.).

### LiME Format Support
LiME (Linux Memory Extractor) format has 32-byte headers between memory ranges:
```
magic:   4 bytes  (0xD4C3B2A1)
version: 4 bytes
s_addr:  8 bytes (start physical address)
e_addr:  8 bytes (end physical address)
reserved: 8 bytes
```
Parse LiME headers to build physical address map before scanning.

### Output with Mandatory Caveats
All memory structure artifacts must include in their description:
"MEMORY FORENSICS: Heuristic detection. Results require verification
with dedicated memory analysis tools (Volatility, MemProcFS) before
evidentiary use."

Emit `Artifact::new("Memory Process", path_str)` per process found.
Emit `Artifact::new("Memory Network Connection", path_str)` per connection.
MITRE: T1057 (process discovery), T1049 (system network connections discovery).
forensic_value: Medium — always note verification requirement.

Wire into Phantom `run()` alongside MEM-1 for same file types.
Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

*STRATA AUTONOMOUS BUILD QUEUE v4*
*Wolfmark Systems — 2026-04-16*
*Category 3: Platform Expansion*
*  Android: Factory Reset, Samsung Artifacts, Work Profile/MDM, ADB Backup*
*  Linux ARBOR: Shell History, Persistence, Logs, SSH/Package/User Artifacts*
*  Containers: Docker forensics*
*  Cloud: AWS/Azure/GCP CLI credential artifacts*
*Category 4: Intelligence Layer*
*  SIGMA: Full SigmaHQ import, Cross-artifact correlation engine*
*  Threat Hunting: Kill chain reconstruction, Behavioral detection*
*  Memory Forensics: String carving, Structure parsing*
*All sprints air-gap compatible — zero network dependencies*
*Execute all incomplete sprints in order. Ship everything.*
