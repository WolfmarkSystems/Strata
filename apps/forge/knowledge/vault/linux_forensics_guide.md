# STRATA KNOWLEDGE: LINUX FORENSIC ARTIFACTS (2024-2025)

This guide documents critical Linux forensic artifacts for server and workstation investigations.

---

## 📜 LOGS & AUDITING
- **Auth Log**: `/var/log/auth.log` or `/var/log/secure` - Records user logins, `sudo` usage, and SSH authentication attempts.
- **Syslog**: `/var/log/syslog` or `/var/log/messages` - General system events and application logs.
- **Auditd Logs**: `/var/log/audit/audit.log` - If enabled, provides deep security events including file access and syscall execution.
- **Systemd Journal**: `journalctl` - Binary logs for modern distros; can be extracted for offline analysis.

---

## 👤 USER ACTIVITY
- **Shell History**: `~/.bash_history`, `~/.zsh_history`, `~/.python_history`.
- **Wtmp / Utmp**: `/var/log/wtmp` - Records every user login and logout across the system's life.
- **Btmp**: `/var/log/btmp` - Records failed login attempts.
- **SSH Known Hosts / Authorized Keys**: `~/.ssh/` - Reveals lateral movement potential and past connections.

---

## ⛓️ PERSISTENCE MECHANISMS
- **Cron Jobs**: `/etc/crontab`, `/var/spool/cron/crontabs/` - Scheduled tasks.
- **Systemd Services**: `/etc/systemd/system/` - Custom services used for persistence.
- **RC Scripts / Profile**: `/etc/rc.local`, `~/.bashrc`, `~/.profile` - Scripts that execute on login or boot.

---

## 🚀 LINUX: DEEP MASTERY (2025)
- **Systemd Journal Advanced**: 
    - **Location**: `/var/log/journal/` (Persistent) or `/run/log/journal/` (Volatile).
    - **Analysis**: Use `journalctl --unit=ssh` to trace specific entry points, or `journalctl --since "1 hour ago"` for rapid triage.
- **Auditd Rule Mastery**: 
    - `-w /etc/shadow -p wa -k shadow_mod` - Monitors password changes.
    - `-a always,exit -F arch=b64 -S execve -k exec_log` - Logs every command execution on the system.
- **Advanced Persistence**:
    - **MOTD Hijacking**: Scripts in `/etc/update-motd.d/` execute with root privileges whenever a user logs in via SSH.
    - **LD_PRELOAD**: Manipulating dynamic linker to load malicious shared libraries before any other.
    - **SUID Backdoors**: Finding binaries with the SUID bit set (`find / -perm -4000`) that an attacker may have modified.

---

## 📁 FILESYSTEM & NETWORK
- **MAC Times**: Access, Modification, and Change (Inode) timestamps.
- **Open Ports**: `netstat -tulpn` or `ss -lntp` - Identifies active listeners.
- **Network Config**: `/etc/network/interfaces`, `/etc/netplan/` - Reveals interface history and static IPs.

---

## 🧠 MEMORY & PROCESSES
- **Process Info**: `/proc/[PID]/` - Direct access to process memory maps, file descriptors, and environment variables in live systems.
- **Kernel Modules**: `lsmod` - Check for loaded modules (and potentially rootkits).

**THIS KNOWLEDGE IS NOW PART OF STRATA'S CORE REASONING ENGINE.** 🛡️🦾
