/// Returns (pattern, description) pairs for suspicious file paths.
pub fn all_suspicious_paths() -> Vec<(String, String)> {
    let entries: Vec<(&str, &str)> = vec![
        // Temp / staging directories
        (
            "\\appdata\\local\\temp\\",
            "User temp directory — common malware staging location",
        ),
        (
            "\\windows\\temp\\",
            "System temp directory — common malware drop zone",
        ),
        (
            "\\users\\public\\",
            "Public user folder — world-writable, used for lateral movement staging",
        ),
        (
            "\\programdata\\",
            "ProgramData — writable by all users, common persistence location",
        ),
        (
            "\\perflogs\\",
            "PerfLogs — rarely monitored, used for hiding payloads",
        ),
        // Suspicious execution paths
        (
            "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
            "User startup folder — persistence mechanism",
        ),
        (
            "\\windows\\system32\\tasks\\",
            "Scheduled tasks folder — persistence via task scheduler",
        ),
        (
            "\\windows\\system32\\drivers\\",
            "System drivers — rootkit installation target",
        ),
        (
            "\\windows\\system32\\wbem\\",
            "WMI repository — fileless persistence target",
        ),
        (
            "\\windows\\system32\\spool\\drivers\\",
            "Print spooler drivers — PrintNightmare exploitation",
        ),
        (
            "\\windows\\syswow64\\",
            "32-bit system directory on 64-bit OS — DLL search order hijacking",
        ),
        (
            "\\windows\\debug\\",
            "Windows debug folder — writable, rarely monitored",
        ),
        (
            "\\windows\\registration\\",
            "COM registration — writable by some service accounts",
        ),
        // Recycle bin
        (
            "\\$recycle.bin\\",
            "Recycle Bin — deleted files, anti-forensics indicator if recently emptied",
        ),
        // Web shells and server paths
        (
            "\\inetpub\\wwwroot\\",
            "IIS web root — web shell deployment target",
        ),
        (
            "\\xampp\\htdocs\\",
            "XAMPP web root — web shell deployment target",
        ),
        // Browser cache / downloads
        (
            "\\downloads\\",
            "Downloads folder — initial payload landing zone",
        ),
        (
            "\\appdata\\local\\google\\chrome\\user data\\",
            "Chrome user data — credential theft target",
        ),
        (
            "\\appdata\\roaming\\mozilla\\firefox\\profiles\\",
            "Firefox profiles — credential theft target",
        ),
        // Remote access
        (
            "\\appdata\\local\\teamviewer\\",
            "TeamViewer — remote access tool",
        ),
        (
            "\\appdata\\local\\anydesk\\",
            "AnyDesk — remote access tool",
        ),
        // Cloud sync (exfiltration)
        (
            "\\appdata\\local\\dropbox\\",
            "Dropbox — potential exfiltration channel",
        ),
        ("\\onedrive\\", "OneDrive — potential exfiltration channel"),
        // WSL / developer tools
        (
            "\\appdata\\local\\packages\\canonicalgrouplimited",
            "WSL installation — can bypass security tools",
        ),
        (
            "\\appdata\\local\\microsoft\\windowsapps\\",
            "Windows Apps — MOTW bypass potential",
        ),
        // Alternate data streams indicator
        (":$data", "Alternate Data Stream — data hiding technique"),
        // Known malware staging patterns
        (
            "\\appdata\\local\\microsoft\\clr_security_config\\",
            "CLR config — .NET hijacking location",
        ),
        (
            "\\appdata\\local\\comms\\",
            "Communications — rarely used legitimately in enterprise",
        ),
        (
            "\\windows\\system32\\config\\systemprofile\\",
            "System profile — services running as SYSTEM",
        ),
        (
            "\\windows\\servicing\\",
            "Windows servicing — writable by TrustedInstaller",
        ),
        // USB / removable media indicators
        ("\\usb\\", "USB path indicator — removable media access"),
        (
            "[removable]",
            "Removable media access — potential data exfiltration or payload delivery",
        ),
        // Network paths
        (
            "\\\\c$\\",
            "Admin share access — lateral movement indicator",
        ),
        (
            "\\\\admin$\\",
            "Admin share access — lateral movement indicator (PsExec)",
        ),
        ("\\\\ipc$\\", "IPC share — enumeration / lateral movement"),
        // Recycle bin SID directories
        (
            "\\$recycle.bin\\s-1-5-",
            "Per-user recycle bin — check for recently deleted evidence",
        ),
        // Common staging directories attackers create
        (
            "\\intel\\",
            "Intel folder — sometimes used by attackers to hide payloads",
        ),
        (
            "\\hp\\",
            "HP folder — sometimes used by attackers on HP systems",
        ),
        (
            "\\dell\\",
            "Dell folder — sometimes used by attackers on Dell systems",
        ),
        ("\\sun\\", "Sun folder — used by some RATs"),
        (
            "\\msocache\\",
            "MS Office cache — sometimes abused for staging",
        ),
    ];

    entries
        .into_iter()
        .map(|(p, d)| (p.to_string(), d.to_string()))
        .collect()
}
