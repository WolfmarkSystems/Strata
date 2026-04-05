//! Forensic artifact knowledge bank — contextual intelligence for the examiner.
//!
//! When an examiner selects a file, the DETAILS tab shows what the artifact is,
//! where it normally lives, its forensic value, and what to look for.

/// Forensic knowledge entry for an artifact type.
pub struct ArtifactKnowledge {
    pub name: &'static str,
    pub description: &'static str,
    pub forensic_value: &'static str,
    pub locations: &'static [&'static str],
    pub what_to_look_for: &'static str,
    pub mitre_techniques: &'static [&'static str],
    pub related_artifacts: &'static [&'static str],
    /// Filename/path patterns that match this entry (lowercase).
    name_patterns: &'static [&'static str],
}

/// Look up forensic knowledge for a given filename and path.
pub fn lookup_knowledge(filename: &str, path: &str) -> Option<&'static ArtifactKnowledge> {
    let lower_name = filename.to_lowercase();
    let lower_path = path.to_lowercase();
    KNOWLEDGE_BANK.iter().find(|k| {
        k.name_patterns
            .iter()
            .any(|p| lower_name.contains(p) || lower_path.contains(p))
    })
}

static KNOWLEDGE_BANK: &[ArtifactKnowledge] = &[
    // ── Entry 1: NTUSER.DAT ─────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "User Registry Hive",
        description: "The user registry hive contains all user-specific settings, \
            preferences, and activity records for a Windows user account. It persists \
            across reboots and contains extensive evidence of user behavior.",
        forensic_value: "Critical \u{2014} contains execution history, recently accessed \
            files, typed URLs, search terms, installed software usage, and network connections.",
        locations: &[
            "C:\\Users\\[username]\\NTUSER.DAT",
            "C:\\Users\\[username]\\NTUSER.DAT.LOG1",
        ],
        what_to_look_for: "UserAssist keys for execution history. RecentDocs for \
            recently opened files. TypedURLs for browser bar entries. WordWheelQuery \
            for File Explorer searches. Run keys for persistence.",
        mitre_techniques: &["T1547.001", "T1204"],
        related_artifacts: &["Jump Lists", "LNK Files", "Prefetch"],
        name_patterns: &["ntuser.dat"],
    },
    // ── Entry 2: Prefetch ────────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Prefetch File",
        description: "Windows Prefetch files record application execution history. \
            Each file corresponds to one executable and contains run count, execution \
            timestamps, and files referenced during execution.",
        forensic_value: "Critical \u{2014} proves program execution even if the program \
            has been deleted. Records up to 8 execution timestamps and total run count.",
        locations: &["C:\\Windows\\Prefetch\\*.pf"],
        what_to_look_for: "Executable name in filename. Run count (how many times). \
            Last 8 execution timestamps. Files and directories referenced. Execution \
            from suspicious paths (Temp, Downloads) indicates potential malware.",
        mitre_techniques: &["T1059"],
        related_artifacts: &["AmCache", "ShimCache", "BAM/DAM", "UserAssist"],
        name_patterns: &[".pf"],
    },
    // ── Entry 3: SRUDB.dat ──────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "System Resource Usage Monitor",
        description: "SRUM records 30 to 60 days of application resource usage \
            including network bytes sent and received, CPU usage, and energy \
            consumption per application per hour.",
        forensic_value: "Critical \u{2014} provides evidence of network activity per \
            application even when other logs have been cleared. Can prove data \
            exfiltration by showing large uploads.",
        locations: &["C:\\Windows\\System32\\SRU\\SRUDB.dat"],
        what_to_look_for: "Bytes sent vs received per app. Unusual upload volumes. \
            Applications with unexpected network activity. Timestamps correlate with \
            other artifacts.",
        mitre_techniques: &["T1048"],
        related_artifacts: &["NTUSER.DAT", "Event Logs", "Browser History"],
        name_patterns: &["srudb.dat"],
    },
    // ── Entry 4: AmCache.hve ────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Application Compatibility Cache",
        description: "AmCache records installed applications, executed programs, \
            and loaded drivers. Uniquely stores the SHA1 hash of the first 31MB of \
            each executable, enabling hash-based identification even after deletion.",
        forensic_value: "Critical \u{2014} SHA1 hash allows identification of exact malware \
            variants. Records presence and execution even if Prefetch is disabled. \
            Survives program uninstallation.",
        locations: &["C:\\Windows\\AppCompat\\Programs\\Amcache.hve"],
        what_to_look_for: "SHA1 hash for malware identification. Publisher field \u{2014} \
            no publisher is suspicious. Files no longer present on disk. Executables \
            from temporary or unusual locations.",
        mitre_techniques: &["T1059", "T1036"],
        related_artifacts: &["Prefetch", "ShimCache", "BAM/DAM"],
        name_patterns: &["amcache.hve"],
    },
    // ── Entry 5: $MFT ───────────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Master File Table",
        description: "The NTFS Master File Table is the index of every file and \
            directory on an NTFS volume. Each file has an MFT record containing \
            timestamps, file size, and data location. Deleted file records remain \
            until overwritten.",
        forensic_value: "Critical \u{2014} provides four timestamps per file, detects \
            timestamp manipulation, recovers deleted file metadata, and reveals the \
            complete file system history.",
        locations: &["C:\\$MFT"],
        what_to_look_for: "Timestamp anomalies ($SI vs $FN mismatch = timestomping). \
            Deleted file records. File size vs allocated size discrepancies. Unusual \
            file attributes.",
        mitre_techniques: &["T1070.006"],
        related_artifacts: &["$UsnJrnl", "$LogFile", "Recycle Bin"],
        name_patterns: &["$mft"],
    },
    // ── Entry 6: Security.evtx ──────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Security Event Log",
        description: "The Windows Security event log records authentication events, \
            privilege use, account management, and process creation. It is a primary \
            source for detecting unauthorized access and lateral movement.",
        forensic_value: "Critical \u{2014} records every logon/logoff, failed login attempt, \
            privilege escalation, account creation, and process execution (if auditing enabled).",
        locations: &["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"],
        what_to_look_for: "Event 4624 (successful logon). Event 4625 (failed logon). \
            Event 4688 (process creation). Event 4698 (scheduled task). Event 4720 \
            (account created). Event 1102 (log cleared = anti-forensic).",
        mitre_techniques: &["T1078", "T1110", "T1059", "T1053", "T1136", "T1070.001"],
        related_artifacts: &["System.evtx", "PowerShell.evtx", "TaskScheduler.evtx"],
        name_patterns: &["security.evtx"],
    },
    // ── Entry 7: Chrome Login Data ──────────────────────────────────────────
    ArtifactKnowledge {
        name: "Browser Saved Credentials",
        description: "Chromium-based browsers store saved passwords in a SQLite \
            database. Passwords are encrypted with DPAPI (Windows Data Protection \
            API) tied to the user account.",
        forensic_value: "High \u{2014} reveals every website the user saved credentials \
            for, usernames, and how frequently credentials were used. Password \
            decryption requires the user's Windows DPAPI key.",
        locations: &[
            "C:\\Users\\[user]\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            "C:\\Users\\[user]\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data",
        ],
        what_to_look_for: "Saved credentials for banking, email, VPN, admin portals. \
            times_used field shows frequency. date_created shows when credential was saved.",
        mitre_techniques: &["T1555.003"],
        related_artifacts: &["Browser History", "Windows Credential Manager", "Firefox logins.json"],
        name_patterns: &["login data"],
    },
    // ── Entry 8: hiberfil.sys ───────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Hibernation File",
        description: "When Windows hibernates it writes a compressed snapshot of \
            RAM to hiberfil.sys. This captures all running processes, open files, \
            network connections, and decrypted content at the moment of hibernation.",
        forensic_value: "Critical \u{2014} may contain decrypted encryption keys, passwords \
            in memory, running process list, open network connections, and evidence \
            that cannot be found anywhere else on disk.",
        locations: &["C:\\hiberfil.sys"],
        what_to_look_for: "Compressed memory requires decompression tool. Look for \
            process list, network connections, registry hives in memory, browser \
            artifacts, decrypted content. Requires memory forensics tooling.",
        mitre_techniques: &["T1003.001"],
        related_artifacts: &["pagefile.sys", "Crash Dumps", "Virtual Memory"],
        name_patterns: &["hiberfil.sys"],
    },
    // ── Entry 9: Recycle Bin $I files ───────────────────────────────────────
    ArtifactKnowledge {
        name: "Recycle Bin Metadata",
        description: "When a file is deleted to the Recycle Bin, Windows creates \
            a metadata file ($I) recording the original file path, deletion time, \
            and original file size. The $R file contains the actual file content.",
        forensic_value: "High \u{2014} proves a file existed at a specific path, when it \
            was deleted, and its original size. The $R content file may still be \
            recoverable.",
        locations: &[
            "C:\\$Recycle.Bin\\{SID}\\$I*",
            "C:\\$Recycle.Bin\\{SID}\\$R*",
        ],
        what_to_look_for: "Original file path reveals where file came from. Deletion \
            timestamp. File size mismatch between $I and $R could indicate tampering.",
        mitre_techniques: &["T1070.004"],
        related_artifacts: &["$UsnJrnl", "$MFT", "Prefetch"],
        name_patterns: &["$i3", "$i4", "$i5", "$i6", "$recycle.bin"],
    },
    // ── Entry 10: KnowledgeC.db ─────────────────────────────────────────────
    ArtifactKnowledge {
        name: "iOS Activity Database",
        description: "KnowledgeC is the iOS activity and usage database. It records \
            app usage patterns, screen time, device orientation, location activity, \
            and Siri interactions with precise start and end times.",
        forensic_value: "Critical for mobile investigations \u{2014} proves which apps \
            were in use at specific times, establishes device usage timeline, and \
            can corroborate or contradict alibis.",
        locations: &[
            "/private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db",
        ],
        what_to_look_for: "ZOBJECT table for app usage events. ZSTARTDATE and ZENDDATE \
            for precise times. ZVALUESTRING for app bundle IDs. Cross-reference with \
            other app databases for complete timeline.",
        mitre_techniques: &["T1636"],
        related_artifacts: &["DataUsage.sqlite", "interactionC.db", "App databases"],
        name_patterns: &["knowledgec.db"],
    },
    // ── Entry 11: $UsnJrnl ──────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "NTFS Change Journal",
        description: "The USN Journal records every change made to files and \
            directories on an NTFS volume, including creates, deletes, renames, \
            and security changes. It survives file deletion.",
        forensic_value: "Critical \u{2014} provides a chronological log of all file system \
            activity. Can reveal anti-forensic behavior such as bulk file deletion, \
            timestamp manipulation, and evidence destruction.",
        locations: &["C:\\$Extend\\$UsnJrnl:$J"],
        what_to_look_for: "File creation and deletion sequences. Bulk operations that \
            indicate evidence wiping. Rename operations. Executable file creation in \
            suspicious directories.",
        mitre_techniques: &["T1070.004", "T1070.006"],
        related_artifacts: &["$MFT", "$LogFile", "Prefetch"],
        name_patterns: &["$usnjrnl", "$j"],
    },
    // ── Entry 12: SAM ───────────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Security Account Manager",
        description: "The SAM registry hive stores local user accounts, password \
            hashes, and account policies. It is essential for understanding who \
            had access to the system and when accounts were created or modified.",
        forensic_value: "Critical \u{2014} local account names, SIDs, last login times, \
            password expiry, account creation dates. Hashes can be extracted for \
            offline cracking.",
        locations: &["C:\\Windows\\System32\\config\\SAM"],
        what_to_look_for: "Account creation timestamps. Last login times. Failed login \
            counts. Hidden or renamed administrator accounts. Accounts created during \
            the incident timeframe.",
        mitre_techniques: &["T1003.002", "T1136.001"],
        related_artifacts: &["SECURITY", "SYSTEM", "Security.evtx"],
        name_patterns: &["\\sam"],
    },
    // ── Entry 13: SYSTEM hive ───────────────────────────────────────────────
    ArtifactKnowledge {
        name: "System Registry Hive",
        description: "The SYSTEM registry hive contains hardware configuration, \
            services, drivers, and boot information. It holds critical forensic \
            artifacts including USB device history and network configurations.",
        forensic_value: "Critical \u{2014} USB device connection history (first/last connect), \
            installed services, network interfaces, mounted devices, and timezone \
            configuration.",
        locations: &["C:\\Windows\\System32\\config\\SYSTEM"],
        what_to_look_for: "USB device history under USBSTOR and USB keys. Service \
            installations (potential persistence). Network interface configurations. \
            MountedDevices for volume assignments. CurrentControlSet for active config.",
        mitre_techniques: &["T1547.001", "T1543.003"],
        related_artifacts: &["SAM", "SECURITY", "SOFTWARE", "setupapi.dev.log"],
        name_patterns: &["config\\system", "config/system"],
    },
    // ── Entry 14: SOFTWARE hive ─────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Software Registry Hive",
        description: "The SOFTWARE registry hive records installed applications, \
            OS configuration, network profiles, and system-wide settings. Contains \
            ShimCache (AppCompatCache) for execution evidence.",
        forensic_value: "Critical \u{2014} ShimCache records program execution with timestamps. \
            Network profiles reveal previously connected networks. Installed software \
            inventory. Uninstall records.",
        locations: &["C:\\Windows\\System32\\config\\SOFTWARE"],
        what_to_look_for: "AppCompatCache (ShimCache) for execution evidence. \
            NetworkList for previously connected WiFi and wired networks. \
            ProfileList for user SID mapping. Run keys for persistence.",
        mitre_techniques: &["T1059", "T1547.001"],
        related_artifacts: &["SYSTEM", "AmCache", "Prefetch"],
        name_patterns: &["config\\software", "config/software"],
    },
    // ── Entry 15: Jump Lists ────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Jump List",
        description: "Jump Lists record recently and frequently accessed files per \
            application. They are stored as Compound Binary Files (CFB/OLE2) and \
            contain embedded LNK entries pointing to opened files.",
        forensic_value: "High \u{2014} proves which files were opened by which application, \
            with access counts and timestamps. Persists even after file deletion.",
        locations: &[
            "C:\\Users\\[user]\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\",
            "C:\\Users\\[user]\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\",
        ],
        what_to_look_for: "Application ID in filename maps to specific program. \
            Embedded LNK targets show accessed files. Access count and timestamps. \
            Files accessed from removable media or network shares.",
        mitre_techniques: &["T1547.009"],
        related_artifacts: &["LNK Files", "NTUSER.DAT", "Prefetch"],
        name_patterns: &["automaticdestinations", "customdestinations"],
    },
    // ── Entry 16: Browser History ───────────────────────────────────────────
    ArtifactKnowledge {
        name: "Browser History Database",
        description: "Chromium-based browsers store browsing history, downloads, \
            and search queries in SQLite databases. Firefox uses places.sqlite. \
            Records include URLs, visit counts, and timestamps.",
        forensic_value: "High \u{2014} establishes web activity timeline. Downloads table \
            shows files obtained from the internet. Search terms reveal intent. \
            Visit frequency shows patterns of behavior.",
        locations: &[
            "C:\\Users\\[user]\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
            "C:\\Users\\[user]\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\places.sqlite",
        ],
        what_to_look_for: "URLs visited around incident timeframe. Downloaded files \
            (especially executables). Search queries related to the investigation. \
            Visits to file sharing, cloud storage, or communication services.",
        mitre_techniques: &["T1071.001"],
        related_artifacts: &["Login Data", "Cookies", "Cache"],
        name_patterns: &["places.sqlite", "chrome/user data"],
    },
    // ── Entry 17: LNK Files ─────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Windows Shortcut",
        description: "LNK files are Windows shortcuts that record the target file \
            path, MAC timestamps of both the LNK and target, volume serial number, \
            and machine identifier. Created automatically when files are opened.",
        forensic_value: "High \u{2014} proves file access even if the original file is deleted. \
            Records the original path, volume serial number, and target timestamps.",
        locations: &[
            "C:\\Users\\[user]\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\",
            "C:\\Users\\[user]\\Desktop\\",
        ],
        what_to_look_for: "Target file path (may reference deleted files or removable \
            media). Volume serial number identifies source drive. MAC timestamps of \
            target file at time of access. Network paths indicate lateral movement.",
        mitre_techniques: &["T1547.009"],
        related_artifacts: &["Jump Lists", "NTUSER.DAT", "Prefetch"],
        name_patterns: &[".lnk"],
    },
    // ── Entry 18: Event Logs (generic .evtx) ────────────────────────────────
    ArtifactKnowledge {
        name: "Windows Event Log",
        description: "Windows Event Logs record system, application, and security \
            events in EVTX format. Over 300 log channels exist covering everything \
            from PowerShell execution to scheduled tasks to remote desktop sessions.",
        forensic_value: "Critical \u{2014} primary source for understanding system activity, \
            authentication events, service installation, and application errors. \
            Tamper-evident through Event ID 1102 (log cleared).",
        locations: &["C:\\Windows\\System32\\winevt\\Logs\\*.evtx"],
        what_to_look_for: "Security.evtx for auth events. PowerShell/Operational.evtx \
            for script execution. System.evtx for service changes. \
            TerminalServices-RDPClient for RDP sessions.",
        mitre_techniques: &["T1070.001"],
        related_artifacts: &["Security.evtx", "PowerShell.evtx", "Sysmon.evtx"],
        name_patterns: &[".evtx"],
    },
    // ── Entry 19: pagefile.sys ──────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Windows Page File",
        description: "The page file stores memory pages swapped to disk by the \
            operating system. It may contain fragments of processes, documents, \
            passwords, and other data that was in RAM.",
        forensic_value: "High \u{2014} may contain remnants of deleted processes, decrypted \
            data, network credentials, and application data. Complements memory \
            forensics when a RAM capture is unavailable.",
        locations: &["C:\\pagefile.sys"],
        what_to_look_for: "String searches for passwords, URLs, email addresses. \
            Process fragments. Document content. Must be analyzed with memory forensics \
            or string extraction tools.",
        mitre_techniques: &["T1003"],
        related_artifacts: &["hiberfil.sys", "Crash Dumps", "swapfile.sys"],
        name_patterns: &["pagefile.sys"],
    },
    // ── Entry 20: WhatsApp databases ────────────────────────────────────────
    ArtifactKnowledge {
        name: "WhatsApp Message Database",
        description: "WhatsApp stores message history in SQLite databases. iOS uses \
            ChatStorage.sqlite, Android uses msgstore.db. Contains messages, \
            timestamps, sender/receiver info, and media references.",
        forensic_value: "Critical for communication investigations \u{2014} complete message \
            history with timestamps, group membership, contact information, and \
            references to sent/received media files.",
        locations: &[
            "/ChatStorage.sqlite (iOS)",
            "/msgstore.db (Android)",
        ],
        what_to_look_for: "Message content and timestamps. Group chat membership. \
            Media attachments (images, videos, documents). Deleted message stubs. \
            Contact names and phone numbers.",
        mitre_techniques: &["T1530"],
        related_artifacts: &["Signal", "Telegram", "iMessage"],
        name_patterns: &["chatstorage.sqlite", "msgstore.db"],
    },
    // ═══════════════════════════════════════════════════════════════════════════
    // WINDOWS EXECUTION ARTIFACTS (entries 21-24)
    // ═══════════════════════════════════════════════════════════════════════════
    // ── Entry 21: ShimCache (AppCompatCache) ────────────────────────────────
    ArtifactKnowledge {
        name: "Application Compatibility Cache",
        description: "Windows tracks executable files for compatibility purposes. \
            Records file path and last modified time for every executable that has \
            been present on the system.",
        forensic_value: "High \u{2014} proves an executable existed on the system even if \
            deleted. Does NOT definitively prove execution on Win8+ but presence is \
            significant.",
        locations: &[
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\\AppCompatCache",
        ],
        what_to_look_for: "Executables in suspicious paths. Files no longer present on \
            disk. Sequence order shows relative execution timeline. Does not include \
            timestamps on Win10+.",
        mitre_techniques: &["T1059"],
        related_artifacts: &["AmCache", "Prefetch", "BAM/DAM"],
        name_patterns: &["appcompatcache", "shimcache"],
    },
    // ── Entry 22: BAM/DAM Registry ──────────────────────────────────────────
    ArtifactKnowledge {
        name: "Background Activity Monitor",
        description: "Windows 10+ Background Activity Moderator tracks every \
            executable that ran, maintained per user SID, with precise last \
            execution timestamp.",
        forensic_value: "Critical \u{2014} provides full executable path and exact last \
            execution time. More reliable than ShimCache for execution timestamps \
            on Windows 10 and later.",
        locations: &[
            "SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings\\{SID}",
            "SYSTEM\\CurrentControlSet\\Services\\dam\\UserSettings\\{SID}",
        ],
        what_to_look_for: "Full path of executed programs. Execution time per user \
            account. Programs executed from unusual locations. Available typically \
            for past week of activity.",
        mitre_techniques: &["T1059"],
        related_artifacts: &["Prefetch", "AmCache", "UserAssist"],
        name_patterns: &["\\bam\\", "\\dam\\"],
    },
    // ── Entry 23: Jump Lists (detailed) ─────────────────────────────────────
    ArtifactKnowledge {
        name: "Application Jump Lists",
        description: "Jump Lists record recently and frequently accessed files per \
            application. Each Jump List file is named by an Application ID (AppID) \
            that identifies which application created it.",
        forensic_value: "High \u{2014} proves files were opened by specific applications. \
            Jump List creation time indicates first time application opened that file \
            type. Contains LNK data with target paths and timestamps.",
        locations: &[
            "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.automaticDestinations-ms",
        ],
        what_to_look_for: "AppID identifies the application. Access count shows \
            frequency. Last accessed timestamp. Target file paths. Network paths \
            indicate file server access.",
        mitre_techniques: &["T1547.009"],
        related_artifacts: &["LNK Files", "RecentDocs", "MRU Lists"],
        name_patterns: &[".automaticdestinations-ms", ".customdestinations-ms"],
    },
    // ── Entry 24: UserAssist ────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "UserAssist Execution Registry",
        description: "Windows records GUI-based program executions in the UserAssist \
            registry key. Values are ROT13 encoded. Contains run count, focus time, \
            and last execution timestamp.",
        forensic_value: "Critical \u{2014} proves user intentionally launched a program \
            via the GUI. Run count shows frequency of use. Focus time indicates how \
            long user interacted with the application.",
        locations: &[
            "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count",
        ],
        what_to_look_for: "Decode ROT13 to get real program names. Run count above 1 \
            shows repeated use. Last execution timestamp. Programs from Temp or \
            Downloads paths are suspicious.",
        mitre_techniques: &["T1204.002"],
        related_artifacts: &["Prefetch", "BAM/DAM", "RecentDocs"],
        name_patterns: &["userassist"],
    },
    // ═══════════════════════════════════════════════════════════════════════════
    // WINDOWS PERSISTENCE ARTIFACTS (entries 25-28)
    // ═══════════════════════════════════════════════════════════════════════════
    // ── Entry 25: Scheduled Tasks XML ───────────────────────────────────────
    ArtifactKnowledge {
        name: "Scheduled Task Definition",
        description: "Windows Scheduled Tasks persist programs to run automatically \
            at specified times or triggers. Each task is defined in an XML file with \
            full execution details.",
        forensic_value: "Critical \u{2014} a common malware persistence mechanism. XML files \
            record creator, creation time, executing program, arguments, and trigger \
            conditions.",
        locations: &[
            "C:\\Windows\\System32\\Tasks\\",
            "C:\\Windows\\SysWOW64\\Tasks\\",
        ],
        what_to_look_for: "Commands executing from Temp or AppData. Base64 encoded \
            arguments. PowerShell with hidden window. Tasks created by non-system \
            accounts. Unusual trigger times. Recently created tasks.",
        mitre_techniques: &["T1053.005"],
        related_artifacts: &["Services", "Run Keys", "BITS Jobs"],
        name_patterns: &["\\tasks\\"],
    },
    // ── Entry 26: Run/RunOnce Registry Keys ─────────────────────────────────
    ArtifactKnowledge {
        name: "Autorun Registry Keys",
        description: "Programs listed in Run and RunOnce registry keys execute \
            automatically when a user logs in. RunOnce entries are deleted after \
            execution. A primary persistence mechanism.",
        forensic_value: "Critical \u{2014} any entry here survives reboot. RunOnce entries \
            may indicate staged malware deployment. HKLM affects all users, HKCU \
            affects current user only.",
        locations: &[
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ],
        what_to_look_for: "Commands from unusual paths. Encoded PowerShell. Entries \
            pointing to deleted files. Recently added entries compared to known-good \
            baseline.",
        mitre_techniques: &["T1547.001"],
        related_artifacts: &["Scheduled Tasks", "Services", "Startup Folder"],
        name_patterns: &["\\currentversion\\run"],
    },
    // ── Entry 27: Windows Services ──────────────────────────────────────────
    ArtifactKnowledge {
        name: "Windows Service Configuration",
        description: "Windows Services run in the background under various accounts. \
            Service configurations are stored in the SYSTEM hive. Malware commonly \
            installs as a service for persistence and privilege.",
        forensic_value: "Critical \u{2014} new service installation is logged as Event 7045. \
            Service binary path reveals executable. Services running as SYSTEM have \
            full privileges.",
        locations: &[
            "SYSTEM\\CurrentControlSet\\Services\\",
            "C:\\Windows\\System32\\winevt\\Logs\\System.evtx (Event ID 7045)",
        ],
        what_to_look_for: "Services with unusual binary paths. Services running as \
            LocalSystem unnecessarily. Recently installed services. Services pointing \
            to Temp or user directories.",
        mitre_techniques: &["T1543.003"],
        related_artifacts: &["Run Keys", "Scheduled Tasks", "Event Logs"],
        name_patterns: &["system.evtx"],
    },
    // ── Entry 28: BITS Jobs ─────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Background Intelligent Transfer",
        description: "BITS is a Windows service for background file transfers. It can \
            execute a notification command when a transfer completes making it a \
            stealthy download and execute persistence mechanism.",
        forensic_value: "Critical \u{2014} can silently download files from any URL and \
            execute them. Survives reboots. Used by malware to download payloads while \
            appearing as legitimate Windows traffic.",
        locations: &[
            "C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr0.dat",
            "C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr1.dat",
        ],
        what_to_look_for: "Transfer source URLs. Destination file paths. Notification \
            commands (execute on complete). Unusual job names. Jobs created by non-system \
            processes.",
        mitre_techniques: &["T1197"],
        related_artifacts: &["Scheduled Tasks", "Run Keys", "Event Logs"],
        name_patterns: &["qmgr0.dat", "qmgr1.dat"],
    },
    // ═══════════════════════════════════════════════════════════════════════════
    // WINDOWS NETWORK ARTIFACTS (entries 29-30)
    // ═══════════════════════════════════════════════════════════════════════════
    // ── Entry 29: Network Profiles Registry ─────────────────────────────────
    ArtifactKnowledge {
        name: "Network Connection History",
        description: "Windows records every network connection in the registry \
            including the network name, type, first connection date, and last \
            connection date.",
        forensic_value: "High \u{2014} proves the device connected to specific networks. \
            Can establish location at specific times for WiFi networks. Shows if \
            device was on corporate vs home vs public networks.",
        locations: &[
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures",
        ],
        what_to_look_for: "First and last connection dates per network. Network type \
            (domain/private/public). Gateway MAC addresses in Signatures key. \
            Unrecognized network names.",
        mitre_techniques: &["T1049"],
        related_artifacts: &["WiFi Profiles", "SRUM", "VPN"],
        name_patterns: &["networklist"],
    },
    // ── Entry 30: RDP Connection History ────────────────────────────────────
    ArtifactKnowledge {
        name: "Remote Desktop Connection History",
        description: "Windows records recent Remote Desktop connection targets in \
            the registry. This shows systems the user connected to via RDP, providing \
            evidence of lateral movement or remote administration.",
        forensic_value: "Critical \u{2014} proves user connected to remote systems. Shows \
            destination hostnames and IPs. UsernameHint subkey reveals username used \
            for authentication.",
        locations: &[
            "NTUSER.DAT\\Software\\Microsoft\\Terminal Server Client\\Default",
            "NTUSER.DAT\\Software\\Microsoft\\Terminal Server Client\\Servers\\[server]\\UsernameHint",
        ],
        what_to_look_for: "Destination hostnames and IP addresses. Usernames used. \
            Correlate timestamps with Event 1149 (RDP authentication) and Event 21 \
            (remote logon) in event logs.",
        mitre_techniques: &["T1021.001"],
        related_artifacts: &["Event Logs", "Network Profiles", "Credential Manager"],
        name_patterns: &["terminal server client"],
    },
    // ═══════════════════════════════════════════════════════════════════════════
    // WINDOWS FILE SYSTEM ARTIFACTS (entries 31-35)
    // ═══════════════════════════════════════════════════════════════════════════
    // ── Entry 31: LNK Files (detailed) ──────────────────────────────────────
    ArtifactKnowledge {
        name: "Windows Shortcut File",
        description: "LNK files are Windows shortcuts automatically created when \
            files are opened. They contain the target file path, timestamps, file \
            size at time of access, and volume information including drive type and \
            serial number.",
        forensic_value: "High \u{2014} proves a file was accessed. Volume serial number can \
            identify specific USB drives. Machine NetBIOS name in LNK can identify \
            where file was accessed from. Timestamps show when file was first and \
            last accessed.",
        locations: &[
            "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk",
        ],
        what_to_look_for: "Target path reveals where original file was stored. Drive \
            type (removable = USB evidence). Volume serial number for drive ID. Machine \
            name if accessed from network. Target timestamps vs LNK timestamps.",
        mitre_techniques: &["T1547.009"],
        related_artifacts: &["Jump Lists", "RecentDocs", "MRU Lists"],
        name_patterns: &["recent\\.lnk", "recent/"],
    },
    // ── Entry 32: Thumbcache Database ───────────────────────────────────────
    ArtifactKnowledge {
        name: "Thumbnail Cache",
        description: "Windows caches thumbnail images of viewed files in Thumbcache \
            databases. Thumbnails persist even after the original files are deleted, \
            providing evidence of file content that no longer exists on disk.",
        forensic_value: "High \u{2014} can recover visual evidence of deleted images and \
            documents. Cache ID cross-references with MFT records to identify original \
            files.",
        locations: &[
            "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db",
        ],
        what_to_look_for: "Thumbnails of deleted files. Content that should not be \
            present. Cross-reference cache IDs with $MFT entries. Multiple size \
            variants per image.",
        mitre_techniques: &["T1005"],
        related_artifacts: &["$MFT", "Recycle Bin", "Gallery"],
        name_patterns: &["thumbcache_"],
    },
    // ── Entry 33: TypedPaths Registry ───────────────────────────────────────
    ArtifactKnowledge {
        name: "File Explorer Typed Paths",
        description: "When a user types a path directly into the File Explorer \
            address bar the path is recorded in the TypedPaths registry key. This \
            indicates the user had prior knowledge of that location.",
        forensic_value: "High \u{2014} proves user knowledge of specific file paths. \
            Network paths indicate knowledge of file server locations. Paths to \
            sensitive directories show intent.",
        locations: &[
            "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
        ],
        what_to_look_for: "Network share paths. Paths to sensitive directories. \
            Paths on removable media. Recently accessed unusual locations.",
        mitre_techniques: &["T1005"],
        related_artifacts: &["RecentDocs", "WordWheelQuery", "MRU Lists"],
        name_patterns: &["typedpaths"],
    },
    // ── Entry 34: WordWheelQuery ────────────────────────────────────────────
    ArtifactKnowledge {
        name: "File Explorer Search History",
        description: "Search terms entered into the Windows File Explorer search \
            box are recorded in the WordWheelQuery registry key as an MRU (Most \
            Recently Used) list.",
        forensic_value: "High \u{2014} reveals what the user was searching for on their \
            own system. Searches for specific filenames, tools, or keywords indicate \
            awareness and intent.",
        locations: &[
            "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery",
        ],
        what_to_look_for: "Searches for known tools or malware names. Searches for \
            victim data or sensitive files. Search timing correlated with other events.",
        mitre_techniques: &["T1005"],
        related_artifacts: &["TypedPaths", "RecentDocs", "Browser History"],
        name_patterns: &["wordwheelquery"],
    },
    // ── Entry 35: $LogFile ──────────────────────────────────────────────────
    ArtifactKnowledge {
        name: "NTFS Transaction Log",
        description: "The NTFS transaction log records all metadata changes to the \
            file system in a circular buffer. It can reveal recent file operations \
            even when the $MFT has been overwritten or the $UsnJrnl has wrapped.",
        forensic_value: "High \u{2014} captures recent file system transactions that may \
            not appear in $UsnJrnl. Can reconstruct sequences of file operations \
            including creates, renames, and deletes.",
        locations: &["C:\\$LogFile"],
        what_to_look_for: "Recent file creation and deletion operations. Transaction \
            sequences showing file manipulation. Operations that occurred between \
            $UsnJrnl journal wraps.",
        mitre_techniques: &["T1070.004"],
        related_artifacts: &["$MFT", "$UsnJrnl", "Recycle Bin"],
        name_patterns: &["$logfile"],
    },
    // ═══════════════════════════════════════════════════════════════════════════
    // WINDOWS ACCOUNT ARTIFACTS (entries 36-37)
    // ═══════════════════════════════════════════════════════════════════════════
    // ── Entry 36: SAM Hive (detailed) ───────────────────────────────────────
    ArtifactKnowledge {
        name: "Local Account Database",
        description: "The SAM hive stores local user account information including \
            usernames, account flags, password hint, last logon time, logon count, \
            and NTLM password hashes.",
        forensic_value: "Critical \u{2014} reveals all local user accounts including hidden \
            or rarely used accounts. Last logon time and logon count show account \
            activity. Account flags reveal if account is enabled, locked, or has \
            special privileges.",
        locations: &[
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SAM.LOG1",
        ],
        what_to_look_for: "Unexpected user accounts. Accounts with no logon history \
            (created but unused). Recently created accounts. Admin accounts with \
            suspicious names.",
        mitre_techniques: &["T1087.001", "T1003.002"],
        related_artifacts: &["Event Logs", "NTUSER.DAT", "Credential Manager"],
        name_patterns: &["config\\sam.log", "config/sam.log"],
    },
    // ── Entry 37: Windows Credential Manager ────────────────────────────────
    ArtifactKnowledge {
        name: "Windows Credential Store",
        description: "Windows Credential Manager stores saved network passwords, \
            certificate credentials, and generic credentials. Credentials are encrypted \
            with DPAPI tied to the user account.",
        forensic_value: "Critical \u{2014} reveals saved passwords for network shares, \
            websites, and applications. Can include domain credentials, VPN passwords, \
            and remote desktop credentials.",
        locations: &[
            "%APPDATA%\\Microsoft\\Credentials\\",
            "%LOCALAPPDATA%\\Microsoft\\Credentials\\",
            "%APPDATA%\\Microsoft\\Protect\\ (DPAPI keys)",
        ],
        what_to_look_for: "Credentials for unexpected systems. Domain credentials \
            indicating network access. VPN or remote access credentials. Recently \
            added credentials.",
        mitre_techniques: &["T1555.004"],
        related_artifacts: &["SAM", "Browser Passwords", "WiFi Profiles"],
        name_patterns: &["microsoft\\credentials", "microsoft/credentials", "microsoft\\protect"],
    },
    // ═══════════════════════════════════════════════════════════════════════════
    // BROWSER ARTIFACTS (entries 38-39)
    // ═══════════════════════════════════════════════════════════════════════════
    // ── Entry 38: Web Browser History (detailed) ────────────────────────────
    ArtifactKnowledge {
        name: "Web Browser History",
        description: "Chromium-based browsers store complete browsing history in a \
            SQLite database including URLs visited, page titles, visit counts, and \
            precise timestamps.",
        forensic_value: "High \u{2014} establishes web activity timeline. Reveals research \
            into specific topics. Download history shows files obtained from the web. \
            Search queries in URLs reveal intent.",
        locations: &[
            "Chrome: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History",
            "Edge: %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History",
            "Firefox: %APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\places.sqlite",
        ],
        what_to_look_for: "Visits to file sharing sites. Searches for tools or \
            techniques. C2 infrastructure domains. Visits timed with incidents. \
            Downloads correlated with events.",
        mitre_techniques: &["T1217"],
        related_artifacts: &["Browser Downloads", "Cookies", "Browser Passwords"],
        name_patterns: &["edge/user data", "edge\\user data"],
    },
    // ── Entry 39: Browser Downloads ─────────────────────────────────────────
    ArtifactKnowledge {
        name: "Browser Download History",
        description: "Web browsers record every file downloaded including the source \
            URL, local save path, file size, and download timestamp. Download records \
            persist even after files are deleted.",
        forensic_value: "High \u{2014} proves files were downloaded from specific URLs. \
            Source URL can identify malicious infrastructure. Save path shows where \
            file was stored. Timestamp establishes timeline.",
        locations: &[
            "Chrome/Edge: History database (downloads table)",
            "Firefox: places.sqlite (moz_annos table)",
        ],
        what_to_look_for: "Downloads from unusual or suspicious domains. Executable \
            files downloaded. Files downloaded then deleted. Downloads timed with other \
            suspicious events.",
        mitre_techniques: &["T1105"],
        related_artifacts: &["Browser History", "Prefetch", "$UsnJrnl"],
        name_patterns: &["downloads"],
    },
    // ═══════════════════════════════════════════════════════════════════════════
    // MOBILE ARTIFACTS (entries 40-41)
    // ═══════════════════════════════════════════════════════════════════════════
    // ── Entry 40: iOS Biome Data ────────────────────────────────────────────
    ArtifactKnowledge {
        name: "iOS Behavioral Analytics",
        description: "The iOS Biome system records fine-grained behavioral data \
            about app usage, notifications, user interactions, and device state. \
            Data is stored in structured binary files in the Biome directory.",
        forensic_value: "High \u{2014} captures extremely detailed behavioral patterns \
            including app interaction times, notification history, and usage patterns \
            not captured elsewhere.",
        locations: &[
            "/private/var/mobile/Library/Biome/",
        ],
        what_to_look_for: "App usage patterns at specific times. Notification history \
            showing received messages. Device interaction patterns. Cross-reference \
            with KnowledgeC.db for comprehensive timeline.",
        mitre_techniques: &["T1636"],
        related_artifacts: &["KnowledgeC.db", "DataUsage", "App Databases"],
        name_patterns: &["biome"],
    },
    // ── Entry 41: Android ADB Backup ────────────────────────────────────────
    ArtifactKnowledge {
        name: "Android Device Backup",
        description: "Android Debug Bridge backups contain device data exported via \
            ADB. The backup includes app data, contacts, SMS messages, and media \
            depending on backup options.",
        forensic_value: "Critical \u{2014} may contain complete app data, SMS history, \
            contacts, and call logs. Header identifies backup version and whether \
            data is encrypted.",
        locations: &[
            "Files ending in .ab",
            "Header: ANDROID BACKUP (15 bytes)",
        ],
        what_to_look_for: "Backup encryption status. App data included in backup. \
            SMS and call log data. Media files. Backup timestamp indicating when \
            data was extracted.",
        mitre_techniques: &["T1636"],
        related_artifacts: &["App Databases", "SMS Database", "Call Logs"],
        name_patterns: &[".ab"],
    },
    // ═══════════════════════════════════════════════════════════════════════════
    // CLOUD AND COMMUNICATION ARTIFACTS (entries 42-44)
    // ═══════════════════════════════════════════════════════════════════════════
    // ── Entry 42: Microsoft Teams Data ──────────────────────────────────────
    ArtifactKnowledge {
        name: "Microsoft Teams Activity",
        description: "Microsoft Teams stores chat messages, meeting history, file \
            transfers, and call logs in local application databases and log files \
            on the workstation.",
        forensic_value: "High \u{2014} reveals internal communications, file sharing, and \
            meeting activity. Log files contain timestamps of calls and meetings. \
            Can prove communication between parties at specific times.",
        locations: &[
            "%APPDATA%\\Microsoft\\Teams\\IndexedDB\\ (LevelDB format)",
            "%APPDATA%\\Microsoft\\Teams\\logs.txt",
        ],
        what_to_look_for: "Call and meeting timestamps. File transfer activity. \
            Channel and direct message activity. User IDs and tenant information. \
            Cross-reference with email and calendar artifacts.",
        mitre_techniques: &["T1213.003"],
        related_artifacts: &["Outlook", "OneDrive", "SharePoint Artifacts"],
        name_patterns: &["microsoft\\teams", "microsoft/teams"],
    },
    // ── Entry 43: OneDrive Sync Activity ────────────────────────────────────
    ArtifactKnowledge {
        name: "OneDrive Synchronization Log",
        description: "Microsoft OneDrive records file synchronization activity in \
            log files and databases. Shows which files were uploaded to or downloaded \
            from OneDrive and when.",
        forensic_value: "High \u{2014} can prove data exfiltration via cloud upload. Shows \
            files synced to personal OneDrive accounts from work systems. Timestamp \
            and file name in logs.",
        locations: &[
            "%LOCALAPPDATA%\\Microsoft\\OneDrive\\logs\\SyncDiagnostics.log",
            "%LOCALAPPDATA%\\Microsoft\\OneDrive\\settings\\",
        ],
        what_to_look_for: "Large volume uploads. Sensitive files synced to personal \
            accounts. Sync activity timed with departure or incidents. Account ID \
            (CID) identifying the account.",
        mitre_techniques: &["T1567.002"],
        related_artifacts: &["SharePoint", "Teams", "Cloud Credentials"],
        name_patterns: &["onedrive"],
    },
    // ── Entry 44: Slack Desktop Activity ────────────────────────────────────
    ArtifactKnowledge {
        name: "Slack Application Data",
        description: "The Slack desktop application stores cached messages, workspace \
            data, and activity logs locally. Even after messages are deleted from Slack \
            servers the local cache may retain content.",
        forensic_value: "High \u{2014} local cache may contain message content not available \
            from Slack servers. Log files show workspace connections and activity timing.",
        locations: &[
            "%APPDATA%\\Slack\\IndexedDB\\",
            "%APPDATA%\\Slack\\Cache\\",
            "%APPDATA%\\Slack\\logs\\",
        ],
        what_to_look_for: "Workspace names and identifiers. Message timing. File \
            transfer activity. Channel membership. Cached message content.",
        mitre_techniques: &["T1213"],
        related_artifacts: &["Teams", "Email", "OneDrive"],
        name_patterns: &["\\slack\\", "/slack/"],
    },
    // ═══════════════════════════════════════════════════════════════════════════
    // MALWARE ANALYSIS ARTIFACTS (entries 45-47)
    // ═══════════════════════════════════════════════════════════════════════════
    // ── Entry 45: PE Executable ─────────────────────────────────────────────
    ArtifactKnowledge {
        name: "Portable Executable File",
        description: "Windows executable files follow the PE format. The file header \
            contains compilation timestamp, imported library functions, exported \
            functions, and section characteristics that reveal the file's capabilities \
            and origin.",
        forensic_value: "Critical \u{2014} import table reveals capabilities (network, \
            process injection, encryption). Compilation timestamp can be verified or \
            identify timestomping. Section entropy indicates packing or encryption.",
        locations: &["Any .exe or .dll file"],
        what_to_look_for: "Compilation timestamp vs file system timestamps. Import \
            functions indicating injection or credential dumping. High section entropy \
            indicating packed/encrypted. Missing version information. No digital \
            signature.",
        mitre_techniques: &["T1059", "T1055", "T1027"],
        related_artifacts: &["Prefetch", "AmCache", "Vector"],
        name_patterns: &[".exe", ".dll", ".sys"],
    },
    // ── Entry 46: PowerShell Script ─────────────────────────────────────────
    ArtifactKnowledge {
        name: "PowerShell Script File",
        description: "PowerShell scripts are plain text files containing PowerShell \
            commands. They are frequently used by attackers due to PowerShell's deep \
            system access and built-in obfuscation capabilities.",
        forensic_value: "Critical \u{2014} script content directly reveals attacker intent \
            and techniques. Encoded commands require base64 decoding. Even deleted \
            scripts may leave traces in event logs and Prefetch.",
        locations: &["Any .ps1 file"],
        what_to_look_for: "Base64 encoded commands (-EncodedCommand). Hidden window \
            execution. Execution policy bypass. Download cradles (IEX + DownloadString). \
            Credential access functions. AMSI bypass attempts.",
        mitre_techniques: &["T1059.001"],
        related_artifacts: &["Event Logs (4103/4104)", "Prefetch", "AmCache"],
        name_patterns: &[".ps1"],
    },
    // ── Entry 47: Office Document with Macros ───────────────────────────────
    ArtifactKnowledge {
        name: "Macro-Enabled Office Document",
        description: "Microsoft Office documents can contain VBA macros that execute \
            automatically when opened. Macro-enabled documents are a primary initial \
            access vector. Legacy formats (.doc .xls) use OLE2 container format.",
        forensic_value: "Critical \u{2014} macro content reveals attacker payload. Document \
            metadata shows creation tool and author. Protected macros indicate \
            deliberate obfuscation. Opened documents appear in RecentDocs.",
        locations: &["Any .doc .xls .ppt .docm .xlsm .pptm file"],
        what_to_look_for: "VBA macro streams in OLE2 container. Auto-execute macros \
            (AutoOpen, AutoClose, Document_Open). Download functions. Shell execution. \
            Base64 encoded content. Document creation metadata.",
        mitre_techniques: &["T1137.001", "T1566.001"],
        related_artifacts: &["Prefetch", "RecentDocs", "Email Artifacts"],
        name_patterns: &[".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"],
    },
    // ═══════════════════════════════════════════════════════════════════════════
    // ADDITIONAL ARTIFACTS (entries 48-50)
    // ═══════════════════════════════════════════════════════════════════════════
    // ── Entry 48: WiFi Profiles XML ─────────────────────────────────────────
    ArtifactKnowledge {
        name: "WiFi Network Profile",
        description: "Windows stores XML configuration files for each WiFi network \
            that has been connected to, including the network name, security type, \
            authentication method, and connection mode (auto vs manual).",
        forensic_value: "High \u{2014} reveals every WiFi network the system has connected \
            to. Profile creation time approximates first connection. Auto-connect \
            setting shows regular usage vs one-time connection.",
        locations: &[
            "C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\{GUID}\\*.xml",
        ],
        what_to_look_for: "Network SSIDs for geolocation. Security type (open networks \
            are risky). Authentication method. Key material if present. Auto-connect \
            status indicating regular use.",
        mitre_techniques: &["T1016"],
        related_artifacts: &["Network Profiles", "SRUM", "Event Logs"],
        name_patterns: &["wlansvc", "wifi", ".xml"],
    },
    // ── Entry 49: Setupapi.dev.log ──────────────────────────────────────────
    ArtifactKnowledge {
        name: "Device Installation Log",
        description: "Setupapi.dev.log records every device driver installation \
            including USB devices, network adapters, and storage devices. Contains \
            timestamps of first connection for each device.",
        forensic_value: "High \u{2014} proves specific devices were connected to the system. \
            USB device first connection timestamp. Device serial numbers. Combined \
            with USBSTOR registry entries provides complete USB history.",
        locations: &[
            "C:\\Windows\\INF\\setupapi.dev.log",
        ],
        what_to_look_for: "USB device connections with timestamps. Device serial \
            numbers for identification. First install date per device. Cross-reference \
            with SYSTEM\\USBSTOR for last connection times.",
        mitre_techniques: &["T1052.001"],
        related_artifacts: &["SYSTEM hive", "Event Logs", "LNK Files"],
        name_patterns: &["setupapi.dev.log", "setupapi"],
    },
    // ── Entry 50: Sysmon Event Log ──────────────────────────────────────────
    ArtifactKnowledge {
        name: "System Monitor Event Log",
        description: "Sysmon is an advanced Windows monitoring tool that records \
            process creation, network connections, file creation time changes, and \
            many other events in a dedicated event log with much more detail than \
            standard Windows logging.",
        forensic_value: "Critical \u{2014} provides process command lines, parent process \
            chains, network connection details, file hash values, and process GUIDs \
            for correlation. Essential for advanced threat detection.",
        locations: &[
            "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
        ],
        what_to_look_for: "Event 1 (Process Create) for full command lines. Event 3 \
            (Network Connect) for C2 connections. Event 11 (File Create) for dropped \
            files. Event 8 (CreateRemoteThread) for injection. Event 22 (DNS Query) \
            for domain resolution.",
        mitre_techniques: &["T1059", "T1055", "T1071"],
        related_artifacts: &["Security.evtx", "PowerShell.evtx", "Prefetch"],
        name_patterns: &["sysmon"],
    },
];
