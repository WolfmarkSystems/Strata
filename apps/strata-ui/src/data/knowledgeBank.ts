export interface KnowledgeEntry {
  title: string
  summary: string
  forensic_value: 'critical' | 'high' | 'medium' | 'low'
  artifact_types: string[]
  typical_locations: string[]
  mitre_techniques: string[]
  examiner_notes: string
  threat_indicators?: string[]
}

export interface KnowledgeLookupResult {
  entry: KnowledgeEntry
  matchType: 'filename' | 'extension'
  extension: string
}

// Keyed by lowercase exact filename OR lowercase extension (no dot).
// Exact filename match takes priority over extension match.
export const KNOWLEDGE_BANK: Record<string, KnowledgeEntry> = {
  // ── EXACT FILENAME MATCHES ──

  'ntuser.dat': {
    title: 'Windows Registry — User Hive',
    summary:
      'The primary user registry hive. Contains the complete record of user activity including every application executed via UserAssist, recently accessed documents via RecentDocs, typed filesystem paths via TypedPaths, Explorer search terms via WordWheelQuery, and network shares accessed via MountPoints2. This single file can reconstruct a detailed timeline of user behavior.',
    forensic_value: 'critical',
    artifact_types: [
      'UserAssist execution history',
      'RecentDocs MRU list',
      'TypedPaths (address bar history)',
      'WordWheelQuery (search terms)',
      'MountPoints2 (USB/network history)',
      'RunMRU (Run dialog history)',
      'OpenSaveMRU (file dialog history)',
      'Shell bags (folder access)',
    ],
    typical_locations: [
      'C:\\Users\\[username]\\NTUSER.DAT',
      'C:\\Documents and Settings\\[username]\\NTUSER.DAT',
    ],
    mitre_techniques: [
      'T1204 — User Execution',
      'T1083 — File Discovery',
      'T1547 — Boot/Logon Autostart',
    ],
    examiner_notes:
      'Always parse this file first. UserAssist decoding requires ROT13 rotation of the application path. Run Chronicle plugin to extract all artifacts automatically.',
  },

  sam: {
    title: 'Windows Registry — SAM Hive',
    summary:
      'Security Account Manager database. Contains all local user accounts, their password hashes (NTLM), last logon timestamps, failed logon counts, account creation dates, and group memberships. Critical for identifying unauthorized accounts and authentication timeline.',
    forensic_value: 'critical',
    artifact_types: [
      'Local user account list',
      'NTLM password hashes',
      'Last logon timestamps',
      'Failed logon attempt counts',
      'Account creation dates',
      'Group memberships',
    ],
    typical_locations: ['C:\\Windows\\System32\\config\\SAM'],
    mitre_techniques: [
      'T1003.002 — Security Account Manager',
      'T1087.001 — Local Account Discovery',
    ],
    examiner_notes:
      'The SAM hive is locked while Windows is running. Access via offline acquisition or VSS shadow copy. Password hashes can be extracted with Mimikatz or offline tools.',
    threat_indicators: [
      'New admin accounts created recently',
      'Accounts with no password (empty hash)',
      'Accounts with recent creation + immediate admin privilege',
    ],
  },

  system: {
    title: 'Windows Registry — SYSTEM Hive',
    summary:
      'System-wide configuration registry hive. Contains USB device connection history (USBSTOR), mounted device map, network interface configuration, service and driver installations, time zone information, and computer name. Essential for device and network timeline reconstruction.',
    forensic_value: 'critical',
    artifact_types: [
      'USB device connection history (USBSTOR)',
      'Mounted devices map',
      'Installed services and drivers',
      'Network interface history',
      'Time zone configuration',
      'BAM/DAM execution timestamps',
    ],
    typical_locations: ['C:\\Windows\\System32\\config\\SYSTEM'],
    mitre_techniques: [
      'T1200 — Hardware Additions',
      'T1543.003 — Windows Service',
      'T1547.001 — Registry Run Keys',
    ],
    examiner_notes:
      'USBSTOR key reveals every USB storage device ever connected including serial numbers and connection timestamps. Run Trace plugin to extract BAM/DAM execution evidence.',
  },

  software: {
    title: 'Windows Registry — SOFTWARE Hive',
    summary:
      'System-wide software registry hive. Contains installed program list with installation dates, Windows version information, browser history (IE/Edge typed URLs), application settings, MUICache (execution evidence), and AppCompatCache/ShimCache for all executed programs.',
    forensic_value: 'high',
    artifact_types: [
      'Installed programs + dates',
      'AppCompatCache (ShimCache)',
      'MUICache execution evidence',
      'Windows version info',
      'Browser typed URLs',
      'Application settings',
    ],
    typical_locations: ['C:\\Windows\\System32\\config\\SOFTWARE'],
    mitre_techniques: ['T1204 — User Execution', 'T1518 — Software Discovery'],
    examiner_notes:
      'AppCompatCache entries survive file deletion and provide evidence of execution even when the binary is gone. ShimCache parsing varies by OS version.',
  },

  security: {
    title: 'Windows Registry — SECURITY Hive',
    summary:
      'Security policy and LSA secrets. Contains audit policy configuration, domain authentication cache, and Local Security Authority secrets which may include cached service account credentials. Typically requires SYSTEM privileges to access.',
    forensic_value: 'high',
    artifact_types: [
      'Audit policy settings',
      'LSA secrets (encrypted creds)',
      'Domain cached credentials',
      'Security policy configuration',
    ],
    typical_locations: ['C:\\Windows\\System32\\config\\SECURITY'],
    mitre_techniques: [
      'T1003.004 — LSA Secrets',
      'T1003.005 — Cached Domain Credentials',
    ],
    examiner_notes:
      'LSA secrets require offline decryption using the SYSTEM hive bootkey. Cached domain credentials (DCC2) are slow to crack but confirm domain membership.',
  },

  'security.evtx': {
    title: 'Windows Security Event Log',
    summary:
      'The most forensically valuable Windows event log. Records every logon and logoff (4624/4625/4634), privilege use, account management changes, policy modifications, and process creation with audit logging enabled. Essential for authentication timeline and lateral movement detection.',
    forensic_value: 'critical',
    artifact_types: [
      '4624 — Successful logon',
      '4625 — Failed logon attempt',
      '4634/4647 — Logoff',
      '4648 — Explicit credential logon',
      '4672 — Special privilege logon',
      '4688 — Process creation (if enabled)',
      '4698 — Scheduled task creation',
      '4720/4726 — Account created/deleted',
      '4776 — NTLM authentication',
    ],
    typical_locations: [
      'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
    ],
    mitre_techniques: [
      'T1078 — Valid Accounts',
      'T1021 — Remote Services',
      'T1053 — Scheduled Task',
    ],
    examiner_notes:
      'Event 4624 logon types: 2=Interactive, 3=Network, 10=RemoteInteractive (RDP). Look for type 3 and 10 for lateral movement. Cleared logs (event 1102) is itself evidence of anti-forensics.',
    threat_indicators: [
      'Event 1102 — Security log cleared',
      'Multiple 4625 failures before 4624',
      'Logon type 10 (RDP) from unexpected source',
      'Privileged accounts logging in outside business hours',
    ],
  },

  'system.evtx': {
    title: 'Windows System Event Log',
    summary:
      'System-level events including service starts and stops, driver loads, hardware changes, and system startup/shutdown times. Useful for establishing system timeline and detecting suspicious service installations.',
    forensic_value: 'high',
    artifact_types: [
      'System startup/shutdown times',
      'Service install events (7045)',
      'Service state changes (7036)',
      'Driver load events',
      'Hardware changes',
    ],
    typical_locations: [
      'C:\\Windows\\System32\\winevt\\Logs\\System.evtx',
    ],
    mitre_techniques: [
      'T1543.003 — Windows Service',
      'T1562.002 — Disable Windows Event Logging',
    ],
    examiner_notes:
      'Event 7045 (new service installed) is critical for detecting malware persistence. Look for services with random names or installed from temp directories.',
    threat_indicators: [
      'Event 7045 — New service from temp directory',
      'Unexpected system reboots',
      'Service names that mimic legitimate Windows services',
    ],
  },

  'mimikatz.exe': {
    title: '\u26A0 KNOWN THREAT — Mimikatz',
    summary:
      'CREDENTIAL DUMPING TOOL. Mimikatz is an open-source post-exploitation tool used to extract plaintext passwords, NTLM hashes, Kerberos tickets, and PIN codes from Windows memory (LSASS). Its presence on a system is a definitive indicator of credential theft activity.',
    forensic_value: 'critical',
    artifact_types: [
      'LSASS memory dumps',
      'Credential extraction evidence',
      'Kerberos ticket theft',
      'Pass-the-hash preparation',
    ],
    typical_locations: [
      'C:\\Windows\\Temp\\',
      'C:\\Users\\[user]\\Downloads\\',
      'Dropped by stagers in random paths',
    ],
    mitre_techniques: [
      'T1003 — OS Credential Dumping',
      'T1003.001 — LSASS Memory',
      'T1550.002 — Pass the Hash',
      'T1558 — Steal Kerberos Tickets',
    ],
    examiner_notes:
      'Search for lsass.dmp files which indicate Mimikatz was used in sekurlsa mode. Check Recycle Bin and USN journal for deleted copies. Prefetch entries prove execution even if binary deleted.',
    threat_indicators: [
      'CRITICAL — Presence alone is IOC',
      'Check for associated lsass.dmp',
      'Check Recycle Bin for deleted copy',
      'Check USN journal for creation event',
      'Check BAM/Prefetch for execution evidence',
    ],
  },

  'lsass.dmp': {
    title: '\u26A0 KNOWN THREAT — LSASS Memory Dump',
    summary:
      'Memory dump of the Windows Local Security Authority Subsystem Service (LSASS). Contains credentials for all logged-in users in plaintext or hash form. Created by credential dumping tools like Mimikatz, ProcDump, or Task Manager. Its presence indicates active credential theft.',
    forensic_value: 'critical',
    artifact_types: [
      'Plaintext credentials in memory',
      'NTLM password hashes',
      'Kerberos ticket cache',
      'Cached user credentials',
    ],
    typical_locations: [
      'C:\\Windows\\Temp\\lsass.dmp',
      'C:\\Users\\[user]\\lsass.dmp',
      'Recycle Bin (if deleted)',
    ],
    mitre_techniques: [
      'T1003.001 — LSASS Memory',
      'T1003 — OS Credential Dumping',
    ],
    examiner_notes:
      'Even if deleted, the USN journal and Recycle Bin metadata will show this file existed. Size typically 30-60MB. Creation timestamp correlated with mimikatz.exe execution.',
    threat_indicators: [
      'CRITICAL — Presence alone is IOC',
      'Cross-reference with mimikatz.exe timestamps',
      'Check Recycle Bin for deleted copy',
    ],
  },

  'cleanup.ps1': {
    title: '\u26A0 SUSPICIOUS — Anti-Forensic Script',
    summary:
      'PowerShell script with anti-forensic capabilities. Analysis of this file shows commands to delete evidence, clear event logs, and remove VSS shadow copies — classic post-intrusion cleanup activity designed to hinder forensic investigation.',
    forensic_value: 'critical',
    artifact_types: [
      'Anti-forensic command evidence',
      'Event log clearing commands',
      'VSS deletion commands',
      'File deletion evidence',
    ],
    typical_locations: ['C:\\Windows\\Temp\\', 'C:\\Users\\[user]\\'],
    mitre_techniques: [
      'T1070.001 — Clear Windows Event Logs',
      'T1070.004 — File Deletion',
      'T1490 — Inhibit System Recovery',
      'T1059.001 — PowerShell',
    ],
    examiner_notes:
      'Even if this script was executed and deleted, PowerShell script block logging (event 4104) may contain the full script content. Check Windows\\Prefetch for ps1 execution evidence.',
    threat_indicators: [
      'wevtutil cl — Event log clearing',
      'vssadmin delete shadows — VSS destruction',
      'Remove-Item with Force flag',
      'Execution timestamp correlated with intrusion timeline',
    ],
  },

  // ── EXTENSION MATCHES ──

  exe: {
    title: 'Windows Executable (PE)',
    summary:
      'Portable Executable format binary. All Windows programs, tools, and malware use this format. Key forensic artifacts include compilation timestamp, import table (reveals capabilities), digital signature status, and execution evidence in Prefetch/BAM/UserAssist.',
    forensic_value: 'medium',
    artifact_types: [
      'PE header + compilation timestamp',
      'Import table (capability analysis)',
      'Digital signature (or lack thereof)',
      'Version info strings',
      'Embedded resources',
    ],
    typical_locations: [
      'C:\\Windows\\System32\\',
      'C:\\Program Files\\',
      'Suspicious: C:\\Windows\\Temp\\',
      'Suspicious: C:\\Users\\[user]\\',
    ],
    mitre_techniques: [
      'T1204.002 — Malicious File',
      'T1027 — Obfuscated Files',
    ],
    examiner_notes:
      'Executables in Temp directories or user profile folders are high-priority for analysis. Run Vector plugin for static analysis. Check Prefetch for execution confirmation.',
  },

  dll: {
    title: 'Windows Dynamic Link Library',
    summary:
      'Shared library loaded by executables. Malware frequently uses DLL hijacking or sideloading to achieve execution. Check loaded DLLs in unusual locations — legitimate system DLLs should always be in System32.',
    forensic_value: 'medium',
    artifact_types: [
      'DLL exports and capabilities',
      'Load order hijacking evidence',
      'Sideloading artifacts',
    ],
    typical_locations: [
      'C:\\Windows\\System32\\',
      'Suspicious: Same dir as unsigned EXE',
      'Suspicious: User-writable directories',
    ],
    mitre_techniques: [
      'T1574.001 — DLL Search Order Hijacking',
      'T1574.002 — DLL Side-Loading',
    ],
    examiner_notes:
      'Compare DLL location against expected path. Legitimate Windows DLLs have valid Microsoft signatures. DLLs in temp or user directories are almost always malicious.',
  },

  lnk: {
    title: 'Windows Shell Link (Shortcut)',
    summary:
      'Windows shortcut file (.lnk). Contains metadata about the target file including original file path, volume serial number, NetBIOS hostname, and MAC address of the machine where the target resided. Critical for proving file access on remote systems.',
    forensic_value: 'high',
    artifact_types: [
      'Target file path',
      'Target volume serial number',
      'Source machine NetBIOS name',
      'Source machine MAC address',
      'File access timestamps',
      'Droid identifiers',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\Recent\\',
      'C:\\Users\\[user]\\Desktop\\',
      'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\',
    ],
    mitre_techniques: [
      'T1547.009 — Shortcut Modification',
      'T1083 — File Discovery',
    ],
    examiner_notes:
      'LNK files in the Recent folder prove a file was accessed — even if the original file no longer exists. The machine identifier fields can link a shortcut to a specific computer.',
  },

  evtx: {
    title: 'Windows Event Log',
    summary:
      'Binary XML event log file used by Windows Vista and later. Contains timestamped event records from system, security, application, and custom event channels. Essential for timeline reconstruction and incident response.',
    forensic_value: 'high',
    artifact_types: [
      'Timestamped system events',
      'Security audit events',
      'Application events',
      'PowerShell execution logs',
      'Scheduled task events',
    ],
    typical_locations: ['C:\\Windows\\System32\\winevt\\Logs\\'],
    mitre_techniques: ['T1562.002 — Disable Windows Event Logging'],
    examiner_notes:
      'A gap in event log timestamps indicates log clearing or system shutdown. Event ID 1102 (Security) or 104 (System) explicitly records log clearing. Run Chronicle plugin for automated parsing.',
  },

  pf: {
    title: 'Windows Prefetch File',
    summary:
      'Windows execution evidence artifact. Created when an executable runs for the first time and updated on subsequent executions. Records the executable path, run count, last 8 execution timestamps, and all files/DLLs accessed during execution.',
    forensic_value: 'high',
    artifact_types: [
      'Program execution path',
      'Run count',
      'Last 8 execution timestamps',
      'Files accessed during execution',
      'Volumes accessed',
    ],
    typical_locations: ['C:\\Windows\\Prefetch\\'],
    mitre_techniques: [
      'T1204 — User Execution',
      'T1070.004 — Indicator Removal',
    ],
    examiner_notes:
      'Prefetch files survive program deletion and prove execution. The filename includes an 8-character hash of the executable path. Windows 10+ stores last 8 run times. Disabled on servers by default.',
  },

  ps1: {
    title: 'PowerShell Script',
    summary:
      'PowerShell script file. PowerShell is a powerful scripting environment commonly abused for attack automation, lateral movement, credential theft, and anti-forensics. Script block logging (event 4104) may capture content even if file is deleted.',
    forensic_value: 'high',
    artifact_types: [
      'Script commands and logic',
      'Encoded command evidence',
      'Download cradle indicators',
      'Lateral movement commands',
    ],
    typical_locations: [
      'Suspicious: C:\\Windows\\Temp\\',
      'Suspicious: C:\\Users\\[user]\\',
      'Legitimate: C:\\Windows\\System32\\WindowsPowerShell\\',
    ],
    mitre_techniques: [
      'T1059.001 — PowerShell',
      'T1027 — Obfuscated Files',
      'T1140 — Deobfuscate/Decode',
    ],
    examiner_notes:
      'Check for Base64 encoded commands (-EncodedCommand). Check PowerShell event logs (Microsoft-Windows-PowerShell/Operational) for script block logging. Run Vector plugin for static analysis.',
  },

  bat: {
    title: 'Windows Batch Script',
    summary:
      'Legacy Windows command script. Batch files execute sequential system commands and are commonly used for simple automation, persistence mechanisms, and basic anti-forensic tasks. Executed by cmd.exe.',
    forensic_value: 'medium',
    artifact_types: [
      'Command sequences',
      'Scheduled task payloads',
      'Startup script content',
    ],
    typical_locations: [
      'C:\\Windows\\Temp\\',
      'C:\\ProgramData\\',
      'Startup folders',
    ],
    mitre_techniques: [
      'T1059.003 — Windows Command Shell',
      'T1547.001 — Registry Run Keys',
    ],
    examiner_notes:
      'Check Prefetch for cmd.exe execution correlated with batch file creation time. Batch files in startup locations indicate persistence.',
  },

  zip: {
    title: 'ZIP Archive',
    summary:
      'Compressed archive file. May contain packed malware, stolen data staged for exfiltration, or legitimate content. The internal file list and timestamps can provide evidence of what was packaged and when.',
    forensic_value: 'medium',
    artifact_types: [
      'Internal file listing',
      'Internal file timestamps',
      'Compression method',
      'Archive creation metadata',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\Downloads\\',
      'C:\\Users\\[user]\\Desktop\\',
      'C:\\Windows\\Temp\\',
    ],
    mitre_techniques: [
      'T1560.001 — Archive via Utility',
      'T1041 — Exfiltration over C2',
    ],
    examiner_notes:
      'Even deleted ZIP files may be recoverable from unallocated space via file carving. Internal timestamps predate the archive creation timestamp. Run Remnant plugin for recovery.',
  },

  rar: {
    title: 'RAR Archive',
    summary:
      'Compressed archive format. Frequently used by threat actors for staging collected data before exfiltration due to its split archive capability and optional password protection. Password-protected RARs require brute-force or dictionary attack.',
    forensic_value: 'medium',
    artifact_types: [
      'Internal file listing',
      'Password protection status',
      'Split archive indicators',
      'Creation metadata',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\',
      'C:\\Windows\\Temp\\',
      'Network shares',
    ],
    mitre_techniques: [
      'T1560.001 — Archive via Utility',
      'T1027 — Obfuscated Files',
    ],
    examiner_notes:
      'Password-protected RARs suggest deliberate obfuscation. Check for WinRAR in installed programs. Remnant plugin may recover deleted archives.',
  },

  db: {
    title: 'SQLite Database',
    summary:
      'SQLite database file. Widely used by browsers, mobile applications, messaging apps, and many Windows components to store structured data. May contain browsing history, messages, credentials, or application data depending on the source application. Open the SQLITE tab in the detail pane to inspect tables and rows with automatic timestamp conversion across all known forensic formats.',
    forensic_value: 'high',
    artifact_types: [
      'Application-specific records',
      'Browser history/cookies',
      'Message content',
      'Login/credential data',
      'Application usage data',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\',
      'Mobile device backups',
      'Browser profile folders',
    ],
    mitre_techniques: [
      'T1539 — Steal Web Session Cookie',
      'T1552 — Unsecured Credentials',
    ],
    examiner_notes:
      'SQLite databases have WAL (Write-Ahead Log) files that may contain recently modified records not yet committed. Check for .db-wal and .db-shm companion files. TIMESTAMP FORMATS IN THIS FILE: iOS/macOS apps (Core Data) use Mac Absolute Time — seconds since 2001-01-01, add 978307200 to get Unix. Android apps typically use Unix milliseconds — divide by 1000. Chrome / Edge use Webkit time — microseconds since 1601-01-01, divide by 1000000 then subtract 11644473600. Windows FILETIME is 100-ns ticks since 1601. The Strata SQLite viewer auto-detects all of these based on value magnitude and column name heuristics; the standalone Timestamp Converter widget at the bottom of the META tab lets you paste any raw number and pick a format manually.',
    threat_indicators: [
      'Message content mentioning sensitive data',
      'Recently modified records (check WAL file)',
      'Encryption tables present (SQLCipher header = 16 bytes of random data instead of "SQLite format 3")',
    ],
  },

  pdf: {
    title: 'PDF Document',
    summary:
      'Portable Document Format file. May contain embedded JavaScript, malicious links, or exploits targeting PDF readers. Metadata fields often reveal the original author, creating application, and creation/modification dates from the source system.',
    forensic_value: 'low',
    artifact_types: [
      'Document metadata (author, dates)',
      'Embedded scripts (if any)',
      'Hyperlinks and attachments',
      'Version history',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\Documents\\',
      'C:\\Users\\[user]\\Downloads\\',
      'Email attachments',
    ],
    mitre_techniques: [
      'T1566.001 — Spearphishing Attachment',
      'T1204.002 — Malicious File',
    ],
    examiner_notes:
      'PDFs received via email and opened may appear in LNK files. Metadata author field often contains the real username from the creating system, even when sent anonymously.',
  },

  xml: {
    title: 'XML Document',
    summary:
      'Extensible Markup Language file. Used extensively by Windows for configuration, scheduled tasks, WiFi profiles, and application settings. Forensically valuable XML files include scheduled task definitions and wireless network profiles.',
    forensic_value: 'medium',
    artifact_types: [
      'Scheduled task definitions',
      'WiFi network profiles',
      'Application configuration',
      'Group policy settings',
    ],
    typical_locations: [
      'C:\\Windows\\System32\\Tasks\\',
      'C:\\ProgramData\\Microsoft\\Wlansvc\\',
      'C:\\Windows\\System32\\GroupPolicy\\',
    ],
    mitre_techniques: [
      'T1053.005 — Scheduled Task',
      'T1552.001 — Credentials in Files',
    ],
    examiner_notes:
      'Scheduled task XML files in C:\\Windows\\System32\\Tasks reveal command, arguments, trigger, and author. WiFi profile XML files contain network credentials in encrypted form.',
  },

  // ══════════════════════════════════════════════════════════════════════
  // v0.6.0 — HIVE ARTIFACTS (Phantom plugin)
  // ══════════════════════════════════════════════════════════════════════

  'amcache.hve': {
    title: 'AmCache — Execution Evidence + SHA1',
    summary:
      'Gold-standard execution evidence hive. Win8+. Records every program executed including the SHA1 hash of the executable, compilation timestamp, publisher, product name, and first-seen time. Unlike Prefetch (volatile) AmCache persists permanently and includes a cryptographic hash you can check against known-bad sets.',
    forensic_value: 'critical',
    artifact_types: [
      'InventoryApplicationFile (SHA1, path, publisher, first-seen)',
      'InventoryApplication (installed apps)',
      'InventoryDriverBinary (signed/unsigned drivers)',
      'InventoryApplicationShortcut',
    ],
    typical_locations: [
      'C:\\Windows\\AppCompat\\Programs\\Amcache.hve',
    ],
    mitre_techniques: [
      'T1059 — Command and Scripting Interpreter',
      'T1204.002 — Malicious File',
      'T1014 — Rootkit (driver inventory)',
    ],
    examiner_notes:
      'Parse with Phantom plugin. FileId field is "0000" + SHA1 — strip the leading zeros. Cross-reference hashes against VirusTotal / your hash sets. Driver inventory reveals unsigned rootkits.',
    threat_indicators: [
      'SHA1 matches known malware',
      'Publisher field empty on an executable',
      'Executable path in Temp or AppData',
      'Unsigned driver outside System32\\drivers',
    ],
  },

  'usrclass.dat': {
    title: 'USRCLASS.DAT — User Class Hive',
    summary:
      'Per-user class registry hive. Contains Shellbags (including network/remote paths distinct from NTUSER.DAT shellbags), MuiCache (application display names — survives file deletion), and UserChoice (default app associations). Critical for proving directory browsing and application execution.',
    forensic_value: 'high',
    artifact_types: [
      'Shellbags (network paths, ZIP browsing, FTP folders, Control Panel)',
      'MuiCache (display names of executed programs)',
      'UserChoice (default handlers per extension)',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat',
    ],
    mitre_techniques: [
      'T1039 — Data from Network Shared Drive',
      'T1021 — Remote Services',
      'T1546.001 — Event Triggered Execution: Change Default File Association',
    ],
    examiner_notes:
      'USRCLASS shellbags capture different paths than NTUSER shellbags — always parse both. MuiCache entries survive the source executable being deleted, giving you display names of files that no longer exist.',
  },

  'shimcache': {
    title: 'ShimCache / AppCompatCache',
    summary:
      'Application Compatibility Cache — stored in the SYSTEM hive under ControlSet001\\Control\\Session Manager\\AppCompatCache. Records every executable the system considered running, along with the file\'s last modification time. It does NOT prove execution — it proves the file existed on the system at some point. Binary format varies by Windows version.',
    forensic_value: 'critical',
    artifact_types: [
      'Executable path',
      'File last modified time (NOT execution time)',
      'Shimmed flag',
      'Entry index (ordering)',
    ],
    typical_locations: [
      'SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCompatCache',
      'SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCompatibility (XP)',
    ],
    mitre_techniques: [
      'T1059 — Command and Scripting Interpreter',
      'T1202 — Indirect Command Execution',
    ],
    examiner_notes:
      'ShimCache is NOT proof of execution. It only proves the file existed. Cross-reference with Prefetch, AmCache, and UserAssist for execution confirmation. Win10 stores up to 1024 entries.',
    threat_indicators: [
      'Executable in ShimCache but not in current MFT → deleted',
      'Path contains Temp, AppData, or user-writable directory',
    ],
  },

  'usbstor': {
    title: 'USBSTOR — USB Device History',
    summary:
      'SYSTEM hive key that tracks every USB storage device ever connected to the system. Contains vendor, product, version, serial number, friendly name, and (in Properties subkey) first install, last connected, and last removal timestamps. Essential for data exfiltration investigations.',
    forensic_value: 'critical',
    artifact_types: [
      'Vendor / Product / Version / Serial number',
      'Friendly name',
      'First install time (Property 0064)',
      'Last connected time (Property 0066)',
      'Last removal time (Property 0067)',
    ],
    typical_locations: [
      'SYSTEM\\ControlSet001\\Enum\\USBSTOR\\{DeviceClass}\\{DeviceID}',
    ],
    mitre_techniques: [
      'T1025 — Data from Removable Media',
      'T1052.001 — Exfiltration over USB',
      'T1200 — Hardware Additions',
    ],
    examiner_notes:
      'Cross-reference USBSTOR serial numbers with MountPoints2 (NTUSER) to link devices to specific users. Also cross-reference with setupapi.dev.log for first-ever connection timestamp.',
    threat_indicators: [
      'New USB device first-connected during incident window',
      'Device connected immediately before large file access or deletion',
    ],
  },

  'mountpoints2': {
    title: 'MountPoints2 — User Drive Mounts',
    summary:
      'NTUSER.DAT key that records every mount point (drive letter assignment, network share) the user accessed. Cross-referenced with USBSTOR for USB device-to-user mapping, and with MRU lists for network share history.',
    forensic_value: 'high',
    artifact_types: [
      'Drive letter GUIDs',
      'Network share paths (##server#share)',
    ],
    typical_locations: [
      'NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2',
    ],
    mitre_techniques: [
      'T1135 — Network Share Discovery',
      'T1021 — Remote Services',
    ],
    examiner_notes:
      'Network share entries are prefixed with ## (doubled hash). Drive letter GUIDs cross-reference to SYSTEM\\MountedDevices to resolve the underlying device.',
  },

  'inventoryapplicationfile': {
    title: 'AmCache InventoryApplicationFile',
    summary:
      'The gold-standard execution evidence key inside AmCache.hve. Each subkey represents a distinct executable that the system has seen. Contains SHA1 hash, full path, publisher, product name, version, PE compilation timestamp, and first-seen-on-system time.',
    forensic_value: 'critical',
    artifact_types: [
      'FileId (SHA1 hash with 0000 prefix)',
      'LowerCaseLongPath (full path)',
      'Publisher / ProductName / ProductVersion',
      'LinkDate (PE compile timestamp)',
      'Size',
    ],
    typical_locations: [
      'AmCache.hve\\Root\\InventoryApplicationFile',
    ],
    mitre_techniques: [
      'T1059 — Command and Scripting Interpreter',
      'T1204.002 — Malicious File',
    ],
    examiner_notes:
      'Strip the leading "0000" from FileId to get the real SHA1. Cross-reference against VirusTotal or internal hash sets. Publisher="" is a strong malware indicator.',
    threat_indicators: [
      'SHA1 known-bad',
      'Empty Publisher + path in Temp/AppData',
      'PE compile time very recent',
    ],
  },

  'shellbags': {
    title: 'Shellbags — Folder Browsing Evidence',
    summary:
      'Windows records view settings for every folder ever browsed in Explorer. These entries persist even after the folder is deleted, providing proof that a specific directory was navigated to. Split between NTUSER.DAT (local paths) and USRCLASS.DAT (network + remote paths).',
    forensic_value: 'high',
    artifact_types: [
      'BagMRU (folder hierarchy)',
      'Bags (view settings per folder)',
      'Last interacted time (key LastWriteTime)',
      'Network shares, ZIP archives, FTP folders, Control Panel applets',
    ],
    typical_locations: [
      'NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\BagMRU',
      'USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU',
    ],
    mitre_techniques: [
      'T1083 — File and Directory Discovery',
      'T1135 — Network Share Discovery',
      'T1039 — Data from Network Shared Drive',
    ],
    examiner_notes:
      'Reconstruct the full path hierarchy by walking the BagMRU tree. A path in Shellbags proves the user navigated there even if the folder has since been deleted.',
  },

  'userassist': {
    title: 'UserAssist — GUI Program Execution',
    summary:
      'NTUSER.DAT key that records GUI program executions via Explorer. Unique in that it captures the last run time and run count for programs launched from the Start menu, desktop, or file explorer. The executable paths are ROT13-encoded — decode before analysis.',
    forensic_value: 'critical',
    artifact_types: [
      'Executable path (ROT13 encoded)',
      'Run count',
      'Last run time (FILETIME)',
      'Focus time (Win7+)',
    ],
    typical_locations: [
      'NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count',
    ],
    mitre_techniques: [
      'T1204 — User Execution',
    ],
    examiner_notes:
      'Decode keys with ROT13. Parsed by Chronicle plugin. Captures only GUI launches, not command-line execution.',
  },

  'runmru': {
    title: 'RunMRU — Run Dialog History',
    summary:
      'NTUSER.DAT key that records every command typed into the Windows Run dialog (Win+R). Direct evidence of user-initiated command execution — very hard to fake since it requires keyboard input.',
    forensic_value: 'high',
    artifact_types: [
      'Commands typed in Run dialog (most-recent first)',
      'Order (MRUListEx)',
    ],
    typical_locations: [
      'NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
    ],
    mitre_techniques: [
      'T1059.003 — Windows Command Shell',
      'T1204 — User Execution',
    ],
    examiner_notes:
      'RunMRU commands carry a trailing "\\1" suffix — strip it. Entries are user-typed so malware typically does not show up here unless an attacker had interactive access.',
  },

  'opensavemru': {
    title: 'OpenSavePidlMRU — File Dialog History',
    summary:
      'NTUSER.DAT key that records files opened or saved via the Windows common file dialog across ALL applications. One of the most universally useful MRUs — if any app used the standard Open/Save dialog, the file appears here.',
    forensic_value: 'high',
    artifact_types: [
      'File paths opened/saved in standard dialog',
      'Per-extension MRU lists',
      'Global MRU',
    ],
    typical_locations: [
      'NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU',
    ],
    mitre_techniques: [
      'T1083 — File and Directory Discovery',
      'T1005 — Data from Local System',
    ],
    examiner_notes:
      'Paths are encoded as PIDLs (shell item lists). Decode to reconstruct the full path. Cross-reference with LastVisitedPidlMRU to see which application accessed which directory.',
  },

  'lastvisitedmru': {
    title: 'LastVisitedPidlMRU — Application + Directory History',
    summary:
      'NTUSER.DAT key that pairs executables with the last directory they accessed via the file dialog. Proves both application execution and directory access in one artifact.',
    forensic_value: 'high',
    artifact_types: [
      'Executable name',
      'Last directory accessed',
    ],
    typical_locations: [
      'NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU',
    ],
    mitre_techniques: [
      'T1204 — User Execution',
      'T1083 — File and Directory Discovery',
    ],
    examiner_notes:
      'Proves both that an application was executed AND which directory it was looking at when it was. Very hard to fake.',
  },

  'bam': {
    title: 'BAM / DAM — Background/Desktop Activity Moderator',
    summary:
      'Win10+ SYSTEM hive feature that tracks background application activity for power management purposes, incidentally preserving execution evidence for every program that has run. Each entry includes the full path and last execution timestamp.',
    forensic_value: 'high',
    artifact_types: [
      'Full executable path',
      'Last execution timestamp (FILETIME)',
      'SID of the user who executed it',
    ],
    typical_locations: [
      'SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings\\{SID}',
      'SYSTEM\\ControlSet001\\Services\\dam\\State\\UserSettings\\{SID}',
    ],
    mitre_techniques: [
      'T1204 — User Execution',
    ],
    examiner_notes:
      'Parsed by Trace plugin. Each SID subkey represents a user — lets you attribute execution to a specific account. BAM tracks background apps, DAM tracks desktop activity.',
  },

  'prefetch': {
    title: 'Windows Prefetch',
    summary:
      'Windows feature that tracks the first 10 seconds of every executable that runs, for performance optimization. As a side effect it creates a per-executable .pf file containing the path, run count, last 8 run times, and all DLLs/files touched during execution.',
    forensic_value: 'critical',
    artifact_types: [
      'Executable path + hash',
      'Run count',
      'Last 8 run timestamps (Win10+)',
      'Accessed files during execution',
      'Volumes touched',
    ],
    typical_locations: [
      'C:\\Windows\\Prefetch\\',
    ],
    mitre_techniques: [
      'T1059 — Command and Scripting Interpreter',
      'T1204 — User Execution',
    ],
    examiner_notes:
      'Disabled by default on server OS. File format changed between Win7 (v23), Win8 (v26), and Win10+ (v30). Compressed with MAM\\x04 header on Win10+. Survives program deletion → smoking-gun execution proof.',
  },

  // ══════════════════════════════════════════════════════════════════════
  // EVTX event IDs — critical events by category
  // ══════════════════════════════════════════════════════════════════════

  'event-4624': {
    title: 'Event 4624 — Successful Logon',
    summary:
      'The most important authentication event on Windows. Records every successful logon with logon type indicating HOW the user logged in (interactive, network, RDP, service, unlock, etc.). Critical for lateral movement detection.',
    forensic_value: 'critical',
    artifact_types: [
      'Account name + domain + SID',
      'Logon type (2=Interactive, 3=Network, 10=RemoteInteractive/RDP)',
      'Source IP + port',
      'Logon GUID',
      'Process name that authenticated',
    ],
    typical_locations: [
      'Security.evtx',
    ],
    mitre_techniques: [
      'T1078 — Valid Accounts',
      'T1021 — Remote Services',
    ],
    examiner_notes:
      'Logon type 3 = network logon (SMB, RPC, share access). Type 10 = RDP. Type 7 = unlock. Cross-reference source IP against known attacker infrastructure.',
    threat_indicators: [
      'Type 10 (RDP) from unexpected source IP',
      'Admin account logon outside business hours',
      'Type 3 burst from single source (share enumeration)',
    ],
  },

  'event-4625': {
    title: 'Event 4625 — Failed Logon',
    summary:
      'Records every failed authentication attempt. Brute force detection: 5+ failures within 60 seconds from the same source is a very strong indicator. Sub-status code reveals WHY the logon failed (wrong password, locked account, disabled, etc.).',
    forensic_value: 'high',
    artifact_types: [
      'Account name (may be attacker-supplied)',
      'Source IP / workstation',
      'Failure reason (Status + Sub Status)',
      'Logon type',
    ],
    typical_locations: [
      'Security.evtx',
    ],
    mitre_techniques: [
      'T1110 — Brute Force',
      'T1078 — Valid Accounts',
    ],
    examiner_notes:
      'Status 0xC000006A = bad password. 0xC0000064 = account does not exist (enumeration). 0xC000006F = account disabled. Run Conduit plugin for brute-force detection windowing.',
    threat_indicators: [
      '5+ failures in 60s from single IP',
      'Failed logons to non-existent accounts (user enumeration)',
      'Failed Administrator logons',
    ],
  },

  'event-4688': {
    title: 'Event 4688 — Process Creation',
    summary:
      'Records every process creation when process auditing is enabled. With command-line auditing also enabled, captures the full command line — the single richest execution artifact available from Windows logging.',
    forensic_value: 'critical',
    artifact_types: [
      'New process name + PID',
      'Parent process name + PID',
      'Command line (if enabled)',
      'Account that launched the process',
      'Mandatory Label (integrity level)',
    ],
    typical_locations: [
      'Security.evtx',
    ],
    mitre_techniques: [
      'T1059 — Command and Scripting Interpreter',
      'T1204 — User Execution',
    ],
    examiner_notes:
      'Requires audit policy "Audit Process Creation" AND "Include command line in process creation events" both enabled. Most corporate systems have only the first enabled.',
    threat_indicators: [
      'Encoded PowerShell (-enc or -encodedcommand)',
      'Parent: winword.exe / outlook.exe, child: cmd.exe / powershell.exe',
      'Command line with base64',
    ],
  },

  'event-7045': {
    title: 'Event 7045 — Service Installed',
    summary:
      'Recorded in System.evtx whenever a new service is installed. One of the cleanest persistence-mechanism indicators — unlike Run keys (which can be added silently), a service install requires admin privileges and generates this specific event.',
    forensic_value: 'critical',
    artifact_types: [
      'Service name',
      'Service file name (ImagePath)',
      'Service type',
      'Start type',
      'Account',
    ],
    typical_locations: [
      'System.evtx',
    ],
    mitre_techniques: [
      'T1543.003 — Windows Service',
    ],
    examiner_notes:
      'Malware frequently installs services with random names or names that mimic Windows services. Cross-reference ImagePath against legitimate service paths.',
    threat_indicators: [
      'Service with ImagePath in \\Temp\\ or \\Users\\',
      'Random-looking service name',
      'Service installed during incident window',
    ],
  },

  'event-1102': {
    title: 'Event 1102 — Security Log Cleared',
    summary:
      'Recorded when the Security event log is manually cleared. This event IS ITSELF evidence of anti-forensics — there is no legitimate reason to clear the Security log on a production system. Always critical severity.',
    forensic_value: 'critical',
    artifact_types: [
      'Account that cleared the log',
      'Clear timestamp',
    ],
    typical_locations: [
      'Security.evtx',
    ],
    mitre_techniques: [
      'T1070.001 — Clear Windows Event Logs',
      'T1562 — Impair Defenses',
    ],
    examiner_notes:
      'Automatic critical indicator. Cross-reference the clear time with other timeline events. The account that cleared the log is often the compromised account or the attacker\'s freshly-created account.',
    threat_indicators: [
      'Log clear event present — always critical',
    ],
  },

  'event-104': {
    title: 'Event 104 — System Log Cleared',
    summary:
      'System.evtx counterpart to Event 1102. Records when the System log is cleared — another anti-forensic indicator.',
    forensic_value: 'critical',
    artifact_types: [
      'Account that cleared the log',
    ],
    typical_locations: [
      'System.evtx',
    ],
    mitre_techniques: [
      'T1070.001 — Clear Windows Event Logs',
    ],
    examiner_notes:
      'Paired with Event 1102. If both are present in a short time window it strongly suggests deliberate anti-forensics.',
  },

  'event-4698': {
    title: 'Event 4698 — Scheduled Task Created',
    summary:
      'Recorded when a new scheduled task is created. Schtasks, Task Scheduler GUI, and programmatic APIs all trigger this event. Captures the full task XML with command, arguments, trigger, and author.',
    forensic_value: 'high',
    artifact_types: [
      'Task name',
      'Task XML (full definition)',
      'Account that created it',
    ],
    typical_locations: [
      'Security.evtx',
    ],
    mitre_techniques: [
      'T1053.005 — Scheduled Task',
    ],
    examiner_notes:
      'Run Trace plugin to extract task commands. Flag tasks that run from Temp directories or run as SYSTEM with unsigned binaries.',
  },

  'event-4720': {
    title: 'Event 4720 — User Account Created',
    summary:
      'Records every local or domain user account creation. Critical for detecting attacker-created backdoor accounts. Cross-reference with 4722 (account enabled) and 4732 (added to administrators).',
    forensic_value: 'critical',
    artifact_types: [
      'New account SID + name',
      'Creator account',
      'Target domain',
    ],
    typical_locations: [
      'Security.evtx',
    ],
    mitre_techniques: [
      'T1136 — Create Account',
      'T1078 — Valid Accounts',
    ],
    examiner_notes:
      'Parsed by Phantom plugin. Always correlate with 4732 (added to Administrators group) — the combination is the smoking gun for persistent admin backdoor creation.',
    threat_indicators: [
      '4720 followed shortly by 4732 (Administrators group add)',
      'Account created outside business hours',
    ],
  },

  'event-4103': {
    title: 'Event 4103 / 4104 — PowerShell Script Block Logging',
    summary:
      'PowerShell Operational log events that capture the full content of every PowerShell command or script block executed. Event 4104 in particular captures deobfuscated script blocks, making it lethal against encoded/obfuscated attacks.',
    forensic_value: 'critical',
    artifact_types: [
      'Script block content (deobfuscated)',
      'Script file path',
      'Executing account',
    ],
    typical_locations: [
      'Microsoft-Windows-PowerShell%4Operational.evtx',
    ],
    mitre_techniques: [
      'T1059.001 — PowerShell',
      'T1027 — Obfuscated Files or Information',
      'T1140 — Deobfuscate/Decode',
    ],
    examiner_notes:
      'Script block logging must be enabled via Group Policy. When present, it is the single richest source of PowerShell forensic evidence. Parsed by Vector plugin.',
    threat_indicators: [
      'Invoke-Expression / IEX',
      'DownloadString / DownloadFile',
      'FromBase64String',
      '-EncodedCommand',
      'Reflection.Assembly::Load',
    ],
  },

  // ══════════════════════════════════════════════════════════════════════
  // v0.7.0 — FILESYSTEM ARTIFACTS
  // ══════════════════════════════════════════════════════════════════════

  'zone.identifier': {
    title: 'Zone.Identifier — Download Origin ADS',
    summary:
      'NTFS alternate data stream (ADS) attached to files downloaded from the internet. Contains the ZoneId (0=Local, 3=Internet, 4=Untrusted), the referrer URL, and the host URL. Proves where a file came from even after it has been moved or renamed.',
    forensic_value: 'high',
    artifact_types: [
      'ZoneId (0-4)',
      'ReferrerUrl',
      'HostUrl',
      'LastWriterPackageName (app that saved it)',
    ],
    typical_locations: [
      ':Zone.Identifier ADS on any downloaded file',
    ],
    mitre_techniques: [
      'T1105 — Ingress Tool Transfer',
      'T1566.001 — Spearphishing Attachment',
    ],
    examiner_notes:
      'Zone 3 or 4 on an executable is a strong IOC — it came from the internet and may be malware. Copy to FAT32 to strip the ADS (which some malware does deliberately).',
    threat_indicators: [
      'Executable with Zone 3/4',
      'Referrer URL to pastebin / file.io / tmpfiles / anonfiles',
    ],
  },

  'thumbcache': {
    title: 'Thumbcache — Image Viewing Evidence',
    summary:
      'Per-user binary cache of image thumbnails. Proves that a user viewed an image even if the source file has been deleted. Cannot reconstruct the filename from the thumbcache alone — cross-reference with MFT via the entry ID.',
    forensic_value: 'high',
    artifact_types: [
      'JPEG thumbnail data',
      'Entry hash (file identifier)',
      'Cache type (32/96/256/1024 px)',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db',
    ],
    mitre_techniques: [
      'T1005 — Data from Local System',
      'T1074.001 — Local Data Staging',
    ],
    examiner_notes:
      'Custom binary format (CMMM magic). Each entry hashes to a specific file identifier. Extract thumbnails to see what the user actually viewed.',
  },

  '$i30': {
    title: '$I30 — NTFS Directory Index',
    summary:
      'NTFS attribute on every directory containing a B-tree index of the files in that directory. Slack space inside the $I30 stream often retains entries for files that have been deleted, providing a record of files that once existed in a folder.',
    forensic_value: 'high',
    artifact_types: [
      'File names in directory (including deleted)',
      'Created / modified / MFT record timestamps',
      'File size',
    ],
    typical_locations: [
      '$I30 attribute on any NTFS directory',
    ],
    mitre_techniques: [
      'T1070.004 — File Deletion',
      'T1083 — File and Directory Discovery',
    ],
    examiner_notes:
      'Presence of a filename in $I30 without a corresponding current MFT entry proves the file was deleted from that directory. Critical for recovering filenames of deleted evidence.',
  },

  '$logfile': {
    title: '$LogFile — NTFS Transaction Journal',
    summary:
      'NTFS metadata journal that records every filesystem operation for crash recovery. Forensically valuable because it can reconstruct file operations (create, rename, delete) even after the USN journal has rolled over.',
    forensic_value: 'high',
    artifact_types: [
      'File operations (create, rename, delete, set-info)',
      'MFT record updates',
      'Operation timestamps',
    ],
    typical_locations: [
      '$LogFile (root of NTFS volume)',
    ],
    mitre_techniques: [
      'T1070.004 — File Deletion',
    ],
    examiner_notes:
      'Complex binary format. Extract basic operation records first. Cross-reference with USN journal for completeness.',
  },

  'setupapi.dev.log': {
    title: 'setupapi.dev.log — First USB Connection',
    summary:
      'Windows device setup log. Contains the first-ever install timestamp for every PnP device (including USB storage) connected to the system. Cross-reference with USBSTOR registry for full device timeline.',
    forensic_value: 'high',
    artifact_types: [
      'Device install timestamps',
      'Driver package source',
      'Device instance IDs',
    ],
    typical_locations: [
      'C:\\Windows\\inf\\setupapi.dev.log (Win7+)',
      'C:\\Windows\\setupapi.log (XP)',
    ],
    mitre_techniques: [
      'T1200 — Hardware Additions',
    ],
    examiner_notes:
      'Log timestamps are in LOCAL time — document the system timezone. Search for device serial numbers to establish first-ever connection time (more reliable than registry which may have been cleared).',
  },

  'ual': {
    title: 'UAL — User Access Logging (Server only)',
    summary:
      'Windows Server-only feature that logs every authenticated client connection to the server. Stored in ESE databases. The single most valuable artifact for lateral movement investigations on servers — records every user and source IP that authenticated.',
    forensic_value: 'critical',
    artifact_types: [
      'Username + domain',
      'Source IP address',
      'Auth type',
      'First access + last access timestamps',
      'Service/role accessed',
    ],
    typical_locations: [
      'C:\\Windows\\System32\\LogFiles\\Sum\\*.mdb',
      'C:\\Windows\\System32\\LogFiles\\Sum\\Current.mdb',
    ],
    mitre_techniques: [
      'T1021 — Remote Services',
      'T1078 — Valid Accounts',
    ],
    examiner_notes:
      'Server OS only — not present on workstations. Retains 2+ years of connection history. Parse via libesedb or similar ESE reader.',
  },

  // ══════════════════════════════════════════════════════════════════════
  // v0.8.0 — THIRD-PARTY APPLICATIONS
  // ══════════════════════════════════════════════════════════════════════

  'winscp.ini': {
    title: 'WinSCP — SFTP Client',
    summary:
      'WinSCP is a free Windows SFTP/FTP/SCP client frequently abused for data exfiltration. The configuration file and registry keys contain remote host history, usernames, saved sessions, and the path to the session log.',
    forensic_value: 'critical',
    artifact_types: [
      'Saved sessions (hostname + username)',
      'Remote directory history',
      'Log file path',
      'Recently edited files',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\Roaming\\WinSCP.ini',
      'HKCU\\Software\\Martin Prikryl\\WinSCP 2\\',
    ],
    mitre_techniques: [
      'T1048 — Exfiltration Over Alternative Protocol',
      'T1567 — Exfiltration Over Web Service',
    ],
    examiner_notes:
      'Parsed by Cipher plugin. The HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\CDCache key contains recent hostnames. Remote directory history is in the History\\RemoteTarget key.',
    threat_indicators: [
      'Recent session to unknown external IP during incident window',
      'Log file showing transferred filenames',
    ],
  },

  'rclone.conf': {
    title: 'Rclone — Cloud Sync / Exfiltration Tool',
    summary:
      'Rclone is a command-line tool that syncs files to 40+ cloud storage providers. Widely used legitimately AND as the #1 mass-exfiltration tool in ransomware incidents. The config file lists every configured remote with type and credentials.',
    forensic_value: 'critical',
    artifact_types: [
      'Remote names (one per configured destination)',
      'Remote type (s3 / gdrive / dropbox / sftp / etc.)',
      'Access keys / OAuth tokens',
      'Endpoints',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\Roaming\\rclone\\rclone.conf',
      '~/.config/rclone/rclone.conf',
      'Directory next to rclone.exe',
    ],
    mitre_techniques: [
      'T1537 — Transfer Data to Cloud Account',
      'T1567 — Exfiltration Over Web Service',
    ],
    examiner_notes:
      'Parsed by Cipher plugin. Cross-reference with Power Efficiency Diagnostics HTML reports (%ProgramData%\\Microsoft\\Windows\\Power Efficiency Diagnostics\\) for long-running rclone sessions.',
    threat_indicators: [
      'Rclone present on victim → near-certain IOC in ransomware cases',
      'Remote type = s3 / b2 with unknown access keys',
    ],
  },

  'megasync': {
    title: 'MEGAsync — Mega.nz Desktop Sync',
    summary:
      'Desktop sync client for MEGA.nz cloud storage. Popular in ransomware data exfiltration due to free 50GB accounts and strong encryption. Configuration file contains sync folder paths and account metadata.',
    forensic_value: 'high',
    artifact_types: [
      'Sync folder paths',
      'Account email (encrypted)',
      'Upload/download logs',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\Local\\Mega Limited\\MEGAsync\\MEGAsync.cfg',
      'C:\\Users\\[user]\\AppData\\Local\\Mega Limited\\MEGAsync\\logs\\',
    ],
    mitre_techniques: [
      'T1537 — Transfer Data to Cloud Account',
    ],
    examiner_notes:
      'Scheduled task \\MEGA\\MEGAsync Update Task is a persistence vector. Check HKCU\\SOFTWARE\\Classes\\CLSID for TargetFolderPath that resolves to sync location.',
  },

  '7zip': {
    title: '7-Zip — Archive Tool',
    summary:
      'Popular archive tool. Registry keys record recently browsed folders and compression settings. Archive creation is frequently the staging step before cloud/FTP exfiltration.',
    forensic_value: 'medium',
    artifact_types: [
      'FolderHistory (recently browsed paths)',
      'Compression settings',
    ],
    typical_locations: [
      'HKCU\\Software\\7-Zip\\FM\\FolderHistory',
      'HKCU\\Software\\7-Zip\\Compression',
    ],
    mitre_techniques: [
      'T1560.001 — Archive via Utility',
      'T1074.001 — Local Data Staging',
    ],
    examiner_notes:
      'Cross-reference 7-Zip activity with subsequent cloud sync or file upload — archive creation immediately before exfiltration is a Sigma rule trigger.',
  },

  'winrar': {
    title: 'WinRAR — Archive Tool',
    summary:
      'Commercial archive tool. Frequently used for data staging. Registry tracks archive history and extraction paths — valuable for proving what was archived.',
    forensic_value: 'medium',
    artifact_types: [
      'ArcHistory (archive history)',
      'DialogEditHistory ExtrPath',
    ],
    typical_locations: [
      'HKCU\\Software\\WinRAR\\ArcHistory',
      'HKCU\\Software\\WinRAR\\DialogEditHistory\\ExtrPath',
    ],
    mitre_techniques: [
      'T1560.001 — Archive via Utility',
    ],
    examiner_notes:
      'Password-protected RAR archives created during incident window are high-priority evidence. Check ArcHistory for filenames you don\'t recognize.',
  },

  'teracopy': {
    title: 'TeraCopy — File Copy Utility',
    summary:
      'TeraCopy replaces the default Windows copy/move dialog. Keeps detailed logs of every file operation including source and destination paths. Extremely valuable for proving file movement in exfiltration cases.',
    forensic_value: 'high',
    artifact_types: [
      'Source path',
      'Destination path',
      'File size',
      'Copy timestamp',
      'Success / failure',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\Roaming\\TeraCopy\\',
    ],
    mitre_techniques: [
      'T1005 — Data from Local System',
      'T1074.001 — Local Data Staging',
    ],
    examiner_notes:
      'TeraCopy logs are often overlooked. If the suspect used TeraCopy to move evidence to an external drive, the logs prove every file and the exact timestamps.',
  },

  'session.xml': {
    title: 'Notepad++ Session History',
    summary:
      'Notepad++ saves a session.xml file listing every recently opened file. Very valuable when examining insider threat cases — reveals which text files, scripts, and config files the user edited.',
    forensic_value: 'high',
    artifact_types: [
      'Recently opened files (paths)',
      'Cursor position',
      'Language mode',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\Roaming\\Notepad++\\session.xml',
    ],
    mitre_techniques: [
      'T1005 — Data from Local System',
    ],
    examiner_notes:
      'Plain XML — open directly. Common targets: hosts files, config files, stolen credentials stored in text, scripts the user wrote or modified.',
  },

  // ══════════════════════════════════════════════════════════════════════
  // v0.9.0 — macOS / iOS / ANDROID
  // ══════════════════════════════════════════════════════════════════════

  'knowledgec': {
    title: 'KnowledgeC.db — macOS/iOS Activity Timeline',
    summary:
      'SQLite database that tracks everything a Mac or iOS device does at the system level: app launches, notifications received, battery state, focus/sleep events, device-to-device handoffs, Siri interactions. The richest forensic artifact on Apple platforms — the macOS/iOS equivalent of SRUM + UserAssist + Event Log combined.',
    forensic_value: 'critical',
    artifact_types: [
      'App usage (launch, quit, focus)',
      'Notifications received',
      'Battery state changes',
      'Lock / unlock events',
      'Handoff events (device transfers)',
      'Siri interactions',
    ],
    typical_locations: [
      '/private/var/db/CoreDuet/Knowledge/knowledgeC.db (macOS)',
      '/private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db (iOS)',
    ],
    mitre_techniques: [
      'T1005 — Data from Local System',
    ],
    examiner_notes:
      'Parsed by Specter plugin. Query the ZOBJECT table joined with ZSTRUCTUREDMETADATA for app usage events. Timestamps are Cocoa epoch (seconds since 2001-01-01 UTC).',
  },

  'powerlog': {
    title: 'PowerLog — iOS App Usage Timeline',
    summary:
      'iOS system database that records fine-grained app usage, screen events, and call events for power-management purposes. Similar to KnowledgeC but with even finer resolution on certain event types. Retains weeks of data.',
    forensic_value: 'critical',
    artifact_types: [
      'App launch / foreground / background events',
      'Screen on / off',
      'Phone call events',
      'Location subsystem activity',
    ],
    typical_locations: [
      '/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL',
    ],
    mitre_techniques: [
      'T1005 — Data from Local System',
    ],
    examiner_notes:
      'iOS only. PLApplicationAgent_EventForward_ApplicationRunTime table has app foreground durations with timestamps. Very useful for proving someone was using a specific app at a specific time.',
  },

  'locationd': {
    title: 'locationd clients.plist — iOS Location Authorizations',
    summary:
      'iOS property list that records every app that has requested location access, with authorization grant/denial timestamps. Reveals which apps could have tracked the user\'s location even if app data has been wiped.',
    forensic_value: 'high',
    artifact_types: [
      'App bundle identifier',
      'Location authorization status',
      'First use timestamp',
      'Last use timestamp',
    ],
    typical_locations: [
      '/private/var/mobile/Library/Caches/locationd/clients.plist',
      '/private/var/root/Library/Caches/locationd/clients.plist',
    ],
    mitre_techniques: [
      'T1430 — Location Tracking (mobile)',
    ],
    examiner_notes:
      'Binary plist. Parse with plist crate. Each client entry has Authorization, LocationTimeStopped, BundlePath.',
  },

  'sms.db': {
    title: 'SMS / iMessage Database',
    summary:
      'SQLite database containing every SMS and iMessage on an iOS device. Survives app reinstall. Includes message text, sender/recipient, timestamp, read status, and metadata for attachments (but not the attachment bodies themselves).',
    forensic_value: 'critical',
    artifact_types: [
      'Message text',
      'Sender / recipient phone numbers',
      'Sent / received timestamps',
      'Read status',
      'Attachment metadata (filenames, MIME types)',
      'Group chat participants',
    ],
    typical_locations: [
      '/private/var/mobile/Library/SMS/sms.db',
      '~/Library/Messages/chat.db (macOS Messages)',
    ],
    mitre_techniques: [
      'T1005 — Data from Local System',
      'T1213 — Data from Information Repositories',
    ],
    examiner_notes:
      'Parsed by Specter plugin. Main tables: message, handle (contacts), chat (groups), attachment. Deleted messages may persist in SQLite free-pages — use a SQLite recovery tool.',
  },

  'callhistory.storedata': {
    title: 'CallHistory — iOS/macOS Call Records',
    summary:
      'SQLite database of all cellular and FaceTime call records. Includes caller/callee, duration, call type (incoming/outgoing/missed/FaceTime audio/video), and timestamp.',
    forensic_value: 'critical',
    artifact_types: [
      'Phone number',
      'Duration',
      'Call type',
      'Start timestamp',
      'Country code',
    ],
    typical_locations: [
      '/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata',
    ],
    mitre_techniques: [
      'T1005 — Data from Local System',
    ],
    examiner_notes:
      'ZCALLRECORD is the main table. Joins with a handles table for contact resolution. Deleted call records may persist in free-pages.',
  },

  'whatsapp.msgstore': {
    title: 'WhatsApp msgstore.db',
    summary:
      'WhatsApp message database for Android. On iOS the equivalent is ChatStorage.sqlite. Contains all messages, group chats, media metadata, and contact info. End-to-end encryption does NOT apply to locally stored data — it is plaintext on the device.',
    forensic_value: 'critical',
    artifact_types: [
      'Message text',
      'Sender JID (phone number)',
      'Chat type (1:1, group)',
      'Media filename / hash',
      'Sent / received timestamps',
    ],
    typical_locations: [
      '/data/data/com.whatsapp/databases/msgstore.db (Android)',
      '~/Library/Containers/net.whatsapp.WhatsApp/Data/Documents/ChatStorage.sqlite (iOS)',
    ],
    mitre_techniques: [
      'T1005 — Data from Local System',
    ],
    examiner_notes:
      'Parsed by Specter plugin. Main tables: messages, jid (contacts), chat_list. Media is referenced by hash — actual files live under Media/. Encrypted backups on external storage use Crypt14/Crypt15.',
  },

  'unified.logarchive': {
    title: 'macOS Unified Log',
    summary:
      'macOS equivalent of Windows Event Log (post-Sierra 10.12). Captures system-wide events across all subsystems: processes, auth, network, sandbox, etc. Stored in a proprietary tracev3 binary format inside a logarchive bundle.',
    forensic_value: 'critical',
    artifact_types: [
      'Process lifecycle events',
      'Authentication events',
      'sudo / ssh activity',
      'Network state changes',
      'Sandbox denials',
    ],
    typical_locations: [
      '/private/var/db/diagnostics/*.logarchive',
      '/private/var/db/uuidtext/',
    ],
    mitre_techniques: [
      'T1078 — Valid Accounts',
      'T1059 — Command and Scripting Interpreter',
    ],
    examiner_notes:
      'Use `log show --archive [path] --predicate [filter]` on macOS, or direct tracev3 parsing for cross-platform analysis. Key subsystems: com.apple.loginwindow, process:sudo, process:sshd, subsystem:com.apple.authd.',
  },

  'launchagents': {
    title: 'macOS LaunchAgents / LaunchDaemons',
    summary:
      'Property list files that configure macOS startup items. LaunchAgents run as the user; LaunchDaemons run as root. The single most common macOS persistence mechanism. Malicious plists are the equivalent of Windows Run keys.',
    forensic_value: 'critical',
    artifact_types: [
      'Label',
      'ProgramArguments (command + args)',
      'RunAtLoad / KeepAlive',
      'StartInterval',
      'Owner (if daemon)',
    ],
    typical_locations: [
      '~/Library/LaunchAgents/*.plist',
      '/Library/LaunchAgents/*.plist',
      '/Library/LaunchDaemons/*.plist',
      '/System/Library/LaunchDaemons/*.plist (baseline)',
    ],
    mitre_techniques: [
      'T1543.001 — Launch Agent',
      'T1543.004 — Launch Daemon',
    ],
    examiner_notes:
      'Compare against a clean-system baseline to identify additions. Any LaunchAgent or LaunchDaemon with ProgramArguments pointing to /tmp, /private/tmp, or a user-writable directory is a strong malware indicator.',
  },

  'plist': {
    title: 'macOS Property List',
    summary:
      'macOS configuration file format — either XML or binary. Used for application preferences, LaunchAgents, network configurations, and countless other settings. Binary plists (bplist00) are compact and widely used on iOS.',
    forensic_value: 'medium',
    artifact_types: [
      'Key-value configuration data',
      'Nested arrays and dictionaries',
      'Dates, data blobs, strings, numbers',
    ],
    typical_locations: [
      '~/Library/Preferences/ (user prefs)',
      '/Library/Preferences/ (system prefs)',
      '~/Library/LaunchAgents/',
    ],
    mitre_techniques: [
      'T1543.001 — Launch Agent',
      'T1555.002 — Credentials from Password Stores',
    ],
    examiner_notes:
      'Binary plists start with "bplist00" magic. Use plist crate for parsing. `plutil -convert xml1 file.plist` converts a binary plist to XML in-place (do not run on evidence).',
  },

  'recent_items': {
    title: 'macOS Recent Items',
    summary:
      'macOS property list tracking recently used applications, documents, and servers — the per-user MRU for the Apple Menu\'s Recent Items submenu.',
    forensic_value: 'high',
    artifact_types: [
      'Recent applications',
      'Recent documents',
      'Recent servers (SMB/AFP/NFS)',
    ],
    typical_locations: [
      '~/Library/Preferences/com.apple.recentitems.plist',
    ],
    mitre_techniques: [
      'T1083 — File and Directory Discovery',
    ],
    examiner_notes:
      'RecentApplications, RecentDocuments, RecentServers keys. Binary plist.',
  },

  // ══════════════════════════════════════════════════════════════════════
  // v1.0.0 — NETWORK + MEMORY
  // ══════════════════════════════════════════════════════════════════════

  'pcap': {
    title: 'PCAP / PCAPNG — Network Packet Capture',
    summary:
      'libpcap-format network capture file. Contains raw packet data including Layer 2/3/4 headers and (for unencrypted protocols) full payloads. The richest possible source of network forensic evidence but very volume-heavy.',
    forensic_value: 'high',
    artifact_types: [
      'TCP / UDP conversations',
      'DNS queries and responses',
      'HTTP requests (User-Agent, URI, headers)',
      'SMTP sender / recipient / subject',
      'FTP commands + filenames',
      'TLS SNI (decrypted or not)',
    ],
    typical_locations: [
      'Tcpdump captures, Wireshark saves, tap output',
    ],
    mitre_techniques: [
      'T1071 — Application Layer Protocol',
      'T1048 — Exfiltration Over Alternative Protocol',
    ],
    examiner_notes:
      'Use tshark / tcpdump for filtering. Flag: DNS TXT records (covert channel), long URI query strings (data exfil), HTTP basic auth (cleartext creds), SMTP to unexpected recipients.',
    threat_indicators: [
      'DNS to known-bad TLD (.tk, .top, .xyz on workstation)',
      'Outbound TLS to non-standard ports',
      'Beaconing pattern (regular interval connections)',
    ],
  },

  '.pcap': {
    title: 'PCAP Packet Capture',
    summary: 'See pcap entry.',
    forensic_value: 'high',
    artifact_types: [],
    typical_locations: [],
    mitre_techniques: ['T1071', 'T1048'],
    examiner_notes: 'See pcap entry for full details.',
  },

  'iis-log': {
    title: 'IIS W3C Log',
    summary:
      'Microsoft IIS web server access log in W3C format. Records every HTTP request with date, time, client IP, method, URI, query, response code, user-agent, and more. Critical for web application compromise investigations.',
    forensic_value: 'high',
    artifact_types: [
      'Client IP',
      'HTTP method + URI + query string',
      'Response code',
      'User-Agent',
      'Authenticated username',
    ],
    typical_locations: [
      'C:\\Windows\\System32\\LogFiles\\W3SVC*\\*.log',
      'C:\\inetpub\\logs\\LogFiles\\W3SVC*\\',
    ],
    mitre_techniques: [
      'T1190 — Exploit Public-Facing Application',
      'T1505.003 — Web Shell',
    ],
    examiner_notes:
      'Grep for webshell indicators: "cmd=", "exec=", "eval(", file uploads to .aspx/.php paths. SQL injection: "union", "--", "1=1", "select " in query strings.',
    threat_indicators: [
      'Webshell URIs (*.aspx, *.jsp, *.php) with non-standard query strings',
      'SQL injection patterns',
      '404 flood from single IP (scanning)',
      'POST to non-existent pages with large bodies',
    ],
  },

  'access-log': {
    title: 'Apache / Nginx access.log',
    summary:
      'Standard web server access log (Combined Log Format). Records every HTTP request similar to IIS but in text format with different field order.',
    forensic_value: 'high',
    artifact_types: [
      'Remote host',
      'Timestamp',
      'HTTP request line',
      'Status code',
      'Bytes sent',
      'Referer',
      'User-Agent',
    ],
    typical_locations: [
      '/var/log/apache2/access.log',
      '/var/log/nginx/access.log',
      '/var/log/httpd/access_log',
    ],
    mitre_techniques: [
      'T1190 — Exploit Public-Facing Application',
      'T1505.003 — Web Shell',
    ],
    examiner_notes:
      'Combined log format: host ident user [timestamp] "request" status bytes "referer" "user-agent". Same webshell / SQL injection patterns apply as IIS.',
  },

  'hiberfil.sys': {
    title: 'hiberfil.sys — Windows Hibernation File',
    summary:
      'Compressed snapshot of physical memory written when Windows enters hibernation (S4 sleep). Contains essentially everything that was in RAM at the time of hibernation: processes, network connections, kernel structures, registry hives in memory, and any plaintext data.',
    forensic_value: 'critical',
    artifact_types: [
      'EPROCESS structures (running processes)',
      'TCPIP structures (network connections)',
      'Loaded drivers (KLDR_DATA_TABLE_ENTRY)',
      'In-memory registry hives',
      'Possible plaintext credentials',
    ],
    typical_locations: [
      'C:\\hiberfil.sys',
    ],
    mitre_techniques: [
      'T1003 — OS Credential Dumping',
      'T1055 — Process Injection',
    ],
    examiner_notes:
      'Win8+ uses xpress-huffman compression. Parse with Volatility or specialized hibernation tools. Very large (GB+) so copy first, analyze on a separate workstation.',
  },

  'pagefile.sys': {
    title: 'pagefile.sys — Windows Swap File',
    summary:
      'Windows virtual memory swap file. Contains arbitrary fragments of process memory that were paged out. Can include credentials, command lines, file contents, and encryption keys depending on what happened to be swapped.',
    forensic_value: 'high',
    artifact_types: [
      'Process memory fragments',
      'URL strings',
      'Command-line strings',
      'Credential fragments',
      'File content fragments',
    ],
    typical_locations: [
      'C:\\pagefile.sys',
    ],
    mitre_techniques: [
      'T1003 — OS Credential Dumping',
      'T1555 — Credentials from Password Stores',
    ],
    examiner_notes:
      'Run Strata\'s Wraith plugin to extract printable strings and pattern-match for IOCs. Not structured — treat as a large carved space.',
  },

  // ══════════════════════════════════════════════════════════════════════
  // v1.1.0 — Gap closure additions
  // ══════════════════════════════════════════════════════════════════════

  'srudb.dat': {
    title: 'Windows SRUM Database',
    summary:
      'System Resource Usage Monitor — an ESE database that tracks 30-60 days of per-application execution and network usage. Records bytes sent and received per process per user, application launches, and energy use. Critical for quantifying data exfiltration volume.',
    forensic_value: 'critical',
    artifact_types: [
      'Application execution history (per-app)',
      'Network bytes sent / received (per-process per-user)',
      'Application durations',
      'User attribution (SID)',
      'Energy use estimator',
    ],
    typical_locations: ['C:\\Windows\\System32\\SRU\\SRUDB.dat'],
    mitre_techniques: [
      'T1059 — Command and Scripting Interpreter',
      'T1071 — Application Layer Protocol',
    ],
    examiner_notes:
      'ESE database — full extraction requires libesedb (use srum-dump or SRUMECmd). Strata\'s Trace plugin emits a presence artifact and scrapes UTF-16LE app paths from raw pages. Cross-reference SRUM bytes_sent for known exfil tool processes (rclone.exe, WinSCP.exe) to quantify data egress volume.',
    threat_indicators: [
      'High bytes_sent for an unknown process',
      'Unusual outbound activity outside business hours',
    ],
  },

  'activitiescache.db': {
    title: 'Windows 10 Timeline Database',
    summary:
      'SQLite database recording recently used applications and files with start/end times and total durations. Persists even after the Timeline UI feature was deprecated in late Win10. Captures both desktop apps and Microsoft account-synced activity.',
    forensic_value: 'critical',
    artifact_types: [
      'AppId (executable path or appx package)',
      'StartTime / EndTime (Unix epoch)',
      'Duration in seconds',
      'DisplayText (file or URL opened)',
      'ContentUri',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\Local\\ConnectedDevicesPlatform\\[account-ID]\\ActivitiesCache.db',
    ],
    mitre_techniques: ['T1204 — User Execution'],
    examiner_notes:
      'Parsed by Chronicle plugin via SQLite. Activity table is the primary source. AppId is JSON like {"application":"Microsoft.MicrosoftEdge"} or a plain executable path — parse accordingly.',
  },

  'capabilityaccessmanager': {
    title: 'Windows Capability Access Manager',
    summary:
      'Per-user registry hive (NTUSER.DAT) that records every application that has been granted access to a sensitive capability — microphone, camera (webcam), location, contacts, calendar, etc. Each entry includes LastUsedTimeStart and LastUsedTimeStop FILETIMEs, allowing you to prove an application was using the camera or microphone at a specific moment.',
    forensic_value: 'high',
    artifact_types: [
      'Per-app capability grant (Allow / Deny)',
      'LastUsedTimeStart (FILETIME)',
      'LastUsedTimeStop (FILETIME)',
      'Capability type (microphone / webcam / location / contacts)',
    ],
    typical_locations: [
      'NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\<capability>\\NonPackaged\\<app>',
    ],
    mitre_techniques: [
      'T1123 — Audio Capture',
      'T1125 — Video Capture',
      'T1430 — Location Tracking',
    ],
    examiner_notes:
      'Parsed by Phantom plugin (v1.1.0). App paths in this key use # as separator instead of \\. Apps in Temp/AppData/Downloads accessing camera or microphone are strong covert-surveillance indicators.',
    threat_indicators: [
      'Application from Temp/AppData/Downloads accessing camera or microphone',
      'Capability access by an application without a publisher',
    ],
  },

  'factory_reset': {
    title: 'Android Factory Reset Marker',
    summary:
      'Marker file written by the Android bootstat service when the device performs a factory reset. Its presence is critical evidence that the device has been wiped — a common evidence-destruction tactic.',
    forensic_value: 'critical',
    artifact_types: ['Existence of the marker file'],
    typical_locations: [
      '/misc/bootstat/factory_reset',
      '/data/system/users/0/factory_reset (older Android)',
    ],
    mitre_techniques: ['T1485 — Data Destruction'],
    examiner_notes:
      'Parsed by Specter plugin. If present, ALSO check setup_wizard_info.xml for the most-recent setup date — if setup date is recent on a device that had been in use for a long time, the wipe + reset is confirmed. Look for selective-wipe evidence: app messaging databases that survived the reset.',
    threat_indicators: [
      'factory_reset file present at all is itself critical evidence',
    ],
  },

  'adb_keys': {
    title: 'Android ADB Connection Keys',
    summary:
      'Plaintext file containing the RSA public keys of every computer that has connected to this Android device via ADB (Android Debug Bridge). Each line ends with `user@hostname` revealing the connecting computer\'s identity.',
    forensic_value: 'high',
    artifact_types: [
      'RSA public key per authorized computer',
      'Hostname of connecting machine',
      'Username on connecting machine',
    ],
    typical_locations: ['/misc/adb/adb_keys', '/data/misc/adb/adb_keys'],
    mitre_techniques: ['T1219 — Remote Access Software'],
    examiner_notes:
      'Parsed by Specter plugin. Note: forensic acquisition tools also leave ADB keys, so a single key from a known-forensic-host is expected. Multiple unfamiliar hostnames is the IOC. Cross-reference hostname against known-good employee/forensic infrastructure.',
    threat_indicators: [
      'Multiple unknown hostnames in adb_keys',
      'Hostnames from outside the organization',
    ],
  },

  'wificonfigstore.xml': {
    title: 'Android WiFi Configuration Store',
    summary:
      'XML file containing every WiFi network the Android device has connected to or has saved credentials for. Includes SSID, security type (WPA/WPA2/WPA3/Enterprise), and (in older Android) PSK in cleartext or weakly obfuscated form.',
    forensic_value: 'high',
    artifact_types: [
      'SSID',
      'BSSID (MAC of access point) sometimes',
      'Security type / cipher suite',
      'Hidden network flag',
      'EAP enterprise auth details',
    ],
    typical_locations: [
      '/misc/apexdata/com.android.wifi/WifiConfigStore.xml (Android 11+)',
      '/misc/wifi/WifiConfigStore.xml (Android 10-)',
    ],
    mitre_techniques: ['T1016 — System Network Configuration Discovery'],
    examiner_notes:
      'Parsed by Specter plugin. Cross-reference SSIDs against known locations to establish movement timeline. Enterprise SSIDs link the device to a specific organization.',
  },

  'interactionc.db': {
    title: 'iOS interactionC.db (CoreDuet People)',
    summary:
      'SQLite database maintained by the iOS CoreDuet framework that tracks every contact interaction across all messaging, email, and call apps. Reveals who the user contacts most often regardless of which app they used.',
    forensic_value: 'high',
    artifact_types: [
      'Contact display name and identifier (email/phone)',
      'Interaction count (across all apps)',
      'Last interaction timestamp',
    ],
    typical_locations: [
      '/private/var/mobile/Library/CoreDuet/People/interactionC.db',
    ],
    mitre_techniques: ['T1213 — Data from Information Repositories'],
    examiner_notes:
      'Parsed by Specter plugin. Main table is ZCONTACT. Useful when an examiner needs to identify the most-contacted people independent of any specific messaging app.',
  },

  'recentsearches.db': {
    title: 'OneNote RecentSearches.db',
    summary:
      'SQLite database that records every search term entered in OneNote. Useful in insider-threat investigations for revealing what the user was looking for.',
    forensic_value: 'medium',
    artifact_types: ['Search terms (history)', 'Search timestamps'],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\Local\\Packages\\Microsoft.Office.OneNote_*\\LocalState\\AppData\\Local\\OneNote\\16.0\\RecentSearches\\RecentSearches.db',
    ],
    mitre_techniques: ['T1083 — File and Directory Discovery'],
    examiner_notes:
      'Surfaced by NetFlow plugin (under Productivity category). Open with sqlite3 read-only.',
  },

  'session.xml.notepad++': {
    title: 'Notepad++ session.xml',
    summary:
      'Notepad++ saves a session.xml file listing every recently opened file. Reveals which text files, scripts, configuration files, and credentials the user edited recently. Survives the source files being deleted.',
    forensic_value: 'high',
    artifact_types: [
      'Recently opened files (full paths)',
      'Cursor position per file',
      'Language mode',
    ],
    typical_locations: [
      'C:\\Users\\[user]\\AppData\\Roaming\\Notepad++\\session.xml',
    ],
    mitre_techniques: ['T1083 — File and Directory Discovery', 'T1005 — Data from Local System'],
    examiner_notes:
      'Parsed by Remnant plugin. Plain XML — open directly. Common targets to flag: hosts files, config files, stolen credentials in text, attacker scripts, files containing "password", "credential", "token", "secret", "private".',
    threat_indicators: [
      'Filenames containing password / cred / token / secret',
      'Filenames in Temp / AppData / Downloads',
    ],
  },

  'vmx': {
    title: 'VMware VMX Configuration',
    summary:
      'VMware virtual machine configuration file. Plain-text key=value format. Records the VM display name, every attached virtual disk (.vmdk path), guest OS, hardware configuration, and recent open history.',
    forensic_value: 'high',
    artifact_types: [
      'displayName (VM friendly name)',
      'guestOS (target OS family)',
      '.vmdk disk paths',
      'memSize / numvcpus',
      'sharedFolder configuration',
    ],
    typical_locations: [
      'Anywhere on disk (typically alongside .vmdk files)',
      'C:\\Users\\[user]\\Documents\\Virtual Machines\\',
    ],
    mitre_techniques: ['T1564.006 — Run Virtual Instance'],
    examiner_notes:
      'Parsed by NetFlow plugin. Each .vmdk reference points to a separate filesystem that requires its own forensic acquisition.',
    threat_indicators: [
      'VM hosted from removable / external media',
      'Recent vmware.log entries — VM was actively used during incident window',
    ],
  },

  'sysmon': {
    title: 'Sysmon Operational Log',
    summary:
      'Microsoft Sysinternals Sysmon is an optional system monitor that writes rich security-relevant events to its own Operational event log. When deployed it is the single richest source of endpoint telemetry — process creation with command lines, network connections, image loads, DNS queries, registry modifications, process injection, and more.',
    forensic_value: 'critical',
    artifact_types: [
      'Event 1 — Process creation + full command line',
      'Event 3 — Network connection',
      'Event 7 — Image loaded',
      'Event 8 — CreateRemoteThread (injection)',
      'Event 10 — Process access (e.g. lsass)',
      'Event 11 — File create',
      'Event 13 — Registry value set',
      'Event 22 — DNS query',
    ],
    typical_locations: [
      'Microsoft-Windows-Sysmon%4Operational.evtx',
    ],
    mitre_techniques: [
      'T1055 — Process Injection',
      'T1059 — Command and Scripting Interpreter',
      'T1071 — Application Layer Protocol',
    ],
    examiner_notes:
      'If present, parse this BEFORE the standard Security log — Sysmon will have captured things Security missed (process command lines without audit policy, network connections without firewall logging).',
    threat_indicators: [
      'Event 10 — process access to lsass.exe',
      'Event 8 — CreateRemoteThread (process injection)',
      'Event 22 — DNS query to known-bad domain',
      'Event 1 — parent=winword.exe, child=powershell.exe',
    ],
  },
}

export function lookupKnowledge(
  fileName: string,
  extension: string,
): KnowledgeLookupResult | null {
  const nameLower = (fileName || '').toLowerCase()
  const extLower = (extension || '').toLowerCase().replace('.', '')

  if (nameLower && KNOWLEDGE_BANK[nameLower]) {
    return {
      entry: KNOWLEDGE_BANK[nameLower],
      matchType: 'filename',
      extension: extLower,
    }
  }
  if (extLower && KNOWLEDGE_BANK[extLower]) {
    return {
      entry: KNOWLEDGE_BANK[extLower],
      matchType: 'extension',
      extension: extLower,
    }
  }
  return null
}
