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
      'SQLite database file. Widely used by browsers, mobile applications, messaging apps, and many Windows components to store structured data. May contain browsing history, messages, credentials, or application data depending on the source application.',
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
      'SQLite databases have WAL (Write-Ahead Log) files that may contain recently modified records not yet committed. Check for .db-wal and .db-shm companion files.',
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
}

export function lookupKnowledge(
  fileName: string,
  extension: string,
): KnowledgeEntry | null {
  const nameLower = (fileName || '').toLowerCase()
  const extLower = (extension || '').toLowerCase().replace('.', '')

  if (nameLower && KNOWLEDGE_BANK[nameLower]) {
    return KNOWLEDGE_BANK[nameLower]
  }
  if (extLower && KNOWLEDGE_BANK[extLower]) {
    return KNOWLEDGE_BANK[extLower]
  }
  return null
}
