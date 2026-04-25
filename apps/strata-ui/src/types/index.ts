export type ViewMode =
  | 'files'
  | 'artifacts'
  | 'tags'
  | 'plugins'
  | 'notes'
  | 'settings'

export type LicenseStatus =
  | 'valid'
  | 'trial'
  | 'expired'
  | 'none'

export interface AppState {
  view: ViewMode
  licensed: LicenseStatus
  caseId: string | null
  caseName: string | null
  isDev: boolean
  examinerName: string
  stats: Stats
  selectedFileId: string | null
  selectedPluginId: string | null
  selectedArtifactCat: string | null
  selectedTag: string | null
  activeTheme: string
}

export interface Stats {
  files: number
  suspicious: number
  flagged: number
  carved: number
  hashed: number
  artifacts: number
}

export interface TreeNode {
  id: string
  name: string
  node_type: 'evidence' | 'volume' | 'folder' | 'file' | string
  count: number
  file_count: number
  folder_count: number
  is_deleted: boolean
  is_flagged: boolean
  is_suspicious: boolean
  has_children: boolean
  parent_id: string | null
  depth: number
}

export interface FileEntry {
  id: string
  name: string
  extension: string
  size: number
  size_display: string
  modified: string
  created: string
  sha256: string | null
  is_deleted: boolean
  is_suspicious: boolean
  is_flagged: boolean
  category: string
  tag: string | null
  tag_color: string | null
}

export interface FileMetadata {
  id: string
  name: string
  full_path: string
  size: number
  size_display: string
  modified: string
  created: string
  accessed: string
  sha256: string | null
  md5: string | null
  category: string
  is_deleted: boolean
  is_suspicious: boolean
  is_flagged: boolean
  mft_entry: number | null
  extension: string
  mime_type: string | null
  inode: number | null
  permissions: string | null
}

export interface PluginInfo {
  name: string
  version: string
  plugin_type: string
  short_desc: string
  full_desc: string
  mitre: string[]
  categories: string[]
  changelog: ChangelogEntry[]
  accent_color: string
  status: 'idle' | 'running' | 'complete' | 'error'
  artifact_count: number
  progress: number
  generic_run_disabled?: boolean
}

export interface ChangelogEntry {
  version: string
  changes: string[]
}

export interface ArtifactCategory {
  name: string
  icon: string
  count: number
  color: string
}

export interface Artifact {
  id: string
  category: string
  name: string
  value: string
  timestamp: string | null
  source_file: string
  forensic_value: 'high' | 'medium' | 'low'
  mitre_technique: string | null
}

export interface TagSummary {
  name: string
  color: string
  count: number
}

export const TAG_CATEGORIES: TagSummary[] = [
  { name: 'Critical Evidence', color: '#a84040', count: 0 },
  { name: 'Suspicious',        color: '#b87840', count: 0 },
  { name: 'Needs Review',      color: '#b8a840', count: 0 },
  { name: 'Confirmed Clean',   color: '#487858', count: 0 },
  { name: 'Key Artifact',      color: '#4a7890', count: 0 },
  { name: 'Excluded',          color: '#3a4858', count: 0 },
]

export const PLUGIN_DATA: PluginInfo[] = [
  {
    name: 'Remnant',
    version: 'v2.0.0',
    plugin_type: 'Carver',
    short_desc: 'Deleted evidence — Recycle Bin, USN journal, anti-forensic detection',
    full_desc: 'Remnant recovers what was deleted. It parses Recycle Bin $I files to reconstruct deleted file paths and exact deletion timestamps, reads the NTFS USN change journal to surface every file operation ever recorded on the volume, and identifies the fingerprints of secure deletion tools like SDelete, CCleaner, and Eraser. When evidence has been deliberately destroyed, Remnant finds the proof it existed.',
    mitre: ['T1070.004', 'T1485', 'T1083'],
    categories: ['Deleted Files', 'File System', 'Anti-Forensics'],
    changelog: [
      { version: 'v2.0.0', changes: ['Full $I Recycle Bin binary parse', '$UsnJrnl complete reason flag decode', 'Anti-forensic tool detection added', 'SQLite WAL recovery detection'] },
      { version: 'v1.0.0', changes: ['Initial release'] },
    ],
    accent_color: '#4a9060',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Chronicle',
    version: 'v2.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'User activity timeline — UserAssist, Jump Lists, RecentDocs, TypedPaths',
    full_desc: 'Chronicle rebuilds the complete story of what a user did on a system. It decodes UserAssist registry entries with ROT13 and GUID resolution to reveal every GUI application launched with run counts and timestamps, reconstructs the recent documents list in access order, parses Jump List CFB files to show which files each application opened, and surfaces TypedPaths and WordWheelQuery entries proving what the user searched for.',
    mitre: ['T1204', 'T1547', 'T1083'],
    categories: ['User Activity', 'Application Execution', 'Timeline'],
    changelog: [
      { version: 'v2.0.0', changes: ['UserAssist ROT13+GUID decode', 'RecentDocs binary MRU decode', 'Jump List CFB full parse', 'TypedPaths + WordWheelQuery added'] },
      { version: 'v1.0.0', changes: ['Initial release'] },
    ],
    accent_color: '#c8a040',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Cipher',
    version: 'v2.0.0',
    plugin_type: 'Cipher',
    short_desc: 'Credentials & exfiltration — WiFi, TeamViewer, AnyDesk, FileZilla',
    full_desc: 'Cipher finds credentials and exfiltration evidence. It extracts saved browser credentials, parses WiFi profile XML files for network history, identifies TeamViewer and AnyDesk remote access session logs, recovers FileZilla FTP credentials, and detects DPAPI-encrypted credential stores in the Windows Credential Manager. When data left the building, Cipher proves how and where it went.',
    mitre: ['T1552', 'T1078', 'T1567', 'T1021.001'],
    categories: ['Credentials', 'Remote Access', 'Exfiltration'],
    changelog: [
      { version: 'v2.0.0', changes: ['WiFi XML full profile parse', 'TeamViewer session log parsing', 'AnyDesk connection trace parse', 'FileZilla FTP credential extraction'] },
      { version: 'v1.0.0', changes: ['Initial release'] },
    ],
    accent_color: '#c05050',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Trace',
    version: 'v2.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Execution & persistence — BAM/DAM, scheduled tasks, BITS, timestomp',
    full_desc: 'Trace answers what ran and what persists. It parses the Windows Background Activity Monitor for precise execution timestamps on Win10+, decodes scheduled task XML files for hidden persistence mechanisms, detects BITS job abuse for stealthy downloads, and identifies timestamp manipulation by comparing NTFS $SI versus $FN attributes. When malware tries to hide, Trace finds it.',
    mitre: ['T1053', 'T1547', 'T1070.006', 'T1197'],
    categories: ['Execution History', 'Persistence', 'Anti-Forensics'],
    changelog: [
      { version: 'v2.0.0', changes: ['BAM/DAM registry full parse', 'Scheduled Tasks XML decode', 'BITS job database detection', '$SI vs $FN timestomp detection'] },
      { version: 'v1.0.0', changes: ['Initial release'] },
    ],
    accent_color: '#4a70c0',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Specter',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Mobile artifacts — iOS KnowledgeC, WhatsApp, Signal, Telegram, Discord',
    full_desc: 'Specter reaches into mobile evidence. It queries the iOS KnowledgeC database for precise application usage timelines, parses DataUsage records for per-app network activity, and extracts message data from WhatsApp, Signal, Telegram, Snapchat, Instagram, and Discord on both iOS and Android. When the evidence is on a phone, Specter finds it.',
    mitre: ['T1636', 'T1430', 'T1409'],
    categories: ['Mobile Devices', 'Social Media', 'Communications'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release'] }],
    accent_color: '#8050c0',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Conduit',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Network history — WiFi profiles, RDP, VPN, hosts file, shares',
    full_desc: 'Conduit maps every network connection a system made. It reconstructs the complete WiFi and wired network connection history, extracts Remote Desktop connection history including username hints, flags non-standard hosts file entries indicating DNS manipulation, and surfaces mounted network share history.',
    mitre: ['T1021.001', 'T1071', 'T1090', 'T1018'],
    categories: ['Network History', 'Remote Access', 'DNS'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release'] }],
    accent_color: '#40a0a0',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Nimbus',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Cloud & comms — OneDrive, Dropbox, Teams, Slack, Zoom',
    full_desc: 'Nimbus uncovers cloud evidence. It parses OneDrive synchronization logs, examines Google DriveFS and Dropbox activity databases, and detects Microsoft Teams, Slack, and Zoom usage through their local application artifacts and log files. For enterprise investigations, Nimbus surfaces evidence that traditional disk forensics misses entirely.',
    mitre: ['T1567', 'T1213', 'T1530'],
    categories: ['Cloud Storage', 'Enterprise Comms', 'Collaboration'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release'] }],
    accent_color: '#6090d0',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Wraith',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Memory artifacts — hiberfil.sys, crash dumps, pagefile strings',
    full_desc: 'Wraith examines the ghosts of running processes. It profiles hibernation files that contain compressed RAM snapshots potentially capturing encryption keys and running processes, identifies crash dump files with process memory snapshots, and extracts IOC strings including URLs, IPs, and malware signatures from page files and dump files.',
    mitre: ['T1005', 'T1212', 'T1083'],
    categories: ['Memory Artifacts', 'Volatile Evidence'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release'] }],
    accent_color: '#8090a0',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Vector',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Static malware analysis — PE headers, macros, IOCs, known tools',
    full_desc: 'Vector answers whether a file is malicious. It analyzes PE executable headers for anomalous compile timestamps and suspicious import combinations, detects VBA macros in Office documents, identifies obfuscated PowerShell, and matches against known malware signatures including Mimikatz, Meterpreter, Cobalt Strike, and BloodHound. Vector gives you answers before you execute anything.',
    mitre: ['T1059', 'T1027', 'T1055', 'T1566.001'],
    categories: ['Malware Detection', 'Static Analysis', 'IOCs'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release'] }],
    accent_color: '#c07040',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Recon',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Identity extraction — usernames, emails, IPs, API keys. Fully offline.',
    full_desc: 'Recon connects artifacts to real people. It harvests system usernames from SAM and event logs, extracts email addresses while flagging anonymization-suggesting domains, identifies public IPs in scripts suggesting C2 infrastructure, and detects cloud API credentials including AWS access keys. All analysis is completely offline. No network connections are made.',
    mitre: ['T1087', 'T1589', 'T1552.001'],
    categories: ['Identity', 'Account Artifacts', 'Credentials'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release'] }],
    accent_color: '#a0a040',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Phantom',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Registry Intelligence Engine — SYSTEM, SOFTWARE, SAM, AmCache, USRCLASS',
    full_desc: 'Phantom owns registry hive parsing. It decodes ShimCache / AppCompatCache for evidence of every file the OS ever considered executing, walks USBSTOR + Enum\\USB + MountedDevices to reconstruct the complete USB device history with first-install, last-connect, and last-removal timestamps, enumerates every service with ImagePath + start type + run-as account to flag non-standard persistence, extracts SHA1 hashes from AmCache.hve InventoryApplicationFile as the gold-standard execution-evidence artifact, surfaces unsigned drivers from InventoryDriverBinary, and reconstructs the hostname, timezone, last shutdown time, network adapter history, installed programs, Microsoft cloud account identities, HKLM AutoRun keys, MuiCache display names, UserChoice default handlers, and USRCLASS shellbags. Phantom is the single biggest coverage win in the v0.6.0 plugin fleet.',
    mitre: ['T1059', 'T1543.003', 'T1547.001', 'T1052.001', 'T1200', 'T1078.003', 'T1546.001'],
    categories: ['Registry Intelligence', 'Execution Evidence', 'Device History', 'Persistence'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release — SYSTEM/SOFTWARE/SAM/SECURITY/AmCache/USRCLASS parsers'] }],
    accent_color: '#d946ef',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Guardian',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Antivirus + System Health — Defender, Avast, MalwareBytes, WER',
    full_desc: 'Guardian proves malware was present even after it has been cleaned up. It surfaces Windows Defender MpEventLog.evtx detection events and quarantined items, parses Avast / MalwareBytes log files for threat-detection records, examines Windows Error Reporting (WER) .wer files for application crashes flagging crashes in Temp or AppData paths, and wires into the Reliability Monitor database for system-health timeline. When an incident cleanup attempt wiped the malware but missed the AV log, Guardian finds the smoking gun.',
    mitre: ['T1562.001', 'T1027', 'T1036', 'T1070.004'],
    categories: ['Antivirus', 'System Health', 'Crash Analysis'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release — Defender log + quarantine, WER parsing, Avast/MBAM detection'] }],
    accent_color: '#06b6d4',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'NetFlow',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Network forensics — PCAP, IIS/Apache logs, WLAN, exfil tools',
    full_desc: 'NetFlow owns FOR572-style network-forensic artifacts plus the top exfil tool signatures. It validates PCAP / PCAPNG magic bytes, scans IIS W3C logs and Apache / Nginx access logs for webshell patterns (cmd=, exec=, c99shell, wso.php), SQL-injection patterns (UNION SELECT, OR 1=1, sqlmap), scanner user-agents (nikto, nmap, masscan), and directory-traversal attempts (..%2f, ..\\..\\), parses WLAN profile XML for SSID + auth type, decodes rclone.conf into per-remote exfil destinations with type (s3, gdrive, dropbox, sftp), surfaces WinSCP.ini and MEGAsync.cfg presence as exfil IOCs, scrapes Power Efficiency Diagnostics HTML reports for long-running rclone / WinSCP / MEGAsync sessions, and flags P2P client artifacts. NetFlow is the plugin that connects "data left the building" to "how it left".',
    mitre: ['T1071', 'T1190', 'T1505.003', 'T1537', 'T1048', 'T1219', 'T1567'],
    categories: ['Network Forensics', 'Exfiltration', 'Web Attacks'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release — PCAP detection, IIS/Apache attack-pattern scanner, WLAN profiles, WinSCP/Rclone/MEGAsync signatures, remote-access tool detection'] }],
    accent_color: '#10b981',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'MacTrace',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'macOS + iOS artifacts — LaunchAgents, KnowledgeC, PowerLog, SMS, WhatsApp',
    full_desc: 'MacTrace owns the FOR518 (macOS/APFS) and FOR585 (iOS) artifact landscape. It parses LaunchAgents / LaunchDaemons for macOS persistence, opens KnowledgeC.db as SQLite to count ZOBJECT activity rows, reads iOS PowerLog (CurrentPowerlog.PLSQL) for app foreground events, surfaces locationd clients.plist authorization history, opens sms.db / chat.db / CallHistory.storedata / AddressBook.sqlitedb for message + call + contact counts, detects macOS Unified Log tracev3 bundles, parses Recent Items + LoginItems + SharedFileList (sfl2/sfl3), and decodes WhatsApp (iOS ChatStorage.sqlite + Android msgstore.db), Signal, and Telegram local databases. When the evidence is on an Apple device or iPhone, MacTrace finds it.',
    mitre: ['T1543.001', 'T1543.004', 'T1005', 'T1430', 'T1213', 'T1547'],
    categories: ['macOS', 'iOS', 'Mobile Communications'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release — LaunchAgents, KnowledgeC, PowerLog, locationd, SMS, CallHistory, Signal, WhatsApp, Telegram, Safari history'] }],
    accent_color: '#f472b6',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  // Sprint 8 P1 F2 additions — the 8 plugins that ship in the backend
  // registry (`strata_engine_adapter::plugins::build_plugins`) but were
  // missing from this array, so their artifacts never rolled up into
  // the UI's stats banner and their cards never appeared in the
  // Plugins view. Short names match the "Strata "-prefix-stripped
  // names emitted by `run_all_plugins`.
  {
    name: 'Sentinel',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Windows Event Logs — per-event extraction from EVTX channels',
    full_desc: 'Sentinel parses Windows Event Logs (*.evtx) across Security, System, PowerShell, and Sysmon channels, with typed extractors for the forensic-critical event IDs: 4624 / 4625 (logon success/failure), 4688 (process creation), 4698/4702 (scheduled task create/update), 7045 (service install), 4103/4104 (PowerShell script block + module logging), and 1102 (audit log cleared).',
    mitre: ['T1078', 'T1059.001', 'T1543.003', 'T1053.005', 'T1070.001'],
    categories: ['Windows Event Logs', 'Authentication', 'Execution'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release — EVTX parsing across Security/System/PowerShell/Sysmon'] }],
    accent_color: '#5090c0',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'CSAM Scanner',
    version: 'v0.1.0',
    plugin_type: 'Analyzer',
    short_desc: 'CSAM detection — hash + perceptual matching with audit log',
    full_desc: 'The CSAM Scanner surfaces as an informational artifact pointing at the dedicated CSAM IPC commands. The real workflow — NCMEC / Project VIC hash-set import, hash + dHash perceptual scan, examiner review / confirm / dismiss, immutable audit log, and report generation — lives behind those commands rather than the generic run_plugin path. Available on every license tier.',
    mitre: ['T1005'],
    categories: ['CSAM'],
    changelog: [{ version: 'v0.1.0', changes: ['Initial registration alongside strata-csam engine'] }],
    accent_color: '#802040',
    status: 'idle', artifact_count: 0, progress: 0,
    generic_run_disabled: true,
  },
  {
    name: 'Apex',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Apple-built apps — Mail, Calendar, Contacts, Maps, Siri, FaceTime',
    full_desc: 'Apex covers the first-party Apple application surface: Mail.app, Calendar.app, Contacts.app, Maps, Siri, iCloud Drive internals, Apple Notes (native), and FaceTime call logs. Distinct from MacTrace (system-layer) and Pulse (third-party apps), Apex owns the artifacts produced by the applications Apple itself ships.',
    mitre: ['T1005', 'T1213'],
    categories: ['macOS', 'iOS', 'Apple Apps'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release'] }],
    accent_color: '#a0a0a0',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Carbon',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Google-built apps — Chrome, Gmail, Drive, Maps, Photos',
    full_desc: 'Carbon covers Google-built application artifacts across desktop and mobile: Chrome (desktop browser), Gmail, Google Drive, Google Maps, Google Photos, plus Android system apps built by Google. Distinct from Pulse (third-party) — Carbon owns what Google itself ships.',
    mitre: ['T1005', 'T1217', 'T1213'],
    categories: ['Web Activity', 'Android', 'Google Apps'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release'] }],
    accent_color: '#4080c0',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Pulse',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Third-party user apps — WhatsApp, Signal, Telegram, Snapchat, Instagram',
    full_desc: 'Pulse covers the third-party user-installed application landscape on iOS and Android: WhatsApp, Signal, Telegram, Snapchat, Instagram, TikTok, Facebook, and third-party browsers. One of the densest plugins in Strata — this is where Apex and Carbon end and the rest of the mobile app ecosystem begins.',
    mitre: ['T1005', 'T1430', 'T1213'],
    categories: ['Communications', 'Social Media', 'Mobile Apps'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release — full third-party mobile app coverage'] }],
    accent_color: '#b040b0',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Vault',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Credentials vault — encrypted stores, hidden partitions, wallets',
    full_desc: 'Vault discovers credential-protected artifact stores: VeraCrypt containers, hidden partitions, photo vault apps, crypto wallets, and Android anti-forensic artifacts. Complements Cipher (which extracts credentials themselves) by locating the containers those credentials unlock.',
    mitre: ['T1552', 'T1027', 'T1070'],
    categories: ['Credentials', 'Encryption', 'Anti-Forensics'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release — VeraCrypt, photo vaults, crypto wallets, hidden partitions'] }],
    accent_color: '#805040',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'ARBOR',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Linux / ChromeOS — systemd, crontab, shell history, containers',
    full_desc: 'ARBOR covers Linux and ChromeOS system artifacts: systemd persistence units, crontab scheduling, shell history artifacts, container / repo discovery, ChromeOS user data, and /var/log archives. The Linux counterpart to Phantom + Trace on the Windows side.',
    mitre: ['T1543.002', 'T1053.003', 'T1059.004'],
    categories: ['Linux', 'ChromeOS', 'Persistence'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release'] }],
    accent_color: '#50a050',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Advisory Analytics',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'ML advisory layer — anomaly, obstruction, summary, charges',
    full_desc: 'Advisory Analytics wraps the four strata-ml-* ML modules (anomaly, obstruction scoring, plain-English summary, charge categorization) and emits them as advisory artifacts with is_advisory = true and an ADVISORY_NOTICE banner so examiners can distinguish ML-derived findings from deterministic forensic parses. Runs after forensic plugins and before Sigma so Sigma rules 30/31/32 can reference its outputs.',
    mitre: ['T1005'],
    categories: ['ML Advisory', 'Anomaly Detection', 'Summary'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release — wraps strata-ml-anomaly / charges / obstruction / summary'] }],
    accent_color: '#708090',
    status: 'idle', artifact_count: 0, progress: 0,
  },
  {
    name: 'Sigma',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Threat correlation — MITRE ATT&CK mapping, kill chain, scoring',
    full_desc: 'Sigma runs last because it needs everything. It reads every artifact produced by all preceding plugins, maps findings to MITRE ATT&CK, builds a kill chain coverage map, detects known attack sequences including credential dumping, ransomware indicators, lateral movement chains, USB exfiltration sequences, archive-then-upload patterns, AV evasion + file deletion pairs, and new-account + persistence combinations. It assigns confidence scores based on corroborating evidence sources and produces a complete threat assessment.',
    mitre: ['Cross-tactic correlation'],
    categories: ['Threat Intelligence', 'Kill Chain', 'ATT&CK'],
    changelog: [
      { version: 'v1.0.0', changes: ['USB Exfil Sequence, Archive+Upload, AV Evasion, New Account + Persistence, Shimcache Ghost correlation rules added'] },
    ],
    accent_color: '#c04080',
    status: 'idle', artifact_count: 0, progress: 0,
  },
]
