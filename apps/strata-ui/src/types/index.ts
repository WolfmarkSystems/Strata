export type ViewMode =
  | 'files'
  | 'artifacts'
  | 'tags'
  | 'plugins'
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
    name: 'Sigma',
    version: 'v1.0.0',
    plugin_type: 'Analyzer',
    short_desc: 'Threat correlation — MITRE ATT&CK mapping, kill chain, scoring',
    full_desc: 'Sigma runs last because it needs everything. It reads every artifact produced by all ten preceding plugins, maps findings to MITRE ATT&CK, builds a kill chain coverage map, detects known attack sequences including credential dumping, ransomware indicators, and lateral movement chains. It assigns confidence scores based on corroborating evidence sources and produces a complete threat assessment.',
    mitre: ['Cross-tactic correlation'],
    categories: ['Threat Intelligence', 'Kill Chain', 'ATT&CK'],
    changelog: [{ version: 'v1.0.0', changes: ['Initial release'] }],
    accent_color: '#c04080',
    status: 'idle', artifact_count: 0, progress: 0,
  },
]
