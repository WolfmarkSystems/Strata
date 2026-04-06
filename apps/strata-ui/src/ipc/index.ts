import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import type { TreeNode, FileEntry, FileMetadata } from '../types'

// Browser preview detection — Tauri injects __TAURI_INTERNALS__ at runtime
const IN_TAURI = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window

export interface EvidenceLoadResult {
  success: boolean
  evidence_id: string
  name: string
  size_display: string
  file_count: number
  error?: string
}

export interface StatsResult {
  files: number
  suspicious: number
  flagged: number
  carved: number
  hashed: number
  artifacts: number
}

export interface HexLine {
  offset: string
  hex: string
  ascii: string
}

export interface HexData {
  lines: HexLine[]
  total_size: number
  offset: number
}

export interface TagSummary {
  name: string
  color: string
  count: number
}

export interface TaggedFile {
  file_id: string
  name: string
  extension: string
  size_display: string
  modified: string
  full_path: string
  tag: string
  tag_color: string
  tagged_at: string
  note: string | null
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
  source_path: string
  forensic_value: 'high' | 'medium' | 'low'
  mitre_technique: string | null
  mitre_name: string | null
  plugin: string
  raw_data: string | null
}

export interface PluginStatus {
  name: string
  status: 'idle' | 'running' | 'complete' | 'error'
  progress: number
  artifact_count: number
}

export interface PluginRunResult {
  plugin_name: string
  success: boolean
  artifact_count: number
  duration_ms: number
  error?: string
}

export interface PluginProgressEvent {
  name: string
  progress: number
  status: 'idle' | 'running' | 'complete' | 'error'
  artifact_count?: number
}

export interface SearchResult {
  id: string
  name: string
  full_path: string
  extension: string
  size_display: string
  modified: string
  is_deleted: boolean
  is_flagged: boolean
  is_suspicious: boolean
  match_field: string
  match_value: string
}

export async function getAppVersion(): Promise<string> {
  try {
    return await invoke('get_app_version')
  } catch {
    return '0.3.0'
  }
}

export async function checkLicense(): Promise<{ status: string; days: number }> {
  try {
    return await invoke('check_license')
  } catch {
    return { status: 'dev', days: 999 }
  }
}

export async function getExaminerProfile(): Promise<{
  name: string
  agency: string
  badge: string
}> {
  try {
    return await invoke('get_examiner_profile')
  } catch {
    return {
      name: 'Dev Examiner',
      agency: 'Wolfmark Systems',
      badge: 'DEV-001',
    }
  }
}

export async function openEvidenceDialog(): Promise<string | null> {
  if (!IN_TAURI) return '/mock/evidence/jo-2009-11-16.E01'
  try {
    return await invoke('open_evidence_dialog')
  } catch {
    return null
  }
}

export async function loadEvidence(path: string): Promise<EvidenceLoadResult> {
  if (!IN_TAURI) {
    return {
      success: true,
      evidence_id: 'ev-001',
      name: path.split('/').pop() ?? path,
      size_display: '9.8 GB',
      file_count: 26235,
    }
  }
  try {
    return await invoke('load_evidence', { path })
  } catch (e) {
    return {
      success: false,
      evidence_id: '',
      name: '',
      size_display: '',
      file_count: 0,
      error: String(e),
    }
  }
}

export async function getTreeRoot(evidenceId: string): Promise<TreeNode[]> {
  if (!IN_TAURI) return MOCK_TREE_ROOT
  try {
    return await invoke('get_tree_root', { evidenceId })
  } catch {
    return []
  }
}

export async function getTreeChildren(nodeId: string): Promise<TreeNode[]> {
  if (!IN_TAURI) return MOCK_TREE_CHILDREN[nodeId] ?? []
  try {
    return await invoke('get_tree_children', { nodeId })
  } catch {
    return []
  }
}

export async function getFiles(
  nodeId: string,
  filter?: string,
  sortCol?: string,
  sortAsc?: boolean,
): Promise<FileEntry[]> {
  if (!IN_TAURI) return MOCK_FILES
  try {
    return await invoke('get_files', { nodeId, filter, sortCol, sortAsc })
  } catch {
    return []
  }
}

export async function getFileMetadata(fileId: string): Promise<FileMetadata | null> {
  if (!IN_TAURI) return MOCK_METADATA[fileId] ?? mockDefaultMeta(fileId)
  try {
    return await invoke('get_file_metadata', { fileId })
  } catch {
    return null
  }
}

export async function getFileHex(
  fileId: string,
  offset: number = 0,
  length: number = 512,
): Promise<HexData> {
  if (!IN_TAURI) return mockHexData(offset)
  try {
    return await invoke('get_file_hex', { fileId, offset, length })
  } catch {
    return { lines: [], total_size: 0, offset: 0 }
  }
}

export async function getFileText(fileId: string, offset: number = 0): Promise<string> {
  if (!IN_TAURI) return mockTextContent(fileId)
  try {
    return await invoke('get_file_text', { fileId, offset })
  } catch {
    return '[Error loading text content]'
  }
}

export async function searchFiles(
  query: string,
  evidenceId: string,
): Promise<SearchResult[]> {
  if (!IN_TAURI) return mockSearch(query)
  try {
    return await invoke('search_files', { query, evidenceId })
  } catch {
    return []
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tag commands
// ──────────────────────────────────────────────────────────────────────────────

const TAG_DEFS: Array<[string, string]> = [
  ['Critical Evidence', '#a84040'],
  ['Suspicious',        '#b87840'],
  ['Needs Review',      '#b8a840'],
  ['Confirmed Clean',   '#487858'],
  ['Key Artifact',      '#4a7890'],
  ['Excluded',          '#3a4858'],
]

// Mock in-memory tag store (browser preview mode)
const mockTagStore = new Map<string, TaggedFile>([
  ['f004', {
    file_id: 'f004', name: 'mimikatz.exe', extension: 'exe',
    size_display: '1.2 MB', modified: '2009-11-15 14:33',
    full_path: '\\Windows\\Temp\\mimikatz.exe',
    tag: 'Critical Evidence', tag_color: '#a84040',
    tagged_at: '2009-11-16 09:00',
    note: 'Known credential dumping tool',
  }],
  ['f003', {
    file_id: 'f003', name: 'svchost32.exe', extension: 'exe',
    size_display: '892 KB', modified: '2009-11-15 14:32',
    full_path: '\\Windows\\System32\\svchost32.exe',
    tag: 'Suspicious', tag_color: '#b87840',
    tagged_at: '2009-11-16 09:01',
    note: null,
  }],
  ['f010', {
    file_id: 'f010', name: 'cleanup.ps1', extension: 'ps1',
    size_display: '4.8 KB', modified: '2009-11-15 14:31',
    full_path: '\\Windows\\Temp\\cleanup.ps1',
    tag: 'Suspicious', tag_color: '#b87840',
    tagged_at: '2009-11-16 09:02',
    note: 'Anti-forensic script',
  }],
  ['f005', {
    file_id: 'f005', name: 'Security.evtx', extension: 'evtx',
    size_display: '44 MB', modified: '2009-11-16 03:44',
    full_path: '\\Windows\\System32\\winevt\\Logs\\Security.evtx',
    tag: 'Key Artifact', tag_color: '#4a7890',
    tagged_at: '2009-11-16 09:03',
    note: null,
  }],
])

export async function getTagSummaries(): Promise<TagSummary[]> {
  if (!IN_TAURI) {
    return TAG_DEFS.map(([name, color]) => ({
      name,
      color,
      count: Array.from(mockTagStore.values()).filter((f) => f.tag === name).length,
    }))
  }
  try {
    return await invoke('get_tag_summaries')
  } catch {
    return TAG_DEFS.map(([name, color]) => ({ name, color, count: 0 }))
  }
}

export async function getTaggedFiles(tag: string): Promise<TaggedFile[]> {
  if (!IN_TAURI) {
    return Array.from(mockTagStore.values()).filter((f) => f.tag === tag)
  }
  try {
    return await invoke('get_tagged_files', { tag })
  } catch {
    return []
  }
}

export async function tagFile(
  fileId: string,
  fileName: string,
  extension: string,
  sizeDisplay: string,
  modified: string,
  fullPath: string,
  tag: string,
  tagColor: string,
  note?: string,
): Promise<void> {
  if (!IN_TAURI) {
    mockTagStore.set(fileId, {
      file_id: fileId,
      name: fileName,
      extension,
      size_display: sizeDisplay,
      modified,
      full_path: fullPath,
      tag,
      tag_color: tagColor,
      tagged_at: new Date().toISOString().slice(0, 16).replace('T', ' '),
      note: note ?? null,
    })
    return
  }
  try {
    await invoke('tag_file', {
      fileId, fileName, extension, sizeDisplay, modified, fullPath, tag, tagColor, note,
    })
  } catch (e) {
    console.error('Tag failed:', e)
  }
}

export async function untagFile(fileId: string): Promise<void> {
  if (!IN_TAURI) {
    mockTagStore.delete(fileId)
    return
  }
  try {
    await invoke('untag_file', { fileId })
  } catch (e) {
    console.error('Untag failed:', e)
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Artifact commands
// ──────────────────────────────────────────────────────────────────────────────

export async function getArtifactCategories(
  evidenceId: string,
): Promise<ArtifactCategory[]> {
  if (!IN_TAURI) return MOCK_ARTIFACT_CATEGORIES
  try {
    return await invoke('get_artifact_categories', { evidenceId })
  } catch {
    return []
  }
}

export async function getArtifacts(
  evidenceId: string,
  category: string,
): Promise<Artifact[]> {
  if (!IN_TAURI) return MOCK_ARTIFACTS[category] ?? []
  try {
    return await invoke('get_artifacts', { evidenceId, category })
  } catch {
    return []
  }
}

const MOCK_ARTIFACT_CATEGORIES: ArtifactCategory[] = [
  { name: 'User Activity',       icon: '\u{1F464}', count: 183, color: '#c8a040' },
  { name: 'Execution History',   icon: '\u{25B6}',  count: 89,  color: '#4a70c0' },
  { name: 'Deleted & Recovered', icon: '\u{1F5D1}', count: 47,  color: '#4a9060' },
  { name: 'Network Artifacts',   icon: '\u{1F517}', count: 34,  color: '#40a0a0' },
  { name: 'Identity & Accounts', icon: '\u{1FAAA}', count: 23,  color: '#a0a040' },
  { name: 'Credentials',         icon: '\u{1F511}', count: 12,  color: '#c05050' },
  { name: 'Malware Indicators',  icon: '\u{1F6E1}', count: 8,   color: '#c07040' },
  { name: 'Cloud & Sync',        icon: '\u{2601}',  count: 5,   color: '#6090d0' },
  { name: 'Memory Artifacts',    icon: '\u{1F4BE}', count: 2,   color: '#8090a0' },
  { name: 'Communications',      icon: '\u{1F4AC}', count: 0,   color: '#8050c0' },
  { name: 'Social Media',        icon: '\u{1F4F1}', count: 0,   color: '#8050c0' },
  { name: 'Web Activity',        icon: '\u{1F310}', count: 0,   color: '#4a7890' },
]

const MOCK_ARTIFACTS: Record<string, Artifact[]> = {
  'User Activity': [
    { id: 'a001', category: 'User Activity', name: 'UserAssist: cmd.exe', value: '23 executions', timestamp: '2009-11-15 14:33:01', source_file: 'NTUSER.DAT', source_path: '\\Documents and Settings\\Administrator\\ntuser.dat', forensic_value: 'high', mitre_technique: 'T1204', mitre_name: 'User Execution', plugin: 'Chronicle', raw_data: 'UEME_RUNPATH:C:\\Windows\\System32\\cmd.exe' },
    { id: 'a002', category: 'User Activity', name: 'UserAssist: mimikatz.exe', value: '3 executions', timestamp: '2009-11-15 14:33:05', source_file: 'NTUSER.DAT', source_path: '\\Documents and Settings\\Administrator\\ntuser.dat', forensic_value: 'high', mitre_technique: 'T1003', mitre_name: 'OS Credential Dumping', plugin: 'Chronicle', raw_data: 'UEME_RUNPATH:C:\\Windows\\Temp\\mimikatz.exe' },
    { id: 'a003', category: 'User Activity', name: 'RecentDocs: evidence_backup.zip', value: 'Last accessed', timestamp: '2009-11-14 22:10:44', source_file: 'NTUSER.DAT', source_path: '\\Documents and Settings\\Administrator\\ntuser.dat', forensic_value: 'medium', mitre_technique: 'T1083', mitre_name: 'File and Directory Discovery', plugin: 'Chronicle', raw_data: null },
    { id: 'a004', category: 'User Activity', name: 'TypedPath: C:\\Windows\\Temp', value: 'Explorer address bar entry', timestamp: '2009-11-15 14:30:12', source_file: 'NTUSER.DAT', source_path: '\\Documents and Settings\\Administrator\\ntuser.dat', forensic_value: 'medium', mitre_technique: 'T1083', mitre_name: 'File and Directory Discovery', plugin: 'Chronicle', raw_data: null },
    { id: 'a005', category: 'User Activity', name: 'WordWheelQuery: lsass', value: 'Start menu search term', timestamp: '2009-11-15 14:28:33', source_file: 'NTUSER.DAT', source_path: '\\Documents and Settings\\Administrator\\ntuser.dat', forensic_value: 'high', mitre_technique: 'T1057', mitre_name: 'Process Discovery', plugin: 'Chronicle', raw_data: null },
  ],
  'Execution History': [
    { id: 'b001', category: 'Execution History', name: 'BAM: mimikatz.exe', value: 'Last executed', timestamp: '2009-11-15 14:33:02', source_file: 'SYSTEM', source_path: '\\Windows\\System32\\config\\SYSTEM', forensic_value: 'high', mitre_technique: 'T1003', mitre_name: 'OS Credential Dumping', plugin: 'Trace', raw_data: 'Path: C:\\Windows\\Temp\\mimikatz.exe\nSequenceNumber: 0x0000047A' },
    { id: 'b002', category: 'Execution History', name: 'BAM: cleanup.ps1', value: 'Last executed', timestamp: '2009-11-15 14:31:00', source_file: 'SYSTEM', source_path: '\\Windows\\System32\\config\\SYSTEM', forensic_value: 'high', mitre_technique: 'T1059.001', mitre_name: 'PowerShell', plugin: 'Trace', raw_data: 'Path: C:\\Windows\\Temp\\cleanup.ps1' },
    { id: 'b003', category: 'Execution History', name: 'Scheduled Task: WindowsUpdate', value: 'Persistence mechanism', timestamp: '2009-11-14 03:00:00', source_file: 'WindowsUpdate.xml', source_path: '\\Windows\\System32\\Tasks\\WindowsUpdate', forensic_value: 'high', mitre_technique: 'T1053.005', mitre_name: 'Scheduled Task', plugin: 'Trace', raw_data: '<Command>C:\\Windows\\Temp\\svchost32.exe</Command>' },
    { id: 'b004', category: 'Execution History', name: 'Prefetch: MIMIKATZ.EXE-ABC123.pf', value: '3 runs', timestamp: '2009-11-15 14:33:05', source_file: 'MIMIKATZ.EXE-ABC123.pf', source_path: '\\Windows\\Prefetch\\MIMIKATZ.EXE-ABC123.pf', forensic_value: 'high', mitre_technique: 'T1003', mitre_name: 'OS Credential Dumping', plugin: 'Trace', raw_data: null },
  ],
  'Deleted & Recovered': [
    { id: 'c001', category: 'Deleted & Recovered', name: 'Recycle Bin: lsass.dmp', value: 'Deleted credential dump', timestamp: '2009-11-15 14:45:00', source_file: '$I001234.dat', source_path: '\\RECYCLER\\S-1-5-21-XXX\\$I001234.dat', forensic_value: 'high', mitre_technique: 'T1003.001', mitre_name: 'LSASS Memory', plugin: 'Remnant', raw_data: 'Original path: C:\\Windows\\Temp\\lsass.dmp\nOriginal size: 44,040,192 bytes' },
    { id: 'c002', category: 'Deleted & Recovered', name: 'USN Journal: mimikatz.exe created', value: 'File system operation', timestamp: '2009-11-15 14:32:58', source_file: '$UsnJrnl', source_path: '\\$Extend\\$UsnJrnl', forensic_value: 'high', mitre_technique: 'T1070.004', mitre_name: 'File Deletion', plugin: 'Remnant', raw_data: 'USN: 0x000000001A4F8800\nReason: FILE_CREATE | CLOSE\nFileName: mimikatz.exe' },
    { id: 'c003', category: 'Deleted & Recovered', name: 'USN Journal: lsass.dmp deleted', value: 'File deletion event', timestamp: '2009-11-15 14:44:55', source_file: '$UsnJrnl', source_path: '\\$Extend\\$UsnJrnl', forensic_value: 'high', mitre_technique: 'T1070.004', mitre_name: 'File Deletion', plugin: 'Remnant', raw_data: 'USN: 0x000000001A512400\nReason: FILE_DELETE | CLOSE\nFileName: lsass.dmp' },
  ],
  'Credentials': [
    { id: 'd001', category: 'Credentials', name: 'WiFi Profile: CorpNetwork', value: 'WPA2-Enterprise saved credential', timestamp: null, source_file: 'CorpNetwork.xml', source_path: '\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\', forensic_value: 'high', mitre_technique: 'T1552.001', mitre_name: 'Credentials in Files', plugin: 'Cipher', raw_data: '<SSID>CorpNetwork</SSID>\n<keyMaterial>[ENCRYPTED]</keyMaterial>' },
    { id: 'd002', category: 'Credentials', name: 'WiFi Profile: HomeNetwork_5G', value: 'WPA2-Personal saved credential', timestamp: null, source_file: 'HomeNetwork_5G.xml', source_path: '\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\', forensic_value: 'medium', mitre_technique: 'T1552.001', mitre_name: 'Credentials in Files', plugin: 'Cipher', raw_data: null },
  ],
  'Malware Indicators': [
    { id: 'e001', category: 'Malware Indicators', name: 'Known Tool: mimikatz.exe', value: 'Credential dumping tool', timestamp: '2009-11-15 14:33:02', source_file: 'mimikatz.exe', source_path: '\\Windows\\Temp\\mimikatz.exe', forensic_value: 'high', mitre_technique: 'T1003', mitre_name: 'OS Credential Dumping', plugin: 'Vector', raw_data: 'PE signature match: Mimikatz v2.x\nImports: LsaOpenPolicy, SamConnect\nMD5: [not computed]' },
    { id: 'e002', category: 'Malware Indicators', name: 'Anti-forensic: Event log cleared', value: 'Evidence destruction', timestamp: '2009-11-15 14:31:05', source_file: 'cleanup.ps1', source_path: '\\Windows\\Temp\\cleanup.ps1', forensic_value: 'high', mitre_technique: 'T1070.001', mitre_name: 'Clear Windows Event Logs', plugin: 'Vector', raw_data: 'Content: wevtutil cl Security\nContent: wevtutil cl System\nContent: vssadmin delete shadows' },
  ],
  'Network Artifacts': [
    { id: 'f001', category: 'Network Artifacts', name: 'RDP Connection: 192.168.1.50', value: 'Remote Desktop target', timestamp: '2009-11-15 13:45:00', source_file: 'NTUSER.DAT', source_path: '\\Documents and Settings\\Administrator\\ntuser.dat', forensic_value: 'high', mitre_technique: 'T1021.001', mitre_name: 'Remote Desktop Protocol', plugin: 'Conduit', raw_data: 'MRU: 192.168.1.50\nUsername hint: Administrator' },
    { id: 'f002', category: 'Network Artifacts', name: 'WiFi History: CorpNetwork', value: 'Previously connected network', timestamp: null, source_file: 'SOFTWARE', source_path: '\\Windows\\System32\\config\\SOFTWARE', forensic_value: 'medium', mitre_technique: 'T1016', mitre_name: 'System Network Config Discovery', plugin: 'Conduit', raw_data: null },
  ],
  'Identity & Accounts': [
    { id: 'g001', category: 'Identity & Accounts', name: 'Local Account: Administrator', value: 'Last login: 2009-11-15 14:30', timestamp: '2009-11-15 14:30:00', source_file: 'SAM', source_path: '\\Windows\\System32\\config\\SAM', forensic_value: 'medium', mitre_technique: 'T1087.001', mitre_name: 'Local Account', plugin: 'Recon', raw_data: null },
    { id: 'g002', category: 'Identity & Accounts', name: 'Email: admin@corpnetwork.local', value: 'Found in document metadata', timestamp: null, source_file: 'ntuser.dat', source_path: '\\Documents and Settings\\Administrator\\ntuser.dat', forensic_value: 'medium', mitre_technique: 'T1589.002', mitre_name: 'Email Addresses', plugin: 'Recon', raw_data: null },
  ],
}

// ──────────────────────────────────────────────────────────────────────────────
// Plugin commands
// ──────────────────────────────────────────────────────────────────────────────

const PLUGIN_NAMES = [
  'Remnant', 'Chronicle', 'Cipher', 'Trace', 'Specter',
  'Conduit', 'Nimbus', 'Wraith', 'Vector', 'Recon', 'Sigma',
] as const

const MOCK_ARTIFACT_COUNTS: Record<string, number> = {
  Remnant: 47, Chronicle: 183, Cipher: 12, Trace: 89, Specter: 0,
  Conduit: 34, Nimbus: 5, Wraith: 2, Vector: 8, Recon: 23, Sigma: 156,
}

// Mock state for browser preview mode
const mockStatuses: Record<string, PluginStatus> = {}
type MockListener = (e: PluginProgressEvent) => void
const mockListeners = new Set<MockListener>()

function emitMock(e: PluginProgressEvent) {
  mockStatuses[e.name] = {
    name: e.name,
    status: e.status,
    progress: e.progress,
    artifact_count: e.artifact_count ?? mockStatuses[e.name]?.artifact_count ?? 0,
  }
  mockListeners.forEach((cb) => cb(e))
}

export async function getPluginStatuses(): Promise<PluginStatus[]> {
  if (!IN_TAURI) {
    return PLUGIN_NAMES.map((n) =>
      mockStatuses[n] ?? {
        name: n,
        status: 'idle' as const,
        progress: 0,
        artifact_count: 0,
      },
    )
  }
  try {
    return await invoke('get_plugin_statuses')
  } catch {
    return []
  }
}

export async function runPlugin(
  pluginName: string,
  evidenceId: string,
): Promise<PluginRunResult> {
  if (!IN_TAURI) {
    // Simulate progress locally with setTimeout sequence
    emitMock({ name: pluginName, progress: 0, status: 'running' })
    const steps = [10, 25, 40, 55, 70, 85, 95]
    let i = 0
    const tick = () => {
      if (i < steps.length) {
        emitMock({ name: pluginName, progress: steps[i], status: 'running' })
        i++
        setTimeout(tick, 400)
      } else {
        const count = MOCK_ARTIFACT_COUNTS[pluginName] ?? 0
        emitMock({
          name: pluginName,
          progress: 100,
          status: 'complete',
          artifact_count: count,
        })
      }
    }
    setTimeout(tick, 400)
    return {
      plugin_name: pluginName,
      success: true,
      artifact_count: 0,
      duration_ms: 0,
    }
  }
  try {
    return await invoke('run_plugin', { pluginName, evidenceId })
  } catch (e) {
    return {
      plugin_name: pluginName,
      success: false,
      artifact_count: 0,
      duration_ms: 0,
      error: String(e),
    }
  }
}

export async function runAllPlugins(evidenceId: string): Promise<void> {
  if (!IN_TAURI) {
    for (const name of PLUGIN_NAMES) {
      await new Promise((r) => setTimeout(r, 200))
      runPlugin(name, evidenceId)
    }
    return
  }
  try {
    await invoke('run_all_plugins', { evidenceId })
  } catch (e) {
    console.error('Run all failed:', e)
  }
}

export function onPluginProgress(
  callback: (data: PluginProgressEvent) => void,
): Promise<() => void> {
  if (!IN_TAURI) {
    mockListeners.add(callback)
    return Promise.resolve(() => {
      mockListeners.delete(callback)
    })
  }
  return listen<PluginProgressEvent>('plugin-progress', (event) => {
    callback(event.payload)
  })
}

export async function getStats(evidenceId: string): Promise<StatsResult> {
  if (!IN_TAURI) {
    return { files: 26235, suspicious: 8993, flagged: 12, carved: 0, hashed: 0, artifacts: 0 }
  }
  try {
    return await invoke('get_stats', { evidenceId })
  } catch {
    return { files: 0, suspicious: 0, flagged: 0, carved: 0, hashed: 0, artifacts: 0 }
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Browser-preview mocks (mirror Rust commands so the UI can be tested in Vite
// dev server without the Tauri runtime). Removed automatically when IN_TAURI.
// ──────────────────────────────────────────────────────────────────────────────

const MOCK_TREE_ROOT: TreeNode[] = [
  {
    id: 'node-root',
    name: 'jo-2009-11-16.E01 (9.8 GB)',
    node_type: 'evidence',
    count: 26235,
    is_deleted: false,
    is_flagged: false,
    is_suspicious: false,
    has_children: true,
    parent_id: null,
    depth: 0,
  },
]

const MOCK_TREE_CHILDREN: Record<string, TreeNode[]> = {
  'node-root': [
    {
      id: 'vol-ntfs',
      name: '[NTFS NTFS] (26235)',
      node_type: 'volume',
      count: 26235,
      is_deleted: false,
      is_flagged: false,
      is_suspicious: false,
      has_children: true,
      parent_id: 'node-root',
      depth: 1,
    },
  ],
  'vol-ntfs': [
    { id: 'folder-docs',     name: 'Documents and Settings',      node_type: 'folder', count: 2050, is_deleted: false, is_flagged: false, is_suspicious: false, has_children: true, parent_id: 'vol-ntfs', depth: 2 },
    { id: 'folder-prog',     name: 'Program Files',               node_type: 'folder', count: 4890, is_deleted: false, is_flagged: false, is_suspicious: false, has_children: true, parent_id: 'vol-ntfs', depth: 2 },
    { id: 'folder-recycler', name: 'RECYCLER',                    node_type: 'folder', count: 3,    is_deleted: false, is_flagged: false, is_suspicious: false, has_children: true, parent_id: 'vol-ntfs', depth: 2 },
    { id: 'folder-sysinfo',  name: 'System Volume Information',   node_type: 'folder', count: 1481, is_deleted: false, is_flagged: false, is_suspicious: false, has_children: true, parent_id: 'vol-ntfs', depth: 2 },
    { id: 'folder-windows',  name: 'Windows',                     node_type: 'folder', count: 8200, is_deleted: false, is_flagged: false, is_suspicious: false, has_children: true, parent_id: 'vol-ntfs', depth: 2 },
    { id: 'folder-ie8',      name: 'ie8',                         node_type: 'folder', count: 740,  is_deleted: false, is_flagged: true,  is_suspicious: true,  has_children: true, parent_id: 'vol-ntfs', depth: 2 },
    { id: 'folder-users',    name: 'Users',                       node_type: 'folder', count: 1200, is_deleted: false, is_flagged: false, is_suspicious: false, has_children: true, parent_id: 'vol-ntfs', depth: 2 },
  ],
}

const MOCK_FILES: FileEntry[] = [
  { id: 'f001', name: 'ntuser.dat',         extension: 'dat',  size: 2516582,  size_display: '2.4 MB',  modified: '2009-11-14 09:22', created: '2009-10-01 00:00', sha256: 'a3f9c2d8e1b447f6...', is_deleted: false, is_suspicious: false, is_flagged: false, category: 'Registry Hive',     tag: null,                  tag_color: null },
  { id: 'f002', name: 'setupapi.log',       extension: 'log',  size: 1258291,  size_display: '1.2 MB',  modified: '2009-11-10 14:00', created: '2009-10-01 00:00', sha256: null,                  is_deleted: false, is_suspicious: false, is_flagged: false, category: 'System Log',        tag: null,                  tag_color: null },
  { id: 'f003', name: 'svchost32.exe',      extension: 'exe',  size: 913408,   size_display: '892 KB',  modified: '2009-11-15 14:32', created: '2009-11-15 14:32', sha256: null,                  is_deleted: false, is_suspicious: true,  is_flagged: false, category: 'Executable',        tag: 'Suspicious',          tag_color: '#b87840' },
  { id: 'f004', name: 'mimikatz.exe',       extension: 'exe',  size: 1258291,  size_display: '1.2 MB',  modified: '2009-11-15 14:33', created: '2009-11-15 14:33', sha256: null,                  is_deleted: false, is_suspicious: false, is_flagged: true,  category: 'Known Malware Tool',tag: 'Critical Evidence',   tag_color: '#a84040' },
  { id: 'f005', name: 'Security.evtx',      extension: 'evtx', size: 46137344, size_display: '44 MB',   modified: '2009-11-16 03:44', created: '2009-10-01 00:00', sha256: null,                  is_deleted: false, is_suspicious: false, is_flagged: false, category: 'Event Log',         tag: null,                  tag_color: null },
  { id: 'f006', name: 'SYSTEM',             extension: '',     size: 19083264, size_display: '18.2 MB', modified: '2009-11-01 00:00', created: '2009-10-01 00:00', sha256: null,                  is_deleted: false, is_suspicious: false, is_flagged: false, category: 'Registry Hive',     tag: null,                  tag_color: null },
  { id: 'f007', name: 'evidence_backup.zip',extension: 'zip',  size: 23068672, size_display: '22 MB',   modified: '2009-11-14 22:11', created: '2009-11-14 22:10', sha256: null,                  is_deleted: true,  is_suspicious: false, is_flagged: false, category: 'Archive',           tag: null,                  tag_color: null },
  { id: 'f008', name: 'cmd.lnk',            extension: 'lnk',  size: 2150,     size_display: '2.1 KB',  modified: '2009-11-15 14:35', created: '2009-11-15 14:35', sha256: null,                  is_deleted: false, is_suspicious: true,  is_flagged: false, category: 'Shell Link',        tag: null,                  tag_color: null },
  { id: 'f009', name: 'WebCacheV01.dat',    extension: 'dat',  size: 12582912, size_display: '12 MB',   modified: '2009-11-16 03:40', created: '2009-10-01 00:00', sha256: null,                  is_deleted: false, is_suspicious: false, is_flagged: false, category: 'Browser Cache',     tag: null,                  tag_color: null },
  { id: 'f010', name: 'cleanup.ps1',        extension: 'ps1',  size: 4915,     size_display: '4.8 KB',  modified: '2009-11-15 14:31', created: '2009-11-15 14:31', sha256: null,                  is_deleted: false, is_suspicious: true,  is_flagged: false, category: 'PowerShell Script', tag: null,                  tag_color: null },
]

function mockDefaultMeta(id: string): FileMetadata {
  return {
    id,
    name: 'Unknown',
    full_path: '\\Unknown',
    size: 0,
    size_display: '0 B',
    modified: '\u2014',
    created: '\u2014',
    accessed: '\u2014',
    sha256: null,
    md5: null,
    category: 'Unknown',
    is_deleted: false,
    is_suspicious: false,
    is_flagged: false,
    mft_entry: null,
    extension: '',
    mime_type: null,
    inode: null,
    permissions: null,
  }
}

const MOCK_METADATA: Record<string, FileMetadata> = {
  f001: {
    id: 'f001',
    name: 'ntuser.dat',
    full_path: '\\Documents and Settings\\Administrator\\ntuser.dat',
    size: 2516582,
    size_display: '2.4 MB',
    modified: '2009-11-14 09:22:14',
    created: '2009-10-01 00:00:00',
    accessed: '2009-11-16 03:44:00',
    sha256: 'a3f9c2d8e1b447f609c382da554f1b9e7d2ca3f8b4e601d288f5a29c3e7b1d4f',
    md5: '5f4dcc3b5aa765d61d8327deb882cf99',
    category: 'Registry Hive',
    is_deleted: false,
    is_suspicious: false,
    is_flagged: false,
    mft_entry: 4922,
    extension: 'dat',
    mime_type: 'application/octet-stream',
    inode: null,
    permissions: 'rw-r--r--',
  },
  f003: {
    id: 'f003',
    name: 'svchost32.exe',
    full_path: '\\Windows\\System32\\svchost32.exe',
    size: 913408,
    size_display: '892 KB',
    modified: '2009-11-15 14:32:00',
    created: '2009-11-15 14:32:00',
    accessed: '2009-11-15 14:32:00',
    sha256: null,
    md5: null,
    category: 'Executable',
    is_deleted: false,
    is_suspicious: true,
    is_flagged: false,
    mft_entry: 6101,
    extension: 'exe',
    mime_type: 'application/x-msdownload',
    inode: null,
    permissions: 'rwxr-xr-x',
  },
  f004: {
    id: 'f004',
    name: 'mimikatz.exe',
    full_path: '\\Windows\\Temp\\mimikatz.exe',
    size: 1258291,
    size_display: '1.2 MB',
    modified: '2009-11-15 14:33:02',
    created: '2009-11-15 14:33:02',
    accessed: '2009-11-15 14:33:05',
    sha256: null,
    md5: null,
    category: 'Known Malware Tool',
    is_deleted: false,
    is_suspicious: false,
    is_flagged: true,
    mft_entry: 7745,
    extension: 'exe',
    mime_type: 'application/x-msdownload',
    inode: null,
    permissions: 'rwxr-xr-x',
  },
  f007: {
    id: 'f007',
    name: 'evidence_backup.zip',
    full_path: '\\Users\\Admin\\Desktop\\evidence_backup.zip',
    size: 23068672,
    size_display: '22 MB',
    modified: '2009-11-14 22:11:00',
    created: '2009-11-14 22:10:00',
    accessed: '2009-11-14 22:11:00',
    sha256: null,
    md5: null,
    category: 'Archive',
    is_deleted: true,
    is_suspicious: false,
    is_flagged: false,
    mft_entry: 8210,
    extension: 'zip',
    mime_type: 'application/zip',
    inode: null,
    permissions: 'rw-r--r--',
  },
  f010: {
    id: 'f010',
    name: 'cleanup.ps1',
    full_path: '\\Windows\\Temp\\cleanup.ps1',
    size: 4915,
    size_display: '4.8 KB',
    modified: '2009-11-15 14:31:00',
    created: '2009-11-15 14:31:00',
    accessed: '2009-11-15 14:31:00',
    sha256: null,
    md5: null,
    category: 'PowerShell Script',
    is_deleted: false,
    is_suspicious: true,
    is_flagged: false,
    mft_entry: 7720,
    extension: 'ps1',
    mime_type: 'text/x-powershell',
    inode: null,
    permissions: 'rw-r--r--',
  },
}

function mockHexData(offset: number): HexData {
  const bytes = [
    0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
    0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0x8c, 0x00, 0x00, 0x54, 0x68, 0x69, 0x73,
    0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20,
    0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20, 0x6d, 0x6f,
    0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]
  const lines: HexLine[] = []
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16)
    const off = offset + i
    const hex = chunk.map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
    const ascii = chunk
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'))
      .join('')
    lines.push({
      offset: off.toString(16).padStart(8, '0').toUpperCase(),
      hex,
      ascii,
    })
  }
  return { lines, total_size: 1258291, offset }
}

function mockTextContent(fileId: string): string {
  if (fileId === 'f010') {
    return [
      '# Cleanup script',
      '# Remove evidence files',
      '',
      'Remove-Item -Path C:\\Windows\\Temp\\mimikatz.exe -Force',
      'Remove-Item -Path C:\\Windows\\Temp\\lsass.dmp -Force',
      'Clear-EventLog -LogName Security',
      'Clear-EventLog -LogName System',
      'wevtutil cl Security',
      'wevtutil cl System',
      '# Delete VSS snapshots',
      'vssadmin delete shadows /all /quiet',
      "Write-Host 'Cleanup complete'",
    ].join('\n')
  }
  if (fileId === 'f008') {
    return '[Binary file - use HEX tab to view]'
  }
  return '[Text content not available for this file type.\nUse HEX tab to view raw bytes.]'
}

function mockSearch(query: string): SearchResult[] {
  if (!query) return []
  const q = query.toLowerCase()
  const all: SearchResult[] = [
    {
      id: 'f004',
      name: 'mimikatz.exe',
      full_path: '\\Windows\\Temp\\mimikatz.exe',
      extension: 'exe',
      size_display: '1.2 MB',
      modified: '2009-11-15 14:33',
      is_deleted: false,
      is_flagged: true,
      is_suspicious: false,
      match_field: 'filename',
      match_value: 'mimikatz.exe',
    },
    {
      id: 'f003',
      name: 'svchost32.exe',
      full_path: '\\Windows\\System32\\svchost32.exe',
      extension: 'exe',
      size_display: '892 KB',
      modified: '2009-11-15 14:32',
      is_deleted: false,
      is_flagged: false,
      is_suspicious: true,
      match_field: 'filename',
      match_value: 'svchost32.exe',
    },
    {
      id: 'f010',
      name: 'cleanup.ps1',
      full_path: '\\Windows\\Temp\\cleanup.ps1',
      extension: 'ps1',
      size_display: '4.8 KB',
      modified: '2009-11-15 14:31',
      is_deleted: false,
      is_flagged: false,
      is_suspicious: true,
      match_field: 'content',
      match_value: 'Remove-Item mimikatz.exe',
    },
    {
      id: 'f007',
      name: 'evidence_backup.zip',
      full_path: '\\Users\\Admin\\Desktop\\evidence_backup.zip',
      extension: 'zip',
      size_display: '22 MB',
      modified: '2009-11-14 22:11',
      is_deleted: true,
      is_flagged: false,
      is_suspicious: false,
      match_field: 'filename',
      match_value: 'evidence_backup.zip',
    },
  ]
  return all.filter(
    (r) =>
      r.name.toLowerCase().includes(q) ||
      r.full_path.toLowerCase().includes(q) ||
      r.match_value.toLowerCase().includes(q),
  )
}
