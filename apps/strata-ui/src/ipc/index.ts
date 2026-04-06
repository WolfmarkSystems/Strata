import { invoke } from '@tauri-apps/api/core'
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
