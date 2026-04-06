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
    mft_entry: 4922,
    extension: 'dat',
    mime_type: 'application/octet-stream',
    inode: null,
    permissions: 'rw-r--r--',
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
    mft_entry: 7745,
    extension: 'exe',
    mime_type: 'application/x-msdownload',
    inode: null,
    permissions: 'rwxr-xr-x',
  },
}
