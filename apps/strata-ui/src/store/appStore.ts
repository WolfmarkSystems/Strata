import { create } from 'zustand'
import type { AppState, ViewMode, Stats } from '../types'
import type { PluginStatus, LicenseResult, ExaminerProfile } from '../ipc'
import { applyTheme, getTheme } from '../themes'

export type AppGate = 'splash' | 'examiner' | 'drive' | 'main'

interface AppStore extends AppState {
  metadataSearch: boolean
  fulltextSearch: boolean
  evidenceId: string | null
  evidenceName: string | null
  evidenceLoaded: boolean
  selectedNodeId: string | null
  treeExpanded: Set<string>
  searchQuery: string
  searchActive: boolean
  setSearchQuery: (q: string) => void
  setSearchActive: (v: boolean) => void
  pluginStatuses: Record<string, PluginStatus>
  setPluginStatus: (name: string, status: PluginStatus) => void
  selectedArtifactId: string | null
  setSelectedArtifactId: (id: string | null) => void
  taggedFiles: Record<string, string>
  setFileTag: (fileId: string, tag: string) => void
  removeFileTag: (fileId: string) => void
  gate: AppGate
  licenseResult: LicenseResult | null
  examinerProfile: ExaminerProfile | null
  selectedDriveId: string | null
  evidencePath: string | null
  isDevMode: boolean
  setGate: (g: AppGate) => void
  setLicenseResult: (r: LicenseResult) => void
  setExaminerProfile: (p: ExaminerProfile) => void
  setSelectedDrive: (id: string, path: string) => void
  reportVisible: boolean
  reportHtml: string | null
  setReportVisible: (v: boolean) => void
  setReportHtml: (h: string | null) => void

  setView: (v: ViewMode) => void
  setLicensed: (s: AppState['licensed']) => void
  setCase: (id: string, name: string) => void
  setStats: (s: Partial<Stats>) => void
  setSelectedFile: (id: string | null) => void
  setSelectedPlugin: (id: string | null) => void
  setSelectedArtifactCat: (c: string | null) => void
  setSelectedTag: (t: string | null) => void
  setTheme: (t: string) => void
  toggleMetadata: () => void
  toggleFulltext: () => void
  setEvidence: (id: string, name: string) => void
  setEvidenceLoaded: (v: boolean) => void
  setSelectedNode: (id: string | null) => void
  toggleTreeNode: (id: string) => void
}

// Apply the default theme immediately so CSS variables match the active theme
// before any component mounts.
if (typeof document !== 'undefined') {
  applyTheme(getTheme('Iron Wolf'))
}

export const useAppStore = create<AppStore>((set) => ({
  view: 'files',
  licensed: 'none',
  caseId: null,
  caseName: null,
  isDev: true,
  examinerName: 'Dev Examiner',
  stats: {
    files: 0,
    suspicious: 0,
    flagged: 0,
    carved: 0,
    hashed: 0,
    artifacts: 0,
  },
  selectedFileId: null,
  selectedPluginId: null,
  selectedArtifactCat: null,
  selectedTag: null,
  activeTheme: 'Iron Wolf',
  metadataSearch: false,
  fulltextSearch: false,
  evidenceId: null,
  evidenceName: null,
  evidenceLoaded: false,
  selectedNodeId: null,
  treeExpanded: new Set<string>(),
  searchQuery: '',
  searchActive: false,
  setSearchQuery: (q) => set({ searchQuery: q }),
  setSearchActive: (v) => set({ searchActive: v }),
  pluginStatuses: {},
  setPluginStatus: (name, status) =>
    set((s) => ({
      pluginStatuses: { ...s.pluginStatuses, [name]: status },
    })),
  selectedArtifactId: null,
  setSelectedArtifactId: (id) => set({ selectedArtifactId: id }),
  taggedFiles: {
    f004: 'Critical Evidence',
    f003: 'Suspicious',
    f010: 'Suspicious',
    f005: 'Key Artifact',
  },
  setFileTag: (fileId, tag) =>
    set((s) => ({ taggedFiles: { ...s.taggedFiles, [fileId]: tag } })),
  removeFileTag: (fileId) =>
    set((s) => {
      const next = { ...s.taggedFiles }
      delete next[fileId]
      return { taggedFiles: next }
    }),
  gate: 'splash',
  licenseResult: null,
  examinerProfile: null,
  selectedDriveId: null,
  evidencePath: null,
  isDevMode: true,
  setGate: (g) => set({ gate: g }),
  setLicenseResult: (r) => set({ licenseResult: r }),
  setExaminerProfile: (p) =>
    set({ examinerProfile: p, examinerName: p.name || 'Examiner' }),
  setSelectedDrive: (id, path) =>
    set({ selectedDriveId: id, evidencePath: path }),
  reportVisible: false,
  reportHtml: null,
  setReportVisible: (v) => set({ reportVisible: v }),
  setReportHtml: (h) => set({ reportHtml: h }),

  setView: (v) => set({ view: v }),
  setLicensed: (s) => set({ licensed: s }),
  setCase: (id, name) => set({ caseId: id, caseName: name }),
  setStats: (s) =>
    set((state) => ({ stats: { ...state.stats, ...s } })),
  setSelectedFile: (id) => set({ selectedFileId: id }),
  setSelectedPlugin: (id) => set({ selectedPluginId: id }),
  setSelectedArtifactCat: (c) => set({ selectedArtifactCat: c }),
  setSelectedTag: (t) => set({ selectedTag: t }),
  setTheme: (t) => {
    const theme = getTheme(t)
    applyTheme(theme)
    set({ activeTheme: t })
  },
  toggleMetadata: () => set((s) => ({ metadataSearch: !s.metadataSearch })),
  toggleFulltext: () => set((s) => ({ fulltextSearch: !s.fulltextSearch })),
  setEvidence: (id, name) =>
    set({ evidenceId: id, evidenceName: name, evidenceLoaded: true }),
  setEvidenceLoaded: (v) => set({ evidenceLoaded: v }),
  setSelectedNode: (id) => set({ selectedNodeId: id }),
  toggleTreeNode: (id) =>
    set((s) => {
      const next = new Set(s.treeExpanded)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return { treeExpanded: next }
    }),
}))
