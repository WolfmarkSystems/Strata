import { create } from 'zustand'
import type { AppState, ViewMode, Stats } from '../types'
import type { PluginStatus, LicenseResult, ExaminerProfile, CaseFile } from '../ipc'
import { saveCase as ipcSaveCase } from '../ipc'
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
  // Sprint 8 P1 F1 — set true while `runAllPlugins` is in flight
  // from the "Open Evidence" flow. TopBar renders an INDEXING badge.
  pluginsRunning: boolean
  setPluginsRunning: (v: boolean) => void
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

  // Day 13 — case management
  caseData: CaseFile | null
  casePath: string | null
  caseModified: boolean
  setCaseData: (c: CaseFile, path: string) => void
  updateCaseNotes: (notes: string) => void
  markCaseModified: () => void
  saveCaseNow: () => Promise<void>
  clearCase: () => void

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
  /// Sprint-11 P2 — expand a chain of tree nodes (the breadcrumb
  /// from `navigate_to_path`) so the leaf becomes visible. Idempotent.
  expandTreeNodes: (ids: string[]) => void
}

// Apply the default theme immediately so CSS variables match the active theme
// before any component mounts.
if (typeof document !== 'undefined') {
  applyTheme(getTheme('Iron Wolf'))
}

// Debounced autosave — coalesces a burst of updates (typing notes, tagging
// files) into a single save 5 seconds after the last change.
let autosaveTimer: ReturnType<typeof setTimeout> | null = null
function scheduleAutosave() {
  if (autosaveTimer) clearTimeout(autosaveTimer)
  autosaveTimer = setTimeout(() => {
    autosaveTimer = null
    void useAppStore.getState().saveCaseNow()
  }, 5000)
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
  pluginsRunning: false,
  setPluginsRunning: (v) => set({ pluginsRunning: v }),
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

  // ── Case management ─────────────────────────────────────────────────────
  caseData: null,
  casePath: null,
  caseModified: false,
  setCaseData: (c, path) =>
    set({
      caseData: c,
      casePath: path,
      caseModified: false,
      caseId: c.case_number,
      caseName: c.case_name,
      examinerProfile: c.examiner,
      examinerName: c.examiner.name || 'Examiner',
    }),
  updateCaseNotes: (notes) => {
    set((s) => {
      if (!s.caseData) return {}
      return {
        caseData: { ...s.caseData, notes },
        caseModified: true,
      }
    })
    scheduleAutosave()
  },
  markCaseModified: () => {
    set({ caseModified: true })
    scheduleAutosave()
  },
  saveCaseNow: async () => {
    const s = useAppStore.getState()
    if (!s.caseData || !s.casePath) return
    const ok = await ipcSaveCase(s.caseData, s.casePath)
    if (ok) set({ caseModified: false })
  },
  clearCase: () =>
    set({
      caseData: null,
      casePath: null,
      caseModified: false,
      caseId: null,
      caseName: null,
    }),

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
  expandTreeNodes: (ids) =>
    set((s) => {
      const next = new Set(s.treeExpanded)
      for (const id of ids) next.add(id)
      return { treeExpanded: next }
    }),
}))
