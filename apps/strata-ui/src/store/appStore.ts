import { create } from 'zustand'
import type { AppState, ViewMode, Stats } from '../types'

interface AppStore extends AppState {
  metadataSearch: boolean
  fulltextSearch: boolean
  evidenceId: string | null
  evidenceName: string | null
  evidenceLoaded: boolean
  selectedNodeId: string | null
  treeExpanded: Set<string>

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
  activeTheme: 'iron-wolf',
  metadataSearch: false,
  fulltextSearch: false,
  evidenceId: null,
  evidenceName: null,
  evidenceLoaded: false,
  selectedNodeId: null,
  treeExpanded: new Set<string>(),

  setView: (v) => set({ view: v }),
  setLicensed: (s) => set({ licensed: s }),
  setCase: (id, name) => set({ caseId: id, caseName: name }),
  setStats: (s) =>
    set((state) => ({ stats: { ...state.stats, ...s } })),
  setSelectedFile: (id) => set({ selectedFileId: id }),
  setSelectedPlugin: (id) => set({ selectedPluginId: id }),
  setSelectedArtifactCat: (c) => set({ selectedArtifactCat: c }),
  setSelectedTag: (t) => set({ selectedTag: t }),
  setTheme: (t) => set({ activeTheme: t }),
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
