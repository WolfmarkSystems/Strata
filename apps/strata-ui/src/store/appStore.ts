import { create } from 'zustand'
import type { AppState, ViewMode, Stats } from '../types'

interface AppStore extends AppState {
  setView: (v: ViewMode) => void
  setLicensed: (s: AppState['licensed']) => void
  setCase: (id: string, name: string) => void
  setStats: (s: Stats) => void
  setSelectedFile: (id: string | null) => void
  setSelectedPlugin: (id: string | null) => void
  setSelectedArtifactCat: (c: string | null) => void
  setSelectedTag: (t: string | null) => void
  setTheme: (t: string) => void
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

  setView: (v) => set({ view: v }),
  setLicensed: (s) => set({ licensed: s }),
  setCase: (id, name) => set({ caseId: id, caseName: name }),
  setStats: (s) => set({ stats: s }),
  setSelectedFile: (id) => set({ selectedFileId: id }),
  setSelectedPlugin: (id) => set({ selectedPluginId: id }),
  setSelectedArtifactCat: (c) => set({ selectedArtifactCat: c }),
  setSelectedTag: (t) => set({ selectedTag: t }),
  setTheme: (t) => set({ activeTheme: t }),
}))
