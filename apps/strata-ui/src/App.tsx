import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import TopBar from './components/TopBar'
import Sidebar from './components/Sidebar'
import SearchOverlay from './components/SearchOverlay'
import ReportViewer from './components/ReportViewer'
import SplashScreen from './components/SplashScreen'
import ExaminerSetup from './components/ExaminerSetup'
import DriveSelection from './components/DriveSelection'
import FileExplorer from './views/FileExplorer'
import ArtifactsView from './views/ArtifactsView'
import TaggedView from './views/TaggedView'
import PluginsView from './views/PluginsView'
import SettingsView from './views/SettingsView'
import NotesView from './views/NotesView'
import { useAppStore } from './store/appStore'
import { generateReport, openEvidenceDialog, loadEvidence, getStats, runAllPlugins } from './ipc'

export default function App() {
  const gate = useAppStore((s) => s.gate)
  const view = useAppStore((s) => s.view)
  const searchActive = useAppStore((s) => s.searchActive)
  const setSearchActive = useAppStore((s) => s.setSearchActive)
  const setView = useAppStore((s) => s.setView)
  const reportVisible = useAppStore((s) => s.reportVisible)
  const setReportVisible = useAppStore((s) => s.setReportVisible)
  const setReportHtml = useAppStore((s) => s.setReportHtml)
  const caseName = useAppStore((s) => s.caseName)
  const examinerProfile = useAppStore((s) => s.examinerProfile)
  const setEvidence = useAppStore((s) => s.setEvidence)
  const setCase = useAppStore((s) => s.setCase)
  const setStats = useAppStore((s) => s.setStats)
  const setSelectedNode = useAppStore((s) => s.setSelectedNode)
  const setPluginsRunning = useAppStore((s) => s.setPluginsRunning)

  useEffect(() => {
    const handler = async (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        // Priority: close report > close search
        if (useAppStore.getState().reportVisible) {
          setReportVisible(false)
          return
        }
        setSearchActive(false)
        return
      }
      if ((e.metaKey || e.ctrlKey) && e.key === 'f') {
        e.preventDefault()
        setSearchActive(true)
        return
      }
      if ((e.metaKey || e.ctrlKey) && e.key === 'r') {
        e.preventDefault()
        const result = await generateReport({
          case_number: 'STRATA-2026-001',
          case_name: caseName ?? 'Unsaved Session',
          examiner_name: examinerProfile?.name ?? 'Dev Examiner',
          examiner_agency: examinerProfile?.agency ?? 'Wolfmark Systems',
          examiner_badge: examinerProfile?.badge ?? 'DEV-001',
          include_artifacts: true,
          include_tagged: true,
          include_mitre: true,
          include_timeline: true,
        })
        setReportHtml(result.html)
        setReportVisible(true)
        return
      }
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault()
        await useAppStore.getState().saveCaseNow()
        return
      }
      if ((e.metaKey || e.ctrlKey) && e.key === 'e') {
        e.preventDefault()
        const path = await openEvidenceDialog()
        if (!path) return
        const result = await loadEvidence(path)
        if (!result.success) return
        setEvidence(result.evidence_id, result.name)
        setCase(result.evidence_id, result.name)
        const preStats = await getStats(result.evidence_id)
        setStats(preStats)
        setSelectedNode('vol-ntfs')
        // Sprint 8 P1 F1 — auto-index after load; same flow as the
        // TopBar "Open Evidence" button. INDEXING badge is rendered
        // in TopBar from the shared `pluginsRunning` store flag.
        setPluginsRunning(true)
        try {
          await runAllPlugins(result.evidence_id)
          const postStats = await getStats(result.evidence_id)
          setStats(postStats)
        } catch (err) {
          console.error('runAllPlugins failed:', err)
        } finally {
          setPluginsRunning(false)
        }
        return
      }
      if (e.metaKey || e.ctrlKey) {
        switch (e.key) {
          case '1': setView('files'); break
          case '2': setView('artifacts'); break
          case '3': setView('tags'); break
          case '4': setView('notes'); break
          case '5': setView('plugins'); break
          case '6': setView('settings'); break
        }
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [setSearchActive, setView, setReportVisible, setReportHtml, caseName, examinerProfile, setEvidence, setCase, setStats, setSelectedNode, setPluginsRunning])

  // Gate routing
  if (gate === 'splash') return <SplashScreen />
  if (gate === 'examiner') return <ExaminerSetup />
  if (gate === 'drive') return <DriveSelection />

  return (
    <div
      style={{
        height: '100vh',
        width: '100vw',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: 'var(--bg-base)',
      }}
    >
      <TopBar />
      <div
        style={{
          display: 'flex',
          flex: 1,
          overflow: 'hidden',
          padding: 8,
          gap: 8,
          background: 'var(--bg-base)',
        }}
      >
        <Sidebar />
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex' }}>
          {view === 'files' && <FileExplorer />}
          {view === 'artifacts' && <ArtifactsView />}
          {view === 'tags' && <TaggedView />}
          {view === 'notes' && <NotesView />}
          {view === 'plugins' && <PluginsView />}
          {view === 'settings' && <SettingsView />}
        </div>
      </div>
      {searchActive && createPortal(<SearchOverlay />, document.body)}
      {reportVisible && createPortal(<ReportViewer />, document.body)}
    </div>
  )
}
