import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import TopBar from './components/TopBar'
import Sidebar from './components/Sidebar'
import SearchOverlay from './components/SearchOverlay'
import FileExplorer from './views/FileExplorer'
import ArtifactsView from './views/ArtifactsView'
import TaggedView from './views/TaggedView'
import PluginsView from './views/PluginsView'
import SettingsView from './views/SettingsView'
import { useAppStore } from './store/appStore'

export default function App() {
  const view = useAppStore((s) => s.view)
  const searchActive = useAppStore((s) => s.searchActive)
  const setSearchActive = useAppStore((s) => s.setSearchActive)
  const setView = useAppStore((s) => s.setView)

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSearchActive(false)
      }
      if ((e.metaKey || e.ctrlKey) && e.key === 'f') {
        e.preventDefault()
        setSearchActive(true)
      }
      if (e.metaKey || e.ctrlKey) {
        switch (e.key) {
          case '1': setView('files'); break
          case '2': setView('artifacts'); break
          case '3': setView('tags'); break
          case '4': setView('plugins'); break
          case '5': setView('settings'); break
        }
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [setSearchActive, setView])

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
        }}
      >
        <Sidebar />
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex' }}>
          {view === 'files' && <FileExplorer />}
          {view === 'artifacts' && <ArtifactsView />}
          {view === 'tags' && <TaggedView />}
          {view === 'plugins' && <PluginsView />}
          {view === 'settings' && <SettingsView />}
        </div>
      </div>
      {searchActive && createPortal(<SearchOverlay />, document.body)}
    </div>
  )
}
