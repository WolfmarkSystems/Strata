import TopBar from './components/TopBar'
import Sidebar from './components/Sidebar'
import FileExplorer from './views/FileExplorer'
import ArtifactsView from './views/ArtifactsView'
import TaggedView from './views/TaggedView'
import PluginsView from './views/PluginsView'
import SettingsView from './views/SettingsView'
import { useAppStore } from './store/appStore'

export default function App() {
  const view = useAppStore((s) => s.view)

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        background: 'var(--bg-base)',
        overflow: 'hidden',
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
        {view === 'files' && <FileExplorer />}
        {view === 'artifacts' && <ArtifactsView />}
        {view === 'tags' && <TaggedView />}
        {view === 'plugins' && <PluginsView />}
        {view === 'settings' && <SettingsView />}
      </div>
    </div>
  )
}
